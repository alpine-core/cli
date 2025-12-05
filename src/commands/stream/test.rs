use std::{
    env,
    io::{self, IsTerminal},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use alpine_protocol_sdk::{
    AlpineClient, CapabilitySet, ChannelFormat, DeviceIdentity, StreamProfile,
};
use anyhow::{Context, Result, anyhow, bail};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use serde::Deserialize;
use serde_json::Value;
use tokio::time::sleep;

use crate::{
    device_cache::DeviceRecord,
    identity_store,
    selector::{DeviceSelectorArgs, resolve_device},
    stream_session::{self, StoredSession},
};

#[derive(Debug, Clone, clap::Args)]
pub struct StreamTestArgs {
    #[command(flatten)]
    pub selector: DeviceSelectorArgs,
    /// Skip the TUI and print log output only (useful in terminals that do not support raw mode).
    #[arg(long)]
    pub no_ui: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct CapabilityInfo {
    #[serde(default)]
    streaming_supported: bool,
    #[serde(default)]
    encryption_supported: bool,
    #[serde(default)]
    max_channels: Option<u32>,
    #[serde(default)]
    channel_formats: Vec<String>,
}

impl CapabilityInfo {
    fn from_set(set: &CapabilitySet) -> Self {
        Self {
            streaming_supported: set.streaming_supported,
            encryption_supported: set.encryption_supported,
            max_channels: Some(set.max_channels),
            channel_formats: set
                .channel_formats
                .iter()
                .map(|format| format_name(format).to_string())
                .collect(),
        }
    }
}

pub async fn run(args: StreamTestArgs) -> Result<()> {
    let resolved = resolve_device(&args.selector)?;
    let record = resolved
        .record
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("stream test requires a cached device entry"))?;

    let capability_set = load_capability_set(record.capabilities.as_ref());
    let capabilities = CapabilityInfo::from_set(&capability_set);

    if !capabilities.streaming_supported {
        bail!("device {} does not support streaming", record.device_id);
    }
    if !capabilities.encryption_supported {
        bail!("device {} requires encrypted streaming", record.device_id);
    }

    let session = stream_session::load_session(&record.device_id)
        .context("reading stored session metadata")?
        .ok_or_else(|| {
            anyhow!(
                "No active session for device {}.\nRun: alpine handshake --id {}",
                record.device_id,
                record.device_id
            )
        })?;

    let sender = SessionSender::new(&record, &session, &capability_set, &capabilities).await?;
    let sender = Arc::new(Mutex::new(sender));

    let channel_count = determine_channel_count(&capabilities);

    let ui_supported = terminal_supports_ui();
    if args.no_ui || ui_supported.is_err() {
        if let Err(reason) = ui_supported {
            eprintln!(
                "Stream test TUI disabled: {}.\nRun in a fully featured terminal (Windows Terminal, native Linux, iTerm2) for the interactive UI.",
                reason
            );
        }
        run_headless(record, capabilities, channel_count, sender).await
    } else {
        run_ui(record, capabilities, channel_count, sender).await
    }
}

fn load_capability_set(value: Option<&Value>) -> CapabilitySet {
    if let Some(value) = value {
        serde_json::from_value(value.clone()).unwrap_or_default()
    } else {
        CapabilitySet::default()
    }
}

fn determine_channel_count(caps: &CapabilityInfo) -> usize {
    let max = caps.max_channels.unwrap_or(64);
    (max.max(1).min(512)) as usize
}

fn terminal_supports_ui() -> Result<(), String> {
    if !io::stdout().is_terminal() {
        return Err("stdout is not a TTY".into());
    }
    let term = env::var("TERM").unwrap_or_default();
    if term.is_empty() || term == "dumb" {
        return Err(format!("unsupported TERM value: {}", term));
    }
    let colorterm = env::var("COLORTERM").unwrap_or_default();
    let is_jetbrains = env::var("JETBRAINS_IDE").is_ok()
        || env::var("IDEA_INITIAL_DIRECTORY").is_ok()
        || env::var("TERMINAL_EMULATOR")
            .map(|v| v.to_lowercase().contains("jetbrains"))
            .unwrap_or(false);
    if is_jetbrains {
        return Err(
            "JetBrains embedded terminal is known to misrender alternate screen/raw mode under WSL"
                .into(),
        );
    }
    if colorterm.to_lowercase() == "truecolor" || term.contains("xterm") {
        return Ok(());
    }
    Ok(())
}

async fn run_ui(
    record: DeviceRecord,
    capabilities: CapabilityInfo,
    channel_count: usize,
    sender: Arc<Mutex<SessionSender>>,
) -> Result<()> {
    tokio::task::spawn_blocking(move || blocking_ui(record, capabilities, channel_count, sender))
        .await?
}

async fn run_headless(
    record: DeviceRecord,
    capabilities: CapabilityInfo,
    channel_count: usize,
    sender: Arc<Mutex<SessionSender>>,
) -> Result<()> {
    println!(
        "[ALPINE][STREAM] starting headless stream test for device {} ({})",
        record.device_id, record.model_id
    );
    println!(
        "Capabilities: formats={:?} max_channels={}",
        capabilities.channel_formats,
        capabilities.max_channels.unwrap_or(0)
    );
    println!("Sending sample frames (press Ctrl+C to stop)...");

    let mut values = vec![0u8; channel_count];
    for tick in 0..20 {
        // Simple ramp pattern
        for (idx, val) in values.iter_mut().enumerate() {
            *val = ((idx + tick) % 256) as u8;
        }
        let mut guard = sender.lock().unwrap();
        if let Err(err) = guard.send_frame(&values) {
            eprintln!("[ALPINE][STREAM][ERROR] frame send failed: {}", err);
            break;
        } else {
            println!(
                "[ALPINE][STREAM] sent frame {} ({} channels)",
                tick + 1,
                values.len()
            );
        }
        sleep(Duration::from_millis(200)).await;
    }
    println!("[ALPINE][STREAM] headless stream test complete.");
    Ok(())
}

fn blocking_ui(
    record: DeviceRecord,
    capabilities: CapabilityInfo,
    channel_count: usize,
    sender: Arc<Mutex<SessionSender>>,
) -> Result<()> {
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = ChannelState::new(channel_count);
    let mut status_message =
        Some("Use Up/Down select, Left/Right adjust, PgUp/PgDn page, q to quit".to_string());

    let loop_result = run_event_loop(
        &mut terminal,
        &record,
        &capabilities,
        &mut state,
        &sender,
        &mut status_message,
    );

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    loop_result
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    record: &DeviceRecord,
    capabilities: &CapabilityInfo,
    state: &mut ChannelState,
    sender: &Arc<Mutex<SessionSender>>,
    status_message: &mut Option<String>,
) -> Result<()> {
    loop {
        terminal.draw(|frame| {
            draw_frame(frame, state, record, capabilities, status_message);
        })?;

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Up => state.move_selection(-1),
                    KeyCode::Down => state.move_selection(1),
                    KeyCode::Left => {
                        if state.adjust_selected_value(-1) {
                            let mut guard = sender.lock().unwrap();
                            if let Err(err) = guard.send_frame(&state.values) {
                                *status_message = Some(format!("frame error: {}", err));
                            } else {
                                *status_message =
                                    Some(format!("sent frame for channel {}", state.selected + 1));
                            }
                        }
                    }
                    KeyCode::Right => {
                        if state.adjust_selected_value(1) {
                            let mut guard = sender.lock().unwrap();
                            if let Err(err) = guard.send_frame(&state.values) {
                                *status_message = Some(format!("frame error: {}", err));
                            } else {
                                *status_message =
                                    Some(format!("sent frame for channel {}", state.selected + 1));
                            }
                        }
                    }
                    KeyCode::PageUp => {
                        state.move_selection(-(state.page_rows() as isize));
                    }
                    KeyCode::PageDown => {
                        state.move_selection(state.page_rows() as isize);
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
}

fn draw_frame<B: ratatui::backend::Backend>(
    frame: &mut ratatui::Frame<B>,
    state: &mut ChannelState,
    record: &DeviceRecord,
    capabilities: &CapabilityInfo,
    status_message: &Option<String>,
) {
    let size = frame.size();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(6),
                Constraint::Length(2),
                Constraint::Length(2),
            ]
            .as_ref(),
        )
        .split(size);

    let format_desc = capabilities
        .channel_formats
        .first()
        .cloned()
        .unwrap_or_else(|| "u8".to_string());
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "ALPINE STREAM TEST",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw(format!("{} ({})", record.device_id, record.manufacturer_id)),
        Span::raw(" | "),
        Span::raw(format!("channels {}", state.values.len())),
        Span::raw(" | "),
        Span::raw(format!("format {}", format_desc)),
        Span::raw(" | ALPINE "),
        Span::raw(&record.alpine_version),
        Span::raw(" | Encrypted"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, outer[0]);

    let window_rows = outer[1].height.saturating_sub(3) as usize;
    let (start, end) = state.visible_range(window_rows);

    let rows: Vec<Row> = (start..end)
        .map(|idx| {
            let value = state.values[idx];
            Row::new(vec![
                Cell::from(format!("{:>3}", idx + 1)),
                Cell::from(format!("{:>3}", value)),
                Cell::from(format!("{:>3}%", percentage(value))),
            ])
        })
        .collect();

    let mut table_state = state.table_state.clone();
    let relative = state.selected.saturating_sub(start);
    if relative < rows.len() {
        table_state.select(Some(relative));
    } else {
        table_state.select(None);
    }

    let table = Table::new(rows)
        .header(
            Row::new(["Channel", "Value", "Level"])
                .style(Style::default().fg(Color::Yellow))
                .bottom_margin(0),
        )
        .block(Block::default().borders(Borders::ALL).title("Channels"))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .widths(&[
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
        ]);

    frame.render_stateful_widget(table, outer[1], &mut table_state);
    state.table_state = table_state;

    let instructions = Paragraph::new(Line::from(vec![Span::raw(
        "Up/Down select  Left/Right adjust  PgUp/PgDn page  q quit",
    )]))
    .block(Block::default().borders(Borders::ALL).title("Keys"));
    frame.render_widget(instructions, outer[2]);

    let status = Paragraph::new(status_message.clone().unwrap_or_default())
        .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(status, outer[3]);
}

fn percentage(value: u8) -> u8 {
    ((value as u16 * 100) / 255) as u8
}

struct ChannelState {
    values: Vec<u8>,
    selected: usize,
    window_start: usize,
    table_state: TableState,
}

impl ChannelState {
    fn new(count: usize) -> Self {
        Self {
            values: vec![0; count],
            selected: 0,
            window_start: 0,
            table_state: TableState::default(),
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let count = self.values.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, count - 1) as usize;
        self.selected = next;
    }

    fn adjust_selected_value(&mut self, delta: i16) -> bool {
        let value = self.values[self.selected] as i16;
        let next = (value + delta).clamp(0, 255) as u8;
        if next != self.values[self.selected] {
            self.values[self.selected] = next;
            true
        } else {
            false
        }
    }

    fn visible_range(&mut self, window_rows: usize) -> (usize, usize) {
        if window_rows == 0 {
            return (0, 0);
        }
        let max_start = self.values.len().saturating_sub(window_rows);
        let mut start = self.window_start.min(max_start);
        if self.selected < start {
            start = self.selected;
        } else if self.selected >= start + window_rows {
            start = self
                .selected
                .saturating_sub(window_rows.saturating_sub(1))
                .min(max_start);
        }
        self.window_start = start;
        let end = (start + window_rows).min(self.values.len());
        (start, end)
    }

    fn page_rows(&self) -> usize {
        10
    }
}

struct SessionSender {
    client: AlpineClient,
    channel_format: ChannelFormat,
    priority: u8,
    stream_id: String,
    stream_kind: String,
}

impl SessionSender {
    async fn new(
        record: &DeviceRecord,
        session: &StoredSession,
        capability_set: &CapabilitySet,
        capabilities: &CapabilityInfo,
    ) -> Result<Self> {
        let local_addr: SocketAddr = session
            .local_addr
            .parse()
            .map_err(|err| anyhow!("invalid local addr: {}", err))?;
        let remote_addr: SocketAddr = session
            .remote_addr
            .parse()
            .map_err(|err| anyhow!("invalid remote addr: {}", err))?;

        let signing_path = PathBuf::from(&session.signing_key);
        let verifying_path = PathBuf::from(&session.verifying_key);
        let credentials = identity_store::load_from_paths(&signing_path, &verifying_path)?;

        let identity = DeviceIdentity {
            device_id: record.device_id.clone(),
            manufacturer_id: record.manufacturer_id.clone(),
            model_id: record.model_id.clone(),
            hardware_rev: record.hardware_rev.clone(),
            firmware_rev: record.firmware_rev.clone(),
        };

        let cap_set = capability_set.clone();

        let mut client =
            AlpineClient::connect(local_addr, remote_addr, identity, cap_set, credentials).await?;

        client.start_stream(StreamProfile::auto())?;

        let channel_format = select_format(capabilities);

        Ok(Self {
            client,
            channel_format,
            priority: 0,
            stream_id: "levels".to_string(),
            stream_kind: "alpine_levels".to_string(),
        })
    }

    fn send_frame(&mut self, values: &[u8]) -> Result<(), alpine_protocol_sdk::AlpineSdkError> {
        // Encode embedded runtime stream frame (type=alpine_frame, session_id, stream_id/kind, payload bstr).
        #[derive(serde::Serialize)]
        struct EmbeddedFrame<'a> {
            #[serde(rename = "type")]
            msg_type: &'a str,
            session_id: &'a str,
            stream_id: &'a str,
            stream_kind: &'a str,
            #[serde(with = "serde_bytes")]
            payload: &'a [u8],
        }

        let session_id = self
            .client
            .session_id()
            .ok_or_else(|| alpine_protocol_sdk::AlpineSdkError::Io("missing session id".into()))?;
        let frame = EmbeddedFrame {
            msg_type: "alpine_frame",
            session_id: &session_id,
            stream_id: &self.stream_id,
            stream_kind: &self.stream_kind,
            payload: values,
        };
        let bytes = serde_cbor::to_vec(&frame)
            .map_err(|e| alpine_protocol_sdk::AlpineSdkError::Io(format!("encode: {}", e)))?;

        let local = self.client.local_addr();
        let remote = self.client.remote_addr();
        let bind = SocketAddr::new(local.ip(), 0);
        let sock = std::net::UdpSocket::bind(bind)
            .map_err(|e| alpine_protocol_sdk::AlpineSdkError::Io(format!("bind: {}", e)))?;
        sock.connect(remote)
            .map_err(|e| alpine_protocol_sdk::AlpineSdkError::Io(format!("connect: {}", e)))?;
        let sent = sock
            .send(&bytes)
            .map_err(|e| alpine_protocol_sdk::AlpineSdkError::Io(format!("send: {}", e)))?;
        println!(
            "[ALPINE][STREAM][TX] bytes={} channels={} local={} remote={}",
            sent,
            values.len(),
            sock.local_addr().unwrap_or(bind),
            remote
        );
        Ok(())
    }
}

fn select_format(capabilities: &CapabilityInfo) -> ChannelFormat {
    let candidate = capabilities.channel_formats.iter().find_map(|format| {
        match format.to_lowercase().as_str() {
            "u8" => Some(ChannelFormat::U8),
            "u16" => Some(ChannelFormat::U16),
            _ => None,
        }
    });
    candidate.unwrap_or(ChannelFormat::U8)
}

fn format_name(format: &ChannelFormat) -> &'static str {
    match format {
        ChannelFormat::U8 => "u8",
        ChannelFormat::U16 => "u16",
    }
}
