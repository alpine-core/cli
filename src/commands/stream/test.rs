use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use alpine_protocol_sdk::{
    AlpineClient, CapabilitySet, DeviceIdentity, HandshakeContext, StreamProfile,
};
use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::{signal, time};

use crate::{
    device_cache::DeviceRecord,
    identity_store,
    selector::{DeviceSelectorArgs, resolve_device},
    stream_session::{self, StoredSession},
};

#[derive(Debug, Clone, Args)]
pub struct StreamTestArgs {
    #[command(flatten)]
    pub selector: DeviceSelectorArgs,

    /// DMX universe number or identifier (e.g. "1" or "u1").
    #[arg(long, default_value = "1")]
    pub universe: String,

    /// Channel overrides (1-indexed). Example: --ch 1=255 --ch 2=0
    #[arg(long = "ch", value_parser = parse_ch_pair)]
    pub ch_pairs: Vec<(usize, u8)>,

    /// Interval between frames in milliseconds.
    #[arg(long, default_value = "33")]
    pub interval_ms: u64,
}

#[derive(Debug, Clone)]
struct CapabilityInfo {
    streaming_supported: bool,
    encryption_supported: bool,
    max_channels: usize,
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

    let universe = args.universe.clone();
    let sender = SessionSender::new(&record, &session, &capability_set, &universe).await?;
    let sender = Arc::new(sender);

    let values = build_frame(&capabilities, &args)?;

    {
        log_start(
            &universe,
            &values,
            args.interval_ms,
            sender.local_addr(),
            sender.remote_addr(),
        );
    }

    let mut ticker = time::interval(Duration::from_millis(args.interval_ms));
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    let mut heartbeat = time::interval(Duration::from_millis(2000));
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(err) = sender.send_frame(&values).await {
                    eprintln!("[ALPINE][STREAM][ERROR] frame send failed: {}", err);
                    break;
                }
            }
            _ = heartbeat.tick() => {
                println!("[ALPINE][STREAM] still sending...");
            }
            _ = signal::ctrl_c() => {
                println!("[ALPINE][STREAM] Ctrl+C received; stopping.");
                break;
            }
        }
    }

    Ok(())
}

fn build_frame(caps: &CapabilityInfo, args: &StreamTestArgs) -> Result<Vec<u8>> {
    let mut values = vec![0u8; caps.max_channels.max(512).min(512)];
    for (idx, val) in args.ch_pairs.iter() {
        if *idx == 0 || *idx > values.len() {
            bail!("channel index {} out of range 1..={}", idx, values.len());
        }
        values[idx - 1] = *val;
    }
    Ok(values)
}

fn load_capability_set(value: Option<&Value>) -> CapabilitySet {
    if let Some(value) = value {
        serde_json::from_value(value.clone()).unwrap_or_default()
    } else {
        CapabilitySet::default()
    }
}

impl CapabilityInfo {
    fn from_set(set: &CapabilitySet) -> Self {
        Self {
            streaming_supported: set.streaming_supported,
            encryption_supported: set.encryption_supported,
            max_channels: set.max_channels as usize,
        }
    }
}

struct SessionSender {
    client: AlpineClient,
    stream_id: String,
    stream_kind: String,
    socket: Arc<UdpSocket>,
}

impl SessionSender {
    async fn new(
        record: &DeviceRecord,
        session: &StoredSession,
        capability_set: &CapabilitySet,
        stream_id: &str,
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

        let mut ctx = HandshakeContext::default();
        if let Some(pk) = record
            .trusted_device_pubkey
            .clone()
            .or_else(|| record.device_identity_pubkey.clone())
        {
            ctx = ctx.with_device_identity_pubkey(pk);
        } else {
            eprintln!(
                "[ALPINE][TRUST][WARN] no trusted device identity found for {}; validation may fail",
                record.device_id
            );
        }

        let client_nonce = record.client_nonce.clone().ok_or_else(|| {
            anyhow!("missing cached client nonce; rerun alpine discover/handshake")
        })?;

        // Bind once and reuse for handshake + frames.
        let std_sock = std::net::UdpSocket::bind(SocketAddr::new(local_addr.ip(), 0))
            .map_err(|e| alpine_protocol_sdk::AlpineSdkError::Io(format!("bind: {}", e)))?;
        std_sock
            .connect(remote_addr)
            .map_err(|e| alpine_protocol_sdk::AlpineSdkError::Io(format!("connect: {}", e)))?;
        std_sock.set_nonblocking(true).map_err(|e| {
            alpine_protocol_sdk::AlpineSdkError::Io(format!("set_nonblocking: {}", e))
        })?;
        let tokio_sock = tokio::net::UdpSocket::from_std(std_sock).map_err(|e| {
            alpine_protocol_sdk::AlpineSdkError::Io(format!("to tokio socket: {}", e))
        })?;

        let mut client = AlpineClient::connect_with_socket_and_nonce(
            tokio_sock,
            remote_addr,
            identity,
            cap_set,
            credentials,
            client_nonce,
            ctx,
        )
        .await?;

        let socket = client.udp_socket();

        client.start_stream(StreamProfile::auto())?;

        Ok(Self {
            client,
            stream_id: stream_id.to_string(),
            stream_kind: "alpine_levels".to_string(),
            socket,
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    fn remote_addr(&self) -> SocketAddr {
        self.client.remote_addr()
    }

    async fn send_frame(&self, values: &[u8]) -> Result<(), alpine_protocol_sdk::AlpineSdkError> {
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

        self.socket
            .send(&bytes)
            .await
            .map_err(|e| alpine_protocol_sdk::AlpineSdkError::Io(format!("send: {}", e)))?;
        Ok(())
    }
}

fn parse_ch_pair(s: &str) -> Result<(usize, u8), String> {
    let parts: Vec<_> = s.split('=').collect();
    if parts.len() != 2 {
        return Err("expected format N=V".into());
    }
    let idx: usize = parts[0]
        .trim()
        .parse()
        .map_err(|_| "channel index must be a number".to_string())?;
    let val: u8 = parts[1]
        .trim()
        .parse()
        .map_err(|_| "channel value must be 0-255".to_string())?;
    if idx == 0 || idx > 512 {
        return Err("channel index must be 1..=512".into());
    }
    Ok((idx, val))
}

fn log_start(
    universe: &str,
    values: &[u8],
    interval_ms: u64,
    local: SocketAddr,
    remote: SocketAddr,
) {
    let mut parts = Vec::new();
    for i in 0..values.len().min(8) {
        parts.push(format!("CH{}={}", i + 1, values[i]));
    }
    println!(
        "[ALPINE][STREAM] universe={} local={} remote={} {}",
        universe,
        local,
        remote,
        parts.join(" ")
    );
    println!(
        "[ALPINE][STREAM] sending every {}ms (Ctrl+C to stop)",
        interval_ms
    );
}
