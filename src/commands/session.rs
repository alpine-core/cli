use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};

use crate::stream_session;

#[derive(Debug, Clone, Subcommand)]
pub enum SessionCommand {
    List,
    Clear(SessionClearArgs),
}

#[derive(Debug, Clone, Args)]
pub struct SessionClearArgs {
    /// Device ID to clear
    #[arg(long, value_name = "id")]
    pub id: Option<String>,
    /// Clear all sessions
    #[arg(long)]
    pub all: bool,
}

pub fn list() -> Result<()> {
    let sessions = stream_session::load_all_sessions()?;
    if sessions.is_empty() {
        println!("No active sessions stored.");
        return Ok(());
    }
    for session in sessions {
        println!(
            "{} @ {} (session {}) created at {}",
            session.device_id, session.remote_addr, session.session_id, session.created_at
        );
    }
    Ok(())
}

pub fn clear(args: SessionClearArgs) -> Result<()> {
    if args.all {
        stream_session::clear_sessions()?;
        println!("Cleared all stored sessions.");
        return Ok(());
    }
    let id = args
        .id
        .ok_or_else(|| anyhow!("--id is required unless --all is specified"))?;
    if stream_session::delete_session(&id)? {
        println!("Cleared session for {}", id);
    } else {
        println!("No session found for {}", id);
    }
    Ok(())
}
