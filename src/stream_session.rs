use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub device_id: String,
    pub session_id: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub profile_config_id: Option<String>,
    pub created_at: u64,
    pub signing_key: String,
    pub verifying_key: String,
}

pub fn load_session(device_id: &str) -> anyhow::Result<Option<StoredSession>> {
    let path = session_file_path();
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)?;
    let sessions: Vec<StoredSession> = serde_json::from_str(&contents)?;
    Ok(sessions
        .into_iter()
        .find(|record| record.device_id == device_id))
}

pub fn save_session(session: &StoredSession) -> anyhow::Result<()> {
    let mut sessions = load_all_sessions()?;
    if let Some(existing) = sessions
        .iter_mut()
        .find(|record| record.device_id == session.device_id)
    {
        *existing = session.clone();
    } else {
        sessions.push(session.clone());
    }
    write_sessions(&sessions)?;
    Ok(())
}

pub fn load_all_sessions() -> anyhow::Result<Vec<StoredSession>> {
    let path = session_file_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = fs::read_to_string(&path)?;
    let sessions: Vec<StoredSession> = serde_json::from_str(&contents)?;
    Ok(sessions)
}

fn write_sessions(sessions: &[StoredSession]) -> anyhow::Result<()> {
    let path = session_file_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let serialized = serde_json::to_string_pretty(sessions)?;
    fs::write(path, serialized)?;
    Ok(())
}

fn session_file_path() -> PathBuf {
    if let Some(proj) = ProjectDirs::from("io", "alpine", "alpine-cli") {
        proj.config_dir().join("sessions.json")
    } else if let Ok(current) = env::current_dir() {
        current.join(".alpine-sessions.json")
    } else {
        env::temp_dir().join("alpine-sessions.json")
    }
}

pub fn delete_session(device_id: &str) -> anyhow::Result<bool> {
    let mut sessions = load_all_sessions()?;
    let initial_len = sessions.len();
    sessions.retain(|entry| entry.device_id != device_id);
    let removed = sessions.len() < initial_len;
    if removed {
        write_sessions(&sessions)?;
    }
    Ok(removed)
}

pub fn clear_sessions() -> anyhow::Result<()> {
    write_sessions(&[])
}

pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
