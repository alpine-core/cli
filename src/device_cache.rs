use alpine_protocol_sdk::DiscoveryOutcome;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub manufacturer_id: String,
    pub model_id: String,
    pub hardware_rev: String,
    pub firmware_rev: String,
    pub alpine_version: String,
    pub mac: String,
    #[serde(default)]
    pub last_addr: Option<String>,
    #[serde(default)]
    pub discovery_local_addr: Option<String>,
    #[serde(default)]
    pub discovery_interface: Option<String>,
    #[serde(default)]
    pub client_nonce: Option<Vec<u8>>,
    #[serde(default)]
    pub device_identity_pubkey: Option<Vec<u8>>,
    #[serde(default)]
    pub trusted_device_pubkey: Option<Vec<u8>>,
    pub last_seen: u64,
    #[serde(default)]
    pub capabilities: Option<Value>,
}

impl DeviceRecord {
    pub fn from_discovery(outcome: &DiscoveryOutcome) -> Self {
        let last_seen = now_epoch_secs();
        Self {
            device_id: outcome.reply.device_id.clone(),
            manufacturer_id: outcome.reply.manufacturer_id.clone(),
            model_id: outcome.reply.model_id.clone(),
            hardware_rev: outcome.reply.hardware_rev.clone(),
            firmware_rev: outcome.reply.firmware_rev.clone(),
            alpine_version: outcome.reply.alpine_version.clone(),
            mac: outcome.reply.mac.clone(),
            last_addr: Some(outcome.peer.to_string()),
            discovery_local_addr: Some(outcome.local_addr.to_string()),
            discovery_interface: outcome.interface.clone(),
            last_seen,
            capabilities: serde_json::to_value(&outcome.reply.capabilities).ok(),
            client_nonce: Some(outcome.client_nonce.clone()),
            device_identity_pubkey: outcome.device_identity_pubkey.clone(),
            trusted_device_pubkey: None,
        }
    }

    pub fn matches_id(&self, query: &str) -> bool {
        self.device_id.eq_ignore_ascii_case(query)
    }

    pub fn matches_name(&self, query: &str) -> bool {
        self.model_id.eq_ignore_ascii_case(query)
    }

    pub fn matches_manufacturer(&self, query: &str) -> bool {
        self.manufacturer_id.eq_ignore_ascii_case(query)
    }
}

pub fn load_devices() -> anyhow::Result<Vec<DeviceRecord>> {
    let path = cache_file_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(&path)?;
    let devices = serde_json::from_str(&data)?;
    Ok(devices)
}

pub fn save_devices(devices: &[DeviceRecord]) -> anyhow::Result<()> {
    let path = cache_file_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let serialized = serde_json::to_string_pretty(devices)?;
    fs::write(&path, serialized)?;
    Ok(())
}

pub fn upsert_device(outcome: &DiscoveryOutcome) -> anyhow::Result<DeviceRecord> {
    let mut devices = load_devices()?;
    let record = DeviceRecord::from_discovery(outcome);
    if let Some(existing) = devices
        .iter_mut()
        .find(|entry| entry.device_id == record.device_id)
    {
        *existing = record.clone();
    } else {
        devices.push(record.clone());
    }
    save_devices(&devices)?;
    Ok(record)
}

fn cache_file_path() -> PathBuf {
    if let Some(proj) = ProjectDirs::from("io", "alpine", "alpine-cli") {
        proj.config_dir().join("devices.json")
    } else if let Ok(current) = env::current_dir() {
        current.join(".alpine-devices.json")
    } else {
        env::temp_dir().join("alpine-devices.json")
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
