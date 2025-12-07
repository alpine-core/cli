use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use alpine_protocol_sdk::{AlpineClient, AlpineSdkError, CapabilitySet, DeviceIdentity};
use anyhow::Result;
use clap::Args;
use serde_json::Value;

use crate::{
    device_cache::DeviceRecord,
    identity_store,
    selector::{DeviceSelectorArgs, resolve_device},
    stream_session::{self, StoredSession, now_epoch_secs},
};

#[derive(Debug, Clone, Args)]
pub struct HandshakeArgs {
    #[command(flatten)]
    pub selector: DeviceSelectorArgs,
    /// Override handshake timeout in milliseconds (default 7000ms).
    #[arg(long, default_value_t = 7000)]
    pub handshake_timeout: u64,
    /// Print CBOR decode tree for handshake messages.
    #[arg(long)]
    pub debug_cbor: bool,
}

pub async fn run(args: HandshakeArgs) -> Result<(), AlpineSdkError> {
    let resolved =
        resolve_device(&args.selector).map_err(|err| AlpineSdkError::Internal(err.to_string()))?;
    let record = resolved.record.as_ref().cloned().ok_or_else(|| {
        AlpineSdkError::InvalidPhaseTransition("device missing from cache".into())
    })?;

    let existing_session = stream_session::load_session(&record.device_id)
        .map_err(|err| AlpineSdkError::Internal(err.to_string()))?;
    if existing_session.is_some() {
        return Err(AlpineSdkError::HandshakeAlreadyInProgress);
    }

    let (credentials, generated) = identity_store::load_or_generate()
        .map_err(|err| AlpineSdkError::Internal(err.to_string()))?;
    let identity = build_identity(&record);
    let capabilities = parse_capabilities(record.capabilities.as_ref());

    let local_addr = record
        .discovery_local_addr
        .as_ref()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
        .map(|addr| SocketAddr::new(addr.ip(), 0))
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let remote_addr = resolved.addr;

    let client_nonce = record
        .client_nonce
        .clone()
        .ok_or(AlpineSdkError::MissingClientNonce)?;

    let mut context = alpine_protocol_sdk::HandshakeContext::default()
        .with_recv_timeout(Duration::from_millis(args.handshake_timeout))
        .with_debug_cbor(args.debug_cbor);
    if let Some(pubkey) = record.device_identity_pubkey.clone() {
        context = context.with_device_identity_pubkey(pubkey);
    }

    let client = AlpineClient::connect_with_context_and_nonce(
        local_addr,
        remote_addr,
        identity,
        capabilities,
        credentials.clone(),
        client_nonce.clone(),
        context,
    )
    .await?;

    let session_id = client.session_id().unwrap_or_else(|| "unknown".to_string());

    // TOFU: persist device identity pubkey if present and not already trusted.
    if let Some(pubkey) = record.device_identity_pubkey.clone() {
        if identity_store::load_trusted_device_key(&record.device_id).is_none() {
            if let Err(err) = identity_store::store_trusted_device_key(&record.device_id, &pubkey) {
                eprintln!(
                    "[ALPINE][TRUST][WARN] failed to store device identity for {}: {}",
                    record.device_id, err
                );
            } else {
                println!(
                    "[ALPINE][TRUST] new device identity trusted (TOFU): {}",
                    record.device_id
                );
            }
        }
    }

    stream_session::save_session(&StoredSession {
        device_id: record.device_id.clone(),
        session_id: session_id.clone(),
        local_addr: client.local_addr().to_string(),
        remote_addr: client.remote_addr().to_string(),
        profile_config_id: None,
        created_at: now_epoch_secs(),
        signing_key: identity_store::signing_key_path()
            .to_string_lossy()
            .to_string(),
        verifying_key: identity_store::verifying_key_path()
            .to_string_lossy()
            .to_string(),
    })
    .map_err(|err| AlpineSdkError::Internal(err.to_string()))?;

    if generated {
        println!("Generated new ALPINE client identity");
    }

    client.close().await;

    println!("Handshake successful");
    println!("Device: {} ({})", record.device_id, record.model_id);
    println!("Protocol: ALPINE {}", record.alpine_version);
    println!("Encryption: enabled");
    println!("Session ID: {}", session_id);

    Ok(())
}

fn build_identity(record: &DeviceRecord) -> DeviceIdentity {
    DeviceIdentity {
        device_id: record.device_id.clone(),
        manufacturer_id: record.manufacturer_id.clone(),
        model_id: record.model_id.clone(),
        hardware_rev: record.hardware_rev.clone(),
        firmware_rev: record.firmware_rev.clone(),
    }
}

fn parse_capabilities(value: Option<&Value>) -> CapabilitySet {
    if let Some(value) = value {
        serde_json::from_value(value.clone()).unwrap_or_else(|_| CapabilitySet::default())
    } else {
        CapabilitySet::default()
    }
}
