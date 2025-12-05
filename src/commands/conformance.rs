use crate::device_cache::{self, DeviceRecord};
use crate::discovery::run_discovery;
use crate::identity_store;
use crate::parse_socket;
use alpine_protocol_sdk::{AlpineClient, CapabilitySet, DeviceIdentity};
use anyhow::{Context, Result, anyhow};
use clap::Args;
use rand::RngCore;
use serde::Serialize;
use serde_bytes;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{Duration, sleep, timeout};

#[derive(Debug, Args)]
pub struct ConformanceArgs {
    /// Target ALPINE device address (accepts ip:port or udp://ip:port)
    pub target: String,
    /// Optional local bind address (default 0.0.0.0:0)
    #[arg(long)]
    pub local: Option<String>,
}

struct TestResult {
    name: &'static str,
    passed: bool,
    detail: String,
}

pub async fn run(args: ConformanceArgs) -> Result<()> {
    let remote = parse_socket(&args.target)?;
    let local = args
        .local
        .as_deref()
        .map(parse_socket)
        .transpose()?
        .unwrap_or_else(default_local_addr);

    let mut results = Vec::new();

    let (_discovery_outcome, cached_record) = match run_discovery(remote).await {
        Ok(outcome) => {
            let record = device_cache::DeviceRecord::from_discovery(&outcome);
            device_cache::upsert_device(&outcome).ok();
            results.push(TestResult {
                name: "valid_discovery",
                passed: true,
                detail: "reply received".into(),
            });
            (outcome, record)
        }
        Err(err) => {
            results.push(TestResult {
                name: "valid_discovery",
                passed: false,
                detail: format!("discovery failed: {}", err),
            });
            return report(results);
        }
    };

    results.push(test_malformed_discovery(remote, local).await?);
    results.push(test_valid_handshake(remote, &cached_record).await?);
    results.push(test_malformed_session_init(remote, local).await?);
    results.push(test_discovery_during_handshake(remote, &cached_record).await?);
    results.push(test_session_ack_fields(remote, &cached_record).await?);

    report(results)
}

async fn test_malformed_discovery(remote: SocketAddr, local: SocketAddr) -> Result<TestResult> {
    let socket = UdpSocket::bind(local).await?;
    let payload = serde_cbor::to_vec(&json!({
        "type": "alpine_discover",
        "version": "1.0",
        "requested": []
    }))?;
    socket.send_to(&payload, remote).await?;
    let mut buf = [0u8; 512];
    let pass = timeout(Duration::from_millis(500), socket.recv_from(&mut buf))
        .await
        .is_err();
    Ok(TestResult {
        name: "malformed_discovery",
        passed: pass,
        detail: if pass {
            "device ignored malformed payload".into()
        } else {
            "device replied to malformed discovery".into()
        },
    })
}

async fn test_valid_handshake(remote: SocketAddr, record: &DeviceRecord) -> Result<TestResult> {
    perform_handshake(remote, record)
        .await
        .map(|_| TestResult {
            name: "valid_session_init",
            passed: true,
            detail: "handshake succeeded".into(),
        })
        .or_else(|err| {
            Ok(TestResult {
                name: "valid_session_init",
                passed: false,
                detail: format!("handshake failed: {}", err),
            })
        })
}

async fn test_malformed_session_init(remote: SocketAddr, local: SocketAddr) -> Result<TestResult> {
    let socket = UdpSocket::bind(local).await?;
    let payload = serde_cbor::to_vec(&json!({
        "type": "session_init",
        "controller_nonce": "",
        "session_id": "00000000-0000-0000-0000-000000000000"
    }))?;
    socket.send_to(&payload, remote).await?;
    let mut buf = [0u8; 512];
    let pass = timeout(Duration::from_millis(800), socket.recv_from(&mut buf))
        .await
        .is_err();
    Ok(TestResult {
        name: "malformed_session_init",
        passed: pass,
        detail: if pass {
            "no SessionAck returned".into()
        } else {
            "device responded to malformed SessionInit".into()
        },
    })
}

async fn test_discovery_during_handshake(
    remote: SocketAddr,
    record: &DeviceRecord,
) -> Result<TestResult> {
    let record_clone = record.clone();
    let handshake = tokio::spawn(async move { perform_handshake(remote, &record_clone).await });
    sleep(Duration::from_millis(30)).await;
    send_valid_discovery(remote).await?;
    let pass = handshake.await.unwrap_or_else(|e| Err(anyhow!(e))).is_ok();
    Ok(TestResult {
        name: "discovery_during_handshake",
        passed: pass,
        detail: if pass {
            "handshake survived concurrent discovery".into()
        } else {
            "handshake aborted when discovery sent".into()
        },
    })
}

async fn test_session_ack_fields(remote: SocketAddr, record: &DeviceRecord) -> Result<TestResult> {
    match perform_handshake(remote, record).await {
        Ok(session_id) => Ok(TestResult {
            name: "session_ack_correctness",
            passed: !session_id.is_empty(),
            detail: format!("session_id={}", session_id),
        }),
        Err(err) => Ok(TestResult {
            name: "session_ack_correctness",
            passed: false,
            detail: err.to_string(),
        }),
    }
}

async fn perform_handshake(remote: SocketAddr, record: &DeviceRecord) -> Result<String> {
    let (credentials, _) =
        identity_store::load_or_generate().context("failed to load/generate identity")?;
    let identity = DeviceIdentity {
        device_id: record.device_id.clone(),
        manufacturer_id: record.manufacturer_id.clone(),
        model_id: record.model_id.clone(),
        hardware_rev: record.hardware_rev.clone(),
        firmware_rev: record.firmware_rev.clone(),
    };
    let capabilities = record
        .capabilities
        .as_ref()
        .map(|value| serde_json::from_value::<CapabilitySet>(value.clone()).unwrap_or_default())
        .unwrap_or_default();
    let local_addr = record
        .discovery_local_addr
        .as_deref()
        .and_then(|addr| addr.parse().ok())
        .unwrap_or_else(default_local_addr);
    let client_nonce = record
        .client_nonce
        .clone()
        .ok_or_else(|| anyhow!("missing cached client nonce"))?;
    let client = AlpineClient::connect_with_nonce(
        local_addr,
        remote,
        identity,
        capabilities,
        credentials,
        client_nonce,
    )
    .await?;
    let session_id = client.session_id().unwrap_or_default();
    client.close().await;
    Ok(session_id)
}

async fn send_valid_discovery(remote: SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind(default_local_addr()).await?;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    #[derive(Serialize)]
    struct Frame<'a> {
        #[serde(rename = "type")]
        message_type: &'static str,
        version: &'static str,
        #[serde(with = "serde_bytes")]
        client_nonce: &'a [u8],
        requested: &'a [&'static str],
    }
    let frame = Frame {
        message_type: "alpine_discover",
        version: "1.0",
        client_nonce: &nonce,
        requested: &["alpine-control"],
    };
    let payload = serde_cbor::to_vec(&frame)?;
    socket.send_to(&payload, remote).await?;
    Ok(())
}

fn default_local_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn report(results: Vec<TestResult>) -> Result<()> {
    let mut all_pass = true;
    for result in &results {
        let status = if result.passed { "PASS" } else { "FAIL" };
        println!("[{}] {} - {}", status, result.name, result.detail);
        if !result.passed {
            all_pass = false;
        }
    }
    if all_pass {
        println!("ALPINE conformance: PASS");
        Ok(())
    } else {
        Err(anyhow!("ALPINE conformance failed"))
    }
}
