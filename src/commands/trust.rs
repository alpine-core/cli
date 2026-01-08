use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::trust::{TrustOptions, load_cached_trust_view_only, load_latest_trust_view};

#[derive(Debug, Clone, Args)]
pub struct TrustArgs {
    /// Ops endpoint that serves the attesters bundle (GET /attesters/latest).
    #[arg(long, value_name = "url")]
    pub ops_url: Option<String>,
    /// Base64 root public key used to verify the bundle (Ed25519, 32 bytes).
    #[arg(long, value_name = "base64")]
    pub root_pubkey: Option<String>,
    /// Dev-only override bundle path (skips fetch).
    #[arg(long, value_name = "path")]
    pub override_bundle: Option<PathBuf>,
    /// Fetch timeout in milliseconds.
    #[arg(long, default_value_t = 5000)]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Subcommand)]
pub enum TrustCommand {
    /// Fetch and verify the latest attesters bundle (fallback to cache on failure).
    Update(TrustArgs),
    /// Show trust status from the cached bundle.
    Status(TrustArgs),
}

pub async fn run(cmd: TrustCommand) -> anyhow::Result<()> {
    match cmd {
        TrustCommand::Update(args) => {
            let opts = TrustOptions {
                bundle_url: args.ops_url,
                root_pubkey_b64: args.root_pubkey,
                override_path: args.override_bundle,
                timeout_ms: Some(args.timeout_ms),
            };
            let view = load_latest_trust_view(&opts).await?;
            print_trust_view("latest", &view);
        }
        TrustCommand::Status(args) => {
            let opts = TrustOptions {
                bundle_url: args.ops_url,
                root_pubkey_b64: args.root_pubkey,
                override_path: args.override_bundle,
                timeout_ms: Some(args.timeout_ms),
            };
            let view = load_cached_trust_view_only(&opts)?;
            print_trust_view("cached", &view);
        }
    }
    Ok(())
}

fn print_trust_view(label: &str, view: &alpine_protocol_sdk::TrustView) {
    println!(
        "attesters bundle ({}): issued_at={} expires_at={} source={:?} attesters={}",
        label,
        view.bundle.issued_at,
        view.bundle.expires_at,
        view.source,
        view.bundle.attesters.len()
    );
    for warning in &view.warnings {
        println!("[ALPINE][TRUST][WARN] {}", warning);
    }
}
