use std::env;
use std::path::PathBuf;
use std::time::Duration;

use alpine_protocol_sdk::{
    TrustConfig, TrustError, TrustView, load_cached_trust_view, load_or_fetch_trust_view,
    parse_root_pubkey_base64,
};

const DEFAULT_ATTESTERS_URL: &str = "http://localhost:3000/attesters/latest";
const ENV_ATTESTERS_URL: &str = "ALPINE_ATTESTERS_URL";
const ENV_ROOT_PUBKEY_B64: &str = "ALPINE_ROOT_PUBKEY_B64";
const ENV_ATTESTERS_OVERRIDE: &str = "ALPINE_ATTESTERS_OVERRIDE";

#[derive(Debug, Default, Clone)]
pub struct TrustOptions {
    pub bundle_url: Option<String>,
    pub root_pubkey_b64: Option<String>,
    pub override_path: Option<PathBuf>,
    pub timeout_ms: Option<u64>,
}

pub fn build_trust_config(opts: &TrustOptions) -> Result<TrustConfig, TrustError> {
    let bundle_url = opts
        .bundle_url
        .clone()
        .or_else(|| env::var(ENV_ATTESTERS_URL).ok())
        .unwrap_or_else(|| DEFAULT_ATTESTERS_URL.to_string());
    let root_pubkey_b64 = opts
        .root_pubkey_b64
        .clone()
        .or_else(|| env::var(ENV_ROOT_PUBKEY_B64).ok());
    let override_path = opts
        .override_path
        .clone()
        .or_else(|| env::var(ENV_ATTESTERS_OVERRIDE).ok().map(PathBuf::from));

    let mut config = TrustConfig::new(bundle_url);
    if let Some(root_pubkey_b64) = root_pubkey_b64 {
        let root_pubkey = parse_root_pubkey_base64(&root_pubkey_b64)?;
        config = config.with_root_pubkey(root_pubkey);
    }
    if let Some(override_path) = override_path {
        config = config.with_override_path(override_path);
    }
    if let Some(timeout_ms) = opts.timeout_ms {
        config = config.with_timeout(Duration::from_millis(timeout_ms));
    }
    Ok(config)
}

pub async fn load_latest_trust_view(opts: &TrustOptions) -> Result<TrustView, TrustError> {
    let config = build_trust_config(opts)?;
    load_or_fetch_trust_view(&config).await
}

pub fn load_cached_trust_view_only(opts: &TrustOptions) -> Result<TrustView, TrustError> {
    let config = build_trust_config(opts)?;
    load_cached_trust_view(&config)
}
