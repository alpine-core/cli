use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use alpine_protocol_sdk::NodeCredentials;
use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};
use directories::ProjectDirs;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

const SIGNING_PEM: &str = "signing_key.pem";
const VERIFYING_PEM: &str = "verifying_cert.pem";

pub fn load_or_generate() -> anyhow::Result<(NodeCredentials, bool)> {
    let signing_path = signing_key_path();
    let verifying_path = verifying_key_path();

    if signing_path.exists() && verifying_path.exists() {
        let signing = NodeCredentials::load_signing_pem(signing_path.to_string_lossy().as_ref())
            .map_err(|err| anyhow!("failed to load signing key: {}", err))?;
        let verifying =
            NodeCredentials::load_verifying_pem(verifying_path.to_string_lossy().as_ref())
                .map_err(|err| anyhow!("failed to load verifying key: {}", err))?;
        Ok((NodeCredentials { signing, verifying }, false))
    } else {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = VerifyingKey::from(&signing);

        let signing_der = signing
            .to_pkcs8_der()
            .map_err(|err| anyhow!("failed to encode signing key: {}", err))?;
        write_pem(&signing_path, "PRIVATE KEY", signing_der.as_bytes())?;
        write_pem(
            &verifying_path,
            "CERTIFICATE",
            verifying
                .to_public_key_der()
                .map_err(|err| anyhow!("failed to encode verifying key: {}", err))?
                .as_bytes(),
        )?;

        let credentials = NodeCredentials { signing, verifying };
        Ok((credentials, true))
    }
}

pub fn load_from_paths(
    signing_path: &Path,
    verifying_path: &Path,
) -> anyhow::Result<NodeCredentials> {
    let signing = NodeCredentials::load_signing_pem(signing_path.to_string_lossy().as_ref())
        .map_err(|err| anyhow!("failed to load signing key: {}", err))?;
    let verifying = NodeCredentials::load_verifying_pem(verifying_path.to_string_lossy().as_ref())
        .map_err(|err| anyhow!("failed to load verifying key: {}", err))?;
    Ok(NodeCredentials { signing, verifying })
}

fn write_pem(path: &Path, label: &str, data: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    let encoded = general_purpose::STANDARD.encode(data);
    writeln!(file, "-----BEGIN {}-----", label)?;
    for chunk in encoded.as_bytes().chunks(64) {
        writeln!(file, "{}", std::str::from_utf8(chunk)?)?;
    }
    writeln!(file, "-----END {}-----", label)?;
    Ok(())
}

fn config_dir() -> PathBuf {
    if let Some(proj) = ProjectDirs::from("io", "alpine", "alpine-cli") {
        proj.config_dir().join("identity")
    } else {
        PathBuf::from(".").join("identity")
    }
}

pub fn signing_key_path() -> PathBuf {
    config_dir().join(SIGNING_PEM)
}

pub fn verifying_key_path() -> PathBuf {
    config_dir().join(VERIFYING_PEM)
}

pub fn trusted_device_dir() -> PathBuf {
    config_dir().join("trusted_devices")
}

pub fn trusted_device_key_path(device_id: &str) -> PathBuf {
    trusted_device_dir().join(format!("{}.pub", device_id))
}

pub fn store_trusted_device_key(device_id: &str, pubkey: &[u8]) -> anyhow::Result<()> {
    let dir = trusted_device_dir();
    std::fs::create_dir_all(&dir)?;
    let path = trusted_device_key_path(device_id);
    std::fs::write(&path, pubkey)?;
    Ok(())
}

pub fn load_trusted_device_key(device_id: &str) -> Option<Vec<u8>> {
    let path = trusted_device_key_path(device_id);
    if let Ok(bytes) = std::fs::read(&path) {
        Some(bytes)
    } else {
        None
    }
}
