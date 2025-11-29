use anyhow::Result;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng; // brings .encode() into scope

use crate::keystore;

/// Ensure device identity exists; returns (sk, vk).
pub fn ensure_device_identity() -> Result<(SigningKey, VerifyingKey)> {
    if let Ok(pair) = keystore::load() {
        return Ok(pair);
    }
    // With ed25519-dalek=2.2 + feature rand_core, this exists:
    let sk = SigningKey::generate(&mut OsRng);
    let vk = VerifyingKey::from(&sk);
    keystore::save(&sk, &vk)?;
    Ok((sk, vk))
}

/// Peer ID (demo): base64 of verifying key bytes
pub fn peer_id_b64() -> Result<String> {
    let (_sk, vk) = ensure_device_identity()?;
    Ok(base64::engine::general_purpose::STANDARD.encode(vk.to_bytes()))
}

pub fn public_key_hex() -> Result<String> {
    let (_sk, vk) = ensure_device_identity()?;
    Ok(hex::encode(vk.to_bytes()))
}
