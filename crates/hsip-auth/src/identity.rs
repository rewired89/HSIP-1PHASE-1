use anyhow::Result;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::keystore;

// Initialize or retrieve device identity keypair
pub fn ensure_device_identity() -> Result<(SigningKey, VerifyingKey)> {
    match keystore::load() {
        Ok(existing_keypair) => Ok(existing_keypair),
        Err(_) => create_and_store_new_identity(),
    }
}

fn create_and_store_new_identity() -> Result<(SigningKey, VerifyingKey)> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    keystore::save(&signing_key, &verifying_key)?;
    Ok((signing_key, verifying_key))
}

// Generate base64-encoded peer identifier from verifying key
pub fn peer_id_b64() -> Result<String> {
    let (_signing_key, verifying_key) = ensure_device_identity()?;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(verifying_key.to_bytes());
    Ok(encoded)
}

// Generate hex-encoded public key string
pub fn public_key_hex() -> Result<String> {
    let (_signing_key, verifying_key) = ensure_device_identity()?;
    Ok(hex::encode(verifying_key.to_bytes()))
}
