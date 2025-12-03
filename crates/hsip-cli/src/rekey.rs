#![allow(dead_code)]

use clap::Args;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hsip_core::identity::{generate_keypair, peer_id_from_pubkey, vk_to_hex};
use hsip_core::keystore::{load_keypair, save_keypair};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Args, Debug)]
pub struct RotateArgs {
    #[arg(long, default_value = "rebind.json")]
    pub out: String,
}

#[derive(Args, Debug)]
pub struct RevokeArgs {
    #[arg(long, default_value = "revoked")]
    pub reason: String,
    #[arg(long, default_value = "revocation.json")]
    pub out: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RebindProof {
    pub old_peer_id: String,
    pub new_peer_id: String,
    pub new_vk_hex: String,
    pub sig_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub peer_id: String,
    pub reason: String,
    pub ts_ms: u64,
    pub sig_hex: String,
}

// Generate new keypair and create cryptographic rebinding proof
pub fn rotate_key_make_rebind() -> (SigningKey, VerifyingKey, RebindProof) {
    let (previous_signing_key, previous_verifying_key) = 
        load_keypair().expect("Failed to load existing identity");
    let (replacement_signing_key, replacement_verifying_key) = generate_keypair();

    let binding_message = replacement_verifying_key.to_bytes();
    let binding_signature = previous_signing_key.sign(&binding_message);
    
    save_keypair(&replacement_signing_key, &replacement_verifying_key)
        .expect("Failed to persist new keystore");

    let rebind_proof = RebindProof {
        old_peer_id: peer_id_from_pubkey(&previous_verifying_key),
        new_peer_id: peer_id_from_pubkey(&replacement_verifying_key),
        new_vk_hex: vk_to_hex(&replacement_verifying_key),
        sig_hex: hex::encode(binding_signature.to_bytes()),
    };

    (replacement_signing_key, replacement_verifying_key, rebind_proof)
}

// Create signed revocation record for current identity
pub fn revoke_current(revocation_reason: String) -> RevocationRecord {
    let (signing_key, verifying_key) = 
        load_keypair().expect("Failed to load identity for revocation");
    let revocation_timestamp = current_timestamp_ms();

    let mut signed_payload = revocation_reason.as_bytes().to_vec();
    signed_payload.extend_from_slice(&revocation_timestamp.to_le_bytes());
    let revocation_signature = signing_key.sign(&signed_payload);

    RevocationRecord {
        peer_id: peer_id_from_pubkey(&verifying_key),
        reason: revocation_reason,
        ts_ms: revocation_timestamp,
        sig_hex: hex::encode(revocation_signature.to_bytes()),
    }
}

// Serialize value to JSON and write to file
pub fn write_json<P: AsRef<std::path::Path>, T: serde::Serialize>(
    file_path: P,
    data: &T,
) -> Result<(), String> {
    let json_string = serde_json::to_string_pretty(data).unwrap();
    fs::write(file_path, json_string).map_err(|e| format!("JSON write failed: {e}"))
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock error")
        .as_millis() as u64
}
