#![allow(dead_code)]

use std::fs;
use clap::Args;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hsip_core::identity::{generate_keypair, peer_id_from_pubkey, vk_to_hex};
use hsip_core::keystore::{load_keypair, save_keypair};
use serde::{Deserialize, Serialize};

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

// -----------------------------------------------------------------------------
// Public (main.rs compatible)
// -----------------------------------------------------------------------------

pub fn rotate_key_make_rebind() -> (SigningKey, VerifyingKey, RebindProof) {
    let (old_sk, old_vk) = load_keypair().expect("load identity");
    let (new_sk, new_vk) = generate_keypair();

    let msg = new_vk.to_bytes();
    let sig = old_sk.sign(&msg);
    save_keypair(&new_sk, &new_vk).expect("save keystore");

    let proof = RebindProof {
        old_peer_id: peer_id_from_pubkey(&old_vk),
        new_peer_id: peer_id_from_pubkey(&new_vk),
        new_vk_hex: vk_to_hex(&new_vk),
        sig_hex: hex::encode(sig.to_bytes()),
    };

    (new_sk, new_vk, proof)
}

pub fn revoke_current(reason: String) -> RevocationRecord {
    let (sk, vk) = load_keypair().expect("load identity");
    let ts = now_ms();

    let mut msg = reason.as_bytes().to_vec();
    msg.extend_from_slice(&ts.to_le_bytes());
    let sig = sk.sign(&msg);

    RevocationRecord {
        peer_id: peer_id_from_pubkey(&vk),
        reason,
        ts_ms: ts,
        sig_hex: hex::encode(sig.to_bytes()),
    }
}

pub fn write_json<P: AsRef<std::path::Path>, T: serde::Serialize>(
    path: P,
    value: &T,
) -> Result<(), String> {
    let s = serde_json::to_string_pretty(value).unwrap();
    fs::write(path, s).map_err(|e| format!("write json: {e}"))
}

// -----------------------------------------------------------------------------
// Private
// -----------------------------------------------------------------------------

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}
