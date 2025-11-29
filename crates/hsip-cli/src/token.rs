#![allow(unused_variables)]
#![allow(dead_code)]

use clap::{Args, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hsip_core::identity::{peer_id_from_pubkey, vk_to_hex};
use hsip_core::keystore::load_keypair;
use serde::{Deserialize, Serialize};
use std::fs;

/// Capability set (MVP)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Session,
    FileTransfer,
    Voice,
    Hello,
    Ping,
}

/// Canonical consent token (MVP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentToken {
    /// Issuer PeerId (derived from issuer vk)
    pub issuer: String,
    /// Legacy alias for compatibility
    pub issuer_peer: String,
    pub grantee: String,
    pub capabilities: Vec<Capability>,
    pub expires_at_ms: u64,
    pub sig_hex: String,
}

#[derive(Args, Debug)]
pub struct TokenIssueArgs {
    #[arg(long)]
    pub grantee: String,
    #[arg(long)]
    pub caps: String,
    #[arg(long)]
    pub ttl_ms: u64,
    #[arg(long, default_value = "token.json")]
    pub out: String,
}

#[derive(Args, Debug)]
pub struct TokenVerifyArgs {
    #[arg(long)]
    pub file: String,
    #[arg(long)]
    pub issuer_vk_hex: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum TokenCmd {
    Issue(TokenIssueArgs),
    Verify(TokenVerifyArgs),
}

// -----------------------------------------------------------------------------
// Public helpers expected by main.rs
// -----------------------------------------------------------------------------

pub fn issue_token(grantee: String, caps: Vec<Capability>, ttl_ms: u64) -> ConsentToken {
    let (sk, vk) = load_keypair().expect("load identity");
    issue_token_inner(&sk, &vk, &grantee, caps, ttl_ms).expect("issue token")
}

pub fn verify_token(tok: &ConsentToken, issuer_vk: &VerifyingKey) -> Result<(), String> {
    if now_ms() > tok.expires_at_ms {
        return Err("token expired".to_string());
    }

    #[derive(Serialize)]
    struct Canon<'a> {
        issuer: &'a str,
        grantee: &'a str,
        capabilities: &'a [Capability],
        expires_at_ms: u64,
    }
    let canon = Canon {
        issuer: &tok.issuer,
        grantee: &tok.grantee,
        capabilities: &tok.capabilities,
        expires_at_ms: tok.expires_at_ms,
    };
    let message = serde_json::to_vec(&canon).map_err(|e| format!("canon json: {e}"))?;

    let sig_hex = tok.sig_hex.strip_prefix("0x").unwrap_or(&tok.sig_hex);
    let sig_vec = hex::decode(sig_hex).map_err(|_| "bad sig hex".to_string())?;
    let sig_arr: [u8; 64] = sig_vec
        .try_into()
        .map_err(|_| "sig must be 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);

    issuer_vk
        .verify(&message, &sig)
        .map_err(|_| "bad signature".to_string())
}

// -----------------------------------------------------------------------------
// Internal
// -----------------------------------------------------------------------------

fn issue_token_inner(
    sk: &SigningKey,
    vk: &VerifyingKey,
    grantee: &str,
    caps: Vec<Capability>,
    ttl_ms: u64,
) -> Result<ConsentToken, String> {
    let issuer_pid = peer_id_from_pubkey(vk);
    let expires_at_ms = now_ms().saturating_add(ttl_ms);

    #[derive(Serialize)]
    struct Canon<'a> {
        issuer: &'a str,
        grantee: &'a str,
        capabilities: &'a [Capability],
        expires_at_ms: u64,
    }
    let canon = Canon {
        issuer: &issuer_pid,
        grantee,
        capabilities: &caps,
        expires_at_ms,
    };
    let message = serde_json::to_vec(&canon).map_err(|e| format!("canon json: {e}"))?;

    let sig = sk.sign(&message);
    let sig_hex = hex::encode(sig.to_bytes());

    Ok(ConsentToken {
        issuer: issuer_pid.clone(),
        issuer_peer: issuer_pid,
        grantee: grantee.to_string(),
        capabilities: caps,
        expires_at_ms,
        sig_hex,
    })
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}
