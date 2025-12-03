#![allow(unused_variables)]
#![allow(dead_code)]

use clap::{Args, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hsip_core::identity::{peer_id_from_pubkey, vk_to_hex};
use hsip_core::keystore::load_keypair;
use serde::{Deserialize, Serialize};
use std::fs;

/// Authorization capability enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Session,
    FileTransfer,
    Voice,
    Hello,
    Ping,
}

/// Cryptographically signed consent authorization token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentToken {
    /// Token issuer peer identifier (derived from issuer public key)
    pub issuer: String,
    /// Backward compatibility alias
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

/// Generate signed consent token with specified capabilities and lifetime
pub fn issue_token(
    grantee_identifier: String,
    capability_list: Vec<Capability>,
    lifetime_ms: u64,
) -> ConsentToken {
    let (signing_key, verifying_key) = load_keypair().expect("Failed to load identity keypair");
    generate_signed_token(&signing_key, &verifying_key, &grantee_identifier, capability_list, lifetime_ms)
        .expect("Token generation failed")
}

/// Validate token cryptographic signature and expiration
pub fn verify_token(
    token: &ConsentToken,
    issuer_public_key: &VerifyingKey,
) -> Result<(), String> {
    check_token_expiration(token)?;
    verify_token_signature(token, issuer_public_key)
}

fn check_token_expiration(token: &ConsentToken) -> Result<(), String> {
    if current_timestamp_ms() > token.expires_at_ms {
        return Err("Token has expired".to_string());
    }
    Ok(())
}

fn verify_token_signature(
    token: &ConsentToken,
    issuer_key: &VerifyingKey,
) -> Result<(), String> {
    let canonical_message = serialize_token_for_signing(
        &token.issuer,
        &token.grantee,
        &token.capabilities,
        token.expires_at_ms,
    )?;

    let signature_hex = token.sig_hex.strip_prefix("0x").unwrap_or(&token.sig_hex);
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|_| "Invalid signature hex encoding")?;

    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes")?;

    let signature = Signature::from_bytes(&signature_array);

    issuer_key
        .verify(&canonical_message, &signature)
        .map_err(|_| "Signature verification failed")?;

    Ok(())
}

fn generate_signed_token(
    signing_key: &SigningKey,
    verifying_key: &VerifyingKey,
    recipient: &str,
    capabilities: Vec<Capability>,
    lifetime_ms: u64,
) -> Result<ConsentToken, String> {
    let issuer_peer_id = peer_id_from_pubkey(verifying_key);
    let expiration_time = current_timestamp_ms().saturating_add(lifetime_ms);

    let signing_message = serialize_token_for_signing(
        &issuer_peer_id,
        recipient,
        &capabilities,
        expiration_time,
    )?;

    let signature = signing_key.sign(&signing_message);
    let signature_encoded = hex::encode(signature.to_bytes());

    Ok(ConsentToken {
        issuer: issuer_peer_id.clone(),
        issuer_peer: issuer_peer_id,
        grantee: recipient.to_string(),
        capabilities,
        expires_at_ms: expiration_time,
        sig_hex: signature_encoded,
    })
}

fn serialize_token_for_signing(
    issuer_id: &str,
    recipient_id: &str,
    caps: &[Capability],
    expiration: u64,
) -> Result<Vec<u8>, String> {
    #[derive(Serialize)]
    struct CanonicalForm<'a> {
        issuer: &'a str,
        grantee: &'a str,
        capabilities: &'a [Capability],
        expires_at_ms: u64,
    }

    let canonical = CanonicalForm {
        issuer: issuer_id,
        grantee: recipient_id,
        capabilities: caps,
        expires_at_ms: expiration,
    };

    serde_json::to_vec(&canonical).map_err(|e| format!("Serialization failed: {e}"))
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock error")
        .as_millis() as u64
}
