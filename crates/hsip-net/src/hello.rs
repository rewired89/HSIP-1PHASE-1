use base64::Engine;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use hsip_core::identity::peer_id_from_pubkey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Hello {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub peer_id: String,
    pub pub_key_hex: String,
    pub caps: Vec<String>,
    pub ts: u64,
    pub nonce: String,
    pub sig: String,
}

// Detect local node capabilities
#[must_use]
fn detect_local_capabilities() -> Vec<String> {
    let mut capabilities = Vec::with_capacity(5);
    capabilities.push("pqc=0".into());
    capabilities.push("dtn=1".into());
    capabilities.push("mesh=1".into());
    capabilities.push("sat=0".into());
    capabilities.push("consent=1".into());
    capabilities
}

// Generate canonical signing payload from HELLO components
#[must_use]
fn generate_signature_payload(
    peer_identity: &str,
    pubkey_encoded: &str,
    capability_list: &[String],
    timestamp: u64,
    nonce_encoded: &str,
) -> String {
    let caps_joined = capability_list.join(",");
    format!(
        "HELLO|{}|{}|{}|{}|{}",
        peer_identity, pubkey_encoded, caps_joined, timestamp, nonce_encoded
    )
}

// Construct cryptographically signed HELLO message
#[must_use]
pub fn build_hello(
    signing_key: &SigningKey,
    verifying_key: &VerifyingKey,
    current_timestamp_ms: u64,
) -> Hello {
    let peer_identity = peer_id_from_pubkey(verifying_key);
    let pubkey_encoded = hex::encode(verifying_key.as_bytes());

    // Generate 12-byte cryptographic nonce
    let mut nonce_buffer = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_buffer);
    let nonce_encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(nonce_buffer);

    let capability_list = detect_local_capabilities();

    let signing_payload = generate_signature_payload(
        &peer_identity,
        &pubkey_encoded,
        &capability_list,
        current_timestamp_ms,
        &nonce_encoded,
    );

    let signature = signing_key.sign(signing_payload.as_bytes());
    let signature_encoded = hex::encode(signature.to_bytes());

    Hello {
        msg_type: "HELLO".into(),
        peer_id: peer_identity,
        pub_key_hex: pubkey_encoded,
        caps: capability_list,
        ts: current_timestamp_ms,
        nonce: nonce_encoded,
        sig: signature_encoded,
    }
}

// Validate HELLO message cryptographic integrity and identity binding
// # Errors
// Returns error for malformed keys, identity mismatch, or signature verification failure
pub fn verify_hello(hello_msg: &Hello) -> Result<(), String> {
    // Reconstruct verifying key from hex-encoded public key
    let pubkey_bytes = hex::decode(&hello_msg.pub_key_hex)
        .map_err(|e| format!("Public key hex decoding failed: {e}"))?;

    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes")?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| format!("Failed to construct verifying key: {e}"))?;

    // Validate peer ID derives from public key
    let derived_peer_id = peer_id_from_pubkey(&verifying_key);
    if derived_peer_id != hello_msg.peer_id {
        return Err("Peer ID does not match public key derivation".into());
    }

    // Reconstruct canonical signing payload
    let signing_payload = generate_signature_payload(
        &hello_msg.peer_id,
        &hello_msg.pub_key_hex,
        &hello_msg.caps,
        hello_msg.ts,
        &hello_msg.nonce,
    );

    // Verify cryptographic signature
    let signature_bytes = hex::decode(&hello_msg.sig)
        .map_err(|e| format!("Signature hex decoding failed: {e}"))?;

    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes")?;

    let signature = Signature::from_bytes(&signature_array);

    verifying_key
        .verify_strict(signing_payload.as_bytes(), &signature)
        .map_err(|e: SignatureError| format!("Signature verification failed: {e}"))?;

    Ok(())
}
