use blake3;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use hex;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

// Represents a requester's consent query for content usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRequest {
    pub version: u8,
    pub requester_peer_id: String,
    pub requester_pub_key_hex: String,
    pub content_cid_hex: String,
    pub purpose: String,
    pub expires_ms: u64,
    pub ts_ms: u64,
    pub nonce_hex: String,
    pub sig_hex: String,
}

// Responder's authorization decision structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentResponse {
    pub version: u8,
    pub request_hash_hex: String,
    pub responder_peer_id: String,
    pub responder_pub_key_hex: String,
    pub decision: String,
    pub ttl_ms: u64,
    pub ts_ms: u64,
    pub sig_hex: String,
}

// Generate blake3-based content identifier as hex string
#[must_use]
pub fn cid_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

// Serialize request data for cryptographic signing
fn serialize_request_for_signature(r: &ConsentRequest) -> String {
    format!(
        "CONSENT_REQUEST|v={}|pid={}|pub={}|cid={}|purpose={}|exp={}|ts={}|nonce={}",
        r.version,
        r.requester_peer_id,
        r.requester_pub_key_hex,
        r.content_cid_hex,
        r.purpose,
        r.expires_ms,
        r.ts_ms,
        r.nonce_hex
    )
}

// Serialize response data for cryptographic signing
fn serialize_response_for_signature(resp: &ConsentResponse) -> String {
    format!(
        "CONSENT_RESPONSE|v={}|req_hash={}|pid={}|pub={}|decision={}|ttl={}|ts={}",
        resp.version,
        resp.request_hash_hex,
        resp.responder_peer_id,
        resp.responder_pub_key_hex,
        resp.decision,
        resp.ttl_ms,
        resp.ts_ms
    )
}

// Extract peer identifier from verifying key using project identity scheme
#[must_use]
pub fn derive_peer_id(vk: &VerifyingKey) -> String {
    hsip_identity_module::peer_id_from_pubkey(vk)
}

mod hsip_identity_module {
    pub use crate::identity::peer_id_from_pubkey;
}

// Construct and cryptographically sign a consent request
#[must_use]
pub fn create_signed_request(
    signing_key: &SigningKey,
    verify_key: &VerifyingKey,
    content_id: String,
    usage_purpose: String,
    expiration_timestamp: u64,
    current_timestamp: u64,
) -> ConsentRequest {
    let peer_identifier = derive_peer_id(verify_key);
    let public_key_encoded = hex::encode(verify_key.as_bytes());

    // Generate 12-byte cryptographic nonce
    let mut nonce_buffer = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_buffer);
    let nonce_encoded = hex::encode(nonce_buffer);

    let mut request = ConsentRequest {
        version: 1,
        requester_peer_id: peer_identifier,
        requester_pub_key_hex: public_key_encoded,
        content_cid_hex: content_id,
        purpose: usage_purpose,
        expires_ms: expiration_timestamp,
        ts_ms: current_timestamp,
        nonce_hex: nonce_encoded,
        sig_hex: String::new(),
    };

    let serialized = serialize_request_for_signature(&request);
    let signature = signing_key.sign(serialized.as_bytes());
    request.sig_hex = hex::encode(signature.to_bytes());
    request
}

// Validate cryptographic integrity of consent request
// # Errors
// Returns error for invalid key encoding, peer ID mismatch, or signature failure
pub fn validate_request(request: &ConsentRequest) -> Result<(), String> {
    let public_key_bytes = hex::decode(&request.requester_pub_key_hex)
        .map_err(|e| format!("Invalid public key hex encoding: {e}"))?;
    
    let key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes")?;
    
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| format!("Failed to construct verifying key: {e}"))?;

    let expected_peer_id = derive_peer_id(&verifying_key);
    if expected_peer_id != request.requester_peer_id {
        return Err("Peer ID does not match derived value from public key".into());
    }

    let serialized = serialize_request_for_signature(request);
    let sig_bytes = hex::decode(&request.sig_hex)
        .map_err(|e| format!("Invalid signature hex encoding: {e}"))?;
    
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes")?;
    
    let signature = Signature::from_bytes(&sig_array);
    verifying_key.verify_strict(serialized.as_bytes(), &signature)
        .map_err(|e: SignatureError| format!("Signature verification failed: {e}"))?;

    Ok(())
}

// Construct and sign consent response bound to specific request
// # Errors
// Returns error only if cryptographic operations fail with valid keys
pub fn create_signed_response(
    signing_key: &SigningKey,
    verify_key: &VerifyingKey,
    original_request: &ConsentRequest,
    authorization_decision: &str,
    time_to_live: u64,
    current_timestamp: u64,
) -> Result<ConsentResponse, String> {
    let request_serialized = serialize_request_for_signature(original_request);
    let request_binding_hash = hex::encode(blake3::hash(request_serialized.as_bytes()).as_bytes());

    let peer_identifier = derive_peer_id(verify_key);
    let public_key_encoded = hex::encode(verify_key.as_bytes());

    let mut response = ConsentResponse {
        version: 1,
        request_hash_hex: request_binding_hash,
        responder_peer_id: peer_identifier,
        responder_pub_key_hex: public_key_encoded,
        decision: authorization_decision.to_string(),
        ttl_ms: time_to_live,
        ts_ms: current_timestamp,
        sig_hex: String::new(),
    };

    let serialized = serialize_response_for_signature(&response);
    let signature = signing_key.sign(serialized.as_bytes());
    response.sig_hex = hex::encode(signature.to_bytes());
    Ok(response)
}

// Validate response cryptographic binding to request
// # Errors
// Returns error for hash mismatch, invalid keys, inconsistent decision/TTL, or signature failure
pub fn validate_response(response: &ConsentResponse, original_request: &ConsentRequest) -> Result<(), String> {
    let request_serialized = serialize_request_for_signature(original_request);
    let expected_hash = hex::encode(blake3::hash(request_serialized.as_bytes()).as_bytes());
    
    if expected_hash != response.request_hash_hex {
        return Err("Response hash does not match request binding".into());
    }

    let public_key_bytes = hex::decode(&response.responder_pub_key_hex)
        .map_err(|e| format!("Invalid responder public key hex: {e}"))?;
    
    let key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "Responder public key must be 32 bytes")?;
    
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| format!("Failed to construct responder verifying key: {e}"))?;

    let expected_peer_id = derive_peer_id(&verifying_key);
    if expected_peer_id != response.responder_peer_id {
        return Err("Responder peer ID does not match public key".into());
    }

    if response.decision != "allow" && response.decision != "deny" {
        return Err("Decision must be either 'allow' or 'deny'".into());
    }
    
    if response.decision == "deny" && response.ttl_ms != 0 {
        return Err("Denial responses must have zero TTL".into());
    }

    let serialized = serialize_response_for_signature(response);
    let sig_bytes = hex::decode(&response.sig_hex)
        .map_err(|e| format!("Invalid response signature hex: {e}"))?;
    
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Response signature must be 64 bytes")?;
    
    let signature = Signature::from_bytes(&sig_array);
    verifying_key.verify_strict(serialized.as_bytes(), &signature)
        .map_err(|e: SignatureError| format!("Response signature verification failed: {e}"))?;

    Ok(())
}
