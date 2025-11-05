use blake3;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use hex;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// What the requester is asking to do with the content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRequest {
    /// Protocol version (currently `1`).
    pub version: u8,
    /// Requester's peer id (derived from `requester_pub_key_hex`).
    pub requester_peer_id: String,
    /// Requester's Ed25519 public key, hex-encoded (32 bytes).
    pub requester_pub_key_hex: String,
    /// Content identifier: hex of `blake3(content)`.
    pub content_cid_hex: String,
    /// Purpose string, e.g. `"indexing"`, `"analytics"`, `"share"`.
    pub purpose: String,
    /// Absolute expiration time (epoch ms).
    pub expires_ms: u64,
    /// Creation timestamp (epoch ms).
    pub ts_ms: u64,
    /// 12 random bytes in hex to prevent replay.
    pub nonce_hex: String,
    /// Ed25519 signature over the canonical preimage.
    pub sig_hex: String,
}

/// Responder's signed decision to a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentResponse {
    /// Protocol version (currently `1`).
    pub version: u8,
    /// Hex of `blake3(canonical_preimage(request))` to bind response to request.
    pub request_hash_hex: String,
    /// Responder's peer id (derived from `responder_pub_key_hex`).
    pub responder_peer_id: String,
    /// Responder's Ed25519 public key, hex-encoded (32 bytes).
    pub responder_pub_key_hex: String,
    /// `"allow"` or `"deny"`.
    pub decision: String,
    /// Time-to-live in ms (`0` if `deny`).
    pub ttl_ms: u64,
    /// Creation timestamp (epoch ms).
    pub ts_ms: u64,
    /// Ed25519 signature over the canonical preimage.
    pub sig_hex: String,
}

/// Compute a content identifier (CID) for arbitrary bytes using `blake3`, hex-encoded.
#[must_use]
pub fn cid_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

fn canonical_preimage_request(r: &ConsentRequest) -> String {
    // Keep order stable — this string is what gets signed.
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

fn canonical_preimage_response(resp: &ConsentResponse) -> String {
    // Keep order stable — this string is what gets signed.
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

/// Derive a requester peer id from a verifying key using the project’s scheme:
/// `blake3(pubkey) → base32[..26]` (implemented in `identity.rs`).
#[must_use]
pub fn requester_peer_id(vk: &VerifyingKey) -> String {
    // use same algorithm as HELLO: blake3(pub) → base32[26] (implemented in identity.rs)
    hsip_core_peer_id(vk)
}

fn hsip_core_peer_id(vk: &VerifyingKey) -> String {
    hsip_crate_identity::peer_id_from_pubkey(vk)
}

mod hsip_crate_identity {
    pub use crate::identity::peer_id_from_pubkey;
}

/// Build & sign a `ConsentRequest`.
///
/// Generates a 12-byte random nonce and signs the canonical request preimage with `sk`.
#[must_use]
pub fn build_request(
    sk: &SigningKey,
    vk: &VerifyingKey,
    content_cid_hex: String,
    purpose: String,
    expires_ms: u64,
    ts_ms: u64,
) -> ConsentRequest {
    let pid = requester_peer_id(vk);
    let requester_pub_key_hex = hex::encode(vk.as_bytes());

    // 12B nonce (hex)
    let mut n = [0u8; 12];
    OsRng.fill_bytes(&mut n);
    let nonce_hex = hex::encode(n);

    let mut r = ConsentRequest {
        version: 1,
        requester_peer_id: pid,
        requester_pub_key_hex,
        content_cid_hex,
        purpose,
        expires_ms,
        ts_ms,
        nonce_hex,
        sig_hex: String::new(),
    };

    let pre = canonical_preimage_request(&r);
    let sig = sk.sign(pre.as_bytes());
    r.sig_hex = hex::encode(sig.to_bytes());
    r
}

/// Verify a `ConsentRequest`.
///
/// # Errors
/// Returns an error if:
/// - the public key hex is invalid or not 32 bytes,
/// - the derived peer id does not match the embedded peer id,
/// - the signature hex is invalid or not 64 bytes, or
/// - signature verification fails.
pub fn verify_request(r: &ConsentRequest) -> Result<(), String> {
    // reconstruct vk
    let pk = hex::decode(&r.requester_pub_key_hex).map_err(|e| format!("pub hex: {e}"))?;
    let pk_arr: [u8; 32] = pk.try_into().map_err(|_| "pub len".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("vk: {e}"))?;

    // peer_id match
    let expect = requester_peer_id(&vk);
    if expect != r.requester_peer_id {
        return Err("peer_id != pubkey".into());
    }

    // signature
    let pre = canonical_preimage_request(r);
    let sig_bytes = hex::decode(&r.sig_hex).map_err(|e| format!("sig hex: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| "sig len".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(pre.as_bytes(), &sig)
        .map_err(|e: SignatureError| format!("verify failed: {e}"))?;

    Ok(())
}

/// Build & sign a `ConsentResponse` from a verified request.
///
/// Binds the response to the request by signing the canonical response preimage which
/// contains `blake3(canonical_preimage(request))`.
///
/// # Errors
/// Returns an error only if local signing fails (shouldn't happen with a valid key).
pub fn build_response(
    sk: &SigningKey,
    vk: &VerifyingKey,
    request: &ConsentRequest,
    decision: &str, // "allow" | "deny"
    ttl_ms: u64,    // 0 if deny
    ts_ms: u64,
) -> Result<ConsentResponse, String> {
    // hash of request preimage to bind response
    let req_pre = canonical_preimage_request(request);
    let req_hash = hex::encode(blake3::hash(req_pre.as_bytes()).as_bytes());

    let pid = requester_peer_id(vk);
    let responder_pub_key_hex = hex::encode(vk.as_bytes());

    let mut resp = ConsentResponse {
        version: 1,
        request_hash_hex: req_hash,
        responder_peer_id: pid,
        responder_pub_key_hex,
        decision: decision.to_string(),
        ttl_ms,
        ts_ms,
        sig_hex: String::new(),
    };

    let pre = canonical_preimage_response(&resp);
    let sig = sk.sign(pre.as_bytes());
    resp.sig_hex = hex::encode(sig.to_bytes());
    Ok(resp)
}

/// Verify a `ConsentResponse` against a known request.
///
/// # Errors
/// Returns an error if:
/// - the request hash in the response does not match the provided request,
/// - the responder public key hex is invalid or not 32 bytes,
/// - the derived peer id does not match the embedded peer id,
/// - the decision/ttl combination is inconsistent, or
/// - signature verification fails.
pub fn verify_response(resp: &ConsentResponse, req: &ConsentRequest) -> Result<(), String> {
    // check that request_hash matches the request
    let req_pre = canonical_preimage_request(req);
    let expect_hash = hex::encode(blake3::hash(req_pre.as_bytes()).as_bytes());
    if expect_hash != resp.request_hash_hex {
        return Err("request_hash mismatch".into());
    }

    // reconstruct responder vk
    let pk = hex::decode(&resp.responder_pub_key_hex).map_err(|e| format!("pub hex: {e}"))?;
    let pk_arr: [u8; 32] = pk.try_into().map_err(|_| "pub len".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("vk: {e}"))?;

    // peer_id match
    let expect = requester_peer_id(&vk);
    if expect != resp.responder_peer_id {
        return Err("peer_id != pubkey (response)".into());
    }

    // decision sanity
    if resp.decision != "allow" && resp.decision != "deny" {
        return Err("decision must be 'allow' or 'deny'".into());
    }
    if resp.decision == "deny" && resp.ttl_ms != 0 {
        return Err("deny must have ttl_ms = 0".into());
    }

    // signature
    let pre = canonical_preimage_response(resp);
    let sig_bytes = hex::decode(&resp.sig_hex).map_err(|e| format!("sig hex: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| "sig len".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(pre.as_bytes(), &sig)
        .map_err(|e: SignatureError| format!("verify failed: {e}"))?;

    Ok(())
}
