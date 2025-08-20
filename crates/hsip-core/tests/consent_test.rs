// crates/hsip-core/tests/consent_test.rs

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hsip_core::consent::{build_response, ConsentRequest, ConsentResponse};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock ok")
        .as_millis() as u64
}

// tiny hex encoder to avoid adding a dependency
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Deterministic keypair for tests (constant 32-byte seed)
fn fixed_keypair() -> (SigningKey, VerifyingKey) {
    let sk_bytes = [0x42u8; 32]; // fixed seed
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = VerifyingKey::from(&sk);
    (sk, vk)
}

/// Build a signed ConsentRequest that matches hsip-core’s expected fields.
/// We sign the canonical JSON where `sig_hex` is empty (common pattern in this repo).
fn signed_request() -> ConsentRequest {
    let (sk_req, vk_req) = fixed_keypair();

    // First, build the request with an empty signature so we can compute the signature over it.
    let ts = now_ms();
    let req_no_sig = ConsentRequest {
        version: 1,
        requester_peer_id: "peer_req_test".to_string(),
        ts_ms: ts,
        expires_ms: 60_000,
        purpose: "unit-test".to_string(),
        // 16 bytes -> 32 hex chars
        nonce_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        // required extra fields:
        requester_pub_key_hex: hex_encode(vk_req.to_bytes().as_ref()),
        content_cid_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(), // 32 bytes hex (dummy)
        sig_hex: String::new(), // empty for signing step
    };

    // Sign the canonical JSON (serde struct order) with empty sig field.
    let bytes = serde_json::to_vec(&req_no_sig).expect("serialize request for signing");
    let sig = sk_req.sign(&bytes);
    let sig_hex = hex_encode(sig.to_bytes().as_ref());

    // Return the same struct but with the signature filled in.
    ConsentRequest {
        sig_hex,
        ..req_no_sig
    }
}

#[test]
fn request_json_roundtrip() {
    let req = signed_request();

    // Serialize to JSON and back, ensure key fields survive the roundtrip
    let json = serde_json::to_string(&req).expect("serialize request");
    let de: ConsentRequest = serde_json::from_str(&json).expect("deserialize request");

    assert_eq!(de.version, 1);
    assert_eq!(de.requester_peer_id, "peer_req_test");
    assert_eq!(de.purpose, "unit-test");
    assert_eq!(de.expires_ms, 60_000);
    assert_eq!(de.nonce_hex.len(), 32); // 16 bytes -> 32 hex chars
    assert!(!de.sig_hex.is_empty());
    assert_eq!(de.requester_pub_key_hex.len(), 64); // ed25519 pubkey = 32 bytes = 64 hex
}

#[test]
fn build_response_allows_and_serializes() {
    // For simplicity, use the same fixed pair as the "responder" as well.
    let (sk_responder, vk_responder) = fixed_keypair();
    let req = signed_request();

    // Build an ALLOW response for 2 minutes
    let ttl = 120_000u64;
    let resp: ConsentResponse =
        build_response(&sk_responder, &vk_responder, &req, "allow", ttl, now_ms())
            .expect("build_response should succeed");

    // Invariants we know from the listener logging:
    assert_eq!(resp.decision, "allow");
    assert_eq!(resp.ttl_ms, ttl);

    // JSON roundtrip
    let json = serde_json::to_string(&resp).expect("serialize response");
    let de: ConsentResponse = serde_json::from_str(&json).expect("deserialize response");
    assert_eq!(de.decision, "allow");
    assert_eq!(de.ttl_ms, ttl);
}
