use ed25519_dalek::VerifyingKey;
use hsip_core::consent::{
    build_request, build_response, cid_hex, verify_request, verify_response, ConsentRequest,
    ConsentResponse,
};
use hsip_core::identity::{generate_keypair, peer_id_from_pubkey};
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms_u64() -> u64 {
    // Avoid clippy cast truncation: clamp to u64::MAX if far future
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_millis();
    u64::try_from(ms).unwrap_or(u64::MAX)
}

#[test]
fn consent_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    // requester keys
    let (sk_req, vk_req) = generate_keypair();
    // responder keys
    let (sk_rsp, vk_rsp) = generate_keypair();

    // content bytes → cid_hex
    let content = b"some test content";
    let cid = cid_hex(content);

    // Build signed request
    let expires = now_ms_u64() + 60_000;
    let req = build_request(
        &sk_req,
        &vk_req,
        cid.clone(),
        "indexing".into(),
        expires,
        now_ms_u64(),
    );

    // Verify request
    verify_request(&req).map_err(|e| format!("verify_request: {e}"))?;

    // Build response "allow"
    let ttl = 120_000u64;
    let resp = build_response(&sk_rsp, &vk_rsp, &req, "allow", ttl, now_ms_u64())
        .map_err(|e| format!("build_response: {e}"))?;

    // Verify response against request
    verify_response(&resp, &req).map_err(|e| format!("verify_response: {e}"))?;

    // serde roundtrip (no .expect())
    let json_req = serde_json::to_string(&req)?;
    let _req2: ConsentRequest = serde_json::from_str(&json_req)?;

    let json_resp = serde_json::to_string(&resp)?;
    let _resp2: ConsentResponse = serde_json::from_str(&json_resp)?;

    // sanity: peer IDs match public keys
    let req_pid = &req.requester_peer_id;
    let expect_req_pid = peer_id_from_pubkey(&VerifyingKey::from(&sk_req));
    assert_eq!(req_pid, &expect_req_pid);

    Ok(())
}

// tiny helper previously flagged by clippy — keep modern formatting
#[allow(dead_code)]
fn bytes_to_hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        let _ = write!(&mut s, "{byte:02x}");
    }
    s
}
