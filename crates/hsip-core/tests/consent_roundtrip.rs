use hsip_core::consent::{build_request, build_response, verify_request, verify_response};
use hsip_core::identity::generate_keypair;

#[test]
fn consent_request_response_roundtrip() {
    let (sk, vk) = generate_keypair();
    let cid = "deadbeef".to_string();
    let req = build_request(&sk, &vk, cid.clone(), "demo".to_string(), 60_000, 0);
    assert!(verify_request(&req).is_ok());

    let resp = build_response(&sk, &vk, &req, "allow", 30_000, 0).unwrap();
    assert!(verify_response(&resp, &req).is_ok());
}
