use hsip_core::consent::{create_signed_request, create_signed_response, validate_request, validate_response};
use hsip_core::identity::generate_keypair;

#[test]
fn consent_request_response_roundtrip() {
    let (sk, vk) = generate_keypair();
    let cid = "deadbeef".to_string();
    let req = create_signed_request(&sk, &vk, cid.clone(), "demo".to_string(), 60_000, 0);
    assert!(validate_request(&req).is_ok());

    let resp = create_signed_response(&sk, &vk, &req, "allow", 30_000, 0).unwrap();
    assert!(validate_response(&resp, &req).is_ok());
}
