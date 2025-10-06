// Run: cargo test -p hsip-core aad_labels
use rand::RngCore;
use hsip_core::crypto::aead::{encrypt, decrypt, PacketKind};

#[test]
fn aad_tamper_rejects_packet() {
    let mut key = [0u8; 32]; rand::thread_rng().fill_bytes(&mut key);
    let mut nonce = [0u8; 12]; rand::thread_rng().fill_bytes(&mut nonce);
    let msg = b"consent:please";

    // Sender encrypts as E1
    let ct = encrypt(PacketKind::E1, &key, &nonce, msg).expect("encrypt");

    // Honest verify (E1) succeeds
    assert!(decrypt(PacketKind::E1, &key, &nonce, &ct).is_ok());

    // Wrong context (HELLO) must FAIL
    assert!(decrypt(PacketKind::Hello, &key, &nonce, &ct).is_err());
}
