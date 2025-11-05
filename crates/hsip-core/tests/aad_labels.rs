use hsip_core::crypto::aead::{decrypt, encrypt, PacketKind};

#[test]
fn aad_is_bound_to_kind() -> Result<(), Box<dyn std::error::Error>> {
    // 32-byte key, 12-byte nonce
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let msg = b"hello-aad";

    // Seal as E1
    let ct =
        encrypt(PacketKind::E1, &key, &nonce, msg).map_err(|e| format!("encrypt failed: {e}"))?;

    // Open as E1 → OK
    let pt =
        decrypt(PacketKind::E1, &key, &nonce, &ct).map_err(|e| format!("decrypt failed: {e}"))?;
    assert_eq!(pt, msg);

    // Open as E2 → must fail (AAD mismatch)
    let err = decrypt(PacketKind::E2, &key, &nonce, &ct).unwrap_err();
    assert!(
        err.contains("auth_failed"),
        "expected auth_failed, got {err}"
    );

    Ok(())
}
