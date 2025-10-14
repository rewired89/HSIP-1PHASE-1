//! Consent handshake (E1 / E2) for HSIP
//! This module provides nonce-aware helper functions that bind AEAD AAD to
//! PacketKind::E1 / PacketKind::E2 and enforce strictly-increasing nonces.

use hsip_core::crypto::aead::{decrypt, encrypt, PacketKind};
use hsip_core::crypto::nonce::{Nonce, NonceGen, NonceTracker};
use hsip_core::wire::prefix::write_prefix;

/// Encrypt an E1 payload producing (ciphertext, nonce_bytes).
/// - Uses a monotonic 96-bit nonce from `gen`.
/// - Binds AEAD AAD to PacketKind::E1 so context-mismatch fails auth.
/// - Prepends HSIP prefix to the outgoing frame.
pub fn e1_encrypt_with_gen(
    gen: &mut NonceGen,
    key: &[u8; 32],
    e1_plain: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), String> {
    let n = gen.next_nonce();
    let ct = encrypt(PacketKind::E1, key, n.as_bytes(), e1_plain)?;

    // Add HSIP prefix + ciphertext
    let mut out = Vec::new();
    write_prefix(&mut out);
    out.extend_from_slice(&ct);

    Ok((out, *n.as_bytes()))
}

/// Decrypt an E1 ciphertext after enforcing strictly-increasing nonces with `tracker`.
/// Returns plaintext if both tracker.accept() and AEAD auth succeed.
pub fn e1_decrypt_with_tracker(
    tracker: &mut NonceTracker,
    key: &[u8; 32],
    nonce_bytes: [u8; 12],
    ct: &[u8],
) -> Result<Vec<u8>, String> {
    let n = Nonce::from_bytes(nonce_bytes);
    tracker.accept(&n).map_err(|_| "nonce_violation")?;

    // ct should already have prefix stripped before calling this function.
    decrypt(PacketKind::E1, key, n.as_bytes(), ct)
}

/// Encrypt an E2 payload producing (ciphertext, nonce_bytes).
pub fn e2_encrypt_with_gen(
    gen: &mut NonceGen,
    key: &[u8; 32],
    e2_plain: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), String> {
    let n = gen.next_nonce();
    let ct = encrypt(PacketKind::E2, key, n.as_bytes(), e2_plain)?;

    // Add HSIP prefix + ciphertext
    let mut out = Vec::new();
    write_prefix(&mut out);
    out.extend_from_slice(&ct);

    Ok((out, *n.as_bytes()))
}

/// Decrypt an E2 ciphertext with strict nonce tracking.
pub fn e2_decrypt_with_tracker(
    tracker: &mut NonceTracker,
    key: &[u8; 32],
    nonce_bytes: [u8; 12],
    ct: &[u8],
) -> Result<Vec<u8>, String> {
    let n = Nonce::from_bytes(nonce_bytes);
    tracker.accept(&n).map_err(|_| "nonce_violation")?;
    decrypt(PacketKind::E2, key, n.as_bytes(), ct)
}

#[cfg(test)]
mod nonce_bind_tests {
    use super::*;
    use hsip_core::crypto::nonce::{NonceGen, NonceTracker};

    // These tests only validate the helper layer; they do not replace your existing consent tests.
    #[test]
    fn e1_nonce_roundtrip_and_tracker() {
        let mut gen = NonceGen::new(0xABCD1234);
        let mut trk = NonceTracker::new();
        let key = [7u8; 32];
        let pt = b"e1 body";

        let (ct, n1) = e1_encrypt_with_gen(&mut gen, &key, pt).expect("enc");
        let out = e1_decrypt_with_tracker(&mut trk, &key, n1, &ct[6..]) // skip prefix
            .expect("dec");
        assert_eq!(out, pt);

        // Reusing same nonce must fail tracker
        let dup = e1_decrypt_with_tracker(&mut trk, &key, n1, &ct[6..]);
        assert!(dup.is_err());
    }

    #[test]
    fn e2_nonce_roundtrip_and_tracker() {
        let mut gen = NonceGen::new(0xFACEB00C);
        let mut trk = NonceTracker::new();
        let key = [9u8; 32];
        let pt = b"e2 body";

        let (ct, n1) = e2_encrypt_with_gen(&mut gen, &key, pt).expect("enc");
        let out = e2_decrypt_with_tracker(&mut trk, &key, n1, &ct[6..])
            .expect("dec");
        assert_eq!(out, pt);

        // Reusing same nonce must fail tracker
        let dup = e2_decrypt_with_tracker(&mut trk, &key, n1, &ct[6..]);
        assert!(dup.is_err());
    }
}
