use crate::crypto::labels::{aad_for, AAD_LABEL_E1, AAD_LABEL_E2, AAD_LABEL_HELLO};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

/// Wire roles to labels for AAD binding
#[derive(Copy, Clone, Debug)]
pub enum PacketKind {
    Hello,
    E1,
    E2,
}

#[must_use]
fn aad(kind: PacketKind) -> [u8; 4 + 2 + 18 + 12] {
    match kind {
        PacketKind::Hello => aad_for(AAD_LABEL_HELLO),
        PacketKind::E1 => aad_for(AAD_LABEL_E1),
        PacketKind::E2 => aad_for(AAD_LABEL_E2),
    }
}

/// Encrypt with ChaCha20-Poly1305, authenticating canonical AAD.
///
/// `key` must be 32 bytes and `nonce` 12 bytes.
///
/// # Errors
/// Returns an `Err(String)` if encryption fails.
pub fn encrypt(
    kind: PacketKind,
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    // Avoid deprecated GenericArray helpers (from_slice/clone_from_slice).
    let key_ga: Key = (*key).into();
    let nonce_ga: Nonce = (*nonce).into();

    let aead = ChaCha20Poly1305::new(&key_ga);
    let payload = Payload {
        msg: plaintext,
        aad: &aad(kind),
    };
    aead.encrypt(&nonce_ga, payload)
        .map_err(|_| "encrypt_failed".to_string())
}

/// Decrypt/verify with AAD bound to the `PacketKind`.
///
/// `key` must be 32 bytes and `nonce` 12 bytes.
///
/// # Errors
/// Returns an `Err(String)` if authentication fails.
pub fn decrypt(
    kind: PacketKind,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let key_ga: Key = (*key).into();
    let nonce_ga: Nonce = (*nonce).into();

    let aead = ChaCha20Poly1305::new(&key_ga);
    let payload = Payload {
        msg: ciphertext,
        aad: &aad(kind),
    };
    aead.decrypt(&nonce_ga, payload)
        .map_err(|_| "auth_failed".to_string())
}
