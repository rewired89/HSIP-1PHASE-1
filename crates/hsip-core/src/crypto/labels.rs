//! Canonical cryptographic context labels for HSIP.
//! Every AEAD (ChaCha20-Poly1305) operation must use these AAD bytes.

pub const PROTOCOL_ID: &[u8] = b"HSIP";
pub const PROTOCOL_VERSION: u16 = 0x0002; // v0.2.0-mvp (bumping breaks compatibility)
pub const CIPHERSUITE: &[u8] = b"CHACHA20-POLY1305";

// Packet role labels
pub const AAD_LABEL_HELLO: &[u8] = b"HELLO";
pub const AAD_LABEL_E1: &[u8]    = b"CONSENT_E1";
pub const AAD_LABEL_E2: &[u8]    = b"CONSENT_E2";

// Build canonical AAD = PROTOCOL_ID | VERSION_LE | CIPHERSUITE (fixed 18 bytes) | LABEL (fixed 12 bytes)
pub fn aad_for(label: &[u8]) -> [u8; 4 + 2 + 18 + 12] {
    let mut out = [0u8; 4 + 2 + 18 + 12];

    // "HSIP"
    out[0..4].copy_from_slice(PROTOCOL_ID);

    // version (LE)
    out[4..6].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());

    // ciphersuite padded to 18
    let mut off = 6;
    let cs = CIPHERSUITE;
    out[off..off + cs.len()].copy_from_slice(cs);
    off += 18;

    // label padded to 12
    let max_label = 12usize;
    let l = label.len().min(max_label);
    out[off..off + l].copy_from_slice(&label[..l]);

    out
}
