//! Canonical cryptographic context labels for HSIP.
//!
//! Every AEAD (ChaCha20-Poly1305) operation must use these AAD bytes to ensure
//! domain separation and prevent cross-protocol misuse.

pub const PROTOCOL_ID: &[u8] = b"HSIP";
pub const PROTOCOL_VERSION: u16 = 0x0002; // v0.2.0-mvp (changing breaks compatibility)
pub const CIPHERSUITE: &[u8] = b"CHACHA20-POLY1305";

// Packet role labels
pub const AAD_LABEL_HELLO: &[u8] = b"HELLO";
pub const AAD_LABEL_E1: &[u8] = b"CONSENT_E1";
pub const AAD_LABEL_E2: &[u8] = b"CONSENT_E2";

/// Build canonical AAD =
/// `[ PROTOCOL_ID (4B) | VERSION_LE (2B) | CIPHERSUITE (18B padded) | LABEL (12B padded) ]`
#[must_use]
pub fn aad_for(label: &[u8]) -> [u8; 4 + 2 + 18 + 12] {
    let mut out = [0u8; 4 + 2 + 18 + 12];

    // "HSIP"
    out[0..4].copy_from_slice(PROTOCOL_ID);

    // version (LE)
    out[4..6].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());

    // ciphersuite padded to 18 bytes
    let mut off = 6;
    let cs = CIPHERSUITE;
    let cs_len = cs.len().min(18);
    out[off..off + cs_len].copy_from_slice(&cs[..cs_len]);
    off += 18;

    // label padded to 12 bytes
    let l = label.len().min(12);
    out[off..off + l].copy_from_slice(&label[..l]);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_structure_ok() {
        let a = aad_for(AAD_LABEL_HELLO);
        assert_eq!(&a[0..4], PROTOCOL_ID);
        assert_eq!(u16::from_le_bytes([a[4], a[5]]), PROTOCOL_VERSION);
        assert!(a.contains(&b'H'));
        assert_eq!(a.len(), 36);
    }
}
