//! HSIP unified Associated Authenticated Data (AAD) constants.
//!
//! These labels are included in AEAD authentication so packets from
//! different protocol layers cannot be replayed or confused with
//! each other. They are *versioned* so HSIP v2+ can coexist safely.

/// AAD for HELLO handshake frames.
pub const AAD_HELLO: &[u8] = b"HSIP-V1-HELLO";

/// AAD for consent request/response frames.
pub const AAD_CONSENT: &[u8] = b"HSIP-V1-CONSENT";

/// AAD for encrypted application data packets.
pub const AAD_DATA: &[u8] = b"HSIP-V1-DATA";

/// AAD for session resumption tickets.
/// (Kept consistent with session_resumption.rs)
pub const AAD_TICKET: &[u8] = b"HSIP-TICKET-V1";

/// AAD for rekey control messages (future use).
pub const AAD_REKEY: &[u8] = b"HSIP-V1-REKEY";

/// AAD for status/daemon metadata (if ever authenticated).
pub const AAD_STATUS: &[u8] = b"HSIP-V1-STATUS";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_unique() {
        assert_ne!(AAD_HELLO, AAD_CONSENT);
        assert_ne!(AAD_HELLO, AAD_DATA);
        assert_ne!(AAD_CONSENT, AAD_DATA);

        // extra checks for new labels
        assert_ne!(AAD_HELLO, AAD_REKEY);
        assert_ne!(AAD_HELLO, AAD_STATUS);
        assert_ne!(AAD_CONSENT, AAD_REKEY);
        assert_ne!(AAD_CONSENT, AAD_STATUS);
        assert_ne!(AAD_DATA, AAD_REKEY);
        assert_ne!(AAD_DATA, AAD_STATUS);
        assert_ne!(AAD_TICKET, AAD_REKEY);
        assert_ne!(AAD_TICKET, AAD_STATUS);
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(AAD_HELLO, b"HSIP-V1-HELLO");
        assert_eq!(AAD_CONSENT, b"HSIP-V1-CONSENT");
        assert_eq!(AAD_DATA, b"HSIP-V1-DATA");
        assert_eq!(AAD_TICKET, b"HSIP-TICKET-V1");
        assert_eq!(AAD_REKEY, b"HSIP-V1-REKEY");
        assert_eq!(AAD_STATUS, b"HSIP-V1-STATUS");
    }
}
