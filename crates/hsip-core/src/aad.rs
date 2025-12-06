// Authenticated encryption labels for HSIP protocol layers
// These constants serve as Associated Authenticated Data (AAD) in AEAD operations
// to prevent cross-layer replay attacks. Version tags enable safe protocol evolution.

// Handshake HELLO frame authentication label
pub const AAD_HELLO: &[u8] = b"HSIP-V1-HELLO";

// Consent request/response frame authentication label
pub const AAD_CONSENT: &[u8] = b"HSIP-V1-CONSENT";

// Application data packet authentication label
pub const AAD_DATA: &[u8] = b"HSIP-V1-DATA";

// Session resumption ticket authentication label
// (Aligned with session_resumption.rs implementation)
pub const AAD_TICKET: &[u8] = b"HSIP-TICKET-V1";

// Rekey control message authentication label (reserved for future use)
pub const AAD_REKEY: &[u8] = b"HSIP-V1-REKEY";

// Status/daemon metadata authentication label (reserved)
pub const AAD_STATUS: &[u8] = b"HSIP-V1-STATUS";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_label_uniqueness() {
        let labels = [
            AAD_HELLO, AAD_CONSENT, AAD_DATA, 
            AAD_TICKET, AAD_REKEY, AAD_STATUS
        ];
        
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(
                    labels[i], labels[j],
                    "Labels at indices {} and {} are not unique",
                    i, j
                );
            }
        }
    }

    #[test]
    fn verify_label_stability() {
        // Ensure labels remain constant across versions
        assert_eq!(AAD_HELLO, b"HSIP-V1-HELLO");
        assert_eq!(AAD_CONSENT, b"HSIP-V1-CONSENT");
        assert_eq!(AAD_DATA, b"HSIP-V1-DATA");
        assert_eq!(AAD_TICKET, b"HSIP-TICKET-V1");
        assert_eq!(AAD_REKEY, b"HSIP-V1-REKEY");
        assert_eq!(AAD_STATUS, b"HSIP-V1-STATUS");
    }
}
