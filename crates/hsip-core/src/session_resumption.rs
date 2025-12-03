// HSIP session resumption implementation
// Enables peers to reconnect after valid sessions without full consent re-negotiation.
// Fresh X25519 and ChaCha20 keys are still generated per connection.
// Tickets are ephemeral, authenticated, and bound to peer identity.

// Ticket wire encoding (variable length):
//   [0..12]   : ChaCha20-Poly1305 nonce (96 bits)
//   [12..]    : authenticated ciphertext with tag
//               plaintext structure:
//               [peer_id:32][caps:4 LE][issued_at:8 LE][expires_at:8 LE]
//               plaintext total = 52 bytes

use core::fmt;

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::hello::{HelloCapabilities, PeerId};

// Server-side static key for ticket encryption/decryption operations
// Must persist across restarts for ticket continuity
#[derive(Clone)]
pub struct TicketEncryptionKey([u8; 32]);

impl TicketEncryptionKey {
    pub fn new(key_material: [u8; 32]) -> Self {
        TicketEncryptionKey(key_material)
    }

    pub fn as_key(&self) -> Key {
        Key::from_slice(&self.0).to_owned()
    }
}

// Session ticket configuration parameters
#[derive(Debug, Clone, Copy)]
pub struct TicketPolicy {
    // Maximum permitted ticket validity duration in milliseconds
    pub max_validity_duration_ms: u64,
}

impl Default for TicketPolicy {
    fn default() -> Self {
        TicketPolicy {
            max_validity_duration_ms: 60_000, // 1 minute default
        }
    }
}

// Decrypted ticket payload structure
#[derive(Debug, Clone, Copy)]
pub struct TicketPayload {
    pub peer_id: PeerId,
    pub caps: HelloCapabilities,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

// Ticket operation error types
#[derive(Debug)]
pub enum TicketError {
    ExcessiveLifetime,
    InsufficientLength,
    AuthenticationFailure,
    TicketExpired,
    FutureTicket,
}

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TicketError::ExcessiveLifetime => {
                write!(f, "Requested lifetime exceeds policy maximum")
            }
            TicketError::InsufficientLength => {
                write!(f, "Ticket data too short for valid format")
            }
            TicketError::AuthenticationFailure => {
                write!(f, "Ticket decryption or authentication failed")
            }
            TicketError::TicketExpired => write!(f, "Ticket validity period elapsed"),
            TicketError::FutureTicket => {
                write!(f, "Ticket not yet valid - possible clock skew")
            }
        }
    }
}

impl std::error::Error for TicketError {}

// AEAD associated data label
const TICKET_LABEL: &[u8] = b"HSIP-TICKET-V1";

const PAYLOAD_SIZE: usize = 32 + 4 + 8 + 8; // PeerId + caps + timestamps

fn serialize_payload(payload: &TicketPayload) -> [u8; PAYLOAD_SIZE] {
    let mut buffer = [0u8; PAYLOAD_SIZE];

    buffer[0..32].copy_from_slice(&payload.peer_id.0);
    buffer[32..36].copy_from_slice(&payload.caps.0.to_le_bytes());
    buffer[36..44].copy_from_slice(&payload.issued_at_ms.to_le_bytes());
    buffer[44..52].copy_from_slice(&payload.expires_at_ms.to_le_bytes());

    buffer
}

fn deserialize_payload(buffer: &[u8; PAYLOAD_SIZE]) -> TicketPayload {
    let mut peer_bytes = [0u8; 32];
    peer_bytes.copy_from_slice(&buffer[0..32]);
    let peer_id = PeerId(peer_bytes);

    let caps_value = u32::from_le_bytes(buffer[32..36].try_into().unwrap());
    let caps = HelloCapabilities(caps_value);

    let issued_at_ms = u64::from_le_bytes(buffer[36..44].try_into().unwrap());
    let expires_at_ms = u64::from_le_bytes(buffer[44..52].try_into().unwrap());

    TicketPayload {
        peer_id,
        caps,
        issued_at_ms,
        expires_at_ms,
    }
}

// Generate encrypted resumption ticket for authenticated peer
// Lifetime must not exceed maximum
pub fn issue_resumption_ticket(
    key: &TicketEncryptionKey,
    policy: &TicketPolicy,
    peer_id: PeerId,
    caps: HelloCapabilities,
    current_time_ms: u64,
    lifetime_ms: u64,
) -> Result<Vec<u8>, TicketError> {
    if lifetime_ms > policy.max_validity_duration_ms {
        return Err(TicketError::ExcessiveLifetime);
    }

    let issued_at_ms = current_time_ms;
    let expires_at_ms = current_time_ms + lifetime_ms;

    let payload = TicketPayload {
        peer_id,
        caps,
        issued_at_ms,
        expires_at_ms,
    };

    let payload_bytes = serialize_payload(&payload);

    let cipher_key = key.as_key();
    let cipher = ChaCha20Poly1305::new(&cipher_key);

    let mut nonce_buffer = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_buffer);
    let nonce = Nonce::from_slice(&nonce_buffer);

    let mut ciphertext = payload_bytes.to_vec();
    cipher
        .encrypt_in_place(nonce, TICKET_LABEL, &mut ciphertext)
        .map_err(|_| TicketError::AuthenticationFailure)?;

    let mut ticket = nonce_buffer.to_vec();
    ticket.extend_from_slice(&ciphertext);
    Ok(ticket)
}

// Decrypt and validate resumption ticket
// Verifies length, AEAD integrity, and temporal validity
pub fn validate_resumption_ticket(
    key: &TicketEncryptionKey,
    policy: &TicketPolicy,
    ticket_data: &[u8],
    current_time_ms: u64,
) -> Result<TicketPayload, TicketError> {
    // Minimum: nonce(12) + payload(52) + tag(16) = 80 bytes
    if ticket_data.len() < 12 + PAYLOAD_SIZE + 16 {
        return Err(TicketError::InsufficientLength);
    }

    let (nonce_bytes, ciphertext_bytes) = ticket_data.split_at(12);

    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher_key = key.as_key();
    let cipher = ChaCha20Poly1305::new(&cipher_key);

    let mut plaintext = ciphertext_bytes.to_vec();

    cipher
        .decrypt_in_place(nonce, TICKET_LABEL, &mut plaintext)
        .map_err(|_| TicketError::AuthenticationFailure)?;

    if plaintext.len() != PAYLOAD_SIZE {
        return Err(TicketError::AuthenticationFailure);
    }

    let mut payload_buffer = [0u8; PAYLOAD_SIZE];
    payload_buffer.copy_from_slice(&plaintext);
    let payload = deserialize_payload(&payload_buffer);

    if current_time_ms < payload.issued_at_ms {
        return Err(TicketError::FutureTicket);
    }

    if current_time_ms > payload.expires_at_ms {
        return Err(TicketError::TicketExpired);
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::PeerId;

    fn test_timestamp() -> u64 {
        1_700_000_000_000
    }

    #[test]
    fn ticket_creation_and_validation() {
        let key = TicketEncryptionKey::new([7u8; 32]);
        let policy = TicketPolicy::default();

        let peer_id = PeerId([1u8; 32]);
        let caps = HelloCapabilities::default_local();

        let ticket = issue_resumption_ticket(&key, &policy, peer_id, caps, test_timestamp(), 30_000)
            .expect("Ticket should be created successfully");

        let payload =
            validate_resumption_ticket(&key, &policy, &ticket, test_timestamp() + 10_000)
                .expect("Ticket should validate successfully");

        assert_eq!(payload.peer_id.0, peer_id.0);
        assert!(payload.caps.supports(crate::hello::CAP_CONSENT_LAYER));
    }

    #[test]
    fn expired_ticket_rejected() {
        let key = TicketEncryptionKey::new([9u8; 32]);
        let policy = TicketPolicy::default();

        let peer_id = PeerId([2u8; 32]);
        let caps = HelloCapabilities::default_local();

        let ticket = issue_resumption_ticket(&key, &policy, peer_id, caps, test_timestamp(), 10_000)
            .expect("Ticket should be created");

        let result = validate_resumption_ticket(&key, &policy, &ticket, test_timestamp() + 11_000);

        assert!(matches!(result, Err(TicketError::TicketExpired)));
    }
}
