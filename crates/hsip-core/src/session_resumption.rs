//! HSIP session resumption tickets.
//!
//! Goal:
//!   * Let a peer reconnect shortly after a valid session
//!     WITHOUT redoing full consent.
//!   * Still do a fresh X25519 + fresh ChaCha keys.
//!   * Ticket is short-lived, encrypted, and bound to peer_id.
//!
//! Wire format for ticket (variable length):
//!   [0..12]   : nonce (ChaCha20-Poly1305, 96-bit)
//!   [12..]    : ciphertext || tag, where plaintext is:
//!               [peer_id:32][caps:4 LE][issued_at:8 LE][expires_at:8 LE]
//!               total inner = 32 + 4 + 8 + 8 = 52 bytes

use core::fmt;

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::hello::{HelloCapabilities, PeerId};

/// A static key used by a server to encrypt/decrypt tickets.
///
/// This must be the same across restarts if you want tickets
/// to survive restarts. You can load it from disk or env.
#[derive(Clone)]
pub struct SessionTicketKey([u8; 32]);

impl SessionTicketKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        SessionTicketKey(bytes)
    }

    pub fn as_key(&self) -> Key {
        Key::from_slice(&self.0).to_owned()
    }
}

/// Config for session tickets.
#[derive(Debug, Clone, Copy)]
pub struct SessionTicketConfig {
    /// Maximum ticket lifetime in milliseconds.
    pub max_lifetime_ms: u64,
}

impl Default for SessionTicketConfig {
    fn default() -> Self {
        SessionTicketConfig {
            max_lifetime_ms: 60_000, // 60 seconds
        }
    }
}

/// Inner ticket data (plaintext before encryption).
#[derive(Debug, Clone, Copy)]
pub struct SessionTicketData {
    pub peer_id: PeerId,
    pub caps: HelloCapabilities,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Errors for ticket creation/validation.
#[derive(Debug)]
pub enum SessionTicketError {
    TooLongLifetime,
    TicketTooShort,
    DecryptFailed,
    Expired,
    NotYetValid,
}

impl fmt::Display for SessionTicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionTicketError::TooLongLifetime => {
                write!(f, "requested lifetime exceeds configured max_lifetime_ms")
            }
            SessionTicketError::TicketTooShort => {
                write!(f, "ticket buffer too short to be valid")
            }
            SessionTicketError::DecryptFailed => {
                write!(f, "failed to decrypt or authenticate session ticket")
            }
            SessionTicketError::Expired => write!(f, "session ticket has expired"),
            SessionTicketError::NotYetValid => {
                write!(f, "session ticket not yet valid (clock skew?)")
            }
        }
    }
}

impl std::error::Error for SessionTicketError {}

/// Label used as associated data for AEAD.
const TICKET_AAD: &[u8] = b"HSIP-TICKET-V1";

const INNER_LEN: usize = 32 + 4 + 8 + 8; // PeerId(32) + caps(u32) + 2x u64

fn encode_inner(data: &SessionTicketData) -> [u8; INNER_LEN] {
    let mut buf = [0u8; INNER_LEN];

    // peer_id: 32 bytes
    buf[0..32].copy_from_slice(&data.peer_id.0);

    // caps: u32 LE
    buf[32..36].copy_from_slice(&data.caps.0.to_le_bytes());

    // issued_at_ms: u64 LE
    buf[36..44].copy_from_slice(&data.issued_at_ms.to_le_bytes());

    // expires_at_ms: u64 LE
    buf[44..52].copy_from_slice(&data.expires_at_ms.to_le_bytes());

    buf
}

fn decode_inner(buf: &[u8; INNER_LEN]) -> SessionTicketData {
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&buf[0..32]);
    let peer_id = PeerId(peer);

    let caps_raw = u32::from_le_bytes(buf[32..36].try_into().unwrap());
    let caps = HelloCapabilities(caps_raw);

    let issued_at_ms = u64::from_le_bytes(buf[36..44].try_into().unwrap());
    let expires_at_ms = u64::from_le_bytes(buf[44..52].try_into().unwrap());

    SessionTicketData {
        peer_id,
        caps,
        issued_at_ms,
        expires_at_ms,
    }
}

/// Create an encrypted resumption ticket for a peer.
///
/// `requested_lifetime_ms` must be <= cfg.max_lifetime_ms.
pub fn create_session_ticket(
    key: &SessionTicketKey,
    cfg: &SessionTicketConfig,
    peer_id: PeerId,
    caps: HelloCapabilities,
    now_ms: u64,
    requested_lifetime_ms: u64,
) -> Result<Vec<u8>, SessionTicketError> {
    if requested_lifetime_ms > cfg.max_lifetime_ms {
        return Err(SessionTicketError::TooLongLifetime);
    }

    let issued_at_ms = now_ms;
    let expires_at_ms = now_ms + requested_lifetime_ms;

    let inner = SessionTicketData {
        peer_id,
        caps,
        issued_at_ms,
        expires_at_ms,
    };

    let inner_bytes = encode_inner(&inner);

    // Build cipher
    let key_bytes = key.as_key();
    let cipher = ChaCha20Poly1305::new(&key_bytes);

    // Random 96-bit nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let mut ct = inner_bytes.to_vec();
    cipher
        .encrypt_in_place(nonce, TICKET_AAD, &mut ct)
        .map_err(|_| SessionTicketError::DecryptFailed)?;

    // Final ticket: nonce || ciphertext+tag
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt and validate a resumption ticket.
///
/// Checks:
///   * length
///   * AEAD integrity
///   * issued_at/expires_at v.s. now_ms
pub fn decrypt_session_ticket(
    key: &SessionTicketKey,
    cfg: &SessionTicketConfig,
    ticket: &[u8],
    now_ms: u64,
) -> Result<SessionTicketData, SessionTicketError> {
    // nonce(12) + inner(52) + tag(16) = 80 bytes minimum
    if ticket.len() < 12 + INNER_LEN + 16 {
        return Err(SessionTicketError::TicketTooShort);
    }

    let (nonce_part, ct_part) = ticket.split_at(12);

    let nonce = Nonce::from_slice(nonce_part);

    let key_bytes = key.as_key();
    let cipher = ChaCha20Poly1305::new(&key_bytes);

    let mut buf = ct_part.to_vec();

    cipher
        .decrypt_in_place(nonce, TICKET_AAD, &mut buf)
        .map_err(|_| SessionTicketError::DecryptFailed)?;

    if buf.len() != INNER_LEN {
        // should never happen if format is correct
        return Err(SessionTicketError::DecryptFailed);
    }

    let mut inner_bytes = [0u8; INNER_LEN];
    inner_bytes.copy_from_slice(&buf);
    let data = decode_inner(&inner_bytes);

    if now_ms < data.issued_at_ms {
        return Err(SessionTicketError::NotYetValid);
    }

    if now_ms > data.expires_at_ms {
        return Err(SessionTicketError::Expired);
    }

    // NOTE: For MVP, we just return data.
    // Caller can double-check peer_id against current identity if desired.
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::PeerId;

    fn now_ms() -> u64 {
        1_700_000_000_000
    }

    #[test]
    fn ticket_roundtrip() {
        let key = SessionTicketKey::new([7u8; 32]);
        let cfg = SessionTicketConfig::default();

        let peer_id = PeerId([1u8; 32]);
        let caps = HelloCapabilities::default_local();

        let ticket = create_session_ticket(
            &key,
            &cfg,
            peer_id,
            caps,
            now_ms(),
            30_000,
        )
        .expect("ticket should be created");

        let data =
            decrypt_session_ticket(&key, &cfg, &ticket, now_ms() + 10_000)
                .expect("ticket should be valid");

        assert_eq!(data.peer_id.0, peer_id.0);
        assert!(data.caps.supports(crate::hello::CAP_CONSENT_LAYER));
    }

    #[test]
    fn ticket_expires() {
        let key = SessionTicketKey::new([9u8; 32]);
        let cfg = SessionTicketConfig::default();

        let peer_id = PeerId([2u8; 32]);
        let caps = HelloCapabilities::default_local();

        let ticket = create_session_ticket(
            &key,
            &cfg,
            peer_id,
            caps,
            now_ms(),
            10_000,
        )
        .expect("ticket should be created");

        let err = decrypt_session_ticket(
            &key,
            &cfg,
            &ticket,
            now_ms() + 11_000,
        )
        .unwrap_err();

        matches!(err, SessionTicketError::Expired);
    }
}
