//! hsip-session: ephemeral session handshake + AEAD sealing helpers.
//! X25519 (ephemeral) → HKDF-SHA256 → ChaCha20-Poly1305
//!
//! - RAM-only keys, Zeroize on drop
//! - Nonce: 96-bit = [4B random prefix | 8B counter]
//! - Rekey via new shared secret
//! - Handshake: transport-agnostic exchange of ephemeral pubkeys.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

pub mod persistence;

/// Default HKDF info for session keys (domain separation).
const DEFAULT_INFO: &[u8] = b"HSIP v1 session key";

#[derive(Debug, Clone)]
pub struct PeerLabel {
    /// Optional ASCII label to bind into HKDF info (e.g., b"CONSENTv1|peerA->peerB")
    pub label: Vec<u8>,
}

/// Errors that can occur when deriving/using a session.
#[derive(Debug)]
pub enum SessionError {
    /// Attempted to reuse an ephemeral secret that was already consumed.
    Consumed,
    /// HKDF expand failed.
    KdfExpand,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Consumed => f.write_str("ephemeral already consumed"),
            Self::KdfExpand => f.write_str("HKDF expand failed"),
        }
    }
}
impl std::error::Error for SessionError {}

/// Errors that can occur during sealing.
#[derive(Debug)]
pub enum SealError {
    /// AEAD encryption failed.
    Encrypt,
}
impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encrypt => f.write_str("AEAD encrypt failed"),
        }
    }
}
impl std::error::Error for SealError {}

/// Errors that can occur during opening a sealed frame.
#[derive(Debug)]
pub enum OpenError {
    /// Input shorter than 12B nonce + 16B tag.
    Truncated,
    /// Nonce prefix mismatch or malformed nonce.
    BadNonce,
    /// Nonce counter not strictly increasing.
    Replayed,
    /// AEAD authentication failed.
    AuthFailed,
}
impl core::fmt::Display for OpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("frame truncated (nonce+tag missing)"),
            Self::BadNonce => f.write_str("bad or mismatched nonce"),
            Self::Replayed => f.write_str("replay detected (stale counter)"),
            Self::AuthFailed => f.write_str("AEAD auth failed"),
        }
    }
}
impl std::error::Error for OpenError {}

/// Our ephemeral X25519 keypair. Secret is "one-shot": consumed on use.
pub struct Ephemeral {
    secret: Option<EphemeralSecret>,
    pubkey: PublicKey,
}

impl Ephemeral {
    /// Generate a fresh ephemeral keypair.
    #[must_use]
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let pubkey = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            pubkey,
        }
    }

    /// Return the public key.
    #[must_use]
    pub const fn public(&self) -> PublicKey {
        self.pubkey
    }

    /// Consume this ephemeral to produce a 32-byte shared secret against `their_pub`.
    ///
    /// # Errors
    /// Returns [`SessionError::Consumed`] if this ephemeral has already been used.
    pub fn into_shared(mut self, their_pub: &PublicKey) -> Result<[u8; 32], SessionError> {
        let Some(secret) = self.secret.take() else {
            return Err(SessionError::Consumed);
        };
        let shared = secret.diffie_hellman(their_pub);
        Ok(shared.to_bytes())
    }
}

/// A symmetric session capable of sealing/opening frames.
///
/// Nonces are split by direction:
/// - TX: we send with our `tx_prefix` and increment `tx_counter`
/// - RX: on first receive we learn the peer `rx_prefix`; then enforce prefix match + monotonic `rx_counter`
pub struct Session {
    key: Key,
    cipher: ChaCha20Poly1305,

    // transmit side
    tx_prefix: [u8; 4],
    tx_counter: u64,

    // receive side
    rx_prefix: Option<[u8; 4]>, // learned from first incoming packet
    rx_counter: u64,            // last seen counter (monotonic)
}

impl Drop for Session {
    fn drop(&mut self) {
        // overwrite key without using deprecated GenericArray helpers
        self.key = Key::from([0u8; 32]);

        // clear counters/prefixes
        self.tx_counter = 0;
        self.rx_counter = 0;

        self.tx_prefix = [0u8; 4];
        if let Some(mut p) = self.rx_prefix.take() {
            p.zeroize();
        }
    }
}

impl Session {
    /// Derive a fresh `Session` from a raw X25519 shared secret + optional label.
    ///
    /// # Errors
    /// Returns [`SessionError::KdfExpand`] if HKDF expansion fails.
    pub fn from_shared_secret(
        shared: [u8; 32],
        label: Option<&PeerLabel>,
    ) -> Result<Self, SessionError> {
        // HKDF-Expand → 32B key
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut okm = [0u8; 32];

        // Use a default info string to ensure domain separation even without a label.
        let info = label.map_or(DEFAULT_INFO, |l| l.label.as_slice());

        hk.expand(info, &mut okm)
            .map_err(|_| SessionError::KdfExpand)?;

        // Avoid deprecated `from_slice`: construct from owned arrays.
        let key_owned: Key = Key::from(okm);
        let cipher = ChaCha20Poly1305::new(&key_owned);
        okm.zeroize();

        // randomize our transmit prefix
        let mut tx_prefix = [0u8; 4];
        OsRng.fill_bytes(&mut tx_prefix);

        Ok(Self {
            key: key_owned,
            cipher,
            tx_prefix,
            tx_counter: 0,
            rx_prefix: None,
            rx_counter: 0,
        })
    }

    /// Build a session by **consuming** our ephemeral secret against their pubkey.
    ///
    /// # Errors
    /// Propagates [`SessionError::Consumed`] or [`SessionError::KdfExpand`].
    pub fn from_handshake(
        our_eph: Ephemeral,
        their_pub: &PublicKey,
        label: Option<&PeerLabel>,
    ) -> Result<Self, SessionError> {
        let shared = our_eph.into_shared(their_pub)?;
        Self::from_shared_secret(shared, label)
    }

    /// Rekey using a NEW shared secret (e.g., after exchanging fresh ephemerals).
    /// Resets both tx and rx state (new prefixes/counters).
    ///
    /// # Errors
    /// Propagates [`SessionError::KdfExpand`].
    pub fn rekey_from_shared(
        &mut self,
        new_shared: [u8; 32],
        label: Option<&PeerLabel>,
    ) -> Result<(), SessionError> {
        *self = Self::from_shared_secret(new_shared, label)?;
        Ok(())
    }

    /// AEAD-seal: returns `nonce(12) || ciphertext+tag`.
    ///
    /// # Errors
    /// Returns [`SealError::Encrypt`] if AEAD encryption fails.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.tx_prefix);
        nonce_bytes[4..].copy_from_slice(&self.tx_counter.to_be_bytes());

        // Avoid deprecated `from_slice`
        let nonce = Nonce::from(nonce_bytes);

        let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
        out.extend_from_slice(&nonce_bytes);

        let ct = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| SealError::Encrypt)?;
        out.extend_from_slice(&ct);

        self.tx_counter = self.tx_counter.wrapping_add(1);
        Ok(out)
    }

    /// AEAD-open a frame produced by `seal`; expects `nonce || ct`.
    ///
    /// # Errors
    /// - [`OpenError::Truncated`] if input shorter than nonce+tag.
    /// - [`OpenError::BadNonce`] if prefix mismatches previously learned, or nonce malformed.
    /// - [`OpenError::Replayed`] if counter is stale.
    /// - [`OpenError::AuthFailed`] if AEAD authentication fails.
    pub fn open(&mut self, aad: &[u8], nonce_and_ct: &[u8]) -> Result<Vec<u8>, OpenError> {
        if nonce_and_ct.len() < 12 + 16 {
            return Err(OpenError::Truncated);
        }
        let (nonce_bytes, ct) = nonce_and_ct.split_at(12);

        // Learn rx_prefix from the first packet; thereafter, enforce equality
        match self.rx_prefix {
            None => {
                let mut p = [0u8; 4];
                p.copy_from_slice(&nonce_bytes[..4]);
                self.rx_prefix = Some(p);
            }
            Some(p) => {
                if p.ct_eq(&nonce_bytes[..4]).unwrap_u8() == 0 {
                    return Err(OpenError::BadNonce);
                }
            }
        }

        // Enforce monotonic counter for replay protection
        let ctr_slice = &nonce_bytes[4..12];
        let Ok(arr) = <&[u8; 8]>::try_from(ctr_slice) else {
            return Err(OpenError::BadNonce);
        };
        let rx_ctr = u64::from_be_bytes(*arr);

        if rx_ctr < self.rx_counter {
            return Err(OpenError::Replayed);
        }
        self.rx_counter = rx_ctr.wrapping_add(1);

        // Avoid deprecated `from_slice`
        let nonce =
            Nonce::from(<[u8; 12]>::try_from(nonce_bytes).map_err(|_| OpenError::BadNonce)?);

        let pt = self
            .cipher
            .decrypt(&nonce, Payload { msg: ct, aad })
            .map_err(|_| OpenError::AuthFailed)?;
        Ok(pt)
    }
}

/// Helper for tests/demos: build both sides.
///
/// # Errors
/// Returns [`SessionError::Consumed`] if an ephemeral is reused, or [`SessionError::KdfExpand`] on HKDF failure.
pub fn demo_pair(
    label: Option<&PeerLabel>,
) -> Result<(PublicKey, PublicKey, Session, Session), SessionError> {
    let client = Ephemeral::generate();
    let server = Ephemeral::generate();

    let c_pub = client.public();
    let s_pub = server.public();

    let c_sess = Session::from_handshake(client, &s_pub, label)?;
    let s_sess = Session::from_handshake(server, &c_pub, label)?;
    Ok((c_pub, s_pub, c_sess, s_sess))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let label = PeerLabel {
            label: b"CONSENTv1".to_vec(),
        };
        let (_c_pub, _s_pub, mut c_sess, mut s_sess) = demo_pair(Some(&label))?;

        let aad = b"type=CONSENT_REQUEST";
        let msg = b"hello world request bytes";

        let ct = c_sess.seal(aad, msg)?;
        let pt = s_sess.open(aad, &ct)?;
        assert_eq!(msg.to_vec(), pt);
        Ok(())
    }

    #[test]
    fn rejects_replay() -> Result<(), Box<dyn std::error::Error>> {
        let label = PeerLabel {
            label: b"CONSENTv1".to_vec(),
        };
        let (_c_pub, _s_pub, mut c_sess, mut s_sess) = demo_pair(Some(&label))?;

        let aad = b"type=CONSENT_RESPONSE";
        let msg = b"payload";

        let ct = c_sess.seal(aad, msg)?;
        let _ = s_sess.open(aad, &ct)?; // first ok

        match s_sess.open(aad, &ct) {
            Err(OpenError::Replayed) => Ok(()),
            Err(e) => Err(format!("expected replay, got {e}").into()),
            Ok(_) => Err("expected replay, got Ok".into()),
        }
    }

    #[test]
    fn rekey_works() -> Result<(), Box<dyn std::error::Error>> {
        let label = PeerLabel {
            label: b"CONSENTv1".to_vec(),
        };
        let (_c_pub, _s_pub, mut c_sess, mut s_sess) = demo_pair(Some(&label))?;

        // fresh ephemerals
        let c2 = Ephemeral::generate();
        let s2 = Ephemeral::generate();

        // take public keys BEFORE consuming ephemerals
        let c2_pub = c2.public();
        let s2_pub = s2.public();

        // now consume each to derive shared secret
        let shared_c = c2.into_shared(&s2_pub)?;
        let shared_s = s2.into_shared(&c2_pub)?;
        assert_eq!(shared_c, shared_s);

        let aad = b"type=CONSENT_AFTER_REKEY";
        c_sess.rekey_from_shared(shared_c, Some(&label))?;
        s_sess.rekey_from_shared(shared_s, Some(&label))?;

        let msg = b"new epoch";
        let ct = c_sess.seal(aad, msg)?;
        let pt = s_sess.open(aad, &ct)?;
        assert_eq!(msg.to_vec(), pt);
        Ok(())
    }
}
