//! hsip-session: ephemeral session handshake + AEAD sealing helpers.
//! X25519 (ephemeral) → HKDF-SHA256 → ChaCha20-Poly1305
//! - RAM-only keys, Zeroize on drop
//! - Nonce: 96-bit = [4B random prefix | 8B counter]
//! - Rekey via new shared secret
//! - Handshake:
//!   Transport-agnostic: you exchange eph pubkeys + signatures however you like.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct PeerLabel {
    /// Optional ASCII label to bind into HKDF info (e.g., b"CONSENTv1|peerA->peerB")
    pub label: Vec<u8>,
}

/// Our ephemeral X25519 keypair. Secret is "one-shot": consumed on use.
pub struct Ephemeral {
    secret: Option<EphemeralSecret>,
    pubkey: PublicKey,
}

impl Ephemeral {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let pubkey = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            pubkey,
        }
    }
    pub fn public(&self) -> PublicKey {
        self.pubkey
    }

    /// Consume this ephemeral to produce a 32-byte shared secret against `their_pub`.
    pub fn into_shared(mut self, their_pub: &PublicKey) -> [u8; 32] {
        let secret = self
            .secret
            .take()
            .expect("ephemeral already consumed (shared secret requested twice)");
        let shared = secret.diffie_hellman(their_pub);
        shared.to_bytes()
    }
}

/// A symmetric session capable of sealing/opening frames.
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
        let mut k = [0u8; 32];
        k.copy_from_slice(self.key.as_slice());
        k.zeroize();
        self.tx_counter = 0;
        self.rx_counter = 0;
        self.tx_prefix.zeroize();
        if let Some(mut p) = self.rx_prefix.take() {
            p.zeroize();
        }
    }
}

impl Session {
    /// Derive a fresh Session from a raw X25519 shared secret + optional label.
    pub fn from_shared_secret(shared: [u8; 32], label: Option<&PeerLabel>) -> Self {
        // HKDF-Expand → 32B key
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut okm = [0u8; 32];
        let info = label.map(|l| l.label.as_slice()).unwrap_or(&[]);
        hk.expand(info, &mut okm).expect("HKDF expand");

        // Create an OWNED Key so we can zeroize okm immediately after
        let key_owned: Key = *Key::from_slice(&okm);
        let cipher = ChaCha20Poly1305::new(&key_owned);
        okm.zeroize();

        // randomize our transmit prefix
        let mut tx_prefix = [0u8; 4];
        OsRng.fill_bytes(&mut tx_prefix);

        Self {
            key: key_owned,
            cipher,
            tx_prefix,
            tx_counter: 0,
            rx_prefix: None,
            rx_counter: 0,
        }
    }

    /// Build a session by CONSUMING our ephemeral secret against their pubkey.
    pub fn from_handshake(
        our_eph: Ephemeral,
        their_pub: &PublicKey,
        label: Option<&PeerLabel>,
    ) -> Self {
        let shared = our_eph.into_shared(their_pub);
        Self::from_shared_secret(shared, label)
    }

    /// Rekey using a NEW shared secret (e.g., after exchanging fresh eph keys).
    /// Resets both tx and rx state (new prefixes/counters).
    pub fn rekey_from_shared(&mut self, new_shared: [u8; 32], label: Option<&PeerLabel>) {
        *self = Self::from_shared_secret(new_shared, label);
    }

    /// AEAD-seal: returns `nonce(12) || ciphertext+tag`.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.tx_prefix);
        nonce_bytes[4..].copy_from_slice(&self.tx_counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
        out.extend_from_slice(&nonce_bytes);

        let ct = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("encrypt");
        out.extend_from_slice(&ct);

        self.tx_counter = self.tx_counter.wrapping_add(1);
        out
    }

    /// AEAD-open a frame produced by `seal`; expects `nonce || ct`.
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
        let rx_ctr = u64::from_be_bytes(nonce_bytes[4..12].try_into().unwrap());
        if rx_ctr < self.rx_counter {
            return Err(OpenError::Replayed);
        }
        self.rx_counter = rx_ctr.wrapping_add(1);

        let nonce = Nonce::from_slice(nonce_bytes);
        let pt = self
            .cipher
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|_| OpenError::AuthFailed)?;
        Ok(pt)
    }
}

#[derive(Debug)]
pub enum OpenError {
    Truncated,
    BadNonce,
    Replayed,
    AuthFailed,
}

/// Helper for tests/demos: build both sides.
pub fn demo_pair(label: Option<&PeerLabel>) -> (PublicKey, PublicKey, Session, Session) {
    let client = Ephemeral::generate();
    let server = Ephemeral::generate();

    let c_pub = client.public();
    let s_pub = server.public();

    let c_sess = Session::from_handshake(client, &s_pub, label);
    let s_sess = Session::from_handshake(server, &c_pub, label);
    (c_pub, s_pub, c_sess, s_sess)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let label = PeerLabel {
            label: b"CONSENTv1".to_vec(),
        };
        let (_c_pub, _s_pub, mut c_sess, mut s_sess) = demo_pair(Some(&label));

        let aad = b"type=CONSENT_REQUEST";
        let msg = b"hello world request bytes";

        let ct = c_sess.seal(aad, msg);
        let pt = s_sess.open(aad, &ct).expect("open");
        assert_eq!(msg.to_vec(), pt);
    }

    #[test]
    fn rejects_replay() {
        let label = PeerLabel {
            label: b"CONSENTv1".to_vec(),
        };
        let (_c_pub, _s_pub, mut c_sess, mut s_sess) = demo_pair(Some(&label));

        let aad = b"type=CONSENT_RESPONSE";
        let msg = b"payload";

        let ct = c_sess.seal(aad, msg);
        let _ = s_sess.open(aad, &ct).expect("open once");

        let err = s_sess.open(aad, &ct).unwrap_err();
        match err {
            OpenError::Replayed => {}
            _ => panic!("expected replay"),
        }
    }

    #[test]
    fn rekey_works() {
        let label = PeerLabel {
            label: b"CONSENTv1".to_vec(),
        };
        let (_c_pub, _s_pub, mut c_sess, mut s_sess) = demo_pair(Some(&label));

        // fresh ephemerals
        let c2 = Ephemeral::generate();
        let s2 = Ephemeral::generate();

        // take public keys BEFORE consuming ephemerals
        let c2_pub = c2.public();
        let s2_pub = s2.public();

        // now consume each to derive shared secret
        let shared_c = c2.into_shared(&s2_pub);
        let shared_s = s2.into_shared(&c2_pub);
        assert_eq!(shared_c, shared_s);

        let aad = b"type=CONSENT_AFTER_REKEY";
        c_sess.rekey_from_shared(shared_c, Some(&label));
        s_sess.rekey_from_shared(shared_s, Some(&label));

        let msg = b"new epoch";
        let ct = c_sess.seal(aad, msg);
        let pt = s_sess.open(aad, &ct).expect("open after rekey");
        assert_eq!(msg.to_vec(), pt);
    }
}
