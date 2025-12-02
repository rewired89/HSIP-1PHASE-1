//! HSIP HELLO message: protocol version + capabilities + signature.
//! This is the first thing peers exchange over UDP before consent.

use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Minimal PeerId for HELLO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        PeerId(vk.to_bytes())
    }
}

/// Current HSIP protocol version for the wire-level format.
pub const HSIP_VERSION_1: u8 = 1;

/// Bitmask capability flags advertised in HELLO.
pub const CAP_ENCRYPTED_SESSIONS: u32 = 1 << 0;
pub const CAP_CONSENT_LAYER: u32 = 1 << 1;
pub const CAP_REPLAY_GUARD: u32 = 1 << 2;
pub const CAP_NONCE_WINDOW: u32 = 1 << 3;
pub const CAP_SESSION_RESUMPTION: u32 = 1 << 4;
// Reserve high bits for future stuff (PQC, migration, etc.)
pub const CAP_RESERVED_PQC: u32 = 1 << 16;

/// Capabilities wrapper for type safety + helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloCapabilities(pub u32);

impl HelloCapabilities {
    /// Convenience for "no capabilities set".
    pub const fn empty() -> Self {
        HelloCapabilities(0)
    }

    /// Default capabilities supported by this HSIP build.
    pub const fn default_local() -> Self {
        HelloCapabilities(
            CAP_ENCRYPTED_SESSIONS
                | CAP_CONSENT_LAYER
                | CAP_REPLAY_GUARD
                | CAP_NONCE_WINDOW
                | CAP_SESSION_RESUMPTION,
        )
    }

    /// Check if a specific capability bit is set.
    pub const fn supports(&self, cap: u32) -> bool {
        (self.0 & cap) != 0
    }

    /// Intersection between local and remote capabilities.
    pub const fn intersect(self, other: HelloCapabilities) -> HelloCapabilities {
        HelloCapabilities(self.0 & other.0)
    }

    /// Returns true if there is at least one overlapping capability.
    pub const fn any_common(self, other: HelloCapabilities) -> bool {
        (self.0 & other.0) != 0
    }
}

/// Unsigned HELLO body.
/// This is what we sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    /// Wire protocol version.
    pub protocol_version: u8,
    /// Capability bitmask advertised by this peer.
    pub capabilities: HelloCapabilities,
    /// Logical identity of the peer (Ed25519-based).
    pub peer_id: PeerId,
    /// Millisecond timestamp when this HELLO was created.
    pub timestamp_ms: u64,
}

/// Signed HELLO wrapper.
///
/// NOTE:
///  * We do NOT derive Serialize/Deserialize here,
///    so we don't need serde support on `Signature`.
#[derive(Debug, Clone)]
pub struct SignedHello {
    pub hello: HelloMessage,
    pub signature: Signature,
}

/// High-level error type for HELLO validation.
#[derive(Debug)]
pub enum HelloError {
    UnsupportedVersion(u8),
    BadSignature,
    NoCommonCapabilities,
    BadTimestamp,
}

impl fmt::Display for HelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HelloError::UnsupportedVersion(v) => {
                write!(f, "unsupported HSIP protocol version: {}", v)
            }
            HelloError::BadSignature => write!(f, "HELLO signature verification failed"),
            HelloError::NoCommonCapabilities => {
                write!(f, "no common capabilities between peers")
            }
            HelloError::BadTimestamp => {
                write!(f, "HELLO timestamp too far in the past or future")
            }
        }
    }
}

impl std::error::Error for HelloError {}

impl HelloMessage {
    /// Construct a new HELLO with the standard local capabilities.
    pub fn new(peer_id: PeerId, timestamp_ms: u64) -> Self {
        HelloMessage {
            protocol_version: HSIP_VERSION_1,
            capabilities: HelloCapabilities::default_local(),
            peer_id,
            timestamp_ms,
        }
    }

    /// Create a HELLO with an explicit capabilities bitmask.
    pub fn with_capabilities(
        peer_id: PeerId,
        timestamp_ms: u64,
        capabilities: HelloCapabilities,
    ) -> Self {
        HelloMessage {
            protocol_version: HSIP_VERSION_1,
            capabilities,
            peer_id,
            timestamp_ms,
        }
    }

    /// Deterministic byte representation used for signing.
    ///
    /// Layout:
    /// [version:1][capabilities:4 LE][peer_id:32][timestamp_ms:8 LE]
    fn to_sig_bytes(&self) -> [u8; 1 + 4 + 32 + 8] {
        let mut out = [0u8; 1 + 4 + 32 + 8];

        // version
        out[0] = self.protocol_version;

        // capabilities (u32, little endian)
        let caps_bytes = self.capabilities.0.to_le_bytes();
        out[1..5].copy_from_slice(&caps_bytes);

        // peer_id bytes
        out[5..37].copy_from_slice(&self.peer_id.0);

        // timestamp_ms (u64, little endian)
        let ts_bytes = self.timestamp_ms.to_le_bytes();
        out[37..45].copy_from_slice(&ts_bytes);

        out
    }
}

impl SignedHello {
    /// Sign a HELLO body with the given Ed25519 signing key.
    ///
    /// NOTE: you should ensure `hello.peer_id` is consistent with
    /// the verifying key you expect on the other side.
    pub fn sign(hello: HelloMessage, signing_key: &SigningKey) -> Self {
        let msg = hello.to_sig_bytes();
        let signature = signing_key.sign(&msg);
        SignedHello { hello, signature }
    }

    /// Verify the HELLO signature and basic invariants.
    ///
    /// * Checks protocol version
    /// * Checks timestamp skew
    /// * Checks signature
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        now_ms: u64,
        max_skew_ms: u64,
    ) -> Result<(), HelloError> {
        // 1. Version check (downgrade protection, future-proofing).
        if self.hello.protocol_version != HSIP_VERSION_1 {
            return Err(HelloError::UnsupportedVersion(self.hello.protocol_version));
        }

        // 2. Timestamp freshness check.
        let ts = self.hello.timestamp_ms;
        if ts + max_skew_ms < now_ms || ts > now_ms + max_skew_ms {
            return Err(HelloError::BadTimestamp);
        }

        // 3. Signature verification.
        let msg = self.hello.to_sig_bytes();
        verifying_key
            .verify(&msg, &self.signature)
            .map_err(|_| HelloError::BadSignature)?;

        Ok(())
    }

    /// Compute negotiated capabilities from local + remote view.
    ///
    /// Call this after verifying the HELLO from the remote peer.
    pub fn negotiated_capabilities(
        &self,
        local_caps: HelloCapabilities,
    ) -> Result<HelloCapabilities, HelloError> {
        let remote_caps = self.hello.capabilities;
        let negotiated = local_caps.intersect(remote_caps);

        if negotiated.0 == 0 {
            return Err(HelloError::NoCommonCapabilities);
        }

        Ok(negotiated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn now_ms() -> u64 {
        // simple fixed timestamp for tests
        1_700_000_000_000
    }

    #[test]
    fn hello_sign_and_verify_roundtrip() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let peer_id = PeerId::from_verifying_key(&verifying_key);

        let hello = HelloMessage::new(peer_id, now_ms());
        let signed = SignedHello::sign(hello, &signing_key);

        // Verify with correct key
        let res = signed.verify(&verifying_key, now_ms(), 60_000);
        assert!(res.is_ok(), "HELLO verify should succeed");

        // Negotiate capabilities with local defaults
        let local_caps = HelloCapabilities::default_local();
        let negotiated = signed
            .negotiated_capabilities(local_caps)
            .expect("should have common capabilities");

        assert!(
            negotiated.supports(CAP_CONSENT_LAYER),
            "negotiated caps should include consent layer"
        );
    }

    #[test]
    fn hello_rejects_bad_signature() {
        let mut rng = OsRng;
        let signing_good = SigningKey::generate(&mut rng);
        let signing_bad = SigningKey::generate(&mut rng);
        let verifying_good = signing_good.verifying_key();
        let peer_id = PeerId::from_verifying_key(&verifying_good);

        let hello = HelloMessage::new(peer_id, now_ms());
        let signed = SignedHello::sign(hello, &signing_good);

        let res = signed.verify(&signing_bad.verifying_key(), now_ms(), 60_000);
        match res {
            Err(HelloError::BadSignature) => {}
            other => panic!("expected BadSignature, got {:?}", other),
        }
    }

    #[test]
    fn hello_rejects_unsupported_version() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let peer_id = PeerId::from_verifying_key(&verifying_key);

        let hello = HelloMessage::new(peer_id, now_ms());
        let mut signed = SignedHello::sign(hello, &signing_key);

        // Tamper with version AFTER signing
        signed.hello.protocol_version = 99;

        let res = signed.verify(&verifying_key, now_ms(), 60_000);
        match res {
            Err(HelloError::UnsupportedVersion(99)) => {}
            other => panic!("expected UnsupportedVersion(99), got {:?}", other),
        }
    }
}
