//! HSIP HELLO handshake helpers.
//!
//! This wires together:
//!   * SignedHello
//!   * capabilities
//!   * on-the-wire encoding/decoding
//!   * version + timestamp checks
//!
//! Wire format for HELLO packet (109 bytes):
//!   [0]       : protocol_version (u8)
//!   [1..5]    : capabilities (u32 LE)
//!   [5..37]   : peer_id bytes (32)
//!   [37..45]  : timestamp_ms (u64 LE)
//!   [45..109] : signature (Ed25519, 64 bytes)

use core::fmt;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::hello::{
    HelloCapabilities, HelloError, HelloMessage, PeerId, SignedHello,
};

/// Fixed length of a HELLO packet on the wire.
pub const HSIP_HELLO_WIRE_LEN: usize = 1 + 4 + 32 + 8 + 64;

/// Handshake config for verifying incoming HELLO.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeConfig {
    /// Maximum allowed clock skew (in ms) between peers.
    pub max_skew_ms: u64,
    /// Local capabilities; will be intersected with remote.
    pub local_caps: HelloCapabilities,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        HandshakeConfig {
            max_skew_ms: 30_000, // 30 seconds
            local_caps: HelloCapabilities::default_local(),
        }
    }
}

impl HandshakeConfig {
    pub fn new(max_skew_ms: u64, local_caps: HelloCapabilities) -> Self {
        HandshakeConfig {
            max_skew_ms,
            local_caps,
        }
    }
}

/// High-level result of a verified HELLO.
#[derive(Debug, Clone)]
pub struct VerifiedHello {
    pub signed: SignedHello,
    pub negotiated_caps: HelloCapabilities,
}

impl fmt::Display for VerifiedHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HELLO from peer {:?}, negotiated_caps=0x{:08x}",
            self.signed.hello.peer_id.0,
            self.negotiated_caps.0
        )
    }
}

/// Build a local HELLO, sign it, and return the encoded wire packet.
pub fn build_local_hello_packet(
    signing_key: &SigningKey,
    now_ms: u64,
    caps: Option<HelloCapabilities>,
) -> [u8; HSIP_HELLO_WIRE_LEN] {
    let verifying_key = signing_key.verifying_key();
    let peer_id = PeerId::from_verifying_key(&verifying_key);

    let hello = match caps {
        Some(c) => HelloMessage::with_capabilities(peer_id, now_ms, c),
        None => HelloMessage::new(peer_id, now_ms),
    };

    let signed = SignedHello::sign(hello, signing_key);
    encode_signed_hello(&signed)
}

/// Encode a SignedHello into the fixed 109-byte wire format.
pub fn encode_signed_hello(signed: &SignedHello) -> [u8; HSIP_HELLO_WIRE_LEN] {
    let mut buf = [0u8; HSIP_HELLO_WIRE_LEN];

    let hello = &signed.hello;
    // Keep this layout in sync with the doc comment.
    buf[0] = hello.protocol_version;
    buf[1..5].copy_from_slice(&hello.capabilities.0.to_le_bytes());
    buf[5..37].copy_from_slice(&hello.peer_id.0);
    buf[37..45].copy_from_slice(&hello.timestamp_ms.to_le_bytes());

    let sig_bytes = signed.signature.to_bytes();
    buf[45..109].copy_from_slice(&sig_bytes);

    buf
}

/// Decode a HELLO packet from wire format into SignedHello.
///
/// NOTE: This does NOT verify the signature or timestamp.
/// Call `verify_remote_hello` after this.
pub fn decode_hello_packet(buf: &[u8]) -> Result<SignedHello, HelloError> {
    if buf.len() != HSIP_HELLO_WIRE_LEN {
        // For MVP we just treat malformed length as "bad signature".
        return Err(HelloError::BadSignature);
    }

    let protocol_version = buf[0];

    let caps_raw = u32::from_le_bytes(
        buf[1..5]
            .try_into()
            .expect("slice length checked above"),
    );
    let capabilities = HelloCapabilities(caps_raw);

    let mut peer_bytes = [0u8; 32];
    peer_bytes.copy_from_slice(&buf[5..37]);
    let peer_id = PeerId(peer_bytes);

    let timestamp_ms = u64::from_le_bytes(
        buf[37..45]
            .try_into()
            .expect("slice length checked above"),
    );

    let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&buf[45..109]);
    let sig = Signature::from_bytes(&sig_bytes);

    let hello = HelloMessage {
        protocol_version,
        capabilities,
        peer_id,
        timestamp_ms,
    };

    Ok(SignedHello { hello, signature: sig })
}

/// Verify an incoming HELLO packet:
///   * decode
///   * signature check
///   * version + timestamp
///   * capabilities negotiation
pub fn verify_remote_hello(
    cfg: &HandshakeConfig,
    raw: &[u8],
    remote_verifying_key: &VerifyingKey,
    now_ms: u64,
) -> Result<VerifiedHello, HelloError> {
    let signed = decode_hello_packet(raw)?;
    // This checks protocol version, timestamp skew, and signature.
    signed.verify(remote_verifying_key, now_ms, cfg.max_skew_ms)?;

    let negotiated = signed.negotiated_capabilities(cfg.local_caps)?;

    Ok(VerifiedHello {
        signed,
        negotiated_caps: negotiated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn now_ms() -> u64 {
        1_700_000_000_000
    }

    #[test]
    fn hello_roundtrip_encode_decode_and_verify() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let cfg = HandshakeConfig::default();

        // Build local HELLO as bytes.
        let packet = build_local_hello_packet(&signing_key, now_ms(), None);

        // Remote side: verify.
        let verified = verify_remote_hello(&cfg, &packet, &verifying_key, now_ms())
            .expect("HELLO should verify");

        assert!(
            verified.negotiated_caps.supports(crate::hello::CAP_CONSENT_LAYER),
            "negotiated caps should include consent layer"
        );
    }

    #[test]
    fn malformed_packet_is_rejected() {
        let mut buf = [0u8; HSIP_HELLO_WIRE_LEN - 1]; // too short
        buf[0] = 1;

        let res = decode_hello_packet(&buf);
        match res {
            Err(HelloError::BadSignature) => {}
            other => panic!("expected BadSignature for malformed, got {:?}", other),
        }
    }
}
