//! Post-Quantum Cryptography (PQC) module for HSIP.
//!
//! This module implements hybrid classical + post-quantum cryptography:
//! - Hybrid KEM: X25519 + Kyber-768 (NIST Round 3 winner, now ML-KEM)
//! - Hybrid Signatures: Ed25519 + Dilithium3 (NIST Round 3 winner, now ML-DSA)
//!
//! The hybrid approach provides "defense in depth" - security against both
//! classical and quantum adversaries. If either algorithm is broken, the
//! combined construction remains secure.
//!
//! # Security Levels
//! - Kyber-768: NIST Level 3 (equivalent to AES-192)
//! - Dilithium3: NIST Level 3 (equivalent to AES-192)
//!
//! # Wire Format
//! Hybrid ciphertexts and signatures include both classical and PQ components,
//! allowing recipients to verify/decrypt with either or both.

#![cfg(feature = "pqc")]

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

// Kyber (ML-KEM) imports
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SharedSecret as KemSharedSecret};

// Dilithium (ML-DSA) imports
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as SignPublicKey};

// Classical crypto
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Domain separation labels for hybrid constructions
pub const HYBRID_KEM_LABEL: &[u8] = b"HSIP-Hybrid-KEM-v1";
pub const HYBRID_SIG_LABEL: &[u8] = b"HSIP-Hybrid-Sig-v1";

/// Kyber-768 public key size (1184 bytes)
pub const KYBER768_PK_SIZE: usize = 1184;
/// Kyber-768 secret key size (2400 bytes)
pub const KYBER768_SK_SIZE: usize = 2400;
/// Kyber-768 ciphertext size (1088 bytes)
pub const KYBER768_CT_SIZE: usize = 1088;
/// Kyber-768 shared secret size (32 bytes)
pub const KYBER768_SS_SIZE: usize = 32;

/// Dilithium3 public key size (1952 bytes)
pub const DILITHIUM3_PK_SIZE: usize = 1952;
/// Dilithium3 secret key size (4000 bytes)
pub const DILITHIUM3_SK_SIZE: usize = 4000;
/// Dilithium3 signature size (3309 bytes - pqcrypto format)
pub const DILITHIUM3_SIG_SIZE: usize = 3309;

/// Errors from PQC operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcError {
    /// Key generation failed
    KeyGenFailed,
    /// Encapsulation failed
    EncapsulateFailed,
    /// Decapsulation failed
    DecapsulateFailed,
    /// Signature generation failed
    SignFailed,
    /// Signature verification failed
    VerifyFailed,
    /// Invalid key format
    InvalidKey,
    /// Invalid ciphertext format
    InvalidCiphertext,
    /// Invalid signature format
    InvalidSignature,
    /// KDF expansion failed
    KdfFailed,
    /// Secret already consumed
    SecretConsumed,
}

impl core::fmt::Display for PqcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyGenFailed => write!(f, "PQC key generation failed"),
            Self::EncapsulateFailed => write!(f, "PQC encapsulation failed"),
            Self::DecapsulateFailed => write!(f, "PQC decapsulation failed"),
            Self::SignFailed => write!(f, "PQC signature generation failed"),
            Self::VerifyFailed => write!(f, "PQC signature verification failed"),
            Self::InvalidKey => write!(f, "Invalid PQC key format"),
            Self::InvalidCiphertext => write!(f, "Invalid PQC ciphertext format"),
            Self::InvalidSignature => write!(f, "Invalid PQC signature format"),
            Self::KdfFailed => write!(f, "KDF expansion failed"),
            Self::SecretConsumed => write!(f, "Secret key already consumed"),
        }
    }
}

impl std::error::Error for PqcError {}

// ============================================================================
// Hybrid KEM: X25519 + Kyber-768
// ============================================================================

/// Hybrid KEM keypair (X25519 + Kyber-768)
pub struct HybridKemKeypair {
    /// X25519 ephemeral secret (consumed on first use)
    x25519_secret: Option<EphemeralSecret>,
    /// X25519 public key
    x25519_public: X25519PublicKey,
    /// Kyber-768 public key
    kyber_pk: kyber768::PublicKey,
    /// Kyber-768 secret key
    kyber_sk: kyber768::SecretKey,
}

impl HybridKemKeypair {
    /// Generate a new hybrid KEM keypair
    #[must_use]
    pub fn generate() -> Self {
        // Generate X25519 ephemeral
        let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Generate Kyber-768 keypair
        let (kyber_pk, kyber_sk) = kyber768::keypair();

        Self {
            x25519_secret: Some(x25519_secret),
            x25519_public,
            kyber_pk,
            kyber_sk,
        }
    }

    /// Get X25519 public key bytes (32 bytes)
    #[must_use]
    pub fn x25519_public_bytes(&self) -> [u8; 32] {
        self.x25519_public.to_bytes()
    }

    /// Get Kyber-768 public key bytes (1184 bytes)
    #[must_use]
    pub fn kyber_pk_bytes(&self) -> Vec<u8> {
        self.kyber_pk.as_bytes().to_vec()
    }

    /// Export the hybrid public key (X25519 || Kyber-768 PK)
    /// Total size: 32 + 1184 = 1216 bytes
    #[must_use]
    pub fn public_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + KYBER768_PK_SIZE);
        out.extend_from_slice(&self.x25519_public_bytes());
        out.extend_from_slice(&self.kyber_pk_bytes());
        out
    }

    /// Check if the X25519 secret has been consumed
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        self.x25519_secret.is_none()
    }
}

/// Hybrid KEM ciphertext (X25519 ephemeral public + Kyber ciphertext)
#[derive(Clone)]
pub struct HybridCiphertext {
    /// X25519 ephemeral public key (32 bytes)
    pub x25519_ct: [u8; 32],
    /// Kyber-768 ciphertext (1088 bytes)
    pub kyber_ct: Vec<u8>,
}

impl HybridCiphertext {
    /// Total size of hybrid ciphertext: 32 + 1088 = 1120 bytes
    pub const SIZE: usize = 32 + KYBER768_CT_SIZE;

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        out.extend_from_slice(&self.x25519_ct);
        out.extend_from_slice(&self.kyber_ct);
        out
    }

    /// Deserialize from bytes
    ///
    /// # Errors
    /// Returns `PqcError::InvalidCiphertext` if bytes are wrong length
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < Self::SIZE {
            return Err(PqcError::InvalidCiphertext);
        }

        let mut x25519_ct = [0u8; 32];
        x25519_ct.copy_from_slice(&bytes[..32]);

        let kyber_ct = bytes[32..32 + KYBER768_CT_SIZE].to_vec();

        Ok(Self { x25519_ct, kyber_ct })
    }
}

/// Encapsulate to a peer's hybrid public key
///
/// Returns (ciphertext, shared_secret)
/// The shared secret is 32 bytes derived via HKDF from both X25519 and Kyber secrets.
///
/// # Errors
/// Returns error if the public key is invalid
pub fn hybrid_encapsulate(
    peer_x25519_pub: &[u8; 32],
    peer_kyber_pk: &[u8],
) -> Result<(HybridCiphertext, [u8; 32]), PqcError> {
    // Validate Kyber public key
    if peer_kyber_pk.len() != KYBER768_PK_SIZE {
        return Err(PqcError::InvalidKey);
    }

    // X25519 ephemeral key exchange
    let x_eph = EphemeralSecret::random_from_rng(OsRng);
    let x_pub = X25519PublicKey::from(&x_eph);
    let peer_x_pub = X25519PublicKey::from(*peer_x25519_pub);
    let x_shared = x_eph.diffie_hellman(&peer_x_pub);

    // Kyber encapsulation
    let kyber_pk = kyber768::PublicKey::from_bytes(peer_kyber_pk)
        .map_err(|_| PqcError::InvalidKey)?;
    let (kyber_ss, kyber_ct) = kyber768::encapsulate(&kyber_pk);

    // Combine shared secrets via HKDF
    let combined_secret = combine_shared_secrets(
        x_shared.as_bytes(),
        kyber_ss.as_bytes(),
    )?;

    let ct = HybridCiphertext {
        x25519_ct: x_pub.to_bytes(),
        kyber_ct: kyber_ct.as_bytes().to_vec(),
    };

    Ok((ct, combined_secret))
}

/// Decapsulate a hybrid ciphertext with our keypair
///
/// # Errors
/// Returns error if the X25519 secret was already consumed or decapsulation fails
pub fn hybrid_decapsulate(
    our_keypair: &mut HybridKemKeypair,
    ciphertext: &HybridCiphertext,
) -> Result<[u8; 32], PqcError> {
    // X25519 decapsulation (consume our ephemeral secret)
    let x_secret = our_keypair.x25519_secret.take()
        .ok_or(PqcError::SecretConsumed)?;
    let peer_x_pub = X25519PublicKey::from(ciphertext.x25519_ct);
    let x_shared = x_secret.diffie_hellman(&peer_x_pub);

    // Kyber decapsulation
    let kyber_ct = kyber768::Ciphertext::from_bytes(&ciphertext.kyber_ct)
        .map_err(|_| PqcError::InvalidCiphertext)?;
    let kyber_ss = kyber768::decapsulate(&kyber_ct, &our_keypair.kyber_sk);

    // Combine shared secrets
    combine_shared_secrets(x_shared.as_bytes(), kyber_ss.as_bytes())
}

/// Combine X25519 and Kyber shared secrets using HKDF-SHA256
fn combine_shared_secrets(x_shared: &[u8], kyber_shared: &[u8]) -> Result<[u8; 32], PqcError> {
    // Concatenate both shared secrets as IKM
    let mut ikm = Vec::with_capacity(x_shared.len() + kyber_shared.len());
    ikm.extend_from_slice(x_shared);
    ikm.extend_from_slice(kyber_shared);

    // HKDF-SHA256 with hybrid label
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HYBRID_KEM_LABEL, &mut okm)
        .map_err(|_| PqcError::KdfFailed)?;

    // Zeroize IKM
    ikm.zeroize();

    Ok(okm)
}

// ============================================================================
// Hybrid Signatures: Ed25519 + Dilithium3
// ============================================================================

/// Hybrid signature (Ed25519 + Dilithium3)
#[derive(Clone)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes)
    pub ed25519_sig: [u8; 64],
    /// Dilithium3 signature (3293 bytes)
    pub dilithium_sig: Vec<u8>,
}

impl HybridSignature {
    /// Total size: 64 + 3293 = 3357 bytes
    pub const SIZE: usize = 64 + DILITHIUM3_SIG_SIZE;

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        out.extend_from_slice(&self.ed25519_sig);
        out.extend_from_slice(&self.dilithium_sig);
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < Self::SIZE {
            return Err(PqcError::InvalidSignature);
        }

        let mut ed25519_sig = [0u8; 64];
        ed25519_sig.copy_from_slice(&bytes[..64]);
        let dilithium_sig = bytes[64..64 + DILITHIUM3_SIG_SIZE].to_vec();

        Ok(Self { ed25519_sig, dilithium_sig })
    }
}

/// Hybrid signing keypair (Ed25519 + Dilithium3)
pub struct HybridSigningKeypair {
    /// Ed25519 signing key
    pub ed25519_sk: SigningKey,
    /// Ed25519 verifying key
    pub ed25519_vk: VerifyingKey,
    /// Dilithium3 public key
    pub dilithium_pk: dilithium3::PublicKey,
    /// Dilithium3 secret key
    pub dilithium_sk: dilithium3::SecretKey,
}

impl HybridSigningKeypair {
    /// Generate a new hybrid signing keypair
    #[must_use]
    pub fn generate() -> Self {
        // Generate Ed25519 keypair
        let ed25519_sk = SigningKey::generate(&mut OsRng);
        let ed25519_vk = ed25519_sk.verifying_key();

        // Generate Dilithium3 keypair
        let (dilithium_pk, dilithium_sk) = dilithium3::keypair();

        Self {
            ed25519_sk,
            ed25519_vk,
            dilithium_pk,
            dilithium_sk,
        }
    }

    /// Get Ed25519 verifying key bytes (32 bytes)
    #[must_use]
    pub fn ed25519_vk_bytes(&self) -> [u8; 32] {
        self.ed25519_vk.to_bytes()
    }

    /// Get Dilithium3 public key bytes (1952 bytes)
    #[must_use]
    pub fn dilithium_pk_bytes(&self) -> Vec<u8> {
        self.dilithium_pk.as_bytes().to_vec()
    }

    /// Export hybrid public key (Ed25519 VK || Dilithium3 PK)
    /// Total size: 32 + 1952 = 1984 bytes
    #[must_use]
    pub fn public_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + DILITHIUM3_PK_SIZE);
        out.extend_from_slice(&self.ed25519_vk_bytes());
        out.extend_from_slice(&self.dilithium_pk_bytes());
        out
    }

    /// Sign a message with hybrid signature (Ed25519 + Dilithium3)
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        // Ed25519 signature
        let ed_sig = self.ed25519_sk.sign(message);

        // Dilithium3 signature
        let dilithium_sig = dilithium3::detached_sign(message, &self.dilithium_sk);

        HybridSignature {
            ed25519_sig: ed_sig.to_bytes(),
            dilithium_sig: dilithium_sig.as_bytes().to_vec(),
        }
    }
}

/// Hybrid verifying key (Ed25519 + Dilithium3)
#[derive(Clone)]
pub struct HybridVerifyingKey {
    /// Ed25519 verifying key
    pub ed25519_vk: VerifyingKey,
    /// Dilithium3 public key
    pub dilithium_pk: dilithium3::PublicKey,
}

impl HybridVerifyingKey {
    /// Total public key size: 32 + 1952 = 1984 bytes
    pub const SIZE: usize = 32 + DILITHIUM3_PK_SIZE;

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < Self::SIZE {
            return Err(PqcError::InvalidKey);
        }

        let ed25519_vk = VerifyingKey::from_bytes(
            bytes[..32].try_into().map_err(|_| PqcError::InvalidKey)?
        ).map_err(|_| PqcError::InvalidKey)?;

        let dilithium_pk = dilithium3::PublicKey::from_bytes(&bytes[32..32 + DILITHIUM3_PK_SIZE])
            .map_err(|_| PqcError::InvalidKey)?;

        Ok(Self { ed25519_vk, dilithium_pk })
    }

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        out.extend_from_slice(self.ed25519_vk.as_bytes());
        out.extend_from_slice(self.dilithium_pk.as_bytes());
        out
    }

    /// Verify a hybrid signature
    ///
    /// Both Ed25519 and Dilithium3 signatures must be valid.
    ///
    /// # Errors
    /// Returns `PqcError::VerifyFailed` if either signature is invalid
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<(), PqcError> {
        // Verify Ed25519 signature
        let ed_sig = Ed25519Signature::from_bytes(&signature.ed25519_sig);
        self.ed25519_vk.verify(message, &ed_sig)
            .map_err(|_| PqcError::VerifyFailed)?;

        // Verify Dilithium3 signature
        let dilithium_sig = dilithium3::DetachedSignature::from_bytes(&signature.dilithium_sig)
            .map_err(|_| PqcError::InvalidSignature)?;
        dilithium3::verify_detached_signature(&dilithium_sig, message, &self.dilithium_pk)
            .map_err(|_| PqcError::VerifyFailed)?;

        Ok(())
    }
}

// ============================================================================
// Capability Flags for Protocol Negotiation
// ============================================================================

/// PQC capability flags for protocol negotiation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PqcCapabilities {
    /// Supports Kyber-768 hybrid key exchange
    pub kyber768: bool,
    /// Supports Dilithium3 hybrid signatures
    pub dilithium3: bool,
}

impl PqcCapabilities {
    /// No PQC support (classical only)
    pub const NONE: Self = Self {
        kyber768: false,
        dilithium3: false,
    };

    /// Full PQC support (all algorithms)
    pub const FULL: Self = Self {
        kyber768: true,
        dilithium3: true,
    };

    /// Encode to capability byte
    /// Bit 0: Kyber-768
    /// Bit 1: Dilithium3
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.kyber768 {
            b |= 0x01;
        }
        if self.dilithium3 {
            b |= 0x02;
        }
        b
    }

    /// Decode from capability byte
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        Self {
            kyber768: (b & 0x01) != 0,
            dilithium3: (b & 0x02) != 0,
        }
    }

    /// Check if any PQC algorithm is supported
    #[must_use]
    pub const fn any(self) -> bool {
        self.kyber768 || self.dilithium3
    }

    /// Negotiate common capabilities between two peers
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            kyber768: self.kyber768 && other.kyber768,
            dilithium3: self.dilithium3 && other.dilithium3,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_roundtrip() {
        // Alice generates keypair
        let mut alice = HybridKemKeypair::generate();
        let alice_x_pub = alice.x25519_public_bytes();
        let alice_kyber_pk = alice.kyber_pk_bytes();

        // Bob encapsulates to Alice
        let (ct, bob_secret) = hybrid_encapsulate(&alice_x_pub, &alice_kyber_pk).unwrap();

        // Alice decapsulates
        let alice_secret = hybrid_decapsulate(&mut alice, &ct).unwrap();

        // Both derive same shared secret
        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn hybrid_kem_cannot_reuse_secret() {
        let mut alice = HybridKemKeypair::generate();
        let alice_x_pub = alice.x25519_public_bytes();
        let alice_kyber_pk = alice.kyber_pk_bytes();

        let (ct, _) = hybrid_encapsulate(&alice_x_pub, &alice_kyber_pk).unwrap();

        // First decapsulation succeeds
        let _ = hybrid_decapsulate(&mut alice, &ct).unwrap();

        // Second decapsulation fails (secret consumed)
        assert!(alice.is_consumed());
        assert_eq!(
            hybrid_decapsulate(&mut alice, &ct).unwrap_err(),
            PqcError::SecretConsumed
        );
    }

    #[test]
    fn hybrid_signature_roundtrip() {
        let keypair = HybridSigningKeypair::generate();
        let message = b"Hello, post-quantum world!";

        let sig = keypair.sign(message);

        // Create verifying key from keypair
        let vk = HybridVerifyingKey {
            ed25519_vk: keypair.ed25519_vk,
            dilithium_pk: keypair.dilithium_pk.clone(),
        };

        // Verify with correct message
        assert!(vk.verify(message, &sig).is_ok());

        // Verify with wrong message
        let wrong_msg = b"Wrong message";
        assert!(vk.verify(wrong_msg, &sig).is_err());
    }

    #[test]
    fn signature_serialization() {
        let keypair = HybridSigningKeypair::generate();
        let message = b"Test message for serialization";

        let sig = keypair.sign(message);
        let bytes = sig.to_bytes();
        let sig2 = HybridSignature::from_bytes(&bytes).unwrap();

        // Check Ed25519 signature matches
        assert_eq!(sig.ed25519_sig, sig2.ed25519_sig);

        // Verify the deserialized signature still works
        let vk = HybridVerifyingKey {
            ed25519_vk: keypair.ed25519_vk,
            dilithium_pk: keypair.dilithium_pk.clone(),
        };
        assert!(vk.verify(message, &sig).is_ok());
        assert!(vk.verify(message, &sig2).is_ok());
    }

    #[test]
    fn ciphertext_serialization() {
        let alice = HybridKemKeypair::generate();
        let alice_x_pub = alice.x25519_public_bytes();
        let alice_kyber_pk = alice.kyber_pk_bytes();

        let (ct, _) = hybrid_encapsulate(&alice_x_pub, &alice_kyber_pk).unwrap();

        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), HybridCiphertext::SIZE);

        let ct2 = HybridCiphertext::from_bytes(&bytes).unwrap();

        assert_eq!(ct.x25519_ct, ct2.x25519_ct);
        assert_eq!(ct.kyber_ct, ct2.kyber_ct);
    }

    #[test]
    fn capability_negotiation() {
        let alice = PqcCapabilities::FULL;
        let bob = PqcCapabilities {
            kyber768: true,
            dilithium3: false,
        };

        let common = alice.intersect(bob);
        assert!(common.kyber768);
        assert!(!common.dilithium3);

        // Test byte encoding
        assert_eq!(PqcCapabilities::FULL.to_byte(), 0x03);
        assert_eq!(PqcCapabilities::NONE.to_byte(), 0x00);
        assert_eq!(bob.to_byte(), 0x01);

        // Test byte decoding
        assert_eq!(PqcCapabilities::from_byte(0x03), PqcCapabilities::FULL);
        assert_eq!(PqcCapabilities::from_byte(0x00), PqcCapabilities::NONE);
    }

    #[test]
    fn verifying_key_serialization() {
        let keypair = HybridSigningKeypair::generate();
        let bytes = keypair.public_bytes();

        assert_eq!(bytes.len(), HybridVerifyingKey::SIZE);

        let vk = HybridVerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(vk.ed25519_vk.as_bytes(), keypair.ed25519_vk.as_bytes());
        assert_eq!(vk.dilithium_pk.as_bytes(), keypair.dilithium_pk.as_bytes());
    }
}
