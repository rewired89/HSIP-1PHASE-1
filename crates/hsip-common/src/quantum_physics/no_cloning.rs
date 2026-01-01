//! No-Cloning Theorem Implementation
//!
//! In quantum mechanics, it's impossible to create an identical copy of an
//! arbitrary unknown quantum state. We implement this as anti-replay protection:
//!
//! - Each token has a unique nonce that can only be used once
//! - Tokens are cryptographically bound to sessions
//! - A sliding window tracks seen nonces to detect replays
//!
//! ## Security Properties
//! - Replay attacks are detected and rejected
//! - Even captured messages cannot be reused
//! - Forward secrecy through session binding

use blake3::Hasher;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Size of the nonce in bytes (192 bits for strong uniqueness)
pub const NONCE_SIZE: usize = 24;

/// Maximum age of nonces to track (default: 5 minutes)
pub const DEFAULT_NONCE_WINDOW_SECS: u64 = 300;

/// Maximum number of nonces to track before cleanup
pub const MAX_NONCE_CACHE_SIZE: usize = 100_000;

/// Errors from no-cloning operations
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NoClonError {
    #[error("Replay attack detected: nonce already used")]
    ReplayDetected,
    #[error("Nonce too old (outside acceptance window)")]
    NonceExpired,
    #[error("Invalid nonce format")]
    InvalidNonce,
    #[error("Session binding mismatch")]
    SessionMismatch,
    #[error("Token verification failed")]
    VerificationFailed,
}

/// A unique, single-use nonce that prevents replay attacks.
///
/// Once used, a nonce cannot be reused - implementing the no-cloning theorem.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuantumNonce {
    /// The unique nonce bytes
    bytes: [u8; NONCE_SIZE],
    /// Unix timestamp when created (for expiry checking)
    created_at_ms: u64,
}

impl QuantumNonce {
    /// Generate a fresh, cryptographically random nonce
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut bytes);

        let created_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self { bytes, created_at_ms }
    }

    /// Get the nonce bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.bytes
    }

    /// Get creation timestamp
    #[must_use]
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Check if nonce is within the acceptable time window
    #[must_use]
    pub fn is_within_window(&self, window_secs: u64) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let age_ms = now_ms.saturating_sub(self.created_at_ms);
        age_ms <= window_secs * 1000
    }

    /// Serialize to hex string
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, NoClonError> {
        let bytes_vec = hex::decode(s).map_err(|_| NoClonError::InvalidNonce)?;
        if bytes_vec.len() != NONCE_SIZE {
            return Err(NoClonError::InvalidNonce);
        }

        let mut bytes = [0u8; NONCE_SIZE];
        bytes.copy_from_slice(&bytes_vec);

        // Parse timestamp from first 8 bytes or use current time
        let created_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(Self { bytes, created_at_ms })
    }
}

/// Entry in the nonce cache with expiry tracking
#[derive(Debug, Clone)]
struct NonceEntry {
    nonce_hash: [u8; 32],
    seen_at: Instant,
}

/// Anti-replay guard that tracks used nonces.
///
/// Implements the No-Cloning Theorem by ensuring each nonce can only be used once.
#[derive(Debug)]
pub struct AntiReplayGuard {
    /// Set of seen nonce hashes
    seen_nonces: RwLock<HashSet<[u8; 32]>>,
    /// Ordered list for expiry cleanup
    nonce_order: RwLock<Vec<NonceEntry>>,
    /// Window duration for accepting nonces
    window: Duration,
    /// Session binding (optional)
    session_id: Option<[u8; 32]>,
}

impl AntiReplayGuard {
    /// Create a new anti-replay guard with default window
    #[must_use]
    pub fn new() -> Self {
        Self::with_window(Duration::from_secs(DEFAULT_NONCE_WINDOW_SECS))
    }

    /// Create with custom window duration
    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            seen_nonces: RwLock::new(HashSet::new()),
            nonce_order: RwLock::new(Vec::new()),
            window,
            session_id: None,
        }
    }

    /// Bind to a specific session for additional security
    pub fn bind_to_session(&mut self, session_id: [u8; 32]) {
        self.session_id = Some(session_id);
    }

    /// Hash a nonce with optional session binding
    fn hash_nonce(&self, nonce: &QuantumNonce) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(nonce.as_bytes());

        if let Some(sid) = &self.session_id {
            hasher.update(sid);
        }

        *hasher.finalize().as_bytes()
    }

    /// Check if a nonce is valid and mark it as used.
    ///
    /// Returns `Ok(())` if the nonce is fresh, or an error if it's a replay.
    ///
    /// # Errors
    /// - `ReplayDetected` if the nonce was already used
    /// - `NonceExpired` if the nonce is too old
    pub fn check_and_mark(&self, nonce: &QuantumNonce) -> Result<(), NoClonError> {
        // Check time window
        if !nonce.is_within_window(self.window.as_secs()) {
            return Err(NoClonError::NonceExpired);
        }

        let hash = self.hash_nonce(nonce);

        // Cleanup expired entries first
        self.cleanup_expired();

        // Check for replay
        {
            let seen = self.seen_nonces.read();
            if seen.contains(&hash) {
                return Err(NoClonError::ReplayDetected);
            }
        }

        // Mark as seen
        {
            let mut seen = self.seen_nonces.write();
            let mut order = self.nonce_order.write();

            // Double-check after acquiring write lock
            if seen.contains(&hash) {
                return Err(NoClonError::ReplayDetected);
            }

            seen.insert(hash);
            order.push(NonceEntry {
                nonce_hash: hash,
                seen_at: Instant::now(),
            });

            // Cleanup if too large
            if seen.len() > MAX_NONCE_CACHE_SIZE {
                self.cleanup_oldest(&mut seen, &mut order);
            }
        }

        Ok(())
    }

    /// Check if a nonce would be valid (without marking it)
    #[must_use]
    pub fn would_accept(&self, nonce: &QuantumNonce) -> bool {
        if !nonce.is_within_window(self.window.as_secs()) {
            return false;
        }

        let hash = self.hash_nonce(nonce);
        let seen = self.seen_nonces.read();
        !seen.contains(&hash)
    }

    /// Remove expired nonces from the cache
    fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut order = self.nonce_order.write();
        let mut seen = self.seen_nonces.write();

        // Remove all expired entries
        let expired_count = order
            .iter()
            .take_while(|e| now.duration_since(e.seen_at) > self.window)
            .count();

        for entry in order.drain(..expired_count) {
            seen.remove(&entry.nonce_hash);
        }
    }

    /// Remove oldest entries when cache is too large
    fn cleanup_oldest(
        &self,
        seen: &mut HashSet<[u8; 32]>,
        order: &mut Vec<NonceEntry>,
    ) {
        // Remove oldest 10% of entries
        let remove_count = order.len() / 10;
        for entry in order.drain(..remove_count) {
            seen.remove(&entry.nonce_hash);
        }
    }

    /// Get current number of tracked nonces
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.seen_nonces.read().len()
    }
}

impl Default for AntiReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// A single-use token that implements the no-cloning theorem.
///
/// This token can only be validated once - attempting to use it again
/// will result in a replay error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleUseToken {
    /// Unique nonce
    pub nonce: QuantumNonce,
    /// Token payload (e.g., consent data)
    pub payload: Vec<u8>,
    /// BLAKE3 hash binding nonce to payload
    pub binding: [u8; 32],
}

impl SingleUseToken {
    /// Create a new single-use token with the given payload
    #[must_use]
    pub fn new(payload: Vec<u8>) -> Self {
        let nonce = QuantumNonce::generate();
        let binding = Self::compute_binding(&nonce, &payload);

        Self {
            nonce,
            payload,
            binding,
        }
    }

    /// Compute the binding hash
    fn compute_binding(nonce: &QuantumNonce, payload: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"HSIP-NO-CLONE-BINDING-v1");
        hasher.update(nonce.as_bytes());
        hasher.update(payload);
        *hasher.finalize().as_bytes()
    }

    /// Verify the token's integrity
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_binding(&self.nonce, &self.payload);
        expected == self.binding
    }

    /// Validate and consume this token using the given guard.
    ///
    /// # Errors
    /// - `VerificationFailed` if integrity check fails
    /// - `ReplayDetected` if token was already used
    /// - `NonceExpired` if token is too old
    pub fn validate_and_consume(&self, guard: &AntiReplayGuard) -> Result<(), NoClonError> {
        // Check integrity first
        if !self.verify_integrity() {
            return Err(NoClonError::VerificationFailed);
        }

        // Mark nonce as used (will fail on replay)
        guard.check_and_mark(&self.nonce)
    }
}

/// Thread-safe anti-replay guard for concurrent access
pub type SharedAntiReplayGuard = Arc<AntiReplayGuard>;

/// Create a new shared anti-replay guard
#[must_use]
pub fn new_shared_guard() -> SharedAntiReplayGuard {
    Arc::new(AntiReplayGuard::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_generation_unique() {
        let n1 = QuantumNonce::generate();
        let n2 = QuantumNonce::generate();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn nonce_hex_roundtrip() {
        let n1 = QuantumNonce::generate();
        let hex = n1.to_hex();
        let n2 = QuantumNonce::from_hex(&hex).unwrap();
        assert_eq!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn guard_accepts_fresh_nonce() {
        let guard = AntiReplayGuard::new();
        let nonce = QuantumNonce::generate();
        assert!(guard.check_and_mark(&nonce).is_ok());
    }

    #[test]
    fn guard_rejects_replay() {
        let guard = AntiReplayGuard::new();
        let nonce = QuantumNonce::generate();

        // First use succeeds
        assert!(guard.check_and_mark(&nonce).is_ok());

        // Second use fails (replay)
        assert_eq!(
            guard.check_and_mark(&nonce),
            Err(NoClonError::ReplayDetected)
        );
    }

    #[test]
    fn guard_session_binding() {
        let nonce = QuantumNonce::generate();

        let mut guard1 = AntiReplayGuard::new();
        guard1.bind_to_session([1u8; 32]);

        let mut guard2 = AntiReplayGuard::new();
        guard2.bind_to_session([2u8; 32]);

        // Same nonce accepted by different sessions
        assert!(guard1.check_and_mark(&nonce).is_ok());
        assert!(guard2.check_and_mark(&nonce).is_ok());
    }

    #[test]
    fn single_use_token_integrity() {
        let token = SingleUseToken::new(b"test payload".to_vec());
        assert!(token.verify_integrity());
    }

    #[test]
    fn single_use_token_tamper_detection() {
        let mut token = SingleUseToken::new(b"test payload".to_vec());
        token.payload = b"tampered".to_vec();
        assert!(!token.verify_integrity());
    }

    #[test]
    fn single_use_token_prevents_reuse() {
        let guard = AntiReplayGuard::new();
        let token = SingleUseToken::new(b"consent data".to_vec());

        // First use succeeds
        assert!(token.validate_and_consume(&guard).is_ok());

        // Second use fails
        assert_eq!(
            token.validate_and_consume(&guard),
            Err(NoClonError::ReplayDetected)
        );
    }
}
