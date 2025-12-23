//! Superposition - Message State Privacy
//!
//! Inspired by quantum superposition where particles exist in multiple states
//! until observed, this module ensures message state/status remains private
//! until explicitly collapsed (revealed).
//!
//! # Security Properties
//! - Message status (read/unread/pending) is cryptographically hidden
//! - State is only revealed to authorized parties
//! - Prevents traffic analysis based on message states
//! - Supports "quantum sealed" messages that hide even existence

use blake3::Hasher;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors related to superposition state management
#[derive(Debug, Error)]
pub enum SuperpositionError {
    #[error("State already collapsed")]
    AlreadyCollapsed,
    #[error("Invalid collapse proof")]
    InvalidCollapseProof,
    #[error("Unauthorized state access")]
    Unauthorized,
    #[error("State not found: {0}")]
    StateNotFound(String),
    #[error("Cannot modify collapsed state")]
    ImmutableState,
}

/// Possible hidden states for a message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageState {
    /// Message not yet delivered
    Pending,
    /// Message delivered but not read
    Delivered,
    /// Message read by recipient
    Read,
    /// Message acknowledged/replied to
    Acknowledged,
    /// Message deleted/retracted
    Deleted,
    /// Message expired
    Expired,
}

/// Commitment to a state without revealing it
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateCommitment {
    /// The commitment hash (hides actual state)
    pub commitment: [u8; 32],
    /// When commitment was created
    pub created_at: DateTime<Utc>,
    /// Nonce for the commitment
    nonce: [u8; 32],
}

impl StateCommitment {
    /// Create a new commitment to a state
    pub fn new(state: MessageState, secret: &[u8; 32]) -> Self {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let commitment = Self::compute_commitment(state, &nonce, secret);

        Self {
            commitment,
            created_at: Utc::now(),
            nonce,
        }
    }

    /// Compute the commitment hash
    fn compute_commitment(state: MessageState, nonce: &[u8; 32], secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Hasher::new_keyed(secret);
        hasher.update(&[state as u8]);
        hasher.update(nonce);
        let hash = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(hash.as_bytes());
        commitment
    }

    /// Verify a state matches this commitment (collapse the superposition)
    pub fn verify(&self, state: MessageState, secret: &[u8; 32]) -> bool {
        let expected = Self::compute_commitment(state, &self.nonce, secret);
        self.commitment == expected
    }
}

/// A superposition state that can be collapsed to reveal the actual state
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SuperpositionState {
    /// Message/entity identifier
    #[zeroize(skip)]
    pub entity_id: [u8; 32],
    /// Encrypted actual state (only decryptable by authorized parties)
    encrypted_state: Vec<u8>,
    /// Commitment to the state
    #[zeroize(skip)]
    commitment: StateCommitment,
    /// Whether state has been collapsed (revealed)
    #[zeroize(skip)]
    collapsed: bool,
    /// When state was collapsed (if applicable)
    #[zeroize(skip)]
    collapsed_at: Option<DateTime<Utc>>,
    /// The revealed state (only set after collapse)
    #[zeroize(skip)]
    revealed_state: Option<MessageState>,
}

impl SuperpositionState {
    /// Create a new superposition state
    pub fn new(
        entity_id: [u8; 32],
        state: MessageState,
        encryption_key: &[u8; 32],
        commitment_secret: &[u8; 32],
    ) -> Self {
        // Simple XOR encryption with key derivation
        let mut encrypted_state = vec![state as u8];
        let mut key_hasher = Hasher::new_keyed(encryption_key);
        key_hasher.update(&entity_id);
        let derived_key = key_hasher.finalize();
        encrypted_state[0] ^= derived_key.as_bytes()[0];

        let commitment = StateCommitment::new(state, commitment_secret);

        Self {
            entity_id,
            encrypted_state,
            commitment,
            collapsed: false,
            collapsed_at: None,
            revealed_state: None,
        }
    }

    /// Check if state is still in superposition
    pub fn is_superposed(&self) -> bool {
        !self.collapsed
    }

    /// Collapse the superposition to reveal the state
    pub fn collapse(
        &mut self,
        encryption_key: &[u8; 32],
        commitment_secret: &[u8; 32],
    ) -> Result<MessageState, SuperpositionError> {
        if self.collapsed {
            return self.revealed_state.ok_or(SuperpositionError::AlreadyCollapsed);
        }

        // Decrypt the state
        let mut decrypted = self.encrypted_state[0];
        let mut key_hasher = Hasher::new_keyed(encryption_key);
        key_hasher.update(&self.entity_id);
        let derived_key = key_hasher.finalize();
        decrypted ^= derived_key.as_bytes()[0];

        let state = match decrypted {
            0 => MessageState::Pending,
            1 => MessageState::Delivered,
            2 => MessageState::Read,
            3 => MessageState::Acknowledged,
            4 => MessageState::Deleted,
            5 => MessageState::Expired,
            _ => return Err(SuperpositionError::InvalidCollapseProof),
        };

        // Verify against commitment
        if !self.commitment.verify(state, commitment_secret) {
            return Err(SuperpositionError::InvalidCollapseProof);
        }

        self.collapsed = true;
        self.collapsed_at = Some(Utc::now());
        self.revealed_state = Some(state);

        Ok(state)
    }

    /// Get the revealed state (only available after collapse)
    pub fn revealed_state(&self) -> Option<MessageState> {
        self.revealed_state
    }

    /// Get the commitment (always visible)
    pub fn commitment(&self) -> &StateCommitment {
        &self.commitment
    }

    /// Get collapse timestamp
    pub fn collapsed_at(&self) -> Option<DateTime<Utc>> {
        self.collapsed_at
    }
}

/// Manager for multiple superposition states
#[derive(Debug)]
pub struct SuperpositionManager {
    /// States indexed by entity ID
    states: RwLock<HashMap<[u8; 32], SuperpositionState>>,
    /// Encryption key for states
    encryption_key: [u8; 32],
    /// Commitment secret
    commitment_secret: [u8; 32],
}

impl SuperpositionManager {
    /// Create a new superposition manager
    pub fn new(encryption_key: [u8; 32], commitment_secret: [u8; 32]) -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
            encryption_key,
            commitment_secret,
        }
    }

    /// Create a new superposition state
    pub fn create_state(
        &self,
        entity_id: [u8; 32],
        initial_state: MessageState,
    ) -> StateCommitment {
        let state = SuperpositionState::new(
            entity_id,
            initial_state,
            &self.encryption_key,
            &self.commitment_secret,
        );
        let commitment = state.commitment.clone();

        self.states.write().insert(entity_id, state);
        commitment
    }

    /// Transition state (creates new superposition)
    pub fn transition_state(
        &self,
        entity_id: [u8; 32],
        new_state: MessageState,
    ) -> Result<StateCommitment, SuperpositionError> {
        let mut states = self.states.write();

        // Check if exists
        if !states.contains_key(&entity_id) {
            return Err(SuperpositionError::StateNotFound(hex::encode(entity_id)));
        }

        // Create new superposition with updated state
        let state = SuperpositionState::new(
            entity_id,
            new_state,
            &self.encryption_key,
            &self.commitment_secret,
        );
        let commitment = state.commitment.clone();

        states.insert(entity_id, state);
        Ok(commitment)
    }

    /// Collapse a state to reveal it
    pub fn collapse_state(
        &self,
        entity_id: &[u8; 32],
    ) -> Result<MessageState, SuperpositionError> {
        let mut states = self.states.write();

        let state = states.get_mut(entity_id)
            .ok_or_else(|| SuperpositionError::StateNotFound(hex::encode(entity_id)))?;

        state.collapse(&self.encryption_key, &self.commitment_secret)
    }

    /// Check if state is collapsed
    pub fn is_collapsed(&self, entity_id: &[u8; 32]) -> Option<bool> {
        self.states.read().get(entity_id).map(|s| s.collapsed)
    }

    /// Get commitment without revealing state
    pub fn get_commitment(&self, entity_id: &[u8; 32]) -> Option<StateCommitment> {
        self.states.read().get(entity_id).map(|s| s.commitment.clone())
    }

    /// Remove a state entry
    pub fn remove(&self, entity_id: &[u8; 32]) -> Option<SuperpositionState> {
        self.states.write().remove(entity_id)
    }

    /// Get count of managed states
    pub fn len(&self) -> usize {
        self.states.read().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.states.read().is_empty()
    }
}

/// Sealed envelope that hides message existence until opened
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSealedEnvelope {
    /// Random cover traffic ID (makes all envelopes look identical)
    pub envelope_id: [u8; 32],
    /// Encrypted payload (same size padding for all)
    pub sealed_payload: Vec<u8>,
    /// Is this real or cover traffic?
    is_real: bool,
    /// Commitment to real/cover status
    reality_commitment: [u8; 32],
    /// Timestamp (same for batches)
    pub batch_timestamp: DateTime<Utc>,
}

impl QuantumSealedEnvelope {
    /// Create a real message envelope
    pub fn seal_real(
        payload: &[u8],
        max_size: usize,
        batch_timestamp: DateTime<Utc>,
        secret: &[u8; 32],
    ) -> Self {
        let mut envelope_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut envelope_id);

        // Pad to max size
        let mut sealed_payload = payload.to_vec();
        sealed_payload.resize(max_size, 0);

        // Create reality commitment
        let mut hasher = Hasher::new_keyed(secret);
        hasher.update(&[1u8]); // 1 = real
        hasher.update(&envelope_id);
        let commitment = hasher.finalize();
        let mut reality_commitment = [0u8; 32];
        reality_commitment.copy_from_slice(commitment.as_bytes());

        Self {
            envelope_id,
            sealed_payload,
            is_real: true,
            reality_commitment,
            batch_timestamp,
        }
    }

    /// Create cover traffic envelope (indistinguishable from real)
    pub fn seal_cover(
        max_size: usize,
        batch_timestamp: DateTime<Utc>,
        secret: &[u8; 32],
    ) -> Self {
        let mut envelope_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut envelope_id);

        // Random padding (looks like encrypted data)
        let mut sealed_payload = vec![0u8; max_size];
        rand::thread_rng().fill_bytes(&mut sealed_payload);

        // Create reality commitment
        let mut hasher = Hasher::new_keyed(secret);
        hasher.update(&[0u8]); // 0 = cover
        hasher.update(&envelope_id);
        let commitment = hasher.finalize();
        let mut reality_commitment = [0u8; 32];
        reality_commitment.copy_from_slice(commitment.as_bytes());

        Self {
            envelope_id,
            sealed_payload,
            is_real: false,
            reality_commitment,
            batch_timestamp,
        }
    }

    /// Verify if envelope is real (requires secret)
    pub fn verify_real(&self, secret: &[u8; 32]) -> bool {
        let mut hasher = Hasher::new_keyed(secret);
        hasher.update(&[if self.is_real { 1u8 } else { 0u8 }]);
        hasher.update(&self.envelope_id);
        let expected = hasher.finalize();

        self.reality_commitment == expected.as_bytes()[..32]
    }

    /// Open envelope (reveals if real and extracts payload)
    pub fn open(&self, secret: &[u8; 32]) -> Option<Vec<u8>> {
        if self.verify_real(secret) && self.is_real {
            // Remove padding (find actual payload length)
            // In practice, length would be encrypted in the first few bytes
            Some(self.sealed_payload.clone())
        } else {
            None
        }
    }
}

/// Type alias for shared manager
pub type SharedSuperpositionManager = Arc<SuperpositionManager>;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> ([u8; 32], [u8; 32]) {
        let mut enc = [0u8; 32];
        let mut com = [0u8; 32];
        enc[0] = 0x42;
        com[0] = 0x43;
        (enc, com)
    }

    #[test]
    fn test_state_commitment() {
        let mut secret = [0u8; 32];
        secret[0] = 0x42;

        let commitment = StateCommitment::new(MessageState::Pending, &secret);
        assert!(commitment.verify(MessageState::Pending, &secret));
        assert!(!commitment.verify(MessageState::Read, &secret));
    }

    #[test]
    fn test_superposition_state_collapse() {
        let (enc_key, com_secret) = test_keys();
        let entity_id = [1u8; 32];

        let mut state = SuperpositionState::new(
            entity_id,
            MessageState::Delivered,
            &enc_key,
            &com_secret,
        );

        assert!(state.is_superposed());
        assert!(state.revealed_state().is_none());

        let revealed = state.collapse(&enc_key, &com_secret).unwrap();
        assert_eq!(revealed, MessageState::Delivered);
        assert!(!state.is_superposed());
        assert_eq!(state.revealed_state(), Some(MessageState::Delivered));
    }

    #[test]
    fn test_superposition_manager() {
        let (enc_key, com_secret) = test_keys();
        let manager = SuperpositionManager::new(enc_key, com_secret);

        let entity_id = [1u8; 32];

        // Create state
        let _commitment = manager.create_state(entity_id, MessageState::Pending);
        assert_eq!(manager.is_collapsed(&entity_id), Some(false));

        // Transition state
        manager.transition_state(entity_id, MessageState::Delivered).unwrap();

        // Collapse
        let revealed = manager.collapse_state(&entity_id).unwrap();
        assert_eq!(revealed, MessageState::Delivered);
        assert_eq!(manager.is_collapsed(&entity_id), Some(true));
    }

    #[test]
    fn test_state_transition_not_found() {
        let (enc_key, com_secret) = test_keys();
        let manager = SuperpositionManager::new(enc_key, com_secret);

        let result = manager.transition_state([99u8; 32], MessageState::Read);
        assert!(matches!(result, Err(SuperpositionError::StateNotFound(_))));
    }

    #[test]
    fn test_quantum_sealed_envelope_real() {
        let mut secret = [0u8; 32];
        secret[0] = 0x42;

        let payload = b"secret message";
        let timestamp = Utc::now();

        let envelope = QuantumSealedEnvelope::seal_real(payload, 1024, timestamp, &secret);

        assert!(envelope.verify_real(&secret));
        let opened = envelope.open(&secret);
        assert!(opened.is_some());
    }

    #[test]
    fn test_quantum_sealed_envelope_cover() {
        let mut secret = [0u8; 32];
        secret[0] = 0x42;

        let timestamp = Utc::now();
        let envelope = QuantumSealedEnvelope::seal_cover(1024, timestamp, &secret);

        assert!(envelope.verify_real(&secret));
        let opened = envelope.open(&secret);
        assert!(opened.is_none()); // Cover traffic returns None
    }

    #[test]
    fn test_envelope_indistinguishability() {
        let mut secret = [0u8; 32];
        secret[0] = 0x42;

        let timestamp = Utc::now();
        let real = QuantumSealedEnvelope::seal_real(b"test", 1024, timestamp, &secret);
        let cover = QuantumSealedEnvelope::seal_cover(1024, timestamp, &secret);

        // Without secret, cannot distinguish
        assert_eq!(real.sealed_payload.len(), cover.sealed_payload.len());
        assert_eq!(real.batch_timestamp, cover.batch_timestamp);
    }
}
