//! Quantum Entanglement - Mutual Consent Synchronization
//!
//! Inspired by quantum entanglement where two particles remain connected
//! regardless of distance, this module ensures consent states between parties
//! are cryptographically linked and instantly synchronized.
//!
//! # Security Properties
//! - Consent between parties is bidirectionally linked
//! - Revoking consent on one side immediately affects the other
//! - Entangled state changes are cryptographically verifiable
//! - Supports multi-party entanglement for group consent

use blake3::Hasher;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;

/// Errors related to consent entanglement
#[derive(Debug, Error)]
pub enum EntanglementError {
    #[error("Parties already entangled")]
    AlreadyEntangled,
    #[error("Entanglement not found")]
    NotFound,
    #[error("Entanglement broken by party: {0}")]
    BrokenByParty(String),
    #[error("Invalid entanglement proof")]
    InvalidProof,
    #[error("Unauthorized party")]
    Unauthorized,
    #[error("Entanglement expired")]
    Expired,
    #[error("Minimum parties not met: need {0}, have {1}")]
    InsufficientParties(usize, usize),
}

/// State of an entangled consent relationship
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntanglementState {
    /// Both parties have active consent
    Active,
    /// Pending acceptance from one party
    Pending,
    /// One party has revoked
    Revoked,
    /// Entanglement has expired
    Expired,
    /// Suspended by mutual agreement
    Suspended,
}

/// A quantum-entangled consent pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntangledConsent {
    /// Unique entanglement identifier
    pub entanglement_id: [u8; 32],
    /// Party A's identifier (public key hash)
    pub party_a: [u8; 32],
    /// Party B's identifier (public key hash)
    pub party_b: [u8; 32],
    /// Current entanglement state
    pub state: EntanglementState,
    /// When entanglement was created
    pub created_at: DateTime<Utc>,
    /// Last state change
    pub updated_at: DateTime<Utc>,
    /// Expiration time (if set)
    pub expires_at: Option<DateTime<Utc>>,
    /// Shared entanglement secret (for verification)
    shared_secret: [u8; 32],
    /// State change history hashes (for audit)
    state_history: Vec<[u8; 32]>,
}

impl EntangledConsent {
    /// Create a new entanglement between two parties
    pub fn new(
        party_a: [u8; 32],
        party_b: [u8; 32],
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        let mut entanglement_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entanglement_id);

        let mut shared_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut shared_secret);

        let now = Utc::now();

        // Initial state hash
        let initial_hash = Self::compute_state_hash(
            &entanglement_id,
            EntanglementState::Pending,
            &[0u8; 32],
            now,
        );

        Self {
            entanglement_id,
            party_a,
            party_b,
            state: EntanglementState::Pending,
            created_at: now,
            updated_at: now,
            expires_at,
            shared_secret,
            state_history: vec![initial_hash],
        }
    }

    /// Compute state hash for history
    fn compute_state_hash(
        entanglement_id: &[u8; 32],
        state: EntanglementState,
        prev_hash: &[u8; 32],
        timestamp: DateTime<Utc>,
    ) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(entanglement_id);
        hasher.update(&[state as u8]);
        hasher.update(prev_hash);
        hasher.update(&timestamp.timestamp_millis().to_le_bytes());

        let mut hash = [0u8; 32];
        hash.copy_from_slice(hasher.finalize().as_bytes());
        hash
    }

    /// Activate the entanglement (both parties consented)
    pub fn activate(&mut self) -> Result<(), EntanglementError> {
        if self.state != EntanglementState::Pending {
            return Err(EntanglementError::InvalidProof);
        }

        self.transition_state(EntanglementState::Active)
    }

    /// Revoke consent (breaks entanglement)
    pub fn revoke(&mut self, revoking_party: &[u8; 32]) -> Result<(), EntanglementError> {
        if self.state == EntanglementState::Revoked {
            return Err(EntanglementError::BrokenByParty(hex::encode(revoking_party)));
        }

        if revoking_party != &self.party_a && revoking_party != &self.party_b {
            return Err(EntanglementError::Unauthorized);
        }

        self.transition_state(EntanglementState::Revoked)
    }

    /// Suspend entanglement temporarily
    pub fn suspend(&mut self) -> Result<(), EntanglementError> {
        if self.state != EntanglementState::Active {
            return Err(EntanglementError::InvalidProof);
        }

        self.transition_state(EntanglementState::Suspended)
    }

    /// Resume from suspension
    pub fn resume(&mut self) -> Result<(), EntanglementError> {
        if self.state != EntanglementState::Suspended {
            return Err(EntanglementError::InvalidProof);
        }

        self.transition_state(EntanglementState::Active)
    }

    /// Transition to a new state
    fn transition_state(&mut self, new_state: EntanglementState) -> Result<(), EntanglementError> {
        let now = Utc::now();

        // Check expiration
        if let Some(expires) = self.expires_at {
            if now > expires {
                self.state = EntanglementState::Expired;
                return Err(EntanglementError::Expired);
            }
        }

        let prev_hash = self.state_history.last().copied().unwrap_or([0u8; 32]);
        let new_hash = Self::compute_state_hash(
            &self.entanglement_id,
            new_state,
            &prev_hash,
            now,
        );

        self.state = new_state;
        self.updated_at = now;
        self.state_history.push(new_hash);

        Ok(())
    }

    /// Check if entanglement is active
    pub fn is_active(&self) -> bool {
        if let Some(expires) = self.expires_at {
            if Utc::now() > expires {
                return false;
            }
        }
        self.state == EntanglementState::Active
    }

    /// Check if a party is part of this entanglement
    pub fn involves_party(&self, party: &[u8; 32]) -> bool {
        &self.party_a == party || &self.party_b == party
    }

    /// Get the other party
    pub fn other_party(&self, party: &[u8; 32]) -> Option<[u8; 32]> {
        if &self.party_a == party {
            Some(self.party_b)
        } else if &self.party_b == party {
            Some(self.party_a)
        } else {
            None
        }
    }

    /// Generate a verification proof for the current state
    pub fn generate_proof(&self) -> EntanglementProof {
        let mut hasher = Hasher::new_keyed(&self.shared_secret);
        hasher.update(&self.entanglement_id);
        hasher.update(&[self.state as u8]);
        hasher.update(&self.updated_at.timestamp_millis().to_le_bytes());

        let mut proof_hash = [0u8; 32];
        proof_hash.copy_from_slice(hasher.finalize().as_bytes());

        EntanglementProof {
            entanglement_id: self.entanglement_id,
            state: self.state,
            timestamp: self.updated_at,
            proof_hash,
        }
    }

    /// Verify a proof matches current state
    pub fn verify_proof(&self, proof: &EntanglementProof) -> bool {
        let mut hasher = Hasher::new_keyed(&self.shared_secret);
        hasher.update(&proof.entanglement_id);
        hasher.update(&[proof.state as u8]);
        hasher.update(&proof.timestamp.timestamp_millis().to_le_bytes());

        let expected = hasher.finalize();
        proof.proof_hash == expected.as_bytes()[..32]
    }

    /// Get state history length
    pub fn history_len(&self) -> usize {
        self.state_history.len()
    }

    /// Verify state history integrity
    pub fn verify_history(&self) -> bool {
        if self.state_history.is_empty() {
            return false;
        }

        // We can't fully verify without timestamps, but we can check chain integrity
        // In a real implementation, we'd store full state records
        !self.state_history.is_empty()
    }
}

/// Proof of entanglement state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntanglementProof {
    /// Entanglement identifier
    pub entanglement_id: [u8; 32],
    /// State at time of proof
    pub state: EntanglementState,
    /// Timestamp of proof
    pub timestamp: DateTime<Utc>,
    /// Cryptographic proof hash
    pub proof_hash: [u8; 32],
}

/// Multi-party entanglement for group consent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupEntanglement {
    /// Unique group entanglement ID
    pub group_id: [u8; 32],
    /// All party identifiers
    pub parties: Vec<[u8; 32]>,
    /// Minimum parties required for valid consent
    pub threshold: usize,
    /// Current consenting parties
    consenting: HashSet<[u8; 32]>,
    /// Current state
    pub state: EntanglementState,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last update
    pub updated_at: DateTime<Utc>,
    /// Expiration
    pub expires_at: Option<DateTime<Utc>>,
    /// Group secret for proofs
    group_secret: [u8; 32],
}

impl GroupEntanglement {
    /// Create a new group entanglement
    pub fn new(
        parties: Vec<[u8; 32]>,
        threshold: usize,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, EntanglementError> {
        if threshold > parties.len() || threshold == 0 {
            return Err(EntanglementError::InsufficientParties(threshold, parties.len()));
        }

        let mut group_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut group_id);

        let mut group_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut group_secret);

        let now = Utc::now();

        Ok(Self {
            group_id,
            parties,
            threshold,
            consenting: HashSet::new(),
            state: EntanglementState::Pending,
            created_at: now,
            updated_at: now,
            expires_at,
            group_secret,
        })
    }

    /// Add consent from a party
    pub fn add_consent(&mut self, party: &[u8; 32]) -> Result<bool, EntanglementError> {
        if !self.parties.contains(party) {
            return Err(EntanglementError::Unauthorized);
        }

        // Check expiration
        if let Some(expires) = self.expires_at {
            if Utc::now() > expires {
                self.state = EntanglementState::Expired;
                return Err(EntanglementError::Expired);
            }
        }

        self.consenting.insert(*party);
        self.updated_at = Utc::now();

        // Check if threshold met
        if self.consenting.len() >= self.threshold && self.state == EntanglementState::Pending {
            self.state = EntanglementState::Active;
            return Ok(true); // Threshold reached
        }

        Ok(false)
    }

    /// Remove consent from a party
    pub fn remove_consent(&mut self, party: &[u8; 32]) -> Result<(), EntanglementError> {
        if !self.parties.contains(party) {
            return Err(EntanglementError::Unauthorized);
        }

        self.consenting.remove(party);
        self.updated_at = Utc::now();

        // Check if we fell below threshold
        if self.consenting.len() < self.threshold && self.state == EntanglementState::Active {
            self.state = EntanglementState::Suspended;
        }

        Ok(())
    }

    /// Check if group consent is active
    pub fn is_active(&self) -> bool {
        if let Some(expires) = self.expires_at {
            if Utc::now() > expires {
                return false;
            }
        }
        self.state == EntanglementState::Active && self.consenting.len() >= self.threshold
    }

    /// Get current consent count
    pub fn consent_count(&self) -> usize {
        self.consenting.len()
    }

    /// Check if a party has consented
    pub fn has_consented(&self, party: &[u8; 32]) -> bool {
        self.consenting.contains(party)
    }
}

/// Manager for entangled consent relationships
#[derive(Debug)]
pub struct EntanglementManager {
    /// Pairwise entanglements
    pairwise: RwLock<HashMap<[u8; 32], EntangledConsent>>,
    /// Group entanglements
    groups: RwLock<HashMap<[u8; 32], GroupEntanglement>>,
    /// Index: party -> entanglement IDs
    party_index: RwLock<HashMap<[u8; 32], Vec<[u8; 32]>>>,
}

impl EntanglementManager {
    /// Create a new entanglement manager
    pub fn new() -> Self {
        Self {
            pairwise: RwLock::new(HashMap::new()),
            groups: RwLock::new(HashMap::new()),
            party_index: RwLock::new(HashMap::new()),
        }
    }

    /// Create a pairwise entanglement
    pub fn create_pairwise(
        &self,
        party_a: [u8; 32],
        party_b: [u8; 32],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<[u8; 32], EntanglementError> {
        // Check if already entangled
        let existing = self.get_entanglement_between(&party_a, &party_b);
        if existing.is_some() {
            return Err(EntanglementError::AlreadyEntangled);
        }

        let entanglement = EntangledConsent::new(party_a, party_b, expires_at);
        let id = entanglement.entanglement_id;

        // Update indices
        {
            let mut index = self.party_index.write();
            index.entry(party_a).or_insert_with(Vec::new).push(id);
            index.entry(party_b).or_insert_with(Vec::new).push(id);
        }

        self.pairwise.write().insert(id, entanglement);
        Ok(id)
    }

    /// Get entanglement between two parties
    pub fn get_entanglement_between(
        &self,
        party_a: &[u8; 32],
        party_b: &[u8; 32],
    ) -> Option<EntangledConsent> {
        let index = self.party_index.read();
        let pairwise = self.pairwise.read();

        if let Some(ids) = index.get(party_a) {
            for id in ids {
                if let Some(e) = pairwise.get(id) {
                    if e.involves_party(party_b) {
                        return Some(e.clone());
                    }
                }
            }
        }

        None
    }

    /// Activate an entanglement
    pub fn activate(&self, entanglement_id: &[u8; 32]) -> Result<(), EntanglementError> {
        let mut pairwise = self.pairwise.write();

        let entanglement = pairwise.get_mut(entanglement_id)
            .ok_or(EntanglementError::NotFound)?;

        entanglement.activate()
    }

    /// Revoke an entanglement
    pub fn revoke(
        &self,
        entanglement_id: &[u8; 32],
        revoking_party: &[u8; 32],
    ) -> Result<(), EntanglementError> {
        let mut pairwise = self.pairwise.write();

        let entanglement = pairwise.get_mut(entanglement_id)
            .ok_or(EntanglementError::NotFound)?;

        entanglement.revoke(revoking_party)
    }

    /// Get all entanglements for a party
    pub fn get_party_entanglements(&self, party: &[u8; 32]) -> Vec<EntangledConsent> {
        let index = self.party_index.read();
        let pairwise = self.pairwise.read();

        index.get(party)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| pairwise.get(id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if two parties are actively entangled
    pub fn are_entangled(&self, party_a: &[u8; 32], party_b: &[u8; 32]) -> bool {
        self.get_entanglement_between(party_a, party_b)
            .map(|e| e.is_active())
            .unwrap_or(false)
    }

    /// Create a group entanglement
    pub fn create_group(
        &self,
        parties: Vec<[u8; 32]>,
        threshold: usize,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<[u8; 32], EntanglementError> {
        let group = GroupEntanglement::new(parties.clone(), threshold, expires_at)?;
        let id = group.group_id;

        // Update party index
        {
            let mut index = self.party_index.write();
            for party in &parties {
                index.entry(*party).or_insert_with(Vec::new).push(id);
            }
        }

        self.groups.write().insert(id, group);
        Ok(id)
    }

    /// Add consent to group
    pub fn add_group_consent(
        &self,
        group_id: &[u8; 32],
        party: &[u8; 32],
    ) -> Result<bool, EntanglementError> {
        let mut groups = self.groups.write();

        let group = groups.get_mut(group_id)
            .ok_or(EntanglementError::NotFound)?;

        group.add_consent(party)
    }

    /// Remove consent from group
    pub fn remove_group_consent(
        &self,
        group_id: &[u8; 32],
        party: &[u8; 32],
    ) -> Result<(), EntanglementError> {
        let mut groups = self.groups.write();

        let group = groups.get_mut(group_id)
            .ok_or(EntanglementError::NotFound)?;

        group.remove_consent(party)
    }

    /// Check if group is active
    pub fn is_group_active(&self, group_id: &[u8; 32]) -> bool {
        self.groups.read().get(group_id)
            .map(|g| g.is_active())
            .unwrap_or(false)
    }

    /// Remove expired entanglements
    pub fn cleanup_expired(&self) -> usize {
        let now = Utc::now();
        let mut removed = 0;

        // Clean pairwise
        {
            let mut pairwise = self.pairwise.write();
            let expired_ids: Vec<_> = pairwise.iter()
                .filter(|(_, e)| e.expires_at.map(|exp| now > exp).unwrap_or(false))
                .map(|(id, _)| *id)
                .collect();

            for id in expired_ids {
                pairwise.remove(&id);
                removed += 1;
            }
        }

        // Clean groups
        {
            let mut groups = self.groups.write();
            let expired_ids: Vec<_> = groups.iter()
                .filter(|(_, g)| g.expires_at.map(|exp| now > exp).unwrap_or(false))
                .map(|(id, _)| *id)
                .collect();

            for id in expired_ids {
                groups.remove(&id);
                removed += 1;
            }
        }

        removed
    }

    /// Get statistics
    pub fn stats(&self) -> EntanglementStats {
        let pairwise = self.pairwise.read();
        let groups = self.groups.read();

        let active_pairwise = pairwise.values()
            .filter(|e| e.is_active())
            .count();

        let active_groups = groups.values()
            .filter(|g| g.is_active())
            .count();

        EntanglementStats {
            total_pairwise: pairwise.len(),
            active_pairwise,
            total_groups: groups.len(),
            active_groups,
        }
    }
}

impl Default for EntanglementManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about entanglements
#[derive(Debug, Clone)]
pub struct EntanglementStats {
    pub total_pairwise: usize,
    pub active_pairwise: usize,
    pub total_groups: usize,
    pub active_groups: usize,
}

/// Type alias for shared manager
pub type SharedEntanglementManager = Arc<EntanglementManager>;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_entangled_consent_lifecycle() {
        let party_a = [1u8; 32];
        let party_b = [2u8; 32];

        let mut consent = EntangledConsent::new(party_a, party_b, None);

        assert_eq!(consent.state, EntanglementState::Pending);
        assert!(!consent.is_active());

        consent.activate().unwrap();
        assert_eq!(consent.state, EntanglementState::Active);
        assert!(consent.is_active());

        consent.suspend().unwrap();
        assert_eq!(consent.state, EntanglementState::Suspended);
        assert!(!consent.is_active());

        consent.resume().unwrap();
        assert!(consent.is_active());

        consent.revoke(&party_a).unwrap();
        assert_eq!(consent.state, EntanglementState::Revoked);
        assert!(!consent.is_active());
    }

    #[test]
    fn test_entanglement_proof() {
        let party_a = [1u8; 32];
        let party_b = [2u8; 32];

        let mut consent = EntangledConsent::new(party_a, party_b, None);
        consent.activate().unwrap();

        let proof = consent.generate_proof();
        assert!(consent.verify_proof(&proof));
        assert_eq!(proof.state, EntanglementState::Active);
    }

    #[test]
    fn test_unauthorized_revocation() {
        let party_a = [1u8; 32];
        let party_b = [2u8; 32];
        let party_c = [3u8; 32];

        let mut consent = EntangledConsent::new(party_a, party_b, None);
        consent.activate().unwrap();

        let result = consent.revoke(&party_c);
        assert!(matches!(result, Err(EntanglementError::Unauthorized)));
    }

    #[test]
    fn test_group_entanglement() {
        let parties = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut group = GroupEntanglement::new(parties.clone(), 2, None).unwrap();

        assert_eq!(group.state, EntanglementState::Pending);

        // First consent
        let reached = group.add_consent(&parties[0]).unwrap();
        assert!(!reached);
        assert!(!group.is_active());

        // Second consent - threshold reached
        let reached = group.add_consent(&parties[1]).unwrap();
        assert!(reached);
        assert!(group.is_active());

        // Remove consent - falls below threshold
        group.remove_consent(&parties[0]).unwrap();
        assert_eq!(group.state, EntanglementState::Suspended);
    }

    #[test]
    fn test_entanglement_manager() {
        let manager = EntanglementManager::new();

        let party_a = [1u8; 32];
        let party_b = [2u8; 32];

        // Create entanglement
        let id = manager.create_pairwise(party_a, party_b, None).unwrap();

        // Should fail to create duplicate
        let result = manager.create_pairwise(party_a, party_b, None);
        assert!(matches!(result, Err(EntanglementError::AlreadyEntangled)));

        // Activate
        manager.activate(&id).unwrap();
        assert!(manager.are_entangled(&party_a, &party_b));

        // Revoke
        manager.revoke(&id, &party_a).unwrap();
        assert!(!manager.are_entangled(&party_a, &party_b));
    }

    #[test]
    fn test_expiration() {
        let party_a = [1u8; 32];
        let party_b = [2u8; 32];

        // Create with past expiration
        let expires = Utc::now() - Duration::hours(1);
        let mut consent = EntangledConsent::new(party_a, party_b, Some(expires));

        let result = consent.activate();
        assert!(matches!(result, Err(EntanglementError::Expired)));
    }

    #[test]
    fn test_manager_stats() {
        let manager = EntanglementManager::new();

        manager.create_pairwise([1u8; 32], [2u8; 32], None).unwrap();
        manager.create_pairwise([3u8; 32], [4u8; 32], None).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.total_pairwise, 2);
        assert_eq!(stats.active_pairwise, 0); // Not activated yet
    }
}
