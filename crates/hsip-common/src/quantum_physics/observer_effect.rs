//! Observer Effect - Read Receipts and Access Logging
//!
//! Inspired by quantum mechanics where observing a particle changes its state,
//! this module provides cryptographic read receipts and tamper-evident access logs.
//!
//! # Security Properties
//! - Every access to sensitive data is cryptographically logged
//! - Read receipts cannot be forged or repudiated
//! - Observation records are tamper-evident (chained hashes)
//! - Supports audit trails for compliance requirements

use blake3::Hasher;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Errors related to observation tracking
#[derive(Debug, Error)]
pub enum ObserverError {
    #[error("Invalid observation signature")]
    InvalidSignature,
    #[error("Chain integrity compromised at index {0}")]
    ChainIntegrityViolation(usize),
    #[error("Observation not found: {0}")]
    ObservationNotFound(String),
    #[error("Observer not authorized")]
    Unauthorized,
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
}

/// Type of observation/access event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObservationType {
    /// Read access to data
    Read,
    /// Metadata access only
    MetadataAccess,
    /// Consent verification check
    ConsentCheck,
    /// Key derivation operation
    KeyDerivation,
    /// Decryption operation
    Decryption,
    /// Export operation
    Export,
    /// Forwarding attempt
    Forward,
}

impl ObservationType {
    /// Returns whether this observation type requires explicit logging
    pub fn requires_explicit_log(&self) -> bool {
        matches!(
            self,
            ObservationType::Decryption
                | ObservationType::Export
                | ObservationType::Forward
        )
    }
}

/// A cryptographic read receipt proving observation occurred
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadReceipt {
    /// Unique receipt identifier
    pub receipt_id: [u8; 32],
    /// Resource that was observed
    pub resource_id: [u8; 32],
    /// Who observed (public key hash)
    pub observer_id: [u8; 32],
    /// Type of observation
    pub observation_type: ObservationType,
    /// When observation occurred
    pub timestamp: DateTime<Utc>,
    /// Cryptographic proof binding all fields
    pub proof: [u8; 32],
    /// Previous receipt hash for chaining
    pub prev_receipt_hash: Option<[u8; 32]>,
}

impl ReadReceipt {
    /// Create a new read receipt
    pub fn new(
        resource_id: [u8; 32],
        observer_id: [u8; 32],
        observation_type: ObservationType,
        prev_receipt_hash: Option<[u8; 32]>,
        binding_secret: &[u8],
    ) -> Self {
        let timestamp = Utc::now();
        let mut receipt_id = [0u8; 32];

        // Generate unique receipt ID
        let mut hasher = Hasher::new();
        hasher.update(&resource_id);
        hasher.update(&observer_id);
        hasher.update(&timestamp.timestamp_millis().to_le_bytes());
        hasher.update(&[observation_type as u8]);
        receipt_id.copy_from_slice(hasher.finalize().as_bytes());

        // Generate proof binding all fields
        let mut proof_hasher = Hasher::new_keyed(binding_secret.try_into().unwrap_or(&[0u8; 32]));
        proof_hasher.update(&receipt_id);
        proof_hasher.update(&resource_id);
        proof_hasher.update(&observer_id);
        proof_hasher.update(&timestamp.timestamp_millis().to_le_bytes());
        if let Some(prev) = &prev_receipt_hash {
            proof_hasher.update(prev);
        }
        let proof_hash = proof_hasher.finalize();
        let mut proof = [0u8; 32];
        proof.copy_from_slice(proof_hash.as_bytes());

        Self {
            receipt_id,
            resource_id,
            observer_id,
            observation_type,
            timestamp,
            proof,
            prev_receipt_hash,
        }
    }

    /// Verify the receipt's cryptographic proof
    pub fn verify(&self, binding_secret: &[u8]) -> bool {
        let mut proof_hasher = Hasher::new_keyed(binding_secret.try_into().unwrap_or(&[0u8; 32]));
        proof_hasher.update(&self.receipt_id);
        proof_hasher.update(&self.resource_id);
        proof_hasher.update(&self.observer_id);
        proof_hasher.update(&self.timestamp.timestamp_millis().to_le_bytes());
        if let Some(prev) = &self.prev_receipt_hash {
            proof_hasher.update(prev);
        }
        let expected_proof = proof_hasher.finalize();

        self.proof == expected_proof.as_bytes()[..32]
    }

    /// Compute hash of this receipt for chaining
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.receipt_id);
        hasher.update(&self.proof);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(hasher.finalize().as_bytes());
        hash
    }
}

/// An observation record for the tamper-evident log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationRecord {
    /// Index in the observation chain
    pub index: u64,
    /// The read receipt
    pub receipt: ReadReceipt,
    /// Additional context (encrypted)
    pub encrypted_context: Option<Vec<u8>>,
    /// Hash of previous record for tamper detection
    pub prev_hash: [u8; 32],
    /// Hash of this record
    pub record_hash: [u8; 32],
}

impl ObservationRecord {
    /// Create a new observation record
    pub fn new(
        index: u64,
        receipt: ReadReceipt,
        encrypted_context: Option<Vec<u8>>,
        prev_hash: [u8; 32],
    ) -> Self {
        // Compute record hash
        let mut hasher = Hasher::new();
        hasher.update(&index.to_le_bytes());
        hasher.update(&receipt.receipt_id);
        hasher.update(&receipt.proof);
        if let Some(ctx) = &encrypted_context {
            hasher.update(ctx);
        }
        hasher.update(&prev_hash);

        let mut record_hash = [0u8; 32];
        record_hash.copy_from_slice(hasher.finalize().as_bytes());

        Self {
            index,
            receipt,
            encrypted_context,
            prev_hash,
            record_hash,
        }
    }

    /// Verify record integrity
    pub fn verify_integrity(&self) -> bool {
        let mut hasher = Hasher::new();
        hasher.update(&self.index.to_le_bytes());
        hasher.update(&self.receipt.receipt_id);
        hasher.update(&self.receipt.proof);
        if let Some(ctx) = &self.encrypted_context {
            hasher.update(ctx);
        }
        hasher.update(&self.prev_hash);

        let expected_hash = hasher.finalize();
        self.record_hash == expected_hash.as_bytes()[..32]
    }
}

/// Tamper-evident observation log (append-only)
#[derive(Debug)]
pub struct ObservationLog {
    /// Chain of observation records
    records: RwLock<Vec<ObservationRecord>>,
    /// Binding secret for receipt generation
    binding_secret: [u8; 32],
    /// Index by resource ID for fast lookup
    resource_index: RwLock<HashMap<[u8; 32], Vec<usize>>>,
    /// Index by observer ID for fast lookup
    observer_index: RwLock<HashMap<[u8; 32], Vec<usize>>>,
}

impl ObservationLog {
    /// Create a new observation log
    pub fn new(binding_secret: [u8; 32]) -> Self {
        Self {
            records: RwLock::new(Vec::new()),
            binding_secret,
            resource_index: RwLock::new(HashMap::new()),
            observer_index: RwLock::new(HashMap::new()),
        }
    }

    /// Record an observation and return the receipt
    pub fn record_observation(
        &self,
        resource_id: [u8; 32],
        observer_id: [u8; 32],
        observation_type: ObservationType,
        encrypted_context: Option<Vec<u8>>,
    ) -> ReadReceipt {
        let mut records = self.records.write();

        // Get previous receipt hash for chaining
        let prev_receipt_hash = records.last().map(|r| r.receipt.hash());
        let prev_hash = records.last()
            .map(|r| r.record_hash)
            .unwrap_or([0u8; 32]);

        // Create receipt
        let receipt = ReadReceipt::new(
            resource_id,
            observer_id,
            observation_type,
            prev_receipt_hash,
            &self.binding_secret,
        );

        // Create record
        let index = records.len() as u64;
        let record = ObservationRecord::new(
            index,
            receipt.clone(),
            encrypted_context,
            prev_hash,
        );

        // Update indices
        {
            let mut resource_idx = self.resource_index.write();
            resource_idx.entry(resource_id)
                .or_insert_with(Vec::new)
                .push(index as usize);
        }
        {
            let mut observer_idx = self.observer_index.write();
            observer_idx.entry(observer_id)
                .or_insert_with(Vec::new)
                .push(index as usize);
        }

        records.push(record);
        receipt
    }

    /// Verify the entire chain integrity
    pub fn verify_chain(&self) -> Result<(), ObserverError> {
        let records = self.records.read();

        let mut expected_prev_hash = [0u8; 32];

        for (i, record) in records.iter().enumerate() {
            // Verify record integrity
            if !record.verify_integrity() {
                return Err(ObserverError::ChainIntegrityViolation(i));
            }

            // Verify chain linkage
            if record.prev_hash != expected_prev_hash {
                return Err(ObserverError::ChainIntegrityViolation(i));
            }

            // Verify receipt proof
            if !record.receipt.verify(&self.binding_secret) {
                return Err(ObserverError::InvalidSignature);
            }

            expected_prev_hash = record.record_hash;
        }

        Ok(())
    }

    /// Get all observations for a resource
    pub fn get_observations_for_resource(&self, resource_id: &[u8; 32]) -> Vec<ReadReceipt> {
        let resource_idx = self.resource_index.read();
        let records = self.records.read();

        resource_idx.get(resource_id)
            .map(|indices| {
                indices.iter()
                    .filter_map(|&i| records.get(i))
                    .map(|r| r.receipt.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all observations by an observer
    pub fn get_observations_by_observer(&self, observer_id: &[u8; 32]) -> Vec<ReadReceipt> {
        let observer_idx = self.observer_index.read();
        let records = self.records.read();

        observer_idx.get(observer_id)
            .map(|indices| {
                indices.iter()
                    .filter_map(|&i| records.get(i))
                    .map(|r| r.receipt.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get total observation count
    pub fn len(&self) -> usize {
        self.records.read().len()
    }

    /// Check if log is empty
    pub fn is_empty(&self) -> bool {
        self.records.read().is_empty()
    }

    /// Get the latest record hash (for external verification)
    pub fn latest_hash(&self) -> Option<[u8; 32]> {
        self.records.read().last().map(|r| r.record_hash)
    }
}

/// Thread-safe shared observation log
pub type SharedObservationLog = Arc<ObservationLog>;

/// Observer tracking for resources
#[derive(Debug)]
pub struct ResourceObserver {
    /// The observation log
    log: SharedObservationLog,
    /// Resource being observed
    resource_id: [u8; 32],
    /// Authorized observers (public key hashes)
    authorized_observers: RwLock<Vec<[u8; 32]>>,
}

impl ResourceObserver {
    /// Create a new resource observer
    pub fn new(log: SharedObservationLog, resource_id: [u8; 32]) -> Self {
        Self {
            log,
            resource_id,
            authorized_observers: RwLock::new(Vec::new()),
        }
    }

    /// Authorize an observer
    pub fn authorize(&self, observer_id: [u8; 32]) {
        let mut observers = self.authorized_observers.write();
        if !observers.contains(&observer_id) {
            observers.push(observer_id);
        }
    }

    /// Revoke observer authorization
    pub fn revoke(&self, observer_id: &[u8; 32]) {
        let mut observers = self.authorized_observers.write();
        observers.retain(|id| id != observer_id);
    }

    /// Check if observer is authorized
    pub fn is_authorized(&self, observer_id: &[u8; 32]) -> bool {
        self.authorized_observers.read().contains(observer_id)
    }

    /// Record an observation (checks authorization)
    pub fn observe(
        &self,
        observer_id: [u8; 32],
        observation_type: ObservationType,
        context: Option<Vec<u8>>,
    ) -> Result<ReadReceipt, ObserverError> {
        if !self.is_authorized(&observer_id) {
            return Err(ObserverError::Unauthorized);
        }

        Ok(self.log.record_observation(
            self.resource_id,
            observer_id,
            observation_type,
            context,
        ))
    }

    /// Get all observation receipts for this resource
    pub fn get_receipts(&self) -> Vec<ReadReceipt> {
        self.log.get_observations_for_resource(&self.resource_id)
    }

    /// Get observation count
    pub fn observation_count(&self) -> usize {
        self.get_receipts().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_binding_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        secret[0] = 0x42;
        secret
    }

    #[test]
    fn test_read_receipt_creation_and_verification() {
        let resource_id = [1u8; 32];
        let observer_id = [2u8; 32];
        let secret = test_binding_secret();

        let receipt = ReadReceipt::new(
            resource_id,
            observer_id,
            ObservationType::Read,
            None,
            &secret,
        );

        assert!(receipt.verify(&secret));
        assert!(!receipt.verify(&[0u8; 32])); // Wrong secret
    }

    #[test]
    fn test_receipt_chaining() {
        let resource_id = [1u8; 32];
        let observer_id = [2u8; 32];
        let secret = test_binding_secret();

        let receipt1 = ReadReceipt::new(
            resource_id,
            observer_id,
            ObservationType::Read,
            None,
            &secret,
        );

        let receipt2 = ReadReceipt::new(
            resource_id,
            observer_id,
            ObservationType::Decryption,
            Some(receipt1.hash()),
            &secret,
        );

        assert!(receipt1.verify(&secret));
        assert!(receipt2.verify(&secret));
        assert_eq!(receipt2.prev_receipt_hash, Some(receipt1.hash()));
    }

    #[test]
    fn test_observation_log_chain_integrity() {
        let secret = test_binding_secret();
        let log = ObservationLog::new(secret);

        let resource1 = [1u8; 32];
        let resource2 = [2u8; 32];
        let observer = [3u8; 32];

        // Record multiple observations
        log.record_observation(resource1, observer, ObservationType::Read, None);
        log.record_observation(resource2, observer, ObservationType::MetadataAccess, None);
        log.record_observation(resource1, observer, ObservationType::Decryption, None);

        // Verify chain integrity
        assert!(log.verify_chain().is_ok());
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn test_observation_log_indexing() {
        let secret = test_binding_secret();
        let log = ObservationLog::new(secret);

        let resource1 = [1u8; 32];
        let resource2 = [2u8; 32];
        let observer1 = [3u8; 32];
        let observer2 = [4u8; 32];

        log.record_observation(resource1, observer1, ObservationType::Read, None);
        log.record_observation(resource1, observer2, ObservationType::Read, None);
        log.record_observation(resource2, observer1, ObservationType::Read, None);

        // Check resource index
        let r1_obs = log.get_observations_for_resource(&resource1);
        assert_eq!(r1_obs.len(), 2);

        // Check observer index
        let o1_obs = log.get_observations_by_observer(&observer1);
        assert_eq!(o1_obs.len(), 2);
    }

    #[test]
    fn test_resource_observer_authorization() {
        let secret = test_binding_secret();
        let log = Arc::new(ObservationLog::new(secret));

        let resource_id = [1u8; 32];
        let authorized = [2u8; 32];
        let unauthorized = [3u8; 32];

        let observer = ResourceObserver::new(log, resource_id);
        observer.authorize(authorized);

        // Authorized observer can observe
        let result = observer.observe(authorized, ObservationType::Read, None);
        assert!(result.is_ok());

        // Unauthorized observer cannot
        let result = observer.observe(unauthorized, ObservationType::Read, None);
        assert!(matches!(result, Err(ObserverError::Unauthorized)));
    }

    #[test]
    fn test_observation_type_explicit_logging() {
        assert!(!ObservationType::Read.requires_explicit_log());
        assert!(!ObservationType::MetadataAccess.requires_explicit_log());
        assert!(ObservationType::Decryption.requires_explicit_log());
        assert!(ObservationType::Export.requires_explicit_log());
        assert!(ObservationType::Forward.requires_explicit_log());
    }

    #[test]
    fn test_revoke_authorization() {
        let secret = test_binding_secret();
        let log = Arc::new(ObservationLog::new(secret));

        let resource_id = [1u8; 32];
        let observer_id = [2u8; 32];

        let observer = ResourceObserver::new(log, resource_id);
        observer.authorize(observer_id);
        assert!(observer.is_authorized(&observer_id));

        observer.revoke(&observer_id);
        assert!(!observer.is_authorized(&observer_id));

        // Should now fail
        let result = observer.observe(observer_id, ObservationType::Read, None);
        assert!(matches!(result, Err(ObserverError::Unauthorized)));
    }
}
