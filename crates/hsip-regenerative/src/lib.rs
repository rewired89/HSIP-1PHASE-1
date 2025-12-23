//! Planarian Distributed Identity Recovery
//!
//! Inspired by planarian worms that can regenerate from any fragment,
//! this crate implements distributed identity recovery using Shamir Secret Sharing.
//!
//! # Security Properties
//! - Identity can be recovered from k-of-n shards
//! - Single shard reveals nothing about the identity
//! - Shards can be stored across devices, trusted contacts, or services
//! - Supports periodic shard rotation for enhanced security
//!
//! # Phase 1 Free Features
//! - 3-of-5 recovery threshold
//! - Local device sharding
//! - Basic contact-based recovery
//!
//! # Future Premium Features
//! - Custom thresholds
//! - Encrypted cloud backup
//! - Hardware token integration

use blake3::Hasher;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use std::collections::HashMap;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default threshold for recovery (Phase 1 Free)
pub const DEFAULT_THRESHOLD: u8 = 3;
/// Default total shards (Phase 1 Free)
pub const DEFAULT_TOTAL_SHARDS: u8 = 5;
/// Maximum secret size (256 bits)
pub const MAX_SECRET_SIZE: usize = 32;

/// Errors related to identity recovery
#[derive(Debug, Error)]
pub enum RegenerativeError {
    #[error("Threshold must be at least 2 and at most total shards")]
    InvalidThreshold,
    #[error("Not enough shards for recovery: have {0}, need {1}")]
    InsufficientShards(usize, u8),
    #[error("Secret too large: max {0} bytes")]
    SecretTooLarge(usize),
    #[error("Shard verification failed")]
    ShardVerificationFailed,
    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),
    #[error("Shard expired")]
    ShardExpired,
    #[error("Shard already used")]
    ShardAlreadyUsed,
    #[error("Invalid shard format")]
    InvalidShardFormat,
    #[error("Shard index out of range")]
    ShardIndexOutOfRange,
}

/// Type of storage for a shard
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShardStorageType {
    /// Stored on local device
    LocalDevice,
    /// Stored with a trusted contact
    TrustedContact,
    /// Stored in encrypted cloud backup
    CloudBackup,
    /// Stored on hardware token
    HardwareToken,
    /// Printed paper backup
    PaperBackup,
}

/// Metadata about a shard (non-sensitive)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMetadata {
    /// Unique shard identifier
    pub shard_id: [u8; 32],
    /// Index in the sharing scheme (1-indexed)
    pub index: u8,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp (if set)
    pub expires_at: Option<DateTime<Utc>>,
    /// Storage type
    pub storage_type: ShardStorageType,
    /// Verification hash (to verify shard integrity)
    pub verification_hash: [u8; 32],
    /// Description/label for this shard
    pub label: String,
    /// Identity fingerprint (not the full identity)
    pub identity_fingerprint: [u8; 8],
}

/// A share of the identity secret
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentityShard {
    /// Shard metadata (public)
    #[zeroize(skip)]
    pub metadata: ShardMetadata,
    /// Encrypted shard data (the actual share)
    shard_data: Vec<u8>,
    /// Optional passphrase protection salt
    #[zeroize(skip)]
    passphrase_salt: Option<[u8; 16]>,
}

impl IdentityShard {
    /// Create from a sharks Share
    fn from_share(
        share: &Share,
        index: u8,
        identity_fingerprint: [u8; 8],
        storage_type: ShardStorageType,
        label: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        let shard_data: Vec<u8> = share.into();

        // Generate shard ID
        let mut hasher = Hasher::new();
        hasher.update(&shard_data);
        hasher.update(&identity_fingerprint);
        let hash = hasher.finalize();
        let mut shard_id = [0u8; 32];
        shard_id.copy_from_slice(hash.as_bytes());

        // Generate verification hash
        let mut verify_hasher = Hasher::new();
        verify_hasher.update(&shard_id);
        verify_hasher.update(&shard_data);
        let verify_hash = verify_hasher.finalize();
        let mut verification_hash = [0u8; 32];
        verification_hash.copy_from_slice(verify_hash.as_bytes());

        let metadata = ShardMetadata {
            shard_id,
            index,
            created_at: Utc::now(),
            expires_at,
            storage_type,
            verification_hash,
            label,
            identity_fingerprint,
        };

        Self {
            metadata,
            shard_data,
            passphrase_salt: None,
        }
    }

    /// Verify shard integrity
    pub fn verify(&self) -> bool {
        let mut hasher = Hasher::new();
        hasher.update(&self.metadata.shard_id);
        hasher.update(&self.shard_data);
        let expected = hasher.finalize();

        self.metadata.verification_hash == expected.as_bytes()[..32]
    }

    /// Check if shard has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.metadata.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    /// Convert back to a sharks Share
    fn to_share(&self) -> Result<Share, RegenerativeError> {
        Share::try_from(self.shard_data.as_slice())
            .map_err(|_| RegenerativeError::InvalidShardFormat)
    }

    /// Get the shard index
    pub fn index(&self) -> u8 {
        self.metadata.index
    }
}

/// Configuration for identity sharding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardingConfig {
    /// Minimum shards needed for recovery
    pub threshold: u8,
    /// Total shards to create
    pub total_shards: u8,
    /// Shard expiration duration (if any)
    pub expiration: Option<Duration>,
    /// Storage assignments for each shard
    pub storage_plan: Vec<(ShardStorageType, String)>,
}

impl Default for ShardingConfig {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
            total_shards: DEFAULT_TOTAL_SHARDS,
            expiration: Some(Duration::days(365)), // 1 year default
            storage_plan: vec![
                (ShardStorageType::LocalDevice, "Primary Device".to_string()),
                (ShardStorageType::LocalDevice, "Backup Device".to_string()),
                (ShardStorageType::TrustedContact, "Contact 1".to_string()),
                (ShardStorageType::TrustedContact, "Contact 2".to_string()),
                (ShardStorageType::PaperBackup, "Paper Backup".to_string()),
            ],
        }
    }
}

impl ShardingConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<(), RegenerativeError> {
        if self.threshold < 2 || self.threshold > self.total_shards {
            return Err(RegenerativeError::InvalidThreshold);
        }
        Ok(())
    }
}

/// Identity regeneration system
pub struct IdentityRegenerator {
    /// Configuration
    config: ShardingConfig,
    /// Sharks instance for the sharing scheme
    sharks: Sharks,
}

impl std::fmt::Debug for IdentityRegenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityRegenerator")
            .field("config", &self.config)
            .field("sharks", &format!("Sharks(threshold={})", self.config.threshold))
            .finish()
    }
}

impl IdentityRegenerator {
    /// Create a new regenerator with default config
    pub fn new() -> Self {
        Self::with_config(ShardingConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: ShardingConfig) -> Self {
        Self {
            sharks: Sharks(config.threshold),
            config,
        }
    }

    /// Shard an identity secret into recoverable pieces
    pub fn shard_identity(
        &self,
        secret: &[u8],
    ) -> Result<Vec<IdentityShard>, RegenerativeError> {
        if secret.len() > MAX_SECRET_SIZE {
            return Err(RegenerativeError::SecretTooLarge(MAX_SECRET_SIZE));
        }

        self.config.validate()?;

        // Create identity fingerprint
        let mut hasher = Hasher::new();
        hasher.update(secret);
        let hash = hasher.finalize();
        let mut fingerprint = [0u8; 8];
        fingerprint.copy_from_slice(&hash.as_bytes()[..8]);

        // Calculate expiration
        let expires_at = self.config.expiration.map(|d| Utc::now() + d);

        // Generate shares using Shamir Secret Sharing
        let dealer = self.sharks.dealer(secret);
        let shares: Vec<Share> = dealer.take(self.config.total_shards as usize).collect();

        // Convert to IdentityShards with metadata
        let shards: Vec<IdentityShard> = shares
            .iter()
            .enumerate()
            .map(|(i, share)| {
                let (storage_type, label) = self.config.storage_plan
                    .get(i)
                    .cloned()
                    .unwrap_or((ShardStorageType::LocalDevice, format!("Shard {}", i + 1)));

                IdentityShard::from_share(
                    share,
                    (i + 1) as u8,
                    fingerprint,
                    storage_type,
                    label,
                    expires_at,
                )
            })
            .collect();

        Ok(shards)
    }

    /// Recover identity from shards
    pub fn recover_identity(
        &self,
        shards: &[IdentityShard],
    ) -> Result<Vec<u8>, RegenerativeError> {
        // Check minimum shards
        if shards.len() < self.config.threshold as usize {
            return Err(RegenerativeError::InsufficientShards(
                shards.len(),
                self.config.threshold,
            ));
        }

        // Verify all shards
        for shard in shards {
            if !shard.verify() {
                return Err(RegenerativeError::ShardVerificationFailed);
            }
            if shard.is_expired() {
                return Err(RegenerativeError::ShardExpired);
            }
        }

        // Convert to sharks Shares
        let shares: Result<Vec<Share>, _> = shards.iter().map(|s| s.to_share()).collect();
        let shares = shares?;

        // Recover the secret
        self.sharks.recover(&shares)
            .map_err(|e| RegenerativeError::RecoveryFailed(format!("{:?}", e)))
    }

    /// Get the threshold required for recovery
    pub fn threshold(&self) -> u8 {
        self.config.threshold
    }

    /// Get total shards
    pub fn total_shards(&self) -> u8 {
        self.config.total_shards
    }
}

impl Default for IdentityRegenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Recovery progress tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProgress {
    /// Identity fingerprint being recovered
    pub fingerprint: [u8; 8],
    /// Required threshold
    pub threshold: u8,
    /// Collected shards (by index)
    pub collected: HashMap<u8, ShardMetadata>,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Expires at (recovery attempt timeout)
    pub expires_at: DateTime<Utc>,
}

impl RecoveryProgress {
    /// Start a new recovery process
    pub fn start(fingerprint: [u8; 8], threshold: u8, timeout: Duration) -> Self {
        let now = Utc::now();
        Self {
            fingerprint,
            threshold,
            collected: HashMap::new(),
            started_at: now,
            expires_at: now + timeout,
        }
    }

    /// Add a collected shard
    pub fn add_shard(&mut self, shard: &IdentityShard) -> bool {
        if shard.metadata.identity_fingerprint != self.fingerprint {
            return false;
        }
        self.collected.insert(shard.metadata.index, shard.metadata.clone());
        true
    }

    /// Check if we have enough shards
    pub fn can_recover(&self) -> bool {
        self.collected.len() >= self.threshold as usize
    }

    /// Check if recovery attempt has timed out
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Get progress percentage
    pub fn progress_percent(&self) -> u8 {
        let progress = (self.collected.len() as f32 / self.threshold as f32) * 100.0;
        progress.min(100.0) as u8
    }

    /// Get remaining shards needed
    pub fn remaining(&self) -> usize {
        self.threshold.saturating_sub(self.collected.len() as u8) as usize
    }
}

/// Shard rotation for enhanced security
pub struct ShardRotation {
    /// Current generation number
    pub generation: u64,
    /// When current shards were created
    pub created_at: DateTime<Utc>,
    /// Rotation interval
    pub rotation_interval: Duration,
}

impl ShardRotation {
    /// Create new rotation tracker
    pub fn new(rotation_interval: Duration) -> Self {
        Self {
            generation: 0,
            created_at: Utc::now(),
            rotation_interval,
        }
    }

    /// Check if rotation is due
    pub fn needs_rotation(&self) -> bool {
        Utc::now() > self.created_at + self.rotation_interval
    }

    /// Record that rotation occurred
    pub fn rotated(&mut self) {
        self.generation += 1;
        self.created_at = Utc::now();
    }

    /// Get time until next rotation
    pub fn time_until_rotation(&self) -> Option<Duration> {
        let due = self.created_at + self.rotation_interval;
        if Utc::now() < due {
            Some(due - Utc::now())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> Vec<u8> {
        vec![42u8; 32]
    }

    #[test]
    fn test_basic_sharding_and_recovery() {
        let regenerator = IdentityRegenerator::new();
        let secret = test_secret();

        // Shard the identity
        let shards = regenerator.shard_identity(&secret).unwrap();
        assert_eq!(shards.len(), DEFAULT_TOTAL_SHARDS as usize);

        // Verify all shards
        for shard in &shards {
            assert!(shard.verify());
            assert!(!shard.is_expired());
        }

        // Recover with minimum shards (3 of 5)
        let recovery_shards = &shards[0..3];
        let recovered = regenerator.recover_identity(recovery_shards).unwrap();

        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_insufficient_shards() {
        let regenerator = IdentityRegenerator::new();
        let secret = test_secret();

        let shards = regenerator.shard_identity(&secret).unwrap();

        // Try with only 2 shards (need 3)
        let recovery_shards = &shards[0..2];
        let result = regenerator.recover_identity(recovery_shards);

        assert!(matches!(result, Err(RegenerativeError::InsufficientShards(2, 3))));
    }

    #[test]
    fn test_any_shard_combination() {
        let regenerator = IdentityRegenerator::new();
        let secret = test_secret();

        let shards = regenerator.shard_identity(&secret).unwrap();

        // Recovery should work with any 3 shards
        let combinations = vec![
            vec![0, 1, 2],
            vec![0, 2, 4],
            vec![1, 3, 4],
            vec![0, 1, 2, 3], // More than threshold is fine
        ];

        for combo in combinations {
            let recovery_shards: Vec<_> = combo.iter().map(|&i| shards[i].clone()).collect();
            let recovered = regenerator.recover_identity(&recovery_shards).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn test_shard_metadata() {
        let regenerator = IdentityRegenerator::new();
        let secret = test_secret();

        let shards = regenerator.shard_identity(&secret).unwrap();

        // Check metadata
        assert_eq!(shards[0].metadata.storage_type, ShardStorageType::LocalDevice);
        assert_eq!(shards[2].metadata.storage_type, ShardStorageType::TrustedContact);
        assert!(shards[0].metadata.expires_at.is_some());

        // All shards should have same fingerprint
        let fingerprint = shards[0].metadata.identity_fingerprint;
        for shard in &shards {
            assert_eq!(shard.metadata.identity_fingerprint, fingerprint);
        }
    }

    #[test]
    fn test_custom_config() {
        let config = ShardingConfig {
            threshold: 2,
            total_shards: 3,
            expiration: None, // No expiration
            storage_plan: vec![
                (ShardStorageType::LocalDevice, "Device".to_string()),
                (ShardStorageType::TrustedContact, "Friend".to_string()),
                (ShardStorageType::PaperBackup, "Paper".to_string()),
            ],
        };

        let regenerator = IdentityRegenerator::with_config(config);
        let secret = test_secret();

        let shards = regenerator.shard_identity(&secret).unwrap();
        assert_eq!(shards.len(), 3);
        assert!(shards[0].metadata.expires_at.is_none());

        // 2-of-3 recovery
        let recovered = regenerator.recover_identity(&shards[0..2]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_recovery_progress() {
        let mut progress = RecoveryProgress::start(
            [1u8; 8],
            3,
            Duration::hours(24),
        );

        assert_eq!(progress.remaining(), 3);
        assert!(!progress.can_recover());
        assert_eq!(progress.progress_percent(), 0);

        // Simulate adding shards
        let regenerator = IdentityRegenerator::new();
        let shards = regenerator.shard_identity(&test_secret()).unwrap();

        // First shard won't match fingerprint
        let matched = progress.add_shard(&shards[0]);
        assert!(!matched); // Different fingerprint

        // Create matching fingerprint progress
        let mut progress2 = RecoveryProgress::start(
            shards[0].metadata.identity_fingerprint,
            3,
            Duration::hours(24),
        );

        progress2.add_shard(&shards[0]);
        assert_eq!(progress2.progress_percent(), 33);

        progress2.add_shard(&shards[1]);
        assert_eq!(progress2.progress_percent(), 66);

        progress2.add_shard(&shards[2]);
        assert!(progress2.can_recover());
        assert_eq!(progress2.remaining(), 0);
    }

    #[test]
    fn test_invalid_threshold() {
        let config = ShardingConfig {
            threshold: 10, // More than total
            total_shards: 5,
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_secret_too_large() {
        let regenerator = IdentityRegenerator::new();
        let large_secret = vec![0u8; 64]; // Too large

        let result = regenerator.shard_identity(&large_secret);
        assert!(matches!(result, Err(RegenerativeError::SecretTooLarge(_))));
    }

    #[test]
    fn test_shard_rotation() {
        let mut rotation = ShardRotation::new(Duration::hours(24));

        assert!(!rotation.needs_rotation());
        assert_eq!(rotation.generation, 0);
        assert!(rotation.time_until_rotation().is_some());

        rotation.rotated();
        assert_eq!(rotation.generation, 1);
    }
}
