//! Quarantine Storage - Capture telemetry for security analysis
//!
//! Captures telemetry that would have been sent for offline analysis.
//! Perfect for OWASP testing and security audits.

use crate::{FlowMeta, TelemetryIntent, RiskLevel, Decision, TelemetryGuardError, Result};
use blake3::Hasher;
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Maximum quarantine entries (default)
const DEFAULT_MAX_ENTRIES: usize = 10000;

/// Maximum payload sample size (bytes)
const MAX_SAMPLE_SIZE: usize = 4096;

/// A quarantined telemetry payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedPayload {
    /// Unique quarantine entry ID
    pub entry_id: [u8; 32],
    /// Flow metadata
    pub flow_meta: QuarantineFlowMeta,
    /// When captured
    pub captured_at: DateTime<Utc>,
    /// Hash of the full payload (for verification)
    pub payload_hash: [u8; 32],
    /// Payload size in bytes
    pub payload_size: u64,
    /// Encrypted sample of payload (user can decrypt to inspect)
    pub encrypted_sample: Vec<u8>,
    /// Why this was quarantined
    pub reason: QuarantineReason,
    /// User's review status
    pub review_status: ReviewStatus,
    /// Analysis results (if analyzed)
    pub analysis: Option<PayloadAnalysis>,
    /// Tags for organization
    pub tags: Vec<String>,
}

/// Simplified flow meta for quarantine (privacy-safe)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineFlowMeta {
    /// Destination hostname
    pub destination: String,
    /// Destination port
    pub port: u16,
    /// Protocol
    pub protocol: String,
    /// HTTP method
    pub method: Option<String>,
    /// Request path
    pub path: Option<String>,
    /// Inferred intent
    pub intent: TelemetryIntent,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Process name (if available)
    pub process: Option<String>,
}

impl From<&FlowMeta> for QuarantineFlowMeta {
    fn from(flow: &FlowMeta) -> Self {
        Self {
            destination: flow.effective_hostname(),
            port: flow.destination_port(),
            protocol: format!("{:?}", flow.protocol),
            method: flow.http_method.clone(),
            path: flow.request_path.clone(),
            intent: flow.inferred_intent,
            risk_level: flow.risk_level,
            process: flow.process_name.clone(),
        }
    }
}

/// Why the payload was quarantined
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuarantineReason {
    /// User requested quarantine for analysis
    UserRequest,
    /// Unknown telemetry endpoint
    UnknownEndpoint,
    /// Suspicious pattern detected
    SuspiciousPattern { pattern: String },
    /// High risk score
    HighRisk { score: f32 },
    /// Large payload
    LargePayload { size: u64 },
    /// Policy configured quarantine
    PolicyRule { rule_id: String },
    /// First time seeing this endpoint
    NewEndpoint,
    /// Anomaly detection triggered
    Anomaly { description: String },
}

/// User review status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewStatus {
    /// Pending review
    Pending,
    /// Reviewed and approved (will allow future traffic)
    Approved,
    /// Reviewed and rejected (will block future traffic)
    Rejected,
    /// Flagged for further investigation
    Flagged,
    /// Archived (processed, kept for records)
    Archived,
}

/// Analysis results for a quarantined payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAnalysis {
    /// When analysis was performed
    pub analyzed_at: DateTime<Utc>,
    /// Detected data types
    pub detected_types: Vec<DetectedDataType>,
    /// Privacy concerns found
    pub privacy_concerns: Vec<PrivacyConcern>,
    /// Confidence in analysis (0.0 - 1.0)
    pub confidence: f32,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Types of data detected in payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectedDataType {
    /// Device identifiers (IMEI, advertising ID, etc.)
    DeviceIdentifier { id_type: String },
    /// IP address
    IpAddress,
    /// Location data
    Location { precision: String },
    /// User identifier
    UserId,
    /// Email address
    Email,
    /// Phone number
    PhoneNumber,
    /// Browsing history
    BrowsingHistory,
    /// App usage patterns
    AppUsage,
    /// Keystroke patterns
    KeystrokeData,
    /// Biometric data
    BiometricData,
    /// Financial data
    FinancialData,
    /// Health data
    HealthData,
    /// Generic PII
    GenericPII,
    /// Encrypted/unknown
    Unknown,
}

/// Privacy concerns in payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConcern {
    /// Type of concern
    pub concern_type: String,
    /// Severity (1-5)
    pub severity: u8,
    /// Description
    pub description: String,
    /// Remediation suggestion
    pub remediation: Option<String>,
}

/// Quarantine storage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineStats {
    /// Total entries
    pub total_entries: usize,
    /// Entries by status
    pub by_status: HashMap<String, usize>,
    /// Entries by intent
    pub by_intent: HashMap<String, usize>,
    /// Entries by risk level
    pub by_risk: HashMap<String, usize>,
    /// Total bytes captured
    pub total_bytes: u64,
    /// Oldest entry
    pub oldest_entry: Option<DateTime<Utc>>,
    /// Newest entry
    pub newest_entry: Option<DateTime<Utc>>,
}

/// Quarantine storage manager
#[derive(Debug)]
pub struct QuarantineStorage {
    /// Stored entries (FIFO when full)
    entries: RwLock<VecDeque<QuarantinedPayload>>,
    /// Index by entry ID
    index: RwLock<HashMap<[u8; 32], usize>>,
    /// Maximum entries to store
    max_entries: usize,
    /// Encryption key for samples
    encryption_key: [u8; 32],
    /// Statistics
    stats: RwLock<QuarantineStats>,
}

impl QuarantineStorage {
    /// Create new quarantine storage
    pub fn new(encryption_key: [u8; 32]) -> Self {
        Self::with_capacity(encryption_key, DEFAULT_MAX_ENTRIES)
    }

    /// Create with custom capacity
    pub fn with_capacity(encryption_key: [u8; 32], max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max_entries)),
            index: RwLock::new(HashMap::new()),
            max_entries,
            encryption_key,
            stats: RwLock::new(QuarantineStats::default()),
        }
    }

    /// Quarantine a payload
    pub fn quarantine(
        &self,
        flow: &FlowMeta,
        payload: &[u8],
        reason: QuarantineReason,
    ) -> Result<[u8; 32]> {
        // Generate entry ID (include payload hash for uniqueness)
        let mut hasher = Hasher::new();
        hasher.update(&flow.flow_id);
        hasher.update(&Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        hasher.update(payload); // Include payload to ensure unique IDs
        let mut entry_id = [0u8; 32];
        entry_id.copy_from_slice(hasher.finalize().as_bytes());

        // Hash full payload
        let payload_hash = blake3::hash(payload);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(payload_hash.as_bytes());

        // Encrypt a sample
        let sample = &payload[..payload.len().min(MAX_SAMPLE_SIZE)];
        let encrypted_sample = self.encrypt_sample(sample, &entry_id);

        let entry = QuarantinedPayload {
            entry_id,
            flow_meta: flow.into(),
            captured_at: Utc::now(),
            payload_hash: hash_bytes,
            payload_size: payload.len() as u64,
            encrypted_sample,
            reason,
            review_status: ReviewStatus::Pending,
            analysis: None,
            tags: Vec::new(),
        };

        // Add to storage
        {
            let mut entries = self.entries.write();
            let mut index = self.index.write();

            // Remove oldest if at capacity
            if entries.len() >= self.max_entries {
                if let Some(old) = entries.pop_front() {
                    index.remove(&old.entry_id);
                }
            }

            let position = entries.len();
            index.insert(entry_id, position);
            entries.push_back(entry);
        }

        // Update stats
        self.update_stats();

        Ok(entry_id)
    }

    /// Simple XOR encryption for sample
    fn encrypt_sample(&self, sample: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
        let mut hasher = Hasher::new_keyed(&self.encryption_key);
        hasher.update(nonce);
        let key_stream = hasher.finalize();

        sample
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key_stream.as_bytes()[i % 32])
            .collect()
    }

    /// Decrypt a sample
    pub fn decrypt_sample(&self, entry_id: &[u8; 32]) -> Option<Vec<u8>> {
        let entries = self.entries.read();
        let index = self.index.read();

        let position = index.get(entry_id)?;
        let entry = entries.get(*position)?;

        // Decrypt
        let decrypted = self.encrypt_sample(&entry.encrypted_sample, entry_id); // XOR is symmetric
        Some(decrypted)
    }

    /// Get entry by ID
    pub fn get(&self, entry_id: &[u8; 32]) -> Option<QuarantinedPayload> {
        let entries = self.entries.read();
        let index = self.index.read();

        let position = index.get(entry_id)?;
        entries.get(*position).cloned()
    }

    /// Update review status
    pub fn set_status(&self, entry_id: &[u8; 32], status: ReviewStatus) -> bool {
        let mut entries = self.entries.write();
        let index = self.index.read();

        if let Some(&position) = index.get(entry_id) {
            if let Some(entry) = entries.get_mut(position) {
                entry.review_status = status;
                return true;
            }
        }
        false
    }

    /// Add analysis results
    pub fn set_analysis(&self, entry_id: &[u8; 32], analysis: PayloadAnalysis) -> bool {
        let mut entries = self.entries.write();
        let index = self.index.read();

        if let Some(&position) = index.get(entry_id) {
            if let Some(entry) = entries.get_mut(position) {
                entry.analysis = Some(analysis);
                return true;
            }
        }
        false
    }

    /// Add tags to an entry
    pub fn add_tag(&self, entry_id: &[u8; 32], tag: String) -> bool {
        let mut entries = self.entries.write();
        let index = self.index.read();

        if let Some(&position) = index.get(entry_id) {
            if let Some(entry) = entries.get_mut(position) {
                if !entry.tags.contains(&tag) {
                    entry.tags.push(tag);
                }
                return true;
            }
        }
        false
    }

    /// Get entries by status
    pub fn get_by_status(&self, status: ReviewStatus) -> Vec<QuarantinedPayload> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.review_status == status)
            .cloned()
            .collect()
    }

    /// Get pending entries
    pub fn get_pending(&self) -> Vec<QuarantinedPayload> {
        self.get_by_status(ReviewStatus::Pending)
    }

    /// Get entries by destination
    pub fn get_by_destination(&self, destination: &str) -> Vec<QuarantinedPayload> {
        let dest_lower = destination.to_lowercase();
        self.entries
            .read()
            .iter()
            .filter(|e| e.flow_meta.destination.to_lowercase().contains(&dest_lower))
            .cloned()
            .collect()
    }

    /// Get entries by risk level
    pub fn get_by_risk(&self, min_risk: RiskLevel) -> Vec<QuarantinedPayload> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.flow_meta.risk_level >= min_risk)
            .cloned()
            .collect()
    }

    /// Delete an entry
    pub fn delete(&self, entry_id: &[u8; 32]) -> bool {
        let mut entries = self.entries.write();
        let mut index = self.index.write();

        if let Some(&position) = index.get(entry_id) {
            entries.remove(position);
            index.remove(entry_id);
            // Rebuild index (positions shifted)
            index.clear();
            for (i, e) in entries.iter().enumerate() {
                index.insert(e.entry_id, i);
            }
            self.update_stats();
            return true;
        }
        false
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.entries.write().clear();
        self.index.write().clear();
        *self.stats.write() = QuarantineStats::default();
    }

    /// Get statistics
    pub fn stats(&self) -> QuarantineStats {
        self.stats.read().clone()
    }

    /// Update statistics
    fn update_stats(&self) {
        let entries = self.entries.read();
        let mut stats = self.stats.write();

        stats.total_entries = entries.len();
        stats.by_status.clear();
        stats.by_intent.clear();
        stats.by_risk.clear();
        stats.total_bytes = 0;
        stats.oldest_entry = None;
        stats.newest_entry = None;

        for entry in entries.iter() {
            let status_key = format!("{:?}", entry.review_status);
            *stats.by_status.entry(status_key).or_insert(0) += 1;

            let intent_key = format!("{:?}", entry.flow_meta.intent);
            *stats.by_intent.entry(intent_key).or_insert(0) += 1;

            let risk_key = format!("{:?}", entry.flow_meta.risk_level);
            *stats.by_risk.entry(risk_key).or_insert(0) += 1;

            stats.total_bytes += entry.payload_size;

            if stats.oldest_entry.is_none() || entry.captured_at < stats.oldest_entry.unwrap() {
                stats.oldest_entry = Some(entry.captured_at);
            }
            if stats.newest_entry.is_none() || entry.captured_at > stats.newest_entry.unwrap() {
                stats.newest_entry = Some(entry.captured_at);
            }
        }
    }

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Export all entries as JSON
    pub fn export_json(&self) -> Result<String> {
        let entries: Vec<_> = self.entries.read().iter().cloned().collect();
        serde_json::to_string_pretty(&entries)
            .map_err(|e| TelemetryGuardError::IoError(e.to_string()))
    }
}

/// Shared quarantine storage
pub type SharedQuarantineStorage = Arc<QuarantineStorage>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn test_flow() -> FlowMeta {
        FlowMeta::from_http(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443)),
            "tracking.example.com",
            "POST",
            "/collect",
        )
    }

    #[test]
    fn test_quarantine_payload() {
        let storage = QuarantineStorage::new(test_key());
        let flow = test_flow();
        let payload = b"some telemetry data";

        let entry_id = storage
            .quarantine(&flow, payload, QuarantineReason::UserRequest)
            .unwrap();

        assert_eq!(storage.len(), 1);

        let entry = storage.get(&entry_id).unwrap();
        assert_eq!(entry.flow_meta.destination, "tracking.example.com");
        assert_eq!(entry.review_status, ReviewStatus::Pending);
    }

    #[test]
    fn test_decrypt_sample() {
        let storage = QuarantineStorage::new(test_key());
        let flow = test_flow();
        let payload = b"secret telemetry data here";

        let entry_id = storage
            .quarantine(&flow, payload, QuarantineReason::UserRequest)
            .unwrap();

        let decrypted = storage.decrypt_sample(&entry_id).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_update_status() {
        let storage = QuarantineStorage::new(test_key());
        let flow = test_flow();

        let entry_id = storage
            .quarantine(&flow, b"data", QuarantineReason::UserRequest)
            .unwrap();

        storage.set_status(&entry_id, ReviewStatus::Approved);

        let entry = storage.get(&entry_id).unwrap();
        assert_eq!(entry.review_status, ReviewStatus::Approved);
    }

    #[test]
    fn test_capacity_limit() {
        let storage = QuarantineStorage::with_capacity(test_key(), 3);
        let flow = test_flow();

        // Add 5 entries
        for i in 0..5 {
            storage
                .quarantine(&flow, &[i as u8], QuarantineReason::UserRequest)
                .unwrap();
        }

        // Should only have 3
        assert_eq!(storage.len(), 3);
    }

    #[test]
    fn test_get_by_status() {
        let storage = QuarantineStorage::new(test_key());
        let flow = test_flow();

        let id1 = storage.quarantine(&flow, b"1", QuarantineReason::UserRequest).unwrap();
        let id2 = storage.quarantine(&flow, b"2", QuarantineReason::UserRequest).unwrap();
        storage.quarantine(&flow, b"3", QuarantineReason::UserRequest).unwrap();

        storage.set_status(&id1, ReviewStatus::Approved);
        storage.set_status(&id2, ReviewStatus::Approved);

        let approved = storage.get_by_status(ReviewStatus::Approved);
        assert_eq!(approved.len(), 2);

        let pending = storage.get_pending();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_statistics() {
        let storage = QuarantineStorage::new(test_key());
        let flow = test_flow();

        storage.quarantine(&flow, b"data1", QuarantineReason::UserRequest).unwrap();
        storage.quarantine(&flow, b"data2", QuarantineReason::UserRequest).unwrap();

        let stats = storage.stats();
        assert_eq!(stats.total_entries, 2);
        assert!(stats.total_bytes > 0);
        assert!(stats.oldest_entry.is_some());
    }

    #[test]
    fn test_add_tags() {
        let storage = QuarantineStorage::new(test_key());
        let flow = test_flow();

        let entry_id = storage.quarantine(&flow, b"data", QuarantineReason::UserRequest).unwrap();

        storage.add_tag(&entry_id, "suspicious".to_string());
        storage.add_tag(&entry_id, "google".to_string());

        let entry = storage.get(&entry_id).unwrap();
        assert_eq!(entry.tags.len(), 2);
        assert!(entry.tags.contains(&"suspicious".to_string()));
    }
}
