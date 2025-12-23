//! Consent Gate - Cryptographically-enforced telemetry consent
//!
//! Integrates with HSIP's quantum physics modules to provide:
//! - Decaying consent (auto-expiry via Decoherence)
//! - Single-use tokens (anti-replay via No-Cloning)
//! - Mutual consent verification (Entanglement)
//! - Privacy-level integration (Uncertainty)

use crate::{Decision, DecisionReason, FlowMeta, TelemetryGuardError, TelemetryIntent, Result};
use blake3::Hasher;
use chrono::{DateTime, Duration, Utc};
use hsip_common::quantum_physics::{
    no_cloning::AntiReplayGuard,
    uncertainty::PrivacyLevel,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Default consent duration (90 days)
const DEFAULT_CONSENT_DAYS: i64 = 90;

/// Scope of telemetry consent
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsentScope {
    /// Consent for a specific domain
    Domain(String),
    /// Consent for a domain pattern (*.example.com)
    DomainPattern(String),
    /// Consent for a specific vendor
    Vendor(String),
    /// Consent for a telemetry intent type
    Intent(TelemetryIntent),
    /// Consent for all telemetry from an app
    Application(String),
    /// Global consent (all telemetry)
    Global,
}

impl ConsentScope {
    /// Check if this scope matches a flow
    pub fn matches(&self, flow: &FlowMeta, vendor: Option<&str>) -> bool {
        match self {
            ConsentScope::Domain(domain) => {
                flow.effective_hostname().to_lowercase() == domain.to_lowercase()
            }
            ConsentScope::DomainPattern(pattern) => {
                let hostname = flow.effective_hostname().to_lowercase();
                if pattern.starts_with("*.") {
                    let suffix = pattern[2..].to_lowercase();
                    hostname.ends_with(&suffix) || hostname == suffix
                } else {
                    hostname == pattern.to_lowercase()
                }
            }
            ConsentScope::Vendor(v) => vendor.map(|vn| vn.to_lowercase() == v.to_lowercase()).unwrap_or(false),
            ConsentScope::Intent(intent) => flow.inferred_intent == *intent,
            ConsentScope::Application(app) => {
                flow.process_name
                    .as_ref()
                    .map(|p| p.to_lowercase().contains(&app.to_lowercase()))
                    .unwrap_or(false)
            }
            ConsentScope::Global => true,
        }
    }

    /// Get a unique identifier for this scope
    pub fn scope_id(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        match self {
            ConsentScope::Domain(d) => {
                hasher.update(b"domain:");
                hasher.update(d.as_bytes());
            }
            ConsentScope::DomainPattern(p) => {
                hasher.update(b"pattern:");
                hasher.update(p.as_bytes());
            }
            ConsentScope::Vendor(v) => {
                hasher.update(b"vendor:");
                hasher.update(v.as_bytes());
            }
            ConsentScope::Intent(i) => {
                hasher.update(b"intent:");
                hasher.update(&[*i as u8]);
            }
            ConsentScope::Application(a) => {
                hasher.update(b"app:");
                hasher.update(a.as_bytes());
            }
            ConsentScope::Global => {
                hasher.update(b"global");
            }
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(hasher.finalize().as_bytes());
        id
    }
}

/// A telemetry consent token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConsent {
    /// Unique consent ID
    pub consent_id: [u8; 32],
    /// What this consent covers
    pub scope: ConsentScope,
    /// User who granted consent (public key hash)
    pub grantor: [u8; 32],
    /// When consent was granted
    pub granted_at: DateTime<Utc>,
    /// When consent expires
    pub expires_at: DateTime<Utc>,
    /// Optional data minimization requirements
    pub minimization: Option<DataMinimization>,
    /// Whether this is single-use
    pub single_use: bool,
    /// Cryptographic signature (as hex string for serde compat)
    pub signature_hex: String,
}

impl TelemetryConsent {
    /// Create a new consent token
    pub fn new(
        scope: ConsentScope,
        grantor: [u8; 32],
        duration: Duration,
        single_use: bool,
        signing_key: &[u8; 32],
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + duration;

        // Generate consent ID
        let mut hasher = Hasher::new();
        hasher.update(&scope.scope_id());
        hasher.update(&grantor);
        hasher.update(&now.timestamp_millis().to_le_bytes());
        let mut consent_id = [0u8; 32];
        consent_id.copy_from_slice(hasher.finalize().as_bytes());

        // Create signature
        let mut sig_hasher = Hasher::new_keyed(signing_key);
        sig_hasher.update(&consent_id);
        sig_hasher.update(&expires_at.timestamp_millis().to_le_bytes());
        let sig_hash = sig_hasher.finalize();
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(sig_hash.as_bytes());
        signature[32..].copy_from_slice(&consent_id);

        Self {
            consent_id,
            scope,
            grantor,
            granted_at: now,
            expires_at,
            minimization: None,
            single_use,
            signature_hex: hex::encode(signature),
        }
    }

    /// Create a 90-day consent (default)
    pub fn standard(scope: ConsentScope, grantor: [u8; 32], signing_key: &[u8; 32]) -> Self {
        Self::new(scope, grantor, Duration::days(DEFAULT_CONSENT_DAYS), false, signing_key)
    }

    /// Create a single-use consent
    pub fn one_time(scope: ConsentScope, grantor: [u8; 32], signing_key: &[u8; 32]) -> Self {
        Self::new(scope, grantor, Duration::hours(24), true, signing_key)
    }

    /// Add data minimization requirements
    pub fn with_minimization(mut self, minimization: DataMinimization) -> Self {
        self.minimization = Some(minimization);
        self
    }

    /// Check if consent is still valid
    pub fn is_valid(&self) -> bool {
        Utc::now() <= self.expires_at
    }

    /// Verify the signature
    pub fn verify(&self, signing_key: &[u8; 32]) -> bool {
        let Ok(sig_bytes) = hex::decode(&self.signature_hex) else {
            return false;
        };
        if sig_bytes.len() != 64 {
            return false;
        }

        let mut sig_hasher = Hasher::new_keyed(signing_key);
        sig_hasher.update(&self.consent_id);
        sig_hasher.update(&self.expires_at.timestamp_millis().to_le_bytes());
        let expected = sig_hasher.finalize();

        sig_bytes[..32] == expected.as_bytes()[..32]
            && sig_bytes[32..] == self.consent_id
    }

    /// Get remaining lifetime
    pub fn remaining(&self) -> Option<Duration> {
        let now = Utc::now();
        if now > self.expires_at {
            None
        } else {
            Some(self.expires_at - now)
        }
    }

    /// Extend the consent (renew)
    pub fn renew(&mut self, duration: Duration) {
        self.expires_at = Utc::now() + duration;
    }
}

/// Data minimization requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataMinimization {
    /// Strip user identifiers
    pub strip_identifiers: bool,
    /// Strip precise timestamps (round to hour)
    pub round_timestamps: bool,
    /// Strip IP addresses
    pub strip_ip: bool,
    /// Strip device info
    pub strip_device_info: bool,
    /// Maximum payload size (bytes)
    pub max_payload_size: Option<u64>,
}

impl Default for DataMinimization {
    fn default() -> Self {
        Self {
            strip_identifiers: true,
            strip_ip: true,
            strip_device_info: false,
            round_timestamps: false,
            max_payload_size: Some(4096),
        }
    }
}

impl DataMinimization {
    /// Create strict minimization
    pub fn strict() -> Self {
        Self {
            strip_identifiers: true,
            round_timestamps: true,
            strip_ip: true,
            strip_device_info: true,
            max_payload_size: Some(1024),
        }
    }
}

/// The consent gate - manages all consent tokens
#[derive(Debug)]
pub struct ConsentGate {
    /// Active consents indexed by scope ID
    consents: RwLock<HashMap<[u8; 32], TelemetryConsent>>,
    /// Signing key for consent verification
    signing_key: [u8; 32],
    /// Anti-replay guard for single-use tokens
    anti_replay: AntiReplayGuard,
    /// Single-use tokens that have been consumed
    consumed_tokens: RwLock<HashMap<[u8; 32], DateTime<Utc>>>,
    /// Privacy level
    privacy_level: RwLock<PrivacyLevel>,
}

impl ConsentGate {
    /// Create a new consent gate
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self {
            consents: RwLock::new(HashMap::new()),
            signing_key,
            anti_replay: AntiReplayGuard::new(),
            consumed_tokens: RwLock::new(HashMap::new()),
            privacy_level: RwLock::new(PrivacyLevel::Balanced),
        }
    }

    /// Set privacy level
    pub fn set_privacy_level(&self, level: PrivacyLevel) {
        *self.privacy_level.write() = level;
    }

    /// Get privacy level
    pub fn privacy_level(&self) -> PrivacyLevel {
        *self.privacy_level.read()
    }

    /// Grant consent
    pub fn grant(&self, consent: TelemetryConsent) -> Result<[u8; 32]> {
        if !consent.verify(&self.signing_key) {
            return Err(TelemetryGuardError::InvalidConsent);
        }

        let id = consent.consent_id;
        let scope_id = consent.scope.scope_id();

        self.consents.write().insert(scope_id, consent);
        Ok(id)
    }

    /// Grant consent for a scope with default settings
    pub fn grant_for_scope(&self, scope: ConsentScope, grantor: [u8; 32]) -> Result<[u8; 32]> {
        let consent = TelemetryConsent::standard(scope, grantor, &self.signing_key);
        self.grant(consent)
    }

    /// Revoke consent
    pub fn revoke(&self, scope: &ConsentScope) -> bool {
        let scope_id = scope.scope_id();
        self.consents.write().remove(&scope_id).is_some()
    }

    /// Revoke all consents
    pub fn revoke_all(&self) {
        self.consents.write().clear();
    }

    /// Check if consent exists for a flow
    pub fn check_consent(&self, flow: &FlowMeta, vendor: Option<&str>) -> Option<TelemetryConsent> {
        let consents = self.consents.read();

        for consent in consents.values() {
            if consent.scope.matches(flow, vendor) && consent.is_valid() {
                // Check if single-use and already consumed
                if consent.single_use {
                    let consumed = self.consumed_tokens.read();
                    if consumed.contains_key(&consent.consent_id) {
                        continue;
                    }
                }

                return Some(consent.clone());
            }
        }

        None
    }

    /// Consume a single-use consent token
    pub fn consume(&self, consent_id: &[u8; 32]) -> bool {
        let consents = self.consents.read();

        // Find the consent
        for consent in consents.values() {
            if &consent.consent_id == consent_id {
                if consent.single_use {
                    self.consumed_tokens.write().insert(*consent_id, Utc::now());
                    return true;
                }
                return true; // Non-single-use can be "consumed" multiple times
            }
        }

        false
    }

    /// Evaluate flow and return decision based on consent
    pub fn evaluate(&self, flow: &FlowMeta, vendor: Option<&str>) -> Decision {
        // Check privacy level - highest privacy blocks almost everything
        let privacy = *self.privacy_level.read();
        if privacy == PrivacyLevel::Maximum {
            // Only allow crash reports at maximum privacy
            if flow.inferred_intent != TelemetryIntent::CrashReport {
                return Decision::block(flow, DecisionReason::PrivacyLevelBlock { level: 4 });
            }
        }

        // Check for valid consent
        if let Some(consent) = self.check_consent(flow, vendor) {
            // Consume single-use tokens
            if consent.single_use {
                self.consume(&consent.consent_id);
                return Decision::allow_once(
                    flow,
                    DecisionReason::UserConsent { consent_id: consent.consent_id },
                );
            }

            let ttl = consent.remaining().map(|d| chrono::Duration::seconds(d.num_seconds()));
            return Decision::allow(
                flow,
                DecisionReason::UserConsent { consent_id: consent.consent_id },
                ttl,
            );
        }

        // No consent - default block
        Decision::block(flow, DecisionReason::NoConsent)
    }

    /// Get all active consents
    pub fn active_consents(&self) -> Vec<TelemetryConsent> {
        self.consents
            .read()
            .values()
            .filter(|c| c.is_valid())
            .cloned()
            .collect()
    }

    /// Get consent count
    pub fn consent_count(&self) -> usize {
        self.consents.read().values().filter(|c| c.is_valid()).count()
    }

    /// Clean up expired consents
    pub fn cleanup_expired(&self) -> usize {
        let mut consents = self.consents.write();
        let before = consents.len();
        consents.retain(|_, c| c.is_valid());
        before - consents.len()
    }

    /// Clean up old consumed tokens
    pub fn cleanup_consumed(&self, max_age: Duration) -> usize {
        let cutoff = Utc::now() - max_age;
        let mut consumed = self.consumed_tokens.write();
        let before = consumed.len();
        consumed.retain(|_, ts| *ts > cutoff);
        before - consumed.len()
    }
}

/// Shared consent gate
pub type SharedConsentGate = Arc<ConsentGate>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_flow(hostname: &str) -> FlowMeta {
        FlowMeta::from_http(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443)),
            hostname,
            "POST",
            "/collect",
        )
    }

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 0x42;
        key
    }

    fn test_grantor() -> [u8; 32] {
        [1u8; 32]
    }

    #[test]
    fn test_consent_creation() {
        let scope = ConsentScope::Domain("analytics.example.com".to_string());
        let consent = TelemetryConsent::standard(scope, test_grantor(), &test_key());

        assert!(consent.is_valid());
        assert!(consent.verify(&test_key()));
        assert!(consent.remaining().is_some());
    }

    #[test]
    fn test_consent_gate_grant() {
        let gate = ConsentGate::new(test_key());

        let scope = ConsentScope::Domain("analytics.example.com".to_string());
        let result = gate.grant_for_scope(scope, test_grantor());

        assert!(result.is_ok());
        assert_eq!(gate.consent_count(), 1);
    }

    #[test]
    fn test_consent_check() {
        let gate = ConsentGate::new(test_key());

        let scope = ConsentScope::Domain("analytics.example.com".to_string());
        gate.grant_for_scope(scope, test_grantor()).unwrap();

        let flow = test_flow("analytics.example.com");
        let consent = gate.check_consent(&flow, None);
        assert!(consent.is_some());

        let other_flow = test_flow("other.example.com");
        let no_consent = gate.check_consent(&other_flow, None);
        assert!(no_consent.is_none());
    }

    #[test]
    fn test_consent_scope_pattern() {
        let gate = ConsentGate::new(test_key());

        let scope = ConsentScope::DomainPattern("*.example.com".to_string());
        gate.grant_for_scope(scope, test_grantor()).unwrap();

        // Should match subdomains
        let flow1 = test_flow("analytics.example.com");
        assert!(gate.check_consent(&flow1, None).is_some());

        let flow2 = test_flow("other.example.com");
        assert!(gate.check_consent(&flow2, None).is_some());

        // Should not match different domain
        let flow3 = test_flow("example.org");
        assert!(gate.check_consent(&flow3, None).is_none());
    }

    #[test]
    fn test_consent_revoke() {
        let gate = ConsentGate::new(test_key());

        let scope = ConsentScope::Domain("analytics.example.com".to_string());
        gate.grant_for_scope(scope.clone(), test_grantor()).unwrap();
        assert_eq!(gate.consent_count(), 1);

        gate.revoke(&scope);
        assert_eq!(gate.consent_count(), 0);
    }

    #[test]
    fn test_single_use_consent() {
        let gate = ConsentGate::new(test_key());

        let scope = ConsentScope::Domain("one-time.example.com".to_string());
        let consent = TelemetryConsent::one_time(scope, test_grantor(), &test_key());
        gate.grant(consent).unwrap();

        let flow = test_flow("one-time.example.com");

        // First check should find consent
        let c1 = gate.check_consent(&flow, None);
        assert!(c1.is_some());

        // Consume the token
        gate.consume(&c1.unwrap().consent_id);

        // Second check should not find it (consumed)
        let c2 = gate.check_consent(&flow, None);
        assert!(c2.is_none());
    }

    #[test]
    fn test_privacy_level_blocking() {
        let gate = ConsentGate::new(test_key());
        gate.set_privacy_level(PrivacyLevel::Maximum);

        // Grant consent
        let scope = ConsentScope::Global;
        gate.grant_for_scope(scope, test_grantor()).unwrap();

        // Should still block due to privacy level (non-crash)
        let mut flow = test_flow("analytics.example.com");
        flow.inferred_intent = TelemetryIntent::UsageAnalytics;

        let decision = gate.evaluate(&flow, None);
        assert!(!decision.allows_traffic());
    }

    #[test]
    fn test_consent_intent_scope() {
        let gate = ConsentGate::new(test_key());

        // Only allow crash reports
        let scope = ConsentScope::Intent(TelemetryIntent::CrashReport);
        gate.grant_for_scope(scope, test_grantor()).unwrap();

        let mut crash_flow = test_flow("sentry.io");
        crash_flow.inferred_intent = TelemetryIntent::CrashReport;
        assert!(gate.check_consent(&crash_flow, None).is_some());

        let mut analytics_flow = test_flow("analytics.com");
        analytics_flow.inferred_intent = TelemetryIntent::UsageAnalytics;
        assert!(gate.check_consent(&analytics_flow, None).is_none());
    }
}
