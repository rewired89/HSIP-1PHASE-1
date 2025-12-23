//! Telemetry Guard - Main entry point
//!
//! The TelemetryGuard combines all components into a single, easy-to-use interface.

use crate::{
    AuditLog, ConsentGate, ConsentScope, Decision, DecisionStats, DecisionType,
    EndpointDatabase, FlowMeta, PolicyConfig, PolicyEngine, PolicyRule,
    QuarantineReason, QuarantineStorage, QuarantineStats, TelemetryConsent,
    TelemetryGuardError, Result,
};
use hsip_common::quantum_physics::uncertainty::PrivacyLevel;
use parking_lot::RwLock;
use std::sync::Arc;

/// The main telemetry guard
pub struct TelemetryGuard {
    /// Known endpoints database
    endpoints: Arc<EndpointDatabase>,
    /// Policy engine
    policy: Arc<PolicyEngine>,
    /// Consent gate
    consent: Arc<ConsentGate>,
    /// Quarantine storage
    quarantine: Arc<QuarantineStorage>,
    /// Audit log
    audit: Arc<AuditLog>,
    /// Decision statistics
    stats: RwLock<DecisionStats>,
    /// Whether guard is enabled
    enabled: RwLock<bool>,
}

impl TelemetryGuard {
    /// Create a new telemetry guard with default settings
    pub fn new() -> Self {
        let endpoints = Arc::new(EndpointDatabase::new());
        let policy = Arc::new(PolicyEngine::new(endpoints.clone()));

        // Generate keys
        let mut signing_key = [0u8; 32];
        signing_key[0] = 0x53; // S
        signing_key[1] = 0x49; // I
        signing_key[2] = 0x47; // G
        signing_key[3] = 0x4E; // N

        let mut encryption_key = [0u8; 32];
        encryption_key[0] = 0x45; // E
        encryption_key[1] = 0x4E; // N
        encryption_key[2] = 0x43; // C

        Self {
            endpoints,
            policy,
            consent: Arc::new(ConsentGate::new(signing_key)),
            quarantine: Arc::new(QuarantineStorage::new(encryption_key)),
            audit: Arc::new(AuditLog::new()),
            stats: RwLock::new(DecisionStats::default()),
            enabled: RwLock::new(true),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: PolicyConfig) -> Self {
        let endpoints = Arc::new(EndpointDatabase::new());
        let policy = Arc::new(PolicyEngine::with_config(endpoints.clone(), config));

        let mut signing_key = [0u8; 32];
        signing_key[0] = 0x53;

        let mut encryption_key = [0u8; 32];
        encryption_key[0] = 0x45;

        Self {
            endpoints,
            policy,
            consent: Arc::new(ConsentGate::new(signing_key)),
            quarantine: Arc::new(QuarantineStorage::new(encryption_key)),
            audit: Arc::new(AuditLog::new()),
            stats: RwLock::new(DecisionStats::default()),
            enabled: RwLock::new(true),
        }
    }

    /// Create a strict privacy guard
    pub fn strict() -> Self {
        Self::with_config(PolicyConfig::strict())
    }

    /// Enable or disable the guard
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.write() = enabled;
    }

    /// Check if guard is enabled
    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    /// Set privacy level
    pub fn set_privacy_level(&self, level: PrivacyLevel) {
        self.consent.set_privacy_level(level);
        let mut config = self.policy.config();
        config.privacy_level = level.value();
        self.policy.set_config(config);
    }

    /// Get privacy level
    pub fn privacy_level(&self) -> PrivacyLevel {
        self.consent.privacy_level()
    }

    /// Evaluate a flow and return a decision
    pub fn evaluate(&self, flow: &FlowMeta) -> Decision {
        // If disabled, allow everything
        if !self.is_enabled() {
            return Decision::allow(flow, crate::DecisionReason::SystemAllowlist, None);
        }

        // Look up endpoint info
        let endpoint = self.endpoints.lookup(&flow.effective_hostname());
        let vendor = endpoint.as_ref().map(|e| e.vendor.as_str());

        // First check consent gate
        let consent_decision = self.consent.evaluate(flow, vendor);
        if consent_decision.allows_traffic() {
            // Log and return
            self.audit.log(&consent_decision);
            self.stats.write().record(&consent_decision, vendor);
            return consent_decision;
        }

        // Then check policy engine
        let policy_decision = self.policy.evaluate(flow);

        // Log the decision
        self.audit.log(&policy_decision);
        self.stats.write().record(&policy_decision, vendor);

        policy_decision
    }

    /// Evaluate and optionally quarantine
    pub fn evaluate_with_quarantine(
        &self,
        flow: &FlowMeta,
        payload: Option<&[u8]>,
    ) -> Decision {
        let decision = self.evaluate(flow);

        // Quarantine if decision is to quarantine
        if decision.decision_type == DecisionType::Quarantine {
            if let Some(data) = payload {
                let _ = self.quarantine.quarantine(
                    flow,
                    data,
                    QuarantineReason::PolicyRule {
                        rule_id: "policy_quarantine".to_string(),
                    },
                );
            }
        }

        decision
    }

    /// Grant consent for a scope
    pub fn grant_consent(&self, scope: ConsentScope, grantor: [u8; 32]) -> Result<[u8; 32]> {
        self.consent.grant_for_scope(scope, grantor)
    }

    /// Grant custom consent
    pub fn grant_custom_consent(&self, consent: TelemetryConsent) -> Result<[u8; 32]> {
        self.consent.grant(consent)
    }

    /// Revoke consent for a scope
    pub fn revoke_consent(&self, scope: &ConsentScope) -> bool {
        self.consent.revoke(scope)
    }

    /// Revoke all consents
    pub fn revoke_all_consent(&self) {
        self.consent.revoke_all();
    }

    /// Add a custom policy rule
    pub fn add_rule(&self, rule: PolicyRule) {
        self.policy.add_rule(rule);
    }

    /// Remove a policy rule
    pub fn remove_rule(&self, rule_id: &str) -> bool {
        self.policy.remove_rule(rule_id)
    }

    /// Get all rules
    pub fn rules(&self) -> Vec<PolicyRule> {
        self.policy.rules()
    }

    /// Update policy configuration
    pub fn set_policy_config(&self, config: PolicyConfig) {
        self.policy.set_config(config);
    }

    /// Get policy configuration
    pub fn policy_config(&self) -> PolicyConfig {
        self.policy.config()
    }

    /// Get decision statistics
    pub fn stats(&self) -> DecisionStats {
        self.stats.read().clone()
    }

    /// Get quarantine statistics
    pub fn quarantine_stats(&self) -> QuarantineStats {
        self.quarantine.stats()
    }

    /// Get pending quarantine entries
    pub fn pending_quarantine(&self) -> Vec<crate::QuarantinedPayload> {
        self.quarantine.get_pending()
    }

    /// Approve a quarantined entry (creates consent for the domain)
    pub fn approve_quarantine(&self, entry_id: &[u8; 32], grantor: [u8; 32]) -> Result<()> {
        if let Some(entry) = self.quarantine.get(entry_id) {
            // Create consent for this domain
            let scope = ConsentScope::Domain(entry.flow_meta.destination.clone());
            self.consent.grant_for_scope(scope, grantor)?;

            // Mark as approved
            self.quarantine.set_status(entry_id, crate::ReviewStatus::Approved);

            Ok(())
        } else {
            Err(TelemetryGuardError::NoConsent(hex::encode(entry_id)))
        }
    }

    /// Reject a quarantined entry (adds block rule)
    pub fn reject_quarantine(&self, entry_id: &[u8; 32]) -> Result<()> {
        if let Some(entry) = self.quarantine.get(entry_id) {
            // Add block rule
            self.add_rule(PolicyRule {
                id: format!("block-{}", hex::encode(&entry_id[..8])),
                name: format!("Block {}", entry.flow_meta.destination),
                description: "Blocked from quarantine review".to_string(),
                enabled: true,
                priority: 50,
                conditions: vec![crate::RuleCondition::DomainExact(
                    entry.flow_meta.destination.clone(),
                )],
                action: crate::RuleAction::Block,
                ttl: None,
            });

            // Mark as rejected
            self.quarantine.set_status(entry_id, crate::ReviewStatus::Rejected);

            Ok(())
        } else {
            Err(TelemetryGuardError::NoConsent(hex::encode(entry_id)))
        }
    }

    /// Get recent audit entries
    pub fn recent_audit(&self, limit: usize) -> Vec<crate::AuditEntry> {
        self.audit.recent(limit)
    }

    /// Verify audit chain integrity
    pub fn verify_audit(&self) -> bool {
        self.audit.verify_chain()
    }

    /// Get consent count
    pub fn consent_count(&self) -> usize {
        self.consent.consent_count()
    }

    /// Get all active consents
    pub fn active_consents(&self) -> Vec<TelemetryConsent> {
        self.consent.active_consents()
    }

    /// Lookup endpoint info
    pub fn lookup_endpoint(&self, hostname: &str) -> Option<crate::EndpointEntry> {
        self.endpoints.lookup(hostname)
    }

    /// Get endpoints by category
    pub fn endpoints_by_category(
        &self,
        category: crate::EndpointCategory,
    ) -> Vec<crate::EndpointEntry> {
        self.endpoints.get_by_category(category)
    }

    /// Add custom endpoint entry
    pub fn add_endpoint(&self, entry: crate::EndpointEntry) {
        self.endpoints.add_custom_rule(entry);
    }

    /// Cleanup expired consents and old data
    pub fn cleanup(&self) -> CleanupResult {
        let expired_consents = self.consent.cleanup_expired();
        let consumed_tokens = self.consent.cleanup_consumed(chrono::Duration::days(7));

        CleanupResult {
            expired_consents,
            consumed_tokens,
        }
    }

    /// Export all data as JSON (for backup/debugging)
    pub fn export_all(&self) -> String {
        serde_json::json!({
            "stats": self.stats(),
            "quarantine_stats": self.quarantine_stats(),
            "policy_config": self.policy_config(),
            "rules": self.rules(),
            "consents": self.active_consents(),
            "audit_sample": self.recent_audit(100),
        }).to_string()
    }
}

impl Default for TelemetryGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of cleanup operation
#[derive(Debug, Clone)]
pub struct CleanupResult {
    /// Number of expired consents removed
    pub expired_consents: usize,
    /// Number of consumed tokens removed
    pub consumed_tokens: usize,
}

/// Builder for TelemetryGuard
pub struct TelemetryGuardBuilder {
    config: PolicyConfig,
    signing_key: Option<[u8; 32]>,
    encryption_key: Option<[u8; 32]>,
    custom_endpoints: Vec<crate::EndpointEntry>,
    initial_rules: Vec<PolicyRule>,
}

impl TelemetryGuardBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: PolicyConfig::default(),
            signing_key: None,
            encryption_key: None,
            custom_endpoints: Vec::new(),
            initial_rules: Vec::new(),
        }
    }

    /// Set policy configuration
    pub fn config(mut self, config: PolicyConfig) -> Self {
        self.config = config;
        self
    }

    /// Use strict privacy settings
    pub fn strict(mut self) -> Self {
        self.config = PolicyConfig::strict();
        self
    }

    /// Set signing key for consent tokens
    pub fn signing_key(mut self, key: [u8; 32]) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Set encryption key for quarantine
    pub fn encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Add custom endpoint
    pub fn add_endpoint(mut self, entry: crate::EndpointEntry) -> Self {
        self.custom_endpoints.push(entry);
        self
    }

    /// Add initial rule
    pub fn add_rule(mut self, rule: PolicyRule) -> Self {
        self.initial_rules.push(rule);
        self
    }

    /// Build the guard
    pub fn build(self) -> TelemetryGuard {
        let endpoints = Arc::new(EndpointDatabase::new());

        // Add custom endpoints
        for entry in self.custom_endpoints {
            endpoints.add_custom_rule(entry);
        }

        let policy = Arc::new(PolicyEngine::with_config(endpoints.clone(), self.config));

        // Add initial rules
        for rule in self.initial_rules {
            policy.add_rule(rule);
        }

        let signing_key = self.signing_key.unwrap_or_else(|| {
            let mut k = [0u8; 32];
            k[0] = 0x53;
            k
        });

        let encryption_key = self.encryption_key.unwrap_or_else(|| {
            let mut k = [0u8; 32];
            k[0] = 0x45;
            k
        });

        TelemetryGuard {
            endpoints,
            policy,
            consent: Arc::new(ConsentGate::new(signing_key)),
            quarantine: Arc::new(QuarantineStorage::new(encryption_key)),
            audit: Arc::new(AuditLog::new()),
            stats: RwLock::new(DecisionStats::default()),
            enabled: RwLock::new(true),
        }
    }
}

impl Default for TelemetryGuardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared telemetry guard
pub type SharedTelemetryGuard = Arc<TelemetryGuard>;

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

    #[test]
    fn test_guard_creation() {
        let guard = TelemetryGuard::new();
        assert!(guard.is_enabled());
        assert_eq!(guard.consent_count(), 0);
    }

    #[test]
    fn test_block_known_tracker() {
        let guard = TelemetryGuard::new();
        let flow = test_flow("www.google-analytics.com");

        let decision = guard.evaluate(&flow);
        assert_eq!(decision.decision_type, DecisionType::Block);
    }

    #[test]
    fn test_consent_allows() {
        let guard = TelemetryGuard::new();
        let grantor = [1u8; 32];

        // Grant consent
        let scope = ConsentScope::Domain("my-analytics.example.com".to_string());
        guard.grant_consent(scope, grantor).unwrap();

        // Should be allowed
        let flow = test_flow("my-analytics.example.com");
        let decision = guard.evaluate(&flow);
        assert!(decision.allows_traffic());
    }

    #[test]
    fn test_revoke_consent() {
        let guard = TelemetryGuard::new();
        let grantor = [1u8; 32];

        let scope = ConsentScope::Domain("tracker.example.com".to_string());
        guard.grant_consent(scope.clone(), grantor).unwrap();

        // Revoke
        guard.revoke_consent(&scope);

        // Should be blocked now
        let flow = test_flow("tracker.example.com");
        let decision = guard.evaluate(&flow);
        assert!(!decision.allows_traffic());
    }

    #[test]
    fn test_privacy_level_affects_decisions() {
        let guard = TelemetryGuard::new();

        // Set maximum privacy
        guard.set_privacy_level(PrivacyLevel::Maximum);

        // Should block analytics even with consent
        let grantor = [1u8; 32];
        let scope = ConsentScope::Domain("analytics.example.com".to_string());
        guard.grant_consent(scope, grantor).unwrap();

        let mut flow = test_flow("analytics.example.com");
        flow.inferred_intent = crate::TelemetryIntent::UsageAnalytics;

        let decision = guard.evaluate(&flow);
        // Maximum privacy blocks analytics
        assert_eq!(decision.decision_type, DecisionType::Block);
    }

    #[test]
    fn test_audit_logging() {
        let guard = TelemetryGuard::new();

        guard.evaluate(&test_flow("tracker1.com"));
        guard.evaluate(&test_flow("tracker2.com"));
        guard.evaluate(&test_flow("tracker3.com"));

        let audit = guard.recent_audit(10);
        assert_eq!(audit.len(), 3);
        assert!(guard.verify_audit());
    }

    #[test]
    fn test_statistics() {
        let guard = TelemetryGuard::new();

        for i in 0..10 {
            guard.evaluate(&test_flow(&format!("tracker{}.example.com", i)));
        }

        let stats = guard.stats();
        assert_eq!(stats.total, 10);
        assert!(stats.blocked > 0);
    }

    #[test]
    fn test_builder() {
        let guard = TelemetryGuardBuilder::new()
            .strict()
            .add_rule(PolicyRule {
                id: "custom".to_string(),
                name: "Custom Rule".to_string(),
                description: "Test".to_string(),
                enabled: true,
                priority: 100,
                conditions: vec![],
                action: crate::RuleAction::Block,
                ttl: None,
            })
            .build();

        assert_eq!(guard.rules().len(), 1);
    }

    #[test]
    fn test_disabled_guard() {
        let guard = TelemetryGuard::new();
        guard.set_enabled(false);

        let flow = test_flow("evil-tracker.com");
        let decision = guard.evaluate(&flow);

        // Should allow when disabled
        assert!(decision.allows_traffic());
    }
}
