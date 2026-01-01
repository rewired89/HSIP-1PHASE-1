//! Policy Engine - Rule-based decision making
//!
//! The policy engine evaluates flows against configurable rules to determine
//! whether telemetry should be allowed, blocked, or quarantined.

use crate::{
    Decision, DecisionReason, DecisionType, EndpointDatabase, EndpointEntry,
    FlowMeta, RiskLevel, TelemetryIntent,
};
use chrono::Duration;
use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// A single policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique rule ID
    pub id: String,
    /// Rule name for display
    pub name: String,
    /// Rule description
    pub description: String,
    /// Whether rule is enabled
    pub enabled: bool,
    /// Priority (higher = evaluated first)
    pub priority: i32,
    /// Conditions that must match
    pub conditions: Vec<RuleCondition>,
    /// Action to take if all conditions match
    pub action: RuleAction,
    /// How long the decision is valid
    pub ttl: Option<i64>, // seconds
}

/// A condition for rule matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    /// Match domain pattern (supports wildcards)
    DomainPattern(String),
    /// Match domain suffix
    DomainSuffix(String),
    /// Match exact domain
    DomainExact(String),
    /// Match path pattern (regex)
    PathRegex(String),
    /// Match path prefix
    PathPrefix(String),
    /// Match telemetry intent
    Intent(TelemetryIntent),
    /// Match risk level (>=)
    MinRiskLevel(RiskLevel),
    /// Match specific vendor
    Vendor(String),
    /// Match category
    Category(String),
    /// Match request size (>= bytes)
    MinRequestSize(u64),
    /// Match protocol
    Protocol(String),
    /// Match process name
    ProcessName(String),
    /// Custom regex on hostname
    HostnameRegex(String),
    /// NOT condition
    Not(Box<RuleCondition>),
    /// AND of multiple conditions
    And(Vec<RuleCondition>),
    /// OR of multiple conditions
    Or(Vec<RuleCondition>),
}

impl RuleCondition {
    /// Evaluate the condition against a flow
    pub fn matches(&self, flow: &FlowMeta, endpoint: Option<&EndpointEntry>) -> bool {
        match self {
            RuleCondition::DomainPattern(pattern) => {
                let hostname = flow.effective_hostname().to_lowercase();
                Self::match_wildcard_pattern(pattern, &hostname)
            }
            RuleCondition::DomainSuffix(suffix) => {
                let hostname = flow.effective_hostname().to_lowercase();
                hostname.ends_with(&suffix.to_lowercase())
            }
            RuleCondition::DomainExact(domain) => {
                flow.effective_hostname().to_lowercase() == domain.to_lowercase()
            }
            RuleCondition::PathRegex(pattern) => {
                if let Some(path) = &flow.request_path {
                    if let Ok(re) = Regex::new(pattern) {
                        return re.is_match(path);
                    }
                }
                false
            }
            RuleCondition::PathPrefix(prefix) => {
                flow.request_path
                    .as_ref()
                    .map(|p| p.starts_with(prefix))
                    .unwrap_or(false)
            }
            RuleCondition::Intent(intent) => flow.inferred_intent == *intent,
            RuleCondition::MinRiskLevel(level) => flow.risk_level >= *level,
            RuleCondition::Vendor(vendor) => {
                endpoint.map(|e| e.vendor.to_lowercase() == vendor.to_lowercase()).unwrap_or(false)
            }
            RuleCondition::Category(category) => {
                endpoint.map(|e| format!("{:?}", e.category).to_lowercase() == category.to_lowercase()).unwrap_or(false)
            }
            RuleCondition::MinRequestSize(size) => flow.request_size >= *size,
            RuleCondition::Protocol(proto) => {
                format!("{:?}", flow.protocol).to_lowercase() == proto.to_lowercase()
            }
            RuleCondition::ProcessName(name) => {
                flow.process_name
                    .as_ref()
                    .map(|p| p.to_lowercase().contains(&name.to_lowercase()))
                    .unwrap_or(false)
            }
            RuleCondition::HostnameRegex(pattern) => {
                let hostname = flow.effective_hostname();
                if let Ok(re) = Regex::new(pattern) {
                    return re.is_match(&hostname);
                }
                false
            }
            RuleCondition::Not(cond) => !cond.matches(flow, endpoint),
            RuleCondition::And(conds) => conds.iter().all(|c| c.matches(flow, endpoint)),
            RuleCondition::Or(conds) => conds.iter().any(|c| c.matches(flow, endpoint)),
        }
    }

    /// Match a wildcard pattern (*.example.com)
    fn match_wildcard_pattern(pattern: &str, hostname: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            hostname.ends_with(suffix) || hostname == suffix
        } else if pattern.contains('*') {
            // Convert glob to regex
            let regex_pattern = pattern
                .replace('.', "\\.")
                .replace('*', ".*");
            if let Ok(re) = Regex::new(&format!("^{}$", regex_pattern)) {
                return re.is_match(hostname);
            }
            false
        } else {
            hostname == pattern
        }
    }
}

/// Action to take when rule matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    /// Allow the traffic
    Allow,
    /// Allow once (single request)
    AllowOnce,
    /// Block the traffic
    Block,
    /// Quarantine for analysis
    Quarantine,
    /// Prompt user for decision
    Prompt,
    /// Skip to next rule (continue evaluation)
    Continue,
}

/// Policy engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Default action when no rules match
    pub default_action: RuleAction,
    /// Block all by default (privacy-first mode)
    pub block_by_default: bool,
    /// Automatically block known trackers
    pub auto_block_trackers: bool,
    /// Automatically block advertising
    pub auto_block_ads: bool,
    /// Minimum risk level to auto-block
    pub auto_block_risk_level: RiskLevel,
    /// Allow crash reporting by default
    pub allow_crash_reports: bool,
    /// Privacy level (0-4, integrates with Uncertainty slider)
    pub privacy_level: u8,
    /// Quarantine unknown telemetry for review
    pub quarantine_unknown: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: RuleAction::Block,
            block_by_default: true,
            auto_block_trackers: true,
            auto_block_ads: true,
            auto_block_risk_level: RiskLevel::High,
            allow_crash_reports: true,
            privacy_level: 2, // Balanced
            quarantine_unknown: false,
        }
    }
}

impl PolicyConfig {
    /// Create a strict privacy configuration
    pub fn strict() -> Self {
        Self {
            default_action: RuleAction::Block,
            block_by_default: true,
            auto_block_trackers: true,
            auto_block_ads: true,
            auto_block_risk_level: RiskLevel::Medium,
            allow_crash_reports: false,
            privacy_level: 4, // Maximum
            quarantine_unknown: true,
        }
    }

    /// Create a permissive configuration
    pub fn permissive() -> Self {
        Self {
            default_action: RuleAction::Allow,
            block_by_default: false,
            auto_block_trackers: false,
            auto_block_ads: true,
            auto_block_risk_level: RiskLevel::Critical,
            allow_crash_reports: true,
            privacy_level: 1, // Basic
            quarantine_unknown: false,
        }
    }
}

/// The policy engine
#[derive(Debug)]
pub struct PolicyEngine {
    /// Configuration
    config: RwLock<PolicyConfig>,
    /// Custom rules (user-defined)
    rules: RwLock<Vec<PolicyRule>>,
    /// Known endpoints database
    endpoints: Arc<EndpointDatabase>,
    /// Compiled regex cache
    regex_cache: RwLock<HashMap<String, Regex>>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(endpoints: Arc<EndpointDatabase>) -> Self {
        Self {
            config: RwLock::new(PolicyConfig::default()),
            rules: RwLock::new(Vec::new()),
            endpoints,
            regex_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Create with custom config
    pub fn with_config(endpoints: Arc<EndpointDatabase>, config: PolicyConfig) -> Self {
        Self {
            config: RwLock::new(config),
            rules: RwLock::new(Vec::new()),
            endpoints,
            regex_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Update configuration
    pub fn set_config(&self, config: PolicyConfig) {
        *self.config.write() = config;
    }

    /// Get current configuration
    pub fn config(&self) -> PolicyConfig {
        self.config.read().clone()
    }

    /// Add a custom rule
    pub fn add_rule(&self, rule: PolicyRule) {
        let mut rules = self.rules.write();
        rules.push(rule);
        // Keep sorted by priority (descending)
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Remove a rule by ID
    pub fn remove_rule(&self, rule_id: &str) -> bool {
        let mut rules = self.rules.write();
        let len_before = rules.len();
        rules.retain(|r| r.id != rule_id);
        rules.len() < len_before
    }

    /// Evaluate a flow and return a decision
    pub fn evaluate(&self, flow: &FlowMeta) -> Decision {
        let config = self.config.read();
        let endpoint = self.endpoints.lookup(&flow.effective_hostname());

        // Enrich flow with intent from endpoint database
        let mut enriched_flow = flow.clone();
        if let Some(ref ep) = endpoint {
            enriched_flow.inferred_intent = ep.intent;
            enriched_flow.risk_level = ep.risk_level;
        }

        // 1. Check custom rules first (highest priority)
        if let Some(decision) = self.evaluate_custom_rules(&enriched_flow, endpoint.as_ref()) {
            return decision;
        }

        // 2. Check known endpoints database
        if let Some(ref ep) = endpoint {
            if let Some(decision) = self.evaluate_known_endpoint(&enriched_flow, ep, &config) {
                return decision;
            }
        }

        // 3. Apply automatic rules based on config
        if let Some(decision) = self.evaluate_auto_rules(&enriched_flow, &config) {
            return decision;
        }

        // 4. Apply privacy level rules
        if let Some(decision) = self.evaluate_privacy_level(&enriched_flow, &config) {
            return decision;
        }

        // 5. Default action
        self.apply_default_action(&enriched_flow, &config)
    }

    /// Evaluate custom rules
    fn evaluate_custom_rules(&self, flow: &FlowMeta, endpoint: Option<&EndpointEntry>) -> Option<Decision> {
        let rules = self.rules.read();

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // Check all conditions
            let matches = rule.conditions.iter().all(|c| c.matches(flow, endpoint));

            if matches {
                let ttl = rule.ttl.map(Duration::seconds);

                return Some(match rule.action {
                    RuleAction::Allow => Decision::allow(
                        flow,
                        DecisionReason::PatternMatch { pattern: rule.id.clone() },
                        ttl,
                    ),
                    RuleAction::AllowOnce => Decision::allow_once(
                        flow,
                        DecisionReason::PatternMatch { pattern: rule.id.clone() },
                    ),
                    RuleAction::Block => Decision::block(
                        flow,
                        DecisionReason::BlocklistMatch { rule_id: rule.id.clone() },
                    ),
                    RuleAction::Quarantine => Decision::quarantine(
                        flow,
                        DecisionReason::PatternMatch { pattern: rule.id.clone() },
                    ),
                    RuleAction::Prompt => Decision::pending(flow),
                    RuleAction::Continue => continue, // Skip to next rule
                });
            }
        }

        None
    }

    /// Evaluate known endpoint
    fn evaluate_known_endpoint(
        &self,
        flow: &FlowMeta,
        endpoint: &EndpointEntry,
        config: &PolicyConfig,
    ) -> Option<Decision> {
        // Auto-block advertising
        if config.auto_block_ads && endpoint.intent == TelemetryIntent::Advertising {
            return Some(Decision::block(
                flow,
                DecisionReason::KnownTracker { vendor: endpoint.vendor.clone() },
            ));
        }

        // Auto-block behavior tracking
        if config.auto_block_trackers && endpoint.intent == TelemetryIntent::BehaviorTracking {
            return Some(Decision::block(
                flow,
                DecisionReason::KnownTracker { vendor: endpoint.vendor.clone() },
            ));
        }

        // Allow crash reports if configured
        if config.allow_crash_reports && endpoint.intent == TelemetryIntent::CrashReport {
            return Some(Decision::allow(
                flow,
                DecisionReason::SystemAllowlist,
                Some(Duration::hours(24)),
            ));
        }

        // Block high-risk endpoints
        if endpoint.risk_level >= config.auto_block_risk_level {
            return Some(Decision::block(
                flow,
                DecisionReason::HighRisk { level: endpoint.risk_level },
            ));
        }

        None
    }

    /// Evaluate automatic rules based on config
    fn evaluate_auto_rules(&self, flow: &FlowMeta, config: &PolicyConfig) -> Option<Decision> {
        // Block based on risk level
        if flow.risk_level >= config.auto_block_risk_level {
            return Some(Decision::block(
                flow,
                DecisionReason::HighRisk { level: flow.risk_level },
            ));
        }

        // Detect telemetry by path
        if config.auto_block_trackers && flow.path_suggests_telemetry() {
            return Some(Decision::block(
                flow,
                DecisionReason::PatternMatch {
                    pattern: "telemetry_path_pattern".to_string(),
                },
            ));
        }

        None
    }

    /// Evaluate privacy level rules
    fn evaluate_privacy_level(&self, flow: &FlowMeta, config: &PolicyConfig) -> Option<Decision> {
        let level = config.privacy_level;

        // Level 4 (Maximum): Block all analytics
        if level >= 4 && flow.inferred_intent == TelemetryIntent::UsageAnalytics {
            return Some(Decision::block(
                flow,
                DecisionReason::PrivacyLevelBlock { level },
            ));
        }

        // Level 3 (Enhanced): Block diagnostics too
        if level >= 3 && flow.inferred_intent == TelemetryIntent::Diagnostics {
            return Some(Decision::block(
                flow,
                DecisionReason::PrivacyLevelBlock { level },
            ));
        }

        // Level 2 (Balanced): Block behavior tracking
        if level >= 2 && flow.inferred_intent == TelemetryIntent::BehaviorTracking {
            return Some(Decision::block(
                flow,
                DecisionReason::PrivacyLevelBlock { level },
            ));
        }

        // All levels: Block advertising
        if flow.inferred_intent == TelemetryIntent::Advertising {
            return Some(Decision::block(
                flow,
                DecisionReason::PrivacyLevelBlock { level },
            ));
        }

        None
    }

    /// Apply default action
    fn apply_default_action(&self, flow: &FlowMeta, config: &PolicyConfig) -> Decision {
        // Quarantine unknown if configured
        if config.quarantine_unknown && flow.inferred_intent == TelemetryIntent::Unknown {
            return Decision::quarantine(flow, DecisionReason::UserQuarantine);
        }

        // Apply default action
        match config.default_action {
            RuleAction::Allow => Decision::allow(flow, DecisionReason::NoConsent, None),
            RuleAction::Block => Decision::block(flow, DecisionReason::NoConsent),
            RuleAction::Quarantine => Decision::quarantine(flow, DecisionReason::NoConsent),
            RuleAction::Prompt => Decision::pending(flow),
            _ => Decision::block(flow, DecisionReason::NoConsent),
        }
    }

    /// Get all rules
    pub fn rules(&self) -> Vec<PolicyRule> {
        self.rules.read().clone()
    }

    /// Clear all custom rules
    pub fn clear_rules(&self) {
        self.rules.write().clear();
    }
}

/// Shared policy engine
pub type SharedPolicyEngine = Arc<PolicyEngine>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_flow(hostname: &str, path: &str) -> FlowMeta {
        FlowMeta::from_http(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443)),
            hostname,
            "POST",
            path,
        )
    }

    #[test]
    fn test_policy_engine_creation() {
        let db = Arc::new(EndpointDatabase::new());
        let engine = PolicyEngine::new(db);
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn test_known_tracker_blocking() {
        let db = Arc::new(EndpointDatabase::new());
        let engine = PolicyEngine::new(db);

        let flow = test_flow("analytics.google-analytics.com", "/collect");
        let decision = engine.evaluate(&flow);

        assert_eq!(decision.decision_type, DecisionType::Block);
    }

    #[test]
    fn test_crash_report_allowed() {
        let db = Arc::new(EndpointDatabase::new());
        let engine = PolicyEngine::new(db);

        let flow = test_flow("sentry.io", "/api/123/store/");
        let decision = engine.evaluate(&flow);

        // Sentry is crash reporting, should be allowed by default
        assert_eq!(decision.decision_type, DecisionType::Allow);
    }

    #[test]
    fn test_custom_rule() {
        let db = Arc::new(EndpointDatabase::new());
        let engine = PolicyEngine::new(db);

        engine.add_rule(PolicyRule {
            id: "block-internal".to_string(),
            name: "Block Internal".to_string(),
            description: "Block internal telemetry".to_string(),
            enabled: true,
            priority: 100,
            conditions: vec![RuleCondition::DomainSuffix(".internal.company.com".to_string())],
            action: RuleAction::Block,
            ttl: None,
        });

        let flow = test_flow("telemetry.internal.company.com", "/events");
        let decision = engine.evaluate(&flow);

        assert_eq!(decision.decision_type, DecisionType::Block);
    }

    #[test]
    fn test_privacy_level_blocking() {
        let db = Arc::new(EndpointDatabase::new());
        let config = PolicyConfig {
            privacy_level: 4, // Maximum
            auto_block_trackers: false, // Disable so we test privacy level specifically
            ..Default::default()
        };
        let engine = PolicyEngine::with_config(db, config);

        // Use a path that doesn't match telemetry patterns
        let mut flow = test_flow("analytics.example.com", "/api/data");
        flow.inferred_intent = TelemetryIntent::UsageAnalytics;

        let decision = engine.evaluate(&flow);
        assert_eq!(decision.decision_type, DecisionType::Block);
        assert!(matches!(decision.primary_reason, DecisionReason::PrivacyLevelBlock { .. }));
    }

    #[test]
    fn test_rule_conditions() {
        let flow = test_flow("sub.example.com", "/api/telemetry/v1");

        assert!(RuleCondition::DomainSuffix("example.com".to_string()).matches(&flow, None));
        assert!(RuleCondition::DomainPattern("*.example.com".to_string()).matches(&flow, None));
        assert!(RuleCondition::PathPrefix("/api/".to_string()).matches(&flow, None));
        assert!(RuleCondition::PathRegex("telemetry".to_string()).matches(&flow, None));
        assert!(!RuleCondition::DomainExact("example.com".to_string()).matches(&flow, None));
    }

    #[test]
    fn test_compound_conditions() {
        let flow = test_flow("ads.tracker.com", "/pixel");

        let condition = RuleCondition::And(vec![
            RuleCondition::DomainSuffix("tracker.com".to_string()),
            RuleCondition::PathPrefix("/pixel".to_string()),
        ]);

        assert!(condition.matches(&flow, None));

        let not_condition = RuleCondition::Not(Box::new(RuleCondition::DomainSuffix("safe.com".to_string())));
        assert!(not_condition.matches(&flow, None));
    }

    #[test]
    fn test_rule_priority() {
        let db = Arc::new(EndpointDatabase::new());
        let engine = PolicyEngine::new(db);

        // Lower priority: block
        engine.add_rule(PolicyRule {
            id: "low".to_string(),
            name: "Low Priority".to_string(),
            description: "".to_string(),
            enabled: true,
            priority: 10,
            conditions: vec![RuleCondition::DomainSuffix("example.com".to_string())],
            action: RuleAction::Block,
            ttl: None,
        });

        // Higher priority: allow
        engine.add_rule(PolicyRule {
            id: "high".to_string(),
            name: "High Priority".to_string(),
            description: "".to_string(),
            enabled: true,
            priority: 100,
            conditions: vec![RuleCondition::DomainExact("safe.example.com".to_string())],
            action: RuleAction::Allow,
            ttl: None,
        });

        // This should be allowed (higher priority)
        let flow = test_flow("safe.example.com", "/api");
        let decision = engine.evaluate(&flow);
        assert_eq!(decision.decision_type, DecisionType::Allow);

        // This should be blocked (only matches low priority)
        let flow2 = test_flow("other.example.com", "/api");
        let decision2 = engine.evaluate(&flow2);
        assert_eq!(decision2.decision_type, DecisionType::Block);
    }
}
