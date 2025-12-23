//! Decision Types - Outcomes of telemetry policy evaluation
//!
//! Defines the possible decisions and their associated metadata.

use crate::{FlowMeta, TelemetryIntent, RiskLevel};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};

/// The decision outcome for a telemetry flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecisionType {
    /// Allow the flow (explicit consent exists)
    Allow,
    /// Allow once (single request/session only)
    AllowOnce,
    /// Block the flow (no consent or policy violation)
    Block,
    /// Quarantine (capture for analysis, don't send)
    Quarantine,
    /// Pending user decision (prompt required)
    Pending,
}

impl DecisionType {
    /// Returns whether this decision allows the traffic
    pub fn allows_traffic(&self) -> bool {
        matches!(self, DecisionType::Allow | DecisionType::AllowOnce)
    }

    /// Returns emoji for display
    pub fn emoji(&self) -> &'static str {
        match self {
            DecisionType::Allow => "✅",
            DecisionType::AllowOnce => "🟨",
            DecisionType::Block => "❌",
            DecisionType::Quarantine => "🧊",
            DecisionType::Pending => "⏳",
        }
    }

    /// Returns human-readable action
    pub fn action_text(&self) -> &'static str {
        match self {
            DecisionType::Allow => "ALLOW",
            DecisionType::AllowOnce => "ALLOW ONCE",
            DecisionType::Block => "BLOCK",
            DecisionType::Quarantine => "QUARANTINE",
            DecisionType::Pending => "PENDING",
        }
    }
}

/// Reason for the decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionReason {
    /// User explicitly granted consent
    UserConsent { consent_id: [u8; 32] },
    /// User explicitly denied consent
    UserDenied,
    /// Consent has expired
    ConsentExpired,
    /// Consent was revoked
    ConsentRevoked,
    /// Matched a blocklist rule
    BlocklistMatch { rule_id: String },
    /// No consent exists (default block)
    NoConsent,
    /// High risk level (auto-block)
    HighRisk { level: RiskLevel },
    /// Known invasive tracker
    KnownTracker { vendor: String },
    /// Privacy level setting blocks this
    PrivacyLevelBlock { level: u8 },
    /// User requested quarantine for analysis
    UserQuarantine,
    /// Awaiting user input
    AwaitingInput,
    /// System allowlist (e.g., crash reporting)
    SystemAllowlist,
    /// Pattern match (path, domain, etc.)
    PatternMatch { pattern: String },
}

impl DecisionReason {
    /// Get a human-readable description
    pub fn description(&self) -> String {
        match self {
            DecisionReason::UserConsent { .. } => "User granted consent".to_string(),
            DecisionReason::UserDenied => "User denied consent".to_string(),
            DecisionReason::ConsentExpired => "Consent has expired".to_string(),
            DecisionReason::ConsentRevoked => "Consent was revoked".to_string(),
            DecisionReason::BlocklistMatch { rule_id } => {
                format!("Matched blocklist rule: {}", rule_id)
            }
            DecisionReason::NoConsent => "No consent exists (blocked by default)".to_string(),
            DecisionReason::HighRisk { level } => {
                format!("High risk level: {:?}", level)
            }
            DecisionReason::KnownTracker { vendor } => {
                format!("Known tracker: {}", vendor)
            }
            DecisionReason::PrivacyLevelBlock { level } => {
                format!("Privacy level {} blocks this telemetry", level)
            }
            DecisionReason::UserQuarantine => "User requested quarantine for analysis".to_string(),
            DecisionReason::AwaitingInput => "Awaiting user decision".to_string(),
            DecisionReason::SystemAllowlist => "Allowed by system policy".to_string(),
            DecisionReason::PatternMatch { pattern } => {
                format!("Matched pattern: {}", pattern)
            }
        }
    }
}

/// Complete decision for a flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// The decision type
    pub decision_type: DecisionType,
    /// Primary reason for the decision
    pub primary_reason: DecisionReason,
    /// Additional contributing reasons
    pub contributing_reasons: Vec<DecisionReason>,
    /// When the decision was made
    pub timestamp: DateTime<Utc>,
    /// How long this decision is valid (for caching)
    pub ttl: Option<Duration>,
    /// Flow metadata (for audit)
    pub flow_summary: DecisionFlowSummary,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
}

/// Simplified flow summary for decision records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionFlowSummary {
    /// Flow ID prefix (first 8 bytes)
    pub flow_id_prefix: String,
    /// Destination
    pub destination: String,
    /// Inferred intent
    pub intent: TelemetryIntent,
    /// Risk level
    pub risk_level: RiskLevel,
}

impl Decision {
    /// Create a new ALLOW decision
    pub fn allow(flow: &FlowMeta, reason: DecisionReason, ttl: Option<Duration>) -> Self {
        Self {
            decision_type: DecisionType::Allow,
            primary_reason: reason,
            contributing_reasons: Vec::new(),
            timestamp: Utc::now(),
            ttl,
            flow_summary: Self::summarize_flow(flow),
            confidence: 1.0,
        }
    }

    /// Create a new ALLOW_ONCE decision
    pub fn allow_once(flow: &FlowMeta, reason: DecisionReason) -> Self {
        Self {
            decision_type: DecisionType::AllowOnce,
            primary_reason: reason,
            contributing_reasons: Vec::new(),
            timestamp: Utc::now(),
            ttl: Some(Duration::seconds(60)), // Very short TTL
            flow_summary: Self::summarize_flow(flow),
            confidence: 1.0,
        }
    }

    /// Create a new BLOCK decision
    pub fn block(flow: &FlowMeta, reason: DecisionReason) -> Self {
        Self {
            decision_type: DecisionType::Block,
            primary_reason: reason,
            contributing_reasons: Vec::new(),
            timestamp: Utc::now(),
            ttl: None,
            flow_summary: Self::summarize_flow(flow),
            confidence: 1.0,
        }
    }

    /// Create a new QUARANTINE decision
    pub fn quarantine(flow: &FlowMeta, reason: DecisionReason) -> Self {
        Self {
            decision_type: DecisionType::Quarantine,
            primary_reason: reason,
            contributing_reasons: Vec::new(),
            timestamp: Utc::now(),
            ttl: None,
            flow_summary: Self::summarize_flow(flow),
            confidence: 1.0,
        }
    }

    /// Create a PENDING decision
    pub fn pending(flow: &FlowMeta) -> Self {
        Self {
            decision_type: DecisionType::Pending,
            primary_reason: DecisionReason::AwaitingInput,
            contributing_reasons: Vec::new(),
            timestamp: Utc::now(),
            ttl: Some(Duration::seconds(30)), // Prompt timeout
            flow_summary: Self::summarize_flow(flow),
            confidence: 0.0,
        }
    }

    /// Add a contributing reason
    pub fn with_reason(mut self, reason: DecisionReason) -> Self {
        self.contributing_reasons.push(reason);
        self
    }

    /// Set confidence level
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Check if decision is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        if let Some(ttl) = self.ttl {
            Utc::now() < self.timestamp + ttl
        } else {
            true
        }
    }

    /// Check if traffic should be allowed
    pub fn allows_traffic(&self) -> bool {
        self.is_valid() && self.decision_type.allows_traffic()
    }

    /// Summarize flow for decision record
    fn summarize_flow(flow: &FlowMeta) -> DecisionFlowSummary {
        DecisionFlowSummary {
            flow_id_prefix: hex::encode(&flow.flow_id[..8]),
            destination: flow.effective_hostname(),
            intent: flow.inferred_intent,
            risk_level: flow.risk_level,
        }
    }

    /// Format for display
    pub fn display(&self) -> String {
        format!(
            "{} {} → {} ({})",
            self.decision_type.emoji(),
            self.decision_type.action_text(),
            self.flow_summary.destination,
            self.primary_reason.description()
        )
    }
}

/// Statistics about decisions
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DecisionStats {
    /// Total decisions made
    pub total: u64,
    /// Allowed
    pub allowed: u64,
    /// Allowed once
    pub allowed_once: u64,
    /// Blocked
    pub blocked: u64,
    /// Quarantined
    pub quarantined: u64,
    /// Pending
    pub pending: u64,
    /// Breakdown by intent
    pub by_intent: std::collections::HashMap<String, u64>,
    /// Breakdown by vendor (top blockers)
    pub by_vendor: std::collections::HashMap<String, u64>,
}

impl DecisionStats {
    /// Record a new decision
    pub fn record(&mut self, decision: &Decision, vendor: Option<&str>) {
        self.total += 1;

        match decision.decision_type {
            DecisionType::Allow => self.allowed += 1,
            DecisionType::AllowOnce => self.allowed_once += 1,
            DecisionType::Block => self.blocked += 1,
            DecisionType::Quarantine => self.quarantined += 1,
            DecisionType::Pending => self.pending += 1,
        }

        // Track by intent
        let intent_key = format!("{:?}", decision.flow_summary.intent);
        *self.by_intent.entry(intent_key).or_insert(0) += 1;

        // Track by vendor if available
        if let Some(v) = vendor {
            *self.by_vendor.entry(v.to_string()).or_insert(0) += 1;
        }
    }

    /// Get block rate percentage
    pub fn block_rate(&self) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            (self.blocked as f32 / self.total as f32) * 100.0
        }
    }

    /// Get top blocked vendors
    pub fn top_blocked_vendors(&self, limit: usize) -> Vec<(String, u64)> {
        let mut vendors: Vec<_> = self.by_vendor.iter().map(|(k, v)| (k.clone(), *v)).collect();
        vendors.sort_by(|a, b| b.1.cmp(&a.1));
        vendors.truncate(limit);
        vendors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_flow() -> FlowMeta {
        FlowMeta::from_http(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443)),
            "analytics.example.com",
            "POST",
            "/collect",
        )
    }

    #[test]
    fn test_decision_creation() {
        let flow = test_flow();

        let allow = Decision::allow(&flow, DecisionReason::UserConsent { consent_id: [0u8; 32] }, None);
        assert!(allow.allows_traffic());
        assert_eq!(allow.decision_type, DecisionType::Allow);

        let block = Decision::block(&flow, DecisionReason::NoConsent);
        assert!(!block.allows_traffic());
    }

    #[test]
    fn test_decision_expiry() {
        let flow = test_flow();

        let short_ttl = Decision::allow(
            &flow,
            DecisionReason::UserConsent { consent_id: [0u8; 32] },
            Some(Duration::seconds(-1)), // Already expired
        );
        assert!(!short_ttl.is_valid());
        assert!(!short_ttl.allows_traffic());
    }

    #[test]
    fn test_decision_stats() {
        let flow = test_flow();
        let mut stats = DecisionStats::default();

        let allow = Decision::allow(&flow, DecisionReason::UserConsent { consent_id: [0u8; 32] }, None);
        let block = Decision::block(&flow, DecisionReason::NoConsent);

        stats.record(&allow, Some("Google"));
        stats.record(&block, Some("Facebook"));
        stats.record(&block, Some("Facebook"));

        assert_eq!(stats.total, 3);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.blocked, 2);
        assert!(stats.block_rate() > 60.0);

        let top = stats.top_blocked_vendors(5);
        assert_eq!(top[0].0, "Facebook");
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_decision_display() {
        let flow = test_flow();
        let block = Decision::block(&flow, DecisionReason::KnownTracker { vendor: "Google".to_string() });

        let display = block.display();
        assert!(display.contains("BLOCK"));
        assert!(display.contains("Google"));
    }
}
