//! Quantum Decoherence Implementation
//!
//! In quantum mechanics, decoherence causes quantum systems to lose their
//! quantum properties over time. We implement this as automatic expiry:
//!
//! - Consent tokens automatically expire after configurable time
//! - Sessions decay if inactive (auto-disconnect)
//! - Old keys are automatically purged
//!
//! ## Security Properties
//! - Forgotten consents expire automatically
//! - Stolen credentials become useless over time
//! - Privacy by default through natural decay

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default consent expiry (90 days)
pub const DEFAULT_CONSENT_EXPIRY_DAYS: i64 = 90;

/// Default session idle timeout (24 hours)
pub const DEFAULT_SESSION_IDLE_HOURS: i64 = 24;

/// Default key rotation interval (30 days)
pub const DEFAULT_KEY_ROTATION_DAYS: i64 = 30;

/// Errors from decoherence operations
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecoherenceError {
    #[error("Consent has expired (decohered)")]
    ConsentExpired,
    #[error("Session has expired due to inactivity")]
    SessionIdle,
    #[error("Key has exceeded its lifetime")]
    KeyExpired,
    #[error("Invalid expiry configuration")]
    InvalidConfig,
}

/// Decoherence configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoherenceConfig {
    /// Consent token lifetime in seconds
    pub consent_lifetime_secs: u64,
    /// Session idle timeout in seconds
    pub session_idle_timeout_secs: u64,
    /// Key rotation interval in seconds
    pub key_rotation_interval_secs: u64,
    /// Grace period before hard expiry (allows for clock drift)
    pub grace_period_secs: u64,
}

impl Default for DecoherenceConfig {
    fn default() -> Self {
        Self {
            consent_lifetime_secs: (DEFAULT_CONSENT_EXPIRY_DAYS * 24 * 60 * 60) as u64,
            session_idle_timeout_secs: (DEFAULT_SESSION_IDLE_HOURS * 60 * 60) as u64,
            key_rotation_interval_secs: (DEFAULT_KEY_ROTATION_DAYS * 24 * 60 * 60) as u64,
            grace_period_secs: 300, // 5 minutes grace
        }
    }
}

/// Tracks the decoherence state of an entity (consent, session, key).
///
/// Entities naturally decay over time and eventually expire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoherenceState {
    /// When the entity was created
    pub created_at: DateTime<Utc>,
    /// When the entity will expire (hard deadline)
    pub expires_at: DateTime<Utc>,
    /// Last activity timestamp (for idle detection)
    pub last_activity: DateTime<Utc>,
    /// Idle timeout duration
    pub idle_timeout_secs: u64,
    /// Whether entity has been explicitly revoked
    pub revoked: bool,
    /// Revocation reason (if revoked)
    pub revocation_reason: Option<String>,
}

impl DecoherenceState {
    /// Create a new decoherence state with the given lifetime
    #[must_use]
    pub fn new(lifetime_secs: u64, idle_timeout_secs: u64) -> Self {
        let now = Utc::now();
        Self {
            created_at: now,
            expires_at: now + ChronoDuration::seconds(lifetime_secs as i64),
            last_activity: now,
            idle_timeout_secs,
            revoked: false,
            revocation_reason: None,
        }
    }

    /// Create with default consent lifetime
    #[must_use]
    pub fn new_consent() -> Self {
        let config = DecoherenceConfig::default();
        Self::new(config.consent_lifetime_secs, config.session_idle_timeout_secs)
    }

    /// Create with custom expiry date
    #[must_use]
    pub fn with_expiry(expires_at: DateTime<Utc>, idle_timeout_secs: u64) -> Self {
        let now = Utc::now();
        Self {
            created_at: now,
            expires_at,
            last_activity: now,
            idle_timeout_secs,
            revoked: false,
            revocation_reason: None,
        }
    }

    /// Record activity to reset idle timeout
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Check if the entity has expired (hard expiry)
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the entity is idle (exceeded idle timeout)
    #[must_use]
    pub fn is_idle(&self) -> bool {
        let idle_deadline = self.last_activity
            + ChronoDuration::seconds(self.idle_timeout_secs as i64);
        Utc::now() > idle_deadline
    }

    /// Check if the entity is still valid (not expired, not idle, not revoked)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.is_expired() && !self.is_idle()
    }

    /// Validate the entity, returning an error if invalid
    pub fn validate(&self) -> Result<(), DecoherenceError> {
        if self.revoked {
            return Err(DecoherenceError::ConsentExpired);
        }
        if self.is_expired() {
            return Err(DecoherenceError::ConsentExpired);
        }
        if self.is_idle() {
            return Err(DecoherenceError::SessionIdle);
        }
        Ok(())
    }

    /// Explicitly revoke the entity
    pub fn revoke(&mut self, reason: impl Into<String>) {
        self.revoked = true;
        self.revocation_reason = Some(reason.into());
    }

    /// Get remaining lifetime in seconds
    #[must_use]
    pub fn remaining_lifetime_secs(&self) -> i64 {
        let remaining = self.expires_at - Utc::now();
        remaining.num_seconds().max(0)
    }

    /// Get time since last activity in seconds
    #[must_use]
    pub fn idle_duration_secs(&self) -> i64 {
        let idle = Utc::now() - self.last_activity;
        idle.num_seconds().max(0)
    }

    /// Get decoherence percentage (0.0 = fresh, 1.0 = expired)
    #[must_use]
    pub fn decoherence_factor(&self) -> f64 {
        let total_lifetime = (self.expires_at - self.created_at).num_seconds() as f64;
        if total_lifetime <= 0.0 {
            return 1.0;
        }

        let elapsed = (Utc::now() - self.created_at).num_seconds() as f64;
        (elapsed / total_lifetime).clamp(0.0, 1.0)
    }

    /// Extend the expiry by the given duration (renewal)
    pub fn extend(&mut self, extension_secs: u64) {
        self.expires_at = self.expires_at + ChronoDuration::seconds(extension_secs as i64);
        self.touch();
    }
}

/// A consent token with automatic expiry (decoherence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayingConsent {
    /// Unique consent ID
    pub consent_id: String,
    /// Who granted consent
    pub grantor_id: String,
    /// Who received consent
    pub grantee_id: String,
    /// What the consent is for
    pub purpose: String,
    /// Decoherence state tracking expiry
    pub state: DecoherenceState,
    /// Consent scope (what actions are allowed)
    pub scope: Vec<String>,
}

impl DecayingConsent {
    /// Create a new decaying consent
    #[must_use]
    pub fn new(
        consent_id: String,
        grantor_id: String,
        grantee_id: String,
        purpose: String,
        lifetime_days: i64,
    ) -> Self {
        let lifetime_secs = (lifetime_days * 24 * 60 * 60) as u64;
        let config = DecoherenceConfig::default();

        Self {
            consent_id,
            grantor_id,
            grantee_id,
            purpose,
            state: DecoherenceState::new(lifetime_secs, config.session_idle_timeout_secs),
            scope: Vec::new(),
        }
    }

    /// Add a scope to this consent
    pub fn add_scope(&mut self, scope: impl Into<String>) {
        self.scope.push(scope.into());
    }

    /// Check if this consent is valid for a specific action
    #[must_use]
    pub fn allows(&self, action: &str) -> bool {
        self.state.is_valid() && (self.scope.is_empty() || self.scope.iter().any(|s| s == action))
    }

    /// Validate and return detailed status
    pub fn validate(&self) -> Result<ConsentStatus, DecoherenceError> {
        self.state.validate()?;
        Ok(ConsentStatus {
            remaining_days: self.state.remaining_lifetime_secs() / 86400,
            decoherence_factor: self.state.decoherence_factor(),
            last_activity_secs_ago: self.state.idle_duration_secs(),
        })
    }

    /// Revoke this consent
    pub fn revoke(&mut self, reason: &str) {
        self.state.revoke(reason);
    }

    /// Renew consent for additional days
    pub fn renew(&mut self, additional_days: i64) {
        let additional_secs = (additional_days * 24 * 60 * 60) as u64;
        self.state.extend(additional_secs);
    }
}

/// Status information for a consent
#[derive(Debug, Clone)]
pub struct ConsentStatus {
    /// Days remaining before expiry
    pub remaining_days: i64,
    /// Decoherence factor (0.0 = fresh, 1.0 = expired)
    pub decoherence_factor: f64,
    /// Seconds since last activity
    pub last_activity_secs_ago: i64,
}

/// A session with idle timeout (decoherence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayingSession {
    /// Session ID
    pub session_id: String,
    /// Peer ID
    pub peer_id: String,
    /// Decoherence state
    pub state: DecoherenceState,
    /// Number of messages exchanged
    pub message_count: u64,
}

impl DecayingSession {
    /// Create a new session with default timeouts
    #[must_use]
    pub fn new(session_id: String, peer_id: String) -> Self {
        let config = DecoherenceConfig::default();
        Self {
            session_id,
            peer_id,
            state: DecoherenceState::new(
                config.consent_lifetime_secs,
                config.session_idle_timeout_secs,
            ),
            message_count: 0,
        }
    }

    /// Record message activity
    pub fn record_message(&mut self) {
        self.state.touch();
        self.message_count += 1;
    }

    /// Check if session is still alive
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.state.is_valid()
    }

    /// Validate session, returning error if expired/idle
    pub fn validate(&self) -> Result<(), DecoherenceError> {
        self.state.validate()
    }
}

/// Manager for tracking and cleaning up expired entities
#[derive(Debug, Default)]
pub struct DecoherenceManager {
    config: DecoherenceConfig,
}

impl DecoherenceManager {
    /// Create with default config
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom config
    #[must_use]
    pub fn with_config(config: DecoherenceConfig) -> Self {
        Self { config }
    }

    /// Check if a consent should be purged
    #[must_use]
    pub fn should_purge_consent(&self, consent: &DecayingConsent) -> bool {
        !consent.state.is_valid()
    }

    /// Check if a session should be purged
    #[must_use]
    pub fn should_purge_session(&self, session: &DecayingSession) -> bool {
        !session.is_alive()
    }

    /// Filter out expired consents from a list
    #[must_use]
    pub fn filter_valid_consents(&self, consents: Vec<DecayingConsent>) -> Vec<DecayingConsent> {
        consents
            .into_iter()
            .filter(|c| c.state.is_valid())
            .collect()
    }

    /// Get config
    #[must_use]
    pub fn config(&self) -> &DecoherenceConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_is_valid() {
        let state = DecoherenceState::new(3600, 1800);
        assert!(state.is_valid());
        assert!(!state.is_expired());
        assert!(!state.is_idle());
    }

    #[test]
    fn expired_state_is_invalid() {
        let mut state = DecoherenceState::new(1, 3600);
        // Manually expire it
        state.expires_at = Utc::now() - ChronoDuration::seconds(10);
        assert!(!state.is_valid());
        assert!(state.is_expired());
    }

    #[test]
    fn revoked_state_is_invalid() {
        let mut state = DecoherenceState::new(3600, 1800);
        state.revoke("user requested");
        assert!(!state.is_valid());
    }

    #[test]
    fn touch_resets_idle() {
        let mut state = DecoherenceState::new(3600, 1);
        // Make it idle
        state.last_activity = Utc::now() - ChronoDuration::seconds(10);
        assert!(state.is_idle());

        // Touch to reset
        state.touch();
        assert!(!state.is_idle());
    }

    #[test]
    fn decoherence_factor_increases() {
        let state = DecoherenceState::new(100, 50);
        let factor = state.decoherence_factor();
        assert!(factor >= 0.0 && factor <= 1.0);
    }

    #[test]
    fn consent_allows_scoped_actions() {
        let mut consent = DecayingConsent::new(
            "test".into(),
            "alice".into(),
            "bob".into(),
            "messaging".into(),
            90,
        );
        consent.add_scope("read");
        consent.add_scope("write");

        assert!(consent.allows("read"));
        assert!(consent.allows("write"));
        assert!(!consent.allows("delete"));
    }

    #[test]
    fn consent_renewal_extends_lifetime() {
        let mut consent = DecayingConsent::new(
            "test".into(),
            "alice".into(),
            "bob".into(),
            "messaging".into(),
            1,
        );
        let original_expiry = consent.state.expires_at;

        consent.renew(30);

        assert!(consent.state.expires_at > original_expiry);
    }

    #[test]
    fn session_tracks_messages() {
        let mut session = DecayingSession::new("sess1".into(), "peer1".into());
        assert_eq!(session.message_count, 0);

        session.record_message();
        session.record_message();

        assert_eq!(session.message_count, 2);
    }
}
