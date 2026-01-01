//! HSIP Telemetry Guard
//!
//! A consent-driven telemetry blocking and policy engine that prevents
//! unauthorized data exfiltration while respecting user choices.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Application Layer                         │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  HSIP Telemetry Guard                        │
//! │  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
//! │  │ Flow Meta   │→ │ Policy Engine │→ │ Consent Gate       │  │
//! │  │ (who/what)  │  │ (rules)       │  │ (TTL + signatures) │  │
//! │  └─────────────┘  └──────────────┘  └────────────────────┘  │
//! │         │                │                    │              │
//! │         ▼                ▼                    ▼              │
//! │  ┌─────────────────────────────────────────────────────┐    │
//! │  │              Decision Engine                         │    │
//! │  │   ✅ ALLOW  │  🟨 ALLOW_ONCE  │  ❌ BLOCK  │  🧊 QUARANTINE │
//! │  └─────────────────────────────────────────────────────┘    │
//! │                          │                                   │
//! │                          ▼                                   │
//! │  ┌─────────────────────────────────────────────────────┐    │
//! │  │              Audit Trail (Observer Effect)           │    │
//! │  └─────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//!            ┌────────────────────────────────┐
//!            │  Network (if ALLOW/ALLOW_ONCE) │
//!            └────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Consent-Driven**: All telemetry requires explicit user consent
//! - **TTL Enforcement**: Consent automatically expires (uses Quantum Decoherence)
//! - **Anti-Replay**: Consent tokens are single-use where needed (No-Cloning)
//! - **Audit Trail**: All decisions are cryptographically logged (Observer Effect)
//! - **Privacy Levels**: Integrates with Uncertainty Principle slider
//! - **Known Endpoints**: Built-in database of 500+ telemetry domains
//! - **Quarantine Mode**: Capture without sending for security analysis

pub mod flow_meta;
pub mod known_endpoints;
pub mod policy;
pub mod consent_gate;
pub mod decisions;
pub mod quarantine;
pub mod audit;
pub mod guard;

#[cfg(feature = "proxy")]
pub mod proxy;

pub use flow_meta::*;
pub use known_endpoints::*;
pub use policy::*;
pub use consent_gate::*;
pub use decisions::*;
pub use quarantine::*;
pub use audit::*;
pub use guard::*;

use thiserror::Error;

/// Errors from telemetry guard operations
#[derive(Debug, Error)]
pub enum TelemetryGuardError {
    #[error("No consent for telemetry to {0}")]
    NoConsent(String),
    #[error("Consent expired")]
    ConsentExpired,
    #[error("Consent revoked")]
    ConsentRevoked,
    #[error("Invalid consent token")]
    InvalidConsent,
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    #[error("Quarantine full")]
    QuarantineFull,
    #[error("Unknown endpoint category")]
    UnknownCategory,
    #[error("Pattern compilation error: {0}")]
    PatternError(String),
    #[error("IO error: {0}")]
    IoError(String),
}

impl From<std::io::Error> for TelemetryGuardError {
    fn from(e: std::io::Error) -> Self {
        TelemetryGuardError::IoError(e.to_string())
    }
}

/// Result type for telemetry guard operations
pub type Result<T> = std::result::Result<T, TelemetryGuardError>;
