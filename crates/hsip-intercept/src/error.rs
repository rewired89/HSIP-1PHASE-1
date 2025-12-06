//! Error types for the intercept module.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, InterceptError>;

#[derive(Error, Debug)]
pub enum InterceptError {
    #[error("Event monitoring error: {0}")]
    EventMonitor(String),

    #[error("Pattern matching error: {0}")]
    PatternMatch(String),

    #[error("Overlay display error: {0}")]
    Overlay(String),

    #[error("HSIP routing error: {0}")]
    Router(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Permission denied: {0}")]
    Permission(String),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HSIP core error: {0}")]
    HSIPCore(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
