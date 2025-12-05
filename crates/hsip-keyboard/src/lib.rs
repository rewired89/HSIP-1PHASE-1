//! HSIP Secure Keyboard - Rust Backend
//!
//! Provides encryption/decryption for the Android IME via JNI.

pub mod crypto;
pub mod message;
pub mod session;
pub mod jni_bridge;

pub use crypto::{encrypt_message, decrypt_message};
pub use message::{HSIPMessage, MessageFormat};
pub use session::SessionManager;

#[cfg(target_os = "android")]
pub use jni_bridge::*;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, HSIPKeyboardError>;

#[derive(Error, Debug)]
pub enum HSIPKeyboardError {
    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Invalid message format: {0}")]
    InvalidFormat(String),

    #[error("HSIP core error: {0}")]
    HSIPCore(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        // Test encrypt/decrypt cycle
        let plaintext = "Hello, HSIP!";
        // TODO: Implement with real session
        assert!(plaintext.len() > 0);
    }
}
