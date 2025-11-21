//! HSIP unified error codes.
//!
//! These are small numeric codes you can put on the wire,
//! in logs, or in CLI messages to explain *why* something failed.

use core::fmt;

use crate::hello::HelloError;
use crate::nonce::NonceError;
use crate::session::SessionError;

/// Stable numeric error codes for HSIP.
///
/// Layout idea:
///   1xxx = handshake / HELLO
///   2xxx = nonce / replay
///   3xxx = session crypto
///   9xxx = generic internal
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsipErrorCode {
    // 1xxx: HELLO / handshake
    ProtocolVersionUnsupported = 1001,
    HelloBadSignature = 1002,
    HelloTimestampSkew = 1003,
    HelloNoCommonCapabilities = 1004,

    // 2xxx: Nonce / replay
    NonceZero = 2001,
    NonceTooOld = 2002,
    NonceReplay = 2003,

    // 3xxx: Session / crypto
    SessionDecryptFailed = 3001,
    SessionPacketTooLarge = 3002,
    SessionNonceMismatch = 3003,
    SessionCryptoFailure = 3004,
    SessionNonceExhausted = 3005,
    SessionRekeyRequired = 3006,

    // 9xxx: generic
    Internal = 9000,
}

impl HsipErrorCode {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Short human-readable description.
    pub fn description(self) -> &'static str {
        match self {
            // 1xxx
            HsipErrorCode::ProtocolVersionUnsupported => "unsupported HSIP protocol version",
            HsipErrorCode::HelloBadSignature => "HELLO signature verification failed",
            HsipErrorCode::HelloTimestampSkew => "HELLO timestamp outside allowed clock skew",
            HsipErrorCode::HelloNoCommonCapabilities => "no common capabilities between peers",

            // 2xxx
            HsipErrorCode::NonceZero => "nonce must not be zero",
            HsipErrorCode::NonceTooOld => "nonce too old (outside sliding window)",
            HsipErrorCode::NonceReplay => "nonce already seen (replay)",

            // 3xxx
            HsipErrorCode::SessionDecryptFailed => "failed to decrypt HSIP packet",
            HsipErrorCode::SessionPacketTooLarge => "HSIP packet too large",
            HsipErrorCode::SessionNonceMismatch => "nonce mismatch in session packet",
            HsipErrorCode::SessionCryptoFailure => "session cryptographic failure",
            HsipErrorCode::SessionNonceExhausted => "session nonce exhausted (rekey required)",
            HsipErrorCode::SessionRekeyRequired => "session key lifetime exceeded (rekey required)",

            // 9xxx
            HsipErrorCode::Internal => "internal HSIP error",
        }
    }
}

impl fmt::Display for HsipErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.as_u16(), self.description())
    }
}

impl std::error::Error for HsipErrorCode {}

/// Map HELLO-level errors to numeric codes.
impl From<HelloError> for HsipErrorCode {
    fn from(e: HelloError) -> Self {
        match e {
            HelloError::UnsupportedVersion(_) => HsipErrorCode::ProtocolVersionUnsupported,
            HelloError::BadSignature => HsipErrorCode::HelloBadSignature,
            HelloError::NoCommonCapabilities => HsipErrorCode::HelloNoCommonCapabilities,
            HelloError::BadTimestamp => HsipErrorCode::HelloTimestampSkew,
        }
    }
}

/// Map nonce / replay errors to numeric codes.
impl From<NonceError> for HsipErrorCode {
    fn from(e: NonceError) -> Self {
        match e {
            NonceError::ZeroNonce => HsipErrorCode::NonceZero,
            NonceError::TooOld => HsipErrorCode::NonceTooOld,
            NonceError::Replay => HsipErrorCode::NonceReplay,
        }
    }
}

/// Map session errors to numeric codes.
impl From<SessionError> for HsipErrorCode {
    fn from(se: SessionError) -> Self {
        match se {
            SessionError::NonceMismatch { .. } => HsipErrorCode::SessionNonceMismatch,
            SessionError::Crypto(_) => HsipErrorCode::SessionCryptoFailure,
            SessionError::NonceExhausted => HsipErrorCode::SessionNonceExhausted,
            SessionError::RekeyRequired => HsipErrorCode::SessionRekeyRequired,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::HelloError;
    use crate::nonce::NonceError;
    use crate::session::SessionError;

    #[test]
    fn hello_error_maps_to_codes() {
        let c = HsipErrorCode::from(HelloError::BadSignature);
        assert_eq!(c, HsipErrorCode::HelloBadSignature);
        assert_eq!(c.as_u16(), 1002);
    }

    #[test]
    fn nonce_error_maps_to_codes() {
        let c = HsipErrorCode::from(NonceError::Replay);
        assert_eq!(c, HsipErrorCode::NonceReplay);
        assert_eq!(c.as_u16(), 2003);
    }

    #[test]
    fn session_error_maps_new_codes() {
        assert_eq!(
            HsipErrorCode::from(SessionError::NonceMismatch {
                expected: 1,
                got: 2
            }),
            HsipErrorCode::SessionNonceMismatch
        );

        assert_eq!(
            HsipErrorCode::from(SessionError::Crypto("x")),
            HsipErrorCode::SessionCryptoFailure
        );

        assert_eq!(
            HsipErrorCode::from(SessionError::NonceExhausted),
            HsipErrorCode::SessionNonceExhausted
        );

        assert_eq!(
            HsipErrorCode::from(SessionError::RekeyRequired),
            HsipErrorCode::SessionRekeyRequired
        );
    }
}
