//! Nonce anti-replay logic for HSIP.
//!
//! We enforce:
//!   * monotonic nonces (they must usually increase)
//!   * a 64-packet sliding window for out-of-order UDP
//!   * replay rejection (reject any nonce we've seen before)
//!
//! This is protocol-agnostic: you can use it for any
//! HSIP-encrypted packet stream.

use core::fmt;

/// Errors for nonce validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    /// Nonces must never be zero.
    ZeroNonce,
    /// Nonce is too far behind the highest we've seen, outside the window.
    TooOld,
    /// Nonce was already seen (replay).
    Replay,
}

impl fmt::Display for NonceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NonceError::ZeroNonce => write!(f, "nonce must not be zero"),
            NonceError::TooOld => write!(f, "nonce is too old (outside sliding window)"),
            NonceError::Replay => write!(f, "nonce has already been seen (replay)"),
        }
    }
}

impl std::error::Error for NonceError {}

/// 64-packet sliding window anti-replay.
///
/// We track:
///   * `max_seen`: highest nonce observed so far
///   * `bitmap`: 64-bit window of which nonces in [max_seen-63, max_seen]
///      have been seen (bit 0 = max_seen, bit 1 = max_seen-1, ...)
#[derive(Debug, Clone, Copy)]
pub struct NonceWindow {
    max_seen: u64,
    bitmap: u64,
}

impl NonceWindow {
    /// Create a fresh window with no nonces seen.
    pub const fn new() -> Self {
        NonceWindow {
            max_seen: 0,
            bitmap: 0,
        }
    }

    /// Returns highest nonce seen so far (0 if none).
    pub const fn max_seen(&self) -> u64 {
        self.max_seen
    }

    /// Check a nonce and update the window if it is accepted.
    ///
    /// Rules:
    ///   * nonce == 0            -> error ZeroNonce
    ///   * nonce > max_seen      -> accept, advance window, set bit 0
    ///   * nonce within window   -> accept if not yet seen, else error Replay
    ///   * nonce below window    -> error TooOld
    pub fn check_and_update(&mut self, nonce: u64) -> Result<(), NonceError> {
        if nonce == 0 {
            return Err(NonceError::ZeroNonce);
        }

        // First accepted nonce.
        if self.max_seen == 0 {
            self.max_seen = nonce;
            self.bitmap = 1; // bit 0 = max_seen
            return Ok(());
        }

        if nonce > self.max_seen {
            let diff = nonce - self.max_seen;

            if diff >= 64 {
                // We've jumped far ahead: clear the window entirely.
                self.bitmap = 0;
            } else {
                // Shift left by diff, dropping old bits.
                self.bitmap <<= diff;
            }

            // Mark new highest nonce as seen (bit 0).
            self.bitmap |= 1;
            self.max_seen = nonce;
            return Ok(());
        }

        // nonce <= max_seen
        let diff = self.max_seen - nonce;

        if diff >= 64 {
            // Too far behind; outside the sliding window.
            return Err(NonceError::TooOld);
        }

        let mask = 1u64 << diff;
        if (self.bitmap & mask) != 0 {
            // We've seen this nonce already.
            return Err(NonceError::Replay);
        }

        // Mark this older nonce as seen.
        self.bitmap |= mask;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_strictly_increasing_nonces() {
        let mut w = NonceWindow::new();

        assert!(w.check_and_update(1).is_ok());
        assert_eq!(w.max_seen(), 1);

        assert!(w.check_and_update(2).is_ok());
        assert_eq!(w.max_seen(), 2);

        assert!(w.check_and_update(3).is_ok());
        assert_eq!(w.max_seen(), 3);
    }

    #[test]
    fn allows_small_out_of_order_nonces() {
        let mut w = NonceWindow::new();

        assert!(w.check_and_update(10).is_ok());
        assert!(w.check_and_update(12).is_ok());
        assert!(w.check_and_update(11).is_ok()); // within window, not seen yet
    }

    #[test]
    fn rejects_replays() {
        let mut w = NonceWindow::new();

        assert!(w.check_and_update(5).is_ok());
        assert!(w.check_and_update(6).is_ok());

        let err = w.check_and_update(6).unwrap_err();
        assert_eq!(err, NonceError::Replay);
    }

    #[test]
    fn rejects_too_old_nonces() {
        let mut w = NonceWindow::new();

        // Fill up some range.
        assert!(w.check_and_update(100).is_ok());
        assert!(w.check_and_update(120).is_ok()); // diff 20
        assert!(w.check_and_update(160).is_ok()); // diff 40

        // Now max_seen = 160; window covers [97..160].
        // 96 is just outside and should be TooOld.
        let err = w.check_and_update(96).unwrap_err();
        assert_eq!(err, NonceError::TooOld);
    }

    #[test]
    fn rejects_zero_nonce() {
        let mut w = NonceWindow::new();
        let err = w.check_and_update(0).unwrap_err();
        assert_eq!(err, NonceError::ZeroNonce);
    }
}
