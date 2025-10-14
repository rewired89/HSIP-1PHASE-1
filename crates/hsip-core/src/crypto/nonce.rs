//! Nonce utilities for ChaCha20-Poly1305 (96-bit = 12 bytes).
//! Format: [ session_id: u32 (BE) | counter: u64 (BE) ]
//! - Monotonic per session.
//! - Deterministic and collision-resistant for a given (session_id, counter).

#[derive(Clone, Copy, Debug)]
pub struct Nonce([u8; 12]);

impl Nonce {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Construct a Nonce from raw 12-byte array.
    #[inline]
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub fn session_id(&self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    #[inline]
    pub fn counter(&self) -> u64 {
        u64::from_be_bytes([
            self.0[4], self.0[5], self.0[6], self.0[7], self.0[8], self.0[9], self.0[10],
            self.0[11],
        ])
    }
}

/// Simple monotonic nonce generator for a single session.
#[derive(Debug)]
pub struct NonceGen {
    session_id: u32,
    counter: u64,
}

impl NonceGen {
    /// Create with a caller-provided session_id (e.g., random u32).
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            counter: 0,
        }
    }

    /// Return the next unique nonce (increments counter).
    pub fn next_nonce(&mut self) -> Nonce {
        self.counter = self.counter.checked_add(1).expect("nonce counter overflow");
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        out[4..12].copy_from_slice(&self.counter.to_be_bytes());
        Nonce(out)
    }

    /// Peek the next counter value (without increment).
    pub fn next_counter(&self) -> u64 {
        self.counter.saturating_add(1)
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }
}

/// Tracks highest-seen nonce per session and enforces strict monotonicity.
#[derive(Debug, Default)]
pub struct NonceTracker {
    last_session: Option<u32>,
    last_counter: u64,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self {
            last_session: None,
            last_counter: 0,
        }
    }

    /// Accept a nonce if strictly increasing within the same session.
    /// If session_id changes, tracker resets to the new session and accepts
    /// only if the first counter is >= 1.
    pub fn accept(&mut self, nonce: &Nonce) -> Result<(), &'static str> {
        let sid = nonce.session_id();
        let ctr = nonce.counter();

        match self.last_session {
            None => {
                if ctr == 0 {
                    return Err("nonce counter must start at >= 1");
                }
                self.last_session = Some(sid);
                self.last_counter = ctr;
                Ok(())
            }
            Some(prev_sid) if prev_sid == sid => {
                if ctr <= self.last_counter {
                    return Err("nonce not strictly increasing");
                }
                self.last_counter = ctr;
                Ok(())
            }
            Some(_) /* different session */ => {
                if ctr == 0 {
                    return Err("nonce counter must start at >= 1 for new session");
                }
                self.last_session = Some(sid);
                self.last_counter = ctr;
                Ok(())
            }
        }
    }
}
