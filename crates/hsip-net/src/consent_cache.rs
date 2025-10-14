use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct ConsentCache {
    allow_until: HashMap<String, Instant>,
    ttl: Duration,
}

impl ConsentCache {
    /// ttl_ms: cache lifetime for an "allow" (e.g., 300_000 ms = 5m)
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            allow_until: HashMap::new(),
            ttl: Duration::from_millis(ttl_ms),
        }
    }

    /// If requester is cached and not expired, return true.
    pub fn is_allowed(&mut self, requester: &str) -> bool {
        if requester.is_empty() {
            return false;
        }
        let now = Instant::now();
        if let Some(exp) = self.allow_until.get(requester).cloned() {
            if now < exp {
                return true;
            }
            self.allow_until.remove(requester);
        }
        false
    }

    /// Insert/refresh an allow entry.
    pub fn insert_allow(&mut self, requester: &str) {
        if requester.is_empty() {
            return;
        }
        let exp = Instant::now() + self.ttl;
        self.allow_until.insert(requester.to_string(), exp);
    }

    /// Remove an entry (e.g., after tamper).
    pub fn revoke(&mut self, requester: &str) {
        if requester.is_empty() {
            return;
        }
        self.allow_until.remove(requester);
    }
}
