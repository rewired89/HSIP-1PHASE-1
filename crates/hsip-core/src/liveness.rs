//! HSIP liveness / keepalive helpers.
//!
//! This does NOT send packets itself.
//! It just tells you:
//!   - "time to send a ping"
//!   - "this session is dead, kill it"
//!
//!     Your UDP layer / hsip-net decides how to encode PING/PONG frames.

use core::fmt;

/// Configuration for keepalive and timeouts.
#[derive(Debug, Clone, Copy)]
pub struct KeepaliveConfig {
    /// How long (ms) without ANY traffic before we start pinging.
    pub idle_after_ms: u64,

    /// How often (ms) to send a ping once idle.
    pub ping_interval_ms: u64,

    /// How many unanswered pings before considering the session dead.
    pub max_missed_pings: u32,

    /// Hard upper bound (ms) with absolutely no traffic before forced death.
    pub hard_timeout_ms: u64,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        KeepaliveConfig {
            idle_after_ms: 15_000,   // 15s of silence -> start pinging
            ping_interval_ms: 5_000, // ping every 5s while idle
            max_missed_pings: 3,     // 3 unanswered pings -> dead
            hard_timeout_ms: 60_000, // 60s total silence -> dead no matter what
        }
    }
}

/// Liveness state for one session.
#[derive(Debug, Clone, Copy)]
pub struct KeepaliveState {
    /// Last time (ms) we received ANY packet (data or pong).
    pub last_rx_ms: u64,
    /// Last time (ms) we sent ANY packet (data or ping).
    pub last_tx_ms: u64,
    /// Last time (ms) we sent a ping (0 if never).
    pub last_ping_ms: u64,
    /// Number of consecutive pings with no response.
    pub missed_pings: u32,
}

impl KeepaliveState {
    /// Create a new state with the initial timestamp "now".
    pub fn new(now_ms: u64) -> Self {
        KeepaliveState {
            last_rx_ms: now_ms,
            last_tx_ms: now_ms,
            last_ping_ms: 0,
            missed_pings: 0,
        }
    }

    /// Record that we sent a normal data packet.
    pub fn on_data_sent(&mut self, now_ms: u64) {
        self.last_tx_ms = now_ms;
    }

    /// Record that we received a normal data packet.
    pub fn on_data_received(&mut self, now_ms: u64) {
        self.last_rx_ms = now_ms;
        // Any incoming traffic resets missed pings.
        self.missed_pings = 0;
    }

    /// Record that we sent a PING.
    pub fn on_ping_sent(&mut self, now_ms: u64) {
        self.last_tx_ms = now_ms;
        self.last_ping_ms = now_ms;
        self.missed_pings = self.missed_pings.saturating_add(1);
    }

    /// Record that we received a PONG (or any explicit response to our ping).
    pub fn on_pong_received(&mut self, now_ms: u64) {
        self.last_rx_ms = now_ms;
        self.missed_pings = 0;
    }

    /// Check if we should send a ping now.
    ///
    /// Returns true if:
    ///   * we've been idle (no RX) for at least idle_after_ms, AND
    ///   * either we've never pinged, or it's been at least ping_interval_ms
    ///     since the last ping.
    pub fn should_send_ping(&self, cfg: &KeepaliveConfig, now_ms: u64) -> bool {
        let idle_for = now_ms.saturating_sub(self.last_rx_ms);

        if idle_for < cfg.idle_after_ms {
            return false;
        }

        if self.last_ping_ms == 0 {
            return true;
        }

        let since_last_ping = now_ms.saturating_sub(self.last_ping_ms);
        since_last_ping >= cfg.ping_interval_ms
    }

    /// Check if this session should be considered dead.
    ///
    /// A session is dead if:
    ///   * missed_pings >= max_missed_pings, OR
    ///   * no RX traffic for >= hard_timeout_ms
    pub fn is_dead(&self, cfg: &KeepaliveConfig, now_ms: u64) -> bool {
        if self.missed_pings >= cfg.max_missed_pings {
            return true;
        }

        let idle_for = now_ms.saturating_sub(self.last_rx_ms);
        idle_for >= cfg.hard_timeout_ms
    }
}

/// Simple debuggable wrapper for liveness decisions.
#[derive(Debug, Clone)]
pub struct LivenessStatus {
    pub should_ping: bool,
    pub is_dead: bool,
}

impl fmt::Display for LivenessStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LivenessStatus {{ should_ping: {}, is_dead: {} }}",
            self.should_ping, self.is_dead
        )
    }
}

/// Convenience function: compute both decisions at once.
pub fn evaluate_liveness(
    cfg: &KeepaliveConfig,
    state: &KeepaliveState,
    now_ms: u64,
) -> LivenessStatus {
    LivenessStatus {
        should_ping: state.should_send_ping(cfg, now_ms),
        is_dead: state.is_dead(cfg, now_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_time() -> u64 {
        1_700_000_000_000
    }

    #[test]
    fn stays_alive_with_regular_traffic() {
        let cfg = KeepaliveConfig::default();
        let mut st = KeepaliveState::new(base_time());

        // Simulate regular traffic every 5 seconds.
        let mut t = base_time();
        for _ in 0..5 {
            t += 5_000;
            st.on_data_received(t);
            let status = evaluate_liveness(&cfg, &st, t);
            assert!(!status.is_dead, "session should be alive");
            assert!(!status.should_ping, "no ping needed with traffic");
        }
    }

    #[test]
    fn starts_pinging_after_idle() {
        let cfg = KeepaliveConfig::default();
        let mut st = KeepaliveState::new(base_time());

        let t_idle_start = base_time() + cfg.idle_after_ms;
        let status = evaluate_liveness(&cfg, &st, t_idle_start);
        assert!(status.should_ping, "should start pinging after idle");

        // Record that we sent a ping
        st.on_ping_sent(t_idle_start);
        assert_eq!(st.missed_pings, 1);
    }

    #[test]
    fn dies_after_too_many_missed_pings() {
        let cfg = KeepaliveConfig {
            idle_after_ms: 5_000,
            ping_interval_ms: 5_000,
            max_missed_pings: 2,
            hard_timeout_ms: 60_000,
        };

        let mut st = KeepaliveState::new(base_time());

        // Go idle long enough to trigger ping.
        let t1 = base_time() + 6_000;
        assert!(st.should_send_ping(&cfg, t1));
        st.on_ping_sent(t1);

        // No response, time for second ping:
        let t2 = t1 + cfg.ping_interval_ms;
        assert!(st.should_send_ping(&cfg, t2));
        st.on_ping_sent(t2);

        // Now we exceeded max_missed_pings.
        let dead = st.is_dead(&cfg, t2 + 1);
        assert!(dead, "session should be considered dead");
    }

    #[test]
    fn hard_timeout_kills_even_without_pings() {
        let cfg = KeepaliveConfig::default();
        let st = KeepaliveState::new(base_time());

        let t_dead = base_time() + cfg.hard_timeout_ms + 1;
        let dead = st.is_dead(&cfg, t_dead);
        assert!(dead, "session should be dead after hard timeout");
    }

    #[test]
    fn pong_resets_missed_pings() {
        let cfg = KeepaliveConfig::default();
        let mut st = KeepaliveState::new(base_time());

        let t1 = base_time() + cfg.idle_after_ms + 1;
        assert!(st.should_send_ping(&cfg, t1));
        st.on_ping_sent(t1);
        assert_eq!(st.missed_pings, 1);

        // Receive pong; should reset missed_pings.
        let t2 = t1 + 1_000;
        st.on_pong_received(t2);
        assert_eq!(st.missed_pings, 0);
        assert!(!st.is_dead(&cfg, t2));
    }
}
