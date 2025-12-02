use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Simple guard configuration (read by udp.rs from env / config).
#[derive(Clone, Debug)]
pub struct GuardCfg {
    /// Whether guard checks are enabled.
    pub enable: bool,
    /// Minutes to keep a peer "pinned" (auto-allowed) after an allow decision.
    pub pin_minutes: u64,
    /// Max number of E1 handshakes allowed per 5s window per IP.
    pub max_e1_per_5s: u32,
    /// Max number of bad signatures allowed per minute per IP.
    pub max_bad_sig_per_min: u32,
    /// Max number of control frames allowed per minute per IP.
    pub max_ctrl_per_min: u32,
    /// Maximum accepted control frame length (post-prefix).
    pub max_frame_len: usize,
    /// Optional padding target sizes (not enforced here; used by sender).
    pub pad_to_sizes: Vec<usize>,
}

/// Back-compat alias for older code that expects `GuardConfig`.
pub type GuardConfig = GuardCfg;

impl Default for GuardCfg {
    fn default() -> Self {
        Self {
            enable: true,
            pin_minutes: 20,
            max_e1_per_5s: 20,
            max_bad_sig_per_min: 5,
            max_ctrl_per_min: 120,
            max_frame_len: 4096,
            pad_to_sizes: vec![],
        }
    }
}

#[derive(Default)]
struct WindowCounter {
    times: VecDeque<Instant>,
    window: Duration,
    limit: u32,
}

impl WindowCounter {
    #[must_use]
    fn new_per(duration: Duration, limit: u32) -> Self {
        Self {
            times: VecDeque::new(),
            window: duration,
            limit,
        }
    }

    /// Record a hit and enforce the (count, window) limit.
    ///
    /// # Errors
    /// Returns an error string if the limit is exceeded for the current window.
    fn hit(&mut self) -> Result<(), String> {
        let now = Instant::now();

        // Evict old timestamps
        while let Some(&t) = self.times.front() {
            if now.duration_since(t) > self.window {
                self.times.pop_front();
            } else {
                break;
            }
        }

        self.times.push_back(now);

        let count = self.times.len() as u32;
        if count > self.limit {
            Err(format!("rate exceeded: {count} in {:?}", self.window))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GuardStats {
    blocked_events: u64,
    blocked_ips: usize,
}

fn stats_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".hsip").join("guard_stats.json"))
}

fn persist_stats(stats: &GuardStats) {
    if let Some(path) = stats_path() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(buf) = serde_json::to_vec(stats) {
            let _ = fs::write(path, buf);
        }
    }
}

fn blocklist_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".hsip").join("tracker_blocklist.txt"))
}

fn load_blocklist() -> HashSet<IpAddr> {
    let mut set = HashSet::new();
    if let Some(path) = blocklist_path() {
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Ok(ip) = line.parse::<IpAddr>() {
                    set.insert(ip);
                }
            }
        }
    }
    set
}

pub struct Guard {
    cfg: GuardCfg,

    // per-IP windows
    e1_per_5s: HashMap<IpAddr, WindowCounter>,
    bad_sig_per_min: HashMap<IpAddr, WindowCounter>,
    ctrl_per_min: HashMap<IpAddr, WindowCounter>,

    // pinned peers (recently allowed)
    pinned: HashSet<String>,
    pin_until: HashMap<String, Instant>,

    // aggregate block stats
    blocked_events: u64,
    blocked_ips: HashSet<IpAddr>,

    // static tracker wall (IP blocklist)
    tracker_blocklist: HashSet<IpAddr>,
}

impl Guard {
    #[must_use]
    pub fn new(cfg: GuardCfg) -> Self {
        Self {
            cfg,
            e1_per_5s: HashMap::new(),
            bad_sig_per_min: HashMap::new(),
            ctrl_per_min: HashMap::new(),
            pinned: HashSet::new(),
            pin_until: HashMap::new(),
            blocked_events: 0,
            blocked_ips: HashSet::new(),
            tracker_blocklist: load_blocklist(),
        }
    }

    /// Back-compat: udp.rs calls this name. We print a one-line banner.
    pub fn debug_banner(&self) {
        eprintln!(
            "[GuardDebug] enable={} pin={}min e1/5s={} badsig/min={} ctrl/min={} max_frame={} pad={:?}",
            self.cfg.enable,
            self.cfg.pin_minutes,
            self.cfg.max_e1_per_5s,
            self.cfg.max_bad_sig_per_min,
            self.cfg.max_ctrl_per_min,
            self.cfg.max_frame_len,
            self.cfg.pad_to_sizes
        );
        if !self.tracker_blocklist.is_empty() {
            eprintln!(
                "[GuardDebug] tracker wall active: {} IPs in blocklist",
                self.tracker_blocklist.len()
            );
        }
    }

    #[must_use]
    pub const fn cfg(&self) -> &GuardCfg {
        &self.cfg
    }

    fn is_blocklisted(&self, ip: IpAddr) -> bool {
        self.tracker_blocklist.contains(&ip)
    }

    /// Mark a peer/IP as blocked for stats (in-memory + persisted).
    fn mark_blocked(&mut self, ip: IpAddr) {
        if !self.cfg.enable {
            return;
        }
        self.blocked_events = self.blocked_events.saturating_add(1);
        self.blocked_ips.insert(ip);

        let stats = GuardStats {
            blocked_events: self.blocked_events,
            blocked_ips: self.blocked_ips.len(),
        };
        persist_stats(&stats);
    }

    /// Expose block statistics for in-process callers.
    #[must_use]
    pub fn blocked_stats(&self) -> (u64, usize) {
        (self.blocked_events, self.blocked_ips.len())
    }

    /// Back-compat: udp.rs sometimes calls `on_control_frame(ip, len)`.
    /// Also enforces `max_frame_len`.
    ///
    /// # Errors
    /// - Returns an error string if the frame length exceeds `max_frame_len`.
    /// - Propagates the per-minute control-rate limiter error.
    pub fn on_control_frame(&mut self, ip: IpAddr, len: usize) -> Result<(), String> {
        if self.cfg.enable && len > self.cfg.max_frame_len {
            self.mark_blocked(ip);
            return Err(format!(
                "frame too large: {} > {}",
                len, self.cfg.max_frame_len
            ));
        }
        self.on_control(ip)
    }

    /// Count a control-plane frame from `ip` against the per-minute window.
    ///
    /// # Errors
    /// Returns a rate-limit error string when exceeded.
    pub fn on_control(&mut self, ip: IpAddr) -> Result<(), String> {
        if !self.cfg.enable {
            return Ok(());
        }

        if self.is_blocklisted(ip) {
            self.mark_blocked(ip);
            eprintln!("[Guard] control from {ip} blocked by tracker wall");
            return Err("blocked by tracker wall".into());
        }

        let entry = self.ctrl_per_min.entry(ip).or_insert_with(|| {
            WindowCounter::new_per(Duration::from_secs(60), self.cfg.max_ctrl_per_min)
        });
        match entry.hit() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.mark_blocked(ip);
                Err(e)
            }
        }
    }

    /// Count an E1 (handshake init) from `ip` against the per-5s window.
    ///
    /// # Errors
    /// Returns a rate-limit error string when exceeded.
    pub fn on_e1(&mut self, ip: IpAddr) -> Result<(), String> {
        if !self.cfg.enable {
            return Ok(());
        }

        if self.is_blocklisted(ip) {
            self.mark_blocked(ip);
            eprintln!("[Guard] E1 from {ip} blocked by tracker wall");
            return Err("blocked by tracker wall".into());
        }

        let entry = self.e1_per_5s.entry(ip).or_insert_with(|| {
            WindowCounter::new_per(Duration::from_secs(5), self.cfg.max_e1_per_5s)
        });
        match entry.hit() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.mark_blocked(ip);
                Err(e)
            }
        }
    }

    /// Count a bad signature from `ip` against the per-minute window.
    ///
    /// # Errors
    /// Returns a rate-limit error string when exceeded.
    pub fn on_bad_sig(&mut self, ip: IpAddr) -> Result<(), String> {
        if !self.cfg.enable {
            return Ok(());
        }

        if self.is_blocklisted(ip) {
            self.mark_blocked(ip);
            eprintln!("[Guard] bad-sig from {ip} blocked by tracker wall");
            return Err("blocked by tracker wall".into());
        }

        let entry = self.bad_sig_per_min.entry(ip).or_insert_with(|| {
            WindowCounter::new_per(Duration::from_secs(60), self.cfg.max_bad_sig_per_min)
        });
        match entry.hit() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.mark_blocked(ip);
                Err(e)
            }
        }
    }

    /// Back-compat: udp.rs calls `pin(&peer_id)` when a request is allowed.
    pub fn pin(&mut self, peer_id: &str) {
        if !self.cfg.enable {
            return;
        }
        let until = Instant::now() + Duration::from_secs(self.cfg.pin_minutes.saturating_mul(60));
        let id = peer_id.to_owned();
        self.pinned.insert(id.clone());
        self.pin_until.insert(id.clone(), until);
        eprintln!("[Guard] pinned {id}");
    }

    /// Back-compat: udp.rs calls `is_pinned(&peer_id)`.
    ///
    /// Performs opportunistic GC of expired pins.
    #[must_use]
    pub fn is_pinned(&mut self, peer_id: &str) -> bool {
        if !self.cfg.enable {
            return false;
        }
        if let Some(&until) = self.pin_until.get(peer_id) {
            if Instant::now() >= until {
                // expired → GC and report not pinned
                self.pinned.remove(peer_id);
                self.pin_until.remove(peer_id);
                return false;
            }
            return true;
        }
        false
    }
}
