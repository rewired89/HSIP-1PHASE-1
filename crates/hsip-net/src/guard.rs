// crates/hsip-net/src/guard.rs

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Simple guard configuration (read by udp.rs from env / config).
#[derive(Clone, Debug)]
pub struct GuardCfg {
    pub enable: bool,
    pub pin_minutes: u64,
    pub max_e1_per_5s: u32,
    pub max_bad_sig_per_min: u32,
    pub max_ctrl_per_min: u32,
    pub max_frame_len: usize,
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
    fn new_per(duration: Duration, limit: u32) -> Self {
        Self {
            times: VecDeque::new(),
            window: duration,
            limit,
        }
    }
    fn hit(&mut self) -> Result<(), String> {
        let now = Instant::now();
        while let Some(&t) = self.times.front() {
            if now.duration_since(t) > self.window {
                self.times.pop_front();
            } else {
                break;
            }
        }
        self.times.push_back(now);
        if (self.times.len() as u32) > self.limit {
            Err(format!(
                "rate exceeded: {} in {:?}",
                self.times.len(),
                self.window
            ))
        } else {
            Ok(())
        }
    }
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
}

impl Guard {
    pub fn new(cfg: GuardCfg) -> Self {
        Self {
            cfg,
            e1_per_5s: HashMap::new(),
            bad_sig_per_min: HashMap::new(),
            ctrl_per_min: HashMap::new(),
            pinned: HashSet::new(),
            pin_until: HashMap::new(),
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
    }

    pub fn cfg(&self) -> &GuardCfg {
        &self.cfg
    }

    /// Back-compat: udp.rs sometimes calls `on_control_frame(ip, len)`.
    pub fn on_control_frame(&mut self, ip: IpAddr, _len: usize) -> Result<(), String> {
        self.on_control(ip)
    }

    pub fn on_control(&mut self, ip: IpAddr) -> Result<(), String> {
        if !self.cfg.enable {
            return Ok(());
        }
        let entry = self.ctrl_per_min.entry(ip).or_insert_with(|| {
            WindowCounter::new_per(Duration::from_secs(60), self.cfg.max_ctrl_per_min)
        });
        entry.hit()
    }

    pub fn on_e1(&mut self, ip: IpAddr) -> Result<(), String> {
        if !self.cfg.enable {
            return Ok(());
        }
        let entry = self.e1_per_5s.entry(ip).or_insert_with(|| {
            WindowCounter::new_per(Duration::from_secs(5), self.cfg.max_e1_per_5s)
        });
        entry.hit()
    }

    pub fn on_bad_sig(&mut self, ip: IpAddr) -> Result<(), String> {
        if !self.cfg.enable {
            return Ok(());
        }
        let entry = self.bad_sig_per_min.entry(ip).or_insert_with(|| {
            WindowCounter::new_per(Duration::from_secs(60), self.cfg.max_bad_sig_per_min)
        });
        entry.hit()
    }

    /// Back-compat: udp.rs calls `pin(&peer_id)` when a request is allowed.
    pub fn pin(&mut self, peer_id: &str) {
        if !self.cfg.enable {
            return;
        }
        let until = Instant::now() + Duration::from_secs(self.cfg.pin_minutes * 60);
        self.pinned.insert(peer_id.to_string());
        self.pin_until.insert(peer_id.to_string(), until);
        eprintln!("[Guard] pinned {}", peer_id);
    }

    /// Back-compat: udp.rs calls `is_pinned(&peer_id)`.
    pub fn is_pinned(&mut self, peer_id: &str) -> bool {
        if !self.cfg.enable {
            return false;
        }
        // GC expired
        if let Some(&until) = self.pin_until.get(peer_id) {
            if Instant::now() >= until {
                self.pinned.remove(peer_id);
                self.pin_until.remove(peer_id);
                return false;
            }
            return true;
        }
        false
    }
}
