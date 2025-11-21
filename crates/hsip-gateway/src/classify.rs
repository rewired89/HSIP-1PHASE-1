//! Simple classification engine for HSIP Web Gateway.
//!
//! Phase 2.0 (MVP):
//! - Block known trackers from ~/.hsip/tracker_blocklist.txt
//! - Everything else: allow.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::metrics::record_tracker_block;

/// Protocol type (we treat HTTP/HTTPS slightly differently later).
#[derive(Debug, Clone, Copy)]
pub enum ProtoKind {
    Http,
    Https,
}

/// Minimal view of a request for classification.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub proto: ProtoKind,
}

/// Outcome of classification.
#[derive(Debug, Clone)]
pub enum DecisionKind {
    Allow,
    Block,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub kind: DecisionKind,
    pub reason: Option<String>,
}

impl Decision {
    pub fn allow() -> Self {
        Self {
            kind: DecisionKind::Allow,
            reason: None,
        }
    }

    pub fn block(reason: impl Into<String>) -> Self {
        Self {
            kind: DecisionKind::Block,
            reason: Some(reason.into()),
        }
    }
}

/// Public entry: classify a request.
pub fn classify(req: &RequestInfo) -> Decision {
    if is_tracker_domain(&req.host) {
        let reason = format!("tracker_domain:{}", req.host);
        // Update local + on-disk metrics
        record_tracker_block(&req.host, &reason);
        return Decision::block(reason);
    }

    // Later: phishing, malware, shady ASNs, etc.
    Decision::allow()
}

// === tracker blocklist loading ===

static TRACKERS: OnceLock<HashSet<String>> = OnceLock::new();

fn tracker_blocklist_path() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".hsip").join("tracker_blocklist.txt")
}

fn load_trackers() -> &'static HashSet<String> {
    TRACKERS.get_or_init(|| {
        let path = tracker_blocklist_path();
        let mut set = HashSet::new();

        let contents = fs::read_to_string(&path).unwrap_or_default();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            set.insert(line.to_lowercase());
        }

        eprintln!(
            "[gateway] loaded {} tracker entries from {}",
            set.len(),
            path.display()
        );
        set
    })
}

fn is_tracker_domain(host: &str) -> bool {
    let host_lc = host.to_lowercase();
    let trackers = load_trackers();

    for t in trackers {
        if host_lc == *t {
            return true;
        }
        if host_lc.ends_with(&format!(".{}", t)) {
            return true;
        }
    }

    false
}
