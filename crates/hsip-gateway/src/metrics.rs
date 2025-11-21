// crates/hsip-gateway/src/metrics.rs

//! Simple on-disk metrics for HSIP Web Gateway.
//!
//! File: ~/.hsip/gateway_metrics.json
//! {
//!   "blocked_trackers": 12,
//!   "last_host": "doubleclick.net",
//!   "last_reason": "tracker_domain:doubleclick.net",
//!   "updated_ms": 1731970000000
//! }

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayMetrics {
    pub blocked_trackers: u64,
    pub last_host: Option<String>,
    pub last_reason: Option<String>,
    pub updated_ms: u64,
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self {
            blocked_trackers: 0,
            last_host: None,
            last_reason: None,
            updated_ms: 0,
        }
    }
}

static METRICS: OnceLock<Mutex<GatewayMetrics>> = OnceLock::new();

fn global() -> &'static Mutex<GatewayMetrics> {
    METRICS.get_or_init(|| Mutex::new(GatewayMetrics::default()))
}

fn metrics_path() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".hsip").join("gateway_metrics.json")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Called when we block a tracker domain.
/// Best effort: failures just log and continue.
pub fn record_tracker_block(host: &str, reason: &str) {
    let mut g = match global().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    g.blocked_trackers = g.blocked_trackers.saturating_add(1);
    g.last_host = Some(host.to_string());
    g.last_reason = Some(reason.to_string());
    g.updated_ms = now_ms();

    // Persist to ~/.hsip/gateway_metrics.json
    let path = metrics_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match serde_json::to_string(&*g) {
        Ok(json) => {
            if let Err(e) = fs::write(&path, json) {
                eprintln!("[gateway] failed to write metrics {}: {e}", path.display());
            }
        }
        Err(e) => {
            eprintln!("[gateway] failed to serialize metrics: {e}");
        }
    }
}
