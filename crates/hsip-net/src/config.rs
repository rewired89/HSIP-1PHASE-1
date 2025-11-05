//! hsip-net config loader
//!
//! Reads HSIP configuration from `$HOME/.hsip/config.toml` or environment variables.
//! Used by hsip-cli and hsip-net for identity, ports, and policy defaults.

use std::fs;
use std::path::PathBuf;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct NetConfig {
    /// Optional identity path override
    pub identity_path: Option<String>,
    /// UDP listening address (default: 127.0.0.1:9100)
    pub listen_addr: Option<String>,
    /// Whether to enable verbose debug
    pub debug: Option<bool>,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            identity_path: None,
            listen_addr: Some("127.0.0.1:9100".to_string()),
            debug: Some(false),
        }
    }
}

impl NetConfig {
    /// Returns `~/.hsip/config.toml` (or HSIP_HOME/config.toml if set)
    fn default_path() -> PathBuf {
        if let Ok(home) = std::env::var("HSIP_HOME") {
            return PathBuf::from(home).join("config.toml");
        }
        let mut p = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        p.push(".hsip");
        p.push("config.toml");
        p
    }

    /// Load config from file if it exists, otherwise return defaults.
    pub fn load() -> Self {
        let path = Self::default_path();
        if !path.exists() {
            return Self::default();
        }
        match fs::read_to_string(&path) {
            Ok(txt) => toml::from_str(&txt).unwrap_or_else(|_| Self::default()),
            Err(_) => Self::default(),
        }
    }

    /// Print a minimal debug banner.
    pub fn debug_banner(&self) {
        eprintln!(
            "[ConfigDebug] listen={} debug={} identity={:?}",
            self.listen_addr.clone().unwrap_or_default(),
            self.debug.unwrap_or(false),
            self.identity_path
        );
    }
}
