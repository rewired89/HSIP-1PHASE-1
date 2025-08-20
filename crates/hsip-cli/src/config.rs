use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub net: Net,
    #[serde(default)]
    pub policy: Policy,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Net {
    pub enc_key_hex: Option<String>,
    pub rl_max: Option<usize>,
    pub rl_window_ms: Option<u64>,
    pub rl_ban_ms: Option<u64>,
    pub replay_window_ms: Option<u64>,
    pub ts_skew_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct Policy {
    pub enforce_rep: Option<bool>,
    pub rep_threshold: Option<i32>,
}

/// Apply config → set env defaults (for commands that rely on env).
pub fn apply() -> Result<()> {
    if let Some(cfg) = read_config().ok().flatten() {
        // ---- NET (set if not already set) ----
        if let Some(k) = cfg.net.enc_key_hex {
            set_if_empty("HSIP_ENC_KEY_HEX", k);
        }
        if let Some(v) = cfg.net.rl_max {
            set_if_empty("HSIP_RL_MAX", v.to_string());
        }
        if let Some(v) = cfg.net.rl_window_ms {
            set_if_empty("HSIP_RL_WINDOW_MS", v.to_string());
        }
        if let Some(v) = cfg.net.rl_ban_ms {
            set_if_empty("HSIP_RL_BAN_MS", v.to_string());
        }
        if let Some(v) = cfg.net.replay_window_ms {
            set_if_empty("HSIP_REPLAY_WINDOW_MS", v.to_string());
        }
        if let Some(v) = cfg.net.ts_skew_ms {
            set_if_empty("HSIP_TS_SKEW_MS", v.to_string());
        }

        // ---- POLICY (force so it’s reliable across commands) ----
        if let Some(true) = cfg.policy.enforce_rep {
            std::env::set_var("HSIP_ENFORCE_REP", "1");
        }
        if let Some(v) = cfg.policy.rep_threshold {
            std::env::set_var("HSIP_REP_THRESHOLD", v.to_string());
        }
    }
    Ok(())
}

/// Direct read of config for commands that shouldn’t rely only on env.
pub fn read_config() -> Result<Option<Config>> {
    let path = default_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let txt = std::fs::read_to_string(&path)?;
    let cfg: Config = toml::from_str(&txt)?;
    Ok(Some(cfg))
}

pub fn default_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot resolve home dir"))?;
    Ok(home.join(".hsip").join("config.toml"))
}

fn set_if_empty(key: &str, val: String) {
    if std::env::var(key).is_err() {
        std::env::set_var(key, val);
    }
}
