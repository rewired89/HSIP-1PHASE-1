//! Configuration for the intercept system.

use crate::{PlatformType, Result, InterceptError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// Configuration for the Private DM Intercept system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptConfig {
    /// Whether the intercept system is enabled globally
    pub enabled: bool,

    /// Minimum confidence threshold to trigger intercept (0.0-1.0)
    pub min_confidence: f64,

    /// Platforms to monitor
    pub enabled_platforms: HashSet<PlatformType>,

    /// Platforms explicitly disabled by user
    pub disabled_platforms: HashSet<PlatformType>,

    /// Path to pattern database
    pub pattern_db_path: PathBuf,

    /// Privacy settings
    pub privacy: PrivacyConfig,

    /// Overlay settings
    pub overlay: OverlayConfig,

    /// HSIP messenger settings
    pub messenger: MessengerConfig,
}

/// Privacy-enhancing features configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Add random timing delays to mask patterns
    pub timing_obfuscation: bool,

    /// Minimum delay in milliseconds
    pub min_delay_ms: u64,

    /// Maximum delay in milliseconds
    pub max_delay_ms: u64,

    /// Normalize message sizes with padding
    pub message_padding: bool,

    /// Strip metadata from shared files
    pub strip_metadata: bool,

    /// Enable cover traffic (future)
    pub cover_traffic: bool,
}

/// Overlay UI configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayConfig {
    /// Position of overlay (TopRight, TopLeft, BottomRight, BottomLeft, Center)
    pub position: OverlayPosition,

    /// Auto-dismiss timeout in seconds (0 = no timeout)
    pub timeout_seconds: u32,

    /// Show tutorial on first intercept
    pub show_tutorial: bool,

    /// Theme (Light, Dark, System)
    pub theme: OverlayTheme,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OverlayPosition {
    TopRight,
    TopLeft,
    BottomRight,
    BottomLeft,
    Center,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OverlayTheme {
    Light,
    Dark,
    System,
}

/// HSIP Messenger configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerConfig {
    /// Auto-open messenger window on intercept
    pub auto_open: bool,

    /// Default consent duration in hours
    pub default_consent_hours: u32,

    /// Enable message queue for offline peers
    pub offline_queue: bool,

    /// Maximum queued messages per peer
    pub max_queue_size: usize,
}

impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Opt-in by default
            min_confidence: 0.80, // 80% confidence threshold
            enabled_platforms: HashSet::from([
                PlatformType::Instagram,
                PlatformType::Facebook,
                PlatformType::WhatsApp,
                PlatformType::Gmail,
            ]),
            disabled_platforms: HashSet::new(),
            pattern_db_path: PathBuf::from("patterns.json"),
            privacy: PrivacyConfig::default(),
            overlay: OverlayConfig::default(),
            messenger: MessengerConfig::default(),
        }
    }
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            timing_obfuscation: true,
            min_delay_ms: 50,
            max_delay_ms: 500,
            message_padding: false, // Disabled by default (adds overhead)
            strip_metadata: true,
            cover_traffic: false, // Future feature
        }
    }
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            position: OverlayPosition::TopRight,
            timeout_seconds: 10,
            show_tutorial: true,
            theme: OverlayTheme::System,
        }
    }
}

impl Default for MessengerConfig {
    fn default() -> Self {
        Self {
            auto_open: true,
            default_consent_hours: 24,
            offline_queue: true,
            max_queue_size: 100,
        }
    }
}

impl InterceptConfig {
    /// Load configuration from file.
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| InterceptError::Config(format!("Failed to read config: {}", e)))?;

        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to file.
    pub fn save(&self) -> Result<()> {
        let config_path = self.get_config_path();
        let content = serde_json::to_string_pretty(self)?;

        std::fs::write(&config_path, content)
            .map_err(|e| InterceptError::Config(format!("Failed to save config: {}", e)))?;

        Ok(())
    }

    /// Get default config file path.
    fn get_config_path(&self) -> PathBuf {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("hsip");

        std::fs::create_dir_all(&config_dir).ok();
        config_dir.join("intercept_config.json")
    }

    /// Check if a platform is enabled for interception.
    pub fn is_platform_enabled(&self, platform: PlatformType) -> bool {
        self.enabled
            && self.enabled_platforms.contains(&platform)
            && !self.disabled_platforms.contains(&platform)
    }

    /// Disable a platform.
    pub fn disable_platform(&mut self, platform: PlatformType) {
        self.disabled_platforms.insert(platform);
    }

    /// Enable a platform.
    pub fn enable_platform(&mut self, platform: PlatformType) {
        self.disabled_platforms.remove(&platform);
        self.enabled_platforms.insert(platform);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = InterceptConfig::default();
        assert!(!config.enabled); // Opt-in
        assert_eq!(config.min_confidence, 0.80);
        assert!(config.privacy.timing_obfuscation);
    }

    #[test]
    fn test_platform_management() {
        let mut config = InterceptConfig::default();
        config.enabled = true;

        assert!(config.is_platform_enabled(PlatformType::Instagram));

        config.disable_platform(PlatformType::Instagram);
        assert!(!config.is_platform_enabled(PlatformType::Instagram));

        config.enable_platform(PlatformType::Instagram);
        assert!(config.is_platform_enabled(PlatformType::Instagram));
    }
}
