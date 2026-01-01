//! Uncertainty Principle - Privacy vs. Performance Slider
//!
//! Inspired by Heisenberg's Uncertainty Principle where measuring one property
//! precisely makes another property uncertain, this module provides a privacy
//! slider that trades off privacy for performance/functionality.
//!
//! # Security Properties
//! - Higher privacy = more encryption, more padding, slower operations
//! - Higher performance = less overhead, more metadata exposure
//! - User-controlled balance with clear tradeoff visualization
//! - No "false sense of security" - clearly shows what is/isn't protected

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Privacy level on the uncertainty spectrum
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PrivacyLevel {
    /// Minimal privacy - maximum performance
    /// Only essential encryption, no padding, timestamps visible
    Minimal = 0,
    /// Basic privacy - good performance
    /// Standard encryption, minimal padding
    Basic = 1,
    /// Balanced privacy and performance
    /// Default setting with reasonable tradeoffs
    Balanced = 2,
    /// Enhanced privacy - reduced performance
    /// Extra encryption layers, significant padding
    Enhanced = 3,
    /// Maximum privacy - significant performance cost
    /// Full padding, cover traffic, delayed delivery
    Maximum = 4,
}

impl PrivacyLevel {
    /// Get the numeric value (0-4)
    pub fn value(&self) -> u8 {
        *self as u8
    }

    /// Create from numeric value
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Minimal),
            1 => Some(Self::Basic),
            2 => Some(Self::Balanced),
            3 => Some(Self::Enhanced),
            4 => Some(Self::Maximum),
            _ => None,
        }
    }

    /// Get descriptive name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Minimal => "Minimal",
            Self::Basic => "Basic",
            Self::Balanced => "Balanced",
            Self::Enhanced => "Enhanced",
            Self::Maximum => "Maximum",
        }
    }

    /// Get the normalized value (0.0 - 1.0)
    pub fn normalized(&self) -> f32 {
        self.value() as f32 / 4.0
    }
}

impl Default for PrivacyLevel {
    fn default() -> Self {
        Self::Balanced
    }
}

/// What's protected at each privacy level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyFeatures {
    /// Message content encryption
    pub content_encrypted: bool,
    /// Metadata (timestamps, sizes) hidden
    pub metadata_hidden: bool,
    /// Traffic analysis resistant (padding)
    pub traffic_analysis_resistant: bool,
    /// Cover traffic enabled
    pub cover_traffic: bool,
    /// Delayed/batched delivery
    pub delayed_delivery: bool,
    /// Multi-hop routing
    pub multi_hop: bool,
    /// Read receipts hidden
    pub receipts_hidden: bool,
    /// Typing indicators hidden
    pub typing_hidden: bool,
}

impl PrivacyFeatures {
    /// Get features for a privacy level
    pub fn for_level(level: PrivacyLevel) -> Self {
        match level {
            PrivacyLevel::Minimal => Self {
                content_encrypted: true,
                metadata_hidden: false,
                traffic_analysis_resistant: false,
                cover_traffic: false,
                delayed_delivery: false,
                multi_hop: false,
                receipts_hidden: false,
                typing_hidden: false,
            },
            PrivacyLevel::Basic => Self {
                content_encrypted: true,
                metadata_hidden: false,
                traffic_analysis_resistant: false,
                cover_traffic: false,
                delayed_delivery: false,
                multi_hop: false,
                receipts_hidden: true,
                typing_hidden: true,
            },
            PrivacyLevel::Balanced => Self {
                content_encrypted: true,
                metadata_hidden: true,
                traffic_analysis_resistant: false,
                cover_traffic: false,
                delayed_delivery: false,
                multi_hop: false,
                receipts_hidden: true,
                typing_hidden: true,
            },
            PrivacyLevel::Enhanced => Self {
                content_encrypted: true,
                metadata_hidden: true,
                traffic_analysis_resistant: true,
                cover_traffic: false,
                delayed_delivery: false,
                multi_hop: true,
                receipts_hidden: true,
                typing_hidden: true,
            },
            PrivacyLevel::Maximum => Self {
                content_encrypted: true,
                metadata_hidden: true,
                traffic_analysis_resistant: true,
                cover_traffic: true,
                delayed_delivery: true,
                multi_hop: true,
                receipts_hidden: true,
                typing_hidden: true,
            },
        }
    }

    /// Count enabled features
    pub fn enabled_count(&self) -> usize {
        let features = [
            self.content_encrypted,
            self.metadata_hidden,
            self.traffic_analysis_resistant,
            self.cover_traffic,
            self.delayed_delivery,
            self.multi_hop,
            self.receipts_hidden,
            self.typing_hidden,
        ];
        features.iter().filter(|&&f| f).count()
    }
}

/// Performance impact at each privacy level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceImpact {
    /// Latency multiplier (1.0 = baseline)
    pub latency_multiplier: f32,
    /// Bandwidth multiplier (1.0 = baseline)
    pub bandwidth_multiplier: f32,
    /// CPU overhead multiplier
    pub cpu_multiplier: f32,
    /// Estimated message delivery delay (milliseconds)
    pub delivery_delay_ms: u64,
    /// Battery impact description
    pub battery_impact: BatteryImpact,
}

/// Battery impact level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatteryImpact {
    Negligible,
    Low,
    Moderate,
    High,
    VeryHigh,
}

impl BatteryImpact {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Negligible => "No noticeable impact",
            Self::Low => "Slightly increased battery usage",
            Self::Moderate => "Moderate battery impact",
            Self::High => "Significant battery drain",
            Self::VeryHigh => "Heavy battery usage",
        }
    }
}

impl PerformanceImpact {
    /// Get performance impact for a privacy level
    pub fn for_level(level: PrivacyLevel) -> Self {
        match level {
            PrivacyLevel::Minimal => Self {
                latency_multiplier: 1.0,
                bandwidth_multiplier: 1.0,
                cpu_multiplier: 1.0,
                delivery_delay_ms: 0,
                battery_impact: BatteryImpact::Negligible,
            },
            PrivacyLevel::Basic => Self {
                latency_multiplier: 1.1,
                bandwidth_multiplier: 1.1,
                cpu_multiplier: 1.1,
                delivery_delay_ms: 50,
                battery_impact: BatteryImpact::Low,
            },
            PrivacyLevel::Balanced => Self {
                latency_multiplier: 1.3,
                bandwidth_multiplier: 1.5,
                cpu_multiplier: 1.3,
                delivery_delay_ms: 200,
                battery_impact: BatteryImpact::Moderate,
            },
            PrivacyLevel::Enhanced => Self {
                latency_multiplier: 2.0,
                bandwidth_multiplier: 3.0,
                cpu_multiplier: 2.0,
                delivery_delay_ms: 1000,
                battery_impact: BatteryImpact::High,
            },
            PrivacyLevel::Maximum => Self {
                latency_multiplier: 5.0,
                bandwidth_multiplier: 10.0,
                cpu_multiplier: 3.0,
                delivery_delay_ms: 5000,
                battery_impact: BatteryImpact::VeryHigh,
            },
        }
    }
}

/// Complete uncertainty configuration showing the tradeoff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncertaintyConfig {
    /// Selected privacy level
    pub level: PrivacyLevel,
    /// Features enabled at this level
    pub features: PrivacyFeatures,
    /// Performance impact at this level
    pub performance: PerformanceImpact,
    /// When this config was set
    pub set_at: DateTime<Utc>,
    /// Custom feature overrides (if any)
    pub custom_overrides: HashMap<String, bool>,
}

impl UncertaintyConfig {
    /// Create a new config at the specified level
    pub fn new(level: PrivacyLevel) -> Self {
        Self {
            level,
            features: PrivacyFeatures::for_level(level),
            performance: PerformanceImpact::for_level(level),
            set_at: Utc::now(),
            custom_overrides: HashMap::new(),
        }
    }

    /// Create with custom overrides
    pub fn with_overrides(level: PrivacyLevel, overrides: HashMap<String, bool>) -> Self {
        let mut config = Self::new(level);
        config.custom_overrides = overrides;
        config
    }

    /// Get the effective value of a feature (considering overrides)
    pub fn effective_feature(&self, feature: &str) -> Option<bool> {
        // Check override first
        if let Some(&value) = self.custom_overrides.get(feature) {
            return Some(value);
        }

        // Fall back to level default
        match feature {
            "content_encrypted" => Some(self.features.content_encrypted),
            "metadata_hidden" => Some(self.features.metadata_hidden),
            "traffic_analysis_resistant" => Some(self.features.traffic_analysis_resistant),
            "cover_traffic" => Some(self.features.cover_traffic),
            "delayed_delivery" => Some(self.features.delayed_delivery),
            "multi_hop" => Some(self.features.multi_hop),
            "receipts_hidden" => Some(self.features.receipts_hidden),
            "typing_hidden" => Some(self.features.typing_hidden),
            _ => None,
        }
    }

    /// Calculate message padding size based on privacy level
    pub fn padding_size(&self, message_size: usize) -> usize {
        match self.level {
            PrivacyLevel::Minimal => 0,
            PrivacyLevel::Basic => 16, // Minimal padding
            PrivacyLevel::Balanced => {
                // Pad to next 256 bytes
                let remainder = message_size % 256;
                if remainder == 0 { 0 } else { 256 - remainder }
            }
            PrivacyLevel::Enhanced => {
                // Pad to next 1KB
                let remainder = message_size % 1024;
                if remainder == 0 { 0 } else { 1024 - remainder }
            }
            PrivacyLevel::Maximum => {
                // Pad all messages to fixed size (4KB)
                let target = 4096;
                if message_size >= target { 0 } else { target - message_size }
            }
        }
    }

    /// Get cover traffic interval (if enabled)
    pub fn cover_traffic_interval_ms(&self) -> Option<u64> {
        if self.features.cover_traffic || self.custom_overrides.get("cover_traffic") == Some(&true) {
            Some(match self.level {
                PrivacyLevel::Maximum => 1000,  // Every second
                PrivacyLevel::Enhanced => 5000, // Every 5 seconds
                _ => 10000,                     // Every 10 seconds
            })
        } else {
            None
        }
    }

    /// Get delay for batched delivery (if enabled)
    pub fn batch_delay_ms(&self) -> Option<u64> {
        if self.features.delayed_delivery || self.custom_overrides.get("delayed_delivery") == Some(&true) {
            Some(self.performance.delivery_delay_ms)
        } else {
            None
        }
    }
}

impl Default for UncertaintyConfig {
    fn default() -> Self {
        Self::new(PrivacyLevel::Balanced)
    }
}

/// Encryption parameters derived from uncertainty config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionParams {
    /// Number of encryption layers
    pub layers: u8,
    /// Key derivation iterations
    pub kdf_iterations: u32,
    /// Use authenticated encryption
    pub authenticated: bool,
    /// Include timestamp in encrypted data
    pub encrypt_timestamp: bool,
}

impl EncryptionParams {
    /// Derive encryption parameters from privacy level
    pub fn from_level(level: PrivacyLevel) -> Self {
        match level {
            PrivacyLevel::Minimal => Self {
                layers: 1,
                kdf_iterations: 10_000,
                authenticated: true,
                encrypt_timestamp: false,
            },
            PrivacyLevel::Basic => Self {
                layers: 1,
                kdf_iterations: 50_000,
                authenticated: true,
                encrypt_timestamp: false,
            },
            PrivacyLevel::Balanced => Self {
                layers: 1,
                kdf_iterations: 100_000,
                authenticated: true,
                encrypt_timestamp: true,
            },
            PrivacyLevel::Enhanced => Self {
                layers: 2,
                kdf_iterations: 200_000,
                authenticated: true,
                encrypt_timestamp: true,
            },
            PrivacyLevel::Maximum => Self {
                layers: 3,
                kdf_iterations: 500_000,
                authenticated: true,
                encrypt_timestamp: true,
            },
        }
    }
}

/// Human-readable summary of the uncertainty tradeoff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeoffSummary {
    /// Privacy score (0-100)
    pub privacy_score: u8,
    /// Performance score (0-100)
    pub performance_score: u8,
    /// What's protected
    pub protected: Vec<String>,
    /// What's exposed
    pub exposed: Vec<String>,
    /// Warnings about current settings
    pub warnings: Vec<String>,
}

impl TradeoffSummary {
    /// Generate summary for a privacy level
    pub fn for_level(level: PrivacyLevel) -> Self {
        let features = PrivacyFeatures::for_level(level);

        let privacy_score = (level.value() as u8 + 1) * 20;
        let performance_score = 100 - (level.value() as u8 * 20);

        let mut protected = vec!["Message content (always encrypted)".to_string()];
        let mut exposed = Vec::new();
        let mut warnings = Vec::new();

        if features.metadata_hidden {
            protected.push("Message metadata".to_string());
        } else {
            exposed.push("Message timestamps and sizes".to_string());
        }

        if features.traffic_analysis_resistant {
            protected.push("Traffic patterns".to_string());
        } else {
            exposed.push("Communication patterns".to_string());
        }

        if features.receipts_hidden {
            protected.push("Read status".to_string());
        } else {
            exposed.push("When messages are read".to_string());
        }

        if features.typing_hidden {
            protected.push("Typing activity".to_string());
        } else {
            exposed.push("When you're typing".to_string());
        }

        // Add warnings for low privacy
        if level == PrivacyLevel::Minimal {
            warnings.push("Minimal privacy: metadata and patterns are visible".to_string());
        }

        // Add warnings for high privacy impact
        if level == PrivacyLevel::Maximum {
            warnings.push("Maximum privacy: significant battery and data usage".to_string());
            warnings.push("Messages may be delayed for batching".to_string());
        }

        Self {
            privacy_score,
            performance_score,
            protected,
            exposed,
            warnings,
        }
    }
}

/// Slider widget data for UI rendering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliderData {
    /// Current position (0-4)
    pub position: u8,
    /// Labels for each position
    pub labels: [String; 5],
    /// Current summary
    pub summary: TradeoffSummary,
}

impl SliderData {
    /// Create slider data for current level
    pub fn new(level: PrivacyLevel) -> Self {
        Self {
            position: level.value(),
            labels: [
                "Speed".to_string(),
                "Basic".to_string(),
                "Balance".to_string(),
                "Privacy".to_string(),
                "Maximum".to_string(),
            ],
            summary: TradeoffSummary::for_level(level),
        }
    }

    /// Move slider left (less privacy, more performance)
    pub fn decrease(&mut self) {
        if self.position > 0 {
            self.position -= 1;
            self.summary = TradeoffSummary::for_level(
                PrivacyLevel::from_value(self.position).unwrap()
            );
        }
    }

    /// Move slider right (more privacy, less performance)
    pub fn increase(&mut self) {
        if self.position < 4 {
            self.position += 1;
            self.summary = TradeoffSummary::for_level(
                PrivacyLevel::from_value(self.position).unwrap()
            );
        }
    }

    /// Get current privacy level
    pub fn level(&self) -> PrivacyLevel {
        PrivacyLevel::from_value(self.position).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_levels() {
        assert_eq!(PrivacyLevel::Minimal.value(), 0);
        assert_eq!(PrivacyLevel::Maximum.value(), 4);
        assert_eq!(PrivacyLevel::from_value(2), Some(PrivacyLevel::Balanced));
        assert_eq!(PrivacyLevel::from_value(99), None);
    }

    #[test]
    fn test_features_progression() {
        let minimal = PrivacyFeatures::for_level(PrivacyLevel::Minimal);
        let maximum = PrivacyFeatures::for_level(PrivacyLevel::Maximum);

        // Minimal has fewer features
        assert!(minimal.enabled_count() < maximum.enabled_count());

        // Content always encrypted
        assert!(minimal.content_encrypted);
        assert!(maximum.content_encrypted);

        // Maximum has all features
        assert!(maximum.cover_traffic);
        assert!(maximum.multi_hop);
        assert!(!minimal.cover_traffic);
    }

    #[test]
    fn test_performance_impact_progression() {
        let minimal = PerformanceImpact::for_level(PrivacyLevel::Minimal);
        let maximum = PerformanceImpact::for_level(PrivacyLevel::Maximum);

        assert!(minimal.latency_multiplier < maximum.latency_multiplier);
        assert!(minimal.bandwidth_multiplier < maximum.bandwidth_multiplier);
        assert_eq!(minimal.delivery_delay_ms, 0);
        assert!(maximum.delivery_delay_ms > 0);
    }

    #[test]
    fn test_uncertainty_config() {
        let config = UncertaintyConfig::new(PrivacyLevel::Balanced);

        assert_eq!(config.level, PrivacyLevel::Balanced);
        assert!(config.features.content_encrypted);
        assert!(config.features.metadata_hidden);
        assert!(!config.features.cover_traffic);
    }

    #[test]
    fn test_custom_overrides() {
        let mut overrides = HashMap::new();
        overrides.insert("cover_traffic".to_string(), true);

        let config = UncertaintyConfig::with_overrides(PrivacyLevel::Basic, overrides);

        // Should use override value
        assert_eq!(config.effective_feature("cover_traffic"), Some(true));
        // Should use level default
        assert_eq!(config.effective_feature("metadata_hidden"), Some(false));
    }

    #[test]
    fn test_padding_calculation() {
        let minimal = UncertaintyConfig::new(PrivacyLevel::Minimal);
        let maximum = UncertaintyConfig::new(PrivacyLevel::Maximum);

        assert_eq!(minimal.padding_size(100), 0);
        assert_eq!(maximum.padding_size(100), 4096 - 100);
    }

    #[test]
    fn test_slider_data() {
        let mut slider = SliderData::new(PrivacyLevel::Balanced);
        assert_eq!(slider.position, 2);

        slider.increase();
        assert_eq!(slider.position, 3);
        assert_eq!(slider.level(), PrivacyLevel::Enhanced);

        slider.decrease();
        slider.decrease();
        assert_eq!(slider.position, 1);
        assert_eq!(slider.level(), PrivacyLevel::Basic);
    }

    #[test]
    fn test_tradeoff_summary() {
        let minimal = TradeoffSummary::for_level(PrivacyLevel::Minimal);
        let maximum = TradeoffSummary::for_level(PrivacyLevel::Maximum);

        // Minimal has lower privacy score, higher performance
        assert!(minimal.privacy_score < maximum.privacy_score);
        assert!(minimal.performance_score > maximum.performance_score);

        // Both should have content protected
        assert!(minimal.protected.iter().any(|s| s.contains("content")));
    }

    #[test]
    fn test_encryption_params() {
        let minimal = EncryptionParams::from_level(PrivacyLevel::Minimal);
        let maximum = EncryptionParams::from_level(PrivacyLevel::Maximum);

        assert_eq!(minimal.layers, 1);
        assert_eq!(maximum.layers, 3);
        assert!(minimal.kdf_iterations < maximum.kdf_iterations);
    }
}
