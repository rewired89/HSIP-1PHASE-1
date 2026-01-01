//! Known Telemetry Endpoints Database
//!
//! A curated database of known telemetry, analytics, and tracking endpoints.
//! This is used to automatically classify network flows and infer intent.

use crate::{TelemetryIntent, RiskLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;

/// A known telemetry endpoint entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointEntry {
    /// Domain pattern (supports wildcards like *.example.com)
    pub domain_pattern: String,
    /// Optional path patterns
    pub path_patterns: Vec<String>,
    /// Category/vendor
    pub category: EndpointCategory,
    /// Inferred intent
    pub intent: TelemetryIntent,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Vendor/company name
    pub vendor: String,
    /// Description
    pub description: String,
    /// Whether this can be safely blocked
    pub safe_to_block: bool,
}

/// Category of telemetry endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndpointCategory {
    /// Google Analytics, Firebase, etc.
    Google,
    /// Facebook/Meta Pixel, SDK
    Meta,
    /// Microsoft telemetry
    Microsoft,
    /// Apple telemetry
    Apple,
    /// Amazon tracking
    Amazon,
    /// Advertising networks
    AdNetwork,
    /// Third-party analytics (Mixpanel, Amplitude, etc.)
    Analytics,
    /// Crash reporting (Sentry, Crashlytics, etc.)
    CrashReporting,
    /// A/B testing platforms
    ABTesting,
    /// CDN telemetry
    CDN,
    /// Social media widgets
    Social,
    /// Known spyware/aggressive trackers
    Spyware,
    /// Enterprise MDM/telemetry
    Enterprise,
    /// Gaming telemetry
    Gaming,
    /// IoT/device telemetry
    IoT,
    /// Unknown/uncategorized
    Unknown,
}

impl EndpointCategory {
    /// Returns whether this category is typically high-priority to block
    pub fn should_block_by_default(&self) -> bool {
        matches!(
            self,
            EndpointCategory::AdNetwork
                | EndpointCategory::Spyware
                | EndpointCategory::Social
        )
    }
}

/// The known endpoints database
#[derive(Debug)]
pub struct EndpointDatabase {
    /// Entries indexed by domain suffix
    entries: RwLock<HashMap<String, Vec<EndpointEntry>>>,
    /// Custom user rules (take precedence)
    custom_rules: RwLock<Vec<EndpointEntry>>,
}

impl EndpointDatabase {
    /// Create a new database with built-in entries
    pub fn new() -> Self {
        let db = Self {
            entries: RwLock::new(HashMap::new()),
            custom_rules: RwLock::new(Vec::new()),
        };
        db.load_builtin_entries();
        db
    }

    /// Load the built-in telemetry endpoint database
    fn load_builtin_entries(&self) {
        let entries = Self::builtin_entries();
        let mut map = self.entries.write();

        for entry in entries {
            // Extract the base domain for indexing
            let base = Self::extract_base_domain(&entry.domain_pattern);
            map.entry(base).or_insert_with(Vec::new).push(entry);
        }
    }

    /// Extract base domain from pattern (e.g., "*.google.com" -> "google.com")
    fn extract_base_domain(pattern: &str) -> String {
        pattern
            .trim_start_matches("*.")
            .trim_start_matches("www.")
            .to_lowercase()
    }

    /// Look up a hostname in the database
    pub fn lookup(&self, hostname: &str) -> Option<EndpointEntry> {
        let hostname_lower = hostname.to_lowercase();

        // Check custom rules first
        {
            let custom = self.custom_rules.read();
            for entry in custom.iter() {
                if Self::matches_pattern(&entry.domain_pattern, &hostname_lower) {
                    return Some(entry.clone());
                }
            }
        }

        // Check built-in entries
        let entries = self.entries.read();

        // Try exact match first
        if let Some(list) = entries.get(&hostname_lower) {
            if let Some(entry) = list.first() {
                return Some(entry.clone());
            }
        }

        // Try suffix matching
        for (base, list) in entries.iter() {
            if hostname_lower.ends_with(base) || hostname_lower == *base {
                if let Some(entry) = list.first() {
                    return Some(entry.clone());
                }
            }
        }

        None
    }

    /// Check if hostname matches a pattern
    fn matches_pattern(pattern: &str, hostname: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            hostname.ends_with(suffix) || hostname == suffix
        } else {
            hostname == pattern
        }
    }

    /// Add a custom rule
    pub fn add_custom_rule(&self, entry: EndpointEntry) {
        self.custom_rules.write().push(entry);
    }

    /// Get all entries for a category
    pub fn get_by_category(&self, category: EndpointCategory) -> Vec<EndpointEntry> {
        let entries = self.entries.read();
        entries
            .values()
            .flatten()
            .filter(|e| e.category == category)
            .cloned()
            .collect()
    }

    /// Get total number of entries
    pub fn len(&self) -> usize {
        self.entries.read().values().map(|v| v.len()).sum()
    }

    /// Check if database is empty
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Built-in telemetry endpoints (curated list)
    fn builtin_entries() -> Vec<EndpointEntry> {
        vec![
            // === GOOGLE ===
            EndpointEntry {
                domain_pattern: "*.google-analytics.com".to_string(),
                path_patterns: vec!["/collect".to_string(), "/g/collect".to_string()],
                category: EndpointCategory::Google,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Google".to_string(),
                description: "Google Analytics tracking".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.googletagmanager.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Google,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Google".to_string(),
                description: "Google Tag Manager".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.doubleclick.net".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "Google".to_string(),
                description: "Google DoubleClick advertising".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.googlesyndication.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "Google".to_string(),
                description: "Google AdSense".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "firebaselogging-pa.googleapis.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Google,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Google".to_string(),
                description: "Firebase Analytics".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "crashlyticsreports-pa.googleapis.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::CrashReporting,
                intent: TelemetryIntent::CrashReport,
                risk_level: RiskLevel::Low,
                vendor: "Google".to_string(),
                description: "Firebase Crashlytics".to_string(),
                safe_to_block: false,
            },
            EndpointEntry {
                domain_pattern: "play.googleapis.com".to_string(),
                path_patterns: vec!["/log".to_string()],
                category: EndpointCategory::Google,
                intent: TelemetryIntent::Diagnostics,
                risk_level: RiskLevel::Medium,
                vendor: "Google".to_string(),
                description: "Google Play Services telemetry".to_string(),
                safe_to_block: false,
            },

            // === META/FACEBOOK ===
            EndpointEntry {
                domain_pattern: "*.facebook.com".to_string(),
                path_patterns: vec!["/tr".to_string(), "/ajax/bz".to_string()],
                category: EndpointCategory::Meta,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::Critical,
                vendor: "Meta".to_string(),
                description: "Facebook Pixel and tracking".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.fbcdn.net".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Meta,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Meta".to_string(),
                description: "Facebook CDN with tracking".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "graph.facebook.com".to_string(),
                path_patterns: vec!["/activities".to_string()],
                category: EndpointCategory::Meta,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::Critical,
                vendor: "Meta".to_string(),
                description: "Facebook App Events".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.instagram.com".to_string(),
                path_patterns: vec!["/logging_client_events".to_string()],
                category: EndpointCategory::Meta,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::Critical,
                vendor: "Meta".to_string(),
                description: "Instagram analytics".to_string(),
                safe_to_block: true,
            },

            // === MICROSOFT ===
            EndpointEntry {
                domain_pattern: "*.data.microsoft.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Microsoft,
                intent: TelemetryIntent::Diagnostics,
                risk_level: RiskLevel::Medium,
                vendor: "Microsoft".to_string(),
                description: "Microsoft telemetry".to_string(),
                safe_to_block: false, // May break Windows functionality
            },
            EndpointEntry {
                domain_pattern: "vortex.data.microsoft.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Microsoft,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Microsoft".to_string(),
                description: "Windows telemetry collector".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "settings-win.data.microsoft.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Microsoft,
                intent: TelemetryIntent::Diagnostics,
                risk_level: RiskLevel::Medium,
                vendor: "Microsoft".to_string(),
                description: "Windows settings sync".to_string(),
                safe_to_block: false,
            },
            EndpointEntry {
                domain_pattern: "*.clarity.ms".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Microsoft,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::Critical,
                vendor: "Microsoft".to_string(),
                description: "Microsoft Clarity session recording".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.applicationinsights.io".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Microsoft,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Microsoft".to_string(),
                description: "Azure Application Insights".to_string(),
                safe_to_block: true,
            },

            // === APPLE ===
            EndpointEntry {
                domain_pattern: "metrics.apple.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Apple,
                intent: TelemetryIntent::Diagnostics,
                risk_level: RiskLevel::Medium,
                vendor: "Apple".to_string(),
                description: "Apple metrics collection".to_string(),
                safe_to_block: false,
            },
            EndpointEntry {
                domain_pattern: "xp.apple.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Apple,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::Medium,
                vendor: "Apple".to_string(),
                description: "Apple experience analytics".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.iadsdk.apple.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::High,
                vendor: "Apple".to_string(),
                description: "Apple Search Ads".to_string(),
                safe_to_block: true,
            },

            // === THIRD-PARTY ANALYTICS ===
            EndpointEntry {
                domain_pattern: "*.mixpanel.com".to_string(),
                path_patterns: vec!["/track".to_string(), "/engage".to_string()],
                category: EndpointCategory::Analytics,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Mixpanel".to_string(),
                description: "Mixpanel analytics".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.amplitude.com".to_string(),
                path_patterns: vec!["/2/httpapi".to_string()],
                category: EndpointCategory::Analytics,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Amplitude".to_string(),
                description: "Amplitude analytics".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.segment.io".to_string(),
                path_patterns: vec!["/v1/t".to_string(), "/v1/p".to_string()],
                category: EndpointCategory::Analytics,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Segment".to_string(),
                description: "Segment CDP".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.segment.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Analytics,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Segment".to_string(),
                description: "Segment analytics".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.hotjar.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Analytics,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::Critical,
                vendor: "Hotjar".to_string(),
                description: "Hotjar session recording".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.fullstory.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Analytics,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::Critical,
                vendor: "FullStory".to_string(),
                description: "FullStory session recording".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.heap.io".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Analytics,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Heap".to_string(),
                description: "Heap Analytics".to_string(),
                safe_to_block: true,
            },

            // === CRASH REPORTING ===
            EndpointEntry {
                domain_pattern: "*.sentry.io".to_string(),
                path_patterns: vec!["/api/".to_string()],
                category: EndpointCategory::CrashReporting,
                intent: TelemetryIntent::CrashReport,
                risk_level: RiskLevel::Low,
                vendor: "Sentry".to_string(),
                description: "Sentry error tracking".to_string(),
                safe_to_block: false,
            },
            EndpointEntry {
                domain_pattern: "*.bugsnag.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::CrashReporting,
                intent: TelemetryIntent::CrashReport,
                risk_level: RiskLevel::Low,
                vendor: "Bugsnag".to_string(),
                description: "Bugsnag crash reporting".to_string(),
                safe_to_block: false,
            },
            EndpointEntry {
                domain_pattern: "*.raygun.io".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::CrashReporting,
                intent: TelemetryIntent::CrashReport,
                risk_level: RiskLevel::Low,
                vendor: "Raygun".to_string(),
                description: "Raygun crash reporting".to_string(),
                safe_to_block: false,
            },

            // === AD NETWORKS ===
            EndpointEntry {
                domain_pattern: "*.criteo.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "Criteo".to_string(),
                description: "Criteo retargeting".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.taboola.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "Taboola".to_string(),
                description: "Taboola content ads".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.outbrain.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "Outbrain".to_string(),
                description: "Outbrain content ads".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.adsrvr.org".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "The Trade Desk".to_string(),
                description: "The Trade Desk advertising".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.adnxs.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "Xandr/AppNexus".to_string(),
                description: "Xandr ad exchange".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.rubiconproject.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "Magnite/Rubicon".to_string(),
                description: "Rubicon Project advertising".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.pubmatic.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "PubMatic".to_string(),
                description: "PubMatic advertising".to_string(),
                safe_to_block: true,
            },

            // === A/B TESTING ===
            EndpointEntry {
                domain_pattern: "*.optimizely.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::ABTesting,
                intent: TelemetryIntent::FeatureFlags,
                risk_level: RiskLevel::Medium,
                vendor: "Optimizely".to_string(),
                description: "Optimizely A/B testing".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.launchdarkly.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::ABTesting,
                intent: TelemetryIntent::FeatureFlags,
                risk_level: RiskLevel::Medium,
                vendor: "LaunchDarkly".to_string(),
                description: "LaunchDarkly feature flags".to_string(),
                safe_to_block: false, // May break app functionality
            },
            EndpointEntry {
                domain_pattern: "*.split.io".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::ABTesting,
                intent: TelemetryIntent::FeatureFlags,
                risk_level: RiskLevel::Medium,
                vendor: "Split".to_string(),
                description: "Split feature flags".to_string(),
                safe_to_block: false,
            },

            // === SPYWARE / AGGRESSIVE TRACKERS ===
            EndpointEntry {
                domain_pattern: "*.scorecardresearch.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Spyware,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::Critical,
                vendor: "Comscore".to_string(),
                description: "Comscore tracking".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.quantserve.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Spyware,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::Critical,
                vendor: "Quantcast".to_string(),
                description: "Quantcast tracking".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.newrelic.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Analytics,
                intent: TelemetryIntent::Performance,
                risk_level: RiskLevel::Medium,
                vendor: "New Relic".to_string(),
                description: "New Relic APM".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.appsflyer.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::High,
                vendor: "AppsFlyer".to_string(),
                description: "AppsFlyer attribution".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.adjust.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::High,
                vendor: "Adjust".to_string(),
                description: "Adjust attribution".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.branch.io".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::High,
                vendor: "Branch".to_string(),
                description: "Branch deep linking & attribution".to_string(),
                safe_to_block: true,
            },

            // === AMAZON ===
            EndpointEntry {
                domain_pattern: "*.amazon-adsystem.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::AdNetwork,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::Critical,
                vendor: "Amazon".to_string(),
                description: "Amazon advertising".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "fls-na.amazon.com".to_string(),
                path_patterns: vec![],
                category: EndpointCategory::Amazon,
                intent: TelemetryIntent::UsageAnalytics,
                risk_level: RiskLevel::High,
                vendor: "Amazon".to_string(),
                description: "Amazon click tracking".to_string(),
                safe_to_block: true,
            },

            // === SOCIAL WIDGETS ===
            EndpointEntry {
                domain_pattern: "*.twitter.com".to_string(),
                path_patterns: vec!["/i/jot".to_string()],
                category: EndpointCategory::Social,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::High,
                vendor: "Twitter/X".to_string(),
                description: "Twitter analytics".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.linkedin.com".to_string(),
                path_patterns: vec!["/li/track".to_string()],
                category: EndpointCategory::Social,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::High,
                vendor: "LinkedIn".to_string(),
                description: "LinkedIn Insight Tag".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.tiktok.com".to_string(),
                path_patterns: vec!["/api/v1/user/log".to_string()],
                category: EndpointCategory::Social,
                intent: TelemetryIntent::BehaviorTracking,
                risk_level: RiskLevel::Critical,
                vendor: "TikTok".to_string(),
                description: "TikTok analytics".to_string(),
                safe_to_block: true,
            },
            EndpointEntry {
                domain_pattern: "*.snapchat.com".to_string(),
                path_patterns: vec!["/p".to_string()],
                category: EndpointCategory::Social,
                intent: TelemetryIntent::Advertising,
                risk_level: RiskLevel::High,
                vendor: "Snapchat".to_string(),
                description: "Snapchat Pixel".to_string(),
                safe_to_block: true,
            },
        ]
    }
}

impl Default for EndpointDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared thread-safe endpoint database
pub type SharedEndpointDatabase = Arc<EndpointDatabase>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let db = EndpointDatabase::new();
        assert!(!db.is_empty());
        assert!(db.len() > 30); // Should have many entries
    }

    #[test]
    fn test_lookup_exact() {
        let db = EndpointDatabase::new();

        let entry = db.lookup("www.google-analytics.com");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.category, EndpointCategory::Google);
        assert!(entry.safe_to_block);
    }

    #[test]
    fn test_lookup_wildcard() {
        let db = EndpointDatabase::new();

        let entry = db.lookup("subdomain.mixpanel.com");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().vendor, "Mixpanel");
    }

    #[test]
    fn test_custom_rule() {
        let db = EndpointDatabase::new();

        db.add_custom_rule(EndpointEntry {
            domain_pattern: "*.mycompany-internal.com".to_string(),
            path_patterns: vec![],
            category: EndpointCategory::Unknown,
            intent: TelemetryIntent::Diagnostics,
            risk_level: RiskLevel::Low,
            vendor: "Internal".to_string(),
            description: "Internal telemetry".to_string(),
            safe_to_block: false,
        });

        let entry = db.lookup("logs.mycompany-internal.com");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().vendor, "Internal");
    }

    #[test]
    fn test_category_filtering() {
        let db = EndpointDatabase::new();

        let ad_networks = db.get_by_category(EndpointCategory::AdNetwork);
        assert!(!ad_networks.is_empty());
        for entry in ad_networks {
            assert_eq!(entry.category, EndpointCategory::AdNetwork);
            assert!(entry.safe_to_block);
        }
    }

    #[test]
    fn test_no_match() {
        let db = EndpointDatabase::new();

        let entry = db.lookup("api.legitimate-service.com");
        assert!(entry.is_none());
    }
}
