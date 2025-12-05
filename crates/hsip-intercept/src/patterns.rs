//! Pattern matching for messaging action detection.

use crate::{MessagingEvent, PlatformType, InterceptConfig, Result, InterceptError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pattern database for recognizing messaging actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDatabase {
    pub version: String,
    pub patterns: Vec<PlatformPattern>,
}

/// Patterns for a specific platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformPattern {
    pub platform: PlatformType,
    pub triggers: Vec<TriggerPattern>,
}

/// A single trigger pattern with confidence weighting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerPattern {
    pub platform: PlatformType,
    pub trigger_type: TriggerType,
    pub value: String,
    pub confidence: f64,
}

/// Types of triggers we can match against.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerType {
    /// Accessibility ID / resource ID
    AccessibilityId,

    /// UI element class name
    ClassName,

    /// Window title text
    WindowTitle,

    /// Button text content
    TextContent,

    /// Process/package name
    ProcessName,

    /// Custom automation ID
    AutomationId,
}

/// Pattern matcher engine.
pub struct PatternMatcher {
    database: PatternDatabase,
    cache: HashMap<String, Option<TriggerPattern>>,
}

impl PatternMatcher {
    /// Load pattern database from configuration.
    pub fn load_from_config(config: &InterceptConfig) -> Result<Self> {
        let database = if config.pattern_db_path.exists() {
            Self::load_database(&config.pattern_db_path)?
        } else {
            Self::default_database()
        };

        Ok(Self {
            database,
            cache: HashMap::new(),
        })
    }

    /// Load pattern database from JSON file.
    fn load_database(path: &std::path::Path) -> Result<PatternDatabase> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| InterceptError::PatternMatch(format!("Failed to read pattern DB: {}", e)))?;

        let db: PatternDatabase = serde_json::from_str(&content)?;
        Ok(db)
    }

    /// Get default built-in pattern database.
    fn default_database() -> PatternDatabase {
        PatternDatabase {
            version: "1.0.0".to_string(),
            patterns: vec![
                // Instagram patterns
                PlatformPattern {
                    platform: PlatformType::Instagram,
                    triggers: vec![
                        TriggerPattern {
                            platform: PlatformType::Instagram,
                            trigger_type: TriggerType::AccessibilityId,
                            value: "direct_inbox_button".to_string(),
                            confidence: 0.95,
                        },
                        TriggerPattern {
                            platform: PlatformType::Instagram,
                            trigger_type: TriggerType::ClassName,
                            value: "DirectThreadView".to_string(),
                            confidence: 0.85,
                        },
                        TriggerPattern {
                            platform: PlatformType::Instagram,
                            trigger_type: TriggerType::TextContent,
                            value: "Send Message".to_string(),
                            confidence: 0.70,
                        },
                    ],
                },
                // Facebook patterns
                PlatformPattern {
                    platform: PlatformType::Facebook,
                    triggers: vec![
                        TriggerPattern {
                            platform: PlatformType::Facebook,
                            trigger_type: TriggerType::AccessibilityId,
                            value: "com.facebook.katana:id/messaging_button".to_string(),
                            confidence: 0.95,
                        },
                        TriggerPattern {
                            platform: PlatformType::Facebook,
                            trigger_type: TriggerType::WindowTitle,
                            value: "Messenger".to_string(),
                            confidence: 0.80,
                        },
                    ],
                },
                // Gmail patterns
                PlatformPattern {
                    platform: PlatformType::Gmail,
                    triggers: vec![
                        TriggerPattern {
                            platform: PlatformType::Gmail,
                            trigger_type: TriggerType::WindowTitle,
                            value: "Compose - Gmail".to_string(),
                            confidence: 0.90,
                        },
                        TriggerPattern {
                            platform: PlatformType::Gmail,
                            trigger_type: TriggerType::AutomationId,
                            value: "compose_button".to_string(),
                            confidence: 0.85,
                        },
                    ],
                },
                // WhatsApp patterns
                PlatformPattern {
                    platform: PlatformType::WhatsApp,
                    triggers: vec![
                        TriggerPattern {
                            platform: PlatformType::WhatsApp,
                            trigger_type: TriggerType::AccessibilityId,
                            value: "chat_input_field".to_string(),
                            confidence: 0.90,
                        },
                    ],
                },
            ],
        }
    }

    /// Match an event against known patterns.
    ///
    /// Returns the best matching pattern with highest confidence,
    /// or None if no match found.
    pub fn match_event(&mut self, event: &MessagingEvent) -> Result<Option<TriggerPattern>> {
        // Create cache key from event
        let cache_key = format!(
            "{}:{}:{}",
            event.process_name,
            event.window_title.as_deref().unwrap_or(""),
            event.metadata.get("resource_id").unwrap_or(&String::new())
        );

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached.clone());
        }

        // Find patterns for this platform
        let platform_patterns = self.database.patterns.iter()
            .filter(|p| p.platform == event.platform)
            .flat_map(|p| &p.triggers);

        let mut best_match: Option<TriggerPattern> = None;
        let mut best_confidence = 0.0;

        for pattern in platform_patterns {
            if let Some(confidence) = self.match_pattern(pattern, event) {
                if confidence > best_confidence {
                    best_confidence = confidence;
                    best_match = Some(pattern.clone());
                }
            }
        }

        // Update cache
        self.cache.insert(cache_key, best_match.clone());

        Ok(best_match)
    }

    /// Match a single pattern against an event.
    fn match_pattern(&self, pattern: &TriggerPattern, event: &MessagingEvent) -> Option<f64> {
        let matched = match &pattern.trigger_type {
            TriggerType::AccessibilityId => {
                event.metadata.get("accessibility_id")
                    .or(event.metadata.get("resource_id"))
                    .map(|id| id.contains(&pattern.value))
                    .unwrap_or(false)
            }
            TriggerType::ClassName => {
                event.metadata.get("class_name")
                    .map(|cn| cn.contains(&pattern.value))
                    .unwrap_or(false)
            }
            TriggerType::WindowTitle => {
                event.window_title.as_ref()
                    .map(|title| title.contains(&pattern.value))
                    .unwrap_or(false)
            }
            TriggerType::TextContent => {
                event.metadata.get("text_content")
                    .or(event.metadata.get("content_description"))
                    .map(|text| text.contains(&pattern.value))
                    .unwrap_or(false)
            }
            TriggerType::ProcessName => {
                event.process_name.contains(&pattern.value)
            }
            TriggerType::AutomationId => {
                event.metadata.get("automation_id")
                    .map(|id| id.contains(&pattern.value))
                    .unwrap_or(false)
            }
        };

        if matched {
            Some(pattern.confidence)
        } else {
            None
        }
    }

    /// Save current database to file.
    pub fn save_database(&self, path: &std::path::Path) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.database)?;
        std::fs::write(path, content)
            .map_err(|e| InterceptError::PatternMatch(format!("Failed to save pattern DB: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventType;

    #[test]
    fn test_pattern_matching() {
        let mut matcher = PatternMatcher {
            database: PatternMatcher::default_database(),
            cache: HashMap::new(),
        };

        // Test Instagram DM button
        let event = MessagingEvent::new(
            PlatformType::Instagram,
            EventType::Click,
            "com.instagram.android".to_string(),
        )
        .with_metadata("accessibility_id", "direct_inbox_button");

        let result = matcher.match_event(&event).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().confidence, 0.95);
    }

    #[test]
    fn test_gmail_compose() {
        let mut matcher = PatternMatcher {
            database: PatternMatcher::default_database(),
            cache: HashMap::new(),
        };

        let event = MessagingEvent::new(
            PlatformType::Gmail,
            EventType::WindowChange,
            "chrome.exe".to_string(),
        )
        .with_window_title("Compose - Gmail");

        let result = matcher.match_event(&event).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().confidence, 0.90);
    }

    #[test]
    fn test_no_match() {
        let mut matcher = PatternMatcher {
            database: PatternMatcher::default_database(),
            cache: HashMap::new(),
        };

        let event = MessagingEvent::new(
            PlatformType::Unknown,
            EventType::Click,
            "unknown_app".to_string(),
        );

        let result = matcher.match_event(&event).unwrap();
        assert!(result.is_none());
    }
}
