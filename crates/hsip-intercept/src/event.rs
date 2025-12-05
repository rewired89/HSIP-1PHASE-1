//! Event types and monitoring abstractions.

use crate::{Result, InterceptError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Platform types that can be intercepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformType {
    Instagram,
    Facebook,
    WhatsApp,
    Gmail,
    Outlook,
    Slack,
    Discord,
    Telegram,
    Signal,
    Messenger,
    Twitter,
    LinkedIn,
    Unknown,
}

impl PlatformType {
    /// Parse platform from process name or package ID.
    pub fn from_process_name(name: &str) -> Self {
        let name_lower = name.to_lowercase();

        if name_lower.contains("instagram") {
            Self::Instagram
        } else if name_lower.contains("facebook") || name_lower.contains("fb") {
            Self::Facebook
        } else if name_lower.contains("whatsapp") {
            Self::WhatsApp
        } else if name_lower.contains("gmail") {
            Self::Gmail
        } else if name_lower.contains("outlook") {
            Self::Outlook
        } else if name_lower.contains("slack") {
            Self::Slack
        } else if name_lower.contains("discord") {
            Self::Discord
        } else if name_lower.contains("telegram") {
            Self::Telegram
        } else if name_lower.contains("signal") {
            Self::Signal
        } else if name_lower.contains("messenger") {
            Self::Messenger
        } else if name_lower.contains("twitter") || name_lower.contains("x.com") {
            Self::Twitter
        } else if name_lower.contains("linkedin") {
            Self::LinkedIn
        } else {
            Self::Unknown
        }
    }
}

/// A messaging event detected by the OS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingEvent {
    /// Platform where the event occurred
    pub platform: PlatformType,

    /// Type of event (click, focus, etc.)
    pub event_type: EventType,

    /// Timestamp of the event
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Process name or package ID
    pub process_name: String,

    /// Window title (if available)
    pub window_title: Option<String>,

    /// UI element metadata (class name, resource ID, etc.)
    pub metadata: HashMap<String, String>,

    /// Confidence that this is a messaging action (0.0-1.0)
    pub confidence: f64,
}

/// Types of OS events we monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Button or element clicked
    Click,

    /// Input field focused
    Focus,

    /// Window title changed
    WindowChange,

    /// Text value changed
    ValueChange,

    /// Custom event type
    Custom,
}

/// Abstract trait for platform-specific event monitors.
#[async_trait::async_trait]
pub trait EventMonitor: Send + Sync {
    /// Start monitoring for messaging events.
    async fn start(&mut self) -> Result<()>;

    /// Stop monitoring.
    async fn stop(&mut self) -> Result<()>;

    /// Check if monitor is running.
    fn is_running(&self) -> bool;

    /// Get the event sender channel.
    fn event_sender(&self) -> &mpsc::Sender<MessagingEvent>;
}

impl MessagingEvent {
    /// Create a new messaging event.
    pub fn new(platform: PlatformType, event_type: EventType, process_name: String) -> Self {
        Self {
            platform,
            event_type,
            timestamp: chrono::Utc::now(),
            process_name,
            window_title: None,
            metadata: HashMap::new(),
            confidence: 0.5, // Default medium confidence
        }
    }

    /// Add metadata to the event.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set window title.
    pub fn with_window_title(mut self, title: impl Into<String>) -> Self {
        self.window_title = Some(title.into());
        self
    }

    /// Set confidence score.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        assert_eq!(
            PlatformType::from_process_name("com.instagram.android"),
            PlatformType::Instagram
        );
        assert_eq!(
            PlatformType::from_process_name("chrome.exe - Gmail"),
            PlatformType::Gmail
        );
        assert_eq!(
            PlatformType::from_process_name("unknown_app"),
            PlatformType::Unknown
        );
    }

    #[test]
    fn test_event_builder() {
        let event = MessagingEvent::new(
            PlatformType::Instagram,
            EventType::Click,
            "com.instagram.android".to_string(),
        )
        .with_metadata("resource_id", "direct_inbox_button")
        .with_window_title("Direct Messages")
        .with_confidence(0.95);

        assert_eq!(event.platform, PlatformType::Instagram);
        assert_eq!(event.confidence, 0.95);
        assert_eq!(event.metadata.get("resource_id").unwrap(), "direct_inbox_button");
    }
}
