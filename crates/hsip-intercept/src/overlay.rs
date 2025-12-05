//! Overlay UI for intercept prompt.

use crate::{MessagingEvent, Result};

/// User's choice from the intercept overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserChoice {
    /// User chose to send via HSIP
    SendPrivately,

    /// User chose to continue with the original platform
    Continue,

    /// User chose to disable intercept for this platform
    DisableForApp(crate::PlatformType),
}

/// Abstract trait for platform-specific overlay UI.
#[async_trait::async_trait]
pub trait InterceptOverlay: Send + Sync {
    /// Show the intercept overlay and wait for user choice.
    ///
    /// # Arguments
    /// * `event` - The messaging event that triggered this intercept
    /// * `recipient` - Optional recipient info extracted from the event
    ///
    /// # Returns
    /// The user's choice (send privately, continue normally, or disable)
    async fn show(&mut self, event: &MessagingEvent, recipient: Option<&str>) -> Result<UserChoice>;

    /// Hide the overlay.
    async fn hide(&mut self) -> Result<()>;

    /// Check if overlay is currently visible.
    fn is_visible(&self) -> bool;
}

/// Overlay content and styling.
pub struct OverlayContent {
    pub title: String,
    pub message: String,
    pub recipient: Option<String>,
    pub show_tutorial: bool,
}

impl OverlayContent {
    /// Create overlay content for a messaging event.
    pub fn from_event(event: &MessagingEvent, recipient: Option<&str>) -> Self {
        let platform_name = format!("{:?}", event.platform);

        let message = if let Some(recipient) = recipient {
            format!(
                "You're about to message {} via {}.\nSend through HSIP for end-to-end encryption?",
                recipient, platform_name
            )
        } else {
            format!(
                "Send this message through HSIP instead?\nYour message will be end-to-end encrypted with consent verification.",
            )
        };

        Self {
            title: "🔒 Private Messaging Available".to_string(),
            message,
            recipient: recipient.map(String::from),
            show_tutorial: false,
        }
    }

    /// Create tutorial content for first-time users.
    pub fn tutorial() -> Self {
        Self {
            title: "🔒 Welcome to HSIP Private DM Intercept".to_string(),
            message: "HSIP detects when you're about to send a message and offers a private alternative.\n\n\
                     ✅ End-to-end encrypted\n\
                     ✅ Consent-based (no spam)\n\
                     ✅ No platform tracking\n\n\
                     You can choose HSIP or continue normally each time.".to_string(),
            recipient: None,
            show_tutorial: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PlatformType, EventType};

    #[test]
    fn test_overlay_content() {
        let event = MessagingEvent::new(
            PlatformType::Instagram,
            EventType::Click,
            "com.instagram.android".to_string(),
        );

        let content = OverlayContent::from_event(&event, Some("alice"));
        assert!(content.message.contains("alice"));
        assert!(content.message.contains("Instagram"));
    }

    #[test]
    fn test_tutorial_content() {
        let content = OverlayContent::tutorial();
        assert!(content.show_tutorial);
        assert!(content.message.contains("End-to-end encrypted"));
    }
}
