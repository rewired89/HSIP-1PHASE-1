//! HSIP Private DM Intercept
//!
//! Detects when users attempt to send messages through traditional platforms
//! and offers a privacy-preserving alternative via HSIP's consent-based protocol.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │  Event Monitor  │  ← OS-level accessibility events
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Pattern Matcher │  ← Recognizes messaging actions
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Intercept UI    │  ← User chooses HSIP or continue
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  HSIP Router    │  ← Consent handshake + session
//! └─────────────────┘
//! ```
//!
//! # Privacy Boundaries
//!
//! ✅ Allowed:
//! - OS-level event listening (accessibility events)
//! - UI element metadata (class names, IDs)
//! - Local pattern matching
//!
//! ❌ Prohibited:
//! - Reading message content from other apps
//! - Modifying other apps' memory/code
//! - Sending analytics to cloud
//!
//! # Platform Support
//!
//! - **Windows**: UI Automation API (production-ready)
//! - **Android**: Accessibility Services (production-ready)
//! - **iOS**: Share Extension only (App Store compliant)
//! - **Linux**: X11/Wayland accessibility (future)
//! - **macOS**: Accessibility API (future)

pub mod error;
pub mod event;
pub mod overlay;
pub mod patterns;
pub mod router;
pub mod config;
pub mod privacy;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "android")]
pub mod android;

// Re-exports
pub use error::{InterceptError, Result};
pub use event::{EventMonitor, MessagingEvent, PlatformType};
pub use overlay::{InterceptOverlay, UserChoice};
pub use patterns::{PatternMatcher, TriggerPattern};
pub use router::HSIPRouter;
pub use config::InterceptConfig;

use tokio::sync::mpsc;
use tracing::{info, warn, error};

/// Main coordinator for the Private DM Intercept system.
///
/// Manages the lifecycle of event monitoring, pattern matching,
/// overlay display, and HSIP routing.
pub struct InterceptCoordinator {
    config: InterceptConfig,
    event_rx: mpsc::Receiver<MessagingEvent>,
    event_monitor: Box<dyn EventMonitor>,
    pattern_matcher: PatternMatcher,
    overlay: Box<dyn InterceptOverlay>,
    router: HSIPRouter,
}

impl InterceptCoordinator {
    /// Create a new intercept coordinator.
    pub async fn new(config: InterceptConfig) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::channel(100);

        // Initialize platform-specific event monitor
        #[cfg(target_os = "windows")]
        let event_monitor = windows::WindowsEventMonitor::new(event_tx, &config)?;

        #[cfg(target_os = "android")]
        let event_monitor = android::AndroidEventMonitor::new(event_tx, &config)?;

        #[cfg(not(any(target_os = "windows", target_os = "android")))]
        compile_error!("Unsupported platform - use Windows or Android");

        // Initialize pattern matcher
        let pattern_matcher = PatternMatcher::load_from_config(&config)?;

        // Initialize platform-specific overlay
        #[cfg(target_os = "windows")]
        let overlay = windows::WindowsOverlay::new(&config)?;

        #[cfg(target_os = "android")]
        let overlay = android::AndroidOverlay::new(&config)?;

        // Initialize HSIP router
        let router = HSIPRouter::new(&config).await?;

        Ok(Self {
            config,
            event_rx,
            event_monitor,
            pattern_matcher,
            overlay,
            router,
        })
    }

    /// Start the intercept coordinator.
    ///
    /// This is the main event loop that:
    /// 1. Monitors for messaging events
    /// 2. Matches against known patterns
    /// 3. Shows intercept overlay
    /// 4. Routes messages via HSIP if user chooses
    pub async fn run(mut self) -> Result<()> {
        info!("Starting HSIP Private DM Intercept");

        // Start event monitoring
        self.event_monitor.start().await?;

        // Main event loop
        while let Some(event) = self.event_rx.recv().await {
            if let Err(e) = self.handle_event(event).await {
                error!("Error handling event: {}", e);
            }
        }

        Ok(())
    }

    /// Handle a single messaging event.
    async fn handle_event(&mut self, event: MessagingEvent) -> Result<()> {
        // Apply privacy timing obfuscation if enabled
        if self.config.privacy.timing_obfuscation {
            privacy::add_timing_jitter().await;
        }

        // Match against known patterns
        let pattern_match = self.pattern_matcher.match_event(&event)?;

        if let Some(matched_pattern) = pattern_match {
            info!(
                "Detected messaging action: platform={:?}, confidence={}",
                matched_pattern.platform, matched_pattern.confidence
            );

            // Only intercept if confidence threshold met
            if matched_pattern.confidence >= self.config.min_confidence {
                self.show_intercept_overlay(&event, &matched_pattern).await?;
            } else {
                warn!(
                    "Skipping intercept (low confidence): {}",
                    matched_pattern.confidence
                );
            }
        }

        Ok(())
    }

    /// Show the intercept overlay and handle user choice.
    async fn show_intercept_overlay(
        &mut self,
        event: &MessagingEvent,
        pattern: &TriggerPattern,
    ) -> Result<()> {
        // Extract recipient if possible
        let recipient = self.extract_recipient(event).await;

        // Show overlay
        let choice = self.overlay.show(event, recipient.as_deref()).await?;

        match choice {
            UserChoice::SendPrivately => {
                info!("User chose to send via HSIP");
                self.router.open_messenger(recipient).await?;
            }
            UserChoice::Continue => {
                info!("User chose to continue normally");
            }
            UserChoice::DisableForApp(platform) => {
                info!("User disabled intercept for {:?}", platform);
                self.config.disable_platform(platform);
                self.config.save()?;
            }
        }

        Ok(())
    }

    /// Attempt to extract recipient information from the event.
    ///
    /// This is platform-specific and may return None if recipient
    /// cannot be determined from accessibility metadata.
    async fn extract_recipient(&self, event: &MessagingEvent) -> Option<String> {
        // Try to extract from event metadata
        if let Some(recipient) = event.metadata.get("recipient") {
            return Some(recipient.clone());
        }

        // Platform-specific extraction
        #[cfg(target_os = "windows")]
        {
            windows::extract_recipient_from_window(event).ok()
        }

        #[cfg(target_os = "android")]
        {
            android::extract_recipient_from_view(event).ok()
        }

        #[cfg(not(any(target_os = "windows", target_os = "android")))]
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coordinator_lifecycle() {
        // Basic smoke test
        let config = InterceptConfig::default();
        let coordinator = InterceptCoordinator::new(config).await;
        assert!(coordinator.is_ok());
    }
}
