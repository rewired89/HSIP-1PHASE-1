//! Android-specific implementation using Accessibility Services.
//!
//! # Architecture
//!
//! Android implementation uses:
//! - AccessibilityService for event monitoring
//! - WindowManager for overlay display (TYPE_APPLICATION_OVERLAY)
//! - JNI bridge to communicate with Rust core
//!
//! # Permissions Required
//!
//! ```xml
//! <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
//! <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
//! ```

#[cfg(target_os = "android")]
pub mod event_monitor;

#[cfg(target_os = "android")]
pub mod overlay;

#[cfg(target_os = "android")]
pub mod messenger;

#[cfg(target_os = "android")]
pub use event_monitor::AndroidEventMonitor;

#[cfg(target_os = "android")]
pub use overlay::AndroidOverlay;

#[cfg(target_os = "android")]
pub use messenger::{open_messenger_activity, extract_recipient_from_view};

// Stub implementations for non-Android platforms (for compilation)
#[cfg(not(target_os = "android"))]
pub mod event_monitor {
    use crate::{EventMonitor, InterceptConfig, Result};
    use tokio::sync::mpsc;

    pub struct AndroidEventMonitor;

    impl AndroidEventMonitor {
        pub fn new(_tx: mpsc::Sender<crate::MessagingEvent>, _config: &InterceptConfig) -> Result<Box<dyn EventMonitor>> {
            unimplemented!("Android event monitor only available on Android")
        }
    }
}

#[cfg(not(target_os = "android"))]
pub mod overlay {
    use crate::{InterceptOverlay, InterceptConfig, Result};

    pub struct AndroidOverlay;

    impl AndroidOverlay {
        pub fn new(_config: &InterceptConfig) -> Result<Box<dyn InterceptOverlay>> {
            unimplemented!("Android overlay only available on Android")
        }
    }
}

#[cfg(not(target_os = "android"))]
pub mod messenger {
    use crate::{Result, MessagingEvent};

    pub async fn open_messenger_activity(_hint: Option<String>) -> Result<()> {
        unimplemented!("Android messenger only available on Android")
    }

    pub fn extract_recipient_from_view(_event: &MessagingEvent) -> Result<String> {
        unimplemented!("Android recipient extraction only available on Android")
    }
}
