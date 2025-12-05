//! Windows-specific implementation using UI Automation API.

pub mod event_monitor;
pub mod overlay;
pub mod messenger;
pub mod utils;

pub use event_monitor::WindowsEventMonitor;
pub use overlay::WindowsOverlay;
pub use messenger::{open_messenger_window, extract_recipient_from_window};

// Re-export common Windows types
pub use windows::Win32::UI::Accessibility::{
    IUIAutomation, IUIAutomationElement, UIA_PATTERN_ID,
};
