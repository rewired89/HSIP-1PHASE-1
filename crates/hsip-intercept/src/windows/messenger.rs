//! Windows HSIP Messenger window integration.

use crate::{Result, InterceptError, MessagingEvent};
use tracing::{info, warn};

/// Open HSIP Messenger window.
///
/// This will either:
/// 1. Launch a new messenger window process
/// 2. Activate existing messenger window
/// 3. Show a temporary encrypted text input dialog
pub async fn open_messenger_window(recipient_hint: Option<String>) -> Result<()> {
    info!("Opening HSIP Messenger window (recipient: {:?})", recipient_hint);

    // TODO: Implement messenger window
    // Options:
    // 1. Spawn `hsip-cli messenger` subprocess
    // 2. Use IPC to communicate with existing daemon
    // 3. Create native Windows UI with WebView2 or native controls

    warn!("Messenger window not yet implemented");

    // For MVP, we can use a simple MessageBox as placeholder
    #[cfg(debug_assertions)]
    unsafe {
        use windows::Win32::UI::WindowsAndMessaging::*;

        let message = if let Some(recipient) = recipient_hint {
            format!("Opening HSIP Messenger for: {}\n\n(Messenger UI not yet implemented)", recipient)
        } else {
            "Opening HSIP Messenger\n\n(Messenger UI not yet implemented)".to_string()
        };

        let wide_msg: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
        let wide_title: Vec<u16> = "HSIP Messenger".encode_utf16().chain(std::iter::once(0)).collect();

        MessageBoxW(
            None,
            windows::core::PCWSTR(wide_msg.as_ptr()),
            windows::core::PCWSTR(wide_title.as_ptr()),
            MB_OK | MB_ICONINFORMATION,
        );
    }

    Ok(())
}

/// Extract recipient information from Windows UI elements.
///
/// This uses UI Automation to try to find recipient information
/// in the current window context.
pub fn extract_recipient_from_window(event: &MessagingEvent) -> Result<String> {
    // Try to extract from window title
    if let Some(title) = &event.window_title {
        // Gmail: "Compose - user@example.com - Gmail"
        if title.contains("Compose") && title.contains('@') {
            if let Some(email_start) = title.find(char::is_alphabetic) {
                if let Some(email_end) = title[email_start..].find(" - ") {
                    let potential_email = &title[email_start..email_start + email_end];
                    if potential_email.contains('@') {
                        return Ok(potential_email.to_string());
                    }
                }
            }
        }

        // Instagram: "Direct - @username"
        if title.contains("Direct") && title.contains('@') {
            if let Some(at_pos) = title.find('@') {
                let rest = &title[at_pos..];
                if let Some(end_pos) = rest.find(|c: char| c.is_whitespace() || c == ')') {
                    return Ok(rest[..end_pos].to_string());
                } else {
                    return Ok(rest.to_string());
                }
            }
        }
    }

    // Try to extract from metadata
    if let Some(recipient) = event.metadata.get("recipient") {
        return Ok(recipient.clone());
    }

    Err(InterceptError::EventMonitor(
        "Could not extract recipient from window".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventType, PlatformType};

    #[test]
    fn test_recipient_extraction_gmail() {
        let event = MessagingEvent::new(
            PlatformType::Gmail,
            EventType::WindowChange,
            "chrome.exe".to_string(),
        )
        .with_window_title("Compose - alice@example.com - Gmail");

        let result = extract_recipient_from_window(&event);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("alice@example.com"));
    }

    #[test]
    fn test_recipient_extraction_instagram() {
        let event = MessagingEvent::new(
            PlatformType::Instagram,
            EventType::WindowChange,
            "Instagram.exe".to_string(),
        )
        .with_window_title("Direct - @alice_crypto");

        let result = extract_recipient_from_window(&event);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "@alice_crypto");
    }

    #[test]
    fn test_recipient_extraction_metadata() {
        let event = MessagingEvent::new(
            PlatformType::WhatsApp,
            EventType::Focus,
            "WhatsApp.exe".to_string(),
        )
        .with_metadata("recipient", "Bob Smith");

        let result = extract_recipient_from_window(&event);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Bob Smith");
    }
}
