//! Windows UI Automation event monitoring.

use crate::{
    EventMonitor, MessagingEvent, EventType, PlatformType, InterceptConfig, Result, InterceptError,
};
use tokio::sync::mpsc;
use tracing::{info, debug, error};
use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::System::Com::{
        CoInitializeEx, CoCreateInstance, CoUninitialize,
        COINIT_APARTMENTTHREADED, CLSCTX_INPROC_SERVER,
    },
    Win32::System::Threading::*,
    Win32::UI::Accessibility::*,
    Win32::UI::WindowsAndMessaging::*,
};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

/// Wrapper for COM objects to mark them as Send+Sync.
/// SAFETY: Windows COM objects with apartment threading are safe to move between threads
/// when properly initialized per-thread.
struct SendSyncWrapper<T>(Option<T>);

unsafe impl<T> Send for SendSyncWrapper<T> {}
unsafe impl<T> Sync for SendSyncWrapper<T> {}

impl<T> SendSyncWrapper<T> {
    fn new(val: T) -> Self {
        Self(Some(val))
    }

    fn none() -> Self {
        Self(None)
    }

    fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }
}

/// Windows event monitor using UI Automation API.
pub struct WindowsEventMonitor {
    event_tx: mpsc::Sender<MessagingEvent>,
    config: InterceptConfig,
    running: Arc<AtomicBool>,
    automation: SendSyncWrapper<IUIAutomation>,
}

impl WindowsEventMonitor {
    /// Create a new Windows event monitor.
    pub fn new(
        event_tx: mpsc::Sender<MessagingEvent>,
        config: &InterceptConfig,
    ) -> Result<Box<dyn EventMonitor>> {
        Ok(Box::new(Self {
            event_tx,
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            automation: SendSyncWrapper::none(),
        }))
    }

    /// Initialize UI Automation COM interface.
    fn initialize_automation(&mut self) -> Result<()> {
        unsafe {
            // Initialize COM - HRESULT.ok() converts to Result
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
                .ok()
                .map_err(|e| InterceptError::EventMonitor(format!("COM init failed: {}", e)))?;

            // Create IUIAutomation instance
            let automation: IUIAutomation = CoCreateInstance(
                &CUIAutomation,
                None,
                CLSCTX_INPROC_SERVER,
            )
            .map_err(|e| InterceptError::EventMonitor(format!("Failed to create IUIAutomation: {}", e)))?;

            self.automation = SendSyncWrapper::new(automation);
            info!("UI Automation initialized successfully");
            Ok(())
        }
    }

    /// Register event handlers for UI Automation events.
    fn register_event_handlers(&self) -> Result<()> {
        let automation = self.automation.as_ref()
            .ok_or_else(|| InterceptError::EventMonitor("Automation not initialized".to_string()))?;

        unsafe {
            // Register for InvokePattern events (button clicks)
            // TODO: Implement IUIAutomationEventHandler
            // This requires creating a COM object that implements the handler interface

            // For now, we'll use a polling approach with SetWinEventHook
            self.register_win_event_hooks()?;
        }

        Ok(())
    }

    /// Register Windows Event Hooks for window and UI events.
    fn register_win_event_hooks(&self) -> Result<()> {
        unsafe {
            // Hook window focus changes
            let hook = SetWinEventHook(
                EVENT_OBJECT_FOCUS,
                EVENT_OBJECT_FOCUS,
                None,
                Some(Self::win_event_proc),
                0,
                0,
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
            );

            if hook.is_invalid() {
                return Err(InterceptError::EventMonitor(
                    "Failed to set WinEventHook".to_string(),
                ));
            }

            // Hook button invokes
            let hook2 = SetWinEventHook(
                EVENT_OBJECT_INVOKED,
                EVENT_OBJECT_INVOKED,
                None,
                Some(Self::win_event_proc),
                0,
                0,
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
            );

            if hook2.is_invalid() {
                return Err(InterceptError::EventMonitor(
                    "Failed to set WinEventHook for invocation".to_string(),
                ));
            }

            info!("Windows event hooks registered");
            Ok(())
        }
    }

    /// Windows event hook callback.
    ///
    /// SAFETY: This is called from Windows, must be unsafe extern "system"
    unsafe extern "system" fn win_event_proc(
        _h_win_event_hook: HWINEVENTHOOK,
        event: u32,
        hwnd: HWND,
        id_object: i32,
        _id_child: i32,
        _id_event_thread: u32,
        _dwms_event_time: u32,
    ) {
        // Only process window-level events
        if id_object != OBJID_WINDOW.0 {
            return;
        }

        // Get window information
        if let Ok(window_info) = Self::get_window_info(hwnd) {
            debug!(
                "Window event: {:?}, title: {}, class: {}",
                event, window_info.title, window_info.class_name
            );

            // TODO: Send event to channel
            // Need to pass event_tx reference through thread-local storage or global state
            // For now, this is just logging
        }
    }

    /// Get information about a window.
    unsafe fn get_window_info(hwnd: HWND) -> Result<WindowInfo> {
        // Get window title
        let mut title_buf = [0u16; 256];
        let title_len = GetWindowTextW(hwnd, &mut title_buf);
        let title = String::from_utf16_lossy(&title_buf[..title_len as usize]);

        // Get window class
        let mut class_buf = [0u16; 256];
        let class_len = GetClassNameW(hwnd, &mut class_buf);
        let class_name = String::from_utf16_lossy(&class_buf[..class_len as usize]);

        // Get process name
        let mut process_id = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut process_id));

        let process_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            process_id,
        )
        .map_err(|e| InterceptError::EventMonitor(format!("Failed to open process: {}", e)))?;

        let mut process_name_buf = [0u16; 260]; // MAX_PATH
        let mut size = 260u32;

        // Try to get process image name
        let process_name = if QueryFullProcessImageNameW(
            process_handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(process_name_buf.as_mut_ptr()),
            &mut size,
        ).is_ok() {
            String::from_utf16_lossy(&process_name_buf[..size as usize])
        } else {
            "unknown".to_string()
        };

        CloseHandle(process_handle).ok();

        Ok(WindowInfo {
            title,
            class_name,
            process_name,
        })
    }

    /// Poll for UI changes (fallback if event hooks don't work).
    async fn poll_ui_changes(&self) -> Result<()> {
        let mut last_focused_window: Option<WindowInfo> = None;

        loop {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }

            unsafe {
                let hwnd = GetForegroundWindow();
                if !hwnd.is_invalid() {
                    if let Ok(window_info) = Self::get_window_info(hwnd) {
                        // Check if window changed
                        if Some(&window_info) != last_focused_window.as_ref() {
                            self.handle_window_change(&window_info).await;
                            last_focused_window = Some(window_info);
                        }
                    }
                }
            }

            // Poll every 500ms
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        Ok(())
    }

    /// Handle window focus change.
    async fn handle_window_change(&self, window_info: &WindowInfo) {
        // Detect platform from window title or process name
        let platform = PlatformType::from_process_name(&window_info.process_name);

        // Check if this looks like a messaging window
        if self.is_messaging_window(window_info, platform) {
            let mut event = MessagingEvent::new(
                platform,
                EventType::WindowChange,
                window_info.process_name.clone(),
            )
            .with_window_title(&window_info.title)
            .with_metadata("class_name", &window_info.class_name);

            // Adjust confidence based on window title
            if window_info.title.to_lowercase().contains("compose")
                || window_info.title.to_lowercase().contains("message")
                || window_info.title.to_lowercase().contains("chat") {
                event = event.with_confidence(0.85);
            }

            // Send event
            if let Err(e) = self.event_tx.send(event).await {
                error!("Failed to send event: {}", e);
            }
        }
    }

    /// Check if a window is likely a messaging window.
    fn is_messaging_window(&self, window_info: &WindowInfo, platform: PlatformType) -> bool {
        // Skip if platform is disabled
        if !self.config.is_platform_enabled(platform) {
            return false;
        }

        // Check for common messaging indicators
        let title_lower = window_info.title.to_lowercase();
        let messaging_keywords = [
            "compose", "message", "chat", "direct", "dm",
            "messenger", "inbox", "conversation",
        ];

        messaging_keywords.iter().any(|&keyword| title_lower.contains(keyword))
    }
}

#[async_trait::async_trait]
impl EventMonitor for WindowsEventMonitor {
    async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        info!("Starting Windows event monitor");

        // Initialize UI Automation
        self.initialize_automation()?;

        // Register event handlers
        self.register_event_handlers()?;

        // Start polling loop
        self.running.store(true, Ordering::Relaxed);

        // Spawn polling task using spawn_blocking for Windows API calls
        let event_tx = self.event_tx.clone();
        let config = self.config.clone();
        let running = Arc::clone(&self.running);

        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            let mut last_focused_window: Option<WindowInfo> = None;

            while running.load(Ordering::Relaxed) {
                unsafe {
                    let hwnd = GetForegroundWindow();
                    if !hwnd.is_invalid() {
                        if let Ok(window_info) = WindowsEventMonitor::get_window_info(hwnd) {
                            // Check if window changed
                            if Some(&window_info) != last_focused_window.as_ref() {
                                // Create and send event synchronously
                                let platform = PlatformType::from_process_name(&window_info.process_name);

                                // Check for messaging window
                                let title_lower = window_info.title.to_lowercase();
                                let messaging_keywords = [
                                    "compose", "message", "chat", "direct", "dm",
                                    "messenger", "inbox", "conversation",
                                ];

                                if messaging_keywords.iter().any(|&kw| title_lower.contains(kw))
                                   && config.is_platform_enabled(platform) {
                                    let event = MessagingEvent::new(
                                        platform,
                                        EventType::WindowChange,
                                        window_info.process_name.clone(),
                                    )
                                    .with_window_title(&window_info.title)
                                    .with_metadata("class_name", &window_info.class_name);

                                    let tx = event_tx.clone();
                                    rt.spawn(async move {
                                        if let Err(e) = tx.send(event).await {
                                            error!("Failed to send event: {}", e);
                                        }
                                    });
                                }

                                last_focused_window = Some(window_info);
                            }
                        }
                    }
                }

                // Sleep without async
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        info!("Stopping Windows event monitor");
        self.running.store(false, Ordering::Relaxed);

        // Cleanup COM
        unsafe {
            CoUninitialize();
        }

        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn event_sender(&self) -> &mpsc::Sender<MessagingEvent> {
        &self.event_tx
    }
}

/// Window information.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowInfo {
    title: String,
    class_name: String,
    process_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_messaging_window_detection() {
        let config = InterceptConfig::default();
        let (tx, _rx) = mpsc::channel(10);

        let monitor = WindowsEventMonitor {
            event_tx: tx,
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            automation: SendSyncWrapper::none(),
        };

        let window = WindowInfo {
            title: "Compose - Gmail".to_string(),
            class_name: "Chrome_WidgetWin_1".to_string(),
            process_name: "chrome.exe".to_string(),
        };

        assert!(monitor.is_messaging_window(&window, PlatformType::Gmail));
    }
}
