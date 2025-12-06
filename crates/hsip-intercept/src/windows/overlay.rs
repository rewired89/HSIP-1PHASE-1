//! Windows overlay UI using layered windows.

use crate::{
    InterceptOverlay, UserChoice, MessagingEvent, InterceptConfig, Result, InterceptError,
    overlay::OverlayContent,
};
use tracing::{info, debug};
use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::Graphics::Gdi::*,
    Win32::UI::WindowsAndMessaging::*,
};
use std::sync::{Arc, Mutex};

/// Windows overlay implementation using layered window.
pub struct WindowsOverlay {
    config: InterceptConfig,
    hwnd: Arc<Mutex<Option<HWND>>>,
    choice: Arc<Mutex<Option<UserChoice>>>,
}

impl WindowsOverlay {
    /// Create a new Windows overlay.
    pub fn new(config: &InterceptConfig) -> Result<Box<dyn InterceptOverlay>> {
        Ok(Box::new(Self {
            config: config.clone(),
            hwnd: Arc::new(Mutex::new(None)),
            choice: Arc::new(Mutex::new(None)),
        }))
    }

    /// Create the overlay window.
    fn create_overlay_window(&self, content: &OverlayContent) -> Result<HWND> {
        unsafe {
            // Register window class
            let class_name = w!("HSIPInterceptOverlay");
            let h_instance = GetModuleHandleW(None)
                .map_err(|e| InterceptError::Overlay(format!("GetModuleHandle failed: {}", e)))?;

            let wc = WNDCLASSW {
                lpfnWndProc: Some(Self::window_proc),
                hInstance: h_instance.into(),
                lpszClassName: class_name,
                hCursor: LoadCursorW(None, IDC_ARROW).ok(),
                hbrBackground: HBRUSH(GetStockObject(BLACK_BRUSH).0),
                ..Default::default()
            };

            RegisterClassW(&wc);

            // Calculate window position based on config
            let (x, y, width, height) = self.calculate_overlay_position();

            // Create layered window (always on top, transparent)
            let hwnd = CreateWindowExW(
                WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                class_name,
                w!("HSIP Intercept"),
                WS_POPUP,
                x,
                y,
                width,
                height,
                None,
                None,
                h_instance,
                None,
            )
            .map_err(|e| InterceptError::Overlay(format!("CreateWindow failed: {}", e)))?;

            // Set window transparency
            SetLayeredWindowAttributes(hwnd, COLORREF(0), 240, LWA_ALPHA)
                .map_err(|e| InterceptError::Overlay(format!("SetLayeredWindowAttributes failed: {}", e)))?;

            // Show window
            ShowWindow(hwnd, SW_SHOW);
            UpdateWindow(hwnd).ok();

            info!("Overlay window created: {:?}", hwnd);
            Ok(hwnd)
        }
    }

    /// Calculate overlay position based on configuration.
    fn calculate_overlay_position(&self) -> (i32, i32, i32, i32) {
        unsafe {
            let screen_width = GetSystemMetrics(SM_CXSCREEN);
            let screen_height = GetSystemMetrics(SM_CYSCREEN);

            let width = 400;
            let height = 200;

            let (x, y) = match self.config.overlay.position {
                crate::config::OverlayPosition::TopRight => {
                    (screen_width - width - 20, 20)
                }
                crate::config::OverlayPosition::TopLeft => {
                    (20, 20)
                }
                crate::config::OverlayPosition::BottomRight => {
                    (screen_width - width - 20, screen_height - height - 20)
                }
                crate::config::OverlayPosition::BottomLeft => {
                    (20, screen_height - height - 20)
                }
                crate::config::OverlayPosition::Center => {
                    ((screen_width - width) / 2, (screen_height - height) / 2)
                }
            };

            (x, y, width, height)
        }
    }

    /// Window procedure for overlay window.
    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);

                // Draw overlay content
                // TODO: Implement proper UI rendering
                // For now, just fill with semi-transparent background

                let mut rect = RECT::default();
                GetClientRect(hwnd, &mut rect).ok();

                // Fill background
                let brush = CreateSolidBrush(COLORREF(0x00333333));
                FillRect(hdc, &rect, brush);
                DeleteObject(brush).ok();

                // Draw text
                let text = w!("🔒 Send through HSIP instead?");
                SetTextColor(hdc, COLORREF(0x00FFFFFF));
                SetBkMode(hdc, TRANSPARENT);

                DrawTextW(
                    hdc,
                    &mut text.as_wide(),
                    &mut rect,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                );

                EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            WM_LBUTTONDOWN => {
                // User clicked - simulate "Send Privately" choice
                // TODO: Implement proper button detection
                PostMessageW(hwnd, WM_CLOSE, WPARAM(1), LPARAM(0)).ok();
                LRESULT(0)
            }
            WM_RBUTTONDOWN => {
                // Right click - simulate "Continue" choice
                PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0)).ok();
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    /// Wait for user interaction with the overlay.
    async fn wait_for_choice(&self, hwnd: HWND) -> Result<UserChoice> {
        // Run message loop in background thread
        let choice_arc = Arc::clone(&self.choice);

        let handle = std::thread::spawn(move || unsafe {
            let mut msg = MSG::default();

            while GetMessageW(&mut msg, None, 0, 0).into() {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);

                if msg.message == WM_CLOSE {
                    // wparam indicates choice: 1 = Send Privately, 0 = Continue
                    let choice = if msg.wParam.0 == 1 {
                        UserChoice::SendPrivately
                    } else {
                        UserChoice::Continue
                    };

                    *choice_arc.lock().unwrap() = Some(choice);
                    break;
                }
            }
        });

        // Wait for choice with timeout
        let timeout = std::time::Duration::from_secs(self.config.overlay.timeout_seconds as u64);
        let start = std::time::Instant::now();

        loop {
            if let Some(choice) = self.choice.lock().unwrap().clone() {
                return Ok(choice);
            }

            if start.elapsed() > timeout {
                // Timeout - auto-dismiss as "Continue"
                debug!("Overlay timeout, auto-dismissing");
                unsafe {
                    PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0)).ok();
                }
                return Ok(UserChoice::Continue);
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

#[async_trait::async_trait]
impl InterceptOverlay for WindowsOverlay {
    async fn show(&mut self, event: &MessagingEvent, recipient: Option<&str>) -> Result<UserChoice> {
        info!("Showing Windows overlay");

        let content = OverlayContent::from_event(event, recipient);

        // Create overlay window
        let hwnd = self.create_overlay_window(&content)?;
        *self.hwnd.lock().unwrap() = Some(hwnd);

        // Wait for user choice
        let choice = self.wait_for_choice(hwnd).await?;

        // Cleanup
        self.hide().await?;

        Ok(choice)
    }

    async fn hide(&mut self) -> Result<()> {
        if let Some(hwnd) = self.hwnd.lock().unwrap().take() {
            unsafe {
                DestroyWindow(hwnd)
                    .map_err(|e| InterceptError::Overlay(format!("DestroyWindow failed: {}", e)))?;
            }
            info!("Overlay hidden");
        }
        Ok(())
    }

    fn is_visible(&self) -> bool {
        self.hwnd.lock().unwrap().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_creation() {
        let config = InterceptConfig::default();
        let overlay = WindowsOverlay::new(&config);
        assert!(overlay.is_ok());
    }

    #[test]
    fn test_position_calculation() {
        let config = InterceptConfig::default();
        let overlay = WindowsOverlay::new(&config).unwrap();

        // Just verify it doesn't crash
        let (x, y, w, h) = overlay.calculate_overlay_position();
        assert!(w > 0);
        assert!(h > 0);
    }
}
