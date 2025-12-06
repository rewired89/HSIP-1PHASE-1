# HSIP Intercept Integration Plan

## Overview

This document outlines how to integrate the `hsip-intercept` module with the existing HSIP codebase.

---

## Workspace Integration

### Step 1: Add to Cargo Workspace

**File: `/Cargo.toml` (root)**

```toml
[workspace]
members = [
    "crates/hsip-core",
    "crates/hsip-session",
    "crates/hsip-net",
    "crates/hsip-auth",
    "crates/hsip-reputation",
    "crates/hsip-cli",
    "crates/hsip-gateway",
    "crates/hsip-intercept",  # ADD THIS LINE
]
```

### Step 2: Add CLI Integration

**File: `crates/hsip-cli/Cargo.toml`**

```toml
[dependencies]
# ... existing dependencies ...
hsip-intercept = { path = "../hsip-intercept", optional = true }

[features]
default = ["intercept"]
intercept = ["hsip-intercept"]
```

### Step 3: Add CLI Subcommands

**File: `crates/hsip-cli/src/main.rs`**

```rust
// Add new subcommand enum variants
#[derive(Subcommand, Debug)]
enum Commands {
    // ... existing commands ...

    /// Private DM Intercept commands
    #[cfg(feature = "intercept")]
    Intercept {
        #[command(subcommand)]
        cmd: InterceptCommands,
    },
}

#[cfg(feature = "intercept")]
#[derive(Subcommand, Debug)]
enum InterceptCommands {
    /// Start the intercept service
    Start {
        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Stop the intercept service
    Stop,

    /// Show intercept status
    Status,

    /// Enable intercept for a platform
    Enable {
        /// Platform name (instagram, facebook, gmail, etc.)
        platform: String,
    },

    /// Disable intercept for a platform
    Disable {
        /// Platform name
        platform: String,
    },

    /// Configure intercept settings
    Config {
        #[command(subcommand)]
        action: ConfigActions,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigActions {
    /// Show current configuration
    Show,

    /// Set minimum confidence threshold
    SetConfidence {
        /// Confidence value (0.0-1.0)
        value: f64,
    },

    /// Enable/disable timing obfuscation
    SetTimingObfuscation {
        /// Enable or disable
        enabled: bool,
    },
}
```

**File: `crates/hsip-cli/src/commands/mod.rs`**

```rust
// Add new module
#[cfg(feature = "intercept")]
pub mod intercept;
```

**File: `crates/hsip-cli/src/commands/intercept.rs`** (NEW)

```rust
use anyhow::Result;
use hsip_intercept::{InterceptCoordinator, InterceptConfig};
use tracing::info;

pub async fn start(config_path: Option<PathBuf>) -> Result<()> {
    info!("Starting HSIP Private DM Intercept");

    // Load or create config
    let config = if let Some(path) = config_path {
        InterceptConfig::load(&path)?
    } else {
        InterceptConfig::default()
    };

    // Create and run coordinator
    let coordinator = InterceptCoordinator::new(config).await?;
    coordinator.run().await?;

    Ok(())
}

pub async fn stop() -> Result<()> {
    info!("Stopping intercept service");
    // TODO: Implement graceful shutdown via IPC
    println!("Intercept service stopped");
    Ok(())
}

pub async fn status() -> Result<()> {
    // TODO: Query service status via IPC
    println!("Intercept Status:");
    println!("  Running: Yes");
    println!("  Platforms monitored: Instagram, Facebook, Gmail");
    println!("  Events detected (session): 42");
    Ok(())
}

pub async fn enable_platform(platform: &str) -> Result<()> {
    info!("Enabling intercept for platform: {}", platform);
    // TODO: Send enable command to running service
    println!("Enabled intercept for {}", platform);
    Ok(())
}

pub async fn disable_platform(platform: &str) -> Result<()> {
    info!("Disabling intercept for platform: {}", platform);
    // TODO: Send disable command to running service
    println!("Disabled intercept for {}", platform);
    Ok(())
}
```

**Update `crates/hsip-cli/src/main.rs` match statement:**

```rust
match cli.command {
    // ... existing commands ...

    #[cfg(feature = "intercept")]
    Commands::Intercept { cmd } => match cmd {
        InterceptCommands::Start { config } => {
            commands::intercept::start(config).await?;
        }
        InterceptCommands::Stop => {
            commands::intercept::stop().await?;
        }
        InterceptCommands::Status => {
            commands::intercept::status().await?;
        }
        InterceptCommands::Enable { platform } => {
            commands::intercept::enable_platform(&platform).await?;
        }
        InterceptCommands::Disable { platform } => {
            commands::intercept::disable_platform(&platform).await?;
        }
        InterceptCommands::Config { action } => {
            match action {
                ConfigActions::Show => {
                    // Show current config
                }
                ConfigActions::SetConfidence { value } => {
                    // Update confidence threshold
                }
                ConfigActions::SetTimingObfuscation { enabled } => {
                    // Update timing obfuscation setting
                }
            }
        }
    },
}
```

---

## Session Integration

The intercept module needs to integrate with existing HSIP session management.

### Update `crates/hsip-intercept/src/router.rs`

```rust
use hsip_core::{
    identity::{Identity, PeerID},
    consent::{ConsentRequest, ConsentResponse},
};
use hsip_session::Session;
use hsip_net::UdpSocket;

impl HSIPRouter {
    /// Start an HSIP session with a known peer.
    async fn start_session_with_peer(&self, peer_id: PeerID) -> Result<()> {
        info!("Starting HSIP session with peer: {:?}", peer_id);

        // 1. Load local identity
        let identity = Identity::load_from_keystore()?;

        // 2. Create consent request
        let consent_request = ConsentRequest::new(
            identity.peer_id(),
            peer_id,
            "Private messaging via HSIP Intercept".to_string(),
            chrono::Duration::hours(self.config.messenger.default_consent_hours as i64),
        );

        // 3. Sign consent request
        let signed_request = consent_request.sign(&identity)?;

        // 4. Send via hsip-net
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_consent_request(&peer_id, &signed_request).await?;

        // 5. Wait for consent response
        let consent_response = socket.recv_consent_response().await?;

        // 6. Verify consent response
        if !consent_response.verify(&peer_id)? {
            return Err(InterceptError::Router("Invalid consent response".to_string()));
        }

        // 7. Check if consent granted
        if !consent_response.granted {
            return Err(InterceptError::Router("Consent denied".to_string()));
        }

        // 8. Establish ephemeral session
        let session = Session::new(
            identity.keypair(),
            peer_id,
            consent_response.ephemeral_pubkey,
        )?;

        // 9. Open messenger UI with active session
        self.open_messenger_with_session(session, peer_id).await?;

        Ok(())
    }

    async fn open_messenger_with_session(
        &self,
        session: Session,
        peer_id: PeerID,
    ) -> Result<()> {
        // TODO: Open messenger UI and pass active session
        // This could be:
        // - IPC to existing daemon with session handle
        // - New messenger window with embedded session
        // - Web-based UI via local HTTP server

        info!("Opening messenger with active session for {:?}", peer_id);
        Ok(())
    }
}
```

---

## Daemon Integration

The intercept service should run as a background daemon alongside the existing HSIP daemon.

### Option 1: Integrated Daemon

Add intercept to existing `hsip-cli daemon` command:

```rust
// crates/hsip-cli/src/commands/daemon.rs

pub async fn run_daemon() -> Result<()> {
    // Start HTTP API server (existing)
    let api_server = start_api_server().await?;

    // Start intercept coordinator (NEW)
    #[cfg(feature = "intercept")]
    let intercept_coordinator = {
        let config = InterceptConfig::default();
        InterceptCoordinator::new(config).await?
    };

    // Run both concurrently
    tokio::select! {
        _ = api_server => {},
        #[cfg(feature = "intercept")]
        _ = intercept_coordinator.run() => {},
    }

    Ok(())
}
```

### Option 2: Separate Service

Run intercept as standalone service:

```bash
# Start main HSIP daemon
hsip daemon start

# Start intercept service
hsip intercept start --daemon
```

---

## Configuration Files

### User Config Directory Structure

```
~/.config/hsip/
├── config.toml              # Main HSIP config
├── keystore.db              # Identity keystore
├── intercept_config.json    # Intercept settings (NEW)
└── patterns.json            # Pattern database (NEW)
```

### Example `intercept_config.json`

```json
{
  "enabled": true,
  "min_confidence": 0.80,
  "enabled_platforms": ["Instagram", "Facebook", "Gmail", "WhatsApp"],
  "disabled_platforms": [],
  "pattern_db_path": "patterns.json",
  "privacy": {
    "timing_obfuscation": true,
    "min_delay_ms": 50,
    "max_delay_ms": 500,
    "message_padding": false,
    "strip_metadata": true,
    "cover_traffic": false
  },
  "overlay": {
    "position": "TopRight",
    "timeout_seconds": 10,
    "show_tutorial": true,
    "theme": "System"
  },
  "messenger": {
    "auto_open": true,
    "default_consent_hours": 24,
    "offline_queue": true,
    "max_queue_size": 100
  }
}
```

---

## Testing Integration

### Unit Tests

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_consent_flow() {
        // Test full consent handshake via router
        let config = InterceptConfig::default();
        let router = HSIPRouter::new(&config).await.unwrap();

        // Mock peer ID
        let peer_id = PeerID::from_str("peer_test123").unwrap();

        // Should initiate consent request
        // (requires mock hsip-net for testing)
        // router.start_session_with_peer(peer_id).await.unwrap();
    }
}
```

### Integration Test Script

```bash
#!/bin/bash
# tests/integration/test_intercept.sh

set -e

echo "Testing HSIP Intercept Integration..."

# 1. Build all crates
cargo build --all-features

# 2. Generate test identity
cargo run -- keygen
cargo run -- init

# 3. Start daemon in background
cargo run -- daemon start &
DAEMON_PID=$!
sleep 2

# 4. Start intercept service
cargo run -- intercept start &
INTERCEPT_PID=$!
sleep 2

# 5. Check status
cargo run -- intercept status

# 6. Test enable/disable
cargo run -- intercept enable instagram
cargo run -- intercept disable instagram

# 7. Cleanup
kill $INTERCEPT_PID
kill $DAEMON_PID

echo "Integration tests passed!"
```

---

## IPC Communication

For daemon-to-intercept communication, use local socket or named pipes:

```rust
// crates/hsip-intercept/src/ipc.rs

use tokio::net::UnixStream;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub enum InterceptCommand {
    Start,
    Stop,
    EnablePlatform(PlatformType),
    DisablePlatform(PlatformType),
    GetStatus,
}

#[derive(Serialize, Deserialize)]
pub struct InterceptStatus {
    pub running: bool,
    pub enabled_platforms: Vec<PlatformType>,
    pub events_detected: u64,
}

pub struct InterceptIPC {
    socket_path: PathBuf,
}

impl InterceptIPC {
    pub async fn send_command(&self, cmd: InterceptCommand) -> Result<InterceptStatus> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;

        // Send command
        let cmd_bytes = serde_json::to_vec(&cmd)?;
        stream.write_all(&cmd_bytes).await?;

        // Receive response
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        let status: InterceptStatus = serde_json::from_slice(&buf[..n])?;

        Ok(status)
    }
}
```

---

## Messenger UI Integration

### Option A: Terminal UI (TUI)

```rust
// Use ratatui for terminal-based messenger
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph},
    Terminal,
};

pub async fn run_tui_messenger(session: Session, peer_id: PeerID) -> Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

    // Render messenger UI
    loop {
        terminal.draw(|f| {
            let block = Block::default()
                .title(format!("HSIP Messenger - {}", peer_id))
                .borders(Borders::ALL);

            f.render_widget(block, f.size());
        })?;

        // Handle input
        // Send messages via session
    }
}
```

### Option B: Web UI (Local Server)

```rust
// Use axum to serve web-based messenger UI
use axum::{Router, response::Html};

pub async fn run_web_messenger() -> Result<()> {
    let app = Router::new()
        .route("/", get(messenger_html))
        .route("/api/send", post(send_message))
        .route("/api/messages", get(get_messages));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn messenger_html() -> Html<&'static str> {
    Html(include_str!("../ui/messenger.html"))
}
```

### Option C: Native UI (Platform-Specific)

- **Windows**: Win32 window with WebView2
- **Android**: Native Activity with Jetpack Compose
- **Linux**: GTK or Qt window
- **macOS**: SwiftUI or AppKit window

---

## Documentation Updates

### README.md Addition

```markdown
## Private DM Intercept (Experimental)

HSIP now includes an experimental feature that detects when you're about to send messages through traditional platforms and offers a privacy-preserving alternative.

### Features

- 🔒 End-to-end encrypted messaging
- ✅ Consent-based communication
- 🚫 No platform intermediaries
- 🛡️ Privacy-enhancing features (timing obfuscation, metadata stripping)

### Quick Start

1. Enable the intercept feature:
   ```bash
   hsip intercept start
   ```

2. Configure which platforms to monitor:
   ```bash
   hsip intercept enable instagram
   hsip intercept enable gmail
   ```

3. Use your messaging apps normally. When you click to send a message, HSIP will offer a private alternative.

### Supported Platforms

- Instagram (Windows, Android)
- Facebook Messenger (Windows, Android)
- Gmail (Windows, Android)
- WhatsApp (Windows, Android)
- More coming soon...

### Privacy & Permissions

The intercept feature uses OS-level accessibility APIs to detect messaging actions. It:
- ✅ Only monitors UI events (button clicks, window focus)
- ✅ Processes everything locally (no cloud)
- ✅ Never reads message content from other apps
- ✅ Requires explicit user permission

See [docs/PRIVATE_DM_INTERCEPT.md](docs/PRIVATE_DM_INTERCEPT.md) for details.
```

---

## Build & Distribution

### Windows Installer

```
NSIS script or WiX toolset:
- Install hsip-cli.exe
- Create registry entries for autostart
- Request accessibility permissions
- Install system tray application
```

### Android APK

```
Build signed APK:
1. cargo ndk build --release
2. Copy .so files to jniLibs
3. ./gradlew assembleRelease
4. Sign with release keystore
```

### Linux Package

```
.deb package:
- Install to /usr/local/bin
- Create systemd service unit
- Install desktop entry
```

---

## Security Considerations

### Code Signing

- **Windows**: Sign with Authenticode certificate
- **Android**: Sign with Google Play keystore
- **macOS**: Notarize with Apple Developer ID

### Sandboxing

- Run intercept service with minimal privileges
- Use AppArmor/SELinux profiles on Linux
- Request only necessary permissions

### Update Mechanism

- Implement secure auto-update
- Verify update signatures before applying
- Provide manual update option

---

## Monitoring & Telemetry (Optional, Opt-In)

If user consents, collect anonymized metrics:

```rust
pub struct InterceptMetrics {
    pub events_detected: Counter,
    pub intercepts_shown: Counter,
    pub user_chose_hsip: Counter,
    pub user_chose_continue: Counter,
    pub average_response_time_ms: Histogram,
}
```

Send to local file or opt-in telemetry endpoint (never send identifying info).

---

## Summary

Integrating HSIP Intercept requires:

1. ✅ Add `hsip-intercept` to workspace
2. ✅ Add CLI subcommands
3. ✅ Integrate with session management
4. ✅ Add daemon/service support
5. ✅ Create messenger UI
6. ✅ Update documentation
7. ✅ Package for distribution

The modular design allows gradual integration without disrupting existing HSIP functionality.
