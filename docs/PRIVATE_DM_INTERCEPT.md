# HSIP Private DM Intercept

## Overview

The **Private DM Intercept** feature detects when users attempt to send messages through traditional platforms (Instagram, Facebook, Gmail, etc.) and offers a privacy-preserving alternative by routing messages through HSIP's consent-based, end-to-end encrypted protocol.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    HSIP Private DM Intercept                     │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌────────────────┐    ┌──────────────┐
│ Event Monitor │    │ Intercept UI   │    │ HSIP Router  │
│   (OS-level)  │───▶│   (Overlay)    │───▶│  (Session)   │
└───────────────┘    └────────────────┘    └──────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌────────────────┐    ┌──────────────┐
│ Accessibility │    │  Notification  │    │   Consent    │
│   Services    │    │     System     │    │  Handshake   │
└───────────────┘    └────────────────┘    └──────────────┘
```

### Core Components

1. **Event Monitor**: OS-level accessibility listener that detects messaging actions
2. **Intercept UI**: Minimal overlay that prompts user to choose HSIP or continue normally
3. **HSIP Router**: Routes messages through HSIP protocol with consent handshake
4. **Messenger Module**: Dedicated HSIP messaging interface (P2P encrypted sessions)

---

## System Flow

```
┌──────────────┐
│ User clicks  │
│ "DM" button  │
│ in Instagram │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────┐
│ OS Accessibility Event       │
│ Detected: ACTION_CLICKED     │
│ Class: com.instagram.dm.btn  │
└──────┬───────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│ Pattern Matcher              │
│ Recognizes: Messaging Action │
└──────┬───────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│ HSIP Intercept Overlay       │
│ "Send through HSIP instead?" │
│ [Send Privately] [Continue]  │
└──────┬───────────────────────┘
       │
       ├─────────────┬──────────────┐
       ▼             ▼              ▼
┌─────────────┐ ┌────────────┐ ┌──────────┐
│ Send        │ │  Continue  │ │ Dismiss  │
│ Privately   │ │  Normally  │ │          │
└─────┬───────┘ └────────────┘ └──────────┘
      │
      ▼
┌─────────────────────────────┐
│ Open HSIP Messenger         │
│ - Extract recipient (if ID) │
│ - Initiate consent request  │
│ - Start encrypted session   │
└─────────────────────────────┘
      │
      ▼
┌─────────────────────────────┐
│ P2P Encrypted Message       │
│ via HSIP Protocol           │
│ (No platform intermediary)  │
└─────────────────────────────┘
```

---

## Event Detection Strategy

### Windows (UI Automation API)
- Monitor `UIA_InvokePatternId` and `UIA_ValueChangedEventId`
- Filter by window class names: `Chrome_WidgetWin_1`, `ApplicationFrameWindow`
- Match accessibility IDs for known messaging buttons
- Hook into window title changes (e.g., "New Message - Gmail")

### Android (Accessibility Services)
- Subscribe to `AccessibilityEvent.TYPE_VIEW_CLICKED`
- Match view resource IDs:
  - `com.instagram.android:id/row_inbox_container`
  - `com.facebook.katana:id/messaging_button`
  - `com.google.android.gm:id/compose`
- Check parent/sibling views for context confirmation

### iOS (Accessibility + App Intents)
⚠️ **iOS Limitations**: Apple's sandbox prevents cross-app monitoring
- **Alternative**: Build HSIP Share Extension instead
  - Users manually share via iOS Share Sheet
  - HSIP appears as share target
  - No automatic detection (Apple policy compliant)

---

## Pattern Recognition Database

### Messaging Trigger Patterns

```json
{
  "patterns": [
    {
      "platform": "instagram",
      "triggers": [
        {
          "type": "accessibility_id",
          "value": "direct_inbox_button",
          "confidence": 0.95
        },
        {
          "type": "class_name",
          "value": "DirectThreadView",
          "confidence": 0.85
        },
        {
          "type": "text_content",
          "value": "Send Message",
          "confidence": 0.70
        }
      ]
    },
    {
      "platform": "facebook",
      "triggers": [
        {
          "type": "resource_id",
          "value": "com.facebook.katana:id/messaging_button",
          "confidence": 0.95
        }
      ]
    },
    {
      "platform": "gmail",
      "triggers": [
        {
          "type": "window_title",
          "value": "Compose - Gmail",
          "confidence": 0.90
        },
        {
          "type": "automation_id",
          "value": "compose_button",
          "confidence": 0.85
        }
      ]
    },
    {
      "platform": "whatsapp",
      "triggers": [
        {
          "type": "accessibility_id",
          "value": "chat_input_field",
          "confidence": 0.90
        }
      ]
    }
  ]
}
```

---

## Privacy & Security Boundaries

### ✅ Allowed Operations

1. **OS-Level Event Listening**
   - Accessibility events (button clicks, window focus)
   - UI element metadata (class names, IDs)
   - Window titles and process names

2. **Local Processing**
   - Pattern matching on accessibility metadata
   - Recipient extraction from visible UI elements
   - Local overlay rendering

3. **User Consent**
   - Explicit permission prompts (accessibility access)
   - Per-app enable/disable toggles
   - Audit log of intercept events

### ❌ Prohibited Operations

1. **No Data Exfiltration**
   - No reading message content from other apps
   - No screenshotting or OCR of foreign UI
   - No network requests for analytics

2. **No App Modification**
   - No code injection
   - No hooking system calls
   - No modifying other apps' memory

3. **No Deceptive Practices**
   - Clear user notification when active
   - Transparent about what data is accessed
   - Easy disable mechanism

### Privacy Enhancements

#### Timing Obfuscation
```rust
// Add random delay to mask user typing patterns
let jitter = thread_rng().gen_range(50..500); // 50-500ms
tokio::time::sleep(Duration::from_millis(jitter)).await;
```

#### Metadata Hiding
- Strip EXIF data from shared images
- Normalize message send times to 5-minute windows
- Add cover traffic for active sessions

#### Cover Traffic Mode (Future)
- Send dummy packets at regular intervals
- Indistinguishable from real messages
- Configurable intensity (low/medium/high)

---

## Platform-Specific Implementation

### Windows Implementation

**Technology Stack:**
- Rust with `windows-rs` crate
- UI Automation API (`IUIAutomation`)
- Win32 overlay windows (layered, topmost)

**Key APIs:**
- `SetWinEventHook`: Monitor window events
- `IUIAutomation::AddAutomationEventHandler`: UI element events
- `CreateWindowEx` with `WS_EX_LAYERED | WS_EX_TOPMOST`: Overlay

### Android Implementation

**Technology Stack:**
- Kotlin/Java with Accessibility Services
- Jetpack Compose for overlay UI
- SYSTEM_ALERT_WINDOW permission

**Key APIs:**
- `AccessibilityService`: Event monitoring
- `WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY`: Floating UI
- `AccessibilityNodeInfo`: UI tree traversal

### iOS Alternative (Share Extension)

Since iOS prohibits cross-app monitoring:
- Build iOS Share Extension target
- User manually selects HSIP from Share Sheet
- Extension extracts recipient and launches HSIP Messenger
- Complies with App Store guidelines

---

## HSIP Messenger Module

### Features

1. **Recipient Resolution**
   - PeerID lookup via DHT
   - Contact book integration
   - QR code exchange
   - Deep link support (`hsip://peer/<peer-id>`)

2. **Session Management**
   - Consent request with expiration
   - Ephemeral key exchange
   - Message queue for offline peers
   - Session resumption on network change

3. **UI Components**
   - Minimalist chat interface
   - Consent status indicator
   - End-to-end encryption badge
   - Message delivery receipts (optional)

### Architecture

```
┌─────────────────────────────────────────┐
│         HSIP Messenger Window           │
├─────────────────────────────────────────┤
│  To: alice@hsip (peer_abc123...)        │
│  Status: ● Consent Granted (2h left)    │
├─────────────────────────────────────────┤
│  [Encrypted Chat Messages]              │
│                                          │
│  You: Hey, switching to HSIP! 🔒        │
│  Alice: Got it, private now ✓           │
│                                          │
├─────────────────────────────────────────┤
│  [Type message...]            [Send] 🔐 │
└─────────────────────────────────────────┘
```

---

## User Experience Flow

### First-Time Setup

1. **Install HSIP Client**
   - Generate identity keypair
   - Request OS permissions (accessibility, overlay)

2. **Enable Intercept**
   - Settings → Private DM Intercept → Enable
   - Select apps to monitor (Instagram, Facebook, Gmail, etc.)
   - Grant accessibility permission

3. **First Intercept**
   - User clicks DM in Instagram
   - Overlay appears: "🔒 Send through HSIP instead?"
   - Tutorial tooltip: "HSIP offers end-to-end encrypted messaging without platform tracking"

### Daily Usage

1. User opens messaging app as normal
2. Clicks to start new message
3. HSIP overlay appears (0.3s fade-in)
4. User chooses:
   - **Send Privately** → HSIP Messenger opens
   - **Continue** → Overlay dismisses, proceed normally
   - **Don't Ask for [App]** → Disable for this app

---

## Security Considerations

### Threat Model

**Attacker Capabilities:**
- Network-level adversary (ISP, VPN provider)
- Platform provider (Meta, Google)
- Malware on user device
- Social engineering

**HSIP Protections:**
- E2E encryption (no platform can read)
- Consent-based access (no unsolicited contact)
- Ephemeral sessions (forward secrecy)
- Local processing (no cloud intermediary)

**Limitations:**
- Cannot protect against compromised OS
- Requires both users to have HSIP
- Platform may detect HSIP usage (metadata)

### Metadata Leakage

Even with HSIP, metadata can leak:
- **Timing**: When messages are sent
- **Frequency**: How often users communicate
- **Size**: Message/attachment sizes
- **Network**: IP addresses, ISP

**Mitigations:**
- Timing obfuscation (random delays)
- Message padding (normalize sizes)
- Tor/VPN integration (hide IP)
- Cover traffic (constant rate)

---

## Compliance & Ethics

### User Consent
- ✅ Explicit permission prompts
- ✅ Clear privacy policy
- ✅ Opt-in by default (disabled until user enables)
- ✅ Per-app granular controls

### Platform Policies
- ⚠️ Windows: Generally allowed (enterprise use case)
- ⚠️ Android: Allowed if accessibility justified (privacy tool)
- ❌ iOS: Not allowed (use Share Extension instead)
- ⚠️ Google Play: May require privacy review
- ❌ App Store: Cannot monitor other apps

### Legal Considerations
- Must comply with wiretapping laws (user owns both ends)
- GDPR: No data collection, local processing only
- CCPA: No sale of data
- Consider legal review before deployment

---

## Development Roadmap

### Phase 1: MVP (Core Functionality)
- Windows event detection (UI Automation)
- Basic overlay UI (Windows only)
- Manual peer ID entry
- Text-only messaging
- Local consent cache

**Deliverables:**
- `hsip-intercept` crate
- Windows event monitor
- Basic overlay window
- Integration with `hsip-cli`

### Phase 2: Beta (Platform Expansion)
- Android event detection (Accessibility Services)
- Android overlay UI (floating window)
- iOS Share Extension (manual sharing)
- Contact book integration
- Recipient auto-fill (from UI context)
- Pattern recognition database
- Settings UI (enable/disable per app)

**Deliverables:**
- Android AccessibilityService
- iOS Share Extension target
- Pattern matcher engine
- Settings panel in `hsip-cli`

### Phase 3: Stable (Polish & Privacy)
- Linux support (X11/Wayland accessibility)
- macOS support (Accessibility API)
- Timing obfuscation
- Message padding
- Cover traffic mode
- Offline message queue
- Multi-device sync
- Audit logging

**Deliverables:**
- Cross-platform event detection
- Privacy enhancement suite
- Compliance documentation
- Security audit report

---

## Testing Strategy

### Unit Tests
- Pattern matcher accuracy
- Consent flow logic
- Message encryption/decryption
- Overlay rendering

### Integration Tests
- Event detection across platforms
- HSIP session establishment
- Messenger UI workflow
- Permission handling

### User Testing
- Privacy-conscious users (target audience)
- Accessibility compliance (screen readers)
- Performance impact (battery, CPU)
- False positive rate (incorrect detections)

### Security Testing
- Fuzz accessibility event inputs
- Test with malicious patterns
- Verify no data leakage
- Audit permission usage

---

## Open Questions

1. **Recipient Discovery**: How to map platform usernames to HSIP PeerIDs?
   - Option A: Manual contact book (user adds mappings)
   - Option B: Decentralized directory (DHT with username → PeerID)
   - Option C: QR code exchange
   - **Decision**: Start with manual (MVP), add DHT later

2. **Offline Messages**: What happens if recipient is offline?
   - Option A: Store locally and retry
   - Option B: Use relay server (breaks P2P purity)
   - Option C: Notify user, don't send
   - **Decision**: Local queue with retry (MVP), explore relays later

3. **Platform Detection**: How reliable is pattern matching?
   - Test with multiple app versions
   - Build update mechanism for pattern database
   - Fallback to generic "messaging action" detection

4. **User Adoption**: How to onboard both sender and receiver?
   - Build viral loop (invite friends)
   - Standalone value (even if recipient doesn't have HSIP, archive encrypted)
   - Interop mode (send via platform, but archive via HSIP)

---

## Success Metrics

### Privacy Metrics
- % of messages sent via HSIP vs platform
- Number of consent handshakes initiated
- Session duration (longer = better UX)

### Performance Metrics
- Event detection latency (<100ms target)
- Overlay render time (<50ms)
- Battery impact (<2% additional drain)
- Memory footprint (<50MB)

### Adoption Metrics
- Daily active users
- Apps with intercept enabled
- Average messages per session
- User retention (30-day)

---

## Future Enhancements

### Advanced Features
- **Voice/Video Calls**: Intercept call buttons, route through HSIP WebRTC
- **File Sharing**: Intercept file pickers, encrypt via HSIP
- **Group Chats**: Multi-party consent with group keys
- **Cross-Device Sync**: Sync conversations across user's devices

### Privacy Innovations
- **Steganography**: Hide HSIP messages in platform noise
- **Deniability**: Plausible deniability for HSIP usage
- **Quantum Resistance**: Post-quantum key exchange (reserved capability bits)

### Platform Integration
- **Browser Extension**: Detect web-based messaging (WhatsApp Web, FB Messenger)
- **Email Client**: Intercept Outlook/Thunderbird compose
- **SMS/MMS**: Route SMS through HSIP on mobile

---

## Conclusion

The **HSIP Private DM Intercept** feature transforms HSIP from a standalone protocol into an ambient privacy layer that empowers users to reclaim control over their communications. By leveraging OS-level accessibility APIs (designed for assistive technology), we can offer a privacy-preserving alternative without modifying or monitoring the content of other applications.

**Key Principles:**
1. **User sovereignty**: User explicitly chooses HSIP or platform
2. **Transparency**: Clear about what's monitored (only metadata)
3. **Privacy by design**: Local processing, no cloud dependency
4. **Standards compliance**: Use official OS APIs only
5. **Ethical development**: Respect platform policies and user trust

This feature has the potential to make end-to-end encrypted, consent-based communication accessible to mainstream users without requiring them to abandon familiar platforms.
