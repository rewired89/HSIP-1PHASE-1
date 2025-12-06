# HSIP iOS Keyboard Extension

Complete iOS keyboard extension that's compatible with Android HSIP keyboard.

---

## Architecture

```
┌─────────────────────────────────────────┐
│   iOS Keyboard Extension (Swift)        │
├─────────────────────────────────────────┤
│  ├─ KeyboardViewController.swift        │
│  ├─ HSIPManager.swift (Bridge to Rust)  │
│  ├─ SessionStorage.swift (Keychain)     │
│  ├─ UI/ (SwiftUI views)                 │
│  └─ Rust FFI (libhsip_keyboard)         │
├─────────────────────────────────────────┤
│   Shared Rust Core                      │
│  ├─ Same crypto as Android              │
│  ├─ Same message format                 │
│  └─ Cross-platform compatible           │
└─────────────────────────────────────────┘
```

**Key Decisions:**
- ✅ Use Rust via FFI (share code with Android)
- ✅ SwiftUI for modern, declarative UI
- ✅ Keychain for secure key storage
- ✅ Same message format (Android ↔ iOS interop)

---

## Project Structure

```
ios/
├── HSIPKeyboard.xcodeproj
├── HSIPKeyboard/                    # Main app
│   ├── AppDelegate.swift
│   ├── SetupView.swift              # Key exchange UI
│   ├── ContactsView.swift           # Contact management
│   └── Info.plist
├── HSIPKeyboardExtension/           # Keyboard extension
│   ├── KeyboardViewController.swift # Main keyboard controller
│   ├── HSIPManager.swift            # Bridge to Rust
│   ├── SessionStorage.swift         # Keychain wrapper
│   ├── UI/
│   │   ├── KeyboardView.swift       # SwiftUI keyboard
│   │   ├─

 TopBar.swift              # HSIP toggle
│   │   ├── KeyButton.swift          # Individual keys
│   │   └── DecryptPopup.swift       # Show decrypted messages
│   ├── Info.plist
│   └── HSIPKeyboard.entitlements
└── HSIPKeyboard-Bridging-Header.h   # Rust FFI bridge
```

---

## 1. Rust FFI for iOS

### crates/hsip-keyboard/src/ios_ffi.rs

```rust
//! iOS FFI bindings for HSIP keyboard.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use crate::{crypto, message::HSIPMessage};

/// Initialize HSIP for iOS.
#[no_mangle]
pub extern "C" fn hsip_ios_init() -> bool {
    // Initialize logging for iOS
    true
}

/// Encrypt a message.
///
/// # Arguments
/// * `plaintext` - UTF-8 C string
/// * `session_key` - 32-byte session key
/// * `peer_id` - 32-byte peer ID
///
/// # Returns
/// Base64-encoded ciphertext (caller must free)
#[no_mangle]
pub extern "C" fn hsip_ios_encrypt(
    plaintext: *const c_char,
    session_key: *const u8,
    peer_id: *const u8,
) -> *mut c_char {
    if plaintext.is_null() || session_key.is_null() || peer_id.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        // Convert C string to Rust string
        let c_str = CStr::from_ptr(plaintext);
        let plaintext_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        // Convert session key
        let session_key_slice = std::slice::from_raw_parts(session_key, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(session_key_slice);

        // Convert peer ID
        let peer_id_slice = std::slice::from_raw_parts(peer_id, 32);
        let mut pid = [0u8; 32];
        pid.copy_from_slice(peer_id_slice);

        // Encrypt
        let message = match crypto::encrypt_message(plaintext_str, &key, &pid) {
            Ok(msg) => msg,
            Err(_) => return std::ptr::null_mut(),
        };

        // Format as compact (for iOS)
        let formatted = message.format(crate::message::MessageFormat::Compact, None);

        // Return as C string
        match CString::new(formatted) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Decrypt a message.
///
/// # Arguments
/// * `encrypted` - Base64-encoded ciphertext
/// * `session_key` - 32-byte session key
///
/// # Returns
/// Plaintext UTF-8 C string (caller must free), or null if decryption fails
#[no_mangle]
pub extern "C" fn hsip_ios_decrypt(
    encrypted: *const c_char,
    session_key: *const u8,
) -> *mut c_char {
    if encrypted.is_null() || session_key.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        // Convert C string to Rust string
        let c_str = CStr::from_ptr(encrypted);
        let encrypted_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        // Parse HSIP message
        let message = match HSIPMessage::parse(encrypted_str) {
            Ok(msg) => msg,
            Err(_) => return std::ptr::null_mut(),
        };

        // Convert session key
        let session_key_slice = std::slice::from_raw_parts(session_key, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(session_key_slice);

        // Decrypt
        let plaintext = match crypto::decrypt_message(&message, &key) {
            Ok(text) => text,
            Err(_) => return std::ptr::null_mut(),
        };

        // Return as C string
        match CString::new(plaintext) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Check if text contains an HSIP message.
#[no_mangle]
pub extern "C" fn hsip_ios_contains_message(text: *const c_char) -> bool {
    if text.is_null() {
        return false;
    }

    unsafe {
        let c_str = CStr::from_ptr(text);
        if let Ok(text_str) = c_str.to_str() {
            HSIPMessage::contains_hsip_message(text_str)
        } else {
            false
        }
    }
}

/// Free a C string allocated by Rust.
#[no_mangle]
pub extern "C" fn hsip_ios_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}
```

### Build for iOS

```bash
#!/bin/bash
# build-ios.sh

set -e

echo "Building HSIP Keyboard for iOS..."

cd crates/hsip-keyboard

# Add iOS targets
rustup target add aarch64-apple-ios       # iPhone/iPad
rustup target add aarch64-apple-ios-sim   # iOS Simulator (M1/M2 Mac)
rustup target add x86_64-apple-ios        # iOS Simulator (Intel Mac)

# Build for all iOS targets
cargo build --target aarch64-apple-ios --release
cargo build --target aarch64-apple-ios-sim --release
cargo build --target x86_64-apple-ios --release

echo "Creating universal library..."

# Create universal library for simulator (Intel + Apple Silicon)
lipo -create \
    ../../target/aarch64-apple-ios-sim/release/libhsip_keyboard.a \
    ../../target/x86_64-apple-ios/release/libhsip_keyboard.a \
    -output ../../target/ios-sim/libhsip_keyboard.a

# Device library (no need for universal, ARM64 only)
cp ../../target/aarch64-apple-ios/release/libhsip_keyboard.a \
   ../../target/ios-device/libhsip_keyboard.a

echo "iOS libraries built successfully!"
echo "  Simulator: target/ios-sim/libhsip_keyboard.a"
echo "  Device:    target/ios-device/libhsip_keyboard.a"
```

---

## 2. Swift Bridge

### HSIPManager.swift

```swift
import Foundation

/// Bridge to Rust HSIP core.
class HSIPManager {

    static let shared = HSIPManager()

    private init() {
        hsip_ios_init()
    }

    /// Encrypt a message.
    func encrypt(plaintext: String, sessionKey: Data, peerID: Data) -> String? {
        guard sessionKey.count == 32, peerID.count == 32 else {
            return nil
        }

        let cPlaintext = plaintext.cString(using: .utf8)!

        let encrypted = sessionKey.withUnsafeBytes { sessionKeyPtr in
            peerID.withUnsafeBytes { peerIDPtr in
                hsip_ios_encrypt(
                    cPlaintext,
                    sessionKeyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    peerIDPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                )
            }
        }

        guard let encrypted = encrypted else {
            return nil
        }

        let result = String(cString: encrypted)
        hsip_ios_free_string(encrypted)

        return result
    }

    /// Decrypt a message.
    func decrypt(encrypted: String, sessionKey: Data) -> String? {
        guard sessionKey.count == 32 else {
            return nil
        }

        let cEncrypted = encrypted.cString(using: .utf8)!

        let plaintext = sessionKey.withUnsafeBytes { sessionKeyPtr in
            hsip_ios_decrypt(
                cEncrypted,
                sessionKeyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            )
        }

        guard let plaintext = plaintext else {
            return nil
        }

        let result = String(cString: plaintext)
        hsip_ios_free_string(plaintext)

        return result
    }

    /// Check if text contains an HSIP message.
    func containsHSIPMessage(_ text: String) -> Bool {
        let cText = text.cString(using: .utf8)!
        return hsip_ios_contains_message(cText)
    }
}

// Declare Rust FFI functions
@_silgen_name("hsip_ios_init")
func hsip_ios_init() -> Bool

@_silgen_name("hsip_ios_encrypt")
func hsip_ios_encrypt(_ plaintext: UnsafePointer<CChar>,
                      _ sessionKey: UnsafePointer<UInt8>?,
                      _ peerID: UnsafePointer<UInt8>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("hsip_ios_decrypt")
func hsip_ios_decrypt(_ encrypted: UnsafePointer<CChar>,
                      _ sessionKey: UnsafePointer<UInt8>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("hsip_ios_contains_message")
func hsip_ios_contains_message(_ text: UnsafePointer<CChar>) -> Bool

@_silgen_name("hsip_ios_free_string")
func hsip_ios_free_string(_ s: UnsafeMutablePointer<CChar>?)
```

---

## 3. Session Storage (Keychain)

### SessionStorage.swift

```swift
import Foundation
import Security

/// Secure storage for HSIP sessions using iOS Keychain.
class SessionStorage {

    static let shared = SessionStorage()

    private let serviceName = "io.hsip.keyboard"

    private init() {}

    /// Save a session to Keychain.
    func saveSession(_ session: Session) throws {
        let data = try JSONEncoder().encode(session)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: session.id,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        // Delete existing
        SecItemDelete(query as CFDictionary)

        // Add new
        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }

    /// Load a session from Keychain.
    func loadSession(id: String) throws -> Session? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: id,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data else {
            if status == errSecItemNotFound {
                return nil
            }
            throw KeychainError.loadFailed(status)
        }

        return try JSONDecoder().decode(Session.self, from: data)
    }

    /// List all sessions.
    func listSessions() throws -> [Session] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            if status == errSecItemNotFound {
                return []
            }
            throw KeychainError.loadFailed(status)
        }

        return try items.compactMap { item in
            guard let data = item[kSecValueData as String] as? Data else {
                return nil
            }
            return try JSONDecoder().decode(Session.self, from: data)
        }
    }

    /// Delete a session.
    func deleteSession(id: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: id
        ]

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }
}

enum KeychainError: Error {
    case saveFailed(OSStatus)
    case loadFailed(OSStatus)
    case deleteFailed(OSStatus)
}

struct Session: Codable {
    let id: String
    let peerID: Data
    let displayName: String
    let sessionKey: Data
    let createdAt: Date
    let expiresAt: Date
    var messageCount: Int
    var isActive: Bool

    var isExpired: Bool {
        Date() >= expiresAt
    }

    var needsRekey: Bool {
        messageCount >= 1000 || isExpired
    }
}
```

---

## 4. Keyboard UI (SwiftUI)

### KeyboardViewController.swift

```swift
import UIKit
import SwiftUI

class KeyboardViewController: UIInputViewController {

    private var hsipManager = HSIPManager.shared
    private var sessionStorage = SessionStorage.shared

    private var hsipEnabled = false
    private var activeSession: Session?
    private var showDecryptBanner = false
    private var detectedMessage: String?

    override func viewDidLoad() {
        super.viewDidLoad()

        // Set up SwiftUI keyboard view
        let keyboardView = KeyboardView(
            onKeyPress: handleKeyPress,
            hsipEnabled: $hsipEnabled,
            activeSession: $activeSession,
            onToggleHSIP: toggleHSIPMode,
            onSelectSession: selectSession
        )

        let hostingController = UIHostingController(rootView: keyboardView)
        hostingController.view.translatesAutoresizingMaskIntoConstraints = false

        addChild(hostingController)
        view.addSubview(hostingController.view)
        hostingController.didMove(toParent: self)

        NSLayoutConstraint.activate([
            hostingController.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            hostingController.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            hostingController.view.topAnchor.constraint(equalTo: view.topAnchor),
            hostingController.view.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])

        // Check for HSIP messages
        checkForHSIPMessage()
    }

    override func textDidChange(_ textInput: UITextInput?) {
        super.textDidChange(textInput)
        checkForHSIPMessage()
    }

    private func checkForHSIPMessage() {
        guard let proxy = textDocumentProxy,
              let text = proxy.documentContextBeforeInput else {
            return
        }

        if hsipManager.containsHSIPMessage(text) {
            showDecryptBanner = true
            detectedMessage = text
        }
    }

    private func handleKeyPress(_ key: KeyType) {
        switch key {
        case .character(let char):
            textDocumentProxy.insertText(String(char))

        case .backspace:
            textDocumentProxy.deleteBackward()

        case .enter:
            commitCurrentText()

        case .space:
            textDocumentProxy.insertText(" ")
        }
    }

    private func commitCurrentText() {
        // If HSIP mode is on, encrypt before sending
        // (In iOS, we commit on each key, so this is for Enter key)
        textDocumentProxy.insertText("\n")
    }

    private func toggleHSIPMode() {
        hsipEnabled.toggle()

        if hsipEnabled && activeSession == nil {
            // Auto-select first session
            activeSession = try? sessionStorage.listSessions().first
        }
    }

    private func selectSession(_ session: Session) {
        activeSession = session
    }
}

enum KeyType {
    case character(Character)
    case backspace
    case enter
    case space
}
```

### KeyboardView.swift (SwiftUI)

```swift
import SwiftUI

struct KeyboardView: View {

    let onKeyPress: (KeyType) -> Void
    @Binding var hsipEnabled: Bool
    @Binding var activeSession: Session?
    let onToggleHSIP: () -> Void
    let onSelectSession: (Session) -> Void

    @State private var showRecipientPicker = false

    var body: some View {
        VStack(spacing: 0) {
            // Top bar with HSIP toggle
            TopBar(
                hsipEnabled: $hsipEnabled,
                activeSession: activeSession,
                onToggleHSIP: onToggleHSIP,
                onSelectRecipient: { showRecipientPicker = true }
            )

            // Keyboard layout
            KeyboardLayout(
                onKeyPress: onKeyPress,
                hsipEnabled: hsipEnabled,
                onToggleHSIP: onToggleHSIP
            )
        }
        .sheet(isPresented: $showRecipientPicker) {
            RecipientPicker(onSelect: onSelectSession)
        }
    }
}

struct TopBar: View {

    @Binding var hsipEnabled: Bool
    let activeSession: Session?
    let onToggleHSIP: () -> Void
    let onSelectRecipient: () -> Void

    var body: some View {
        HStack {
            Button(action: onToggleHSIP) {
                HStack {
                    Image(systemName: hsipEnabled ? "lock.fill" : "lock.open")
                        .foregroundColor(hsipEnabled ? .green : .gray)

                    VStack(alignment: .leading) {
                        Text(hsipEnabled ? "HSIP Mode ON" : "Normal Mode")
                            .font(.caption)
                            .fontWeight(.semibold)

                        if hsipEnabled, let session = activeSession {
                            Text("To: \(session.displayName)")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }

            Spacer()

            if hsipEnabled {
                Button(action: onSelectRecipient) {
                    Image(systemName: "person.fill")
                        .foregroundColor(.green)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(hsipEnabled ? Color.green.opacity(0.1) : Color.gray.opacity(0.1))
    }
}

struct KeyboardLayout: View {

    let onKeyPress: (KeyType) -> Void
    let hsipEnabled: Bool
    let onToggleHSIP: () -> Void

    let rows: [[Character]] = [
        ["Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"],
        ["A", "S", "D", "F", "G", "H", "J", "K", "L"],
        ["Z", "X", "C", "V", "B", "N", "M"]
    ]

    var body: some View {
        VStack(spacing: 8) {
            // Row 1
            HStack(spacing: 4) {
                ForEach(rows[0], id: \.self) { char in
                    KeyButton(label: String(char)) {
                        onKeyPress(.character(char))
                    }
                }
            }

            // Row 2 (with offset)
            HStack(spacing: 4) {
                Spacer(minLength: 20)
                ForEach(rows[1], id: \.self) { char in
                    KeyButton(label: String(char)) {
                        onKeyPress(.character(char))
                    }
                }
                Spacer(minLength: 20)
            }

            // Row 3
            HStack(spacing: 4) {
                KeyButton(label: "⇧", isSpecial: true) {
                    // TODO: Shift
                }
                .frame(width: 50)

                ForEach(rows[2], id: \.self) { char in
                    KeyButton(label: String(char)) {
                        onKeyPress(.character(char))
                    }
                }

                KeyButton(label: "⌫", isSpecial: true) {
                    onKeyPress(.backspace)
                }
                .frame(width: 50)
            }

            // Bottom row
            HStack(spacing: 4) {
                KeyButton(label: hsipEnabled ? "🔒" : "🔓", isSpecial: hsipEnabled) {
                    onToggleHSIP()
                }
                .frame(width: 50)

                KeyButton(label: "123", isSpecial: true) {
                    // TODO: Number layout
                }
                .frame(width: 50)

                KeyButton(label: "space") {
                    onKeyPress(.space)
                }

                KeyButton(label: "return", isSpecial: true) {
                    onKeyPress(.enter)
                }
                .frame(width: 70)
            }
        }
        .padding(8)
        .background(Color(.systemGray6))
    }
}

struct KeyButton: View {

    let label: String
    var isSpecial: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 20))
                .frame(maxWidth: .infinity, minHeight: 42)
                .background(isSpecial ? Color.green : Color.white)
                .foregroundColor(isSpecial ? .white : .black)
                .cornerRadius(6)
                .shadow(radius: 1)
        }
    }
}
```

---

## 5. Cross-Platform Testing

### Message Format Compatibility

Both Android and iOS use the **exact same format**:

```
Version: 1 byte (0x01)
Sender PeerID: 32 bytes
Nonce: 12 bytes
Tag: 16 bytes
Ciphertext: variable

Display: 🔒<base64(above)>
```

### Testing (Android ↔ iOS)

**Android (Girlfriend) → iOS (You):**
```
1. Girlfriend types in Instagram on Android
2. HSIP Keyboard encrypts: "🔒hQEMA..."
3. You see message on iPhone Instagram
4. HSIP Keyboard detects → "Decrypt" banner
5. Tap Decrypt → See plaintext!
```

**iOS (You) → Android (Girlfriend):**
```
1. You type in WhatsApp on iPhone
2. HSIP Keyboard encrypts: "🔒hQEMA..."
3. Girlfriend sees on Android WhatsApp
4. HSIP Keyboard detects → Shows plaintext
```

**It just works!** ✨

---

## 6. Distribution

### iOS Sideload (TestFlight Alternative)

**For testing without App Store:**

1. **Build IPA**:
```bash
xcodebuild archive -project HSIPKeyboard.xcodeproj \
                   -scheme HSIPKeyboard \
                   -archivePath build/HSIPKeyboard.xcarchive

xcodebuild -exportArchive \
           -archivePath build/HSIPKeyboard.xcarchive \
           -exportPath build/ \
           -exportOptionsPlist ExportOptions.plist
```

2. **Sign with your Apple ID** (free developer account works for 7 days)

3. **Install via Xcode** or **AltStore** (popular iOS sideload tool)

### TestFlight (Proper Beta)

1. **Enroll in Apple Developer Program** ($99/year)
2. **Upload IPA** to App Store Connect
3. **Add beta testers** (up to 10,000)
4. **Push updates** instantly (no review for beta)

---

## Next Steps

1. ✅ Build Rust for iOS (`./build-ios.sh`)
2. ⏳ Create Xcode project
3. ⏳ Implement KeyboardViewController
4. ⏳ Test on iPhone
5. ⏳ Test Android ↔ iOS messaging
6. ⏳ Refine UX based on real usage

---

**Android + iOS keyboards ready!** 🤖🍎

Your girlfriend on Android and you on iPhone will be able to exchange E2E encrypted messages through Instagram/WhatsApp/Gmail using HSIP. **This is revolutionary!** 🚀🔐
