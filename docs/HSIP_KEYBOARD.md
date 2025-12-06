# HSIP Secure Keyboard

## Vision

A standard Android keyboard (IME) that provides end-to-end encryption for any messaging platform—without requiring platform cooperation or modifications.

**Key Insight:** Instead of detecting messaging actions and offering alternatives, we become the INPUT METHOD itself. Users type normally, but when HSIP mode is enabled, the plaintext never leaves the keyboard—only encrypted ciphertext reaches the app.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              HSIP Secure Keyboard (IME)                  │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐   │
│  │  Keyboard UI (Jetpack Compose)                  │   │
│  │  - QWERTY layout                                │   │
│  │  - HSIP mode toggle (🔒)                        │   │
│  │  - Recipient selector                           │   │
│  │  - Session status indicator                     │   │
│  └─────────────────────────────────────────────────┘   │
│                        ↓                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Input Processing                               │   │
│  │  - Plaintext buffer                             │   │
│  │  - Auto-complete / suggestions                  │   │
│  │  - Emoji support                                │   │
│  └─────────────────────────────────────────────────┘   │
│                        ↓                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │  HSIP Mode Check                                │   │
│  │  if (hsipEnabled && hasActiveSession):          │   │
│  │    → Encrypt                                    │   │
│  │  else:                                          │   │
│  │    → Send plaintext                             │   │
│  └─────────────────────────────────────────────────┘   │
│                        ↓                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │  HSIP Encryption Engine (Rust via JNI)         │   │
│  │  1. Get active session key                      │   │
│  │  2. Encrypt with ChaCha20-Poly1305              │   │
│  │  3. Format: 🔒 [HSIP] base64(ciphertext)        │   │
│  │  4. Add decrypt URL: hsip://m/<msg-id>          │   │
│  └─────────────────────────────────────────────────┘   │
│                        ↓                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Send to Target App                             │   │
│  │  - Facebook sees: "🔒 [HSIP] hQEMA..."          │   │
│  │  - Instagram sees: encrypted blob               │   │
│  │  - Gmail sees: ciphertext + decrypt link        │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                         ↓
         ┌───────────────────────────────┐
         │   Recipient's Side            │
         ├───────────────────────────────┤
         │ Option 1: HSIP Keyboard       │
         │   → Auto-detects, decrypts    │
         │                               │
         │ Option 2: HSIP Mobile App     │
         │   → Click decrypt link        │
         │                               │
         │ Option 3: HSIP Web App        │
         │   → hsip.io/decrypt?msg=...   │
         └───────────────────────────────┘
```

---

## User Experience

### First-Time Setup

1. **Install HSIP Keyboard** from Google Play
2. **Enable in Settings**:
   ```
   Settings → System → Languages & Input
   → On-screen keyboard → HSIP Keyboard → Enable
   ```
3. **Generate Identity** (if first time using HSIP)
   - Ed25519 keypair generated
   - PeerID derived (Blake3 hash)
   - Stored in encrypted keystore

4. **Exchange Keys with Contacts**:
   - **Option A (QR Code)**: Show QR → Friend scans → Keys exchanged
   - **Option B (Deep Link)**: Share link → Friend clicks → Keys exchanged
   - **Option C (NFC)**: Tap phones together → Keys exchanged
   - **Option D (Manual)**: Copy PeerID → Send via existing channel

### Daily Usage

1. **Open any messaging app** (Instagram, WhatsApp, Gmail, etc.)
2. **Tap message input field** → HSIP Keyboard appears
3. **Toggle HSIP mode ON** (tap 🔒 icon in toolbar)
4. **Select recipient** from contact list (or use current chat context)
5. **Type message normally**: "Hey, coffee at 3pm?"
6. **Keyboard shows preview**:
   ```
   Plaintext: "Hey, coffee at 3pm?"
   Will send (encrypted): 🔒 [HSIP] hQEMA8Kxq...
   ```
7. **Tap Send** → Encrypted message sent to app
8. **Recipient sees**:
   - With HSIP Keyboard: Plaintext appears automatically ✨
   - Without HSIP: Ciphertext + decrypt link

---

## Technical Architecture

### Android InputMethodService

```kotlin
class HSIPKeyboardService : InputMethodService() {

    private lateinit var keyboardView: ComposeView
    private lateinit var hsipEngine: HSIPEngine
    private var hsipModeEnabled = false
    private var activeSession: Session? = null

    override fun onCreate() {
        super.onCreate()
        hsipEngine = HSIPEngine.initialize(this)
    }

    override fun onCreateInputView(): View {
        keyboardView = ComposeView(this).apply {
            setContent {
                HSIPKeyboardTheme {
                    KeyboardLayout(
                        onKeyPress = { key -> handleKeyPress(key) },
                        hsipEnabled = hsipModeEnabled,
                        onToggleHSIP = { hsipModeEnabled = !hsipModeEnabled },
                        activeSession = activeSession
                    )
                }
            }
        }
        return keyboardView
    }

    private fun handleKeyPress(key: Key) {
        when (key) {
            is Key.Character -> appendCharacter(key.char)
            is Key.Backspace -> deleteCharacter()
            is Key.Enter -> commitText()
            is Key.Space -> appendCharacter(' ')
        }
    }

    private fun commitText() {
        val text = currentInputBuffer.toString()

        if (hsipModeEnabled && activeSession != null) {
            // Encrypt with HSIP
            val encrypted = hsipEngine.encrypt(text, activeSession!!)
            val formatted = formatEncryptedMessage(encrypted)
            currentInputConnection?.commitText(formatted, 1)
        } else {
            // Send plaintext
            currentInputConnection?.commitText(text, 1)
        }

        currentInputBuffer.clear()
    }
}
```

### Encryption Format

#### Option 1: Compact (for platforms with character limits)

```
🔒hQEMA8KxqFn8KjfzAQv/Z2xF...
```
- Emoji prefix (visual indicator)
- Base64 encoded ciphertext
- ~30% overhead

#### Option 2: Verbose (for platforms without limits)

```
🔒 [HSIP Encrypted Message]
Decrypt: hsip://m/abc123-def456
Or visit: https://hsip.io/decrypt?id=abc123-def456

hQEMA8KxqFn8KjfzAQv/Z2xF7vK3pM9qR...
```
- Clear labeling
- Multiple decrypt options
- User-friendly for non-HSIP users

#### Option 3: Stealth (looks like gibberish)

```
hQEMA8KxqFn8KjfzAQv/Z2xF7vK3pM9qR...
```
- Just the ciphertext
- HSIP keyboard auto-detects and decrypts
- Plausible deniability (could be any random text)

### Ciphertext Structure

```rust
struct HSIPMessage {
    // Header (unencrypted, 32 bytes)
    version: u8,           // Protocol version (0x01)
    sender_peer_id: [u8; 32],  // Blake3 hash of sender pubkey

    // Encrypted payload
    nonce: [u8; 12],       // ChaCha20-Poly1305 nonce
    ciphertext: Vec<u8>,   // Encrypted message
    tag: [u8; 16],         // Authentication tag
}

// Serialization
fn encode_message(msg: HSIPMessage) -> String {
    let bytes = msg.to_bytes();
    format!("🔒{}", base64::encode(bytes))
}

// Deserialization
fn decode_message(text: &str) -> Result<HSIPMessage> {
    if !text.starts_with("🔒") {
        return Err("Not an HSIP message");
    }
    let bytes = base64::decode(&text[4..])?;
    HSIPMessage::from_bytes(&bytes)
}
```

---

## Session Management

### Contact Book Schema

```kotlin
data class Contact(
    val peerID: String,           // peer_abc123...
    val displayName: String,      // "Alice Smith"
    val publicKey: ByteArray,     // Ed25519 pubkey
    val lastSeen: Instant?,
    val sessions: List<Session>
)

data class Session(
    val sessionID: String,
    val sharedSecret: ByteArray,  // X25519 shared secret
    val derivedKey: ByteArray,    // HKDF output
    val createdAt: Instant,
    val expiresAt: Instant,
    val messageCount: Int,        // For rekeying
    val isActive: Boolean
)
```

### Session Lifecycle

1. **Key Exchange** (one-time, out-of-band)
   ```
   Alice → QR Code → Bob
   - Alice's PeerID
   - Alice's Ed25519 pubkey
   - Ephemeral X25519 pubkey
   ```

2. **Session Derivation**
   ```rust
   let shared_secret = x25519(my_ephemeral_privkey, their_ephemeral_pubkey);
   let session_key = hkdf_sha256(shared_secret, b"HSIPKeyboard-v1", 32);
   ```

3. **Encryption**
   ```rust
   let nonce = generate_nonce(); // Random 12 bytes
   let ciphertext = chacha20poly1305_encrypt(
       session_key,
       nonce,
       plaintext,
       aad = b"HSIP-MSG-v1"
   );
   ```

4. **Rekeying** (after 1000 messages or 7 days)
   ```rust
   // Generate new ephemeral keypair
   let new_ephemeral = x25519_keypair();

   // Send rekeying request (encrypted with old key)
   let rekey_msg = HSIPRekeyRequest {
       new_ephemeral_pubkey: new_ephemeral.public,
       signature: sign(new_ephemeral.public, identity_privkey)
   };
   ```

---

## Auto-Decryption

### Incoming Message Detection

The keyboard monitors the input field for HSIP-encrypted messages:

```kotlin
override fun onUpdateSelection(
    oldSelStart: Int, oldSelEnd: Int,
    newSelStart: Int, newSelEnd: Int,
    candidatesStart: Int, candidatesEnd: Int
) {
    super.onUpdateSelection(...)

    // Get text from input field
    val text = currentInputConnection?.getTextBeforeCursor(500, 0)

    // Check if it contains HSIP message
    if (text?.contains("🔒") == true) {
        val hsipMessage = extractHSIPMessage(text)
        if (hsipMessage != null) {
            // Try to decrypt
            val decrypted = hsipEngine.tryDecrypt(hsipMessage)
            if (decrypted != null) {
                // Replace ciphertext with plaintext
                showDecryptedPreview(decrypted)
            }
        }
    }
}
```

### Decrypt Helper Activity

For non-HSIP users who receive encrypted messages:

```kotlin
// DeepLinkActivity.kt
class DecryptActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Handle hsip://m/<msg-id> deep link
        val messageId = intent.data?.lastPathSegment

        if (messageId != null) {
            // Fetch message from relay (optional)
            // Or extract from URL query param
            val encrypted = fetchMessage(messageId)

            if (hasHSIPSession()) {
                // Decrypt locally
                val plaintext = decrypt(encrypted)
                showMessage(plaintext)
            } else {
                // Show setup prompt
                showSetupPrompt()
            }
        }
    }
}
```

---

## Privacy & Security

### Threat Model

**Attacker Capabilities:**
- Platform provider (Meta, Google) sees ciphertext
- Network observer sees encrypted traffic
- Malicious keyboard (if user installs other IMEs)

**HSIP Protections:**
- End-to-end encryption (platform can't read)
- Forward secrecy (ephemeral session keys)
- Authentication (Ed25519 signatures)
- Consent-based (no unsolicited messages)

**Limitations:**
- **Metadata visible**: Platform knows you sent *something* to someone
- **Timing attacks**: Platform can analyze message patterns
- **Recipient must have key**: Can't decrypt without session
- **Keyboard permissions**: IME has access to ALL typed text (user must trust HSIP)

### Keyboard Security

**Critical: IMEs have full access to typed text**

To build trust:
1. ✅ **Open-source**: All code public, auditable
2. ✅ **Reproducible builds**: Verify Play Store binary matches source
3. ✅ **No network in keyboard**: Encryption done locally, no API calls
4. ✅ **Minimal permissions**: Only IME permission required
5. ✅ **Local key storage**: Keys never leave device (except during exchange)
6. ✅ **Regular security audits**: Third-party reviews
7. ✅ **F-Droid distribution**: Alternative to Google Play (no proprietary code)

### Metadata Hiding (Optional)

Even with E2E encryption, platforms see:
- Message length (approximate)
- Timing (when messages sent)
- Frequency (how often you message)

**Mitigations:**
1. **Message Padding**: Pad to fixed size buckets
2. **Dummy Messages**: Send cover traffic
3. **Batching**: Queue messages, send in bursts
4. **Timing Randomization**: Add random delays

---

## Integration with Existing HSIP

### Rust Core (hsip-core)

The keyboard uses existing HSIP crypto:

```rust
// crates/hsip-keyboard/ (new crate)

use hsip_core::{
    identity::Identity,
    session::Session,
};
use hsip_session::SessionCipher;

#[no_mangle]
pub extern "C" fn hsip_keyboard_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    session_id: *const u8,
) -> *mut u8 {
    // 1. Load session by ID
    let session = Session::load(session_id)?;

    // 2. Encrypt with session key
    let cipher = SessionCipher::new(&session);
    let ciphertext = cipher.encrypt(plaintext)?;

    // 3. Format as HSIP message
    let formatted = format_hsip_message(ciphertext);

    formatted.as_ptr()
}

#[no_mangle]
pub extern "C" fn hsip_keyboard_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
) -> *mut u8 {
    // 1. Parse HSIP message
    let msg = parse_hsip_message(ciphertext)?;

    // 2. Find session by sender PeerID
    let session = Session::find_by_peer(msg.sender_peer_id)?;

    // 3. Decrypt
    let cipher = SessionCipher::new(&session);
    let plaintext = cipher.decrypt(&msg.ciphertext)?;

    plaintext.as_ptr()
}
```

### JNI Bridge

```kotlin
// HSIPEngine.kt
class HSIPEngine private constructor(context: Context) {

    companion object {
        init {
            System.loadLibrary("hsip_keyboard")
        }

        fun initialize(context: Context): HSIPEngine {
            return HSIPEngine(context)
        }
    }

    // Native methods
    private external fun nativeEncrypt(
        plaintext: ByteArray,
        sessionId: String
    ): ByteArray

    private external fun nativeDecrypt(
        ciphertext: ByteArray
    ): ByteArray?

    private external fun nativeGenerateKeypair(): ByteArray

    // Kotlin wrappers
    fun encrypt(plaintext: String, session: Session): ByteArray {
        return nativeEncrypt(
            plaintext.toByteArray(Charsets.UTF_8),
            session.id
        )
    }

    fun tryDecrypt(ciphertext: ByteArray): String? {
        return nativeDecrypt(ciphertext)?.toString(Charsets.UTF_8)
    }
}
```

---

## Message Relay (Optional)

For users who don't have HSIP installed, we can provide a relay:

### Architecture

```
Alice (HSIP Keyboard)
      ↓
   Encrypts message
      ↓
   Posts to relay: POST /messages
      ↓
   Gets message ID: "abc123"
      ↓
   Sends to Bob: "🔒 Decrypt: hsip://m/abc123"
      ↓
Bob (no HSIP)
      ↓
   Clicks link
      ↓
   Redirects to: https://hsip.io/decrypt?id=abc123
      ↓
   Fetches encrypted message from relay
      ↓
   Bob enters shared secret (or scans QR)
      ↓
   Decrypts in browser (WASM)
      ↓
   Sees plaintext (never sent to server!)
```

### Relay API

```
POST /messages
Body: {
  "encrypted": "base64...",
  "sender_peer_id": "peer_abc123...",
  "expires_at": "2024-12-06T10:00:00Z"
}
Response: {
  "id": "abc123-def456",
  "url": "hsip://m/abc123-def456"
}

GET /messages/:id
Response: {
  "encrypted": "base64...",
  "sender_peer_id": "peer_abc123...",
  "created_at": "2024-12-05T10:00:00Z"
}
```

**Privacy**: Relay only stores ciphertext, never has keys.

---

## Platform-Specific Considerations

### Instagram / Facebook

- **Character limit**: Use compact format
- **Link preview**: hsip:// links won't render (good for privacy)
- **Detection**: Platform may flag unusual patterns
- **Mitigation**: Randomize prefix, use stealth mode

### Gmail

- **No character limit**: Use verbose format with decrypt link
- **HTML rendering**: Could embed decrypt button (future)
- **Threading**: Each message has separate session

### WhatsApp

- **E2E encrypted already**: HSIP adds another layer (overkill?)
- **Use case**: Don't trust WhatsApp's encryption, want own keys
- **Backup**: HSIP messages can be backed up separately

### Signal

- **Already E2E encrypted + open source**
- **Use case**: Probably unnecessary, Signal is good enough
- **Compatibility**: Could still work for cross-platform (Signal ↔ Instagram)

---

## Advantages Over Intercept Approach

| Feature | Intercept | HSIP Keyboard |
|---------|-----------|---------------|
| **Platform detection** | Required (fragile) | Not needed ✅ |
| **Accessibility permissions** | Required (red flag) | Not needed ✅ |
| **Overlay permissions** | Required (annoying) | Not needed ✅ |
| **Works with any app** | Only detected apps | YES ✅ |
| **Unilateral deployment** | Both need HSIP | Sender only ✅ |
| **App Store friendly** | Risky | Standard IME ✅ |
| **User friction** | High (new UI) | Low (familiar keyboard) ✅ |
| **Breaking on updates** | High risk | Low risk ✅ |

---

## Roadmap

### Phase 1: MVP (4-6 weeks)

**Core Functionality:**
- [ ] Android IME service implementation
- [ ] Basic QWERTY keyboard UI (Jetpack Compose)
- [ ] HSIP mode toggle
- [ ] Encrypt/decrypt with hsip-core
- [ ] Contact management (manual PeerID entry)
- [ ] Session key storage
- [ ] Ciphertext formatting (compact format)

**Testing:**
- [ ] Manual testing with Instagram, WhatsApp, Gmail
- [ ] Encryption/decryption correctness
- [ ] Performance (typing latency <50ms)
- [ ] Battery impact (<1%)

### Phase 2: Beta (6-8 weeks)

**Enhanced Features:**
- [ ] QR code key exchange
- [ ] Auto-detection of HSIP messages (incoming)
- [ ] Auto-decryption in input field
- [ ] Recipient suggestions (from current chat)
- [ ] Session expiry and rekeying
- [ ] Offline message queue
- [ ] Multiple keyboard themes
- [ ] Emoji support

**Decrypt Helpers:**
- [ ] Web app (hsip.io/decrypt)
- [ ] Deep link handler (hsip://m/...)
- [ ] Message relay (optional)

**Distribution:**
- [ ] Google Play Store listing
- [ ] F-Droid release (open-source build)
- [ ] Documentation and tutorials

### Phase 3: Stable (8-12 weeks)

**Advanced Features:**
- [ ] Swype/gesture typing
- [ ] Voice input with encryption
- [ ] GIF/image encryption (embed in messages)
- [ ] Group messaging (multi-party keys)
- [ ] Cross-device sync (encrypted cloud backup)
- [ ] Integration with password managers

**Privacy Enhancements:**
- [ ] Message padding (hide length)
- [ ] Timing randomization
- [ ] Cover traffic mode
- [ ] Stealth mode (no visual indicators)

**Platform Expansion:**
- [ ] iOS keyboard extension
- [ ] Desktop apps (Windows, macOS, Linux)
- [ ] Browser extension (for web messaging)

---

## Success Metrics

### Technical
- ✅ Typing latency <50ms
- ✅ Encryption overhead <100ms
- ✅ Battery impact <1%
- ✅ Memory footprint <100MB
- ✅ Works with 20+ messaging apps

### User
- 🎯 10,000+ installs (year 1)
- 🎯 4.0+ star rating on Play Store
- 🎯 80%+ retention (30-day)
- 🎯 50%+ daily active users use HSIP mode
- 🎯 Featured in privacy-focused media

### Security
- 🎯 Zero critical vulnerabilities
- 🎯 Third-party security audit passed
- 🎯 Reproducible builds verified
- 🎯 F-Droid inclusion approved

---

## Comparison with Alternatives

### vs. Signal

**Signal:** Separate app, requires both users to install, platform-specific
**HSIP Keyboard:** Works with existing apps, unilateral deployment ✅

### vs. PGP Email

**PGP:** Clunky UX, manual copy-paste, mainly for email
**HSIP Keyboard:** Seamless, works with any app, modern crypto ✅

### vs. Encrypted Keyboards (AnySoftKeyboard + GPG)

**Existing:** Complex setup, poor UX, limited adoption
**HSIP Keyboard:** Built for HSIP protocol, native integration, better UX ✅

---

## Open Questions

1. **Recipient without HSIP**: What's the best fallback?
   - **Option A**: Verbose message with decrypt link (user-friendly)
   - **Option B**: Compact ciphertext + hope they install HSIP (pushy)
   - **Option C**: Hybrid - detect if recipient has HSIP, adjust format
   - **Decision**: Start with Option A (verbose), add Option C later

2. **Key Exchange**: How to make it frictionless?
   - **Option A**: QR codes (requires physical presence)
   - **Option B**: Deep links (can share remotely)
   - **Option C**: NFC (cool but limited hardware support)
   - **Decision**: Support all three, default to QR codes

3. **Message Relay**: Should we host one?
   - **Pro**: Better UX for non-HSIP users (just click link)
   - **Con**: Centralization, operational cost, moderation
   - **Decision**: Optional community-run relays, not required

4. **Platform Detection**: Should keyboard detect which app is active?
   - **Pro**: Auto-suggest recipient based on chat context
   - **Con**: Requires reading app package name (privacy concern)
   - **Decision**: Make it optional, disabled by default

---

## Conclusion

The **HSIP Secure Keyboard** approach is MORE practical, MORE deployable, and MORE user-friendly than the intercept approach. It leverages the fact that keyboards are already trusted input methods, and extends them with HSIP's consent-based, end-to-end encryption.

**Key Advantages:**
1. ✅ Works with ANY messaging app (no platform detection)
2. ✅ Standard Android IME (App Store friendly)
3. ✅ Unilateral deployment (sender doesn't need receiver to have HSIP)
4. ✅ Natural UX (users type normally, encryption is transparent)
5. ✅ Minimal permissions (just IME, no accessibility/overlay abuse)

**This is like PGP for the smartphone era—seamless, ubiquitous, and practical.** 🔐📱

Ready to build it! 🚀
