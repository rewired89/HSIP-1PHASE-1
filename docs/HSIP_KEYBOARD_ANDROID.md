# HSIP Secure Keyboard - Android Implementation Guide

This guide provides complete Kotlin/Java code for building the HSIP Secure Keyboard Android IME.

---

## Project Structure

```
android/
├── app/
│   ├── build.gradle
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── java/io/hsip/keyboard/
│   │   │   ├── HSIPKeyboardService.kt        # Main IME service
│   │   │   ├── HSIPEngine.kt                 # JNI bridge to Rust
│   │   │   ├── SessionManager.kt             # Session storage
│   │   │   ├── ui/
│   │   │   │   ├── KeyboardView.kt           # Compose UI
│   │   │   │   ├── HSIPModeToggle.kt         # HSIP toggle button
│   │   │   │   └── RecipientSelector.kt      # Contact picker
│   │   │   ├── SetupActivity.kt               # First-run setup
│   │   │   └── DecryptActivity.kt             # Handle hsip:// links
│   │   ├── res/
│   │   │   ├── xml/method.xml                 # IME definition
│   │   │   └── values/strings.xml
│   │   └── jniLibs/
│   │       ├── arm64-v8a/libhsip_keyboard.so
│   │       ├── armeabi-v7a/libhsip_keyboard.so
│   │       └── x86_64/libhsip_keyboard.so
│   └── CMakeLists.txt (optional, if using C++)
└── build.gradle
```

---

## AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="io.hsip.keyboard">

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:name=".HSIPApplication"
        android:label="HSIP Keyboard"
        android:icon="@mipmap/ic_launcher"
        android:allowBackup="false">

        <!-- Main Setup Activity -->
        <activity
            android:name=".SetupActivity"
            android:exported="true"
            android:label="HSIP Keyboard Setup">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Decrypt Activity (handles hsip:// links) -->
        <activity
            android:name=".DecryptActivity"
            android:exported="true"
            android:label="Decrypt HSIP Message">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="hsip" android:host="m" />
            </intent-filter>
        </activity>

        <!-- Input Method Service -->
        <service
            android:name=".HSIPKeyboardService"
            android:label="HSIP Keyboard"
            android:permission="android.permission.BIND_INPUT_METHOD"
            android:exported="true">
            <intent-filter>
                <action android:name="android.view.InputMethod" />
            </intent-filter>
            <meta-data
                android:name="android.view.im"
                android:resource="@xml/method" />
        </service>

    </application>

</manifest>
```

---

## res/xml/method.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<input-method xmlns:android="http://schemas.android.com/apk/res/android"
    android:settingsActivity="io.hsip.keyboard.SetupActivity"
    android:supportsSwitchingToNextInputMethod="true" />
```

---

## HSIPEngine.kt (JNI Bridge)

```kotlin
package io.hsip.keyboard

import android.content.Context

class HSIPEngine private constructor(context: Context) {

    companion object {
        // Load native library
        init {
            System.loadLibrary("hsip_keyboard")
        }

        @Volatile
        private var INSTANCE: HSIPEngine? = null

        fun getInstance(context: Context): HSIPEngine {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: HSIPEngine(context.applicationContext).also { INSTANCE = it }
            }
        }
    }

    // Native methods (implemented in Rust)
    private external fun nativeInitialize(): Boolean
    private external fun nativeEncrypt(plaintext: String, sessionKey: ByteArray, peerID: ByteArray): ByteArray
    private external fun nativeDecrypt(encrypted: ByteArray, sessionKey: ByteArray): String?
    private external fun nativeFormatMessage(encrypted: ByteArray, format: Int, messageId: String?): String
    private external fun nativeParseMessage(text: String): ByteArray?
    private external fun nativeContainsHSIPMessage(text: String): Boolean

    init {
        if (!nativeInitialize()) {
            throw RuntimeException("Failed to initialize HSIP Engine")
        }
    }

    // Message format constants
    object Format {
        const val COMPACT = 0    // 🔒base64...
        const val VERBOSE = 1    // 🔒 [HSIP] base64... + decrypt link
        const val STEALTH = 2    // just base64
    }

    /**
     * Encrypt a plaintext message.
     *
     * @param plaintext The message to encrypt
     * @param sessionKey 32-byte session key
     * @param peerID 32-byte peer identifier
     * @return Encrypted message bytes
     */
    fun encrypt(plaintext: String, sessionKey: ByteArray, peerID: ByteArray): ByteArray {
        require(sessionKey.size == 32) { "Session key must be 32 bytes" }
        require(peerID.size == 32) { "Peer ID must be 32 bytes" }

        return nativeEncrypt(plaintext, sessionKey, peerID)
    }

    /**
     * Decrypt an HSIP message.
     *
     * @param encrypted Encrypted message bytes
     * @param sessionKey 32-byte session key
     * @return Decrypted plaintext, or null if decryption fails
     */
    fun decrypt(encrypted: ByteArray, sessionKey: ByteArray): String? {
        require(sessionKey.size == 32) { "Session key must be 32 bytes" }

        return nativeDecrypt(encrypted, sessionKey)
    }

    /**
     * Format an encrypted message for display.
     *
     * @param encrypted Encrypted message bytes
     * @param format Format type (COMPACT, VERBOSE, or STEALTH)
     * @param messageId Optional message ID for decrypt link
     * @return Formatted string
     */
    fun formatMessage(encrypted: ByteArray, format: Int = Format.COMPACT, messageId: String? = null): String {
        return nativeFormatMessage(encrypted, format, messageId)
    }

    /**
     * Parse an HSIP message from text.
     *
     * @param text Text containing HSIP message
     * @return Encrypted message bytes, or null if not found
     */
    fun parseMessage(text: String): ByteArray? {
        return nativeParseMessage(text)
    }

    /**
     * Check if text contains an HSIP message.
     *
     * @param text Text to check
     * @return true if HSIP message detected
     */
    fun containsHSIPMessage(text: String): Boolean {
        return nativeContainsHSIPMessage(text)
    }
}
```

---

## SessionManager.kt

```kotlin
package io.hsip.keyboard

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.util.concurrent.ConcurrentHashMap

data class Session(
    val id: String,
    val peerID: ByteArray,
    val displayName: String,
    val sessionKey: ByteArray,
    val createdAt: Long,
    val expiresAt: Long,
    var messageCount: Int = 0,
    var isActive: Boolean = true
) {
    fun isExpired(): Boolean {
        return System.currentTimeMillis() / 1000 >= expiresAt
    }

    fun needsRekey(): Boolean {
        return messageCount >= 1000 || isExpired()
    }
}

class SessionManager private constructor(context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(
        "hsip_sessions",
        Context.MODE_PRIVATE
    )

    private val gson = Gson()
    private val sessions = ConcurrentHashMap<String, Session>()

    companion object {
        @Volatile
        private var INSTANCE: SessionManager? = null

        fun getInstance(context: Context): SessionManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: SessionManager(context.applicationContext).also { INSTANCE = it }
            }
        }
    }

    init {
        loadSessions()
    }

    private fun loadSessions() {
        val json = prefs.getString("sessions", null) ?: return

        val type = object : TypeToken<List<Session>>() {}.type
        val loadedSessions: List<Session> = gson.fromJson(json, type)

        loadedSessions.forEach { session ->
            if (!session.isExpired()) {
                sessions[session.id] = session
            }
        }
    }

    private fun saveSessions() {
        val json = gson.toJson(sessions.values.toList())
        prefs.edit().putString("sessions", json).apply()
    }

    fun addSession(session: Session) {
        sessions[session.id] = session
        saveSessions()
    }

    fun getSession(sessionId: String): Session? {
        return sessions[sessionId]
    }

    fun findByPeerID(peerID: ByteArray): Session? {
        return sessions.values.find { it.peerID.contentEquals(peerID) && it.isActive }
    }

    fun listActiveSessions(): List<Session> {
        return sessions.values.filter { it.isActive && !it.isExpired() }
    }

    fun deactivateSession(sessionId: String) {
        sessions[sessionId]?.isActive = false
        saveSessions()
    }

    fun cleanupExpired() {
        val expired = sessions.values.filter { it.isExpired() }
        expired.forEach { sessions.remove(it.id) }
        saveSessions()
    }
}
```

---

## HSIPKeyboardService.kt (Main IME)

```kotlin
package io.hsip.keyboard

import android.inputmethodservice.InputMethodService
import android.view.View
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.unit.dp
import io.hsip.keyboard.ui.KeyboardView

class HSIPKeyboardService : InputMethodService() {

    private lateinit var hsipEngine: HSIPEngine
    private lateinit var sessionManager: SessionManager

    private var hsipModeEnabled by mutableStateOf(false)
    private var activeSession: Session? by mutableStateOf(null)
    private var currentInputBuffer = StringBuilder()

    override fun onCreate() {
        super.onCreate()

        // Initialize engines
        hsipEngine = HSIPEngine.getInstance(this)
        sessionManager = SessionManager.getInstance(this)

        // Cleanup expired sessions
        sessionManager.cleanupExpired()
    }

    override fun onCreateInputView(): View {
        val composeView = ComposeView(this)

        composeView.setContent {
            MaterialTheme {
                KeyboardView(
                    onKeyPress = { key -> handleKeyPress(key) },
                    hsipEnabled = hsipModeEnabled,
                    onToggleHSIP = { toggleHSIPMode() },
                    activeSession = activeSession,
                    onSelectSession = { session -> activeSession = session }
                )
            }
        }

        return composeView
    }

    private fun handleKeyPress(key: Key) {
        when (key) {
            is Key.Character -> {
                currentInputBuffer.append(key.char)
                currentInputConnection?.commitText(key.char.toString(), 1)
            }
            is Key.Backspace -> {
                if (currentInputBuffer.isNotEmpty()) {
                    currentInputBuffer.deleteCharAt(currentInputBuffer.length - 1)
                }
                currentInputConnection?.deleteSurroundingText(1, 0)
            }
            is Key.Enter -> {
                commitCurrentText()
            }
            is Key.Space -> {
                currentInputBuffer.append(' ')
                currentInputConnection?.commitText(" ", 1)
            }
        }
    }

    private fun commitCurrentText() {
        val text = currentInputBuffer.toString()

        if (hsipModeEnabled && activeSession != null) {
            // Encrypt with HSIP
            val encrypted = hsipEngine.encrypt(
                text,
                activeSession!!.sessionKey,
                activeSession!!.peerID
            )

            // Format message
            val formatted = hsipEngine.formatMessage(encrypted, HSIPEngine.Format.COMPACT)

            // Send encrypted text to app
            currentInputConnection?.commitText(formatted, 1)

            // Update message counter
            activeSession!!.messageCount++
        } else {
            // Send plaintext
            currentInputConnection?.commitText(text, 1)
        }

        currentInputBuffer.clear()
        currentInputConnection?.commitText("\n", 1)
    }

    private fun toggleHSIPMode() {
        if (!hsipModeEnabled && sessionManager.listActiveSessions().isEmpty()) {
            // No sessions, prompt user to set up
            // TODO: Show setup prompt
            return
        }

        hsipModeEnabled = !hsipModeEnabled

        // Auto-select first active session if none selected
        if (hsipModeEnabled && activeSession == null) {
            activeSession = sessionManager.listActiveSessions().firstOrNull()
        }
    }

    // Monitor incoming text for HSIP messages
    override fun onUpdateSelection(
        oldSelStart: Int, oldSelEnd: Int,
        newSelStart: Int, newSelEnd: Int,
        candidatesStart: Int, candidatesEnd: Int
    ) {
        super.onUpdateSelection(oldSelStart, oldSelEnd, newSelStart, newSelEnd, candidatesStart, candidatesEnd)

        // Get text from input field
        val text = currentInputConnection?.getTextBeforeCursor(500, 0)?.toString() ?: return

        // Check if it contains HSIP message
        if (hsipEngine.containsHSIPMessage(text)) {
            tryAutoDecrypt(text)
        }
    }

    private fun tryAutoDecrypt(text: String) {
        // Parse HSIP message
        val encrypted = hsipEngine.parseMessage(text) ?: return

        // Try to decrypt with active sessions
        for (session in sessionManager.listActiveSessions()) {
            val decrypted = hsipEngine.decrypt(encrypted, session.sessionKey)
            if (decrypted != null) {
                // Show decrypted preview (TODO: implement UI)
                break
            }
        }
    }
}

// Key types
sealed class Key {
    data class Character(val char: Char) : Key()
    object Backspace : Key()
    object Enter : Key()
    object Space : Key()
}
```

---

## build.gradle (app)

```gradle
plugins {
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'
    id 'org.jetbrains.kotlin.plugin.compose'
}

android {
    namespace 'io.hsip.keyboard'
    compileSdk 34

    defaultConfig {
        applicationId "io.hsip.keyboard"
        minSdk 28
        targetSdk 34
        versionCode 1
        versionName "0.1.0"

        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64'
        }
    }

    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = '17'
    }

    buildFeatures {
        compose true
    }

    sourceSets {
        main {
            jniLibs.srcDirs = ['src/main/jniLibs']
        }
    }
}

dependencies {
    // Kotlin
    implementation 'androidx.core:core-ktx:1.12.0'
    implementation 'androidx.appcompat:appcompat:1.6.1'

    // Jetpack Compose
    implementation platform('androidx.compose:compose-bom:2024.02.00')
    implementation 'androidx.compose.ui:ui'
    implementation 'androidx.compose.material3:material3'
    implementation 'androidx.compose.ui:ui-tooling-preview'
    debugImplementation 'androidx.compose.ui:ui-tooling'

    // Lifecycle
    implementation 'androidx.lifecycle:lifecycle-runtime-ktx:2.7.0'

    // JSON
    implementation 'com.google.code.gson:gson:2.10.1'
}
```

---

## Build Instructions

### 1. Build Rust Library

```bash
# Install cargo-ndk
cargo install cargo-ndk

# Add Android targets
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android

# Build for all architectures
cd crates/hsip-keyboard

cargo ndk --target aarch64-linux-android --platform 28 build --release
cargo ndk --target armv7-linux-androideabi --platform 28 build --release
cargo ndk --target x86_64-linux-android --platform 28 build --release
```

### 2. Copy Libraries

```bash
mkdir -p android/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}

cp ../../target/aarch64-linux-android/release/libhsip_keyboard.so \
   android/app/src/main/jniLibs/arm64-v8a/

cp ../../target/armv7-linux-androideabi/release/libhsip_keyboard.so \
   android/app/src/main/jniLibs/armeabi-v7a/

cp ../../target/x86_64-linux-android/release/libhsip_keyboard.so \
   android/app/src/main/jniLibs/x86_64/
```

### 3. Build APK

```bash
cd android
./gradlew assembleDebug

# Install on device
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## User Setup

1. **Enable Keyboard**:
   - Settings → System → Languages & Input
   - On-screen keyboard → HSIP Keyboard → Enable

2. **Generate Identity** (first time):
   - Open HSIP Keyboard app
   - Tap "Generate Identity"
   - Save recovery phrase

3. **Add Contact** (exchange keys):
   - Tap "Add Contact"
   - Option A: Scan QR code
   - Option B: Enter PeerID manually
   - Option C: Share via deep link

4. **Use Keyboard**:
   - Open any messaging app
   - Tap message input → Select HSIP Keyboard
   - Toggle HSIP mode ON (🔒 icon)
   - Select recipient
   - Type normally → Message encrypted automatically

---

## Testing Checklist

- [ ] Keyboard appears when tapping input field
- [ ] Can type normally with HSIP mode OFF
- [ ] Can toggle HSIP mode ON
- [ ] Message encrypts when sending with HSIP ON
- [ ] Encrypted message appears in target app (Instagram, WhatsApp, etc.)
- [ ] Recipient can decrypt (if they have HSIP)
- [ ] Auto-decrypt works for incoming messages
- [ ] Sessions persist across app restarts
- [ ] Expired sessions are cleaned up

---

## Next Steps

1. **Implement UI**: Complete Jetpack Compose keyboard layout
2. **QR Code Exchange**: Add camera permission + QR scanner
3. **Deep Links**: Handle hsip:// URLs for key exchange
4. **Decrypt Helper**: Web app or share intent for non-HSIP users
5. **Polish**: Add animations, themes, emoji support
6. **Publish**: Google Play Store listing

---

This is the complete foundation for HSIP Secure Keyboard on Android! 🚀🔒
