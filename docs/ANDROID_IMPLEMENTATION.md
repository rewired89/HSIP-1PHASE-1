# Android Implementation Guide

## Overview

The Android implementation of HSIP Private DM Intercept uses:
- **AccessibilityService** for monitoring UI events across apps
- **TYPE_APPLICATION_OVERLAY** windows for the intercept UI
- **JNI bridge** to communicate with Rust core logic

---

## Architecture

```
┌─────────────────────────────────────┐
│   Android App (Kotlin/Java)         │
├─────────────────────────────────────┤
│  HSIPAccessibilityService           │
│  ├─ AccessibilityEventListener      │
│  ├─ OverlayWindowManager            │
│  └─ JNI Bridge (Rust)               │
├─────────────────────────────────────┤
│  Rust Core (hsip-intercept)         │
│  ├─ Pattern Matcher                 │
│  ├─ HSIP Router                     │
│  └─ Privacy Engine                  │
└─────────────────────────────────────┘
```

---

## Required Permissions

### AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.hsip.intercept">

    <!-- Overlay permission for floating UI -->
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />

    <!-- Internet for HSIP protocol -->
    <uses-permission android:name="android.permission.INTERNET" />

    <!-- Accessibility service permission (granted by user in Settings) -->
    <!-- This is automatically granted when user enables the service -->

    <application
        android:name=".HSIPApplication"
        android:label="HSIP Private DM"
        android:icon="@mipmap/ic_launcher">

        <!-- Main Activity -->
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Messenger Activity -->
        <activity
            android:name=".MessengerActivity"
            android:exported="false"
            android:launchMode="singleTask" />

        <!-- Accessibility Service -->
        <service
            android:name=".accessibility.HSIPAccessibilityService"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
            android:exported="true">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
            <meta-data
                android:name="android.accessibilityservice"
                android:resource="@xml/accessibility_service_config" />
        </service>

    </application>

</manifest>
```

### res/xml/accessibility_service_config.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<accessibility-service
    xmlns:android="http://schemas.android.com/apk/res/android"
    android:description="@string/accessibility_service_description"
    android:accessibilityEventTypes="typeViewClicked|typeViewFocused|typeWindowStateChanged"
    android:accessibilityFlags="flagReportViewIds|flagRetrieveInteractiveWindows"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:notificationTimeout="100"
    android:canRetrieveWindowContent="true" />
```

### res/values/strings.xml

```xml
<resources>
    <string name="app_name">HSIP Private DM</string>
    <string name="accessibility_service_description">
        HSIP Private DM Intercept detects when you\'re about to send a message
        and offers a private, end-to-end encrypted alternative through HSIP protocol.

        This service only monitors UI events to detect messaging actions.
        No message content is read or transmitted.
    </string>
</resources>
```

---

## Kotlin Implementation

### HSIPAccessibilityService.kt

```kotlin
package org.hsip.intercept.accessibility

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.util.Log
import org.hsip.intercept.overlay.OverlayManager
import org.hsip.intercept.jni.RustBridge

class HSIPAccessibilityService : AccessibilityService() {

    private lateinit var overlayManager: OverlayManager
    private lateinit var rustBridge: RustBridge

    companion object {
        private const val TAG = "HSIPAccessibility"

        // Pattern matching resource IDs
        private val MESSAGING_PATTERNS = mapOf(
            "com.instagram.android" to listOf(
                "direct_inbox_button",
                "row_inbox_container",
                "message_composer"
            ),
            "com.facebook.katana" to listOf(
                "messaging_button",
                "composer_text"
            ),
            "com.google.android.gm" to listOf(
                "compose",
                "compose_button"
            ),
            "com.whatsapp" to listOf(
                "chat_input_field",
                "conversation_entry_panel"
            )
        )
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        Log.i(TAG, "HSIP Accessibility Service connected")

        // Initialize overlay manager
        overlayManager = OverlayManager(this)

        // Initialize Rust bridge
        rustBridge = RustBridge()
        rustBridge.initialize()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        // Only process relevant event types
        when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_CLICKED,
            AccessibilityEvent.TYPE_VIEW_FOCUSED,
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                processEvent(event)
            }
        }
    }

    private fun processEvent(event: AccessibilityEvent) {
        // Get package name
        val packageName = event.packageName?.toString() ?: return

        // Check if this is a monitored app
        if (!MESSAGING_PATTERNS.containsKey(packageName)) {
            return
        }

        // Get root node
        val rootNode = rootInActiveWindow ?: return

        // Search for messaging UI elements
        val messagingElement = findMessagingElement(rootNode, packageName)

        if (messagingElement != null) {
            Log.d(TAG, "Messaging action detected in $packageName")

            // Extract event metadata
            val metadata = extractMetadata(event, messagingElement)

            // Send to Rust for pattern matching
            val shouldIntercept = rustBridge.matchEvent(
                packageName,
                metadata["resource_id"] ?: "",
                metadata["class_name"] ?: "",
                metadata["text_content"] ?: ""
            )

            if (shouldIntercept) {
                // Extract recipient if possible
                val recipient = extractRecipient(rootNode, packageName)

                // Show intercept overlay
                overlayManager.show(packageName, recipient) { choice ->
                    when (choice) {
                        OverlayManager.Choice.SEND_PRIVATELY -> {
                            // Open HSIP Messenger
                            openMessenger(recipient)
                        }
                        OverlayManager.Choice.CONTINUE -> {
                            // Do nothing
                        }
                        OverlayManager.Choice.DISABLE_FOR_APP -> {
                            // Disable intercept for this app
                            rustBridge.disablePlatform(packageName)
                        }
                    }
                }
            }
        }

        rootNode.recycle()
    }

    private fun findMessagingElement(
        node: AccessibilityNodeInfo,
        packageName: String
    ): AccessibilityNodeInfo? {
        val patterns = MESSAGING_PATTERNS[packageName] ?: return null

        // Check current node
        val resourceId = node.viewIdResourceName
        if (resourceId != null) {
            for (pattern in patterns) {
                if (resourceId.contains(pattern)) {
                    return node
                }
            }
        }

        // Recursively search children
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val result = findMessagingElement(child, packageName)
            if (result != null) {
                return result
            }
            child.recycle()
        }

        return null
    }

    private fun extractMetadata(
        event: AccessibilityEvent,
        node: AccessibilityNodeInfo
    ): Map<String, String> {
        return mapOf(
            "resource_id" to (node.viewIdResourceName ?: ""),
            "class_name" to (node.className?.toString() ?: ""),
            "text_content" to (node.text?.toString() ?: ""),
            "content_description" to (node.contentDescription?.toString() ?: "")
        )
    }

    private fun extractRecipient(
        rootNode: AccessibilityNodeInfo,
        packageName: String
    ): String? {
        // Platform-specific recipient extraction
        when (packageName) {
            "com.instagram.android" -> {
                // Look for username in title bar
                return findTextByResourceId(rootNode, "action_bar_title")
            }
            "com.google.android.gm" -> {
                // Look for email in "To:" field
                return findTextByResourceId(rootNode, "to")
            }
            "com.whatsapp" -> {
                // Look for contact name in title
                return findTextByResourceId(rootNode, "conversation_contact_name")
            }
        }
        return null
    }

    private fun findTextByResourceId(
        node: AccessibilityNodeInfo,
        resourceIdPart: String
    ): String? {
        val resourceId = node.viewIdResourceName
        if (resourceId != null && resourceId.contains(resourceIdPart)) {
            return node.text?.toString()
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val result = findTextByResourceId(child, resourceIdPart)
            child.recycle()
            if (result != null) {
                return result
            }
        }

        return null
    }

    private fun openMessenger(recipient: String?) {
        val intent = Intent(this, MessengerActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("recipient", recipient)
        }
        startActivity(intent)
    }

    override fun onInterrupt() {
        Log.w(TAG, "Accessibility service interrupted")
    }

    override fun onDestroy() {
        super.onDestroy()
        overlayManager.cleanup()
        rustBridge.cleanup()
    }
}
```

---

## JNI Bridge

### RustBridge.kt

```kotlin
package org.hsip.intercept.jni

class RustBridge {

    companion object {
        init {
            System.loadLibrary("hsip_intercept")
        }
    }

    // Native methods (implemented in Rust)
    external fun initialize(): Boolean

    external fun matchEvent(
        packageName: String,
        resourceId: String,
        className: String,
        textContent: String
    ): Boolean

    external fun disablePlatform(packageName: String)

    external fun cleanup()
}
```

### Rust JNI Implementation (add to hsip-intercept/src/android/)

```rust
// android/jni.rs
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jboolean;
use crate::patterns::PatternMatcher;
use std::sync::Mutex;

static PATTERN_MATCHER: Mutex<Option<PatternMatcher>> = Mutex::new(None);

#[no_mangle]
pub extern "system" fn Java_org_hsip_intercept_jni_RustBridge_initialize(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    // Initialize pattern matcher
    let config = crate::InterceptConfig::default();
    match PatternMatcher::load_from_config(&config) {
        Ok(matcher) => {
            *PATTERN_MATCHER.lock().unwrap() = Some(matcher);
            1 // true
        }
        Err(_) => 0, // false
    }
}

#[no_mangle]
pub extern "system" fn Java_org_hsip_intercept_jni_RustBridge_matchEvent(
    env: JNIEnv,
    _class: JClass,
    package_name: JString,
    resource_id: JString,
    class_name: JString,
    text_content: JString,
) -> jboolean {
    // Convert JStrings to Rust strings
    let package_name: String = env.get_string(package_name).unwrap().into();
    let resource_id: String = env.get_string(resource_id).unwrap().into();
    // ... convert others

    // TODO: Implement pattern matching logic
    // For now, return true for known messaging apps
    1
}
```

---

## Overlay Implementation

### OverlayManager.kt

```kotlin
package org.hsip.intercept.overlay

import android.content.Context
import android.graphics.PixelFormat
import android.os.Build
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import org.hsip.intercept.R

class OverlayManager(private val context: Context) {

    enum class Choice {
        SEND_PRIVATELY,
        CONTINUE,
        DISABLE_FOR_APP
    }

    private val windowManager: WindowManager =
        context.getSystemService(Context.WINDOW_SERVICE) as WindowManager

    private var overlayView: View? = null

    fun show(packageName: String, recipient: String?, onChoice: (Choice) -> Unit) {
        // Inflate overlay layout
        val inflater = LayoutInflater.from(context)
        overlayView = inflater.inflate(R.layout.intercept_overlay, null)

        // Set up UI
        val titleText = overlayView?.findViewById<TextView>(R.id.title)
        val messageText = overlayView?.findViewById<TextView>(R.id.message)
        val sendPrivatelyBtn = overlayView?.findViewById<Button>(R.id.btn_send_privately)
        val continueBtn = overlayView?.findViewById<Button>(R.id.btn_continue)

        titleText?.text = "🔒 Send through HSIP instead?"
        messageText?.text = if (recipient != null) {
            "You're about to message $recipient.\nSend privately via HSIP?"
        } else {
            "Send this message through HSIP for end-to-end encryption?"
        }

        sendPrivatelyBtn?.setOnClickListener {
            hide()
            onChoice(Choice.SEND_PRIVATELY)
        }

        continueBtn?.setOnClickListener {
            hide()
            onChoice(Choice.CONTINUE)
        }

        // Set up window layout params
        val layoutParams = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                @Suppress("DEPRECATION")
                WindowManager.LayoutParams.TYPE_PHONE
            },
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.END
            x = 20
            y = 100
        }

        // Add overlay to window manager
        windowManager.addView(overlayView, layoutParams)
    }

    fun hide() {
        overlayView?.let { view ->
            windowManager.removeView(view)
            overlayView = null
        }
    }

    fun cleanup() {
        hide()
    }
}
```

---

## Build Configuration

### build.gradle (app module)

```gradle
android {
    ...

    defaultConfig {
        ...
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64'
        }
    }

    sourceSets {
        main {
            jniLibs.srcDirs = ['src/main/jniLibs']
        }
    }
}

dependencies {
    // Standard Android dependencies
    implementation 'androidx.core:core-ktx:1.12.0'
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.11.0'
}
```

### Cargo.toml addition for Android

```toml
[lib]
crate-type = ["cdylib", "staticlib"]

[target.'cfg(target_os = "android")'.dependencies]
jni = "0.21"
```

---

## Compilation Instructions

### 1. Setup Android NDK

```bash
# Install Android NDK via Android Studio or command line
export ANDROID_NDK_ROOT=/path/to/android-ndk

# Install cargo-ndk
cargo install cargo-ndk
```

### 2. Build Rust library for Android

```bash
# Add Android targets
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android

# Build for all Android architectures
cargo ndk --target aarch64-linux-android --platform 28 build --release
cargo ndk --target armv7-linux-androideabi --platform 28 build --release
cargo ndk --target x86_64-linux-android --platform 28 build --release
```

### 3. Copy libraries to Android project

```bash
mkdir -p android/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}

cp target/aarch64-linux-android/release/libhsip_intercept.so \
   android/app/src/main/jniLibs/arm64-v8a/

cp target/armv7-linux-androideabi/release/libhsip_intercept.so \
   android/app/src/main/jniLibs/armeabi-v7a/

cp target/x86_64-linux-android/release/libhsip_intercept.so \
   android/app/src/main/jniLibs/x86_64/
```

### 4. Build Android APK

```bash
cd android
./gradlew assembleDebug
```

---

## User Setup Flow

1. **Install APK** on Android device
2. **Grant Permissions**:
   - Open Settings → Apps → HSIP Private DM
   - Enable "Display over other apps" (SYSTEM_ALERT_WINDOW)
3. **Enable Accessibility Service**:
   - Open Settings → Accessibility → HSIP Private DM
   - Toggle ON
   - Read and accept permission dialog
4. **Configure Intercept**:
   - Open HSIP app
   - Select which apps to monitor (Instagram, WhatsApp, etc.)
   - Configure privacy settings (timing obfuscation, etc.)

---

## Testing

### Manual Testing Checklist

- [ ] Open Instagram, click DM button → Overlay appears
- [ ] Click "Send Privately" → HSIP Messenger opens
- [ ] Click "Continue" → Overlay dismisses, Instagram continues
- [ ] Open Gmail, click Compose → Overlay appears with recipient extraction
- [ ] Test with disabled app → No overlay shown
- [ ] Test timeout → Overlay auto-dismisses after configured time

### ADB Testing Commands

```bash
# Check if accessibility service is enabled
adb shell settings get secure enabled_accessibility_services

# Check overlay permission
adb shell appops get org.hsip.intercept SYSTEM_ALERT_WINDOW

# View logs
adb logcat | grep HSIP
```

---

## Privacy Compliance

### Google Play Policy Requirements

1. **Accessibility Service Declaration**:
   - Clear description of why accessibility is needed
   - Must be primary use case (not additional feature)
   - Privacy policy link required

2. **Overlay Permission**:
   - Must explain why overlay is needed
   - User must explicitly grant permission

3. **Data Handling**:
   - No collection of user data
   - No analytics or tracking
   - All processing local only

### Best Practices

- ✅ Transparent permission requests
- ✅ Clear privacy policy
- ✅ Opt-in by default
- ✅ Easy disable mechanism
- ✅ No network requests for event data
- ✅ Local-only pattern matching

---

## Future Enhancements

1. **Jetpack Compose UI**: Modern declarative UI for overlay
2. **WorkManager**: Background processing for offline queue
3. **Room Database**: Local contact book and message cache
4. **Biometric Auth**: Protect messenger access
5. **Share Extension**: Android Share Sheet integration

