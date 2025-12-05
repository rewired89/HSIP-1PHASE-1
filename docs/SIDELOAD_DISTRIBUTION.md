# HSIP Keyboard - Sideload Distribution Guide

## Overview

HSIP Keyboard is distributed via **direct APK download** from the official HSIP website, bypassing Google Play Store. This is standard practice for privacy-focused apps and gives us full control over distribution, updates, and user privacy.

---

## Why Sideload?

### Advantages
- ✅ **No Google involvement** - No Play Store fees, policies, or tracking
- ✅ **Faster updates** - Push updates immediately without waiting for review
- ✅ **Full control** - No risk of arbitrary bans or policy changes
- ✅ **Privacy first** - No Google analytics or mandatory permissions
- ✅ **Industry standard** - Signal, F-Droid, Briar, and many security apps use this

### Legal & Safe
- Android natively supports sideloading (it's a feature, not a hack)
- Users explicitly enable "Install from Unknown Sources"
- APK is cryptographically signed (verifiable authenticity)
- No jailbreaking or rooting required

---

## Build Process

### 1. Generate Signing Key (One-Time Setup)

```bash
# Create keystore directory
mkdir -p android/keystore

# Generate release keystore
keytool -genkey -v -keystore android/keystore/hsip-keyboard-release.jks \
  -alias hsip-keyboard \
  -keyalg RSA \
  -keysize 4096 \
  -validity 10000 \
  -storepass YOUR_STORE_PASSWORD \
  -keypass YOUR_KEY_PASSWORD \
  -dname "CN=HSIP Keyboard, OU=Security, O=HSIP, L=Unknown, ST=Unknown, C=US"

# IMPORTANT: Back up this keystore! Store in:
# - Password manager
# - Encrypted USB drive
# - Secure cloud storage (encrypted)
# If you lose this, you can't update the app!
```

### 2. Configure Gradle Signing

Create `android/keystore.properties`:
```properties
storePassword=YOUR_STORE_PASSWORD
keyPassword=YOUR_KEY_PASSWORD
keyAlias=hsip-keyboard
storeFile=keystore/hsip-keyboard-release.jks
```

Update `android/app/build.gradle`:
```gradle
android {
    // ... existing config ...

    signingConfigs {
        release {
            def keystorePropertiesFile = rootProject.file("keystore.properties")
            def keystoreProperties = new Properties()
            keystoreProperties.load(new FileInputStream(keystorePropertiesFile))

            storeFile file(keystoreProperties['storeFile'])
            storePassword keystoreProperties['storePassword']
            keyPassword keystoreProperties['keyPassword']
            keyAlias keystoreProperties['keyAlias']
        }
    }

    buildTypes {
        release {
            signingConfig signingConfigs.release
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}
```

### 3. Build Release APK

```bash
#!/bin/bash
# build-release.sh

set -e

echo "Building HSIP Keyboard Release APK..."

# Step 1: Build Rust libraries for all Android architectures
echo "Building Rust libraries..."
cd crates/hsip-keyboard

cargo ndk --target aarch64-linux-android --platform 28 build --release
cargo ndk --target armv7-linux-androideabi --platform 28 build --release
cargo ndk --target x86_64-linux-android --platform 28 build --release

echo "Rust libraries built successfully"

# Step 2: Copy libraries to Android project
echo "Copying native libraries..."
mkdir -p ../../android/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}

cp ../../target/aarch64-linux-android/release/libhsip_keyboard.so \
   ../../android/app/src/main/jniLibs/arm64-v8a/

cp ../../target/armv7-linux-androideabi/release/libhsip_keyboard.so \
   ../../android/app/src/main/jniLibs/armeabi-v7a/

cp ../../target/x86_64-linux-android/release/libhsip_keyboard.so \
   ../../android/app/src/main/jniLibs/x86_64/

echo "Native libraries copied"

# Step 3: Build Android APK
echo "Building Android APK..."
cd ../../android

./gradlew clean
./gradlew assembleRelease

echo "APK built successfully!"

# Step 4: Output APK location
APK_PATH="app/build/outputs/apk/release/app-release.apk"
echo ""
echo "✅ Release APK ready: $APK_PATH"
echo ""

# Step 5: Get APK info
APK_SIZE=$(du -h "$APK_PATH" | cut -f1)
APK_SHA256=$(sha256sum "$APK_PATH" | cut -d' ' -f1)

echo "APK Size: $APK_SIZE"
echo "SHA-256: $APK_SHA256"
echo ""

# Step 6: Verify signature
echo "Verifying APK signature..."
jarsigner -verify -verbose -certs "$APK_PATH"

echo ""
echo "Build complete! 🚀"
```

Make it executable:
```bash
chmod +x build-release.sh
```

### 4. Run Build

```bash
./build-release.sh
```

Output:
```
Building HSIP Keyboard Release APK...
Building Rust libraries...
   Compiling hsip-keyboard v0.1.0
    Finished release [optimized] target(s) in 45.2s
Rust libraries built successfully
Copying native libraries...
Native libraries copied
Building Android APK...
BUILD SUCCESSFUL in 1m 23s
✅ Release APK ready: app/build/outputs/apk/release/app-release.apk

APK Size: 8.4M
SHA-256: a3f5e2d8c1b9f4e6a7c2d9b8e1f3a5c7d2e9f1b4c6a8e3f7d1c5b9a2e8f4d6c1
```

---

## Distribution

### 1. Host APK on HSIP Website

```
https://hsip.io/
  ├── download/
  │   ├── hsip-keyboard-v0.1.0.apk
  │   ├── hsip-keyboard-latest.apk (symlink)
  │   └── checksums.txt
  └── install.html (installation guide)
```

**checksums.txt:**
```
# HSIP Keyboard v0.1.0
# Date: 2025-12-05

SHA-256: a3f5e2d8c1b9f4e6a7c2d9b8e1f3a5c7d2e9f1b4c6a8e3f7d1c5b9a2e8f4d6c1
APK Size: 8.4 MB
Min Android: 9.0 (API 28)

# Verify:
sha256sum hsip-keyboard-v0.1.0.apk
```

### 2. Create Download Page

**install.html:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Install HSIP Keyboard</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
        }
        .download-btn {
            display: inline-block;
            background: #007bff;
            color: white;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            margin: 20px 0;
        }
        .steps {
            background: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .checksum {
            background: #e8e8e8;
            padding: 10px;
            font-family: monospace;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <h1>🔒 HSIP Secure Keyboard</h1>
    <p>End-to-end encrypted keyboard for Android. Works with Instagram, WhatsApp, Gmail, and all messaging apps.</p>

    <a href="/download/hsip-keyboard-latest.apk" class="download-btn">
        📥 Download HSIP Keyboard (8.4 MB)
    </a>

    <div class="steps">
        <h2>Installation Steps</h2>
        <ol>
            <li><strong>Enable Unknown Sources</strong>
                <ul>
                    <li>Settings → Security</li>
                    <li>Enable "Install from Unknown Sources" or "Install Unknown Apps"</li>
                    <li>(On newer Android: Enable for your browser)</li>
                </ul>
            </li>
            <li><strong>Download APK</strong>
                <ul>
                    <li>Tap the download button above</li>
                    <li>APK will download to your device</li>
                </ul>
            </li>
            <li><strong>Install</strong>
                <ul>
                    <li>Open the downloaded file</li>
                    <li>Tap "Install"</li>
                    <li>Wait for installation to complete</li>
                </ul>
            </li>
            <li><strong>Enable Keyboard</strong>
                <ul>
                    <li>Settings → System → Languages & Input</li>
                    <li>On-screen keyboard → HSIP Keyboard → Enable</li>
                </ul>
            </li>
            <li><strong>Start Using</strong>
                <ul>
                    <li>Open any messaging app</li>
                    <li>Tap message input → Select HSIP Keyboard</li>
                    <li>Toggle HSIP mode ON (🔒 icon)</li>
                </ul>
            </li>
        </ol>
    </div>

    <h2>Verify Authenticity</h2>
    <p>Always verify the APK before installing:</p>
    <div class="checksum">
        SHA-256: a3f5e2d8c1b9f4e6a7c2d9b8e1f3a5c7d2e9f1b4c6a8e3f7d1c5b9a2e8f4d6c1
    </div>
    <p>On your computer:
    <pre>sha256sum hsip-keyboard-v0.1.0.apk</pre>
    </p>

    <h2>Source Code</h2>
    <p>HSIP is fully open-source. Audit the code at:</p>
    <p><a href="https://github.com/rewired89/HSIP-1PHASE">github.com/rewired89/HSIP-1PHASE</a></p>

    <h2>Privacy</h2>
    <ul>
        <li>✅ All encryption done locally on device</li>
        <li>✅ No cloud dependencies</li>
        <li>✅ No analytics or tracking</li>
        <li>✅ Open-source and auditable</li>
    </ul>

    <h2>Support</h2>
    <p>Questions? Issues? Visit:</p>
    <p><a href="https://github.com/rewired89/HSIP-1PHASE/issues">GitHub Issues</a></p>
</body>
</html>
```

---

## Auto-Update Mechanism

### 1. Version Check API

Host `version.json` on HSIP website:
```json
{
  "latest_version": "0.1.0",
  "latest_version_code": 1,
  "download_url": "https://hsip.io/download/hsip-keyboard-v0.1.0.apk",
  "sha256": "a3f5e2d8c1b9f4e6a7c2d9b8e1f3a5c7d2e9f1b4c6a8e3f7d1c5b9a2e8f4d6c1",
  "min_android_version": 28,
  "release_date": "2025-12-05",
  "changelog": [
    "Initial release",
    "E2E encryption for all messaging apps",
    "Session management",
    "Auto-decryption"
  ]
}
```

### 2. In-App Update Checker

**UpdateChecker.kt:**
```kotlin
class UpdateChecker(private val context: Context) {

    private val currentVersionCode = BuildConfig.VERSION_CODE

    suspend fun checkForUpdate(): UpdateInfo? = withContext(Dispatchers.IO) {
        try {
            val url = URL("https://hsip.io/version.json")
            val connection = url.openConnection() as HttpURLConnection
            connection.connectTimeout = 5000
            connection.readTimeout = 5000

            val response = connection.inputStream.bufferedReader().readText()
            val json = JSONObject(response)

            val latestVersionCode = json.getInt("latest_version_code")

            if (latestVersionCode > currentVersionCode) {
                UpdateInfo(
                    version = json.getString("latest_version"),
                    downloadUrl = json.getString("download_url"),
                    sha256 = json.getString("sha256"),
                    changelog = json.getJSONArray("changelog").let { array ->
                        List(array.length()) { array.getString(it) }
                    }
                )
            } else {
                null // Already up to date
            }
        } catch (e: Exception) {
            Log.e("UpdateChecker", "Failed to check for updates", e)
            null
        }
    }

    fun promptUpdate(updateInfo: UpdateInfo) {
        val intent = Intent(Intent.ACTION_VIEW).apply {
            data = Uri.parse(updateInfo.downloadUrl)
        }
        context.startActivity(intent)
    }
}

data class UpdateInfo(
    val version: String,
    val downloadUrl: String,
    val sha256: String,
    val changelog: List<String>
)
```

### 3. Automatic Check on App Launch

```kotlin
class HSIPApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Check for updates (daily)
        val prefs = getSharedPreferences("app", MODE_PRIVATE)
        val lastCheck = prefs.getLong("last_update_check", 0)
        val now = System.currentTimeMillis()

        if (now - lastCheck > 24 * 60 * 60 * 1000) { // 24 hours
            lifecycleScope.launch {
                val updateChecker = UpdateChecker(this@HSIPApplication)
                val updateInfo = updateChecker.checkForUpdate()

                if (updateInfo != null) {
                    // Show update notification
                    showUpdateNotification(updateInfo)
                }

                prefs.edit().putLong("last_update_check", now).apply()
            }
        }
    }

    private fun showUpdateNotification(updateInfo: UpdateInfo) {
        val notification = NotificationCompat.Builder(this, "updates")
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("HSIP Keyboard Update Available")
            .setContentText("Version ${updateInfo.version} is ready to download")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(/* open download */)
            .build()

        notificationManager.notify(UPDATE_NOTIFICATION_ID, notification)
    }
}
```

---

## Security Best Practices

### 1. APK Signing

✅ **Always sign with same keystore**
- Users can verify authenticity
- Android enforces signature matching for updates

✅ **Use strong passwords**
- Store in password manager
- Never commit to git

✅ **Backup keystore securely**
- Encrypted cloud storage
- Physical USB drive
- Password manager attachments

### 2. Reproducible Builds

Allow community to verify APK matches source:

```bash
# Build from source
git clone https://github.com/rewired89/HSIP-1PHASE
cd HSIP-1PHASE
git checkout v0.1.0
./build-release.sh

# Verify signature matches official APK
sha256sum android/app/build/outputs/apk/release/app-release.apk
# Should match published checksum
```

### 3. Code Signing Certificate

Consider getting a code signing certificate for added trust:
- EV Code Signing Certificate (~$200/year)
- Display "Verified Publisher" in Android install prompt
- Not required, but increases user trust

---

## Legal & Compliance

### Terms of Service

Create `terms.html`:
```
HSIP Keyboard Terms of Service

1. Open Source: HSIP is licensed under MIT/Apache-2.0
2. No Warranty: Software provided "as-is"
3. Privacy: No data collection, all processing local
4. Updates: Automatic update checks (can be disabled)
5. Liability: Use at your own risk
```

### Privacy Policy

Create `privacy.html`:
```
HSIP Keyboard Privacy Policy

Data Collection: NONE
- No analytics
- No crash reporting
- No user tracking
- No cloud sync (optional, encrypted)

Keyboard Access:
- Required for IME functionality
- All encryption done locally
- No network requests from keyboard

Updates:
- Daily check for new versions
- Only version.json fetched
- No user identification

Contact:
- Email: privacy@hsip.io
- GitHub: github.com/rewired89/HSIP-1PHASE
```

---

## Deployment Checklist

- [ ] Generate release keystore (backed up securely)
- [ ] Build signed APK
- [ ] Verify APK signature
- [ ] Calculate SHA-256 checksum
- [ ] Upload APK to hsip.io/download/
- [ ] Create install.html page
- [ ] Update version.json
- [ ] Create checksums.txt
- [ ] Test download + install on real device
- [ ] Verify auto-update works
- [ ] Announce release (GitHub, social media)

---

## User Installation Guide (TL;DR)

For users who ask "How do I install?":

```
1. Go to https://hsip.io/download
2. Tap "Download HSIP Keyboard"
3. Open downloaded file
4. Tap "Install" (enable Unknown Sources if prompted)
5. Settings → System → Languages & Input
6. Enable "HSIP Keyboard"
7. Open any messaging app
8. Tap 🔒 to enable HSIP mode
9. Start typing encrypted messages!
```

---

## Conclusion

Sideload distribution gives us:
- ✅ Full control over updates
- ✅ No Google dependencies
- ✅ Faster iteration
- ✅ Better privacy for users
- ✅ Standard practice for security apps

This is the right approach for HSIP! 🚀🔒
