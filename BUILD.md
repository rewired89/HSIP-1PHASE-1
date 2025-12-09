# HSIP Keyboard - Build Guide

Complete guide to building the HSIP Secure Keyboard for Android and iOS.

## 📋 Prerequisites

### For Both Platforms

1. **Rust** (1.70+)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Rust Android/iOS Targets**
   ```bash
   # Android targets
   rustup target add aarch64-linux-android armv7-linux-androideabi
   rustup target add i686-linux-android x86_64-linux-android

   # iOS targets
   rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
   ```

### For Android

1. **Android Studio** (latest version)
   - Download from: https://developer.android.com/studio

2. **Android SDK** (API 26+)
   - Install via Android Studio SDK Manager

3. **Android NDK** (r25+)
   ```bash
   # Via Android Studio: Tools → SDK Manager → SDK Tools → NDK
   ```

4. **Environment Variables**
   ```bash
   export ANDROID_HOME=$HOME/Android/Sdk
   export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/25.2.9519653
   ```

5. **Cargo NDK** (for cross-compilation)
   ```bash
   cargo install cargo-ndk
   ```

### For iOS

1. **macOS** (required for iOS development)

2. **Xcode** (14.0+)
   - Download from Mac App Store

3. **Xcode Command Line Tools**
   ```bash
   xcode-select --install
   ```

4. **Apple Developer Account** ($99/year)
   - Required for device testing and distribution
   - Sign up at: https://developer.apple.com

---

## 🤖 Building for Android

### Step 1: Configure Android NDK

Create `~/.cargo/config.toml`:

```toml
[target.aarch64-linux-android]
ar = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang"

[target.armv7-linux-androideabi]
ar = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi30-clang"

[target.i686-linux-android]
ar = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android30-clang"

[target.x86_64-linux-android]
ar = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android30-clang"
```

**Note:** Replace `darwin-x86_64` with your platform:
- macOS Intel: `darwin-x86_64`
- macOS Apple Silicon: `darwin-aarch64`
- Linux: `linux-x86_64`

### Step 2: Build Rust Library

```bash
cd crates/hsip-keyboard

# Build for all Android architectures
cargo ndk --target aarch64-linux-android --platform 30 build --release
cargo ndk --target armv7-linux-androideabi --platform 30 build --release
cargo ndk --target i686-linux-android --platform 30 build --release
cargo ndk --target x86_64-linux-android --platform 30 build --release
```

### Step 3: Copy Native Libraries

```bash
cd ../../android-app

mkdir -p app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

cp ../target/aarch64-linux-android/release/libhsip_keyboard.so app/src/main/jniLibs/arm64-v8a/
cp ../target/armv7-linux-androideabi/release/libhsip_keyboard.so app/src/main/jniLibs/armeabi-v7a/
cp ../target/x86_64-linux-android/release/libhsip_keyboard.so app/src/main/jniLibs/x86_64/
cp ../target/i686-linux-android/release/libhsip_keyboard.so app/src/main/jniLibs/x86/
```

### Step 4: Open in Android Studio

1. Open Android Studio
2. File → Open → Select `android-app/` directory
3. Wait for Gradle sync to complete
4. Build → Make Project

### Step 5: Build APK

**Option A: Using Build Script (Recommended)**
```bash
cd android-app
./build-apk.sh
```

**Option B: Using Android Studio**
1. Build → Build Bundle(s) / APK(s) → Build APK(s)
2. APK location: `app/build/outputs/apk/debug/app-debug.apk`

**Option C: Using Gradle**
```bash
cd android-app
./gradlew assembleDebug      # Debug APK
./gradlew assembleRelease    # Release APK
```

### Step 6: Sign APK (for release)

1. Generate keystore:
   ```bash
   keytool -genkey -v -keystore hsip-release.keystore \
     -alias hsip -keyalg RSA -keysize 2048 -validity 10000
   ```

2. Sign APK:
   ```bash
   jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
     -keystore hsip-release.keystore \
     app/build/outputs/apk/release/app-release-unsigned.apk hsip
   ```

3. Align APK:
   ```bash
   zipalign -v 4 app-release-unsigned.apk hsip-keyboard.apk
   ```

### Step 7: Install on Device

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## 🍎 Building for iOS

### Step 1: Build Rust Library

```bash
cd crates/hsip-keyboard

# Build for iOS device (arm64)
cargo build --release --target aarch64-apple-ios

# Build for iOS simulator (x86_64)
cargo build --release --target x86_64-apple-ios

# Build for iOS simulator (Apple Silicon)
cargo build --release --target aarch64-apple-ios-sim
```

### Step 2: Create Universal Library

```bash
cd ../../ios-app
mkdir -p Frameworks

# Create universal library for simulator
lipo -create \
    ../target/x86_64-apple-ios/release/libhsip_keyboard.a \
    ../target/aarch64-apple-ios-sim/release/libhsip_keyboard.a \
    -output Frameworks/libhsip_keyboard_sim.a

# Copy device library
cp ../target/aarch64-apple-ios/release/libhsip_keyboard.a \
   Frameworks/libhsip_keyboard_device.a
```

### Step 3: Create Xcode Project

1. Open Xcode
2. Create new iOS App project:
   - Product Name: `HSIP Keyboard`
   - Bundle ID: `io.hsip.keyboard`
   - Language: Swift
   - User Interface: SwiftUI

3. Add Keyboard Extension target:
   - File → New → Target → Custom Keyboard Extension
   - Product Name: `HSIPKeyboardExtension`
   - Bundle ID: `io.hsip.keyboard.extension`

4. Add Rust static library:
   - Select project → Build Phases → Link Binary With Libraries
   - Click `+` → Add Other → Add Files
   - Add `Frameworks/libhsip_keyboard_device.a` (for device build)
   - For simulator: Add `Frameworks/libhsip_keyboard_sim.a`

5. Add Swift files:
   - Drag all `.swift` files from `ios-app/` into Xcode
   - `Shared/HSIPManager.swift` → Shared between app and extension
   - `MainApp/ContentView.swift` → Main app target
   - `KeyboardExtension/KeyboardViewController.swift` → Extension target

6. Configure Info.plist files:
   - Use `ios-app/Info.plist` for main app
   - Use `ios-app/KeyboardExtension/Info.plist` for extension

### Step 4: Configure Build Settings

1. **App Groups** (for data sharing between app and extension):
   - Select project → Signing & Capabilities
   - Click `+ Capability` → App Groups
   - Add group: `group.io.hsip.keyboard`
   - Do this for BOTH targets (main app and extension)

2. **Code Signing**:
   - Select project → Signing & Capabilities
   - Team: Select your Apple Developer team
   - Signing Certificate: Automatic or Manual

3. **Build Settings**:
   - Search for "Other Linker Flags"
   - Add: `-lc++` (required for Rust FFI)

### Step 5: Build in Xcode

1. Select target: `HSIP Keyboard`
2. Select device: Your iPhone or Simulator
3. Product → Build (⌘B)
4. Product → Run (⌘R)

### Step 6: Create IPA (for distribution)

**Option A: Using Build Script**
```bash
cd ios-app
./build-ipa.sh
```

**Option B: Using Xcode**
1. Product → Archive
2. Window → Organizer → Archives
3. Select archive → Distribute App
4. Choose distribution method:
   - **TestFlight**: For beta testing
   - **Ad Hoc**: For specific devices
   - **Enterprise**: For internal distribution

**Option C: Using xcodebuild**
```bash
cd ios-app

# Build for device
xcodebuild -project HSIPKeyboard.xcodeproj \
    -scheme HSIPKeyboard \
    -configuration Release \
    -sdk iphoneos \
    -archivePath build/HSIPKeyboard.xcarchive \
    archive

# Export IPA
xcodebuild -exportArchive \
    -archivePath build/HSIPKeyboard.xcarchive \
    -exportPath build/ipa \
    -exportOptionsPlist ExportOptions.plist
```

### Step 7: Install on Device

**Option A: Via Xcode**
- Connect iPhone → Product → Run

**Option B: Via TestFlight**
1. Upload IPA to App Store Connect
2. Send invite to testers
3. Install via TestFlight app

**Option C: Via Direct Install (requires jailbreak or enterprise cert)**
```bash
# Using ios-deploy
npm install -g ios-deploy
ios-deploy --bundle build/ipa/HSIPKeyboard.ipa
```

---

## 🧪 Testing Cross-Platform Compatibility

### Test Message Format

Both Android and iOS MUST produce identical encrypted message format:

```
🔒<base64(version + senderPeerID + nonce + ciphertext + tag)>
```

### Test Scenario 1: Android → iOS

1. **Android (Girlfriend)**:
   - Type "Hello from Android" in Instagram
   - Select your contact
   - Press Enter → see `🔒hQEMA...`

2. **iOS (You)**:
   - Receive Instagram message with `🔒hQEMA...`
   - Tap message → HSIP detects and decrypts
   - See "Hello from Android"

### Test Scenario 2: iOS → Android

1. **iOS (You)**:
   - Type "Hello from iOS" in WhatsApp
   - Select girlfriend's contact
   - Press Return → see `🔒hQEMA...`

2. **Android (Girlfriend)**:
   - Receive WhatsApp message with `🔒hQEMA...`
   - Tap notification → HSIP decrypts
   - See "Hello from iOS"

### Verify Compatibility

```bash
# Extract message format test from Android log
adb logcat | grep "HSIP_MESSAGE"

# Extract message format from iOS log
xcrun simctl spawn booted log stream --predicate 'subsystem == "io.hsip.keyboard"'
```

---

## 🚀 Distribution

### Android

1. **Sideload APK**:
   - Host on website: `https://hsip.io/download/hsip-keyboard.apk`
   - Users download and install
   - Enable "Install from Unknown Sources"

2. **Google Play Store** (optional, later):
   - Requires Play Console account ($25 one-time)
   - Submit APK for review
   - 2-7 days approval time

### iOS

1. **TestFlight** (recommended for beta):
   - Upload to App Store Connect
   - Add testers (up to 10,000)
   - Install via TestFlight app

2. **Direct Install** (for development):
   - Install via Xcode
   - Valid for 7 days (free account) or 1 year (paid account)

3. **App Store** (optional, later):
   - Submit for review
   - 1-3 days approval time

---

## 🔍 Troubleshooting

### Android

**Error: `UnsatisfiedLinkError`**
- Ensure `.so` files are in correct `jniLibs/` folders
- Check architecture matches device (arm64-v8a for modern phones)

**Error: `Gradle sync failed`**
- Update Android Studio to latest version
- Invalidate caches: File → Invalidate Caches → Restart

**Error: `NDK not found`**
- Install NDK via SDK Manager
- Set `ANDROID_NDK_HOME` environment variable

### iOS

**Error: `Library not found -lhsip_keyboard`**
- Check Rust library is in Frameworks folder
- Verify library is added to "Link Binary With Libraries"

**Error: `Code signing failed`**
- Check Apple Developer account is active
- Verify provisioning profile is valid
- Try automatic signing in Xcode

**Error: `Symbol not found: _hsip_ios_encrypt`**
- Rust library not linked properly
- Add `-lc++` to Other Linker Flags
- Rebuild Rust library

---

## 📚 Next Steps

1. **Test locally**: Build both Android and iOS apps
2. **Exchange contacts**: Use deep link or QR code
3. **Test encryption**: Send messages in Instagram/WhatsApp
4. **Verify decryption**: Ensure cross-platform compatibility
5. **Distribute**: Share APK/IPA with beta testers

For detailed usage instructions, see [docs/CROSS_PLATFORM_TESTING.md](docs/CROSS_PLATFORM_TESTING.md)
