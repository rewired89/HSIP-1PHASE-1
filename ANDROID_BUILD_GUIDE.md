# HSIP Android Keyboard - Complete Build Guide

## 📋 Overview

The HSIP Android Keyboard is an end-to-end encrypted keyboard that uses the HSIP protocol to encrypt messages before they're sent in any app.

---

## ✅ What You Need

### 1. **Prerequisites**
- **Rust** (1.87 or later) - Install from https://rustup.rs
- **Android NDK** (version 25.2.9519653 recommended)
- **Android SDK** (API 26+ / Android 8.0+)
- **Gradle** (will be auto-downloaded by the build script)

### 2. **Environment Setup**

Set your Android NDK path:
```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/25.2.9519653
```

Or on Windows:
```powershell
$env:ANDROID_NDK_HOME = "C:\Users\YourName\AppData\Local\Android\Sdk\ndk\25.2.9519653"
```

---

## 🏗️ Project Structure

Here's what files are involved in the Android build:

```
HSIP-1PHASE-1/
├── crates/hsip-keyboard/          ← Rust JNI library
│   ├── src/
│   │   ├── lib.rs                 ← Main Rust library
│   │   ├── jni_bridge.rs          ← JNI exports for Android
│   │   ├── crypto.rs              ← Encryption implementation
│   │   └── message.rs             ← Message format
│   └── Cargo.toml                 ← Rust dependencies
│
├── android-app/                   ← Android application
│   ├── app/
│   │   ├── src/main/
│   │   │   ├── java/io/hsip/keyboard/
│   │   │   │   ├── HSIPApplication.kt       ← App entry point
│   │   │   │   ├── crypto/HSIPEngine.kt     ← JNI interface
│   │   │   │   ├── keyboard/HSIPKeyboardService.kt  ← Keyboard IME
│   │   │   │   └── ui/                      ← UI Activities
│   │   │   │       ├── setup/SetupActivity.kt
│   │   │   │       ├── settings/SettingsActivity.kt
│   │   │   │       └── contacts/ContactsActivity.kt
│   │   │   ├── res/                         ← Android resources
│   │   │   └── AndroidManifest.xml
│   │   └── build.gradle                     ← App build config
│   ├── build.gradle                         ← Project build config
│   ├── settings.gradle                      ← Gradle settings
│   └── build-apk.sh                         ← **MAIN BUILD SCRIPT**
│
└── target/                        ← Compiled .so files go here
```

---

## 🚀 Quick Build (Easiest Method)

**Use the automated build script:**

```bash
cd android-app
chmod +x build-apk.sh
./build-apk.sh
```

This script will:
1. ✅ Check prerequisites (Rust, NDK)
2. ✅ Install Android Rust targets
3. ✅ Compile Rust library for all Android architectures
4. ✅ Copy `.so` files to `jniLibs/`
5. ✅ Build the Android APK

**Output:** `android-app/app/build/outputs/apk/debug/app-debug.apk`

---

## 🔧 Manual Build (Step by Step)

If you prefer to build manually or troubleshoot:

### **Step 1: Install Android Targets**

```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android
rustup target add i686-linux-android
```

### **Step 2: Build Rust Library**

```bash
cd crates/hsip-keyboard

# For ARM64 devices (modern phones)
cargo build --release --target aarch64-linux-android

# For ARM32 devices (older phones)
cargo build --release --target armv7-linux-androideabi

# For x86_64 emulator
cargo build --release --target x86_64-linux-android

# For x86 emulator (32-bit)
cargo build --release --target i686-linux-android
```

### **Step 3: Copy .so Files to Android**

```bash
cd ../../android-app

# Create jniLibs directories
mkdir -p app/src/main/jniLibs/arm64-v8a
mkdir -p app/src/main/jniLibs/armeabi-v7a
mkdir -p app/src/main/jniLibs/x86_64
mkdir -p app/src/main/jniLibs/x86

# Copy compiled libraries
cp ../target/aarch64-linux-android/release/libhsip_keyboard.so \
   app/src/main/jniLibs/arm64-v8a/

cp ../target/armv7-linux-androideabi/release/libhsip_keyboard.so \
   app/src/main/jniLibs/armeabi-v7a/

cp ../target/x86_64-linux-android/release/libhsip_keyboard.so \
   app/src/main/jniLibs/x86_64/

cp ../target/i686-linux-android/release/libhsip_keyboard.so \
   app/src/main/jniLibs/x86/
```

### **Step 4: Build Android APK**

```bash
# Download Gradle wrapper if needed
curl -L https://services.gradle.org/distributions/gradle-8.0-bin.zip -o gradle.zip
unzip gradle.zip
./gradlew wrapper --gradle-version=8.0

# Build debug APK
./gradlew assembleDebug

# Or build release APK (requires signing)
./gradlew assembleRelease
```

---

## 📱 Installation

### **Install on Physical Device**

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

### **Install on Emulator**

1. Start Android emulator
2. Drag and drop the APK file onto the emulator
   OR
3. ```bash
   adb install app/build/outputs/apk/debug/app-debug.apk
   ```

### **Enable the Keyboard**

1. Open **Settings** on your Android device
2. Go to **System → Keyboard**
3. Tap **On-screen keyboard**
4. Enable **HSIP Keyboard**
5. When typing, long-press the spacebar to switch keyboards

---

## 🔍 Files You Need to Build

### **Essential Rust Files:**
1. `crates/hsip-keyboard/src/jni_bridge.rs` - JNI interface
2. `crates/hsip-keyboard/src/crypto.rs` - Encryption logic
3. `crates/hsip-keyboard/src/message.rs` - Message format
4. `crates/hsip-keyboard/src/lib.rs` - Library entry point
5. `crates/hsip-keyboard/Cargo.toml` - Dependencies

### **Essential Kotlin Files:**
1. `android-app/app/src/main/java/io/hsip/keyboard/HSIPApplication.kt`
2. `android-app/app/src/main/java/io/hsip/keyboard/crypto/HSIPEngine.kt`
3. `android-app/app/src/main/java/io/hsip/keyboard/keyboard/HSIPKeyboardService.kt`
4. `android-app/app/src/main/java/io/hsip/keyboard/ui/setup/SetupActivity.kt`
5. `android-app/app/src/main/java/io/hsip/keyboard/ui/settings/SettingsActivity.kt`
6. `android-app/app/src/main/java/io/hsip/keyboard/ui/contacts/ContactsActivity.kt`

### **Essential Build Files:**
1. `android-app/build-apk.sh` - **Main build script**
2. `android-app/app/build.gradle` - App configuration
3. `android-app/build.gradle` - Project configuration
4. `android-app/settings.gradle` - Gradle settings
5. `android-app/app/src/main/AndroidManifest.xml` - App manifest

---

## 🐛 Troubleshooting

### **Error: ANDROID_NDK_HOME not set**
```bash
export ANDROID_NDK_HOME=/path/to/your/ndk
```

### **Error: Target not found**
```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
```

### **Error: Gradle not found**
Use the build script - it will download Gradle automatically.

### **Error: libhsip_keyboard.so not found**
Make sure you completed Step 2 and Step 3 to compile and copy the Rust libraries.

### **Error: JNI method not found**
The function signatures in `HSIPEngine.kt` must match exactly with `jni_bridge.rs`.

---

## ✅ Verification

After building, verify the APK contains the native libraries:

```bash
unzip -l app/build/outputs/apk/debug/app-debug.apk | grep libhsip_keyboard.so
```

You should see:
```
lib/arm64-v8a/libhsip_keyboard.so
lib/armeabi-v7a/libhsip_keyboard.so
lib/x86_64/libhsip_keyboard.so
lib/x86/libhsip_keyboard.so
```

---

## 📦 What Gets Built

When you run the build script, you're building:

1. **Rust Native Library** (`libhsip_keyboard.so`)
   - Compiled from `crates/hsip-keyboard/`
   - Contains all encryption logic
   - Exports JNI functions for Android

2. **Android APK** (`app-debug.apk`)
   - Kotlin UI code
   - Keyboard service (InputMethodService)
   - Native libraries embedded
   - All activities and resources

---

## 🎯 Next Steps

After successful build:

1. **Install APK** on your device
2. **Enable keyboard** in Android settings
3. **Open the app** to generate your identity
4. **Add contacts** by sharing your HSIP contact link
5. **Start encrypting** - select a contact in the keyboard UI

---

## 📞 Support

If you encounter issues:
- Check that ANDROID_NDK_HOME is set correctly
- Ensure you have the correct NDK version (25.x)
- Make sure Rust is installed and up to date
- Try running `./build-apk.sh` with verbose output

