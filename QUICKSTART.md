# HSIP Keyboard - Quick Start Guide

**Goal:** Build APK (Android) and IPA (iOS) to test encrypted messaging with your girlfriend.

---

## ⚡ Quick Summary

### What You'll Do:
1. **Android**: Run one script → Get APK → Install on girlfriend's phone
2. **iOS**: Run one script → Follow Xcode instructions → Install on your iPhone
3. **Test**: Exchange contacts → Send encrypted messages!

### What You'll Get:
- ✅ Android APK (for girlfriend)
- ✅ iOS app (for you)
- ✅ Emoji fingerprint verification (🐕🌲🚗🎸⚡🍕)
- ✅ End-to-end encrypted messaging in ANY app

---

## 🤖 Android Build (For Girlfriend's Phone)

### Prerequisites:
1. **Rust** - https://rustup.rs
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Android NDK** - Install via Android Studio:
   - Android Studio → Settings → SDK Manager → SDK Tools → NDK
   - Set environment variable:
     ```bash
     export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/25.2.9519653
     ```

### Build Steps:

```bash
# 1. Navigate to android-app directory
cd android-app

# 2. Run build script (does everything automatically!)
./build-apk.sh

# 3. Wait for build (5-10 minutes first time)
# Output: android-app/app/build/outputs/apk/debug/app-debug.apk
```

### What the script does:
1. ✅ Installs Rust Android targets
2. ✅ Compiles Rust crypto library for all Android architectures
3. ✅ Copies `.so` files to correct locations
4. ✅ Downloads Gradle wrapper
5. ✅ Builds APK with everything bundled

### Install on Girlfriend's Phone:

```bash
# Connect her phone via USB
adb devices

# Install APK
adb install app/build/outputs/apk/debug/app-debug.apk

# Done! She can now open "HSIP Keyboard" app
```

---

## 🍎 iOS Build (For Your iPhone)

### Prerequisites:
1. **macOS** (required for iOS development)
2. **Xcode** (from Mac App Store)
3. **Xcode Command Line Tools**:
   ```bash
   xcode-select --install
   ```
4. **Rust** - https://rustup.rs
5. **Apple Developer Account** ($99/year) - needed for device installation

### Build Steps:

```bash
# 1. Navigate to ios-app directory
cd ios-app

# 2. Run build script (compiles Rust libraries)
./build-ipa.sh

# 3. Follow on-screen instructions to create Xcode project
```

### What the script does:
1. ✅ Installs Rust iOS targets
2. ✅ Compiles Rust crypto library for iOS (device + simulator)
3. ✅ Creates universal `.a` libraries
4. ✅ Shows you how to set up Xcode project

### Create Xcode Project (One-Time Setup):

**Follow the instructions printed by `build-ipa.sh`, or:**

1. Open Xcode → Create new iOS App
   - Name: `HSIP Keyboard`
   - Bundle ID: `io.hsip.keyboard`

2. Add Keyboard Extension
   - File → New → Target → Custom Keyboard Extension
   - Name: `HSIPKeyboardExtension`

3. Add Rust library
   - Build Phases → Link Binary With Libraries → Add `Frameworks/libhsip_keyboard_device.a`

4. Add Swift files
   - Drag all `.swift` files from `ios-app/` into Xcode

5. Build → Run on your iPhone

**That's it!** Detailed steps are shown by the build script.

---

## 🧪 Testing: You ↔ Girlfriend

### Step 1: Both Install Apps

**Her (Android):**
- Install APK: `adb install app-debug.apk`
- Open "HSIP Keyboard" app
- Tap through setup
- Go to Settings → Keyboard → Enable "HSIP Keyboard"

**You (iOS):**
- Run app from Xcode on your iPhone
- Tap through setup
- Go to Settings → General → Keyboard → Add New Keyboard → "HSIP Keyboard"

---

### Step 2: Exchange Contacts

**You send her:**
```
Open HSIP app → "Share My Contact" → Copy text → Send via Instagram

She receives:
🔐 HSIP Contact
YourName
hsip://add?pubkey=ABC123...&name=YourName

She clicks the link → HSIP opens → Tap "Accept"
```

**She sends you:**
```
Same process - she shares her contact link
You click it → Accept
```

---

### Step 3: Verify Emoji Fingerprint

**Both devices show:**
```
┌─────────────────────────────┐
│  Verify with [Name]:        │
│                             │
│  🐕 🌲 🚗 🎸 ⚡ 🍕          │
│                             │
│  Does it match?             │
│  [Yes, Match!]              │
└─────────────────────────────┘
```

**Video call or in person:**
- You: "I see dog, tree, car, guitar, lightning, pizza"
- Her: "Yep, same here!"
- Both tap "Yes, Match!" ✅

**You only do this ONCE per contact!**

---

### Step 4: Send Encrypted Messages

**Her (Android) → You (iOS):**

1. She opens Instagram
2. Taps text field → HSIP keyboard appears
3. Taps lock icon 🔒 → Selects your name
4. Types: "Hello from Android!"
5. Presses Enter

**What you see:**
```
Instagram message from her:
🔒hQEMA5k7x9mP2qR8nL4vW6jH3sT1zN5bY0cF8d...
```

6. You tap the message
7. HSIP detects it → Shows "Decrypt?"
8. Tap "Decrypt"
9. See: "Hello from Android!" ✅

**You (iOS) → Her (Android):**

Same process but reversed!

---

## ✅ How to Know It's Working

### Test 1: Visual Confirmation
**If you see `🔒` followed by gibberish → Encryption is working!**

```
✅ Good:  🔒hQEMA5k7x9mP2qR8nL4vW6jH3sT1zN5bY0cF8d...
❌ Bad:   Hello from Android! (not encrypted)
```

### Test 2: Third Person Can't Read
**Send encrypted message to someone WITHOUT HSIP:**

They see:
```
🔒hQEMA5k7x9mP2qR8nL4vW6jH3sT1zN5bY0cF8d...
```

They can't decrypt it (no key) ✅ **This proves it's really encrypted!**

### Test 3: Cross-Platform Works
**She (Android) sends → You (iOS) decrypts successfully**
- Proves: Same Rust crypto core on both platforms
- Proves: Message format is compatible
- Proves: Keys are correctly exchanged

### Test 4: Emoji Verification Matches
**Both sides see same 6 emoji**
- Proves: No man-in-the-middle attack
- Proves: Keys are correct
- Proves: Secure connection established

---

## 🐛 Troubleshooting

### Android Build Fails

**Problem:** `ANDROID_NDK_HOME not set`
```bash
# Solution:
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/25.2.9519653
# Add to ~/.bashrc or ~/.zshrc to make permanent
```

**Problem:** `Rust not found`
```bash
# Solution:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

**Problem:** Gradle fails
```bash
# Solution: Clean and rebuild
./gradlew clean
./build-apk.sh
```

### iOS Build Fails

**Problem:** `xcodebuild not found`
```bash
# Solution:
xcode-select --install
```

**Problem:** `Library not found: -lhsip_keyboard`
- **Solution:** Make sure you added the `.a` file in Xcode → Build Phases → Link Binary With Libraries

**Problem:** Code signing error
- **Solution:** Xcode → Signing & Capabilities → Select your team

### Message Not Decrypting

**Problem:** Emoji fingerprints don't match
- ⚠️ **Possible MITM attack!**
- Solution: Exchange keys again, verify carefully

**Problem:** Message shows as gibberish even after "decrypt"
- Check: Are you both using the same version of the app?
- Check: Did you complete emoji verification?
- Try: Delete contact → Re-add → Verify emoji again

---

## 📚 Next Steps

### After Successful Test:

1. **Build release APK** (signed, optimized):
   ```bash
   cd android-app
   ./gradlew assembleRelease
   # Then sign with keystore
   ```

2. **Distribute to friends**:
   - Host APK on website
   - Share via direct download
   - Later: Submit to Play Store / App Store

3. **Add more features**:
   - Group chat encryption
   - File encryption
   - Voice message encryption

4. **Security audit**:
   - Have Rust crypto code audited
   - Penetration testing
   - Bug bounty program

---

## 🎯 Summary

| Step | Android (Girlfriend) | iOS (You) | Time |
|------|---------------------|-----------|------|
| **1. Build** | `./build-apk.sh` | `./build-ipa.sh` + Xcode setup | 10-30 min |
| **2. Install** | `adb install` | Xcode → Run | 2 min |
| **3. Setup** | Open app → Enable keyboard | Open app → Enable keyboard | 2 min |
| **4. Exchange** | Share contact link | Share contact link | 1 min |
| **5. Verify** | Check emoji | Check emoji | 30 sec |
| **6. Test** | Send message → See 🔒 | Receive → Decrypt | 1 min |

**Total time to first encrypted message: ~20-40 minutes**

---

## 💡 Key Takeaways

✅ **Rust = Crypto Brain** (write once, works on both platforms)
✅ **Kotlin/Swift = UI Layer** (platform-specific, calls Rust)
✅ **One-time emoji verification** (then automatic key rotation)
✅ **Works in ANY app** (Instagram, WhatsApp, Gmail, etc.)
✅ **Even sender can't decrypt** (ephemeral keys, forward secrecy)

**You're building something powerful!** 🚀

For detailed technical info, see [BUILD.md](BUILD.md)
