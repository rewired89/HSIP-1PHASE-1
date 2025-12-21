# Building HSIP Keyboard for iOS

## Option 1: GitHub Actions (No Mac Required)

GitHub Actions will automatically build the iOS app when you push code.

**Steps:**
1. Push your code to GitHub
2. Go to: https://github.com/YOUR-USERNAME/HSIP-1PHASE/actions
3. Click on the latest "Build iOS App" workflow run
4. Download the IPA from "Artifacts" section
5. Install on your iPhone using a tool like:
   - **AltStore** (free, requires computer nearby)
   - **Sideloadly** (free, Windows/Mac)
   - **TestFlight** (requires Apple Developer account $99/year)

**To manually trigger a build:**
```bash
git push origin claude/review-hsip-project-01MUeuCGZ4XaC2E97SNTknEp
```

Then go to Actions tab on GitHub and wait for build to complete (5-10 minutes).

## Option 2: Build Locally on Mac

### Prerequisites
- macOS with Xcode 15+ installed
- Rust toolchain
- iOS development certificate (free with Apple ID)

### Build Steps

**1. Install Rust iOS targets:**
```bash
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
```

**2. Build Rust library:**
```bash
cd crates/hsip-keyboard

# For real iPhone (ARM64)
cargo build --release --target aarch64-apple-ios

# For iOS Simulator (Intel)
cargo build --release --target x86_64-apple-ios

# For iOS Simulator (M1/M2 Mac)
cargo build --release --target aarch64-apple-ios-sim
```

**3. Create fat library (combines all architectures):**
```bash
cd ../../ios-app

lipo -create \
  ../target/aarch64-apple-ios/release/libhsip_keyboard.a \
  ../target/x86_64-apple-ios/release/libhsip_keyboard.a \
  -output libhsip_keyboard.a
```

**4. Open in Xcode:**
```bash
open HSIPKeyboard.xcodeproj
```

**5. In Xcode:**
- Select your development team (Xcode → Preferences → Accounts)
- Connect your iPhone
- Select "HSIP Keyboard" scheme
- Click Run (▶) or Archive

**6. Install on iPhone:**
- For testing: Click Run in Xcode (installs directly)
- For distribution: Product → Archive → Export → Ad Hoc

## Option 3: Cloud Mac Rental (Easiest)

**MacStadium / MacinCloud ($1-2 for a day):**
1. Rent a Mac: https://www.macincloud.com
2. Use remote desktop to access Mac
3. Clone your repo
4. Follow "Build Locally" steps above
5. Download IPA and install on iPhone

## Installing IPA on iPhone

### Method 1: AltStore (Free, Easiest)
1. Install AltStore on PC: https://altstore.io
2. Install AltStore on iPhone via computer
3. Open AltStore on iPhone → "+" → Select IPA
4. App expires every 7 days, need to refresh

### Method 2: Sideloadly (Free)
1. Download: https://sideloadly.io
2. Connect iPhone to computer
3. Drag IPA into Sideloadly
4. Sign with your Apple ID
5. App expires every 7 days

### Method 3: TestFlight (Requires Developer Account)
1. Join Apple Developer Program ($99/year)
2. Upload IPA to App Store Connect
3. Add testers via email
4. Testers install via TestFlight app
5. No expiration

## Troubleshooting

**"Developer Mode Required":**
- Settings → Privacy & Security → Developer Mode → Enable

**"Untrusted Developer":**
- Settings → General → VPN & Device Management → Trust your Apple ID

**Build fails in GitHub Actions:**
- Check Actions tab for error logs
- Common issue: iOS app project not created yet
- Solution: Will create iOS app skeleton in next step

## Next Steps

The iOS keyboard app UI and Xcode project will be created in the next phase.
For now, the workflow is set up and ready to build once the app exists.
