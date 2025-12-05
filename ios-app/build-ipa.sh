#!/bin/bash

# HSIP Keyboard - iOS IPA Build Script
# This script compiles the Rust library and builds the iOS IPA

set -e  # Exit on error

echo "🔨 Building HSIP Keyboard for iOS"
echo "=================================="

# Step 1: Build Rust library for iOS targets
echo ""
echo "📦 Step 1/3: Compiling Rust library for iOS..."
cd ../crates/hsip-keyboard

# Install iOS targets if not already installed
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim

# Build for each iOS architecture
echo "  Building for iOS device (arm64)..."
cargo build --release --target aarch64-apple-ios

echo "  Building for iOS simulator (x86_64)..."
cargo build --release --target x86_64-apple-ios

echo "  Building for iOS simulator (arm64)..."
cargo build --release --target aarch64-apple-ios-sim

# Step 2: Create universal library using lipo
echo ""
echo "🔗 Step 2/3: Creating universal library..."
cd ../../ios-app

mkdir -p Frameworks

# Create universal library for simulator
lipo -create \
    ../target/x86_64-apple-ios/release/libhsip_keyboard.a \
    ../target/aarch64-apple-ios-sim/release/libhsip_keyboard.a \
    -output Frameworks/libhsip_keyboard_sim.a

# Copy device library
cp ../target/aarch64-apple-ios/release/libhsip_keyboard.a Frameworks/libhsip_keyboard_device.a

echo "  ✅ Universal libraries created"

# Step 3: Build iOS app using xcodebuild
echo ""
echo "🏗️  Step 3/3: Building iOS app..."

# Check if Xcode is installed
if ! command -v xcodebuild &> /dev/null; then
    echo "Error: xcodebuild not found. Please install Xcode."
    exit 1
fi

# Check if Xcode project exists
if [ ! -f "HSIPKeyboard.xcodeproj/project.pbxproj" ]; then
    echo "⚠️  Warning: Xcode project not found."
    echo "You need to create the Xcode project first:"
    echo "  1. Open Xcode"
    echo "  2. Create new iOS App project"
    echo "  3. Add Keyboard Extension target"
    echo "  4. Link the Rust static library"
    echo "  5. Add all Swift files"
    exit 1
fi

# Build for simulator (for testing)
echo "Building for iOS Simulator..."
xcodebuild -project HSIPKeyboard.xcodeproj \
    -scheme HSIPKeyboard \
    -configuration Debug \
    -sdk iphonesimulator \
    -derivedDataPath build/simulator

echo ""
echo "✅ Simulator build completed!"
echo "📱 Location: ios-app/build/simulator/Build/Products/Debug-iphonesimulator/HSIPKeyboard.app"

# Build for device (requires Apple Developer account)
echo ""
echo "🚀 Building for iOS device..."
xcodebuild -project HSIPKeyboard.xcodeproj \
    -scheme HSIPKeyboard \
    -configuration Release \
    -sdk iphoneos \
    -derivedDataPath build/device \
    CODE_SIGN_IDENTITY="iPhone Distribution" \
    PROVISIONING_PROFILE_SPECIFIER="YourProvisioningProfile"

echo ""
echo "✅ Device build completed!"

# Create IPA (requires codesigning)
echo ""
echo "📦 Creating IPA..."
mkdir -p build/ipa/Payload
cp -r build/device/Build/Products/Release-iphoneos/HSIPKeyboard.app build/ipa/Payload/
cd build/ipa
zip -r HSIPKeyboard.ipa Payload
cd ../..

echo ""
echo "✅ IPA created successfully!"
echo "📱 Location: ios-app/build/ipa/HSIPKeyboard.ipa"
echo ""
echo "⚠️  Note: IPA needs valid code signing for installation on devices."
echo "For development, use TestFlight or Xcode direct installation."
