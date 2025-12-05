#!/bin/bash

# HSIP Keyboard - Android APK Build Script
# This script compiles the Rust library and builds the Android APK

set -e  # Exit on error

echo "🔨 Building HSIP Keyboard for Android"
echo "======================================"

# Step 1: Build Rust library for Android targets
echo ""
echo "📦 Step 1/3: Compiling Rust library for Android..."
cd ../crates/hsip-keyboard

# Install Android targets if not already installed
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# Build for each Android architecture
echo "  Building for arm64-v8a..."
cargo build --release --target aarch64-linux-android

echo "  Building for armeabi-v7a..."
cargo build --release --target armv7-linux-androideabi

echo "  Building for x86_64..."
cargo build --release --target x86_64-linux-android

echo "  Building for x86..."
cargo build --release --target i686-linux-android

# Step 2: Copy .so files to Android jniLibs directory
echo ""
echo "📋 Step 2/3: Copying native libraries to jniLibs..."
cd ../../android-app

mkdir -p app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

cp ../target/aarch64-linux-android/release/libhsip_keyboard.so app/src/main/jniLibs/arm64-v8a/
cp ../target/armv7-linux-androideabi/release/libhsip_keyboard.so app/src/main/jniLibs/armeabi-v7a/
cp ../target/x86_64-linux-android/release/libhsip_keyboard.so app/src/main/jniLibs/x86_64/
cp ../target/i686-linux-android/release/libhsip_keyboard.so app/src/main/jniLibs/x86/

echo "  ✅ Native libraries copied"

# Step 3: Build Android APK
echo ""
echo "🏗️  Step 3/3: Building Android APK..."

# Check if Gradle wrapper exists
if [ ! -f "./gradlew" ]; then
    echo "Error: Gradle wrapper not found. Please run 'gradle wrapper' first."
    exit 1
fi

# Build debug APK (for testing)
./gradlew assembleDebug

echo ""
echo "✅ Debug APK built successfully!"
echo "📱 Location: android-app/app/build/outputs/apk/debug/app-debug.apk"

# Build release APK (for distribution)
echo ""
echo "🚀 Building release APK..."
./gradlew assembleRelease

echo ""
echo "✅ Release APK built successfully!"
echo "📱 Location: android-app/app/build/outputs/apk/release/app-release.apk"
echo ""
echo "⚠️  Note: Release APK needs to be signed for distribution."
echo "Run: ./sign-apk.sh to sign the APK"
