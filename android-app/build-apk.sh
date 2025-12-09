#!/bin/bash

# HSIP Keyboard - Complete Android Build Script
# Compiles Rust library and builds Android APK

set -e  # Exit on error

echo "🔨 Building HSIP Keyboard for Android"
echo "======================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command -v rustc &> /dev/null; then
    echo -e "${RED}❌ Rust not found. Install from https://rustup.rs${NC}"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Cargo not found. Install Rust toolchain.${NC}"
    exit 1
fi

# Check for Android NDK
if [ -z "$ANDROID_NDK_HOME" ]; then
    echo -e "${RED}❌ ANDROID_NDK_HOME not set${NC}"
    echo "Please set it to your NDK path:"
    echo "  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/25.2.9519653"
    exit 1
fi

if [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo -e "${RED}❌ Android NDK not found at: $ANDROID_NDK_HOME${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites OK${NC}"
echo ""

# Step 1: Install Android targets
echo -e "${BLUE}📦 Step 1/5: Installing Rust Android targets...${NC}"
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
echo -e "${GREEN}✅ Targets installed${NC}"
echo ""

# Step 2: Build Rust library for Android
echo -e "${BLUE}🔧 Step 2/5: Compiling Rust library for Android...${NC}"
cd ../crates/hsip-keyboard

echo "  Building for arm64-v8a (64-bit ARM)..."
cargo build --release --target aarch64-linux-android

echo "  Building for armeabi-v7a (32-bit ARM)..."
cargo build --release --target armv7-linux-androideabi

echo "  Building for x86_64 (64-bit emulator)..."
cargo build --release --target x86_64-linux-android

echo "  Building for x86 (32-bit emulator)..."
cargo build --release --target i686-linux-android

echo -e "${GREEN}✅ Rust compilation complete${NC}"
echo ""

# Step 3: Copy .so files to jniLibs
echo -e "${BLUE}📋 Step 3/5: Copying native libraries to jniLibs...${NC}"
cd ../../android-app

mkdir -p app/src/main/jniLibs/arm64-v8a
mkdir -p app/src/main/jniLibs/armeabi-v7a
mkdir -p app/src/main/jniLibs/x86_64
mkdir -p app/src/main/jniLibs/x86

cp ../target/aarch64-linux-android/release/libhsip_keyboard.so app/src/main/jniLibs/arm64-v8a/
cp ../target/armv7-linux-androideabi/release/libhsip_keyboard.so app/src/main/jniLibs/armeabi-v7a/
cp ../target/x86_64-linux-android/release/libhsip_keyboard.so app/src/main/jniLibs/x86_64/
cp ../target/i686-linux-android/release/libhsip_keyboard.so app/src/main/jniLibs/x86/

echo -e "${GREEN}✅ Native libraries copied${NC}"
echo ""

# Step 4: Download Gradle wrapper if missing
if [ ! -f "gradlew" ]; then
    echo -e "${BLUE}⬇️  Step 4/5: Downloading Gradle wrapper...${NC}"

    # Download gradle-wrapper.jar
    mkdir -p gradle/wrapper
    curl -L https://raw.githubusercontent.com/gradle/gradle/master/gradle/wrapper/gradle-wrapper.jar \
         -o gradle/wrapper/gradle-wrapper.jar

    # Download gradlew scripts
    curl -L https://raw.githubusercontent.com/gradle/gradle/master/gradlew -o gradlew
    curl -L https://raw.githubusercontent.com/gradle/gradle/master/gradlew.bat -o gradlew.bat

    chmod +x gradlew

    echo -e "${GREEN}✅ Gradle wrapper downloaded${NC}"
else
    echo -e "${BLUE}📦 Step 4/5: Gradle wrapper exists${NC}"
    echo -e "${GREEN}✅ Skipping download${NC}"
fi
echo ""

# Step 5: Build Android APK
echo -e "${BLUE}🏗️  Step 5/5: Building Android APK...${NC}"
echo ""

# Build debug APK (for testing)
echo "Building DEBUG APK..."
./gradlew assembleDebug --warning-mode all

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Build Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "📱 APK Location:"
echo "   android-app/app/build/outputs/apk/debug/app-debug.apk"
echo ""
echo "📦 Install on device:"
echo "   adb install app/build/outputs/apk/debug/app-debug.apk"
echo ""
echo "🔐 Enable keyboard:"
echo "   Settings → System → Keyboard → Add Keyboard → HSIP Keyboard"
echo ""
