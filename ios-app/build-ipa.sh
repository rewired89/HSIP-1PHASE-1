#!/bin/bash

# HSIP Keyboard - Complete iOS Build Script
# Compiles Rust library and provides instructions for Xcode build

set -e  # Exit on error

echo "🔨 Building HSIP Keyboard for iOS"
echo "=================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
echo "📋 Checking prerequisites..."

if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED}❌ iOS builds require macOS${NC}"
    exit 1
fi

if ! command -v rustc &> /dev/null; then
    echo -e "${RED}❌ Rust not found. Install from https://rustup.rs${NC}"
    exit 1
fi

if ! command -v xcodebuild &> /dev/null; then
    echo -e "${RED}❌ Xcode command line tools not found${NC}"
    echo "Install with: xcode-select --install"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites OK${NC}"
echo ""

# Step 1: Install iOS targets
echo -e "${BLUE}📦 Step 1/4: Installing Rust iOS targets...${NC}"
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
echo -e "${GREEN}✅ Targets installed${NC}"
echo ""

# Step 2: Build Rust library for iOS
echo -e "${BLUE}🔧 Step 2/4: Compiling Rust library for iOS...${NC}"
cd ../crates/hsip-keyboard

echo "  Building for iOS device (arm64)..."
cargo build --release --target aarch64-apple-ios

echo "  Building for iOS simulator (x86_64 - Intel Macs)..."
cargo build --release --target x86_64-apple-ios

echo "  Building for iOS simulator (arm64 - Apple Silicon)..."
cargo build --release --target aarch64-apple-ios-sim

echo -e "${GREEN}✅ Rust compilation complete${NC}"
echo ""

# Step 3: Create universal library
echo -e "${BLUE}🔗 Step 3/4: Creating universal library...${NC}"
cd ../../ios-app

mkdir -p Frameworks

# Create universal library for simulator (supports both Intel and Apple Silicon)
echo "  Creating simulator universal library..."
lipo -create \
    ../target/x86_64-apple-ios/release/libhsip_keyboard.a \
    ../target/aarch64-apple-ios-sim/release/libhsip_keyboard.a \
    -output Frameworks/libhsip_keyboard_sim.a

# Copy device library
echo "  Copying device library..."
cp ../target/aarch64-apple-ios/release/libhsip_keyboard.a Frameworks/libhsip_keyboard_device.a

echo -e "${GREEN}✅ Universal libraries created:${NC}"
echo "   - Frameworks/libhsip_keyboard_sim.a (for simulator)"
echo "   - Frameworks/libhsip_keyboard_device.a (for device)"
echo ""

# Step 4: Instructions for Xcode
echo -e "${BLUE}📱 Step 4/4: Xcode Project Setup${NC}"
echo ""
echo -e "${YELLOW}⚠️  You need to create the Xcode project manually:${NC}"
echo ""
echo "1. Open Xcode"
echo "2. Create new iOS App project:"
echo "   - Product Name: HSIP Keyboard"
echo "   - Bundle ID: io.hsip.keyboard"
echo "   - Language: Swift"
echo "   - User Interface: SwiftUI"
echo ""
echo "3. Add Keyboard Extension:"
echo "   - File → New → Target → Custom Keyboard Extension"
echo "   - Product Name: HSIPKeyboardExtension"
echo "   - Bundle ID: io.hsip.keyboard.extension"
echo ""
echo "4. Add Rust static library:"
echo "   - Select project → Build Phases → Link Binary With Libraries"
echo "   - Click + → Add Other → Add Files"
echo "   - For DEVICE builds: Add Frameworks/libhsip_keyboard_device.a"
echo "   - For SIMULATOR builds: Add Frameworks/libhsip_keyboard_sim.a"
echo ""
echo "5. Add Swift files to project:"
echo "   - Drag all .swift files from ios-app/ into Xcode"
echo "   - Shared/HSIPManager.swift → Add to BOTH targets"
echo "   - MainApp/*.swift → Main app target only"
echo "   - KeyboardExtension/*.swift → Extension target only"
echo ""
echo "6. Configure Info.plist files:"
echo "   - Use ios-app/Info.plist for main app"
echo "   - Use ios-app/KeyboardExtension/Info.plist for extension"
echo ""
echo "7. Add App Groups (for data sharing):"
echo "   - Select project → Signing & Capabilities"
echo "   - Click + Capability → App Groups"
echo "   - Add group: group.io.hsip.keyboard"
echo "   - Do this for BOTH main app AND extension targets"
echo ""
echo "8. Configure Build Settings:"
echo "   - Search for 'Other Linker Flags'"
echo "   - Add: -lc++"
echo ""
echo "9. Build and Run:"
echo "   - Select target: HSIP Keyboard"
echo "   - Select device or simulator"
echo "   - Product → Run (⌘R)"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Rust Libraries Ready!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "📚 Next Steps:"
echo "   1. Follow the Xcode setup instructions above"
echo "   2. Build the project in Xcode"
echo "   3. Install on your iPhone"
echo "   4. Enable keyboard: Settings → General → Keyboard → Keyboards → Add New Keyboard"
echo ""
echo "💡 Tip: For detailed instructions, see BUILD.md"
echo ""
