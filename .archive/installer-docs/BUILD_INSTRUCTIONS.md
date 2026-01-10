# HSIP Windows Installer - Build Instructions

This guide explains how to build the Windows installer package for HSIP.

---

## Prerequisites

### Required Software
1. **Windows 10 or Windows 11**
2. **Rust** (latest stable)
   - Install from: https://rustup.rs/
   - Run: `rustup default stable`
3. **PowerShell 5.1+** (comes with Windows)
4. **Git** (to clone the repository)

### System Requirements
- At least 4GB RAM
- 2GB free disk space
- Internet connection (for downloading Rust dependencies)

---

## Quick Start (Automated Build)

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/your-repo/HSIP-1PHASE
   cd HSIP-1PHASE
   ```

2. **Run the build script:**
   ```powershell
   cd installer
   .\build-windows-package.ps1
   ```

3. **Result:**
   - Creates `hsip-windows-installer\` folder with all files
   - Creates `HSIP-Windows-Installer-YYYY-MM-DD.zip` ready to distribute

**Done!** The ZIP file is ready to distribute to users.

---

## Manual Build (Step-by-Step)

If you prefer to build manually or need to customize:

### Step 1: Build the CLI Executable

```powershell
# From repository root
cargo build --release --bin hsip-cli
```

**Output:** `target\release\hsip-cli.exe` (~5-10 MB)

### Step 2: Build the Tray Icon

```powershell
cargo build --release --bin hsip-tray
```

**Output:** `target\release\hsip-tray.exe` (~3-5 MB)

### Step 3: Create Installer Folder

```powershell
# Create installer directory
New-Item -ItemType Directory -Path "hsip-installer" -Force

# Copy executables
Copy-Item "target\release\hsip-cli.exe" "hsip-installer\" -Force
Copy-Item "target\release\hsip-tray.exe" "hsip-installer\" -Force

# Copy installer scripts
Copy-Item "installer\*.ps1" "hsip-installer\" -Force

# Copy documentation
Copy-Item "README.md" "hsip-installer\" -Force
Copy-Item "ENCRYPTION_VERIFICATION_REPORT.md" "hsip-installer\" -Force
Copy-Item "HOW_TO_VERIFY_ENCRYPTION.md" "hsip-installer\" -Force
```

### Step 4: Create ZIP Archive

```powershell
Compress-Archive -Path "hsip-installer\*" -DestinationPath "HSIP-Windows-Installer.zip" -Force
```

---

## What Gets Included in the Installer

```
HSIP-Windows-Installer.zip
├── hsip-cli.exe                          # Main HSIP daemon
├── hsip-tray.exe                         # System tray icon
├── install.ps1                           # Main installation script
├── uninstall.ps1                         # Uninstallation script
├── register-daemon.ps1                   # Auto-start daemon setup
├── register-tray.ps1                     # Auto-start tray setup
├── run-daemon.ps1                        # Daemon launcher (hidden)
├── run-tray.ps1                          # Tray launcher (hidden)
├── README.md                             # Project documentation
├── ENCRYPTION_VERIFICATION_REPORT.md     # Encryption proof
├── HOW_TO_VERIFY_ENCRYPTION.md           # User verification guide
└── INSTALL.md                            # Installation instructions
```

---

## Build Modes

### Release Build (Recommended for Distribution)
```powershell
.\build-windows-package.ps1 -Release
```
- Optimized for performance
- ~10-15 MB total size
- No debug symbols
- **Use this for production/distribution**

### Debug Build (Development Only)
```powershell
.\build-windows-package.ps1 -Release:$false
```
- Includes debug symbols
- Larger file size (~50-100 MB)
- Better error messages
- **Only for development/testing**

---

## Troubleshooting Build Issues

### Error: "rustc not found"
**Solution:** Install Rust from https://rustup.rs/

```powershell
# Install Rust
curl https://sh.rustup.rs -sSf | sh

# Restart PowerShell, then verify:
rustc --version
cargo --version
```

### Error: "linking with `link.exe` failed"
**Solution:** Install Visual Studio Build Tools

1. Download: https://visualstudio.microsoft.com/downloads/
2. Install "Desktop development with C++"
3. Restart PowerShell
4. Rebuild

### Error: "cannot find -ladvapi32"
**Solution:** This means Windows SDK is missing

```powershell
# Install via rustup
rustup toolchain install stable-x86_64-pc-windows-msvc
rustup default stable-x86_64-pc-windows-msvc
```

### Error: "failed to run custom build command for `winres`"
**Solution:** Icon file is missing

```powershell
# Create a simple icon or disable icon embedding:
$env:HSIP_NO_ICON = "1"
cargo build --release
```

### Build is Very Slow
**Tips to speed up:**

```powershell
# Use more CPU cores
$env:CARGO_BUILD_JOBS = "8"

# Enable incremental compilation
$env:CARGO_INCREMENTAL = "1"

# Rebuild
cargo build --release
```

---

## Customization

### Change Installer Output Directory
```powershell
.\build-windows-package.ps1 -OutputDir "C:\MyCustomPath"
```

### Add Custom Files to Installer
Edit `build-windows-package.ps1` and add:

```powershell
# After line 66 (Copy documentation section)
Copy-Item "my-custom-file.txt" "$OutputDir\" -Force
```

### Change Application Metadata
Edit `crates/hsip-cli/build.rs`:

```rust
resource_builder.set("CompanyName", "Your Company");
resource_builder.set("ProductName", "Your Product");
resource_builder.set("FileDescription", "Your Description");
```

---

## Distribution Checklist

Before distributing the installer to users:

- [ ] Build in Release mode (`-Release`)
- [ ] Test install on clean Windows machine
- [ ] Verify tray icon shows after install
- [ ] Verify auto-start works after reboot
- [ ] Test that no terminal windows appear
- [ ] Run uninstall and verify clean removal
- [ ] Include README and verification docs
- [ ] Create SHA256 checksum for ZIP file

### Create Checksum

```powershell
Get-FileHash "HSIP-Windows-Installer.zip" -Algorithm SHA256 | Format-List
```

Share the checksum with users so they can verify download integrity.

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build Windows Installer

on:
  push:
    tags:
      - 'v*'

jobs:
  build-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          profile: minimal

      - name: Build Installer
        run: |
          cd installer
          .\build-windows-package.ps1

      - name: Upload Artifact
        uses: actions/upload-artifact@v3
        with:
          name: hsip-windows-installer
          path: "HSIP-Windows-Installer-*.zip"
```

---

## Code Signing (Optional but Recommended)

For production distribution, sign the executables:

```powershell
# Get a code signing certificate from:
# - DigiCert, Sectigo, or other CA
# Cost: ~$100-$500/year

# Sign the exe files
signtool sign /f "your-certificate.pfx" /p "password" /t http://timestamp.digicert.com "hsip-cli.exe"
signtool sign /f "your-certificate.pfx" /p "password" /t http://timestamp.digicert.com "hsip-tray.exe"
```

**Benefits:**
- No "Unknown Publisher" warning
- Windows SmartScreen won't block it
- More professional appearance
- Required for enterprise deployment

---

## Testing the Installer

### Test on Virtual Machine
1. Create Windows 10/11 VM
2. Install fresh Windows (no dev tools)
3. Extract and run installer
4. Verify:
   - ✅ Tray icon appears
   - ✅ No terminal windows
   - ✅ Auto-starts after reboot
   - ✅ Uninstall removes everything

### Test Upgrade Path
1. Install old version
2. Install new version over it
3. Verify settings are preserved
4. Verify no duplicate tasks/processes

---

## Version Numbering

Update version in these files:

1. `Cargo.toml` (workspace version)
2. `crates/hsip-cli/Cargo.toml`
3. `crates/hsip-cli/build.rs` (FileVersion)

```toml
# Cargo.toml
[package]
version = "0.2.0"  # <-- Update this
```

```rust
// build.rs
resource_builder.set("ProductVersion", "0.2.0.0");  // <-- Update this
resource_builder.set("FileVersion", "0.2.0.0");     // <-- Update this
```

---

## Support

**Questions?**
- Open an issue: https://github.com/your-repo/HSIP-1PHASE/issues
- Read docs: `README.md`
- Verify encryption: `HOW_TO_VERIFY_ENCRYPTION.md`

---

**Last Updated:** 2025-12-18
**Maintainer:** Nyx Systems LLC
