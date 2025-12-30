# HSIP Windows Installer Package Builder
# This script builds the Windows executables and creates an installer package
# Run this on a Windows machine with Rust installed

param(
    [switch]$Release = $true,
    [string]$OutputDir = ".\hsip-windows-installer"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " HSIP Windows Installer Package Builder" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get the repository root
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $repoRoot) {
    $repoRoot = Split-Path $PSScriptRoot -Parent
}

Write-Host "[1/7] Repository root: $repoRoot" -ForegroundColor Yellow
Set-Location $repoRoot

# Clean previous build artifacts
Write-Host "[2/7] Cleaning previous build artifacts..." -ForegroundColor Yellow
cargo clean

# Build the main CLI executable
Write-Host "[3/7] Building HSIP CLI (hsip-cli.exe)..." -ForegroundColor Yellow
if ($Release) {
    cargo build --release --bin hsip-cli
    $buildDir = "target\release"
} else {
    cargo build --bin hsip-cli
    $buildDir = "target\debug"
}

if (-not (Test-Path "$buildDir\hsip-cli.exe")) {
    Write-Host "ERROR: Failed to build hsip-cli.exe" -ForegroundColor Red
    exit 1
}

# Build the tray icon executable
Write-Host "[4/7] Building HSIP Tray Icon (hsip-tray.exe)..." -ForegroundColor Yellow
if ($Release) {
    cargo build --release --bin hsip-tray
} else {
    cargo build --bin hsip-tray
}

if (-not (Test-Path "$buildDir\hsip-tray.exe")) {
    Write-Host "ERROR: Failed to build hsip-tray.exe" -ForegroundColor Red
    exit 1
}

# Create output directory
Write-Host "[5/7] Creating installer package directory..." -ForegroundColor Yellow
if (Test-Path $OutputDir) {
    Remove-Item $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDir | Out-Null

# Copy executables
Write-Host "[6/7] Copying files to installer package..." -ForegroundColor Yellow
Copy-Item "$buildDir\hsip-cli.exe" "$OutputDir\" -Force
Copy-Item "$buildDir\hsip-tray.exe" "$OutputDir\" -Force

# Copy installer scripts
Copy-Item "installer\register-daemon.ps1" "$OutputDir\" -Force
Copy-Item "installer\register-tray.ps1" "$OutputDir\" -Force
Copy-Item "installer\run-daemon.ps1" "$OutputDir\" -Force
Copy-Item "installer\run-tray.ps1" "$OutputDir\" -Force
Copy-Item "installer\uninstall.ps1" "$OutputDir\" -Force

# Copy documentation
Copy-Item "README.md" "$OutputDir\" -Force -ErrorAction SilentlyContinue
Copy-Item "ENCRYPTION_VERIFICATION_REPORT.md" "$OutputDir\" -Force -ErrorAction SilentlyContinue
Copy-Item "HOW_TO_VERIFY_ENCRYPTION.md" "$OutputDir\" -Force -ErrorAction SilentlyContinue

# Create installation instructions
$installInstructions = @"
# HSIP Windows Installation Instructions

## System Requirements
- Windows 10 or Windows 11
- Administrator privileges (for auto-start setup)

## Installation Steps

### 1. Extract This Package
Extract all files to a permanent location, for example:
   C:\Program Files\HSIP\

**IMPORTANT:** Do NOT run from Downloads or Temp folder!

### 2. Run the Installer (Right-click → Run as Administrator)
Open PowerShell as Administrator and run:

``````powershell
cd "C:\Program Files\HSIP"
.\install.ps1
``````

This will:
- ✅ Install HSIP daemon to run on system startup
- ✅ Install HSIP tray icon to show protection status
- ✅ Start HSIP immediately

### 3. Verify Installation
Look for the system tray icon (bottom-right of screen):
- 🟢 **GREEN**  = HSIP is running and protecting you
- 🟡 **YELLOW** = HSIP is blocking threats right now
- 🔴 **RED**    = HSIP is offline or there's an error

Hover over the icon to see detailed status.

## Status Indicators

### 🟢 Green (Protected)
- HSIP daemon is running
- Encryption is active
- No threats detected
- **You are protected**

### 🟡 Yellow (Blocking Threats)
- HSIP is actively blocking attacks
- Shows number of blocked connections/IPs/trackers
- **You are protected** - HSIP is working!

### 🔴 Red (Not Protected)
- HSIP daemon is offline OR
- There's an error OR
- Protection is not active
- **Click the icon to see error details**

## Uninstallation

To remove HSIP:

``````powershell
cd "C:\Program Files\HSIP"
.\uninstall.ps1
``````

This will:
- Remove auto-start tasks
- Stop the daemon and tray icon
- You can then delete the folder

## Troubleshooting

### Tray icon shows RED
1. Check if daemon is running:
   ``````powershell
   Get-ScheduledTask -TaskName "HSIP Daemon"
   ``````

2. Check daemon logs:
   ``````powershell
   type "C:\Program Files\HSIP\daemon.log"
   ``````

3. Restart services:
   ``````powershell
   .\register-daemon.ps1
   .\register-tray.ps1
   ``````

### No tray icon visible
1. Check if tray is running:
   ``````powershell
   Get-Process -Name "hsip-tray" -ErrorAction SilentlyContinue
   ``````

2. Restart tray:
   ``````powershell
   .\register-tray.ps1
   ``````

### "Empty black terminals" after restart
**This is FIXED in this version!** The daemon and tray now run completely hidden.

If you still see terminals:
1. Run uninstall.ps1
2. Delete old HSIP folder
3. Re-install with this new version

## Verification

To verify HSIP encryption is working:
1. Read `HOW_TO_VERIFY_ENCRYPTION.md`
2. Run the official IETF RFC 8439 test vectors
3. Use tcpdump/Wireshark to capture encrypted traffic

## Support

- Documentation: See README.md
- Encryption Verification: See ENCRYPTION_VERIFICATION_REPORT.md
- Issues: https://github.com/your-repo/HSIP-1PHASE/issues

---

**Version:** 0.2.0
**Build Date:** $(Get-Date -Format "yyyy-MM-dd")
**Status:** Production Ready ✅
"@

Set-Content -Path "$OutputDir\INSTALL.md" -Value $installInstructions -Encoding UTF8

# Create main install script
$mainInstaller = @"
# HSIP Main Installer
# Run this as Administrator

`$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  HSIP Installation Wizard" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
`$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not `$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell → Run as Administrator" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "[1/4] Checking executables..." -ForegroundColor Yellow
if (-not (Test-Path ".\hsip-cli.exe") -or -not (Test-Path ".\hsip-tray.exe")) {
    Write-Host "ERROR: Executable files not found!" -ForegroundColor Red
    Write-Host "Make sure you extracted all files from the ZIP archive." -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "[2/4] Registering HSIP daemon (auto-start on boot)..." -ForegroundColor Yellow
.\register-daemon.ps1

Write-Host "[3/4] Registering HSIP tray icon..." -ForegroundColor Yellow
.\register-tray.ps1

Write-Host "[4/4] Verifying installation..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

`$daemonTask = Get-ScheduledTask -TaskName "HSIP Daemon" -ErrorAction SilentlyContinue
`$trayTask = Get-ScheduledTask -TaskName "HSIP Tray" -ErrorAction SilentlyContinue

if (`$daemonTask -and `$trayTask) {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "  ✅ HSIP Installation Successful!" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Look for the tray icon in your system tray (bottom-right):" -ForegroundColor Cyan
    Write-Host "  🟢 GREEN  = Protected" -ForegroundColor Green
    Write-Host "  🟡 YELLOW = Blocking threats" -ForegroundColor Yellow
    Write-Host "  🔴 RED    = Not protected / Error" -ForegroundColor Red
    Write-Host ""
    Write-Host "HSIP will start automatically when you log in." -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "WARNING: Installation may have issues." -ForegroundColor Yellow
    Write-Host "Check the logs in this folder for details." -ForegroundColor Yellow
    Write-Host ""
}

pause
"@

Set-Content -Path "$OutputDir\install.ps1" -Value $mainInstaller -Encoding UTF8

# Create uninstaller
$uninstaller = @"
# HSIP Uninstaller

`$ErrorActionPreference = "SilentlyContinue"

Write-Host "Uninstalling HSIP..." -ForegroundColor Yellow

# Stop and remove scheduled tasks
Unregister-ScheduledTask -TaskName "HSIP Daemon" -Confirm:`$false
Unregister-ScheduledTask -TaskName "HSIP Tray" -Confirm:`$false

# Kill running processes
Stop-Process -Name "hsip-cli" -Force
Stop-Process -Name "hsip-tray" -Force

Write-Host "HSIP has been uninstalled." -ForegroundColor Green
Write-Host "You can now delete this folder if you wish." -ForegroundColor Cyan
pause
"@

Set-Content -Path "$OutputDir\uninstall.ps1" -Value $uninstaller -Encoding UTF8

# Create ZIP archive
Write-Host "[7/7] Creating ZIP archive..." -ForegroundColor Yellow
$zipName = "HSIP-Windows-Installer-$(Get-Date -Format 'yyyy-MM-dd').zip"
if (Test-Path $zipName) {
    Remove-Item $zipName -Force
}

# Use .NET compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    (Resolve-Path $OutputDir).Path,
    (Join-Path (Get-Location) $zipName)
)

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  ✅ Build Complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Package created: $zipName" -ForegroundColor Cyan
$sizeMB = [math]::Round((Get-Item $zipName).Length / 1MB, 2)
Write-Host "Size: $sizeMB MB" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Extract $zipName on target Windows machine" -ForegroundColor White
Write-Host "2. Run install.ps1 as Administrator" -ForegroundColor White
Write-Host "3. Look for tray icon (Green = Protected)" -ForegroundColor White
Write-Host ""
