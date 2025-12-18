# HSIP Windows Installer Builder (Inno Setup Version)
# Creates a professional .exe installer using Inno Setup

param(
    [switch]$SkipBuild = $false,
    [string]$InnoSetupPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " HSIP Installer Builder (Inno Setup)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get repository root
$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot

# Check if Inno Setup is installed
if (-not (Test-Path $InnoSetupPath)) {
    Write-Host "ERROR: Inno Setup not found at: $InnoSetupPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Inno Setup from:" -ForegroundColor Yellow
    Write-Host "  https://jrsoftware.org/isdl.php" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Or specify the path with -InnoSetupPath parameter" -ForegroundColor Yellow
    exit 1
}

# Build executables unless skipped
if (-not $SkipBuild) {
    Write-Host "[1/3] Building HSIP executables..." -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  Building hsip-cli.exe..." -ForegroundColor Gray
    cargo build --release --bin hsip-cli
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to build hsip-cli.exe" -ForegroundColor Red
        exit 1
    }

    Write-Host "  Building hsip-tray.exe..." -ForegroundColor Gray
    cargo build --release --bin hsip-tray
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to build hsip-tray.exe" -ForegroundColor Red
        exit 1
    }

    Write-Host "  ✓ Executables built successfully" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "[1/3] Skipping build (using existing executables)..." -ForegroundColor Yellow
    Write-Host ""
}

# Verify executables exist
Write-Host "[2/3] Verifying executables..." -ForegroundColor Yellow
$cliExe = "target\release\hsip-cli.exe"
$trayExe = "target\release\hsip-tray.exe"

if (-not (Test-Path $cliExe)) {
    Write-Host "ERROR: $cliExe not found!" -ForegroundColor Red
    Write-Host "Run without -SkipBuild to build executables" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $trayExe)) {
    Write-Host "ERROR: $trayExe not found!" -ForegroundColor Red
    Write-Host "Run without -SkipBuild to build executables" -ForegroundColor Yellow
    exit 1
}

Write-Host "  ✓ hsip-cli.exe:  $((Get-Item $cliExe).Length / 1MB | ForEach-Object {[math]::Round($_, 2)}) MB" -ForegroundColor Green
Write-Host "  ✓ hsip-tray.exe: $((Get-Item $trayExe).Length / 1MB | ForEach-Object {[math]::Round($_, 2)}) MB" -ForegroundColor Green
Write-Host ""

# Build installer with Inno Setup
Write-Host "[3/3] Building installer with Inno Setup..." -ForegroundColor Yellow
Write-Host ""

$issFile = Join-Path $PSScriptRoot "hsip-installer.iss"
if (-not (Test-Path $issFile)) {
    Write-Host "ERROR: Inno Setup script not found: $issFile" -ForegroundColor Red
    exit 1
}

# Run Inno Setup compiler
Write-Host "  Compiling: $issFile" -ForegroundColor Gray
& $InnoSetupPath $issFile

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Inno Setup compilation failed" -ForegroundColor Red
    exit 1
}

# Find the generated installer
$outputDir = Join-Path $PSScriptRoot "output"
$installerExe = Get-ChildItem $outputDir -Filter "HSIP-Setup-*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $installerExe) {
    Write-Host "ERROR: Installer exe not found in $outputDir" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  ✅ Installer Built Successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Installer: $($installerExe.FullName)" -ForegroundColor Cyan
Write-Host "Size:      $($installerExe.Length / 1MB | ForEach-Object {[math]::Round($_, 2)}) MB" -ForegroundColor Cyan
Write-Host ""

# Generate SHA256 checksum
Write-Host "SHA256 Checksum:" -ForegroundColor Yellow
$hash = Get-FileHash $installerExe.FullName -Algorithm SHA256
Write-Host $hash.Hash -ForegroundColor White
Write-Host ""

# Save checksum to file
$checksumFile = Join-Path $outputDir "$($installerExe.BaseName).sha256"
Set-Content $checksumFile $hash.Hash
Write-Host "Checksum saved to: $checksumFile" -ForegroundColor Gray
Write-Host ""

Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Test installer on clean Windows VM" -ForegroundColor White
Write-Host "  2. Verify tray icon appears (Green/Yellow/Red)" -ForegroundColor White
Write-Host "  3. Test auto-start after reboot (no terminals!)" -ForegroundColor White
Write-Host "  4. Distribute $($installerExe.Name)" -ForegroundColor White
Write-Host ""
Write-Host "Users can verify encryption:" -ForegroundColor Cyan
Write-Host "  • Read HOW_TO_VERIFY_ENCRYPTION.md" -ForegroundColor White
Write-Host "  • Run official IETF RFC 8439 tests" -ForegroundColor White
Write-Host "  • Use tcpdump to see encrypted traffic" -ForegroundColor White
Write-Host ""
