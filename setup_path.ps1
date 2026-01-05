# HSIP Environment Setup Script
# Run this in new PowerShell terminals with: . .\setup_path.ps1

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  HSIP Development Environment Setup" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Detect project directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$binPath = Join-Path $scriptPath "target\release"

# Add to PATH
$env:PATH += ";$binPath"

Write-Host "[✓] HSIP binaries added to PATH" -ForegroundColor Green
Write-Host "    Location: $binPath" -ForegroundColor Gray
Write-Host ""

# Verify binaries
$hsipCli = Get-Command hsip-cli -ErrorAction SilentlyContinue
$hsipGateway = Get-Command hsip-gateway -ErrorAction SilentlyContinue

if ($hsipCli) {
    $version = & hsip-cli --version 2>&1 | Out-String
    Write-Host "[✓] hsip-cli available" -ForegroundColor Green
    Write-Host "    Version: $($version.Trim())" -ForegroundColor Gray
} else {
    Write-Host "[!] hsip-cli not found - did you run 'cargo build --release'?" -ForegroundColor Yellow
}

if ($hsipGateway) {
    Write-Host "[✓] hsip-gateway available" -ForegroundColor Green
} else {
    Write-Host "[!] hsip-gateway not found" -ForegroundColor Yellow
}

Write-Host ""

# Check if services are running
Write-Host "Checking HSIP services..." -ForegroundColor Cyan

try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    Write-Host "[✓] Daemon running on port 8787" -ForegroundColor Green
} catch {
    Write-Host "[!] Daemon not running - start with: hsip-cli daemon" -ForegroundColor Yellow
}

$gatewayRunning = Get-Process -Name hsip-gateway -ErrorAction SilentlyContinue
if ($gatewayRunning) {
    Write-Host "[✓] Gateway running (PID: $($gatewayRunning.Id))" -ForegroundColor Green
} else {
    Write-Host "[!] Gateway not running - start with: hsip-gateway" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Available commands:" -ForegroundColor Cyan
Write-Host "  hsip-cli --help        - View all CLI commands" -ForegroundColor Gray
Write-Host "  hsip-cli daemon        - Start daemon API (port 8787)" -ForegroundColor Gray
Write-Host "  hsip-gateway           - Start HTTP proxy (port 8080)" -ForegroundColor Gray
Write-Host "  hsip-cli hello-listen  - Test UDP protocol" -ForegroundColor Gray
Write-Host "  hsip-cli session-send  - Test encrypted sessions" -ForegroundColor Gray
Write-Host ""
Write-Host "Security testing:" -ForegroundColor Cyan
Write-Host "  cd security_tests" -ForegroundColor Gray
Write-Host "  .\windows_tests.ps1    - Run automated security tests" -ForegroundColor Gray
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
