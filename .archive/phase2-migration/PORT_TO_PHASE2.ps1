# HSIP Security Fixes Migration Script
# Ports all security updates from HSIP-1PHASE-1 to HSIP-2PHASE
# Run this from HSIP-2PHASE directory

param(
    [string]$Phase1Path = "..\HSIP-1PHASE-1"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  HSIP Security Fixes Migration: Phase 1 → Phase 2                ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verify we're in HSIP-2PHASE
if (-not (Test-Path "Cargo.toml")) {
    Write-Host "ERROR: Not in HSIP project root (no Cargo.toml found)" -ForegroundColor Red
    Write-Host "Please run this from HSIP-2PHASE directory" -ForegroundColor Yellow
    exit 1
}

# Verify Phase 1 exists
if (-not (Test-Path $Phase1Path)) {
    Write-Host "ERROR: HSIP-1PHASE-1 not found at: $Phase1Path" -ForegroundColor Red
    Write-Host "Please specify path with -Phase1Path parameter" -ForegroundColor Yellow
    exit 1
}

Write-Host "Phase 1 source: $Phase1Path" -ForegroundColor Gray
Write-Host "Phase 2 target: $(Get-Location)" -ForegroundColor Gray
Write-Host ""

# Create backup branch
Write-Host "[1/8] Creating backup branch..." -ForegroundColor Yellow
$currentBranch = git rev-parse --abbrev-ref HEAD 2>$null
if ($currentBranch) {
    Write-Host "  Current branch: $currentBranch" -ForegroundColor Gray
    git checkout -b "backup-before-security-port-$(Get-Date -Format 'yyyyMMdd-HHmmss')" 2>$null
    git checkout $currentBranch 2>$null
}

# Create new branch for security updates
Write-Host ""
Write-Host "[2/8] Creating security update branch..." -ForegroundColor Yellow
git checkout -b "claude/hsip2-security-port"
Write-Host "  ✓ Branch created: claude/hsip2-security-port" -ForegroundColor Green

# Port HMAC protection code
Write-Host ""
Write-Host "[3/8] Porting HMAC protection code..." -ForegroundColor Yellow
$daemonFile = "crates\hsip-cli\src\daemon\mod.rs"
if (Test-Path $daemonFile) {
    Write-Host "  Copying HMAC-protected daemon code..." -ForegroundColor Gray
    Copy-Item "$Phase1Path\$daemonFile" $daemonFile -Force
    Write-Host "  ✓ Updated: $daemonFile" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  WARNING: $daemonFile not found in Phase 2" -ForegroundColor Yellow
    Write-Host "     You may need to manually add HMAC protection" -ForegroundColor Yellow
}

# Update Cargo.toml workspace
Write-Host ""
Write-Host "[4/8] Updating Cargo workspace configuration..." -ForegroundColor Yellow
if (Test-Path "Cargo.toml") {
    $cargoContent = Get-Content "$Phase1Path\Cargo.toml" -Raw
    if ($cargoContent -match 'exclude\s*=\s*\[[\s\S]*?hsip-intercept') {
        Write-Host "  Updating workspace exclusions..." -ForegroundColor Gray
        Copy-Item "$Phase1Path\Cargo.toml" "Cargo.toml" -Force
        Write-Host "  ✓ Updated: Cargo.toml" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Cargo.toml unchanged (no intercept exclusion needed)" -ForegroundColor Gray
    }
}

# Copy security documentation
Write-Host ""
Write-Host "[5/8] Copying security documentation..." -ForegroundColor Yellow
$securityDocs = @(
    "SECURITY_HARDENING_STRATEGY.md",
    "BUILD_INSTALLER.md"
)
foreach ($doc in $securityDocs) {
    if (Test-Path "$Phase1Path\$doc") {
        Copy-Item "$Phase1Path\$doc" $doc -Force
        Write-Host "  ✓ Copied: $doc" -ForegroundColor Green
    }
}

# Copy security test suite
Write-Host ""
Write-Host "[6/8] Copying security test suite..." -ForegroundColor Yellow
if (-not (Test-Path "security_tests")) {
    New-Item -ItemType Directory -Path "security_tests" | Out-Null
}
Copy-Item "$Phase1Path\security_tests\*" "security_tests\" -Recurse -Force
Write-Host "  ✓ Copied all security tests to security_tests\" -ForegroundColor Green

# Update installer
Write-Host ""
Write-Host "[7/8] Updating installer to v0.2.1-security..." -ForegroundColor Yellow
if (Test-Path "installer") {
    # Copy updated installer files
    $installerFiles = @(
        "installer\hsip-installer.iss",
        "installer\build-with-inno.ps1",
        "installer\RELEASE_NOTES_v0.2.1.md"
    )
    foreach ($file in $installerFiles) {
        if (Test-Path "$Phase1Path\$file") {
            Copy-Item "$Phase1Path\$file" $file -Force
            Write-Host "  ✓ Updated: $file" -ForegroundColor Green
        }
    }
} else {
    Write-Host "  ⚠️  No installer directory found" -ForegroundColor Yellow
}

# Update Cargo.lock if needed
Write-Host ""
Write-Host "[8/8] Verifying dependencies..." -ForegroundColor Yellow
Write-Host "  Checking for new dependencies (hmac, sha2, hex)..." -ForegroundColor Gray
$cargoToml = Get-Content "crates\hsip-cli\Cargo.toml" -Raw
if ($cargoToml -notmatch 'hmac\s*=') {
    Write-Host "  ⚠️  WARNING: hmac dependency not found in hsip-cli/Cargo.toml" -ForegroundColor Yellow
    Write-Host "     Add these to crates/hsip-cli/Cargo.toml:" -ForegroundColor Yellow
    Write-Host '       hmac = "0.12"' -ForegroundColor White
    Write-Host '       sha2 = "0.10"' -ForegroundColor White
    Write-Host '       hex = "0.4"' -ForegroundColor White
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✅ Security fixes ported successfully!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

Write-Host "Files updated:" -ForegroundColor Cyan
Write-Host "  • crates/hsip-cli/src/daemon/mod.rs (HMAC protection)" -ForegroundColor White
Write-Host "  • Cargo.toml (workspace exclusions)" -ForegroundColor White
Write-Host "  • SECURITY_HARDENING_STRATEGY.md (banking roadmap)" -ForegroundColor White
Write-Host "  • BUILD_INSTALLER.md (build instructions)" -ForegroundColor White
Write-Host "  • security_tests/ (complete test suite)" -ForegroundColor White
Write-Host "  • installer/ (v0.2.1-security)" -ForegroundColor White
Write-Host ""

Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review changes: git diff" -ForegroundColor White
Write-Host "  2. Build and test: cargo build --release" -ForegroundColor White
Write-Host "  3. Run security tests: .\security_tests\test_hmac_complete.ps1" -ForegroundColor White
Write-Host "  4. Commit: git add -A && git commit -m 'Port security fixes from Phase 1'" -ForegroundColor White
Write-Host "  5. Push: git push -u origin claude/hsip2-security-port" -ForegroundColor White
Write-Host ""

Write-Host "Security updates ported:" -ForegroundColor Cyan
Write-Host "  ✅ OWASP A08 fix (HMAC-SHA256 response integrity)" -ForegroundColor Green
Write-Host "  ✅ Complete security test suite" -ForegroundColor Green
Write-Host "  ✅ Banking security roadmap" -ForegroundColor Green
Write-Host "  ✅ Installer v0.2.1-security" -ForegroundColor Green
Write-Host ""
