# Fix HSIP-2PHASE build issues after security migration
# Run this from HSIP-2PHASE directory

param()

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Fixing HSIP-2PHASE Build Issues                                 ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Fix 1: Clean up duplicated identity.rs content
Write-Host "[1/3] Fixing identity.rs duplicate code..." -ForegroundColor Yellow
$identityFile = "crates\hsip-auth\src\identity.rs"

if (Test-Path $identityFile) {
    $content = @'
use anyhow::Result;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::keystore;

// Initialize or retrieve device identity keypair
pub fn ensure_device_identity() -> Result<(SigningKey, VerifyingKey)> {
    match keystore::load() {
        Ok(existing_keypair) => Ok(existing_keypair),
        Err(_) => create_and_store_new_identity(),
    }
}

fn create_and_store_new_identity() -> Result<(SigningKey, VerifyingKey)> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    keystore::save(&signing_key, &verifying_key)?;
    Ok((signing_key, verifying_key))
}

// Generate base64-encoded peer identifier from verifying key
pub fn peer_id_b64() -> Result<String> {
    let (_signing_key, verifying_key) = ensure_device_identity()?;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(verifying_key.to_bytes());
    Ok(encoded)
}

// Generate hex-encoded public key string
pub fn public_key_hex() -> Result<String> {
    let (_signing_key, verifying_key) = ensure_device_identity()?;
    Ok(hex::encode(verifying_key.to_bytes()))
}
'@

    Set-Content $identityFile $content -NoNewline
    Write-Host "  ✓ Fixed identity.rs (removed duplicate code)" -ForegroundColor Green
}

# Fix 2: Add HMAC dependencies to hsip-cli
Write-Host ""
Write-Host "[2/3] Adding HMAC dependencies..." -ForegroundColor Yellow
$cliCargoFile = "crates\hsip-cli\Cargo.toml"

if (Test-Path $cliCargoFile) {
    $cargoContent = Get-Content $cliCargoFile -Raw

    # Check if dependencies already exist
    if ($cargoContent -notmatch 'hmac\s*=') {
        Write-Host "  Adding hmac, sha2, hex to hsip-cli dependencies..." -ForegroundColor Gray

        # Find [dependencies] section and add our deps
        if ($cargoContent -match '(\[dependencies\])') {
            $cargoContent = $cargoContent -replace '(\[dependencies\])', @'
$1
hmac = "0.12"
sha2 = "0.10"
hex = "0.4"
'@
            Set-Content $cliCargoFile $cargoContent
            Write-Host "  ✓ Added HMAC dependencies" -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  Could not find [dependencies] section" -ForegroundColor Yellow
            Write-Host "     Add these manually to crates/hsip-cli/Cargo.toml:" -ForegroundColor Yellow
            Write-Host '       hmac = "0.12"' -ForegroundColor White
            Write-Host '       sha2 = "0.10"' -ForegroundColor White
            Write-Host '       hex = "0.4"' -ForegroundColor White
        }
    } else {
        Write-Host "  ✓ HMAC dependencies already present" -ForegroundColor Green
    }
}

# Fix 3: Enable identity feature or remove feature gates
Write-Host ""
Write-Host "[3/3] Fixing feature flags..." -ForegroundColor Yellow
$authLibFile = "crates\hsip-auth\src\lib.rs"

if (Test-Path $authLibFile) {
    $libContent = Get-Content $authLibFile -Raw

    # Remove feature gates for identity module (it's always needed)
    $libContent = $libContent -replace '#\[cfg\(feature = "identity"\)\]\s*pub mod identity;', 'pub mod identity;'
    $libContent = $libContent -replace '#\[cfg\(not\(feature = "identity"\)\)\]\s*pub mod identity \{[^}]*\}', ''

    Set-Content $authLibFile $libContent
    Write-Host "  ✓ Removed conditional compilation for identity module" -ForegroundColor Green
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✅ Build fixes applied!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Build: cargo build --release" -ForegroundColor White
Write-Host "  2. Test: .\security_tests\test_hmac_complete.ps1" -ForegroundColor White
Write-Host "  3. Commit: git add -A && git commit -m 'Port security fixes + build fixes'" -ForegroundColor White
Write-Host "  4. Push: git push -u origin claude/hsip2-security-port" -ForegroundColor White
Write-Host ""
