# Fix HSIP-2PHASE Cargo.toml workspace members
# Run this from HSIP-2PHASE directory

Write-Host "Fixing Cargo.toml workspace for Phase 2..." -ForegroundColor Yellow

$cargoToml = @'
[workspace]
members = [
    "crates/hsip-core",
    "crates/hsip-session",
    "crates/hsip-net",
    "crates/hsip-reputation",
    "crates/hsip-cli",
    "crates/hsip-auth",
    "crates/hsip-gateway",
    "crates/hsip-api",
    "crates/hsip-audit",
    "crates/hsip-enterprise",
    "crates/hsip-policy",
    "crates/hsip-verify",
]

exclude = [
    "crates/hsip-session/fuzz",
]
resolver = "2"

[workspace.dependencies]
tokio   = "1.39"
mio     = "0.8.11"
socket2 = "0.5.7"
windows = "0.58.0"
windows-sys = "0.60.2"
windows-targets = "0.53.5"
'@

Set-Content "Cargo.toml" $cargoToml

Write-Host "✓ Fixed Cargo.toml workspace members for Phase 2" -ForegroundColor Green
Write-Host ""
Write-Host "Now try: cargo build --release" -ForegroundColor Cyan
