#!/usr/bin/env pwsh
# Simple test to verify daemon is working

Write-Host "Testing daemon connectivity..." -ForegroundColor Cyan
Write-Host ""

# Test 1: Direct connection
Write-Host "Test 1: Direct connection to daemon" -ForegroundColor Yellow
Write-Host "Command: curl.exe http://localhost:8787/status"
Write-Host ""

$response = Invoke-WebRequest -Uri "http://localhost:8787/status" -UseBasicParsing -ErrorAction Stop
Write-Host "Status Code: $($response.StatusCode)"
Write-Host "Content:"
Write-Host $response.Content
Write-Host ""

# Parse and check for signature
$json = $response.Content | ConvertFrom-Json
Write-Host "Parsed JSON fields:"
Write-Host "  - Has 'data' field: $($null -ne $json.data)"
Write-Host "  - Has 'signature' field: $($null -ne $json.signature)"
Write-Host "  - Has 'sig_alg' field: $($null -ne $json.sig_alg)"
Write-Host ""

if ($json.signature) {
    Write-Host "✅ SUCCESS: Daemon is sending signed responses!" -ForegroundColor Green
    Write-Host "   Signature algorithm: $($json.sig_alg)"
    Write-Host "   Signature (first 32 chars): $($json.signature.Substring(0, 32))..."
} else {
    Write-Host "❌ FAILED: Response not signed" -ForegroundColor Red
}
