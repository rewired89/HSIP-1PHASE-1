#!/usr/bin/env pwsh
<#
.SYNOPSIS
    HSIP HMAC Signature Verification - Client-Side Protection Demo (PowerShell)

.DESCRIPTION
    This script demonstrates how a proper HSIP client would detect
    response tampering using HMAC signature verification.

.PARAMETER UseProxy
    Test through mitmproxy (attack scenario)

.EXAMPLE
    .\verify_hmac_protection.ps1
    # Test without proxy - shows legitimate signed response

.EXAMPLE
    .\verify_hmac_protection.ps1 -UseProxy
    # Test through mitmproxy - demonstrates tamper detection
#>

param(
    [switch]$UseProxy
)

# HMAC key (same as daemon)
$HMAC_KEY = [System.Text.Encoding]::UTF8.GetBytes("HSIP-DAEMON-RESPONSE-INTEGRITY-KEY-V1-CHANGE-IN-PRODUCTION")

function Verify-ResponseSignature {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ResponseJson
    )

    try {
        # Check required fields
        if (-not $ResponseJson.data) {
            return @{
                IsValid = $false
                Message = "Missing 'data' field - response may be tampered"
            }
        }

        if (-not $ResponseJson.signature) {
            return @{
                IsValid = $false
                Message = "Missing 'signature' field - response may be tampered"
            }
        }

        if (-not $ResponseJson.sig_alg) {
            return @{
                IsValid = $false
                Message = "Missing 'sig_alg' field - response may be tampered"
            }
        }

        # Verify algorithm
        if ($ResponseJson.sig_alg -ne "HMAC-SHA256") {
            return @{
                IsValid = $false
                Message = "Unknown signature algorithm: $($ResponseJson.sig_alg)"
            }
        }

        # Extract components
        $receivedSignature = $ResponseJson.signature

        # Compute expected signature
        $dataJson = $ResponseJson.data | ConvertTo-Json -Compress -Depth 10
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($dataJson)

        $hmac = [System.Security.Cryptography.HMACSHA256]::new($HMAC_KEY)
        $hashBytes = $hmac.ComputeHash($dataBytes)
        $expectedSignature = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()

        # Compare signatures
        if ($receivedSignature -ne $expectedSignature) {
            return @{
                IsValid = $false
                Message = "SIGNATURE MISMATCH - Response has been tampered!`n  Expected: $($expectedSignature.Substring(0, 32))...`n  Received: $($receivedSignature.Substring(0, 32))..."
            }
        }

        return @{
            IsValid = $true
            Message = "Signature valid - response is authentic"
        }

    } catch {
        return @{
            IsValid = $false
            Message = "Verification error: $($_.Exception.Message)"
        }
    }
}

function Test-Endpoint {
    param([bool]$UseProxy)

    $url = "http://localhost:8787/status"

    Write-Host "=" * 70
    if ($UseProxy) {
        Write-Host "Testing HSIP Daemon - WITH PROXY (attack)"
    } else {
        Write-Host "Testing HSIP Daemon - DIRECT (no attack)"
    }
    Write-Host "=" * 70
    Write-Host "URL: $url"
    if ($UseProxy) {
        Write-Host "Proxy: http://localhost:8080"
    }
    Write-Host ""

    try {
        # Make request
        if ($UseProxy) {
            $response = curl.exe -s -x http://localhost:8080 $url
        } else {
            $response = curl.exe -s $url
        }

        # Show raw response
        Write-Host "Raw Response:"
        Write-Host ("-" * 70)
        if ($response.Length -gt 500) {
            Write-Host $response.Substring(0, 500)
            Write-Host "... ($($response.Length) bytes total)"
        } else {
            Write-Host $response
        }
        Write-Host ("-" * 70)
        Write-Host ""

        # Try to parse as JSON
        try {
            $responseJson = $response | ConvertFrom-Json
            Write-Host "✓ Response is valid JSON"
            Write-Host ""

            # Verify signature
            $result = Verify-ResponseSignature -ResponseJson $responseJson

            if ($result.IsValid) {
                Write-Host "✅ SIGNATURE VERIFICATION: PASSED" -ForegroundColor Green
                Write-Host "   $($result.Message)"
                Write-Host ""
                Write-Host "🔒 Response is AUTHENTIC - Safe to use" -ForegroundColor Green
                Write-Host ""
                Write-Host "Response data:"
                Write-Host ($responseJson.data | ConvertTo-Json -Depth 10)
                return $true
            } else {
                Write-Host "❌ SIGNATURE VERIFICATION: FAILED" -ForegroundColor Red
                Write-Host "   $($result.Message)"
                Write-Host ""
                Write-Host "🚨 SECURITY ALERT: Response has been TAMPERED!" -ForegroundColor Red
                Write-Host "   DO NOT trust this data. Possible MITM attack detected."
                return $false
            }

        } catch {
            Write-Host "✗ Response is NOT valid JSON"
            Write-Host ""
            Write-Host "❌ SIGNATURE VERIFICATION: FAILED" -ForegroundColor Red
            Write-Host "   Response is not in expected format - likely tampered"
            Write-Host ""
            Write-Host "🚨 SECURITY ALERT: Response has been TAMPERED!" -ForegroundColor Red
            Write-Host "   DO NOT trust this data. Possible MITM attack detected."
            return $false
        }

    } catch {
        Write-Host "❌ ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main execution
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════╗"
Write-Host "║  HSIP HMAC Signature Verification Demo                           ║"
Write-Host "║  Testing Response Integrity Protection (OWASP A08 Defense)       ║"
Write-Host "╚═══════════════════════════════════════════════════════════════════╝"
Write-Host ""

$result = Test-Endpoint -UseProxy $UseProxy

Write-Host ""
Write-Host "=" * 70
if ($result) {
    Write-Host "RESULT: Response is authentic and safe to use ✅" -ForegroundColor Green
} else {
    Write-Host "RESULT: Response failed verification - REJECTED ❌" -ForegroundColor Red
}
Write-Host "=" * 70
Write-Host ""

# Exit code
exit $(if ($result) { 0 } else { 1 })
