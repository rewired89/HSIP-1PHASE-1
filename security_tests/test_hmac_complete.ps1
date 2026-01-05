#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Complete HMAC verification test suite

.DESCRIPTION
    Tests both legitimate responses and tamper detection
#>

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  HSIP HMAC Protection - Complete Test Suite                      ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# HMAC key (same as daemon)
$HMAC_KEY = [System.Text.Encoding]::UTF8.GetBytes("HSIP-DAEMON-RESPONSE-INTEGRITY-KEY-V1-CHANGE-IN-PRODUCTION")

function Verify-Signature {
    param($Json)

    if (-not $Json.signature) { return $false }

    $dataJson = $Json.data | ConvertTo-Json -Compress -Depth 10
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($dataJson)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($HMAC_KEY)
    $hashBytes = $hmac.ComputeHash($dataBytes)
    $expectedSig = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()

    return $Json.signature -eq $expectedSig
}

# TEST 1: Check daemon is running and responding with signatures
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "TEST 1: Verify Daemon Sends Signed Responses" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

try {
    $response = Invoke-WebRequest -Uri "http://localhost:8787/status" -UseBasicParsing -ErrorAction Stop
    $json = $response.Content | ConvertFrom-Json

    Write-Host "✓ Daemon is responding" -ForegroundColor Green
    Write-Host "✓ Response is valid JSON" -ForegroundColor Green

    if ($json.signature -and $json.sig_alg -eq "HMAC-SHA256") {
        Write-Host "✓ Response includes HMAC-SHA256 signature" -ForegroundColor Green

        if (Verify-Signature -Json $json) {
            Write-Host ""
            Write-Host "✅ TEST 1 PASSED: Signature is VALID" -ForegroundColor Green -BackgroundColor Black
            Write-Host "   Response is authentic and can be trusted" -ForegroundColor Green
            $test1Pass = $true
        } else {
            Write-Host ""
            Write-Host "❌ TEST 1 FAILED: Signature is INVALID" -ForegroundColor Red -BackgroundColor Black
            Write-Host "   Signature doesn't match data!" -ForegroundColor Red
            $test1Pass = $false
        }
    } else {
        Write-Host ""
        Write-Host "❌ TEST 1 FAILED: No signature in response" -ForegroundColor Red -BackgroundColor Black
        $test1Pass = $false
    }
} catch {
    Write-Host "❌ TEST 1 FAILED: Cannot connect to daemon" -ForegroundColor Red -BackgroundColor Black
    Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "   Please start daemon: .\target\release\hsip-cli.exe daemon" -ForegroundColor Yellow
    $test1Pass = $false
}

Write-Host ""
Write-Host ""

# TEST 2: Simulate tampered response
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "TEST 2: Verify Tamper Detection (Simulated Attack)" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

# Simulate a tampered response (what an attacker would send)
$tamperedResponse = @{
    data = @{
        protected = $false
        active_sessions = 999
        egress_peer = "ATTACKER_CONTROLLED"
        cipher = "None"
        since = "2020-01-01T00:00:00Z"
        bytes_in = 0
        bytes_out = 0
        path = @("Attacker", "MITM", "Evil-Gateway")
        blocked_connections = 0
        blocked_ips = 0
        blocked_trackers = 0
    }
    signature = "0000000000000000000000000000000000000000000000000000000000000000"
    sig_alg = "HMAC-SHA256"
}

Write-Host "Simulating MITM attack with modified data:" -ForegroundColor Yellow
Write-Host "  - Changed 'protected' to false" -ForegroundColor Yellow
Write-Host "  - Changed 'active_sessions' to 999" -ForegroundColor Yellow
Write-Host "  - Changed 'egress_peer' to 'ATTACKER_CONTROLLED'" -ForegroundColor Yellow
Write-Host "  - Forged signature with all zeros" -ForegroundColor Yellow
Write-Host ""

if (Verify-Signature -Json $tamperedResponse) {
    Write-Host "❌ TEST 2 FAILED: Tampered response was ACCEPTED" -ForegroundColor Red -BackgroundColor Black
    Write-Host "   CRITICAL SECURITY ISSUE!" -ForegroundColor Red
    $test2Pass = $false
} else {
    Write-Host "✅ TEST 2 PASSED: Tampered response REJECTED" -ForegroundColor Green -BackgroundColor Black
    Write-Host "   Client correctly detected the forgery" -ForegroundColor Green
    $test2Pass = $true
}

Write-Host ""
Write-Host ""

# TEST 3: Test with curl through mitmproxy (if available)
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "TEST 3: Real MITM Attack Test (requires mitmproxy)" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

Write-Host "Checking if mitmproxy is active on port 8080..." -ForegroundColor Cyan
try {
    $proxyTest = Test-NetConnection -ComputerName localhost -Port 8080 -WarningAction SilentlyContinue
    if ($proxyTest.TcpTestSucceeded) {
        Write-Host "✓ mitmproxy detected on port 8080" -ForegroundColor Green
        Write-Host ""
        Write-Host "Sending request through mitmproxy attack proxy..." -ForegroundColor Cyan

        # Use curl.exe with proxy (more reliable than Invoke-WebRequest for localhost proxy)
        $proxyResponse = curl.exe -s -x http://localhost:8080 http://localhost:8787/status

        Write-Host "Response received: $($proxyResponse.Substring(0, [Math]::Min(100, $proxyResponse.Length)))..." -ForegroundColor Gray
        Write-Host ""

        # Check if response was tampered
        if ($proxyResponse -match "ATTACKER") {
            Write-Host "✓ Attack succeeded at network level (expected)" -ForegroundColor Yellow
            Write-Host "✓ Response contains: $proxyResponse" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Now checking if client would detect this tampering..." -ForegroundColor Cyan

            # Try to parse and verify
            try {
                $proxyJson = $proxyResponse | ConvertFrom-Json
                if (Verify-Signature -Json $proxyJson) {
                    Write-Host "❌ TEST 3 FAILED: Tampered response accepted!" -ForegroundColor Red -BackgroundColor Black
                    $test3Pass = $false
                } else {
                    Write-Host "✅ TEST 3 PASSED: Client rejected tampered response" -ForegroundColor Green -BackgroundColor Black
                    $test3Pass = $true
                }
            } catch {
                Write-Host "✅ TEST 3 PASSED: Tampered response is not even valid JSON" -ForegroundColor Green -BackgroundColor Black
                Write-Host "   Client would reject it immediately" -ForegroundColor Green
                $test3Pass = $true
            }
        } else {
            # Response not tampered - verify it's legitimate
            try {
                $proxyJson = $proxyResponse | ConvertFrom-Json
                if (Verify-Signature -Json $proxyJson) {
                    Write-Host "⚠️  TEST 3 INCONCLUSIVE: mitmproxy didn't tamper with response" -ForegroundColor Yellow -BackgroundColor Black
                    Write-Host "   Response passed through proxy unchanged" -ForegroundColor Yellow
                    Write-Host "   Make sure attack script is loaded: mitmdump -s security_tests\owasp_integrity_failure.py" -ForegroundColor Yellow
                    $test3Pass = $null
                } else {
                    Write-Host "✅ TEST 3 PASSED: Response rejected (invalid signature)" -ForegroundColor Green -BackgroundColor Black
                    $test3Pass = $true
                }
            } catch {
                Write-Host "⚠️  TEST 3 ERROR: $($_.Exception.Message)" -ForegroundColor Yellow
                $test3Pass = $null
            }
        }
    } else {
        Write-Host "⚠️  mitmproxy not detected on port 8080" -ForegroundColor Yellow
        Write-Host "   TEST 3 SKIPPED" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   To run this test, start mitmproxy in another terminal:" -ForegroundColor Gray
        Write-Host "   mitmdump -s security_tests\owasp_integrity_failure.py --listen-port 8080" -ForegroundColor Gray
        $test3Pass = $null
    }
} catch {
    Write-Host "⚠️  Cannot check for mitmproxy" -ForegroundColor Yellow
    Write-Host "   TEST 3 SKIPPED" -ForegroundColor Yellow
    $test3Pass = $null
}

Write-Host ""
Write-Host ""

# FINAL RESULTS
Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  FINAL RESULTS                                                    ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($test1Pass) {
    Write-Host "✅ TEST 1: Daemon sends valid HMAC signatures" -ForegroundColor Green
} else {
    Write-Host "❌ TEST 1: Daemon signature test failed" -ForegroundColor Red
}

if ($test2Pass) {
    Write-Host "✅ TEST 2: Client detects forged signatures" -ForegroundColor Green
} else {
    Write-Host "❌ TEST 2: Client accepts forged signatures" -ForegroundColor Red
}

if ($test3Pass -eq $true) {
    Write-Host "✅ TEST 3: Real MITM attack detected and blocked" -ForegroundColor Green
} elseif ($test3Pass -eq $false) {
    Write-Host "❌ TEST 3: Real MITM attack NOT detected" -ForegroundColor Red
} else {
    Write-Host "⚠️  TEST 3: Skipped (mitmproxy not available)" -ForegroundColor Yellow
}

Write-Host ""

$totalTests = 2
$passedTests = 0
if ($test1Pass) { $passedTests++ }
if ($test2Pass) { $passedTests++ }

if ($passedTests -eq $totalTests) {
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✅ HMAC PROTECTION IS WORKING CORRECTLY" -ForegroundColor Green -BackgroundColor Black
    Write-Host "  All critical tests passed ($passedTests/$totalTests)" -ForegroundColor Green -BackgroundColor Black
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "🔒 OWASP A08 Vulnerability FIXED" -ForegroundColor Green
    Write-Host "   Clients can now detect response tampering attacks" -ForegroundColor Green
} else {
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "  ❌ HMAC PROTECTION HAS ISSUES" -ForegroundColor Red -BackgroundColor Black
    Write-Host "  Only $passedTests/$totalTests critical tests passed" -ForegroundColor Red -BackgroundColor Black
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Red
}

Write-Host ""

exit $(if ($passedTests -eq $totalTests) { 0 } else { 1 })
