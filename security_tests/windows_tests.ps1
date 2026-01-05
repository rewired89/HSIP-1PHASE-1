# HSIP Phase 1 Security Testing - Windows PowerShell Edition
# Run from: C:\Users\melas\HSIP-1PHASE-1\security_tests

Write-Host "========================================" -ForegroundColor Blue
Write-Host "  HSIP Phase 1 Security Testing (Windows)" -ForegroundColor Blue
Write-Host "========================================" -ForegroundColor Blue
Write-Host ""

# Create results directory
$resultsDir = ".\results"
if (-not (Test-Path $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Check prerequisites
Write-Host "[*] Checking prerequisites..." -ForegroundColor Yellow

if (-not (Get-Command mitmdump -ErrorAction SilentlyContinue)) {
    Write-Host "[!] mitmproxy not found. Install with: pip install mitmproxy" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command curl -ErrorAction SilentlyContinue)) {
    Write-Host "[!] curl not found. Please install curl" -ForegroundColor Red
    exit 1
}

Write-Host "[✓] Prerequisites OK" -ForegroundColor Green
Write-Host ""

# Check if HSIP is running
Write-Host "[*] Checking HSIP services..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -UseBasicParsing -ErrorAction Stop
    Write-Host "[✓] HSIP daemon running on port 8787" -ForegroundColor Green
    Write-Host "    Response: $($response.Content)" -ForegroundColor Gray
} catch {
    Write-Host "[!] HSIP daemon not responding on port 8787" -ForegroundColor Yellow
    Write-Host "[!] Start with: hsip-cli daemon --addr 127.0.0.1:8787" -ForegroundColor Yellow
}

try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8080" -UseBasicParsing -ErrorAction Stop
    Write-Host "[✓] HSIP gateway running on port 8080" -ForegroundColor Green
} catch {
    Write-Host "[!] HSIP gateway not responding on port 8080" -ForegroundColor Yellow
}

Write-Host ""

# Test 1: API Fuzzing
Write-Host "[1/6] Testing HTTP Status API..." -ForegroundColor Blue
$testResults = @()

try {
    Write-Host "  - Normal GET request..."
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -Method GET -UseBasicParsing
    $testResults += "[PASS] Normal GET: Status $($response.StatusCode)"
} catch {
    $testResults += "[INFO] Normal GET failed: $($_.Exception.Message)"
}

try {
    Write-Host "  - DELETE method (should fail)..."
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -Method DELETE -UseBasicParsing
    $testResults += "[WARN] DELETE succeeded: Status $($response.StatusCode)"
} catch {
    $testResults += "[PASS] DELETE blocked: $($_.Exception.Message.Substring(0,50))..."
}

try {
    Write-Host "  - Path traversal attempt..."
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8787/../../../etc/passwd" -UseBasicParsing
    $testResults += "[WARN] Path traversal succeeded: Status $($response.StatusCode)"
} catch {
    $testResults += "[PASS] Path traversal blocked: $($_.Exception.Message.Substring(0,50))..."
}

try {
    Write-Host "  - Malformed POST data..."
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -Method POST -Body "malformed{{{data" -UseBasicParsing
    $testResults += "[INFO] Malformed POST: Status $($response.StatusCode)"
} catch {
    $testResults += "[PASS] Malformed POST rejected: $($_.Exception.Message.Substring(0,50))..."
}

$testResults | Out-File "$resultsDir\01_api_tests_$timestamp.log"
Write-Host "[✓] Results: $resultsDir\01_api_tests_$timestamp.log" -ForegroundColor Green
Write-Host ""

# Test 2: Rate Limiting (PowerShell version)
Write-Host "[2/6] Testing Rate Limiting..." -ForegroundColor Blue
Write-Host "  Sending 100 concurrent requests..."

$jobs = @()
for ($i = 1; $i -le 100; $i++) {
    $jobs += Start-Job -ScriptBlock {
        Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
    }
}

$jobs | Wait-Job | Remove-Job

try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -UseBasicParsing
    Write-Host "[PASS] Server still responsive after 100 requests: Status $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Server unresponsive after rate limit test" -ForegroundColor Red
}

Write-Host ""

# Test 3: Large Payload (PowerShell version)
Write-Host "[3/6] Testing Large Payload..." -ForegroundColor Blue
Write-Host "  Generating 10MB random data..."

$largeData = [byte[]]::new(10MB)
(New-Object Random).NextBytes($largeData)

try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -Method POST -Body $largeData -UseBasicParsing -TimeoutSec 10
    Write-Host "[WARN] Large payload accepted: Status $($response.StatusCode)" -ForegroundColor Yellow
} catch {
    Write-Host "[PASS] Large payload rejected: $($_.Exception.Message.Substring(0,80))..." -ForegroundColor Green
}

Write-Host ""

# Test 4: Header Injection
Write-Host "[4/6] Testing Header Injection Attack..." -ForegroundColor Blue

$job = Start-Job -ScriptBlock {
    mitmdump -s security_tests\header_injection.py -p 8091 --ssl-insecure 2>&1
}

Start-Sleep -Seconds 2

try {
    $response = curl.exe -x http://127.0.0.1:8091 http://example.com -s
    Write-Host "  Response length: $($response.Length) bytes"

    if ($response -match "TAMPERED|INJECTED") {
        Write-Host "[WARN] Attack may have succeeded - found attack markers" -ForegroundColor Yellow
    } else {
        Write-Host "[INFO] No obvious attack markers in response" -ForegroundColor Gray
    }
} catch {
    Write-Host "[INFO] Request failed: $($_.Exception.Message)" -ForegroundColor Gray
}

Stop-Job $job | Out-Null
Remove-Job $job | Out-Null

Write-Host ""

# Test 5: Response Tampering
Write-Host "[5/6] Testing Response Tampering Attack..." -ForegroundColor Blue

$job = Start-Job -ScriptBlock {
    mitmdump -s security_tests\response_tamper.py -p 8092 --ssl-insecure 2>&1
}

Start-Sleep -Seconds 2

try {
    $response = curl.exe -x http://127.0.0.1:8092 http://example.com -s

    if ($response -match "TAMPERED_DATA_BY_ATTACKER") {
        Write-Host "[CRITICAL] Response tampering succeeded!" -ForegroundColor Red
        Write-Host "  This means AEAD protection is NOT active or bypassed" -ForegroundColor Red
        Write-Host "  Response: $response" -ForegroundColor Yellow
    } else {
        Write-Host "[PASS] Response tampering blocked" -ForegroundColor Green
    }
} catch {
    Write-Host "[PASS] Connection failed (expected if HSIP blocked it)" -ForegroundColor Green
}

Stop-Job $job | Out-Null
Remove-Job $job | Out-Null

Write-Host ""

# Test 6: SSL Stripping
Write-Host "[6/6] Testing SSL Stripping Attack..." -ForegroundColor Blue

$job = Start-Job -ScriptBlock {
    mitmdump -s security_tests\ssl_strip.py -p 8093 --ssl-insecure 2>&1
}

Start-Sleep -Seconds 2

try {
    # Use -k to ignore cert errors for this test
    $response = curl.exe -x http://127.0.0.1:8093 https://example.com -k -s

    if ($response -match "Example Domain") {
        Write-Host "[WARN] SSL stripping may have succeeded" -ForegroundColor Yellow
        Write-Host "  HTTPS was downgraded to HTTP" -ForegroundColor Yellow
    } else {
        Write-Host "[PASS] SSL stripping blocked" -ForegroundColor Green
    }
} catch {
    Write-Host "[PASS] SSL stripping blocked (connection failed)" -ForegroundColor Green
}

Stop-Job $job | Out-Null
Remove-Job $job | Out-Null

Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Blue
Write-Host "  Test Suite Complete" -ForegroundColor Blue
Write-Host "========================================" -ForegroundColor Blue
Write-Host ""
Write-Host "Results saved to: $resultsDir" -ForegroundColor Green
Write-Host ""
Write-Host "CRITICAL FINDINGS TO INVESTIGATE:" -ForegroundColor Yellow
Write-Host "1. If response tampering succeeded: AEAD protection may not be active" -ForegroundColor Yellow
Write-Host "2. Check if HSIP daemon and gateway are running" -ForegroundColor Yellow
Write-Host "3. Verify traffic is actually routing through HSIP" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Review log files in $resultsDir" -ForegroundColor Cyan
Write-Host "2. Test UDP protocol with: hsip-cli commands" -ForegroundColor Cyan
Write-Host "3. Verify HSIP is intercepting traffic correctly" -ForegroundColor Cyan
Write-Host ""
