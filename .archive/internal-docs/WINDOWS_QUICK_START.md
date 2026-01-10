# HSIP Security Testing - Windows PowerShell Guide

## Quick Start

```powershell
cd C:\Users\melas\HSIP-1PHASE-1\security_tests
.\windows_tests.ps1
```

---

## Individual Tests (PowerShell Syntax)

### 1. API Fuzzing

```powershell
# Normal request
Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -UseBasicParsing

# DELETE method (should fail)
Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -Method DELETE -UseBasicParsing

# Path traversal
Invoke-WebRequest -Uri "http://127.0.0.1:8787/../../../etc/passwd" -UseBasicParsing

# Malformed data
Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -Method POST -Body "malformed{{{data" -UseBasicParsing
```

### 2. Rate Limiting Test

```powershell
# Send 100 concurrent requests
1..100 | ForEach-Object -Parallel {
    Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -UseBasicParsing | Out-Null
}

# Check if server still responsive
Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -UseBasicParsing
```

### 3. Large Payload Test

```powershell
# Create 10MB random data
$largeData = [byte[]]::new(10MB)
(New-Object Random).NextBytes($largeData)

# Send it
Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -Method POST -Body $largeData -UseBasicParsing
```

### 4. mitmproxy Attacks (use curl.exe, not Invoke-WebRequest)

**Header Injection:**
```powershell
# Terminal 1
Start-Job { mitmdump -s security_tests\header_injection.py -p 8091 --ssl-insecure }

# Terminal 2
curl.exe -x http://127.0.0.1:8091 http://example.com
```

**Response Tampering:**
```powershell
# Terminal 1
Start-Job { mitmdump -s security_tests\response_tamper.py -p 8092 --ssl-insecure }

# Terminal 2
curl.exe -x http://127.0.0.1:8092 http://example.com
```

**SSL Stripping:**
```powershell
# Terminal 1
Start-Job { mitmdump -s security_tests\ssl_strip.py -p 8093 --ssl-insecure }

# Terminal 2
curl.exe -x http://127.0.0.1:8093 https://example.com -k
```

**Replay Attack:**
```powershell
# Capture traffic
Start-Job { mitmdump -s security_tests\replay_attack.py -w capture.flow -p 8094 }

# Send requests
curl.exe -x http://127.0.0.1:8094 http://example.com

# Replay (use different port to avoid conflict)
mitmdump -r capture.flow --mode regular@8095
```

---

## Interpreting Your Results

### ✅ PASS: SSL Stripping Test
```
curl: (60) schannel: SEC_E_UNTRUSTED_ROOT
```
**This is GOOD!** The certificate was rejected. HSIP should use Ed25519 signatures, not trust certificates.

### ⚠️ CRITICAL: Response Tampering
```
TAMPERED_DATA_BY_ATTACKER
```
**This is BAD!** The tampered response was accepted. This means:

1. **Either:** HSIP's AEAD protection is NOT active on the HTTP layer
2. **Or:** The traffic is bypassing HSIP entirely
3. **Or:** HSIP gateway is not running

**To diagnose:**
```powershell
# Check if HSIP services are running
Get-Process | Where-Object { $_.Name -like "*hsip*" }

# Check what's listening on port 8080
Get-NetTCPConnection -LocalPort 8080

# Check what's listening on port 8787
Get-NetTCPConnection -LocalPort 8787

# Test if HSIP is responding
Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -UseBasicParsing
```

### 📊 Port Conflict Error
```
[Errno 10048] ... only one usage of each socket address
```
**This is expected.** Port 8080 is already in use by hsip-gateway. Use a different port:
```powershell
mitmdump -r capture.flow --mode regular@8095
```

---

## Key Differences: Bash vs PowerShell

| Bash | PowerShell |
|------|------------|
| `for i in {1..100}; do ... done` | `1..100 \| ForEach-Object { ... }` |
| `dd if=/dev/zero bs=1M count=10` | `[byte[]]::new(10MB)` |
| `curl` | `curl.exe` (for proxy support) |
| `&` (background) | `Start-Job { ... }` |
| `@-` (stdin) | `-Body $variable` |

---

## Critical Security Checks

### 1. Verify HSIP is Running

```powershell
# Check daemon
try {
    $status = Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" -UseBasicParsing
    Write-Host "HSIP Daemon: RUNNING" -ForegroundColor Green
    $status.Content
} catch {
    Write-Host "HSIP Daemon: NOT RUNNING" -ForegroundColor Red
}

# Check gateway
try {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:8080" -UseBasicParsing
    Write-Host "HSIP Gateway: RUNNING" -ForegroundColor Green
} catch {
    Write-Host "HSIP Gateway: NOT RUNNING" -ForegroundColor Red
}
```

### 2. Test HSIP's AEAD Protection

The response tampering test is CRITICAL. If you see `TAMPERED_DATA_BY_ATTACKER`, it means:

**Expected behavior:**
- HSIP should detect tampering via ChaCha20-Poly1305 AEAD
- Tampered responses should cause decryption failure
- Connection should fail or return an error

**If tampering succeeds:**
- HSIP may not be active on this connection
- The HTTP proxy may not have AEAD protection
- This is a **security vulnerability**

### 3. Test with Real HSIP Traffic

```powershell
# Start HSIP listener
Start-Job { hsip-cli session-listen --addr 127.0.0.1:9002 }

# Send encrypted session
hsip-cli session-send --to 127.0.0.1:9002 --packets 5

# Check results
Get-Job | Receive-Job
```

---

## Common Issues

### Issue 1: "curl is an alias"
**Solution:** Use `curl.exe` instead of `curl` to get the real curl binary.

### Issue 2: PowerShell blocks scripts
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Issue 3: mitmproxy not found
```powershell
pip install mitmproxy
# Or use conda:
conda install -c conda-forge mitmproxy
```

### Issue 4: Port already in use
Change the port number:
```powershell
mitmdump -s script.py -p 8095  # Use different port
```

---

## Expected Results Summary

| Test | Expected Result | What It Means |
|------|----------------|---------------|
| **DELETE /status** | 405 Method Not Allowed | API properly restricts methods ✅ |
| **Path traversal** | 404 Not Found | Input validation works ✅ |
| **Rate limiting** | Server stays responsive | DoS protection active ✅ |
| **Large payload** | 413 Payload Too Large | Size limits enforced ✅ |
| **Header injection** | Request rejected | AAD protection active ✅ |
| **Response tamper** | Connection error | **AEAD must block this!** ⚠️ |
| **SSL strip** | Certificate error | Cert validation (expected) ✅ |
| **Replay attack** | Nonce mismatch | Replay protection active ✅ |

---

## What To Do If Response Tampering Succeeds

If you see `TAMPERED_DATA_BY_ATTACKER`:

1. **Verify HSIP is actually running:**
   ```powershell
   Get-Process | Where-Object { $_.Name -like "*hsip*" }
   ```

2. **Check if traffic routes through HSIP:**
   ```powershell
   # See what's on port 8080
   Get-NetTCPConnection -LocalPort 8080 | Format-Table
   ```

3. **Test HSIP's crypto directly:**
   ```powershell
   # This bypasses HTTP and tests HSIP protocol
   hsip-cli session-send --to 127.0.0.1:9002 --packets 5
   ```

4. **Review the architecture:**
   - The HTTP proxy (port 8080) may not have AEAD protection
   - AEAD protection is in the UDP session layer
   - You may need to test the UDP protocol directly, not HTTP proxy

5. **This could be a design issue:**
   - HTTP proxy layer may be just forwarding traffic
   - Real crypto protection is in HSIP UDP sessions
   - Need to confirm if HTTP proxy is supposed to have AEAD

---

## Next Steps

1. Run the automated script: `.\windows_tests.ps1`
2. Investigate any response tampering success
3. Test UDP protocol directly with `hsip-cli`
4. Verify which layer has cryptographic protection
5. Document findings

---

## Report Security Issues

If you find vulnerabilities:

📧 **Email:** nyxsystemsllc@gmail.com

Include:
- Attack vector description
- Reproduction steps (PowerShell commands)
- Expected vs actual behavior
- Screenshots/logs

**Do NOT disclose publicly before vendor has time to fix!**
