# HSIP Phase 1 Security Testing Guide

**Purpose:** Pre-sale security validation for HSIP cryptographic protocol
**Date:** 2026-01-05
**Test Environment:** mitmproxy attack simulation

---

## Architecture Overview

HSIP has three attack surfaces:
1. **UDP Protocol** - Handshakes and encrypted sessions (ports vary)
2. **HTTP Status API** - Daemon endpoint at `127.0.0.1:8787`
3. **HTTP/HTTPS Proxy** - Gateway at `127.0.0.1:8080`

---

## Prerequisites

```bash
# Install mitmproxy if not already installed
pip install mitmproxy

# Verify installation
mitmproxy --version
```

---

## Test Category 1: HTTP/HTTPS Proxy Attacks (Port 8080)

### 1.1 Man-in-the-Middle Attack (Basic)
```bash
# Start mitmproxy in transparent mode
mitmproxy --mode transparent --showhost

# Expected: HSIP should detect MITM via signature verification
# Success criteria: Connections fail with signature errors
```

### 1.2 SSL Stripping Attack
```bash
# Try to downgrade HTTPS to HTTP
mitmproxy --mode transparent --ssl-insecure

# Expected: HSIP enforces encryption at protocol level
# Success criteria: Downgrade attempts blocked
```

### 1.3 Certificate Manipulation
```bash
# Use custom certificate authority
mitmproxy --mode transparent --set confdir=~/.mitmproxy

# Expected: HSIP uses Ed25519 signatures, not X.509 certs
# Success criteria: Certificate validation bypassed by signature auth
```

### 1.4 Request Replay Attack
```bash
# Capture and replay requests
mitmdump -w captured_traffic.flow
mitmdump -r captured_traffic.flow

# Expected: Nonce counter prevents replays
# Success criteria: Replayed packets rejected
```

### 1.5 Header Injection Attack
```python
# Save as: header_injection.py
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    flow.request.headers["X-Injected"] = "malicious"
    flow.request.headers["Content-Length"] = "999999"

# Run: mitmproxy -s header_injection.py
# Expected: AAD protection detects tampering
# Success criteria: Modified requests rejected
```

### 1.6 Response Tampering
```python
# Save as: response_tamper.py
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if flow.response:
        flow.response.content = b"TAMPERED_DATA"

# Run: mitmproxy -s response_tamper.py
# Expected: ChaCha20-Poly1305 AEAD detects tampering
# Success criteria: Tampered responses rejected with auth tag failure
```

---

## Test Category 2: HTTP Status API Attacks (Port 8787)

### 2.1 Status Endpoint Fuzzing
```bash
# Fuzz the status endpoint
curl http://127.0.0.1:8787/status -X POST -d "malformed{{{data"
curl http://127.0.0.1:8787/status -X GET -H "Content-Length: -1"
curl http://127.0.0.1:8787/../../../etc/passwd

# Expected: Proper error handling, no crashes
# Success criteria: Returns 4xx errors, no information disclosure
```

### 2.2 HTTP Method Tampering
```bash
# Try unexpected HTTP methods
curl -X DELETE http://127.0.0.1:8787/status
curl -X PUT http://127.0.0.1:8787/status -d '{"protected":false}'
curl -X TRACE http://127.0.0.1:8787/status
curl -X OPTIONS http://127.0.0.1:8787/status

# Expected: Only allowed methods accepted
# Success criteria: 405 Method Not Allowed for unauthorized methods
```

### 2.3 Rate Limiting Test
```bash
# Flood the API endpoint
for i in {1..1000}; do curl http://127.0.0.1:8787/status & done

# Expected: Rate limiting or connection throttling
# Success criteria: No DoS, graceful degradation
```

### 2.4 Large Payload Attack
```bash
# Send oversized request
dd if=/dev/zero bs=1M count=100 | curl -X POST http://127.0.0.1:8787/status --data-binary @-

# Expected: Request size limits enforced
# Success criteria: 413 Payload Too Large or connection closed
```

---

## Test Category 3: UDP Protocol Attacks (HSIP Core)

### 3.1 HELLO Message Tampering
```python
# Save as: udp_tamper.py
# This is conceptual - use scapy for actual implementation

from scapy.all import *

def tamper_hello():
    # Capture HELLO packet
    pkt = sniff(filter="udp", count=1)[0]

    # Tamper with signature bytes
    payload = bytes(pkt[UDP].payload)
    tampered = payload[:-64] + b'\x00' * 64  # Zero out signature

    # Replay tampered packet
    send(IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport)/Raw(load=tampered))

# Expected: Ed25519 signature verification fails
# Success criteria: Tampered HELLO rejected immediately
```

### 3.2 Timestamp Manipulation Attack
```python
# Test timestamp skew tolerance
# HELLO timestamp validation at hello.rs:198-201

# Test 1: Past timestamp (> max_skew_ms)
# Test 2: Future timestamp (> max_skew_ms)
# Test 3: Replay old signed HELLO

# Expected: Timestamps outside 60s window rejected
# Success criteria: HelloError::BadTimestamp
```

### 3.3 Protocol Version Downgrade
```python
# Try to downgrade protocol version
# Modify protocol_version field to 0 or 255

# Expected: Version check at hello.rs:193-195
# Success criteria: HelloError::UnsupportedVersion
```

### 3.4 Nonce Exhaustion Attack
```bash
# Try to exhaust nonce counter space
# Send MAX_PACKETS_BEFORE_REKEY + 1 packets

# Expected: Session rekey triggered at session.rs:185-186
# Success criteria: SessionError::RekeyRequired after 100,000 packets
```

### 3.5 Session Hijacking Attempt
```python
# Try to hijack active session
# 1. Capture ephemeral key exchange
# 2. Attempt to derive session key
# 3. Try to decrypt session traffic

# Expected: X25519 provides perfect forward secrecy
# Success criteria: Cannot derive session key from captured handshake
```

---

## Test Category 4: Cryptographic Attacks

### 4.1 Signature Forgery Attempt
```python
# Try to forge Ed25519 signature without private key
# Target: HELLO signature at hello.rs:175-178

# Expected: Ed25519 is computationally infeasible to forge
# Success criteria: All forged signatures rejected
```

### 4.2 Key Confusion Attack
```python
# Try to use one peer's key to impersonate another
# Mix peer_id and signing_key from different identities

# Expected: PeerId derived from public key (hello.rs:13-15)
# Success criteria: Mismatch detected, connection rejected
```

### 4.3 Nonce Reuse Attack
```python
# Try to reuse same nonce with same key
# Send duplicate counter value

# Expected: Nonce counter monotonicity at session.rs:99-104
# Success criteria: SessionError::NonceMismatch
```

### 4.4 AEAD Tag Stripping
```python
# Try to remove or modify Poly1305 authentication tag

# Expected: ChaCha20-Poly1305 AEAD at session.rs:110-112
# Success criteria: Decrypt fails, SessionError::Crypto
```

---

## Test Category 5: Consent Token Attacks

### 5.1 Token Signature Forgery
```bash
# Try to forge consent token signature
# Target: consent.rs signature validation

# Expected: Ed25519 signature verification
# Success criteria: Forged tokens rejected
```

### 5.2 Token Replay Attack
```bash
# Capture valid token and replay after expiration

# Expected: expires_ms timestamp check
# Success criteria: Expired tokens rejected
```

### 5.3 Token Permission Escalation
```python
# Modify token permissions after signing
# Change "read" to "read,write,admin"

# Expected: Signature covers full token
# Success criteria: Modified tokens fail signature check
```

---

## Test Category 6: Unknown/Edge Case Attacks

### 6.1 Malformed Protocol Messages
```python
# Send completely invalid protocol data
messages = [
    b"",                           # Empty
    b"\x00" * 1500,               # All zeros
    b"\xff" * 1500,               # All ones
    b"RANDOM" + os.urandom(1000), # Random data
    b"A" * 65536,                 # Oversized
]

# Expected: Graceful rejection, no crashes
# Success criteria: No panics, proper error handling
```

### 6.2 Resource Exhaustion
```python
# Try to exhaust resources
# 1. Open maximum connections
# 2. Fill session table
# 3. Exhaust nonce space
# 4. Trigger rekey loops

# Expected: Resource limits enforced
# Success criteria: Graceful degradation, no crashes
```

### 6.3 Race Conditions
```python
# Concurrent operations
# 1. Simultaneous handshakes
# 2. Parallel session creation
# 3. Concurrent rekey operations

# Expected: Proper synchronization
# Success criteria: No race conditions, data corruption, or deadlocks
```

### 6.4 Side-Channel Timing Analysis
```python
# Measure signature verification timing
# Try to detect timing differences between:
# - Valid vs invalid signatures
# - Different error paths

# Expected: Constant-time operations in crypto libraries
# Success criteria: No exploitable timing differences
```

### 6.5 Memory Safety Attacks
```bash
# Test for memory safety issues
# 1. Buffer overflows in packet parsing
# 2. Use-after-free in session management
# 3. Double-free in cleanup paths

# Expected: Rust memory safety guarantees
# Success criteria: No memory corruption (run with: RUSTFLAGS="-Z sanitizer=address")
```

---

## Automated Testing Script

```bash
#!/bin/bash
# Save as: run_security_tests.sh

echo "=== HSIP Phase 1 Security Testing ==="
echo "Starting comprehensive attack simulation..."

# Ensure HSIP is running
if ! curl -s http://127.0.0.1:8787/status > /dev/null; then
    echo "ERROR: HSIP daemon not running on port 8787"
    exit 1
fi

echo ""
echo "[1/6] Testing HTTP Proxy Attacks..."
mitmproxy --mode transparent --showhost -p 8081 &
MITM_PID=$!
sleep 2

# Configure system to route through mitmproxy
# This is OS-specific - example for Linux with iptables
sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8081
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8081

# Test HTTP traffic
curl -x http://127.0.0.1:8081 http://example.com
curl -x http://127.0.0.1:8081 https://example.com

# Cleanup
sudo iptables -t nat -F
kill $MITM_PID

echo ""
echo "[2/6] Testing Status API..."
curl http://127.0.0.1:8787/status
curl -X POST http://127.0.0.1:8787/status -d "malformed"
curl http://127.0.0.1:8787/../etc/passwd

echo ""
echo "[3/6] Testing Rate Limiting..."
for i in {1..100}; do
    curl -s http://127.0.0.1:8787/status > /dev/null &
done
wait

echo ""
echo "[4/6] Testing Large Payloads..."
dd if=/dev/zero bs=1M count=10 | curl -X POST http://127.0.0.1:8787/status --data-binary @- 2>&1

echo ""
echo "[5/6] Testing UDP Protocol..."
# Requires hsip-cli commands
hsip-cli handshake-connect --addr 127.0.0.1:9000 &
sleep 1
hsip-cli handshake-listen --addr 127.0.0.1:9000

echo ""
echo "[6/6] Testing Session Encryption..."
hsip-cli session-listen --addr 127.0.0.1:9002 &
sleep 1
hsip-cli session-send --to 127.0.0.1:9002 --packets 5

echo ""
echo "=== Testing Complete ==="
echo "Review output above for any failures or vulnerabilities"
```

---

## Success Criteria Summary

| Attack Category | Expected Defense | Pass Criteria |
|----------------|------------------|---------------|
| **MITM** | Ed25519 signatures | Impersonation impossible |
| **SSL Stripping** | Protocol-level encryption | Downgrade blocked |
| **Replay** | Nonce counters | Duplicate packets rejected |
| **Tampering** | AEAD auth tags | Modified data detected |
| **Signature Forgery** | Ed25519 security | All forgeries fail |
| **Session Hijack** | Perfect forward secrecy | Cannot derive session keys |
| **Nonce Reuse** | Monotonic counters | Reuse detected |
| **DoS** | Rate limiting | Graceful degradation |
| **Fuzzing** | Input validation | No crashes |
| **Memory Safety** | Rust guarantees | No corruption |

---

## Known Limitations (Alpha Phase)

1. **No formal security audit** - Independent audit planned
2. **Timestamp validation** - Currently 60s window (configurable)
3. **Rate limiting** - May need tuning for production
4. **DoS protection** - Basic implementation, may need hardening

---

## Reporting Vulnerabilities

If you discover a security issue during testing:

1. **Do NOT disclose publicly**
2. Email: nyxsystemsllc@gmail.com
3. Include: Attack vector, reproduction steps, severity
4. Allow 90 days for fix before disclosure

---

## References

- Protocol Spec: `docs/PROTOCOL_SPEC.md`
- Crypto Implementation: `crates/hsip-core/src/`
- Test Vectors: `crates/hsip-core/tests/`
