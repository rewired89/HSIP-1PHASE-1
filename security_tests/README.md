# HSIP Phase 1 Security Testing - Quick Start

## Quick Commands

### Run All Tests Automatically
```bash
cd /home/user/HSIP-1PHASE-1/security_tests
./run_all_tests.sh
```

### Individual mitmproxy Attack Simulations

#### 1. Header Injection Attack
```bash
# Terminal 1: Start mitmproxy with attack script
mitmdump -s header_injection.py -p 8081 --ssl-insecure

# Terminal 2: Send traffic through the proxy
curl -x http://127.0.0.1:8081 http://example.com
```

#### 2. Response Tampering Attack
```bash
# Terminal 1: Start mitmproxy
mitmdump -s response_tamper.py -p 8082 --ssl-insecure

# Terminal 2: Send request
curl -x http://127.0.0.1:8082 http://example.com
```

#### 3. SSL Stripping Attack
```bash
# Terminal 1: Start mitmproxy
mitmdump -s ssl_strip.py -p 8083 --ssl-insecure

# Terminal 2: Send HTTPS request
curl -x http://127.0.0.1:8083 https://example.com
```

#### 4. Replay Attack
```bash
# Terminal 1: Capture traffic
mitmdump -s replay_attack.py -p 8084 -w captured.flow

# Terminal 2: Send some requests
curl -x http://127.0.0.1:8084 http://example.com

# Terminal 3: Replay captured traffic
mitmdump -r captured.flow
```

## Manual Attack Commands

### HTTP Status API Attacks (Port 8787)

```bash
# Basic fuzzing
curl http://127.0.0.1:8787/status
curl -X POST http://127.0.0.1:8787/status -d "malformed{{{data"
curl -X DELETE http://127.0.0.1:8787/status
curl http://127.0.0.1:8787/../../../etc/passwd

# Path traversal
curl "http://127.0.0.1:8787/status/../../etc/passwd"
curl "http://127.0.0.1:8787/status%00.txt"

# Header injection
curl -H "X-Injected: malicious" http://127.0.0.1:8787/status
curl -H "Content-Length: -1" http://127.0.0.1:8787/status
curl -H "Host: evil.com" http://127.0.0.1:8787/status

# HTTP method fuzzing
for method in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE CONNECT; do
    echo "Testing $method..."
    curl -X $method http://127.0.0.1:8787/status
done

# Rate limiting test
for i in {1..1000}; do curl -s http://127.0.0.1:8787/status & done; wait

# Large payload
dd if=/dev/zero bs=1M count=100 | curl -X POST http://127.0.0.1:8787/status --data-binary @-

# Slowloris attack simulation
curl --max-time 300 --limit-rate 1 http://127.0.0.1:8787/status &
```

### HTTP Proxy Attacks (Port 8080)

```bash
# Configure system to use HSIP proxy
export http_proxy="http://127.0.0.1:8080"
export https_proxy="http://127.0.0.1:8080"

# Test normal request
curl http://example.com

# Test with mitmproxy in the middle
mitmproxy --mode transparent -p 8090

# Test HTTPS
curl https://example.com
```

### UDP Protocol Attacks (HSIP Core)

```bash
# Start HSIP listener
hsip-cli session-listen --addr 127.0.0.1:9002 &

# Normal session
hsip-cli session-send --to 127.0.0.1:9002 --packets 5

# Stress test - try to exhaust nonce space
hsip-cli session-send --to 127.0.0.1:9002 --packets 100000

# Test handshake
hsip-cli handshake-listen --addr 127.0.0.1:9000 &
hsip-cli handshake-connect --addr 127.0.0.1:9000
```

## Advanced Attack Scenarios

### Scenario 1: Full MITM with Certificate
```bash
# Generate mitmproxy certificate
mitmproxy --set confdir=~/.mitmproxy

# Install cert and intercept HTTPS
mitmproxy --mode transparent --showhost

# Expected: HSIP should ignore cert and use Ed25519 signatures
```

### Scenario 2: Replay Attack with Time Delay
```bash
# Capture traffic
mitmdump -w capture.flow -p 8081

# Wait 2 minutes (beyond timestamp window)
sleep 120

# Replay
mitmdump -r capture.flow

# Expected: HSIP should reject due to timestamp skew
```

### Scenario 3: Session Hijacking
```bash
# Capture active session traffic
tcpdump -i any -w session.pcap udp

# Try to extract session key (should fail - PFS)
# Try to inject packets into session (should fail - nonce mismatch)
```

### Scenario 4: Concurrent Attack Simulation
```bash
#!/bin/bash
# Launch multiple attacks simultaneously

# Attack 1: Rate limiting
(for i in {1..500}; do curl -s http://127.0.0.1:8787/status; done) &

# Attack 2: Large payloads
(dd if=/dev/zero bs=1M count=50 | curl -X POST http://127.0.0.1:8787/status --data-binary @-) &

# Attack 3: Malformed requests
(for i in {1..100}; do curl -X DELETE http://127.0.0.1:8787/status; done) &

# Attack 4: MITM proxy
mitmdump -p 8081 --ssl-insecure &

wait
```

## Expected Results

| Attack | Expected HSIP Behavior | Pass Criteria |
|--------|------------------------|---------------|
| Header Injection | AAD detects tampering | 4xx error or rejection |
| Response Tamper | AEAD auth fails | Decrypt error |
| SSL Strip | Protocol enforces encryption | Connection fails |
| Replay | Nonce counter mismatch | Duplicate rejected |
| MITM | Signature verification fails | Cannot impersonate |
| Session Hijack | Cannot derive session key | PFS protects |
| Large Payload | Size limit enforced | 413 or connection close |
| Rate Limit | Throttling active | Graceful degradation |
| Malformed Data | Input validation | No crash, clean error |

## Analyzing Results

### Check for Vulnerabilities

1. **Server Crashes**: Any segfault or panic is critical
```bash
dmesg | tail -50
journalctl -xe | grep hsip
```

2. **Memory Leaks**: Monitor during stress tests
```bash
ps aux | grep hsip
watch -n 1 'ps -o pid,rss,vsz,cmd | grep hsip'
```

3. **Timing Attacks**: Look for timing differences
```bash
# Time signature verification
for i in {1..100}; do
    time curl -s http://127.0.0.1:8787/status > /dev/null
done | grep real
```

4. **Network Inspection**: Verify encryption
```bash
# Capture traffic
tcpdump -i any -w hsip_traffic.pcap port 8080 or port 8787

# Check if any plaintext leaked
strings hsip_traffic.pcap | grep -i password
```

## Checklist Before Production

- [ ] All mitmproxy attack scripts: PASSED
- [ ] API fuzzing: No crashes
- [ ] Rate limiting: Active and effective
- [ ] Large payloads: Rejected gracefully
- [ ] Replay attacks: Detected and blocked
- [ ] Session hijacking: Impossible (PFS verified)
- [ ] Signature forgery: All attempts failed
- [ ] Nonce reuse: Detected and rejected
- [ ] Memory safety: No leaks or corruption
- [ ] Timing attacks: No exploitable differences
- [ ] DoS resistance: Graceful degradation
- [ ] Error messages: No information disclosure

## Getting Help

If tests fail or you find vulnerabilities:

1. **Save test results**: All output is in `security_tests/results/`
2. **Document the issue**: Attack vector, repro steps, severity
3. **Contact**: nyxsystemsllc@gmail.com
4. **Do NOT disclose publicly** until patched

## References

- Main documentation: `../SECURITY_TESTING.md`
- Protocol spec: `../docs/PROTOCOL_SPEC.md`
- Code: `../crates/hsip-core/src/`
