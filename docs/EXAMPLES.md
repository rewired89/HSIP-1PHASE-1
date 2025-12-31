# HSIP Examples

Practical step-by-step examples for using HSIP.

---

## Example 1: Basic Setup

### 1.1 Create Identity

```powershell
# Generate new identity
hsip-cli init

# View your identity
hsip-cli whoami

Output:

[INIT] Generated new identity.
[INIT] Saved to: C:\Users\you\.hsip\identity.json

[IDENT] PeerID: a1b2c3d4e5f6...
[IDENT] PublicKey: 0x1234567890abcdef...

Example 2: Network Communication Test
2.1 HELLO Handshake

Terminal 1 - Listener:

hsip-cli hello-listen

Terminal 2 - Sender:

hsip-cli hello-send --to 127.0.0.1:9001

Expected Output (Terminal 1):

[hello-listen] Listening on 0.0.0.0:9001
[hello-listen] Received HELLO from 127.0.0.1:xxxxx
[hello-listen] PeerID: a1b2c3...
[hello-listen] Signature valid: ✓

2.2 Encrypted Session

Terminal 1 - Listener:

hsip-cli session-listen

Terminal 2 - Sender:

hsip-cli session-send --to 127.0.0.1:9002 --packets 5

Expected Output:

[session-send] Connecting to 127.0.0.1:9002
[session-send] X25519 handshake complete
[session-send] Sent 5 encrypted packets

Example 3: Consent Flow
3.1 Auto-Approve Consent Listener

hsip-cli consent-listen \
  --addr 127.0.0.1:9100 \
  --decision allow \
  --ttl-ms 30000

3.2 Send Consent Request

hsip-cli consent-send-request \
  --to 127.0.0.1:9100 \
  --purpose "test connection" \
  --wait-reply

Output:

[consent] Request sent
[consent] Response: ALLOW (ttl: 30000ms)

Example 4: Token Operations
4.1 Issue Token

hsip-cli token-issue \
  --grantee a1b2c3d4e5f6... \
  --capabilities "read,write" \
  --ttl 3600

Output:

{
  "token": "eyJhbGciOiJFZERTQSI...",
  "expires_at": 1638363600,
  "issuer": "your-peer-id"
}

4.2 Verify Token

hsip-cli token-verify \
  --token eyJhbGciOiJFZERTQSI... \
  --issuer-pubkey 0x1234567890abcdef...

Output:

✓ Token valid
  Grantee: a1b2c3...
  Capabilities: read,write
  Expires: 2024-12-01T12:00:00Z

Example 5: Daemon & Monitoring
5.1 Start Daemon

hsip-cli daemon

5.2 Check Status

curl http://127.0.0.1:8787/status

Response:

{
  "protected": true,
  "active_sessions": 1,
  "cipher": "ChaCha20-Poly1305"
}

5.3 List Sessions

curl http://127.0.0.1:8787/sessions

Response:

[
  {
    "peer": "NYTFBVDZFNSMDASRNINFBTWZJ4",
    "age_secs": 120,
    "cipher": "ChaCha20-Poly1305"
  }
]

Example 6: Gateway Proxy
6.1 Start Gateway

hsip-gateway

6.2 Use as HTTP Proxy

# Set proxy for this session
$env:HTTP_PROXY="http://127.0.0.1:8080"
$env:HTTPS_PROXY="http://127.0.0.1:8080"

# Test
curl http://example.com

6.3 Add Blocklist

Edit: %USERPROFILE%\.hsip\tracker_blocklist.txt

ads.example.com
tracker.malicious.net

Test blocking:

curl -x http://127.0.0.1:8080 http://ads.example.com
# Should be blocked

Example 7: Key Management
7.1 Export (Plaintext)

hsip-cli key-export > backup.json

7.2 Export (Encrypted)

hsip-cli key-export-enc > backup-encrypted.json
# Enter passphrase when prompted

7.3 Import

hsip-cli key-import --file backup.json

Example 8: System Tray (Windows)
8.1 Start Tray

hsip-tray

What it does:

    Shows colored square icon in system tray
    Green = Protected, Yellow = Blocking detected, Red = Offline
    Right-click to exit

Example 9: Diagnostics
9.1 Run Full Diagnostic

hsip-cli diag

Output:

=== HSIP Diagnostic Report ===

[Identity]
PeerID: a1b2c3...
PublicKey: 0x1234...

[Crypto Test]
✓ X25519 key exchange successful
✓ ChaCha20-Poly1305 seal/open roundtrip OK
✓ Nonce generation working (counter: 1, 2)

[Environment]
Platform: Windows
Config dir: C:\Users\you\.hsip

Troubleshooting Examples
Port Already in Use

# Find what's using port 8787
netstat -ano | findstr :8787

# Kill the process
taskkill /F /PID <PID>

Firewall Blocking UDP

# Allow HSIP through Windows Firewall
netsh advfirewall firewall add rule name="HSIP UDP" dir=in action=allow protocol=UDP localport=9001-9002

Verbose Logging

# Enable debug logs
$env:RUST_LOG="debug"
hsip-cli daemon

For more details, see:
    Protocol Specification
    API Reference
    Security Model
