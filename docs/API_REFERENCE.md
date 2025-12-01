# HSIP API Reference (v0.2.0-mvp)

Complete API documentation for HSIP CLI and HTTP daemon.

---

## 1. CLI Commands

### Identity Management

#### `hsip-cli init`
Generate and save identity to keystore.

```powershell
hsip-cli init

Output: Creates ~/.hsip/identity.json with Ed25519 keypair.
hsip-cli whoami

Show your PeerID and public key.

hsip-cli whoami

Example Output:

[IDENT] PeerID: a1b2c3d4e5f6...
[IDENT] PublicKey: 0x1234567890abcdef...

hsip-cli key-export

Export identity to plaintext JSON.

hsip-cli key-export > identity-backup.json

⚠️ Warning: Keep exported keys private!
hsip-cli key-import

Import identity from JSON file.

hsip-cli key-import --file identity-backup.json

hsip-cli key-export-enc

Export identity encrypted with passphrase (Argon2id + ChaCha20-Poly1305).

hsip-cli key-export-enc > identity-encrypted.json
# Prompts for passphrase

hsip-cli key-import-enc

Import encrypted identity.

hsip-cli key-import-enc --file identity-encrypted.json
# Prompts for passphrase

Network Communication
hsip-cli hello-listen

Listen for HELLO frames on UDP.

hsip-cli hello-listen [--addr 0.0.0.0:9001]

Default Port: 9001
hsip-cli hello-send

Send a HELLO frame to UDP endpoint.

hsip-cli hello-send --to 127.0.0.1:9001

hsip-cli session-listen

Start encrypted session listener.

hsip-cli session-listen [--addr 0.0.0.0:9002]

Default Port: 9002
hsip-cli session-send

Send encrypted packets to session listener.

hsip-cli session-send --to 127.0.0.1:9002 [--packets 5]

Consent Operations
hsip-cli consent-listen

Auto-respond to consent requests.

hsip-cli consent-listen --addr 127.0.0.1:9100 --decision allow --ttl-ms 30000

Decisions: allow | deny
hsip-cli consent-send-request

Send consent request and wait for reply.

hsip-cli consent-send-request --to 127.0.0.1:9100 --purpose "test" --wait-reply

Token Operations
hsip-cli token-issue

Issue a capability token for a peer.

hsip-cli token-issue \
  --grantee <peer-id-hex> \
  --capabilities "read,write" \
  --ttl 3600

Output: JWT-EdDSA token (base64)
hsip-cli token-verify

Verify a token against issuer's public key.

hsip-cli token-verify \
  --token <base64-jwt> \
  --issuer-pubkey <hex-pubkey>

Daemon & Services
hsip-cli daemon

Start background HTTP status API.

hsip-cli daemon [--status-addr 127.0.0.1:8787]

Default Port: 8787
hsip-cli tray

Start system tray UI (Windows only).

hsip-cli tray

hsip-cli diag

Run diagnostic tests (crypto roundtrip).

hsip-cli diag

Tests:

    X25519 key exchange
    ChaCha20-Poly1305 seal/open
    Nonce generation
    Identity verification

2. HTTP API (Daemon)

Base URL: http://127.0.0.1:8787 (default)
GET /health

Check daemon health.

Request:

curl http://127.0.0.1:8787/health

Response:

{
  "status": "ok"
}

GET /stats

Get daemon statistics.

Request:

curl http://127.0.0.1:8787/stats

Response:

{
  "uptime_seconds": 42,
  "total_sessions": 5,
  "active_sessions": 2
}

GET /sessions

List active sessions.

Request:

curl http://127.0.0.1:8787/sessions

Response:

{
  "sessions": [
    {
      "peer_id": "a1b2c3...",
      "remote_addr": "192.168.1.100:12345",
      "established_ms": 1638360000000
    }
  ]
}

3. Gateway (HTTP Proxy)

The gateway runs on port 8080 and acts as an HTTP/HTTPS proxy.
Start Gateway

hsip-gateway

Default Port: 8080
Use as Proxy

# HTTP requests
curl -x http://127.0.0.1:8080 http://example.com

# HTTPS requests (CONNECT tunnel)
curl -x http://127.0.0.1:8080 https://example.com

Tracker Blocklist

Configure blocked hosts in:

%USERPROFILE%\.hsip\tracker_blocklist.txt

Format: One hostname per line

ads.example.com
tracker.badcorp.io

Requests to these hosts are blocked and logged.
4. Configuration Files
Identity File

Location: ~/.hsip/identity.json

{
  "secret_key": "hex...",
  "public_key": "hex...",
  "peer_id": "base32..."
}

Policy Config

Location: ~/.hsip/hsip.toml

[policy]
enforce_rep = true
rep_threshold = 1
require_valid_sig = true

[guard]
enable = true
pin_minutes = 20
max_control_per_min = 120
max_bad_sig_per_min = 5
max_frame = 4096

5. Exit Codes
Code	Meaning
0	Success
1	General error
2	Invalid arguments
10	Identity not found
20	Network error
30	Crypto error
6. Environment Variables
Variable	Description	Default
RUST_LOG	Log level (error, warn, info, debug, trace)	info
HSIP_CONFIG_DIR	Override config directory	~/.hsip
HSIP_CACHE_ALLOW_MS	Auto-accept window duration	300000 (5min)