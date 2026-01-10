# Getting Started with HSIP

Welcome to HSIP - a consent-based encrypted communication protocol. This guide will help you install, configure, and start using HSIP for private communication.

---

## What You'll Learn

1. How to install HSIP on Windows
2. How to verify HSIP is running
3. How to test encrypted sessions
4. How to grant and revoke consent tokens
5. How to check system status

---

## Installation

### Windows 10/11

**Step 1: Download the installer**

Visit the [Releases page](https://github.com/nyxsystems/HSIP-1PHASE-1/releases) and download the latest `HSIP-Setup.exe`.

**Step 2: Run the installer**

1. Double-click `HSIP-Setup.exe`
2. Click "Yes" when prompted for Administrator privileges
3. Follow the installation wizard
4. HSIP will start automatically

**Step 3: Verify installation**

Look for the HSIP icon in your system tray (bottom-right corner):

- 🟢 **Green** = Protected and running
- 🟡 **Yellow** = Active (blocking/encrypting)
- 🔴 **Red** = Offline or error

If you see a green icon, HSIP is working!

### Other Platforms

- **Linux**: Coming soon (NGI funding pending)
- **macOS**: Coming soon (NGI funding pending)
- **Android**: Coming soon
- **iOS**: Planned (Share Extension model for App Store compliance)

---

## Your First Encrypted Session

HSIP uses a client-server model where one peer listens and another connects.

### Terminal 1: Start a listener

Open PowerShell or Command Prompt:

```bash
cd "C:\Program Files\HSIP"
.\hsip-cli.exe session-listen --addr 127.0.0.1:9002
```

You should see:
```
[HSIP] Listening on 127.0.0.1:9002
[HSIP] Waiting for connections...
```

### Terminal 2: Send encrypted packets

In a new terminal:

```bash
cd "C:\Program Files\HSIP"
.\hsip-cli.exe session-send --to 127.0.0.1:9002 --packets 5
```

You should see:
```
[HSIP] Connecting to 127.0.0.1:9002...
[HSIP] Handshake completed
[HSIP] Sent 5 encrypted packets
[HSIP] Session closed
```

**Congratulations!** You just sent your first encrypted HSIP packets.

---

## Understanding Consent Tokens

HSIP requires **explicit consent** before communication. This is enforced through cryptographic tokens.

### Grant consent to a peer

```bash
hsip-cli consent grant \
  --grantee <peer_public_key> \
  --purpose "file-sharing" \
  --expires 3600000
```

This creates a signed token allowing the peer to connect for 1 hour (3600000 milliseconds).

### Revoke consent

```bash
hsip-cli consent revoke --grantee <peer_public_key>
```

The peer can no longer connect using that token.

### List active consents

```bash
hsip-cli consent list
```

Shows all active consent tokens you've granted.

---

## Checking System Status

HSIP runs a daemon with an HTTP API on port 8787 (localhost only).

### Using curl

```bash
curl http://127.0.0.1:8787/status
```

Response:
```json
{
  "data": {
    "protected": true,
    "active_sessions": 1,
    "egress_peer": "ABCD1234...",
    "cipher": "ChaCha20-Poly1305",
    "since": "2024-12-01T10:30:00Z"
  },
  "signature": "hmac-sha256-hex...",
  "sig_alg": "HMAC-SHA256"
}
```

### Using PowerShell

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8787/status" | Select-Object -Expand Content
```

### Fields explained

- `protected`: Whether HSIP encryption is active
- `active_sessions`: Number of current encrypted sessions
- `cipher`: Encryption algorithm in use (ChaCha20-Poly1305)
- `signature`: HMAC signature for response integrity
- `sig_alg`: Signature algorithm (HMAC-SHA256)

---

## Common Tasks

### View active sessions

```bash
curl http://127.0.0.1:8787/sessions
```

Shows all current encrypted sessions.

### Check reputation of a peer

```bash
curl http://127.0.0.1:8787/reputation/<peer_id>
```

Returns reputation score (if reputation system is enabled).

### Stop HSIP

Right-click the system tray icon and select "Exit", or:

```bash
taskkill /IM hsip-cli.exe /F
taskkill /IM hsip-tray.exe /F
```

HSIP will restart automatically on next login (unless you uninstall).

### Uninstall HSIP

1. Windows Settings → Apps
2. Find "HSIP"
3. Click Uninstall
4. All settings and proxies are automatically restored

---

## Security Best Practices

### 1. Protect your private key

Your Ed25519 private key is stored in:
```
C:\Users\<YourName>\AppData\Local\hsip\identity.key
```

**Never share this file.** Anyone with your private key can impersonate you.

### 2. Verify handshakes

HSIP automatically verifies Ed25519 signatures during handshakes. If you see connection errors, it may be an impersonation attempt.

### 3. Use time-limited tokens

Always set expiration times on consent tokens:

```bash
--expires 3600000  # 1 hour
--expires 86400000 # 24 hours
```

Never create permanent tokens unless absolutely necessary.

### 4. Monitor active sessions

Regularly check active sessions:

```bash
curl http://127.0.0.1:8787/sessions
```

Unexpected sessions may indicate unauthorized access.

### 5. Keep HSIP updated

Check for updates regularly. Security patches are released as needed.

---

## Troubleshooting

### "Cannot connect to daemon"

**Problem**: `curl http://127.0.0.1:8787/status` returns connection refused.

**Solution**:
1. Check if daemon is running: `tasklist | findstr hsip-cli`
2. Restart HSIP: Run installer or restart computer
3. Check firewall: Allow `hsip-cli.exe` on port 8787

### "Handshake failed"

**Problem**: Session connections fail with signature errors.

**Solution**:
1. Verify both peers have valid Ed25519 keypairs
2. Check system clocks are synchronized (signatures include timestamps)
3. Ensure consent token is valid and not expired

### "Tray icon is red"

**Problem**: HSIP shows red (offline) status.

**Solution**:
1. Check if daemon is running
2. View logs: `C:\Users\<YourName>\AppData\Local\hsip\logs\`
3. Restart HSIP
4. Report bugs on GitHub Issues

### Performance issues

**Problem**: Slow connections or high CPU usage.

**Solution**:
1. Check active sessions (limit to needed connections)
2. Verify no interfering firewall/antivirus
3. Update to latest version
4. Report performance issues with system specs

---

## Next Steps

### Learn More

- [WHY_HSIP.md](WHY_HSIP.md) - Understand the mission and problem space
- [docs/PROTOCOL_SPEC.md](docs/PROTOCOL_SPEC.md) - Dive into wire format and handshake
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md) - Complete CLI and API documentation
- [SECURITY.md](SECURITY.md) - Security model and threat analysis

### Build Applications

HSIP is designed as **protocol infrastructure**. You can build on top of it:

- Private messaging apps
- File sharing tools
- Decentralized social networks
- Anonymous browsing proxies
- Research prototypes

See [docs/EXAMPLES.md](docs/EXAMPLES.md) for code samples.

### Contribute

HSIP is open-source and community-driven. Contribute:

- Bug reports and fixes
- Protocol improvements
- Documentation
- Platform ports (Linux, macOS, mobile)
- Use case studies

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

---

## Getting Help

- **GitHub Issues**: https://github.com/nyxsystems/HSIP-1PHASE-1/issues
- **Email**: nyxsystemsllc@gmail.com

---

**Welcome to consent-based communication. Your privacy is mathematically guaranteed.**
