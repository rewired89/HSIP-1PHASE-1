# HSIP - Hyper-Secure Internet Protocol

**Consent-based encrypted communication at the protocol level.**

HSIP is a cryptographic protocol that requires mutual authentication and explicit consent before any data exchange. Communication only happens when both parties agree - enforced by cryptography, not policy.

**Status:** Alpha - Windows 10/11

---

## How HSIP Works

### 1. Cryptographic Identity
Every peer has an Ed25519 keypair. Your public key is your identity - no registration, no central authority, no phone numbers or emails required.

### 2. Signed Handshake
Before any communication, peers exchange signed HELLO messages:
```
[HELLO] version=1, capabilities=0x1F, peer_id=ABCD..., timestamp=...
[SIGNATURE] Ed25519(HELLO_bytes)
```
Invalid signatures are rejected immediately. No connection without proof of identity.

### 3. Ephemeral Key Exchange
After HELLO verification, peers perform X25519 Diffie-Hellman using fresh ephemeral keys. This provides **perfect forward secrecy** - compromising long-term keys doesn't expose past sessions.

### 4. Encrypted Sessions
All traffic uses ChaCha20-Poly1305 authenticated encryption:
- Counter-based nonces prevent replay attacks
- Sessions automatically rekey after 100,000 packets or 1 hour
- Tampering is detected and rejected

### 5. Consent Tokens
To communicate, you need a capability token from the recipient:
```json
{
  "purpose": "file-transfer",
  "expires_ms": 3600000,
  "permissions": ["read", "write"]
}
```
Tokens are cryptographically signed, time-bounded, and permission-scoped. **No token = no connection.**

---

## What This Means For You

| Threat | How HSIP Protects |
|--------|-------------------|
| **Man-in-the-middle** | Signed handshakes verify identity. Attackers can't impersonate. |
| **Eavesdropping** | ChaCha20-Poly1305 encryption. Traffic is unreadable. |
| **Replay attacks** | Nonce management rejects duplicate packets. |
| **Session hijacking** | Ephemeral keys. Each session has unique secrets. |
| **Unauthorized contact** | Consent tokens required. No spam, no unwanted connections. |
| **Key compromise** | Perfect forward secrecy. Past sessions stay protected. |

---

## Installation

### Windows
1. Download `HSIP-Setup.exe` from Releases
2. Run installer, click Yes
3. Done - HSIP runs in background

System tray icon shows status:
- **Green** = Protected
- **Yellow** = Active (blocking/encrypting)
- **Red** = Offline

### Uninstall
Windows Settings > Apps > HSIP > Uninstall

All settings restored automatically.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      HSIP Stack                         │
├─────────────────────────────────────────────────────────┤
│  hsip-cli.exe     Daemon with HTTP API (port 8787)      │
│                   - Session management                  │
│                   - Consent token handling              │
│                   - Status reporting                    │
├─────────────────────────────────────────────────────────┤
│  hsip-gateway.exe HTTP/HTTPS proxy (port 8080)          │
│                   - Traffic interception                │
│                   - Tracker blocking                    │
│                   - Encrypted tunneling                 │
├─────────────────────────────────────────────────────────┤
│  hsip-tray.exe    System tray indicator                 │
│                   - Visual status                       │
│                   - Quick actions                       │
└─────────────────────────────────────────────────────────┘
```

---

## Protocol Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Identity | Ed25519 | Signatures, authentication |
| Key Exchange | X25519 | Ephemeral Diffie-Hellman |
| Encryption | ChaCha20-Poly1305 | AEAD, authenticated encryption |
| Key Derivation | HKDF-SHA256 | Session keys from shared secret |
| Hashing | BLAKE3 | PeerID derivation |

---

## Test the Protocol

### Start a listener:
```bash
hsip-cli session-listen --addr 127.0.0.1:9002
```

### Send encrypted packets:
```bash
hsip-cli session-send --to 127.0.0.1:9002 --packets 5
```

### Check daemon status:
```bash
curl http://127.0.0.1:8787/status
```

Response:
```json
{
  "protected": true,
  "active_sessions": 1,
  "cipher": "ChaCha20-Poly1305"
}
```

---

## Documentation

- [Protocol Specification](docs/PROTOCOL_SPEC.md) - Wire format, handshake, sessions
- [API Reference](docs/API_REFERENCE.md) - CLI commands, HTTP endpoints
- [Examples](docs/EXAMPLES.md) - Common use cases

---

## Security

HSIP uses audited cryptographic libraries:
- `ed25519-dalek` - Signatures
- `x25519-dalek` - Key exchange
- `chacha20poly1305` - AEAD encryption (RustCrypto)

The protocol is in alpha. Independent security audit planned.

**Report vulnerabilities:** nyxsystemsllc@gmail.com

---

## License

**HSIP Community License (Non-Commercial)**

**Free** for:
- Personal use
- Education and research
- Open-source projects

**Commercial use requires a license** from Nyx Systems LLC.

This includes:
- Selling software containing HSIP
- Using HSIP in business operations
- Integrating HSIP into commercial products
- Offering HSIP as part of paid services

**Contact:** nyxsystemsllc@gmail.com

See [LICENSE](LICENSE) for full terms.

---

## Contributing

Contributions welcome. See [CONTRIBUTING](docs/CONTRIBUTING.md).

---

## Contact

- **GitHub Issues:** https://github.com/rewired89/HSIP/issues
- **Email:** nyxsystemsllc@gmail.com

---

Copyright (c) Nyx Systems LLC. All rights reserved.
