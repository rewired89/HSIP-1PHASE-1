# HSIP - Consent-Based Encrypted Communication Protocol

**A cryptographic protocol for privacy-preserving internet communication where consent is enforced by mathematics, not policy.**

HSIP (Hyper-Secure Internet Protocol) enables peer-to-peer encrypted communication that requires **mutual cryptographic consent** before any data exchange. Communication only happens when both parties explicitly agree - enforced at the protocol level through capability tokens and signed handshakes.

**Status:** Alpha Release (Windows 10/11)
**License:** Free for non-commercial use
**Mission:** Restore user autonomy and privacy to internet communications

---

## Why HSIP Exists

The internet was designed for open communication between machines, not privacy-conscious exchanges between people. Modern protocols prioritize connectivity over consent, leading to:

- **Unwanted contact:** Spam, harassment, and unsolicited connections
- **Surveillance capitalism:** Every connection tracked, analyzed, and monetized
- **Centralized control:** Gatekeepers deciding who can communicate with whom
- **Privacy violations:** Eavesdropping and metadata harvesting as business models

HSIP reimagines internet communication from first principles:

### What if...
- You could **only** be contacted by people you've explicitly authorized?
- Every connection was **encrypted by default** with military-grade cryptography?
- Your identity required **no registration, no phone number, no email**?
- Communication systems **couldn't spy on you** even if they wanted to?

**That's HSIP.**

---

## How It Works

### 1. **Cryptographic Identity (No Registration)**
Every user generates an Ed25519 keypair. Your public key is your identity. No central authority, no personal information required.

```
Your Identity = Ed25519 Public Key
No emails • No phone numbers • No passwords
```

### 2. **Consent Tokens (Permission Required)**
To communicate with you, someone needs a **capability token** that you've signed:

```json
{
  "grantee": "peer_public_key",
  "purpose": "messaging",
  "expires": "2024-12-31T23:59:59Z",
  "permissions": ["send", "receive"]
}
```

No token = no connection. **Cryptographically enforced.**

### 3. **Signed Handshakes (Proof of Identity)**
Every connection starts with mutual signature verification:

```
Alice → Bob: [HELLO + Ed25519 Signature]
Bob → Alice: [HELLO + Ed25519 Signature]
✓ Signatures verified → Connection established
✗ Invalid signature → Connection rejected
```

Impersonation is mathematically impossible.

### 4. **Encrypted Sessions (Perfect Forward Secrecy)**
All traffic uses ChaCha20-Poly1305 authenticated encryption with ephemeral keys:

- **Nonce management** prevents replay attacks
- **Automatic rekeying** every 100,000 packets or 1 hour
- **Tampering detected** and rejected immediately

Even if long-term keys are compromised, past sessions stay protected.

---

## What HSIP Protects Against

| Attack | HSIP Defense |
|--------|--------------|
| **Man-in-the-middle** | Signed handshakes verify identity. Attackers cannot impersonate. |
| **Eavesdropping** | ChaCha20-Poly1305 AEAD encryption. Traffic is unreadable. |
| **Replay attacks** | Nonce counters reject duplicate packets. |
| **Session hijacking** | Ephemeral keys provide unique session secrets. |
| **Unwanted contact** | Consent tokens required. No spam, no unsolicited connections. |
| **Key compromise** | Perfect forward secrecy protects past communications. |
| **Metadata harvesting** | Peer-to-peer design minimizes metadata exposure. |

---

## Getting Started

### Installation (Windows)

1. Download `HSIP-Setup.exe` from [Releases](https://github.com/nyxsystems/HSIP-1PHASE-1/releases)
2. Run installer (requires Administrator)
3. HSIP runs automatically in background

**System tray icon** shows status:
- 🟢 **Green** = Protected and active
- 🟡 **Yellow** = Blocking threats
- 🔴 **Red** = Offline or error

### Test the Protocol

Start a listening session:
```bash
hsip-cli session-listen --addr 127.0.0.1:9002
```

Send encrypted packets:
```bash
hsip-cli session-send --to 127.0.0.1:9002 --packets 5
```

Check daemon status:
```bash
curl http://127.0.0.1:8787/status
```

See [GETTING_STARTED.md](GETTING_STARTED.md) for detailed usage.

---

## Architecture

HSIP is built from **audited cryptographic primitives**:

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Identity** | Ed25519 | Signatures and authentication |
| **Key Exchange** | X25519 | Ephemeral Diffie-Hellman |
| **Encryption** | ChaCha20-Poly1305 | Authenticated encryption (AEAD) |
| **Key Derivation** | HKDF-SHA256 | Derive session keys from shared secrets |
| **Hashing** | BLAKE3 | Peer ID derivation |
| **Integrity** | HMAC-SHA256 | API response protection |

All cryptography is provided by **RustCrypto**, a well-audited open-source library.

### System Components

```
┌─────────────────────────────────────────────────────────┐
│  hsip-cli         Daemon managing sessions & consent    │
│  hsip-gateway     Encrypted tunneling proxy             │
│  hsip-tray        Status indicator                      │
└─────────────────────────────────────────────────────────┘
```

See [docs/PROTOCOL_SPEC.md](docs/PROTOCOL_SPEC.md) for wire format details.

---

## Use Cases

### Personal Privacy
- End-to-end encrypted messaging without corporate intermediaries
- File sharing with cryptographic proof of sender identity
- Anonymous browsing with consent-based traffic routing

### Research & Education
- Study consent-based protocol design
- Teach cryptographic principles in practice
- Prototype privacy-preserving applications

### Open-Source Projects
- Build decentralized applications on consent-first architecture
- Integrate HSIP into privacy-focused tools
- Contribute to commons-based internet infrastructure

---

## Security & Transparency

### Cryptographic Libraries
HSIP uses industry-standard, audited implementations:
- `ed25519-dalek` - Ed25519 signatures
- `x25519-dalek` - X25519 key exchange
- `chacha20poly1305` - AEAD encryption (RustCrypto)

### Security Testing
- ✅ OWASP Top 10 attack resistance verified
- ✅ HMAC-SHA256 response integrity protection
- ✅ Perfect forward secrecy implemented
- ⏳ Independent security audit planned (NGI support pending)

### Vulnerability Reporting
Found a security issue? Report privately to: **nyxsystemsllc@gmail.com**

We follow responsible disclosure. Security researchers are credited in our hall of fame.

---

## License & Usage

### Free for Non-Commercial Use

HSIP is **free** for:
- ✅ Personal use
- ✅ Education and research
- ✅ Open-source projects
- ✅ Non-profit organizations

### Commercial Use
Organizations using HSIP for commercial purposes require a license. Contact: **nyxsystemsllc@gmail.com**

This ensures sustainable development while keeping HSIP accessible as a **public commons**.

See [LICENSE](LICENSE) for full terms.

---

## Contributing

HSIP is open to community contributions. We welcome:

- **Bug reports** and security disclosures
- **Protocol improvements** and cryptographic review
- **Documentation** enhancements
- **Platform ports** (Linux, macOS, iOS, Android)
- **Use case studies** and research

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

---

## Project Goals

HSIP is designed as **commons infrastructure** for the internet:

1. **User Autonomy** - You control who contacts you, not platforms
2. **Privacy by Default** - Encryption and consent are protocol-level, not optional features
3. **No Surveillance** - Peer-to-peer design minimizes metadata exposure
4. **Open Standards** - Fully documented protocol for interoperability
5. **Sustainable Commons** - Free for non-commercial use, licensed for commercial use

We believe privacy and consent should be **mathematical guarantees**, not corporate promises.

---

## Documentation

- [Getting Started Guide](GETTING_STARTED.md) - Installation and basic usage
- [Why HSIP?](WHY_HSIP.md) - Mission and problem statement
- [Protocol Specification](docs/PROTOCOL_SPEC.md) - Wire format and handshake
- [API Reference](docs/API_REFERENCE.md) - CLI commands and HTTP endpoints
- [Security Model](SECURITY.md) - Threat model and protections

---

## Funding & Support

HSIP is applying for **NGI Zero Commons Fund** support to:
- Conduct independent security audits
- Port to Linux, macOS, and mobile platforms
- Develop interoperability standards
- Build community and documentation

This project is committed to remaining **open and accessible as commons infrastructure**.

---

## Contact

- **GitHub Issues:** https://github.com/nyxsystems/HSIP-1PHASE-1/issues
- **Security:** nyxsystemsllc@gmail.com
- **General:** nyxsystemsllc@gmail.com

---

**HSIP: Where consent is code, not policy.**

*Built for the commons. Designed for privacy. Enforced by mathematics.*
