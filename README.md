# HSIP

**Cryptographic consent protocol for secure peer-to-peer communication.**

HSIP enforces consent at the protocol level using capability-based tokens. Unlike application-layer solutions, consent violations are cryptographically impossible.

**Status:** Alpha (security audit in progress)  
**Platform:** Windows 10/11 (Linux/Mac coming soon)

---

## Features

**Core Protocol:**
- Ed25519 identity (self-sovereign, no central registry)
- Capability-based consent tokens (time-bounded, granular permissions)
- X25519 + ChaCha20-Poly1305 session encryption
- Reputation-based peer filtering

**This Release Includes:**
- Background daemon with HTTP API
- System tray status indicator
- CLI tools for testing
- Optional local gateway (browser traffic inspection)

---

## Quick Start

**Install:**
```powershell
# Download installer from Releases
# Run HSIP-Setup.exe
```

**Verify it's running:**
```powershell
curl http://127.0.0.1:8787/status
```

**Should return:**
```json
{
  "protected": true,
  "active_sessions": 0,
  "cipher": "ChaCha20-Poly1305"
}
```

---

## Use Cases

**Telemedicine:** HIPAA-compliant consent tokens for patient data access

**IoT:** Device-to-device authorization with automatic expiration

**Finance:** PSD2/Open Banking consent verification

**Privacy Apps:** Protocol-level enforcement of user preferences

---

## Architecture
```
hsip-cli daemon          # Core protocol daemon
  ├─ :8787/status       # Status API
  ├─ :8787/sessions     # Session management
  └─ :8787/consent      # Consent token operations

hsip-tray               # System tray indicator (optional)
hsip-gateway            # Local proxy for testing (optional)
```

---

## Documentation

- [Protocol Specification](docs/protocol.md)
- [API Reference](docs/api.md)
- [Examples](examples/)
- [Security Model](docs/security.md)

---

## Development

**Build from source:**
```powershell
git clone https://github.com/rewired89/HSIP.git
cd HSIP
cargo build --release
```

**Run tests:**
```powershell
cargo test
```

**Contributions welcome.** See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Status

**What works:**
✅ Consent token issuance/verification  
✅ Secure session establishment  
✅ Reputation-based filtering  
✅ Background daemon + API  

**In progress:**
🚧 Security audit (Mozilla MOSS)  
🚧 Python/JavaScript SDKs  
🚧 Post-quantum crypto option  

**Planned:**
📋 Session resumption  
📋 Connection migration  
📋 Multi-device identity  

---

## Security

**Current status:** Alpha - not production ready

**Audits:**
- Mozilla security audit: In progress
- Additional audits planned

**Cryptography:**
- Ed25519 (identity/signatures)
- X25519 (key exchange)
- ChaCha20-Poly1305 (encryption)

**Report vulnerabilities:** security@hsip.dev

---

## License

Apache 2.0 / MIT dual license

---

## Contact

- GitHub: [Issues](https://github.com/rewired89/HSIP/issues)
- Email: [your-email]
- Documentation: [hsip.dev](https://hsip.dev)