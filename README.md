**HSIP**

Consent-based secure communication protocol with strong cryptography and explicit user authorization at the transport layer.

HSIP enforces consent through capability tokens, ensuring that communication only occurs when explicitly granted.
Unlike application-layer solutions, HSIP embeds consent directly into the protocol itself.

**Status: Alpha
Platforms: Windows 10/11 (Linux & macOS planned)**

**Features**
🔐 Core Protocol
Identity based on Ed25519
Capability tokens (time-bounded, permission-scoped)
Encrypted sessions using X25519 + ChaCha20-Poly1305
Optional reputation-based peer filtering
Explicit, cryptographically enforced consent

**🔧 Included in this Release**
Background daemon with HTTP API
System tray indicator (Windows)
CLI tools for debugging and testing
Optional local gateway (for development and inspection)

**Quick Start (Windows)**
Install:
# Download the installer from Releases
# Run: HSIP-Setup.exe

Check status:
curl http://127.0.0.1:8787/status

Expected output:
{
  "protected": true,
  "active_sessions": 0
}

**Use Cases**
Telemedicine – patient-controlled access to sessions and data
IoT – device-to-device authorization with token expiration
Finance – consent-verifiable operations (PSD2/Open Banking workflows)
Privacy Apps – enforce user preferences cryptographically

**Architecture Overview**
hsip-cli             # CLI for testing and development
  └── communicates with:
      hsip-daemon    # Background service with HTTP API
        ├── /status
        ├── /sessions
        └── /consent

hsip-tray            # System tray companion (optional)
hsip-gateway         # Local proxy for testing use cases (optional)


**Documentation**
Protocol Specification — docs/PROTOCOL_SPEC.md
API Reference — docs/API_REFERENCE.md
Examples — docs/EXAMPLES.md

**Development**
Build from source:
git clone https://github.com/rewired89/HSIP.git
cd HSIP
cargo build --release

**Run tests:**
cargo test

**Contributions welcome.**
 See CONTRIBUTING
.

**Current Status**
✔ Working
Consent token creation/validation
Secure session establishment
Reputation filtering
Background daemon + tools
Windows integration

**🚧 In Progress**
Cross-platform support (Linux/macOS)
Developer SDKs (Python/JS)
Extended test coverage

**📝 Planned**
Session resumption
Connection migration
Multi-device identity workflow

**Security**
HSIP is currently in alpha and not yet recommended for production deployments.

**Cryptography**
Ed25519 for identity and signatures
X25519 for key agreement
ChaCha20-Poly1305 for authenticated encryption

**Reporting**
Please report vulnerabilities privately to:
nyxsystemsllc@gmail.com

**License**
HSIP Community License (Non-Commercial)
Free for personal, educational, research, and open-source projects
Commercial use requires an Enterprise License from Nyx Systems LLC
See the full license in LICENSE.
For commercial inquiries: nyxsystemsllc@gmail.com

**Contact**
GitHub Issues: https://github.com/rewired89/HSIP/issues
Email: nyxsystemsllc@gmail.com

