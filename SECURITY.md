# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in HSIP, please report it responsibly:

**Email:** security@hsip.io

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 7 days
- **Fix Timeline:** 90 days for responsible disclosure

### Disclosure Policy

We follow coordinated vulnerability disclosure:

1. Report sent to security contact
2. Issue is confirmed and assessed
3. Fix is developed and tested
4. Security advisory is published
5. CVE is assigned (if applicable)

### Security Features

HSIP implements the following security measures:

- **Cryptographic Consent:** All communication requires explicit cryptographic consent tokens
- **Modern Cryptography:** Ed25519 signatures, X25519 key exchange, ChaCha20-Poly1305 encryption
- **Anti-Replay Protection:** Nonce-based replay prevention
- **Session Security:** Perfect forward secrecy through ephemeral key exchange
- **Memory Safety:** 100% safe Rust code in core implementation (0% unsafe)

### Security Audits

See [SECURITY_AUDIT.md](./SECURITY_AUDIT.md) for detailed security audit reports.

### Dependencies

We actively monitor dependencies for vulnerabilities using:

- `cargo-audit` (RustSec Advisory Database)
- `cargo-deny` (license and policy enforcement)
- GitHub Dependabot (if enabled)

### Scope

**In Scope:**
- Protocol implementation (hsip-core, hsip-session)
- Cryptographic operations
- Network handling (hsip-net)
- Authentication (hsip-auth)
- CLI tools (hsip-cli)

**Out of Scope:**
- Third-party dependencies (report to upstream)
- Denial of Service (bandwidth-based)
- Physical access attacks

### Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

*No reports yet*

---

Thank you for helping keep HSIP secure!
