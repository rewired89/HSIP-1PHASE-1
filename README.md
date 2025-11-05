# 🌐 HSIP – Human-Secure Internet Protocol

**HSIP (Human-Secure Internet Protocol)** is a next-gen protocol that puts **users first**:
privacy, consent, and accountability are built in.

- 🔐 Privacy-first identities (Ed25519 PeerIDs)
- ✅ Consent-driven data access (signed requests/responses)
- 🧾 Auditable, hash-chained reputation (tamper-evident)
- ⚡ Lightweight over UDP, decentralized, extensible

## ✅ Implemented (status)
- **Key mgmt**: generate/save Ed25519 keypairs, print PeerID/WhoAmI
- **HELLO**: build/send + listen/verify over UDP
- **Consent**:
  - Build/verify `CONSENT_REQUEST` & `CONSENT_RESPONSE`
  - Send/listen consent messages over UDP control port
- **Reputation**:
  - Append signed allow/deny decisions (hash-chained log)
  - Verify chain & signatures
  - Pretty-print log

## 🚀 Roadmap
- Encrypted channels (Noise/TLS), multiplexing, NAT traversal
- Gossip reputation + weighted trust scoring
- Delegated & expiring consent; fine-grained scopes
- PQ crypto (Kyber/Dilithium), ZK proofs
- Dev UX: Rust lib, browser extension/proxy, dashboard

## Crates

# HSIP CLI (v0.2.0-mvp)

## Quick Install (Windows)
1. Download and run **HSIP-CLI-Setup.exe**.
2. (Optional) Check **“Add HSIP to PATH”**.
3. Start Menu → **HSIP Quickstart** to demo.

## Quick Start (CLI)
```powershell
hsip-cli --help
hsip-cli init
# Window 1:
hsip-cli hello-listen --addr 0.0.0.0:40404
# Window 2:
hsip-cli hello-send --to 127.0.0.1:40404
# Session:
hsip-cli session-listen --addr 127.0.0.1:50505
hsip-cli session-send   --to   127.0.0.1:50505 --packets 3
# Ping:
hsip-cli ping-listen --addr 127.0.0.1:51515
hsip-cli ping --to 127.0.0.1:51515 --count 3
