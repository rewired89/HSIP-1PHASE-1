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


## Quick local demo (Windows, dev build)
From the repo root:

# 0) Build once
cargo build -p hsip-core -p hsip-net -p hsip-cli

# 1) Generate a local identity (writes to %USERPROFILE%\.hsip)
cargo run -p hsip-cli -- init

# 2) HELLO handshake demo
# Terminal 1
cargo run -p hsip-cli -- handshake-listen --addr 127.0.0.1:9000

# Terminal 2
cargo run -p hsip-cli -- handshake-connect --addr 127.0.0.1:9000

## Sealed UDP session demo
This shows HSIP’s ephemeral X25519 + ChaCha20-Poly1305 session over UDP.

# Terminal 1 – listener
cargo run -p hsip-cli -- session-listen --addr 127.0.0.1:50505

# Terminal 2 – sender
cargo run -p hsip-cli -- session-send --to 127.0.0.1:50505


┌───────────────────────────────┐
│        Application Layer       │
│  (chat, storage, browser ext)  │
└───────────────────────────────┘
           ▲
           │ sealed frames
           ▼
┌───────────────────────────────┐
│      Ephemeral Session Layer   │
│ X25519 → ChaCha20-Poly1305     │
│ Nonce guard + integrity        │
└───────────────────────────────┘
           ▲
           │ consent token
           ▼
┌───────────────────────────────┐
│        Consent Layer           │
│ Signed allow/deny decisions    │
│ Scope-bound, TTL-based         │
└───────────────────────────────┘
           ▲
           │ signed HELLO
           ▼
┌───────────────────────────────┐
│         Identity Layer         │
│ Ed25519 PeerIDs                │
│ Self-sovereign keys            │
└───────────────────────────────┘

