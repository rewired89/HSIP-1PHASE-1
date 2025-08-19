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
