# HSIP Consent & Reputation System  
### Specification (v0.2.0-MVP)

Consent and reputation are the foundation of HSIP:  
**a peer cannot interact with another unless explicit, verifiable consent is granted**,  
and **all decisions become tamper-evident evidence.**

---

# 1. Consent Objects

HSIP defines two signed JSON objects:

- `ConsentRequest`
- `ConsentResponse`

Both use **Ed25519 signatures** with the peer identity.

All fields are required unless marked optional.

---

## 1.1 ConsentRequest

```json
{
  "version": 1,
  "timestamp_ms": 1731880000000,
  "expires_ms": 30000,
  "requester_peer_id": "hsip:abcd...",
  "cid_hex": "e0a1f1...",
  "purpose": "session-init",
  "signature_hex": "..."
}
