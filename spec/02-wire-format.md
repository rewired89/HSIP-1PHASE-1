# HSIP Wire Format – HELLO, Consent, Sessions, Ping

This document describes the **on-wire format** used by the HSIP CLI demos in the
`v0.2.0-mvp` release:

- HELLO (identity + capabilities)
- Consent control-plane over UDP
- Sealed UDP sessions
- Privacy-preserving Ping

It is intentionally simple and designed for auditors + implementers who want to
understand what actually goes over the network.

---

## 1. Notation cheatsheet

- All multi-byte integers are **big-endian** unless noted otherwise.
- `len(X)` means raw byte length.
- JSON structures are UTF-8 encoded.
- `TAG_*` are **single-byte type tags** on the wire.
- `AAD_*` are Additional Authenticated Data strings inside AEAD.

From the implementation:

```rust
// Tags
const TAG_E1: u8 = 0xE1; // client hello (ephemeral pubkey)
const TAG_E2: u8 = 0xE2; // server hello (ephemeral pubkey)
const TAG_D:  u8 = 0xD0; // sealed data frame

// AAD labels
const LABEL_CONSENT_V1: &[u8] = b"CONSENTv1";
const AAD_CONTROL: &[u8]     = b"type=CONTROL";
const AAD_DATA: &[u8]        = b"type=DATA";
const AAD_PING: &[u8]        = b"type=PING";
