# HSIP Security Analysis (v0.2.0-mvp)

This document summarizes the **security goals**, current guarantees, and known limitations
of the HSIP MVP as implemented in this repository.

It is written for auditors (e.g. Mozilla) and technical reviewers.

---

## 1. Goals (MVP scope)

HSIP aims to:

1. **Bind traffic to human-controlled identities**, not raw IPs.
2. **Require explicit consent** before high-value actions or ongoing sessions.
3. **Make abuse auditable** via signed, hash-chained reputation logs.
4. **Support lightweight, UDP-friendly deployment** for real-time apps.
5. **Be incrementally deployable**: HSIP can coexist with legacy stacks.

Out of scope for this MVP:

- Global routing, DHT, name resolution.
- Full anti-fingerprint/metadata-hiding guarantees.
- End-to-end application semantics (we focus on transport + consent).

---

## 2. Trust Model

### 2.1 Identities

- Each device/user has an **Ed25519 keypair** (generated locally).
- The public key is embedded in a **PeerID** used in HELLO & consent.
- Identity storage lives under `%USERPROFILE%\.hsip` on Windows.

Trust assumption:

- If you control the private key, you control that identity.
- Peers may pin or whitelist known PeerIDs out-of-band.

### 2.2 Consent & Reputation

- **Consent** is expressed via signed `CONSENT_REQUEST` / `CONSENT_RESPONSE` records.
- **Reputation** is a signed, append-only log that records allow/deny decisions and misbehavior.

Trust assumption:

- A verifier can reconstruct reputation from the log and validate signatures and hash links.
- A peer may local-policy **block** low-reputation identities.

---

## 3. Attacker Model

We consider an active network attacker that can:

- Observe, inject, drop, and replay UDP packets.
- Try to impersonate peers (spoof IPs & ports).
- Attempt to coerce or confuse the consent layer.
- Perform replay/adaptive attacks on encrypted sessions.

We do **not** (yet) fully address:

- Global passive adversaries capable of long-term correlation across many networks.
- Side-channel attacks on endpoints (timing, memory corruption, etc.).
- Compromised OS or kernel-level rootkits.

---

## 4. Properties Provided (MVP)

### 4.1 Identity & Authentication

- **HELLO** messages are signed with the Ed25519 device key.
- Receivers verify signatures and reject invalid HELLO frames.
- Consent and reputation records are also signed, allowing offline audit.

Effect:

- An attacker **cannot** forge a HELLO, consent record, or reputation entry without the private key.
- IP spoofing alone does not yield a valid HSIP identity.

### 4.2 Confidentiality & Integrity (Data Plane)

- Sessions use **X25519 ephemeral key exchange** to derive shared secrets.
- Payloads are protected with **ChaCha20-Poly1305 AEAD**.
- Each frame is sealed with an associated data (AAD) label (`CONTROL`, `DATA`, `PING`).

Effect:

- Session payloads are encrypted and integrity protected.
- Frames cannot be moved across planes (e.g., DATA → CONTROL) without detection.

> Note: This MVP focuses on a **single-session handshake**. Future versions will formalize a full Noise-style pattern and cross-session PFS.

### 4.3 Replay & Abuse Resistance

Mechanisms:

- The session layer maintains **nonces** and will reject replayed ciphertext.
- The consent layer uses **timestamps**, TTLs, and **reputation**:
  - Low-reputation peers can be auto-denied.
  - Misbehavior can be logged as signed reputation entries.
- The CLI demos include **rate-limiting & replay guard** in the consent listener.

Effect:

- Naive replay of previously sealed frames is not accepted.
- Repeated misbehavior from a peer accumulates a negative reputation score and can be blocked by policy.

### 4.4 Consent Binding

A `CONSENT_RESPONSE` is bound to a specific `CONSENT_REQUEST` via:

- A **hash of the request** embedded in the response (`request_hash_hex` or equivalent).
- Both signed with Ed25519 keys of requester/issuer.

This prevents:

- An attacker from taking a valid “allow” response and reattaching it to a different request.
- Silent consent upgrading for different scopes/resources.

### 4.5 Local-Only Consent Tokens

The `Tray` / local consent HTTP server:

- Issues **short-lived JWT-like tokens** signed with Ed25519 (local device authority).
- Enforces a strict **Origin policy**:
  - Only `moz-extension://…` (the HSIP browser extension) or explicitly allowed dev origins can call `/consent` and `/verify`.
- Tokens are verified by `token-verify-local`, returning structured JSON with scopes/audience.

Effect:

- Websites themselves cannot directly mint tokens; they must go through the extension.
- This mitigates the “hidden prompt injection” problem for pages trying to coerce the local agent.

---

## 5. Limitations (Honest Reality Check)

MVP limitations (by design, not bugs):

1. **No global PKI yet**  
   - PeerIDs are self-issued; there is no federation or PKI hierarchy yet.
   - Pinning/allow-lists are local policy.

2. **Single-shot handshake pattern**  
   - We do not yet use a formal Noise/X3DH-like pattern with identity binding embedded in the transcript.
   - Ephemeral keys provide session secrecy, but long-term PFS strategy across many sessions is not fully specified.

3. **Metadata still visible**  
   - IP/port, packet sizes, and timing are not obfuscated.
   - Cover traffic exists as a prototype in the CLI for sessions, but is **optional** and not tuned for mobile/low-bandwidth users.

4. **Local agent trust**  
   - We assume the HSIP tray/daemon and CLI are running on a relatively honest host.
   - If the endpoint OS is compromised, HSIP cannot fully protect the user.

5. **No formal proofs (yet)**  
   - Design is consistent with modern secure transports (TLS 1.3 / Noise), but we do not yet have a formal model or proof.

---

## 6. Planned Hardening & Future Work

Short-term roadmap (post-MVP):

1. **Formalize handshake pattern**
   - Define a Noise-style pattern (e.g. `XX` with static keys) and document transcript.
   - Bind identity keys to sessions more explicitly.

2. **Session rekeying**
   - Rekey after N packets or T seconds.
   - Session tickets for resumption, with strong nonce / key separation.

3. **Stronger replay resistance**
   - Explicit per-session sequence numbers in AAD.
   - Optional server-side sliding windows for replay detection across restarts.

4. **PQC hybrid modes**
   - Add Kyber/Dilithium hybrid handshake alongside X25519/Ed25519.
   - Allow gradual migration without breaking existing peers.

5. **Better cover traffic UX**
   - Make cover traffic opt-in but easy to tune for users with higher threat models.
   - Tie into reputation to avoid abuse/amplification.

6. **Auditable policies**
   - Machine-readable policy docs (e.g. JSON-based HSIP policy for a host or org).
   - Tools to replay reputation logs and derive effective risk scores.

---

## 7. Summary

The HSIP MVP already delivers:

- Signed identity & HELLO
- Consent-bound, auditable actions
- Encrypted, integrity-protected UDP sessions
- Replay and abuse resistance primitives
- A local consent agent with browser-only Origin checks

It is not yet a full “new Internet,” but it **concretely improves**:

- Who can talk to whom
- Under which conditions
- And with what level of after-the-fact accountability

The remaining work is mostly **formalization and hardening**, not rethinking the core model.