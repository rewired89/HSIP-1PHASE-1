# HSIP v0.2.0-mvp — Hyper Secure Internet Protocol

**Repo:** `rewired89/HSIP-fresh`  
**Product owner:** Nyx Systems LLC  

HSIP is a **consent-first secure session protocol over UDP**.

It is *not* a replacement for TCP, QUIC, or WireGuard.  
Instead, HSIP is a **secure, consent-aware shim** that apps can stack under or next to existing transports when they need:

- Strong, user-owned identity (no CAs, no PKI bureaucracy)
- Mandatory consent **before** any application data flows
- Encrypted UDP sessions with replay protection
- Explicit capability tokens (“what is this peer allowed to do?”)

---

## 1. What Works in v0.2.0-mvp

This tag is the **Basic, free HSIP MVP**. It focuses on:

1. **Identity & HELLO**
2. **Consent layer (local JSON + UDP control plane)**
3. **Encrypted sessions over UDP**
4. **Encrypted PING (latency + integrity)**
5. **Tokens & local device consent**
6. **Tray-lite + local demo site**

Everything below is already implemented and tested on Windows (Rust, Cargo).

---

## 2. Building the Project

Requirements:

- Rust (stable)
- `cargo`
- Windows (MVP dev target; Linux should work with small tweaks)

Build all crates:

```bash
cargo build
