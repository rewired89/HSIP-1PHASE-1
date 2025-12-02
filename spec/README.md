# 📘 HSIP Specification (v0.2.0-mvp)

This folder contains the **formal technical specification** for the HSIP protocol.
It is written for auditors, researchers, and implementers (Mozilla, grant reviewers, etc.).

Each document is self-contained and focuses on one part of the protocol.

---

## 📑 Documents

### **00 – Overview**
**File:** `00-overview.md`  
High-level description of HSIP: goals, threat model, identity, consent, and the protocol architecture.

### **01 – Handshake**
**File:** `01-handshake.md`  
Formal handshake flow for the MVP, including HELLO, ephemeral key exchange, AAD labels, and session establishment.

### **02 – Wire Format**
**File:** `02-wire-format.md`  
Exact bytes sent over the wire: HELLO JSON, E1/E2 handshake frames, sealed frames, PING, tags, labels, and UDP framing rules.

### **03 – Security Analysis**
**File:** `03-security-analysis.md`  
What HSIP protects, what it doesn’t yet, attacker model, replay protection, identity guarantees, consent security, and planned hardening.

---

## 🧭 How to Read This Spec

- Start with **00-overview.md** to understand the protocol goals.
- Move to **01-handshake.md** for the live flow of packets and keys.
- Use **02-wire-format.md** when implementing interop or verifying correctness.
- Refer to **03-security-analysis.md** for audits or grant submissions.

These files track the **current MVP implementation** exactly, including:
- `hsip-core`
- `hsip-net`
- `hsip-cli`

Whenever the Rust code changes (new tags, new fields, new handshake steps),
the corresponding sections in `spec/*.md` must be updated.

---

## 📌 Versioning

This spec tracks **HSIP v0.2.0-mvp**, the first public-ready release.

Future versions:
- v0.3.x → hardening & rekeying  
- v0.4.x → negotiation, migration support  
- v1.0.0 → audited stable spec with PQ support  

---

## 📞 Contact / Attribution

**Nyx Systems LLC**
HSIP — Human-Secure Internet Protocol
Miami, FL

Primary author: Rewired89

---

That’s it.  
Simple, clean, professional, auditor-ready.
