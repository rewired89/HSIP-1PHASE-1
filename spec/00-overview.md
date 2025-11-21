# HSIP — Human-Secure Internet Protocol  
### Overview (v0.2.0-MVP)

HSIP is a **consent-first secure session protocol** designed for the modern internet:  
a transport-like layer over UDP that guarantees **no packet flows unless both peers cryptographically agree**.

Traditional transports (TCP, QUIC, TLS, WireGuard) protect confidentiality,  
but they still allow unsolicited packets, scanning, metadata leaks, and silent connection attempts.

HSIP removes that attack surface.

---

# 1. Core Principles

## 🔐 1.1 Consent Before Data  
Every operation (session, ping, file, voice, login) requires:

