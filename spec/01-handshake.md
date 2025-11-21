# HSIP Handshake Specification

## 1. HELLO Message

Fields:
- version (u8)
- timestamp_ms (u64)
- caps_bitmap (u32)
- peer_id (32 bytes)
- signature (64 bytes)

Signature scheme:
Ed25519 over:
  version || timestamp || caps || peer_id

## 2. Consent Phase

Two types:
- CONSENT_REQUEST
- CONSENT_RESPONSE

A request includes:
- requester PeerID
- requested scopes (Vec<String>)
- timestamp
- signature

A response includes:
- responder PeerID
- decision (allow/deny)
- TTL
- signature
- hash-chain pointer for audit logs

## 3. Ephemeral Session

X25519 handshake:
- A sends ephemeral pubkey + timestamp
- B verifies + responds with its own ephemeral pubkey

Session keys:
K = HKDF(X25519(A,B), AAD = PeerIDs || timestamps)

All application data:
ChaCha20-Poly1305(K, nonce++, AAD)

Nonces are monotonic per session.

## 4. Replay Prevention
The receiver rejects:
- timestamps older than 3s
- nonces that do not strictly increase
- signatures bound to stale AAD

## 5. Handshake Summary

1. HELLO → verify identity  
2. CONSENT_REQUEST → signed ask  
3. CONSENT_RESPONSE → allow/deny  
4. SESSION_INIT → X25519 ephemeral exchange  
5. SESSION_DATA → encrypted communication
