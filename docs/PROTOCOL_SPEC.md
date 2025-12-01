# HSIP Protocol Specification (v0.2.0-mvp)

This document defines the wire format, handshake, consent layer, and encrypted session protocol used in HSIP.

---

## 1. Overview
HSIP is a consent-first secure session protocol built on UDP.  
Before any encrypted data flows, the user must approve a signed consent request.  
After approval, both peers negotiate an ephemeral session key and exchange encrypted frames.

**Protocol Layers:**
1. **Identity** (Ed25519)
2. **Consent** (signed allow/deny)
3. **Session** (X25519 + ChaCha20-Poly1305)

---

## 2. Identities
### 2.1 Long-Term Identity
Each device generates:
- Ed25519 keypair  
- Stored locally at `%USERPROFILE%\.hsip\identity.json` (Windows) or `~/.hsip/identity.json` (Linux/Mac)

### 2.2 Peer ID
peer_id = first_26_bytes(Ed25519_public_key)
PeerId is 26 bytes (208 bits) and uniquely identifies a device.

---

## 3. Wire Prefix

All HSIP packets start with a 6-byte prefix:
[ 0..4 ] = b"HSIP" (magic bytes) [ 4..6 ] = version u16 BE (protocol version, currently 0x0002)


**Version Compatibility:**
- MIN_VER: 0x0001
- MAX_VER: 0x0002  
- CURRENT: 0x0002

Packets with wrong magic or unsupported version are dropped silently.

---

## 4. HELLO Message

Used to announce identity + capabilities. Always signed.

**Wire Format (115 bytes total):**
[ 0 ] = protocol_version (u8) [ 1..5 ] = capabilities (u32, big-endian) [ 5..31 ] = peer_id (26 bytes) [ 31..39] = timestamp_ms (u64, big-endian) [ 39..51] = nonce (12 bytes, random) [ 51..115] = signature (64 bytes, Ed25519)


**Signature covers:** version || caps || peer_id || timestamp || nonce

**Validation:**
- Signature must verify against peer_id
- Timestamp must be within ±60 seconds of receiver's clock
- Nonce prevents replay attacks

**Capabilities Bitmask:**
- Bit 0 (CAP_CONSENT_LAYER): Supports consent protocol
- Bit 1 (CAP_SESSION_RESUMPTION): Supports session tickets
- Bit 2 (CAP_COVER_TRAFFIC): Can send/receive cover traffic
- Bits 3-31: Reserved for future use

---

## 5. Consent Tokens
Consent is mandatory before any handshake.

### 5.1 Consent Request
```json
{
  "purpose": "string (why peer wants session)",
  "expires_ms": "u64 (expiration timestamp)",
  "nonce": "bytes16 (random)",
  "payload": "bytes (optional application data)",
  "signature": "bytes64 (Ed25519)"
}

5.2 Consent Response
{
  "decision": "allow | deny",
  "ttl_ms": "u64 (auto-accept window duration)",
  "nonce_echo": "bytes16 (must match request)",
  "signature": "bytes64 (Ed25519)"
}

Decision Flow:
    If deny → stop immediately, no session
    If allow → proceed to handshake

6. Session Handshake (Ephemeral X25519)
6.1 E1 Frame (Initiator → Responder)

[ HSIP prefix (6 bytes) ]
[ eph_pub (32 bytes, X25519 public key) ]
[ nonce1 (12 bytes) ]
[ ciphertext (ChaCha20-Poly1305 encrypted) ]

6.2 E2 Frame (Responder → Initiator)
[ HSIP prefix (6 bytes) ]
[ eph_pub (32 bytes, X25519 public key) ]
[ nonce2 (12 bytes) ]
[ ciphertext (ChaCha20-Poly1305 encrypted) ]

6.3 Shared Secret Derivation
shared_secret = X25519(eph_sk_local, eph_pk_remote)
session_key = HKDF-SHA256(
    ikm: shared_secret,
    salt: None,
    info: label || nonce1 || nonce2,
    length: 32 bytes
)

6.4 Cipher Suite
    Algorithm: ChaCha20-Poly1305 AEAD
    Key Size: 256 bits (32 bytes)
    Nonce Size: 96 bits (12 bytes)
    Tag Size: 128 bits (16 bytes)

Nonce Format:

[ session_id: u32 (BE) | counter: u64 (BE) ]

    session_id: Derived from HKDF output (first 4 bytes)
    counter: Monotonically increasing, starts at 1

AAD (Additional Authenticated Data):
    Packet type (E1, E2, DATA)
    Protocol version
    Session ID

7. Encrypted Data Frames
All session data after handshake:

[ HSIP prefix (6 bytes) ]
[ ciphertext (ChaCha20-Poly1305) ]

Ciphertext Contains:
    Encrypted payload
    16-byte authentication tag

Nonce Management:
    Sender: increments counter for each packet
    Receiver: uses 64-packet sliding window for replay protection

8. Session Resumption (Optional)
8.1 Session Ticket

[ nonce (12 bytes) ]
[ encrypted_ticket_data (ChaCha20-Poly1305) ]

Ticket Data (encrypted):

[ peer_id (26 bytes) ]
[ capabilities (4 bytes) ]
[ issued_at (8 bytes, u64) ]
[ expires_at (8 bytes, u64) ]

Key Derivation:
ticket_key = SessionTicketKey([u8; 32])  // Server-side secret

8.2 Ticket Validation
    Decrypt ticket with server's session ticket key
    Verify timestamp: now_ms ∈ [issued_at, expires_at]
    Check peer_id matches
    Resume session if valid, else full handshake

9. Replay Protection
Per-Session Nonce Window (64 packets):

    Tracks highest nonce counter seen: max_seen
    Maintains 64-bit bitmap of recent packets
    Accepts nonces in range: [max_seen - 63, max_seen]
    Rejects:
        Nonce counter = 0 (invalid)
        Nonce > 64 packets old (TooOld)
        Nonce already seen (Replay)

Timestamp Validation:
    HELLO messages must be within ±60 seconds of receiver clock
    Prevents replay of old handshake messages

10. Error Codes
Code	Name	Description
0x01	HelloTimestampSkew	Timestamp outside acceptable window
0x02	HelloBadSignature	Signature verification failed
0x03	HelloNoCommonCapabilities	No shared capabilities
0x10	ConsentDenied	User explicitly denied consent
0x11	ConsentExpired	Consent request expired
0x20	SessionAuthFailed	AEAD authentication failed
0x21	SessionNonceReplay	Nonce replay detected
0x22	SessionNonceTooOld	Nonce outside window


11. Security Properties

Confidentiality:
    All session data encrypted with ephemeral X25519 keys
    Forward secrecy: compromising long-term keys doesn't decrypt past sessions

Authenticity:
    All handshake messages signed with Ed25519
    AEAD provides authentication for session data

Integrity:
    ChaCha20-Poly1305 detects any tampering
    Nonce binding prevents packet reordering attacks

Consent:
    Cryptographically enforced: no session without signed consent response
    TTL allows auto-accept windows to reduce user friction

Replay Protection:
    Nonce counters prevent replaying session packets
    Timestamps prevent replaying handshake messages
    Sliding window allows out-of-order delivery

12. Future Extensions
Planned for v0.3:
    Post-quantum key exchange (Kyber + X25519 hybrid)
    Connection migration (IP address changes)
    Multi-device identity synchronization
    Rekeying after N packets or T seconds

References
    Ed25519: RFC 8032
    X25519: RFC 7748
    ChaCha20-Poly1305: RFC 8439
    HKDF: RFC 5869


