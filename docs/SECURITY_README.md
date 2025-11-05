HSIP MVP — Security Overview


Threat model (MVP):
- Protect data-in-flight confidentiality & integrity using ephemeral X25519-derived symmetric keys and ChaCha20-Poly1305.
- Replay guard: sessions are single-use per handshake (prevent replay of control frames).
- Reputation gating: optional local reputation store used to auto-deny misbehaving peers.
- Cover traffic: optional sealed decoys to raise analysis cost for passive observers.


What we DO NOT store:
- Secret keys and session shared secrets are never persisted to disk by CLI.
- Only metadata (e.g., eph public key hex, label, peer_addr, ts_ms) saved in ~/.hsip/state for operator visibility.


Recommendations before production:
- Add session rekeying (after N packets or T seconds).
- Harden NAT traversal & deterministic backoff for handshake failures.
- Add code-signing to distributed binaries and an installer with SHA256 verification.