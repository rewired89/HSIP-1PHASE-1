# Threat Model (alpha)
- **Assets:** user identity keys, consent decisions, in-flight control frames, session payloads.
- **Adversaries:** network observers, spammy peers, replayers, malformed-frame senders.
- **Controls in code:**
  - Ephemeral X25519 handshake + sealed frames (nonce misuse prevention, replay reject).
  - Guard rate limits: E1 rate, badsig/min, control/min, max frame size.
  - Policy engine: reputation threshold, allow list, signature requirement.
  - Cached allow window (`HSIP_CACHE_ALLOW_MS`) to reduce prompt fatigue post-auth.
- **Open items:** key rotation cadence; persistent pinned peers; automatic evidence logging; fuzzing coverage; formal nonce audit.
