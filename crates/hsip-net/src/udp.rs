// crates/hsip-net/src/udp.rs
// UDP transport for HELLO + CONSENT control messages.
//
// Features:
// 1) Optional reputation enforcement (listener):
//      HSIP_ENFORCE_REP=1
//      HSIP_REP_THRESHOLD=<int>          (default: -6)
// 2) Optional per-IP rate limiting (listener):
//      HSIP_RL_MAX=<int>                 (default: 30)
//      HSIP_RL_WINDOW_MS=<int>           (default: 10000)
//      HSIP_RL_BAN_MS=<int>              (default: 30000)
// 3) Optional end-to-end encryption (both sides):
//      HSIP_ENC_KEY_HEX=<32-byte hex>    (ChaCha20-Poly1305, 12B nonce)
// 4) NEW: Replay protection (listener):
//      HSIP_REPLAY_WINDOW_MS=<int>       (default: 60000)
//      HSIP_TS_SKEW_MS=<int>             (default: 30000)

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hello::build_hello;
use hsip_core::consent::{build_response, ConsentRequest, ConsentResponse};
use hsip_core::identity::peer_id_from_pubkey;
use hsip_core::keystore::load_keypair;
use hsip_reputation::store::{DecisionType, Store};

// Encryption (optional) — standard ChaCha20-Poly1305 (96-bit nonce)
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
enum ControlFrame {
    HELLO(String),                     // pretty-printed JSON of HELLO
    CONSENT_REQUEST(ConsentRequest),   // raw JSON struct
    CONSENT_RESPONSE(ConsentResponse), // raw JSON struct
}

// On-the-wire encrypted envelope
#[derive(Debug, Serialize, Deserialize)]
struct EncEnvelope {
    #[serde(rename = "type")]
    typ: String,       // always "ENC"
    nonce_hex: String, // 12B nonce
    ct_hex: String,    // ciphertext of serialized ControlFrame
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock ok")
        .as_millis() as u64
}

fn bind_udp(addr: &str) -> Result<UdpSocket> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_nonblocking(false)?;
    Ok(sock)
}

// ---------- Optional encryption helpers ----------

fn enc_key_from_env() -> Option<[u8; 32]> {
    let hexkey = std::env::var("HSIP_ENC_KEY_HEX").ok()?;
    let bytes = hex::decode(hexkey).ok()?;
    if bytes.len() != 32 {
        eprintln!("[ENC] HSIP_ENC_KEY_HEX must be 32 bytes (64 hex chars)");
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Some(k)
}

fn encrypt_if_enabled(plain: &[u8]) -> Result<Vec<u8>> {
    if let Some(key) = enc_key_from_env() {
        let cipher = ChaCha20Poly1305::new(&key.into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plain)
            .map_err(|e| anyhow!("encrypt: {e}"))?;
        let env = EncEnvelope {
            typ: "ENC".to_string(),
            nonce_hex: hex::encode(nonce_bytes),
            ct_hex: hex::encode(ct),
        };
        let bytes = serde_json::to_vec(&env)?;
        Ok(bytes)
    } else {
        Ok(plain.to_vec())
    }
}

fn decrypt_if_needed(bytes: &[u8]) -> Result<Vec<u8>> {
    let v: Value = serde_json::from_slice(bytes)?;
    if v.get("type").and_then(|t| t.as_str()) == Some("ENC") {
        let key = enc_key_from_env().ok_or_else(|| anyhow!("encrypted frame but HSIP_ENC_KEY_HEX is not set"))?;
        let nonce_hex = v.get("nonce_hex").and_then(|x| x.as_str()).ok_or_else(|| anyhow!("ENC missing nonce_hex"))?;
        let ct_hex = v.get("ct_hex").and_then(|x| x.as_str()).ok_or_else(|| anyhow!("ENC missing ct_hex"))?;
        let nonce_vec = hex::decode(nonce_hex).map_err(|e| anyhow!("nonce hex: {e}"))?;
        let ct = hex::decode(ct_hex).map_err(|e| anyhow!("ct hex: {e}"))?;
        if nonce_vec.len() != 12 { return Err(anyhow!("nonce must be 12 bytes")); }
        let nonce = Nonce::from_slice(&nonce_vec);
        let cipher = ChaCha20Poly1305::new(&key.into());
        let pt = cipher
            .decrypt(nonce, ct.as_ref())
            .map_err(|e| anyhow!("decrypt: {e}"))?;
        Ok(pt)
    } else {
        Ok(bytes.to_vec())
    }
}

fn send_frame(sock: &UdpSocket, to: &str, frame: &ControlFrame) -> Result<()> {
    let to_addr: SocketAddr = to.parse()?;
    let plain = serde_json::to_vec(frame)?;
    let wire = encrypt_if_enabled(&plain)?;
    sock.send_to(&wire, to_addr)?;
    Ok(())
}

fn recv_frame<'b>(buf: &'b mut [u8], sock: &UdpSocket) -> Result<(ControlFrame, SocketAddr)> {
    let (n, from) = sock.recv_from(buf)?;
    let wire = &buf[..n];
    let plain = decrypt_if_needed(wire)?;
    let frame: ControlFrame = serde_json::from_slice(&plain)?;
    Ok((frame, from))
}

fn other_type(cf: &ControlFrame) -> &'static str {
    match cf {
        ControlFrame::HELLO(_) => "HELLO",
        ControlFrame::CONSENT_REQUEST(_) => "CONSENT_REQUEST",
        ControlFrame::CONSENT_RESPONSE(_) => "CONSENT_RESPONSE",
    }
}

// ---------------- Rate Limiter ----------------

struct RateLimiter {
    hits: HashMap<IpAddr, VecDeque<Instant>>,
    bans: HashMap<IpAddr, Instant>,
    max: usize,
    window: Duration,
    ban_for: Duration,
}

impl RateLimiter {
    fn new(max: usize, window_ms: u64, ban_ms: u64) -> Self {
        Self {
            hits: HashMap::new(),
            bans: HashMap::new(),
            max,
            window: Duration::from_millis(window_ms),
            ban_for: Duration::from_millis(ban_ms),
        }
    }
    fn check_and_note(&mut self, ip: IpAddr, now: Instant) -> bool {
        if let Some(until) = self.bans.get(&ip) {
            if *until > now {
                return false;
            } else {
                self.bans.remove(&ip);
            }
        }
        let q = self.hits.entry(ip).or_insert_with(VecDeque::new);
        while let Some(&t0) = q.front() {
            if now.duration_since(t0) > self.window {
                q.pop_front();
            } else {
                break;
            }
        }
        q.push_back(now);
        if q.len() > self.max {
            self.bans.insert(ip, now + self.ban_for);
            return false;
        }
        true
    }
}

// ---------------- Replay Guard (per-requester) ----------------

struct ReplayGuard {
    // For each requester peer: recent nonces (dedupe) and a timestamp queue for expiry.
    seen: HashMap<String, HashSet<String>>,
    order: HashMap<String, VecDeque<(String, u64)>>, // (nonce_hex, ts_ms seen_at)
    window_ms: u64,
    skew_ms: u64,
}

impl ReplayGuard {
    fn new(window_ms: u64, skew_ms: u64) -> Self {
        Self {
            seen: HashMap::new(),
            order: HashMap::new(),
            window_ms,
            skew_ms,
        }
    }

    fn allow(&mut self, requester_peer_id: &str, nonce_hex: &str, req_ts_ms: u64, now_ms: u64) -> bool {
        // reject if timestamp too far in the past/future
        let delta = if now_ms > req_ts_ms { now_ms - req_ts_ms } else { req_ts_ms - now_ms };
        if delta > self.window_ms + self.skew_ms {
            return false;
        }

        let set = self.seen.entry(requester_peer_id.to_string()).or_default();
        let q = self.order.entry(requester_peer_id.to_string()).or_default();

        // expire old entries for this requester
        while let Some((_, seen_ms)) = q.front().cloned() {
            if now_ms.saturating_sub(seen_ms) > self.window_ms {
                if let Some((old_nonce, _)) = q.pop_front() {
                    set.remove(&old_nonce);
                }
            } else {
                break;
            }
        }

        // replay?
        if set.contains(nonce_hex) {
            return false;
        }

        // record
        set.insert(nonce_hex.to_string());
        q.push_back((nonce_hex.to_string(), now_ms));
        true
    }
}

// =============== Public API used by hsip-cli/main.rs ===================

/// Listen for HELLO frames and print them (debug utility)
pub fn listen_hello(addr: &str) -> Result<()> {
    let sock = bind_udp(addr)?;
    println!("[listen_hello] bound to {}", addr);

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match recv_frame(&mut buf, &sock) {
            Ok((ControlFrame::HELLO(s), from)) => {
                println!("[HELLO] from {}:\n{}", from, s);
            }
            Ok((other, from)) => {
                println!("[listen_hello] got unexpected {:?} from {}", other_type(&other), from);
            }
            Err(e) => eprintln!("[listen_hello] recv error: {e}"),
        }
    }
}

/// Send a HELLO frame to <to>, building the message from the provided keys and timestamp.
pub fn send_hello(sk: &SigningKey, vk: &VerifyingKey, to: &str, ts_ms: u64) -> Result<()> {
    let sock = bind_udp("0.0.0.0:0")?;
    let hello = build_hello(sk, vk, ts_ms);
    let json = serde_json::to_string_pretty(&hello)?;
    let frame = ControlFrame::HELLO(json);
    send_frame(&sock, to, &frame)?;
    Ok(())
}

/// Listen for CONSENT control-plane frames (requests/responses).
/// Optional policies:
/// - Reputation
/// - Rate limiting
/// - Replay protection
/// Optional encryption: HSIP_ENC_KEY_HEX must be set (same key on both ends)
pub fn listen_control(addr: &str) -> Result<()> {
    let sock = bind_udp(addr)?;
    println!("[listen_control] bound to {}", addr);

    // Reputation policy
    let enforce_rep = std::env::var("HSIP_ENFORCE_REP").ok().as_deref() == Some("1");
    let threshold_env = std::env::var("HSIP_REP_THRESHOLD").ok();
    let threshold: i32 = threshold_env
        .as_deref()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(-6);

    // Rate limiting policy
    let rl_max: usize = std::env::var("HSIP_RL_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(30);
    let rl_window_ms: u64 = std::env::var("HSIP_RL_WINDOW_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let rl_ban_ms: u64 = std::env::var("HSIP_RL_BAN_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(30_000);
    let mut rl = RateLimiter::new(rl_max, rl_window_ms, rl_ban_ms);

    // Replay protection policy
    let rp_window_ms: u64 = std::env::var("HSIP_REPLAY_WINDOW_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(60_000);
    let rp_skew_ms: u64   = std::env::var("HSIP_TS_SKEW_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(30_000);
    let mut rp = ReplayGuard::new(rp_window_ms, rp_skew_ms);

    if enc_key_from_env().is_some() {
        println!("[ENC] encryption ENABLED (HSIP_ENC_KEY_HEX set)");
    } else {
        println!("[ENC] encryption OFF (set HSIP_ENC_KEY_HEX to enable)");
    }

    println!("[Replay] window={}ms skew={}ms", rp_window_ms, rp_skew_ms);

    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let (frame, from) = match recv_frame(&mut buf, &sock) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[listen_control] recv error: {e}");
                continue;
            }
        };

        // ---- Rate limit by source IP ----
        let now = Instant::now();
        if !rl.check_and_note(from.ip(), now) {
            eprintln!(
                "[RateLimit] drop from {} (max={} window={}ms ban={}ms)",
                from, rl_max, rl_window_ms, rl_ban_ms
            );
            continue;
        }

        match frame {
            ControlFrame::CONSENT_REQUEST(req) => {
                println!("[CONSENT_REQUEST] from {}", from);

                // ---- Replay protection (per requester) ----
                let now_ms_u64 = now_ms();
                if !rp.allow(&req.requester_peer_id, &req.nonce_hex, req.ts_ms, now_ms_u64) {
                    eprintln!(
                        "[Replay] drop requester={} nonce={} ts_ms={}",
                        req.requester_peer_id, req.nonce_hex, req.ts_ms
                    );
                    // Optionally: send a signed DENY here (commented out to stay quiet)
                    // let (sk, vk) = load_keypair().map_err(|e| anyhow!(e))?;
                    // let deny = build_response(&sk, &vk, &req, "deny", 0, now_ms_u64)?;
                    // let frame = ControlFrame::CONSENT_RESPONSE(deny);
                    // let wire = encrypt_if_enabled(&serde_json::to_vec(&frame)?)?;
                    // sock.send_to(&wire, from)?;
                    continue;
                }

                // ---- Reputation enforcement (optional) ----
                if enforce_rep {
                    if let Err(e) = maybe_deny_low_rep(&sock, &from, &req, threshold) {
                        eprintln!("[ListenerPolicy] enforcement error: {e}");
                        continue;
                    } else {
                        // handled (deny) or allowed (logged); prototype stops here
                        continue;
                    }
                }

                // Default: log fields (you can forward to your pipeline here)
                println!(
                    "[CONSENT_REQUEST] requester_peer_id={} purpose={} expires_ms={}",
                    req.requester_peer_id, req.purpose, req.expires_ms
                );
            }
            ControlFrame::CONSENT_RESPONSE(resp) => {
                println!(
                    "[CONSENT_RESPONSE] from {} decision={} ttl_ms={}",
                    from, resp.decision, resp.ttl_ms
                );
            }
            other => {
                println!("[listen_control] unexpected {:?} from {}", other_type(&other), from);
            }
        }
    }
}

/// Send a CONSENT_REQUEST over UDP to <to>.
pub fn send_consent_request(to: &str, req: &ConsentRequest) -> Result<()> {
    let sock = bind_udp("0.0.0.0:0")?;
    let frame = ControlFrame::CONSENT_REQUEST(req.clone());
    send_frame(&sock, to, &frame)
}

/// Send a CONSENT_RESPONSE over UDP to <to>.
pub fn send_consent_response(to: &str, resp: &ConsentResponse) -> Result<()> {
    let sock = bind_udp("0.0.0.0:0")?;
    let frame = ControlFrame::CONSENT_RESPONSE(resp.clone());
    send_frame(&sock, to, &frame)
}

// ========================= Enforcement helpers ================================

fn maybe_deny_low_rep(sock: &UdpSocket, from: &SocketAddr, req: &ConsentRequest, threshold: i32) -> Result<()> {
    let requester = req.requester_peer_id.clone();

    // Open log and compute score
    let log_path = format!(
        "{}/.hsip/reputation.log",
        dirs::home_dir()
            .ok_or_else(|| anyhow!("home dir not found"))?
            .to_string_lossy()
    );
    let store = Store::open(log_path)?;
    let score = store.compute_score(&requester).unwrap_or(0);

    if score < threshold {
        eprintln!(
            "[ListenerPolicy] requester {} score {} < {} → auto-deny",
            requester, score, threshold
        );

        // Build a signed DENY response and send back immediately
        let (sk, vk) = load_keypair().map_err(|e| anyhow!(e))?;
        let deny = build_response(&sk, &vk, req, "deny", 0, now_ms())
            .map_err(|e| anyhow!("build deny response: {e}"))?;
        let frame = ControlFrame::CONSENT_RESPONSE(deny);
        let wire = encrypt_if_enabled(&serde_json::to_vec(&frame)?)?;
        sock.send_to(&wire, from)?;

        // Append a policy event (best-effort)
        let my_peer = peer_id_from_pubkey(&vk);
        let _ = store.append(
            &sk,
            &my_peer,
            &requester,
            DecisionType::MISBEHAVIOR,
            1,
            "POLICY_THRESHOLD",
            "Listener auto-deny due to low reputation score",
            vec![],
            Some("7d".to_string()),
        );

        return Ok(());
    }

    println!(
        "[ListenerPolicy] requester {} score {} ≥ {} → allow",
        requester, score, threshold
    );
    Ok(())
}
