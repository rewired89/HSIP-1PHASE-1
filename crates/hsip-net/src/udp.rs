// crates/hsip-net/src/udp.rs

use anyhow::{anyhow, Context, Result};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use ed25519_dalek::Signer; // for sk.sign(...)
use hsip_core::consent::{verify_request, ConsentRequest, ConsentResponse};
use hsip_core::identity::{peer_id_from_pubkey, vk_to_hex};
use hsip_core::keystore::load_keypair;
use hsip_session::{Ephemeral, PeerLabel, Session};
use x25519_dalek::PublicKey as XPublicKey;

use hsip_reputation::store::Store;

use crate::guard::{Guard, GuardConfig as GuardCfg};

// === mini hello module exposed to hsip-cli ===
pub mod hello {
    use super::*;
    use crate::hello::build_hello; // internal module path

    pub fn listen_hello(addr: &str) -> Result<()> {
        let sock = UdpSocket::bind(addr).map_err(|e| anyhow!("bind hello listen: {e}"))?;
        sock.set_nonblocking(false)?;
        println!("[hello-listen] bound on {addr}");
        let mut buf = [0u8; 65535];
        loop {
            let (n, p) = sock.recv_from(&mut buf)?;
            let s = String::from_utf8_lossy(&buf[..n]);
            println!("[hello] from {p} {s}");
        }
    }

    pub fn send_hello(sk: &SigningKey, vk: &VerifyingKey, to: &str, now_ms: u64) -> Result<()> {
        let hello = build_hello(sk, vk, now_ms);
        let json = serde_json::to_vec(&hello)?;
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.send_to(&json, to)?;
        Ok(())
    }
}

// === Wire tags ===
const TAG_E1: u8 = 0xE1;
const TAG_E2: u8 = 0xE2;
const TAG_D:  u8 = 0xD0;

// Control-plane AAD
const AAD_CONTROL: &[u8] = b"type=CONTROL";

// Small helper to read effective policy from env
#[derive(Clone, Debug)]
struct PolicyCfg {
    enforce: bool,
    threshold: i32,
    log_path: PathBuf,
}

impl PolicyCfg {
    fn from_env() -> Self {
        let enforce = std::env::var("HSIP_ENFORCE_REP").ok().as_deref() == Some("1");
        let threshold = std::env::var("HSIP_REP_THRESHOLD")
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(-6);
        let log_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".hsip")
            .join("reputation.log");
        Self { enforce, threshold, log_path }
    }

    fn print_banner(&self) {
        let onoff = if self.enforce { "ON" } else { "OFF" };
        eprintln!(
            "[PolicyDebug] reputation enforcement {onoff} | threshold={} | log='{}'",
            self.threshold,
            self.log_path.display()
        );
        let require_sig = std::env::var("HSIP_REQUIRE_VALID_SIG").ok().as_deref() == Some("1");
        if require_sig {
            eprintln!("[PolicyDebug] signature requirement ON (HSIP_REQUIRE_VALID_SIG=1)");
        }
    }
}

// == Public entrypoints used by CLI ==
pub fn listen_control(addr: &str) -> Result<()> {
    // Guard config & banner
    let gcfg = GuardCfg { enable: true, ..Default::default() };
    let mut guard = Guard::new(gcfg);
    guard.debug_banner();

    // Effective policy (env-driven)
    let pcfg = PolicyCfg::from_env();
    pcfg.print_banner();

    // Bind UDP
    let sock = UdpSocket::bind(addr).map_err(|e| anyhow!("bind {addr}: {e}"))?;
    sock.set_nonblocking(true).ok();
    println!("[control-listen] bound on {addr}");

    // Wait for E1
    let mut buf = [0u8; 65535];
    let (_n, peer) = loop {
        match sock.recv_from(&mut buf) {
            Ok((n, p)) if n >= 1 + 32 && buf[0] == TAG_E1 => {
                guard.on_e1(p.ip()).ok();
                break (n, p)
            }
            Ok((_n, _p)) => continue,
            Err(ref e) if is_win_connreset(e) => { continue; }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(anyhow!("recv E1: {e}")),
        }
    };

    // Peer eph pub
    let mut peer_pub_bytes = [0u8; 32];
    peer_pub_bytes.copy_from_slice(&buf[1..33]);
    let peer_pub = XPublicKey::from(peer_pub_bytes);

    // Our eph + shared
    let eph = Ephemeral::generate();
    let our_pub = eph.public();
    let label = PeerLabel { label: b"CONSENTv1".to_vec() };
    let shared = eph.into_shared(&peer_pub);

    // Two sessions (rx/tx)
    let mut sess_rx = Session::from_shared_secret(shared, Some(&label));
    let mut sess_tx = Session::from_shared_secret(shared, Some(&label));

    // Send E2
    let mut e2 = [0u8; 1 + 32];
    e2[0] = TAG_E2;
    e2[1..].copy_from_slice(our_pub.as_bytes());
    sock.send_to(&e2, peer).ok();
    println!("[control-listen] handshake complete with {peer}");

    // Load identity (for auto-respond)
    let (sk, vk) = load_keypair().map_err(|e| anyhow!("load identity: {e}"))?;
    let _my_peer = peer_id_from_pubkey(&vk);

    // Open reputation store (lazy, on first use)
    let mut rep_store: Option<Store> = None;

    let mut rbuf = [0u8; 65535];
    loop {
        match sock.recv_from(&mut rbuf) {
            Ok((n, p)) if n >= 1 && rbuf[0] == TAG_D => {
                if let Err(reason) = guard.on_control_frame(p.ip(), n) {
                    eprintln!("[guard] drop control from {p}: {reason}");
                    continue;
                }
                let ct = &rbuf[1..n];
                match sess_rx.open(AAD_CONTROL, ct) {
                    Ok(pt) => {
                        // Try parse as request, else as response, else raw JSON
                        if let Ok(req) = serde_json::from_slice::<ConsentRequest>(&pt) {
                            println!(
                                "[control] CONSENT_REQUEST from {p}: purpose='{}' expires_ms={}",
                                req.purpose, req.expires_ms
                            );

                            // 1) Verify signature (if HSIP_REQUIRE_VALID_SIG=1, this will enforce)
                            let mut decision = "allow".to_string();
                            if let Err(err) = verify_request(&req) {
                                eprintln!("[Policy] invalid request signature → deny (err={err})");
                                guard.on_bad_sig(p.ip()).ok();
                                decision = "deny".into();
                            }

                            // 2) Reputation enforcement (env-driven)
                            if decision == "allow" && pcfg.enforce {
                                let requester = req.requester_peer_id.clone();
                                if requester.is_empty() {
                                    eprintln!("[Policy] enforcement ON but requester peer missing → deny");
                                    decision = "deny".into();
                                } else {
                                    // Open store once
                                    if rep_store.is_none() {
                                        rep_store = Some(
                                            Store::open(&pcfg.log_path)
                                                .with_context(|| format!("open rep log '{}'", pcfg.log_path.display()))?
                                        );
                                    }
                                    let store = rep_store.as_ref().unwrap();
                                    let score = store.compute_score(&requester).unwrap_or(0);
                                    eprintln!(
                                        "[PolicyDebug] requester '{}' score={} threshold={}",
                                        requester, score, pcfg.threshold
                                    );
                                    if score < pcfg.threshold {
                                        eprintln!(
                                            "[Policy] {} score {} < {} → deny",
                                            requester, score, pcfg.threshold
                                        );
                                        decision = "deny".into();
                                    } else {
                                        eprintln!(
                                            "[Policy] {} score {} ≥ {} → allow",
                                            requester, score, pcfg.threshold
                                        );
                                    }
                                }
                            }

                            // 3) Guard pin on allow
                            if decision == "allow" {
                                let requester = req.requester_peer_id.clone();
                                if !requester.is_empty() { guard.pin(&requester); }
                            }

                            // 4) Build & send response with the final decision
                            let resp = build_response_with_decision(&sk, &vk, &req, decision, 60_000)?;
                            let payload = serde_json::to_vec(&resp)?;
                            let ct = sess_tx.seal(AAD_CONTROL, &payload);
                            let mut pkt = Vec::with_capacity(1 + ct.len());
                            pkt.push(TAG_D);
                            pkt.extend_from_slice(&ct);
                            sock.send_to(&pkt, p).ok();
                            println!(
                                "[control-listen] auto-responded '{}' (ttl_ms={}) to {}",
                                resp.decision, resp.ttl_ms, p
                            );
                        } else if let Ok(resp) = serde_json::from_slice::<ConsentResponse>(&pt) {
                            println!(
                                "[control] CONSENT_RESPONSE from {p}: decision='{}' ttl_ms={} for={}",
                                resp.decision, resp.ttl_ms, resp.request_hash_hex
                            );
                        } else {
                            let s = String::from_utf8_lossy(&pt);
                            println!("[control] json: {s}");
                        }
                    }
                    Err(e) => eprintln!("[control] open error from {p}: {e:?}"),
                }
            }
            Ok((_n, _p)) => {}
            Err(ref e) if is_win_connreset(e) => { continue; }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                return Err(anyhow!("recv: {e}"));
            }
        }
    }
}

pub fn send_consent_request(to: &str, req: &ConsentRequest) -> Result<()> {
    let payload = serde_json::to_vec(req)?;
    sealed_send(to, &payload)
}

pub fn send_consent_response(to: &str, resp: &ConsentResponse) -> Result<()> {
    let payload = serde_json::to_vec(resp)?;
    sealed_send(to, &payload)
}

// == helpers ==

fn sealed_send(to: &str, payload: &[u8]) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(2000))).ok();

    // E1
    let eph = Ephemeral::generate();
    let our_pub = eph.public();
    let mut e1 = [0u8; 1 + 32];
    e1[0] = TAG_E1;
    e1[1..].copy_from_slice(our_pub.as_bytes());
    sock.send_to(&e1, to).map_err(|e| anyhow!("send E1: {e}"))?;

    // E2
    let mut buf = [0u8; 64];
    let (n, _peer) = sock.recv_from(&mut buf).map_err(|e| anyhow!("recv E2: {e}"))?;
    if n < 1 + 32 || buf[0] != TAG_E2 {
        return Err(anyhow!("unexpected handshake response"));
    }
    let mut srv_pub_bytes = [0u8; 32];
    srv_pub_bytes.copy_from_slice(&buf[1..33]);
    let srv_pub = XPublicKey::from(srv_pub_bytes);

    // Session
    let label = PeerLabel { label: b"CONSENTv1".to_vec() };
    let shared = eph.into_shared(&srv_pub);
    let mut sess = Session::from_shared_secret(shared, Some(&label));

    // Seal & send
    let ct = sess.seal(AAD_CONTROL, payload);
    let mut pkt = Vec::with_capacity(1 + ct.len());
    pkt.push(TAG_D);
    pkt.extend_from_slice(&ct);
    sock.send_to(&pkt, to).ok();
    println!("[control-send] sealed {} bytes → {}", payload.len(), to);
    Ok(())
}

fn is_win_connreset(e: &std::io::Error) -> bool {
    // Windows UDP may raise 10054 spuriously. Treat as ignorable.
    if let Some(code) = e.raw_os_error() { code == 10054 } else { false }
}

/// Build a CONSENT_RESPONSE bound to request hash with the chosen decision/ttl.
fn build_response_with_decision(
    sk: &SigningKey,
    vk: &VerifyingKey,
    req: &ConsentRequest,
    decision: String,
    ttl_ms: u64,
) -> Result<ConsentResponse> {
    use sha2::{Digest, Sha256};

    // canonical hash of the request json
    let req_bytes = serde_json::to_vec(req)?;
    let mut h = Sha256::new();
    h.update(&req_bytes);
    let request_hash_hex = hex::encode(h.finalize());

    // response struct
    let mut resp = ConsentResponse {
        version: 1,
        request_hash_hex,
        responder_peer_id: peer_id_from_pubkey(vk),
        responder_pub_key_hex: vk_to_hex(vk),
        decision,
        ttl_ms,
        sig_hex: String::new(),
        ts_ms: now_ms(),
    };

    // sign (payload = canonical json of resp without signature)
    let mut tmp = resp.clone(); tmp.sig_hex.clear();
    let payload = serde_json::to_string(&tmp)?;
    let sig = sk.sign(payload.as_bytes());
    resp.sig_hex = hex::encode(sig.to_bytes());
    Ok(resp)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}
