use anyhow::{anyhow, Context, Result};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::Signer;
use ed25519_dalek::{SigningKey, VerifyingKey};

use hsip_core::consent::{verify_request, ConsentRequest, ConsentResponse};
use hsip_core::crypto::labels::{aad_for, AAD_LABEL_E2};
use hsip_core::identity::{peer_id_from_pubkey, vk_to_hex};
use hsip_core::keystore::load_keypair;
use hsip_core::session::{ManagedSession, SessionError as CoreSessionError};
use hsip_core::wire::prefix::{check_prefix, write_prefix, PREFIX_LEN};

use hsip_session::{Ephemeral, PeerLabel};
use x25519_dalek::PublicKey as XPublicKey;

use hsip_reputation::store::Store;

use crate::guard::{Guard, GuardConfig as GuardCfg};

use rand::rngs::OsRng;
use rand::RngCore;

use hkdf::Hkdf;
use sha2::Sha256;

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
            if n < PREFIX_LEN || !hsip_core::wire::prefix::check_prefix(&buf[..n]) {
                // ignore non-HSIP packets
                continue;
            }
            let raw = &buf[PREFIX_LEN..n]; // strip HSIP prefix
            let s = String::from_utf8_lossy(raw);
            println!("[hello] from {p} {s}");
        }
    }

    pub fn send_hello(sk: &SigningKey, vk: &VerifyingKey, to: &str, now_ms: u64) -> Result<()> {
        let hello = build_hello(sk, vk, now_ms);
        let json = serde_json::to_vec(&hello)?;
        let sock = UdpSocket::bind("0.0.0.0:0")?;

        // add HSIP prefix
        let mut pkt = Vec::with_capacity(PREFIX_LEN + json.len());
        hsip_core::wire::prefix::write_prefix(&mut pkt);
        pkt.extend_from_slice(&json);

        sock.send_to(&pkt, to)?;
        Ok(())
    }
}

// === Wire tags ===
const TAG_E1: u8 = 0xE1;
const TAG_E2: u8 = 0xE2;
const TAG_D: u8 = 0xD0;

// === Policy config ===
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

        Self {
            enforce,
            threshold,
            log_path,
        }
    }

    fn print_banner(&self) {
        let onoff = if self.enforce { "ON" } else { "OFF" };
        eprintln!(
            "[PolicyDebug] reputation enforcement {onoff} | threshold={} | log='{}'",
            self.threshold,
            self.log_path.display()
        );

        if std::env::var("HSIP_REQUIRE_VALID_SIG").ok().as_deref() == Some("1") {
            eprintln!("[PolicyDebug] signature requirement ON (HSIP_REQUIRE_VALID_SIG=1)");
        }
    }
}

fn random_salt() -> [u8; 4] {
    let mut salt = [0u8; 4];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn spawn_decoy_if_env() {
    let addr = match std::env::var("HSIP_DECOY_ADDR") {
        Ok(v) if !v.is_empty() => v,
        _ => return,
    };

    std::thread::spawn(move || {
        match UdpSocket::bind(&addr) {
            Ok(sock) => {
                eprintln!("[decoy] HSIP decoy bound on {}", addr);
                let mut buf = [0u8; 2048];
                let mut tick = 0u64;

                loop {
                    match sock.recv_from(&mut buf) {
                        Ok((n, p)) => {
                            tick = tick.wrapping_add(1);
                            let delay_ms = 2 + ((n as u64 + tick) % 7);
                            std::thread::sleep(Duration::from_millis(delay_ms));

                            // Send malformed HSIP-looking packet
                            let mut pkt = Vec::with_capacity(PREFIX_LEN + 1 + 16);
                            write_prefix(&mut pkt);
                            pkt.push(0xFF);
                            let pad_len = 8 + (n & 0x07);
                            pkt.resize(pkt.len() + pad_len, 0);

                            let _ = sock.send_to(&pkt, p);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(ref e) if is_win_connreset(e) => continue,
                        Err(e) => eprintln!("[decoy] recv error: {e}"),
                    }
                }
            }
            Err(e) => eprintln!("[decoy] bind failed on {}: {}", addr, e),
        }
    });
}

// === CONTROL LISTEN ===
pub fn listen_control(addr: &str) -> Result<()> {
    let mut guard = Guard::new(GuardCfg {
        enable: true,
        ..Default::default()
    });
    guard.debug_banner();

    let pcfg = PolicyCfg::from_env();
    pcfg.print_banner();

    let sock = UdpSocket::bind(addr).map_err(|e| anyhow!("bind {addr}: {e}"))?;
    sock.set_nonblocking(true).ok();
    println!("[control-listen] bound on {addr}");

    spawn_decoy_if_env();

    // === WAIT FOR E1 ===
    let mut buf = [0u8; 65535];
    let (_n, peer) = loop {
        match sock.recv_from(&mut buf) {
            Ok((n, p))
                if n > PREFIX_LEN + 32 && check_prefix(&buf[..n]) && buf[PREFIX_LEN] == TAG_E1 =>
            {
                let _ = guard.on_e1(p.ip());
                break (n, p);
            }
            Ok(_) => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(_) => continue,
        }
    };

    // === Parse E1 ===
    let raw = &buf[PREFIX_LEN.._n];
    let mut peer_pub_bytes = [0u8; 32];
    peer_pub_bytes.copy_from_slice(&raw[1..33]);
    let peer_pub = XPublicKey::from(peer_pub_bytes);

    // === X25519 ephemeral → shared secret ===
    let eph = Ephemeral::generate();
    let our_pub = eph.public();

    let label = PeerLabel {
        label: b"CONSENTv1".to_vec(),
    };

    let shared = eph.into_shared(&peer_pub)?;

    // === Derive AEAD key via HKDF ===
    let key_bytes = {
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut okm = [0u8; 32];
        hk.expand(&label.label, &mut okm)
            .map_err(|_| anyhow!("kdf expand"))?;
        okm
    };

    let mut managed = ManagedSession::new(&key_bytes, random_salt());

    // === Send E2 ===
    let mut e2 = [0u8; 1 + 32];
    e2[0] = TAG_E2;
    e2[1..].copy_from_slice(our_pub.as_bytes());

    let mut pkt = Vec::with_capacity(PREFIX_LEN + e2.len());
    write_prefix(&mut pkt);
    pkt.extend_from_slice(&e2);
    sock.send_to(&pkt, peer).ok();

    println!("[control-listen] handshake complete with {peer}");

    // Load identity
    let (sk, vk) = load_keypair().map_err(|e| anyhow!("load identity: {e}"))?;
    let _my_peer = peer_id_from_pubkey(&vk);

    let mut rep_store: Option<Store> = None;
    let mut rbuf = [0u8; 65535];

    // === MAIN LOOP ===
    loop {
        match sock.recv_from(&mut rbuf) {
            Ok((n, p))
                if n > PREFIX_LEN && check_prefix(&rbuf[..n]) && rbuf[PREFIX_LEN] == TAG_D =>
            {
                if let Err(reason) = guard.on_control_frame(p.ip(), n) {
                    eprintln!("[guard] drop control from {p}: {reason}");
                    continue;
                }

                // New frame format: TAG_D | counter(8) | ciphertext...
                let raw = &rbuf[PREFIX_LEN + 1..n];
                if raw.len() < 8 {
                    eprintln!("[control] short frame from {p}");
                    continue;
                }

                let counter = u64::from_be_bytes(raw[0..8].try_into().unwrap());
                let ciphertext = &raw[8..];
                let aad = aad_for(AAD_LABEL_E2);

                match managed.decrypt(counter, ciphertext, &aad) {
                    Ok(pt) => {
                        // Try REQUEST
                        if let Ok(req) = serde_json::from_slice::<ConsentRequest>(&pt) {
                            println!(
                                "[control] CONSENT_REQUEST from {p}: purpose='{}' expires_ms={}",
                                req.purpose, req.expires_ms
                            );

                            let mut decision = "allow".to_string();

                            // Verify Sig
                            if let Err(err) = verify_request(&req) {
                                eprintln!("[Policy] invalid signature → deny: {err}");
                                guard.on_bad_sig(p.ip()).ok();
                                decision = "deny".into();
                            }

                            // Reputation
                            if decision == "allow" && pcfg.enforce {
                                let requester = req.requester_peer_id.clone();

                                if requester.is_empty() {
                                    decision = "deny".into();
                                } else {
                                    if rep_store.is_none() {
                                        rep_store = Some(
                                            Store::open(&pcfg.log_path).with_context(|| {
                                                format!(
                                                    "open rep log '{}'",
                                                    pcfg.log_path.display()
                                                )
                                            })?,
                                        );
                                    }

                                    let score = rep_store
                                        .as_ref()
                                        .unwrap()
                                        .compute_score(&requester)
                                        .unwrap_or(0);

                                    if score < pcfg.threshold {
                                        decision = "deny".into();
                                    }
                                }
                            }

                            if decision == "allow" {
                                let requester = req.requester_peer_id.clone();
                                if !requester.is_empty() {
                                    guard.pin(&requester);
                                }
                            }

                            // Build response
                            let resp =
                                build_response_with_decision(&sk, &vk, &req, decision, 60_000)?;

                            let payload = serde_json::to_vec(&resp)?;

                            let (ctr2, ct2) = managed
                                .encrypt(&payload, &aad)
                                .map_err(|e| anyhow!("{:?}", e))?;

                            let mut pkt = Vec::with_capacity(PREFIX_LEN + 1 + 8 + ct2.len());
                            write_prefix(&mut pkt);
                            pkt.push(TAG_D);
                            pkt.extend_from_slice(&ctr2.to_be_bytes());
                            pkt.extend_from_slice(&ct2);

                            sock.send_to(&pkt, p).ok();

                        // RESPONSE
                        } else if let Ok(resp) = serde_json::from_slice::<ConsentResponse>(&pt) {
                            println!(
                                "[control] CONSENT_RESPONSE from {p}: '{}' ttl_ms={} req={}",
                                resp.decision, resp.ttl_ms, resp.request_hash_hex
                            );
                        } else {
                            println!("[control] json: {}", String::from_utf8_lossy(&pt));
                        }
                    }

                    Err(CoreSessionError::RekeyRequired) => {
                        eprintln!("[control] session requires rekey (todo)");
                    }

                    Err(e) => eprintln!("[control] decrypt error from {p}: {e:?}"),
                }
            }

            // ignore non-HSIP
            Ok((_n, _p)) => {}

            Err(ref e) if is_win_connreset(e) => continue,

            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }

            Err(e) => return Err(anyhow!("recv: {e}")),
        }
    }
}

// === CLIENT SEND ===
pub fn send_consent_request(to: &str, req: &ConsentRequest) -> Result<()> {
    sealed_send(to, &serde_json::to_vec(req)?)
}

pub fn send_consent_response(to: &str, resp: &ConsentResponse) -> Result<()> {
    sealed_send(to, &serde_json::to_vec(resp)?)
}

// === CLIENT IMPLEMENTATION (E1/E2 + TAG_D) ===
fn sealed_send(to: &str, payload: &[u8]) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(2000)))
        .ok();

    // === E1 ===
    let eph = Ephemeral::generate();
    let our_pub = eph.public();

    let mut e1 = [0u8; 33];
    e1[0] = TAG_E1;
    e1[1..33].copy_from_slice(our_pub.as_bytes());

    let mut pkt_e1 = Vec::with_capacity(PREFIX_LEN + 33);
    write_prefix(&mut pkt_e1);
    pkt_e1.extend_from_slice(&e1);

    sock.send_to(&pkt_e1, to)?;

    // === E2 ===
    let mut buf = [0u8; 64];
    let (n, _) = sock.recv_from(&mut buf)?;

    if n < PREFIX_LEN + 33 || !check_prefix(&buf[..n]) {
        return Err(anyhow!("invalid E2"));
    }

    let raw = &buf[PREFIX_LEN..n];
    if raw[0] != TAG_E2 {
        return Err(anyhow!("unexpected tag in E2"));
    }

    let mut srv_pub_bytes = [0u8; 32];
    srv_pub_bytes.copy_from_slice(&raw[1..33]);
    let srv_pub = XPublicKey::from(srv_pub_bytes);

    let label = PeerLabel {
        label: b"CONSENTv1".to_vec(),
    };

    let shared = eph.into_shared(&srv_pub)?;

    let key_bytes = {
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut okm = [0u8; 32];
        hk.expand(&label.label, &mut okm)
            .map_err(|_| anyhow!("kdf expand"))?;
        okm
    };

    let mut managed = ManagedSession::new(&key_bytes, random_salt());
    let aad = aad_for(AAD_LABEL_E2);

    let (ctr, ct) = managed
        .encrypt(payload, &aad)
        .map_err(|e| anyhow!("encrypt: {:?}", e))?;

    let mut pkt = Vec::with_capacity(PREFIX_LEN + 1 + 8 + ct.len());
    write_prefix(&mut pkt);
    pkt.push(TAG_D);
    pkt.extend_from_slice(&ctr.to_be_bytes());
    pkt.extend_from_slice(&ct);

    sock.send_to(&pkt, to)?;
    Ok(())
}

// === OS UDP weirdness on Windows ===
fn is_win_connreset(e: &std::io::Error) -> bool {
    if let Some(code) = e.raw_os_error() {
        code == 10054
    } else {
        false
    }
}

// === Build Consent Response ===
fn build_response_with_decision(
    sk: &SigningKey,
    vk: &VerifyingKey,
    req: &ConsentRequest,
    decision: String,
    ttl_ms: u64,
) -> Result<ConsentResponse> {
    use sha2::{Digest, Sha256};

    let req_bytes = serde_json::to_vec(req)?;
    let mut h = Sha256::new();
    h.update(&req_bytes);

    let request_hash_hex = hex::encode(h.finalize());

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

    let mut tmp = resp.clone();
    tmp.sig_hex.clear();
    let payload = serde_json::to_string(&tmp)?;

    let sig = sk.sign(payload.as_bytes());
    resp.sig_hex = hex::encode(sig.to_bytes());
    Ok(resp)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
