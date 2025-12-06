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

// === Wire protocol frame tags ===
const TAG_E1: u8 = 0xE1; // Initial ephemeral key exchange
const TAG_E2: u8 = 0xE2; // Response ephemeral key
const TAG_D: u8 = 0xD0; // Data frame

// === Reputation-based policy configuration ===
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

// === Cryptographic utilities ===

/// Generate a unique 4-byte salt for session initialization
fn random_salt() -> [u8; 4] {
    let mut salt = [0u8; 4];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive AEAD encryption key from X25519 shared secret using HKDF-SHA256
fn derive_session_key_from_shared(
    shared_secret: &[u8; 32],
    peer_label: &PeerLabel,
) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key_material = [0u8; 32];
    hk.expand(&peer_label.label, &mut key_material)
        .map_err(|_| anyhow!("HKDF key derivation failed"))?;
    Ok(key_material)
}

/// Create standard HSIP peer label for consent protocol
fn hsip_consent_label() -> PeerLabel {
    PeerLabel {
        label: b"CONSENTv1".to_vec(),
    }
}

// === Ephemeral key exchange structures ===

struct InitiatorHandshake {
    ephemeral: Ephemeral,
    our_public_key: x25519_dalek::PublicKey,
}

impl InitiatorHandshake {
    fn new() -> Self {
        let ephemeral = Ephemeral::generate();
        let our_public_key = ephemeral.public();
        Self {
            ephemeral,
            our_public_key,
        }
    }

    fn build_e1_packet(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(PREFIX_LEN + 1 + 32);
        write_prefix(&mut packet);
        packet.push(TAG_E1);
        packet.extend_from_slice(self.our_public_key.as_bytes());
        packet
    }

    fn complete_exchange(
        self,
        remote_public_key: &XPublicKey,
    ) -> Result<(ManagedSession, PeerLabel)> {
        let label = hsip_consent_label();
        let shared_secret = self.ephemeral.into_shared(remote_public_key)?;
        let session_key = derive_session_key_from_shared(&shared_secret, &label)?;
        let managed_session = ManagedSession::new(&session_key, random_salt());
        Ok((managed_session, label))
    }
}

struct ResponderHandshake {
    our_public_key: x25519_dalek::PublicKey,
    shared_secret: [u8; 32],
}

impl ResponderHandshake {
    fn from_received_e1(remote_e1_key: &XPublicKey) -> Result<Self> {
        let ephemeral = Ephemeral::generate();
        let our_public_key = ephemeral.public();
        let shared_secret = ephemeral.into_shared(remote_e1_key)?;
        Ok(Self {
            our_public_key,
            shared_secret,
        })
    }

    fn build_e2_packet(&self) -> Vec<u8> {
        let mut frame = [0u8; 1 + 32];
        frame[0] = TAG_E2;
        frame[1..].copy_from_slice(self.our_public_key.as_bytes());

        let mut packet = Vec::with_capacity(PREFIX_LEN + frame.len());
        write_prefix(&mut packet);
        packet.extend_from_slice(&frame);
        packet
    }

    fn finalize_sessions(self) -> Result<(ManagedSession, ManagedSession)> {
        let label = hsip_consent_label();
        let session_key = derive_session_key_from_shared(&self.shared_secret, &label)?;
        let rx_session = ManagedSession::new(&session_key, random_salt());
        let tx_session = ManagedSession::new(&session_key, random_salt());
        Ok((rx_session, tx_session))
    }
}

// === Decoy traffic for traffic analysis resistance ===

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
                        Err(ref e) if is_windows_connection_reset(e) => continue,
                        Err(e) => eprintln!("[decoy] recv error: {e}"),
                    }
                }
            }
            Err(e) => eprintln!("[decoy] bind failed on {}: {}", addr, e),
        }
    });
}

// === Main control plane listener ===
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

    // Wait for and parse E1 handshake initiation
    let (remote_peer_addr, remote_ephemeral_key) = receive_e1_initiation(&sock, &mut guard)?;

    // Perform responder-side handshake
    let handshake = ResponderHandshake::from_received_e1(&remote_ephemeral_key)?;
    let e2_packet = handshake.build_e2_packet();
    sock.send_to(&e2_packet, remote_peer_addr).ok();
    println!("[control-listen] handshake complete with {remote_peer_addr}");

    let (mut rx_session, mut tx_session) = handshake.finalize_sessions()?;

    // Load our identity for signing responses
    let (sk, vk) = load_keypair().map_err(|e| anyhow!("load identity: {e}"))?;

    // Main control message processing loop
    process_control_messages(
        &sock,
        &mut rx_session,
        &mut tx_session,
        &mut guard,
        &pcfg,
        &sk,
        &vk,
    )
}

/// Wait for and validate an E1 handshake initiation frame
fn receive_e1_initiation(
    sock: &UdpSocket,
    guard: &mut Guard,
) -> Result<(std::net::SocketAddr, XPublicKey)> {
    let mut buf = [0u8; 65535];

    let (frame_size, peer_addr) = loop {
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

    // Extract remote ephemeral public key
    let raw_frame = &buf[PREFIX_LEN..frame_size];
    let mut remote_key_bytes = [0u8; 32];
    remote_key_bytes.copy_from_slice(&raw_frame[1..33]);
    let remote_key = XPublicKey::from(remote_key_bytes);

    Ok((peer_addr, remote_key))
}

/// Main loop for processing encrypted control messages
fn process_control_messages(
    sock: &UdpSocket,
    rx_session: &mut ManagedSession,
    tx_session: &mut ManagedSession,
    guard: &mut Guard,
    policy: &PolicyCfg,
    signing_key: &SigningKey,
    verifying_key: &VerifyingKey,
) -> Result<()> {
    let mut reputation_store: Option<Store> = None;
    let mut receive_buffer = [0u8; 65535];
    let aad = aad_for(AAD_LABEL_E2);

    loop {
        match sock.recv_from(&mut receive_buffer) {
            Ok((n, peer_addr))
                if n > PREFIX_LEN
                    && check_prefix(&receive_buffer[..n])
                    && receive_buffer[PREFIX_LEN] == TAG_D =>
            {
                if let Err(reason) = guard.on_control_frame(peer_addr.ip(), n) {
                    eprintln!("[guard] drop control from {peer_addr}: {reason}");
                    continue;
                }

                // Decrypt and process the control message
                if let Some(plaintext) =
                    decrypt_control_frame(&receive_buffer[PREFIX_LEN..n], rx_session, &aad)
                {
                    handle_control_message(
                        plaintext,
                        peer_addr,
                        sock,
                        tx_session,
                        guard,
                        policy,
                        &mut reputation_store,
                        signing_key,
                        verifying_key,
                        &aad,
                    )?;
                }
            }

            Ok((_n, _p)) => {} // Ignore non-control frames

            Err(ref e) if is_windows_connection_reset(e) => continue,

            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }

            Err(e) => return Err(anyhow!("recv: {e}")),
        }
    }
}

/// Decrypt a control frame (TAG_D with counter + ciphertext)
fn decrypt_control_frame(
    raw_frame: &[u8],
    session: &mut ManagedSession,
    aad: &[u8],
) -> Option<Vec<u8>> {
    if raw_frame.len() < 9 {
        // Need at least TAG_D(1) + counter(8)
        return None;
    }

    let counter = u64::from_be_bytes(raw_frame[1..9].try_into().unwrap());
    let ciphertext = &raw_frame[9..];

    match session.decrypt(counter, ciphertext, aad) {
        Ok(plaintext) => Some(plaintext),
        Err(CoreSessionError::RekeyRequired) => {
            eprintln!("[control] session requires rekey (not implemented)");
            None
        }
        Err(e) => {
            eprintln!("[control] decrypt error: {e:?}");
            None
        }
    }
}

/// Process a decrypted control message (either request or response)
#[allow(clippy::too_many_arguments)]
fn handle_control_message(
    plaintext: Vec<u8>,
    peer_addr: std::net::SocketAddr,
    sock: &UdpSocket,
    tx_session: &mut ManagedSession,
    guard: &mut Guard,
    policy: &PolicyCfg,
    reputation_store: &mut Option<Store>,
    signing_key: &SigningKey,
    verifying_key: &VerifyingKey,
    aad: &[u8],
) -> Result<()> {
    // Try parsing as ConsentRequest
    if let Ok(request) = serde_json::from_slice::<ConsentRequest>(&plaintext) {
        println!(
            "[control] CONSENT_REQUEST from {peer_addr}: purpose='{}' expires_ms={}",
            request.purpose, request.expires_ms
        );

        let decision =
            evaluate_consent_request(&request, peer_addr, guard, policy, reputation_store)?;

        let response =
            build_response_with_decision(signing_key, verifying_key, &request, decision, 60_000)?;

        send_encrypted_response(sock, tx_session, &response, peer_addr, aad)?;
        return Ok(());
    }

    // Try parsing as ConsentResponse
    if let Ok(response) = serde_json::from_slice::<ConsentResponse>(&plaintext) {
        println!(
            "[control] CONSENT_RESPONSE from {peer_addr}: '{}' ttl_ms={} req={}",
            response.decision, response.ttl_ms, response.request_hash_hex
        );
        return Ok(());
    }

    // Unknown JSON message
    println!("[control] json: {}", String::from_utf8_lossy(&plaintext));
    Ok(())
}

/// Evaluate whether to grant or deny a consent request
fn evaluate_consent_request(
    request: &ConsentRequest,
    peer_addr: std::net::SocketAddr,
    guard: &mut Guard,
    policy: &PolicyCfg,
    reputation_store: &mut Option<Store>,
) -> Result<String> {
    let mut decision = "allow".to_string();

    // First check: signature validity
    if let Err(err) = verify_request(request) {
        eprintln!("[Policy] invalid signature → deny: {err}");
        guard.on_bad_sig(peer_addr.ip()).ok();
        decision = "deny".into();
    }

    // Second check: reputation-based filtering
    if decision == "allow" && policy.enforce {
        let requester_id = request.requester_peer_id.clone();

        if requester_id.is_empty() {
            decision = "deny".into();
        } else {
            // Lazy-load reputation store
            if reputation_store.is_none() {
                *reputation_store =
                    Some(Store::open(&policy.log_path).with_context(|| {
                        format!("open rep log '{}'", policy.log_path.display())
                    })?);
            }

            let score = reputation_store
                .as_ref()
                .unwrap()
                .compute_score(&requester_id)
                .unwrap_or(0);

            if score < policy.threshold {
                decision = "deny".into();
            }
        }
    }

    // If allowed, pin the requester for guard
    if decision == "allow" {
        let requester_id = request.requester_peer_id.clone();
        if !requester_id.is_empty() {
            guard.pin(&requester_id);
        }
    }

    Ok(decision)
}

/// Encrypt and send a ConsentResponse back to the requester
fn send_encrypted_response(
    sock: &UdpSocket,
    session: &mut ManagedSession,
    response: &ConsentResponse,
    dest: std::net::SocketAddr,
    aad: &[u8],
) -> Result<()> {
    let response_json = serde_json::to_vec(response)?;

    let (counter, ciphertext) = session
        .encrypt(&response_json, aad)
        .map_err(|e| anyhow!("encrypt response: {:?}", e))?;

    let mut packet = Vec::with_capacity(PREFIX_LEN + 1 + 8 + ciphertext.len());
    write_prefix(&mut packet);
    packet.push(TAG_D);
    packet.extend_from_slice(&counter.to_be_bytes());
    packet.extend_from_slice(&ciphertext);

    sock.send_to(&packet, dest).ok();
    Ok(())
}

// === CLIENT-SIDE FUNCTIONS ===

pub fn send_consent_request(to: &str, req: &ConsentRequest) -> Result<()> {
    let payload = serde_json::to_vec(req)?;
    perform_client_exchange(to, &payload)
}

pub fn send_consent_response(to: &str, resp: &ConsentResponse) -> Result<()> {
    let payload = serde_json::to_vec(resp)?;
    perform_client_exchange(to, &payload)
}

/// Perform client-side handshake and send encrypted payload
fn perform_client_exchange(server_addr: &str, payload: &[u8]) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(2000)))
        .ok();

    // Initiate handshake with E1
    let handshake = InitiatorHandshake::new();
    let e1_packet = handshake.build_e1_packet();
    sock.send_to(&e1_packet, server_addr)?;

    // Receive E2 response
    let server_ephemeral_key = receive_e2_response(&sock)?;

    // Complete handshake and get session
    let (mut session, _label) = handshake.complete_exchange(&server_ephemeral_key)?;

    // Encrypt and send the payload
    let aad = aad_for(AAD_LABEL_E2);
    let (counter, ciphertext) = session
        .encrypt(payload, &aad)
        .map_err(|e| anyhow!("encrypt: {:?}", e))?;

    let mut data_packet = Vec::with_capacity(PREFIX_LEN + 1 + 8 + ciphertext.len());
    write_prefix(&mut data_packet);
    data_packet.push(TAG_D);
    data_packet.extend_from_slice(&counter.to_be_bytes());
    data_packet.extend_from_slice(&ciphertext);

    sock.send_to(&data_packet, server_addr)?;
    Ok(())
}

/// Receive and validate E2 handshake response from server
fn receive_e2_response(sock: &UdpSocket) -> Result<XPublicKey> {
    let mut buf = [0u8; 64];
    let (received_bytes, _) = sock.recv_from(&mut buf)?;

    if received_bytes < PREFIX_LEN + 33 || !check_prefix(&buf[..received_bytes]) {
        return Err(anyhow!("invalid E2 frame format"));
    }

    let frame_data = &buf[PREFIX_LEN..received_bytes];
    if frame_data[0] != TAG_E2 {
        return Err(anyhow!("expected E2 tag, got {:#x}", frame_data[0]));
    }

    let mut server_key_bytes = [0u8; 32];
    server_key_bytes.copy_from_slice(&frame_data[1..33]);
    Ok(XPublicKey::from(server_key_bytes))
}

// === Platform-specific error handling ===

/// Check if error is Windows-specific connection reset (WSAECONNRESET)
fn is_windows_connection_reset(e: &std::io::Error) -> bool {
    if let Some(code) = e.raw_os_error() {
        code == 10054 // WSAECONNRESET on Windows
    } else {
        false
    }
}

// === Response construction ===

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
        ts_ms: current_timestamp_ms(),
    };

    let mut tmp = resp.clone();
    tmp.sig_hex.clear();
    let payload = serde_json::to_string(&tmp)?;

    let sig = sk.sign(payload.as_bytes());
    resp.sig_hex = hex::encode(sig.to_bytes());
    Ok(resp)
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
