use clap::{Parser, Subcommand};
use hsip_session::persistence as session_persist;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};

use hsip_core::consent::{
    build_request, build_response, cid_hex, verify_request, verify_response, ConsentRequest,
    ConsentResponse,
};
use hsip_core::identity::{generate_keypair, peer_id_from_pubkey, sk_to_hex, vk_to_hex};
use hsip_core::keystore::{load_keypair, save_keypair};

use hsip_net::hello::build_hello;
use hsip_net::udp::hello::{listen_hello, send_hello};
use hsip_net::udp::{send_consent_request, send_consent_response};

// NEW: tiny local consent HTTP + helpers (user-mode, no admin)
use std::io::Read;
use std::process::Command;
use std::thread;
use std::time::Duration;

// NEW: passwordless device identity + consent tokens
use hsip_auth::{identity as auth_identity, tokens as auth_tokens};

// NEW: status/daemon API module (adds /status endpoints, etc.)
mod daemon;

// New commands module
mod commands;

// NEW: identity web demo (serves /status, /token, /demo on 127.0.0.1:9100)
mod identity;

use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::Rng; // for try_fill
use rpassword::prompt_password;

use rand::RngCore;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::net::UdpSocket as StdUdpSocket;

// session demo + wait-reply
use hsip_session::{Ephemeral, PeerLabel, Session};
use x25519_dalek::PublicKey as XPublicKey;

// NEW: helper modules (existing)
mod cmd_rep;
mod config;
mod discovery;
mod rekey;
mod token;

// ===== Unified labels/AAD =====
const LABEL_CONSENT_V1: &[u8] = b"CONSENTv1";
const AAD_CONTROL: &[u8] = b"type=CONTROL";
const AAD_DATA: &[u8] = b"type=DATA";
const AAD_PING: &[u8] = b"type=PING";

// wire tags
const TAG_E1: u8 = 0xE1;
const TAG_E2: u8 = 0xE2;
const TAG_D: u8 = 0xD0;

// NEW: local consent HTTP bind (tray-lite)
pub const CONSENT_HTTP_ADDR: &str = "127.0.0.1:9389";

// NEW: local demo HSIP-aware website
pub const DEMO_HTTP_ADDR: &str = "127.0.0.1:8080";

#[derive(Parser)]
#[command(name = "hsip", version, about = "HSIP command-line (v0.2.0-mvp)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // --- Identity ---
    /// Generate a new identity (prints keys)
    Keygen,
    /// Generate and save identity to keystore
    Init,
    /// Show my PeerID and public key
    Whoami,

    /// Export identity to plaintext JSON (keep private!)
    KeyExport {
        #[arg(long)]
        out: Option<String>,
    },

    /// Import identity from plaintext JSON
    KeyImport {
        #[arg(long)]
        file: String,
    },

    /// Export identity encrypted with a passphrase (Argon2id + ChaCha20-Poly1305)
    KeyExportEnc {
        #[arg(long)]
        out: Option<String>,
    },

    /// Import encrypted identity (prompts for passphrase)
    KeyImportEnc {
        #[arg(long)]
        file: String,
    },

    // --- Key lifecycle ---
    /// Create and persist a signed revocation record for current key
    Revoke {
        #[arg(long, default_value = "compromised or rotation")]
        reason: String,
        #[arg(long, default_value = "revocation.json")]
        out: String,
    },

    /// Rotate to a fresh keypair and emit an identity continuity proof
    RotateKey {
        #[arg(long, default_value = "rebind.json")]
        out: String,
    },

    // --- Hello ---
    /// Print a signed HELLO JSON to stdout
    Hello,

    /// Listen for HELLO frames on UDP and print them
    #[command(name = "hello-listen", aliases = ["listen"])]
    HelloListen {
        #[arg(long, default_value = "0.0.0.0:40404")]
        addr: String,
    },

    /// Send a HELLO frame to a UDP endpoint
    #[command(name = "hello-send", aliases = ["send"])]
    HelloSend {
        #[arg(long)]
        to: String,
    },

    /// Low-level HSIP HELLO handshake listener (new path)
    #[command(name = "handshake-listen")]
    HandshakeListen {
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,
    },

    /// Low-level HSIP HELLO handshake connector (new path)
    #[command(name = "handshake-connect")]
    HandshakeConnect {
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,
    },

    // --- Consent (local) ---
    ConsentRequest {
        #[arg(long)]
        file: String,
        #[arg(long)]
        purpose: String,
        #[arg(long)]
        expires_ms: u64,
        #[arg(long, default_value = "consent_request.json")]
        out: String,
    },
    ConsentVerify {
        #[arg(long, default_value = "consent_request.json")]
        file: String,
    },

    // --- Consent over UDP ---
    /// Sealed control-plane listener (auto-respond allow/deny)
    ConsentListen {
        #[arg(long, default_value = "0.0.0.0:40405")]
        addr: String,
        #[arg(long, default_value_t = false)]
        enforce_rep: bool,
        #[arg(long, default_value_t = -6)]
        threshold: i32,

        // cover toggles
        #[arg(long, default_value_t = false)]
        cover: bool,
        #[arg(long, default_value_t = 90)]
        cover_rate_per_min: u32,
        #[arg(long, default_value_t = 256)]
        cover_min_size: usize,
        #[arg(long, default_value_t = 1200)]
        cover_max_size: usize,
        #[arg(long, default_value_t = 800)]
        cover_jitter_ms: u64,
        #[arg(long, default_value_t = 0u64)]
        cover_verbose_every: u64,

        // auto decision (for test/demo)
        #[arg(long, default_value = "allow")]
        decision: String,
        #[arg(long, default_value_t = 30000)]
        ttl_ms: u64,
    },

    ConsentSendRequest {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "req.json")]
        file: String,
        #[arg(long, default_value_t = false)]
        wait_reply: bool,
        #[arg(long, default_value_t = 3000)]
        wait_timeout_ms: u64,
    },
    ConsentSendResponse {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "resp.json")]
        file: String,
    },

    /// Create and sign a CONSENT_RESPONSE for a request JSON (local)
    ConsentRespond {
        #[arg(long, default_value = "req.json")]
        request: String,
        #[arg(long)]
        decision: String,
        #[arg(long, default_value_t = 0)]
        ttl_ms: u64,
        #[arg(long, default_value = "resp.json")]
        out: String,
        #[arg(long, default_value_t = false)]
        enforce_rep: bool,
        #[arg(long)]
        requester_peer: Option<String>,
        #[arg(long, default_value_t = -6)]
        threshold: i32,
    },
    ConsentVerifyResponse {
        #[arg(long, default_value = "req.json")]
        request: String,
        #[arg(long, default_value = "resp.json")]
        response: String,
    },

    // --- Session demo (sealed UDP) ---
    /// Minimal UDP session listener: eph X25519 handshake, then opens sealed frames.
    SessionListen {
        #[arg(long, default_value = "127.0.0.1:50505")]
        addr: String,
        #[arg(long, default_value_t = false)]
        cover: bool,
        #[arg(long, default_value_t = 60)]
        cover_rate_per_min: u32,
        #[arg(long, default_value_t = 256)]
        cover_min_size: usize,
        #[arg(long, default_value_t = 1200)]
        cover_max_size: usize,
        #[arg(long, default_value_t = 800)]
        cover_jitter_ms: u64,
        #[arg(long, default_value_t = 20u64)]
        cover_verbose_every: u64,
    },

    /// Minimal UDP session sender: handshakes with listener, then sends sealed frames.
    SessionSend {
        #[arg(long, default_value = "127.0.0.1:50505")]
        to: String,
        #[arg(long, default_value_t = 10)]
        packets: u32,
        #[arg(long, default_value_t = 128)]
        min_size: usize,
        #[arg(long, default_value_t = 512)]
        max_size: usize,
    },

    // --- Privacy Ping ---
    PingListen {
        #[arg(long, default_value = "127.0.0.1:51515")]
        addr: String,
    },
    Ping {
        #[arg(long, default_value = "127.0.0.1:51515")]
        to: String,
        #[arg(long, default_value_t = 5)]
        count: u32,
        #[arg(long, default_value_t = 64)]
        size: usize,
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
    },

    // --- Session persistence helpers ---
    SessionSave {
        #[arg(long)]
        name: String,
        #[arg(long)]
        file: String,
    },
    SessionLoad {
        #[arg(long)]
        name: String,
        #[arg(long)]
        out: String,
    },

    // --- Tokens ---
    /// Issue a time-limited capability token for a grantee
    TokenIssue {
        #[arg(long)]
        grantee: String,
        /// CSV of capabilities (Voice,FileTransfer,Session,Hello,Ping)
        #[arg(long, default_value = "Session")]
        caps: String,
        #[arg(long, default_value_t = 30_000)]
        ttl_ms: u64,
        #[arg(long, default_value = "token.json")]
        out: String,
    },

    /// Verify a token against issuer pubkey hex
    TokenVerify {
        #[arg(long, default_value = "token.json")]
        file: String,
        #[arg(long)]
        issuer_vk_hex: String,
    },

    /// Verify a local device token (JWT-EdDSA) using `kid` from header; input via --token or --file.
    TokenVerifyLocal {
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        file: Option<String>,
    },

    // --- Discovery (static directory prototype) ---
    DiscoverList,
    DiscoverAdd {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        addr: String,
    },
    DiscoverRemove {
        #[arg(long)]
        peer: String,
    },

    // --- Reputation ---
    Rep(cmd_rep::RepArgs),

    // --- Daemon / Status API ---
    /// Start local status API (e.g. 127.0.0.1:8787) for tray/extension
    Daemon {
        #[arg(long, default_value = "127.0.0.1:8787")]
        status_addr: String,
    },

    // --- Identity Web Demo ---
    /// Run local HSIP Identity Broker (serves /demo on 127.0.0.1:9100)
    IdentityServe,

    // NEW: User-mode tray-lite: silent identity + spawn daemon + /consent HTTP
    /// Start user-mode tray-lite (no admin): ensures identity, spawns daemon, serves /consent on 127.0.0.1:9389
    Tray,

    // NEW: HSIP demo website (local-only)
    /// Run local HSIP demo site on 127.0.0.1:8080 for testing HSIP-aware pages
    DemoSite,

    /// Print HSIP diagnostic info (identity, config, env, endpoints)
    Diag,
}

fn main() {
    if let Err(e) = config::apply() {
        eprintln!("[CFG] warning: {e}");
    }
    let cli = Cli::parse();

    match cli.command {
        // ===== Identity =====
        Commands::Keygen => {
            let (sk, vk) = generate_keypair();
            let peer_id = peer_id_from_pubkey(&vk);
            println!("[IDENT] PeerID: {}", peer_id);
            println!("[IDENT] PublicKey(hex): {}", vk_to_hex(&vk));
            println!("[IDENT] SecretKey(hex): {}", sk_to_hex(&sk));
            println!("\nNOTE: Keep SecretKey private.");
        }
        Commands::Init => {
            let (sk, vk) = generate_keypair();
            let peer_id = peer_id_from_pubkey(&vk);
            save_keypair(&sk, &vk).expect("save keystore");
            println!("[IDENT] Saved identity. PeerID: {}", peer_id);
            println!("[IDENT] Tip: also run `hsip key-export-enc` to keep an encrypted backup.");
        }
        Commands::Whoami => match load_keypair() {
            Ok((_sk, vk)) => {
                let pid = peer_id_from_pubkey(&vk);
                println!("[IDENT] PeerID: {}", pid);
                println!("[IDENT] PublicKey(hex): {}", vk_to_hex(&vk));
            }
            Err(e) => eprintln!("[IDENT] No identity found: {e}"),
        },

        // ----- Plain export/import -----
        Commands::KeyExport { out } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            let peer_id = peer_id_from_pubkey(&vk);
            let default_out: PathBuf = dirs::home_dir().unwrap().join(".hsip").join("id.json");
            let out_path = out.map(PathBuf::from).unwrap_or(default_out);
            let json = serde_json::json!({
                "version": 1, "peer_id": peer_id,
                "sk_hex": sk_to_hex(&sk), "vk_hex": vk_to_hex(&vk),
                "note": "KEEP THIS FILE PRIVATE. Anyone with sk_hex can impersonate you."
            });
            fs::create_dir_all(out_path.parent().unwrap()).ok();
            fs::write(&out_path, serde_json::to_string_pretty(&json).unwrap())
                .expect("write export");
            println!("[IDENT] Exported identity to {}", out_path.display());
        }
        Commands::KeyImport { file } => {
            let s = fs::read_to_string(&file).expect("read identity json");
            let v: serde_json::Value = serde_json::from_str(&s).expect("parse json");
            let sk_hex = v
                .get("sk_hex")
                .and_then(|x| x.as_str())
                .expect("missing sk_hex");
            let sk_bytes = hex::decode(sk_hex).expect("sk_hex decode");
            assert_eq!(sk_bytes.len(), 32, "sk_hex must be 32 bytes");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&sk_bytes);
            let sk = SigningKey::from_bytes(&arr);
            let vk = VerifyingKey::from(&sk);
            save_keypair(&sk, &vk).expect("save keystore");
            let pid = peer_id_from_pubkey(&vk);
            println!("[IDENT] Imported identity. PeerID: {}", pid);
        }

        // ----- Encrypted export/import -----
        Commands::KeyExportEnc { out } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            let peer_id = peer_id_from_pubkey(&vk);
            let default_out: PathBuf = dirs::home_dir().unwrap().join(".hsip").join("id.enc.json");
            let out_path = out.map(PathBuf::from).unwrap_or(default_out);
            let pass = prompt_password("Passphrase: ").expect("read pass");
            let pass2 = prompt_password("Repeat passphrase: ").expect("read pass2");
            if pass != pass2 {
                eprintln!("Passphrases do not match.");
                return;
            }
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let ph = argon2
                .hash_password(pass.as_bytes(), &salt)
                .expect("argon2 hash");
            let hash_str = ph.hash.unwrap();
            let key_material = hash_str.as_bytes();
            assert!(key_material.len() >= 32);
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&key_material[..32]);
            let key = Key::from(key_bytes);
            let cipher = ChaCha20Poly1305::new(&key);
            let mut nonce_bytes = [0u8; 12];
            OsRng.try_fill(&mut nonce_bytes).expect("nonce");
            let nonce = Nonce::from(nonce_bytes);
            let sk_hex = sk_to_hex(&sk);
            let ct = cipher.encrypt(&nonce, sk_hex.as_bytes()).expect("encrypt");
            let out_json = serde_json::json!({
                "version": 1, "peer_id": peer_id, "vk_hex": vk_to_hex(&vk),
                "kdf": "argon2id", "argon2": ph.to_string(),
                "nonce_b64": B64.encode(nonce_bytes), "ciphertext_b64": B64.encode(ct),
                "note": "Encrypted export. Keep file private, remember your passphrase."
            });
            fs::create_dir_all(out_path.parent().unwrap()).ok();
            fs::write(&out_path, serde_json::to_string_pretty(&out_json).unwrap())
                .expect("write export enc");
            println!(
                "[IDENT] Encrypted identity exported to {}",
                out_path.display()
            );
        }
        Commands::KeyImportEnc { file } => {
            let s = fs::read_to_string(&file).expect("read encrypted identity json");
            let v: serde_json::Value = serde_json::from_str(&s).expect("parse json");
            let ph_s = v
                .get("argon2")
                .and_then(|x| x.as_str())
                .expect("missing argon2");
            let nonce_b64 = v
                .get("nonce_b64")
                .and_then(|x| x.as_str())
                .expect("missing nonce_b64");
            let ct_b64 = v
                .get("ciphertext_b64")
                .and_then(|x| x.as_str())
                .expect("missing ciphertext_b64");
            let pass = prompt_password("Passphrase: ").expect("read pass");
            let parsed_ph = PasswordHash::new(ph_s).expect("parse argon2 hash");
            let salt = parsed_ph.salt.expect("no salt in PHC");
            let argon2 = Argon2::default();
            let ph2 = argon2
                .hash_password(pass.as_bytes(), salt)
                .expect("argon2 re-hash");
            let hash_str2 = ph2.hash.unwrap();
            let key_material = hash_str2.as_bytes();
            assert!(key_material.len() >= 32);
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&key_material[..32]);
            let key = Key::from(key_bytes);
            let nonce_bytes = B64.decode(nonce_b64).expect("b64 nonce");
            let ct = B64.decode(ct_b64).expect("b64 ct");
            let cipher = ChaCha20Poly1305::new(&key);
            let nonce = Nonce::from({
                let mut n = [0u8; 12];
                n.copy_from_slice(&nonce_bytes[..12]);
                n
            });
            let pt = cipher.decrypt(&nonce, ct.as_ref()).expect("decrypt");
            let sk_hex = String::from_utf8(pt).expect("utf8");
            let sk_bytes = hex::decode(sk_hex).expect("sk_hex decode");
            assert_eq!(sk_bytes.len(), 32, "sk_hex must be 32 bytes");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&sk_bytes);
            let sk = SigningKey::from_bytes(&arr);
            let vk = VerifyingKey::from(&sk);
            save_keypair(&sk, &vk).expect("save keystore");
            let pid = peer_id_from_pubkey(&vk);
            println!("[IDENT] Encrypted identity imported. PeerID: {}", pid);
        }

        // ===== Key lifecycle =====
        Commands::Revoke { reason, out } => {
            let rec = rekey::revoke_current(reason);
            let v = serde_json::to_value(&rec).unwrap();
            rekey::write_json(&out, &v).expect("write revocation");
            println!(
                "[IDENT] wrote {}",
                dirs::home_dir().unwrap().join(".hsip").join(out).display()
            );
        }
        Commands::RotateKey { out } => {
            let (_nsk, nvk, rec) = rekey::rotate_key_make_rebind();
            let v = serde_json::to_value(&rec).unwrap();
            rekey::write_json(&out, &v).expect("write rebind");
            println!("[IDENT] rotated. new vk={}", vk_to_hex(&nvk));
        }

        // ===== Hello =====
        Commands::Hello => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            let hello = build_hello(&sk, &vk, now_ms());
            let json = serde_json::to_string_pretty(&hello).unwrap();
            println!("[HELLO] {}", json);
        }
        Commands::HelloListen { addr } => {
            if let Err(e) = listen_hello(&addr) {
                eprintln!("[HELLO] listen error: {e}");
            }
        }
        Commands::HelloSend { to } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            if let Err(e) = send_hello(&sk, &vk, &to, now_ms()) {
                eprintln!("[HELLO] send error: {e}");
            } else {
                println!("[HELLO] sent → {}", to);
            }
        }

        // ===== New low-level handshake commands (using commands::handshake) =====
        Commands::HandshakeListen { addr } => {
            if let Err(e) = commands::handshake::run_listen(&addr) {
                eprintln!("[HANDSHAKE] listen error: {e}");
            }
        }
        Commands::HandshakeConnect { addr } => {
            if let Err(e) = commands::handshake::run_connect(&addr) {
                eprintln!("[HANDSHAKE] connect error: {e}");
            }
        }

        // ===== Consent (local) =====
        Commands::ConsentRequest {
            file,
            purpose,
            expires_ms,
            out,
        } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            let data = fs::read(&file).expect("read file");
            let cid = cid_hex(&data);
            let req = build_request(&sk, &vk, cid, purpose, expires_ms, now_ms());
            let json = serde_json::to_string_pretty(&req).unwrap();
            fs::write(&out, json).expect("write out");
            println!("[CONSENT] wrote {}", out);
        }
        Commands::ConsentVerify { file } => {
            let data = fs::read(&file).expect("read file");
            let req: ConsentRequest = serde_json::from_slice(&data).expect("parse json");
            match verify_request(&req) {
                Ok(()) => println!("[CONSENT] [OK] request valid"),
                Err(e) => println!("[CONSENT] [BAD] request invalid: {e}"),
            }
        }

        // ===== Consent over UDP (sealed CONTROL) =====
        Commands::ConsentListen {
            addr,
            enforce_rep,
            threshold,
            // cover
            cover,
            cover_rate_per_min,
            cover_min_size,
            cover_max_size,
            cover_jitter_ms,
            cover_verbose_every,
            // autodecide
            decision,
            ttl_ms,
        } => {
            if enforce_rep {
                std::env::set_var("HSIP_ENFORCE_REP", "1");
            }
            std::env::set_var("HSIP_REP_THRESHOLD", threshold.to_string());

            // Background decoy
            let _cover_handle = if cover {
                println!(
                    "[SESSION] cover ON → {} | ~{} pkt/min | sizes {}–{} | jitter ±{} ms",
                    addr, cover_rate_per_min, cover_min_size, cover_max_size, cover_jitter_ms
                );
                let to_addr = addr.clone();
                Some(thread::spawn(move || {
                    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind cover");
                    let mut buf = vec![0u8; cover_max_size.max(cover_min_size)];
                    let mut sent: u64 = 0;
                    let mean_ms = if cover_rate_per_min == 0 {
                        60_000
                    } else {
                        (60_000f64 / (cover_rate_per_min as f64)).round() as u64
                    };
                    loop {
                        let size = if cover_max_size <= cover_min_size {
                            cover_min_size
                        } else {
                            cover_min_size
                                + rand::thread_rng()
                                    .gen_range(0..=(cover_max_size - cover_min_size))
                        };
                        OsRng.fill_bytes(&mut buf[..size]);
                        let _ = sock.send_to(&buf[..size], &to_addr);
                        sent += 1;
                        if cover_verbose_every > 0 && sent.is_multiple_of(cover_verbose_every) {
                            println!(
                                "[SESSION] (cover) sent {} decoys (last={} bytes) → {}",
                                sent, size, to_addr
                            );
                        }
                        let jit = cover_jitter_ms as i64;
                        let delta = if jit == 0 {
                            0
                        } else {
                            rand::thread_rng().gen_range(-jit..=jit)
                        };
                        let sleep_ms = ((mean_ms as i64) + delta).max(0) as u64;
                        thread::sleep(Duration::from_millis(sleep_ms));
                    }
                }))
            } else {
                None
            };

            // Inline control listener so we can autodecide (allow/deny) with our unified AAD/label
            let sock = StdUdpSocket::bind(&addr).expect("bind control listener");
            sock.set_nonblocking(true).ok();
            println!("[CONTROL] bound on {}", addr);

            // --- handshake E1 ---
            let mut buf = [0u8; 4096];
            let (_n, peer) = loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, p)) if n > 32 && buf[0] == TAG_E1 => break (n, p),
                    Ok((_n, _p)) => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("[CONTROL] recv E1: {e}"),
                }
            };
            let mut peer_pub_bytes = [0u8; 32];
            peer_pub_bytes.copy_from_slice(&buf[1..33]);
            let peer_pub = XPublicKey::from(peer_pub_bytes);

            // --- our E2 + sessions (rx/tx) ---
            let eph = Ephemeral::generate();
            let our_pub = eph.public();
            let label = PeerLabel {
                label: LABEL_CONSENT_V1.to_vec(),
            };
            let shared = match eph.into_shared(&peer_pub) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[CONTROL] into_shared: {e:?}");
                    return;
                }
            };
            let mut sess_rx = Session::from_shared_secret(shared, Some(&label)).expect("sess rx");
            let mut sess_tx = Session::from_shared_secret(shared, Some(&label)).expect("sess tx");

            let mut e2 = [0u8; 1 + 32];
            e2[0] = TAG_E2;
            e2[1..].copy_from_slice(our_pub.as_bytes());
            let _ = sock.send_to(&e2, peer);
            println!("[CONTROL] handshake with {} complete", peer);

            // --- wait sealed CONTROL request → auto respond ---
            let mut rbuf = vec![0u8; 65535];
            loop {
                match sock.recv_from(&mut rbuf) {
                    Ok((n, p)) if n >= 1 && rbuf[0] == TAG_D => {
                        let ct = &rbuf[1..n];
                        match sess_rx.open(AAD_CONTROL, ct) {
                            Ok(pt) => {
                                if let Ok(req) = serde_json::from_slice::<ConsentRequest>(&pt) {
                                    let (sk, vk) = load_keypair().expect("identity");
                                    let resp =
                                        build_response(&sk, &vk, &req, &decision, ttl_ms, now_ms())
                                            .expect("build resp");
                                    let body = serde_json::to_vec(&resp).unwrap();
                                    match sess_tx.seal(AAD_CONTROL, &body) {
                                        Ok(ct2) => {
                                            let mut pkt = Vec::with_capacity(1 + ct2.len());
                                            pkt.push(TAG_D);
                                            pkt.extend_from_slice(&ct2);
                                            let _ = sock.send_to(&pkt, p);
                                            println!(
                                                "[CONTROL] replied decision={} ttl={} to {}",
                                                decision, ttl_ms, p
                                            );
                                        }
                                        Err(e) => eprintln!("[CONTROL] seal resp: {e:?}"),
                                    }
                                }
                            }
                            Err(_e) => { /* ignore non CONTROL */ }
                        }
                    }
                    Ok((_n, _p)) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => {
                        eprintln!("[CONTROL] recv error: {e}");
                        break;
                    }
                }
            }
        }

        // === sender
        Commands::ConsentSendRequest {
            to,
            file,
            wait_reply,
            wait_timeout_ms,
        } => {
            let bytes = std::fs::read(&file).expect("read request json");
            let req: ConsentRequest = serde_json::from_slice(&bytes).expect("parse request json");

            if !wait_reply {
                if let Err(e) = send_consent_request(&to, &req) {
                    eprintln!("[CONTROL] send request error: {e}");
                } else {
                    println!("[CONTROL] request sent → {}", to);
                }
                return;
            }

            // sealed request/reply
            let payload = serde_json::to_vec(&req).expect("encode req");
            let sock = StdUdpSocket::bind("0.0.0.0:0").expect("bind sender");
            sock.set_read_timeout(Some(std::time::Duration::from_millis(wait_timeout_ms)))
                .expect("set timeout");

            // E1
            let eph = Ephemeral::generate();
            let our_pub = eph.public();
            let mut e1 = [0u8; 1 + 32];
            e1[0] = TAG_E1;
            e1[1..].copy_from_slice(our_pub.as_bytes());
            if let Err(e) = sock.send_to(&e1, &to) {
                eprintln!("[CONTROL] send E1: {e}");
                return;
            }

            // E2
            let mut buf = [0u8; 64];
            let (n, _peer) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[CONTROL] recv E2: {e}");
                    return;
                }
            };
            if n < 33 || buf[0] != TAG_E2 {
                eprintln!("[CONTROL] unexpected handshake response");
                return;
            }
            let mut srv_pub_bytes = [0u8; 32];
            srv_pub_bytes.copy_from_slice(&buf[1..33]);
            let srv_pub = XPublicKey::from(srv_pub_bytes);

            // session
            let label = PeerLabel {
                label: LABEL_CONSENT_V1.to_vec(),
            };
            let mut sess = match Session::from_handshake(eph, &srv_pub, Some(&label)) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[CONTROL] from_handshake: {e:?}");
                    return;
                }
            };

            // send sealed CONTROL frame
            let ct = match sess.seal(AAD_CONTROL, &payload) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[CONTROL] seal: {e:?}");
                    return;
                }
            };
            let mut packet = Vec::with_capacity(1 + ct.len());
            packet.push(TAG_D);
            packet.extend_from_slice(&ct);
            let _ = sock.send_to(&packet, &to);
            println!("[CONTROL] sealed {} bytes → {}", payload.len(), to);

            // wait for sealed reply
            let mut rbuf = vec![0u8; 65535];
            match sock.recv_from(&mut rbuf) {
                Ok((rn, _p)) if rn >= 1 && rbuf[0] == TAG_D => {
                    let ct = &rbuf[1..rn];
                    match sess.open(AAD_CONTROL, ct) {
                        Ok(pt) => match serde_json::from_slice::<ConsentResponse>(&pt) {
                            Ok(resp) => println!(
                                "[CONTROL] reply: decision='{}' ttl_ms={} request_hash={}",
                                resp.decision, resp.ttl_ms, resp.request_hash_hex
                            ),
                            Err(_) => {
                                println!("[CONTROL] reply (json): {}", String::from_utf8_lossy(&pt))
                            }
                        },
                        Err(e) => eprintln!("[CONTROL] failed to open reply: {e:?}"),
                    }
                }
                Ok((_rn, _p)) => eprintln!("[CONTROL] unexpected frame while waiting for reply"),
                Err(e) => eprintln!("[CONTROL] no reply within {} ms ({e})", wait_timeout_ms),
            }
        }

        Commands::ConsentSendResponse { to, file } => {
            let bytes = std::fs::read(&file).expect("read response json");
            let resp: ConsentResponse =
                serde_json::from_slice(&bytes).expect("parse response json");
            if let Err(e) = send_consent_response(&to, &resp) {
                eprintln!("[CONTROL] send response error: {e}");
            } else {
                println!("[CONTROL] response sent → {}", to);
            }
        }

        Commands::ConsentRespond {
            request,
            decision,
            ttl_ms,
            out,
            enforce_rep,
            requester_peer,
            threshold,
        } => {
            let (sk, vk) = load_keypair().expect("load identity");
            let req_bytes = fs::read(&request).expect("read request file");
            let req: ConsentRequest = serde_json::from_slice(&req_bytes).expect("parse request");
            let requester_peer_id = if !req.requester_peer_id.trim().is_empty() {
                req.requester_peer_id.clone()
            } else {
                requester_peer.clone().unwrap_or_default()
            };

            let cfg = config::read_config().ok().flatten();
            let env_enforce = std::env::var("HSIP_ENFORCE_REP").ok().as_deref() == Some("1");
            let cfg_enforce = cfg
                .as_ref()
                .and_then(|c| c.policy.enforce_rep)
                .unwrap_or(false);
            let effective_enforce = enforce_rep || env_enforce || cfg_enforce;
            let env_thresh = std::env::var("HSIP_REP_THRESHOLD")
                .ok()
                .and_then(|s| s.parse::<i32>().ok());
            let cfg_thresh = cfg.as_ref().and_then(|c| c.policy.rep_threshold);
            let block_threshold = env_thresh.or(cfg_thresh).unwrap_or(threshold);

            let log_path: PathBuf = dirs::home_dir()
                .unwrap()
                .join(".hsip")
                .join("reputation.log");
            eprintln!(
                "[POLICY] enforce={} threshold={} requester='{}'",
                effective_enforce, block_threshold, requester_peer_id
            );

            let mut final_decision = decision.clone();
            if effective_enforce && !requester_peer_id.is_empty() {
                let store =
                    hsip_reputation::store::Store::open(log_path.clone()).expect("open rep log");
                let score = store.compute_score(&requester_peer_id).unwrap_or(0);
                eprintln!("[POLICY] requester score={}", score);
                if score < block_threshold {
                    eprintln!("[POLICY] auto-deny due to low reputation");
                    final_decision = "deny".to_string();
                    let (my_sk, my_vk) = load_keypair().expect("load identity");
                    let my_peer = peer_id_from_pubkey(&my_vk);
                    let _ = store.append(
                        &my_sk,
                        &my_peer,
                        &requester_peer_id,
                        hsip_reputation::store::DecisionType::MISBEHAVIOR,
                        1,
                        "POLICY_THRESHOLD",
                        "Auto-deny due to low reputation score",
                        vec![],
                        Some("7d".to_string()),
                    );
                }
            }

            let resp = build_response(&sk, &vk, &req, &final_decision, ttl_ms, now_ms())
                .expect("build response");
            let json = serde_json::to_string_pretty(&resp).unwrap();
            fs::write(&out, json).expect("write response");
            println!("[CONSENT] wrote {}", out);
        }

        Commands::ConsentVerifyResponse { request, response } => {
            let req: ConsentRequest = {
                let b = fs::read(&request).expect("read request");
                serde_json::from_slice(&b).expect("parse request")
            };
            let resp: ConsentResponse = {
                let b = fs::read(&response).expect("read response");
                serde_json::from_slice(&b).expect("parse response")
            };
            match verify_response(&resp, &req) {
                Ok(()) => println!("[CONSENT] [OK] response is valid and bound to request"),
                Err(e) => println!("[CONSENT] [BAD] response invalid: {e}"),
            }
        }

        // ===== Session: listener =====
        Commands::SessionListen {
            addr,
            cover,
            cover_rate_per_min,
            cover_min_size,
            cover_max_size,
            cover_jitter_ms,
            cover_verbose_every,
        } => {
            let sock = StdUdpSocket::bind(&addr).expect("bind listener");
            sock.set_nonblocking(true).ok();
            println!("[SESSION] listen on {}", addr);

            let mut buf = vec![0u8; 4096];
            let (_n, peer) = loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, p)) if n > 32 && buf[0] == TAG_E1 => break (n, p),
                    Ok((_n, _p)) => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("[SESSION] recv E1: {e}"),
                }
            };
            let mut peer_pub_bytes = [0u8; 32];
            peer_pub_bytes.copy_from_slice(&buf[1..33]);
            let peer_pub = XPublicKey::from(peer_pub_bytes);

            let eph = Ephemeral::generate();
            let our_pub = eph.public();
            let label = PeerLabel {
                label: LABEL_CONSENT_V1.to_vec(),
            };

            let shared = match eph.into_shared(&peer_pub) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[SESSION] into_shared: {e:?}");
                    return;
                }
            };
            let mut sess_rx = Session::from_shared_secret(shared, Some(&label)).expect("rx");
            let mut sess_tx = Session::from_shared_secret(shared, Some(&label)).expect("tx");

            let mut e2 = [0u8; 1 + 32];
            e2[0] = TAG_E2;
            e2[1..].copy_from_slice(our_pub.as_bytes());
            let _ = sock.send_to(&e2, peer);
            println!("[SESSION] handshake with {} complete", peer);

            let _ = session_persist::write_json(
                "last_session.json",
                &serde_json::json!({
                    "role": "listener", "peer_addr": peer.to_string(), "ts_ms": now_ms(),
                    "label": "CONSENTv1", "transport": "udp"
                }),
            );

            let cover_handle = if cover {
                println!(
                    "[SESSION] cover ON → {} | ~{} pkt/min | sizes {}–{} | jitter ±{} ms",
                    peer, cover_rate_per_min, cover_min_size, cover_max_size, cover_jitter_ms
                );
                let to_addr = peer;
                let rate = cover_rate_per_min;
                let min = cover_min_size;
                let max = cover_max_size;
                let jit = cover_jitter_ms;
                let verbose_every = cover_verbose_every;
                Some(std::thread::spawn(move || {
                    let sock_tx = StdUdpSocket::bind("0.0.0.0:0").expect("bind tx");
                    let mean = mean_interval_ms(rate);
                    let mut sent: u64 = 0;
                    loop {
                        let size = rand_range(min, max);
                        let mut payload = vec![0u8; size];
                        rand::rngs::OsRng.fill_bytes(&mut payload);
                        let ct = match sess_tx.seal(AAD_DATA, &payload) {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("[SESSION] cover seal: {e:?}");
                                std::thread::sleep(std::time::Duration::from_millis(50));
                                continue;
                            }
                        };
                        let mut packet = Vec::with_capacity(1 + ct.len());
                        packet.push(TAG_D);
                        packet.extend_from_slice(&ct);
                        let _ = sock_tx.send_to(&packet, to_addr);
                        sent += 1;
                        if verbose_every > 0 && sent.is_multiple_of(verbose_every) {
                            println!(
                                "[SESSION] (cover) sent {} decoys (last={} bytes) → {}",
                                sent, size, to_addr
                            );
                        }
                        let jit_i = jit as i64;
                        let delta = if jit_i == 0 {
                            0
                        } else {
                            rand::thread_rng().gen_range(-jit_i..=jit_i)
                        };
                        let sleep_ms = ((mean as i64) + delta).max(0) as u64;
                        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                    }
                }))
            } else {
                None
            };

            let mut buf = vec![0u8; 4096];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, p)) if n >= 1 && buf[0] == TAG_D => {
                        let ct = &buf[1..n];
                        match sess_rx.open(AAD_DATA, ct) {
                            Ok(pt) => println!("[SESSION] opened {} bytes from {}", pt.len(), p),
                            Err(e) => eprintln!("[SESSION] open error from {p}: {e:?}"),
                        }
                    }
                    Ok((_n, _p)) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => {
                        eprintln!("[SESSION] recv error: {e}");
                        break;
                    }
                }
            }
            if let Some(h) = cover_handle {
                let _ = h.join();
            }
        }

        // ===== Session: sender =====
        Commands::SessionSend {
            to,
            packets,
            min_size,
            max_size,
        } => {
            let sock = StdUdpSocket::bind("0.0.0.0:0").expect("bind sender");
            sock.set_nonblocking(true).ok();

            let resume_path = session_persist::path_for("last_session.json");
            let eph = if resume_path.exists() {
                if let Some(resume_meta) =
                    session_persist::read_json::<serde_json::Value>("last_session.json")
                {
                    println!(
                        "[SESSION] resume → peer={} ts_ms={}",
                        resume_meta["peer_addr"], resume_meta["ts_ms"]
                    );
                    Ephemeral::generate()
                } else {
                    Ephemeral::generate()
                }
            } else {
                Ephemeral::generate()
            };

            let our_pub = eph.public();

            let mut e1 = [0u8; 1 + 32];
            e1[0] = TAG_E1;
            e1[1..].copy_from_slice(our_pub.as_bytes());
            let _ = sock.send_to(&e1, &to);

            let mut buf = [0u8; 64];
            let (_n, _peer) = loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, p)) if n > 32 && buf[0] == TAG_E2 => break (n, p),
                    Ok((_n, _p)) => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => {
                        eprintln!("[SESSION] recv E2: {e}");
                        return;
                    }
                }
            };
            let mut srv_pub_bytes = [0u8; 32];
            srv_pub_bytes.copy_from_slice(&buf[1..33]);
            let srv_pub = XPublicKey::from(srv_pub_bytes);

            let label = PeerLabel {
                label: LABEL_CONSENT_V1.to_vec(),
            };
            let mut sess = match Session::from_handshake(eph, &srv_pub, Some(&label)) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[SESSION] from_handshake: {e:?}");
                    return;
                }
            };

            let eph_pk_hex = hex::encode(our_pub.as_bytes());
            let _ = session_persist::write_json(
                "last_session.json",
                &serde_json::json!({
                    "role": "sender", "peer_addr": to, "ts_ms": now_ms(),
                    "eph_pk_hex": eph_pk_hex, "label": "CONSENTv1", "transport": "udp"
                }),
            );

            for i in 1..=packets {
                let size = rand_range(min_size, max_size);
                let mut payload = vec![0u8; size];
                rand::rngs::OsRng.fill_bytes(&mut payload);
                let ct = match sess.seal(AAD_DATA, &payload) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[SESSION] seal: {e:?}");
                        continue;
                    }
                };
                let mut packet = Vec::with_capacity(1 + ct.len());
                packet.push(TAG_D);
                packet.extend_from_slice(&ct);
                let _ = sock.send_to(&packet, &to);
                println!("[SESSION] sent {i}/{packets} ({} bytes payload)", size);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            println!("[SESSION] done.");
        }

        // ===== Privacy Ping =====
        Commands::PingListen { addr } => {
            let sock = StdUdpSocket::bind(&addr).expect("bind ping-listen");
            sock.set_nonblocking(true).ok();
            println!("[PING] listen on {}", addr);

            let mut buf = [0u8; 4096];
            let (_n, peer) = loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, p)) if n > 32 && buf[0] == TAG_E1 => break (n, p),
                    Ok((_n, _p)) => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("[PING] recv E1: {e}"),
                }
            };
            let mut peer_pub_bytes = [0u8; 32];
            peer_pub_bytes.copy_from_slice(&buf[1..33]);
            let peer_pub = XPublicKey::from(peer_pub_bytes);

            let eph = Ephemeral::generate();
            let our_pub = eph.public();
            let label = PeerLabel {
                label: LABEL_CONSENT_V1.to_vec(),
            };

            let shared = match eph.into_shared(&peer_pub) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[PING] into_shared: {e:?}");
                    return;
                }
            };
            let mut sess_rx = Session::from_shared_secret(shared, Some(&label)).expect("rx");
            let mut sess_tx = Session::from_shared_secret(shared, Some(&label)).expect("tx");

            let mut e2 = [0u8; 1 + 32];
            e2[0] = TAG_E2;
            e2[1..].copy_from_slice(our_pub.as_bytes());
            let _ = sock.send_to(&e2, peer);
            println!("[PING] handshake with {} complete", peer);

            let mut rbuf = vec![0u8; 65535];
            loop {
                match sock.recv_from(&mut rbuf) {
                    Ok((n, p)) if n >= 1 && rbuf[0] == TAG_D => {
                        let ct = &rbuf[1..n];
                        if let Ok(pt) = sess_rx.open(AAD_PING, ct) {
                            match sess_tx.seal(AAD_PING, &pt) {
                                Ok(ct2) => {
                                    let mut pkt = Vec::with_capacity(1 + ct2.len());
                                    pkt.push(TAG_D);
                                    pkt.extend_from_slice(&ct2);
                                    let _ = sock.send_to(&pkt, p);
                                }
                                Err(e) => eprintln!("[PING] seal echo: {e:?}"),
                            }
                        }
                    }
                    Ok((_n, _p)) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => {
                        eprintln!("[PING] recv error: {e}");
                        break;
                    }
                }
            }
        }
        Commands::Ping {
            to,
            count,
            size,
            timeout_ms,
        } => {
            let sock = StdUdpSocket::bind("0.0.0.0:0").expect("bind ping sender");
            sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
                .ok();

            let eph = Ephemeral::generate();
            let our_pub = eph.public();
            let mut e1 = [0u8; 1 + 32];
            e1[0] = TAG_E1;
            e1[1..].copy_from_slice(our_pub.as_bytes());
            let _ = sock.send_to(&e1, &to);

            let mut buf = [0u8; 64];
            let (n, _peer) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[PING] recv E2: {e}");
                    return;
                }
            };
            if n < 33 || buf[0] != TAG_E2 {
                eprintln!("[PING] unexpected handshake response");
                return;
            }
            let mut srv_pub_bytes = [0u8; 32];
            srv_pub_bytes.copy_from_slice(&buf[1..33]);
            let srv_pub = XPublicKey::from(srv_pub_bytes);

            let label = PeerLabel {
                label: LABEL_CONSENT_V1.to_vec(),
            };
            let mut sess = match Session::from_handshake(eph, &srv_pub, Some(&label)) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[PING] from_handshake: {e:?}");
                    return;
                }
            };

            println!(
                "[PING] to {} | {} bytes | {} pings | {} ms timeout",
                to, size, count, timeout_ms
            );

            let mut sent: u32 = 0;
            let mut received: u32 = 0;
            let mut rtt_min: u128 = u128::MAX;
            let mut rtt_max: u128 = 0;
            let mut rtt_sum: u128 = 0;

            for seq in 1..=count {
                let mut payload = vec![0u8; size.max(16)];
                rand::rngs::OsRng.fill_bytes(&mut payload);
                let stamp = now_ms();
                payload[0..8].copy_from_slice(&stamp.to_le_bytes());
                let ct = match sess.seal(AAD_PING, &payload) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[PING] seal: {e:?}");
                        continue;
                    }
                };
                let mut pkt = Vec::with_capacity(1 + ct.len());
                pkt.push(TAG_D);
                pkt.extend_from_slice(&ct);

                let t0 = Instant::now();
                let _ = sock.send_to(&pkt, &to);
                sent += 1;

                let mut rbuf = vec![0u8; 65535];
                match sock.recv_from(&mut rbuf) {
                    Ok((rn, _p)) if rn >= 1 && rbuf[0] == TAG_D => {
                        let ct2 = &rbuf[1..rn];
                        match sess.open(AAD_PING, ct2) {
                            Ok(pt) => {
                                let rtt = t0.elapsed().as_millis();
                                received += 1;
                                rtt_min = rtt_min.min(rtt);
                                rtt_max = rtt_max.max(rtt);
                                rtt_sum += rtt;
                                let ok = pt.len() >= 8 && pt[0..8] == stamp.to_le_bytes();
                                println!(
                                    "[PING] seq={} bytes={} rtt={} ms integrity={}",
                                    seq,
                                    pt.len(),
                                    rtt,
                                    if ok { "ok" } else { "mismatch" }
                                );
                            }
                            Err(e) => eprintln!("[PING] open echo: {e:?}"),
                        }
                    }
                    Ok((_rn, _p)) => eprintln!("[PING] unexpected frame"),
                    Err(e) => eprintln!("[PING] timeout ({} ms): {}", timeout_ms, e),
                }
            }
            if received > 0 {
                let avg = (rtt_sum as f64) / (received as f64);
                println!(
                    "[PING] stats: sent={} recv={} loss={}%% min={}ms avg={:.1}ms max={}ms",
                    sent,
                    received,
                    ((sent - received) as f64 * 100.0 / sent as f64).round() as u32,
                    rtt_min,
                    avg,
                    rtt_max
                );
            } else {
                println!("[PING] stats: sent={} recv=0 (100% loss)", sent);
            }
        }

        // ===== Session persistence =====
        Commands::SessionSave { name, file } => {
            let buf = fs::read(&file).expect("read input file");
            match session_persist::save_blob(&name, &buf) {
                Ok(()) => {
                    let path = session_persist::path_for(&name);
                    println!("[SESSION] saved blob '{}' → {}", name, path.display());
                }
                Err(e) => eprintln!("[SESSION] save error: {e}"),
            }
        }
        Commands::SessionLoad { name, out } => match session_persist::load_blob(&name) {
            Ok(buf) => {
                fs::write(&out, &buf).expect("write output file");
                println!("[SESSION] loaded blob '{}' → {}", name, out);
            }
            Err(e) => eprintln!("[SESSION] load failed: {}", e),
        },

        // ===== Tokens =====
        Commands::TokenIssue {
            grantee,
            caps,
            ttl_ms,
            out,
        } => {
            let caps_vec = caps
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| match s.to_lowercase().as_str() {
                    "voice" => token::Capability::Voice,
                    "filetransfer" | "file" => token::Capability::FileTransfer,
                    "session" => token::Capability::Session,
                    "hello" => token::Capability::Hello,
                    "ping" => token::Capability::Ping,
                    _ => token::Capability::Session,
                })
                .collect::<Vec<_>>();
            let tok = token::issue_token(grantee, caps_vec, ttl_ms);
            let out_json = serde_json::to_string_pretty(&tok).unwrap();
            fs::write(&out, out_json).expect("write token");
            println!("[TOKEN] wrote {}", out);
        }
        Commands::TokenVerify {
            file,
            issuer_vk_hex,
        } => {
            let s = fs::read_to_string(&file).expect("read token");
            let tok: token::ConsentToken = serde_json::from_str(&s).expect("parse token");
            let vk_bytes = hex::decode(issuer_vk_hex).expect("vk hex");
            let vk =
                VerifyingKey::from_bytes(&vk_bytes.try_into().expect("vk len")).expect("vk parse");
            match token::verify_token(&tok, &vk) {
                Ok(()) => println!("[TOKEN] [OK] valid (issuer={})", tok.issuer_peer),
                Err(e) => println!("[TOKEN] [BAD] {e}"),
            }
        }

        // ===== Local device token verifier (JWT-EdDSA) =====
        Commands::TokenVerifyLocal { token, file } => {
            let tok = if let Some(t) = token {
                t
            } else if let Some(f) = file {
                fs::read_to_string(&f)
                    .expect("read token file")
                    .trim()
                    .to_string()
            } else {
                eprintln!("[TOKEN] provide --token or --file");
                return;
            };
            match verify_local_token_str(&tok) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("[TOKEN] [BAD] {}", e),
            }
        }

        // ===== Discovery (static) =====
        Commands::DiscoverList => {
            let dir = discovery::list();
            if dir.peers.is_empty() {
                println!("[DISC] (empty)");
            }
            for p in dir.peers {
                println!("[DISC] {} → {}", p.peer_id, p.addr);
            }
        }
        Commands::DiscoverAdd { peer, addr } => {
            discovery::add(peer.clone(), addr.clone());
            println!("[DISC] added {} → {}", peer, addr);
        }
        Commands::DiscoverRemove { peer } => {
            discovery::remove(peer.clone());
            println!("[DISC] removed {}", peer);
        }

        // ===== Reputation =====
        Commands::Rep(args) => {
            cmd_rep::run_rep(args).expect("rep command failed");
        }

        // ===== Daemon / Status API =====
        Commands::Daemon { status_addr } => {
            // Ensure passwordless device identity exists (no UI)
            let _ = ensure_identity_silent();
            let addr: SocketAddr = status_addr.parse().expect("invalid --status_addr");
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                if let Err(e) = daemon::http::serve(addr).await {
                    eprintln!("[daemon] error: {e:?}");
                }
            });
        }

        // ===== Identity Web Demo =====
        Commands::IdentityServe => {
            // Ensure identity (no prompts)
            let _ = ensure_identity_silent();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                if let Err(e) = identity::run_identity_broker().await {
                    eprintln!("[IDENTITY] broker error: {e:?}");
                }
            });
        }

        // ===== Tray-lite (user-mode): identity + spawn daemon + /consent =====
        Commands::Tray => {
            // 1) Ensure identity silently
            match ensure_identity_silent() {
                Ok(pid) => println!("[TRAY] identity ok (peer={})", pid),
                Err(e) => {
                    eprintln!("[TRAY] identity error: {e}");
                    return;
                }
            }

            // 2) Spawn daemon as child (same user, no admin)
            if let Err(e) = ensure_daemon_running() {
                eprintln!("[TRAY] daemon spawn error: {e}");
            } else {
                println!("[TRAY] daemon running (or will single-instance)");
            }

            // 3) Start local /consent HTTP (+ /status, + /verify)
            start_local_consent_http();
            println!(
                "[TRAY] consent server on http://{}/consent",
                CONSENT_HTTP_ADDR
            );

            // 4) Keep process alive (your real tray UI would live here)
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }

        // ===== Demo site (local HSIP-aware webpage) =====
        Commands::DemoSite => {
            run_demo_site();
        }

        // ===== Diagnostics =====
        Commands::Diag => {
            if let Err(e) = commands::diag::run_diag() {
                eprintln!("[DIAG] error: {e:?}");
            }
        }
    }
}

fn run_demo_site() {
    use tiny_http::{Header, Response, Server, StatusCode};

    println!(
        "[DEMO] starting HSIP demo site on http://{}/",
        DEMO_HTTP_ADDR
    );

    let server = match Server::http(DEMO_HTTP_ADDR) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[DEMO] failed to bind {}: {}", DEMO_HTTP_ADDR, e);
            return;
        }
    };

    // Simple HSIP-aware HTML page with the meta marker
    let html = r#"<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>HSIP Demo Site</title>
    <meta name="hsip-site" content="1">
    <style>
      body { font-family: system-ui, sans-serif; padding: 20px; }
      h1 { margin-top: 0; }
      .box { border: 1px solid #ccc; padding: 12px; border-radius: 8px; max-width: 520px; }
      .badge-info { font-size: 12px; color: #555; margin-top: 8px; }
      code { background: #f5f5f5; padding: 2px 4px; border-radius: 3px; }
    </style>
  </head>
  <body>
    <h1>HSIP Demo Site</h1>
    <div class="box">
      <p>If HSIP is installed and the browser extension is active, you should see a small
      <strong>“Protected by HSIP”</strong> badge in the bottom-right corner of this page.</p>

      <p class="badge-info">
        This page simply tells the browser:<br>
        <code>&lt;meta name="hsip-site" content="1"&gt;</code><br>
        The HSIP extension does the rest automatically.
      </p>
    </div>
  </body>
</html>
"#;

    loop {
        match server.recv() {
            Ok(req) => {
                let url = req.url().to_string();
                if url == "/" {
                    let mut resp = Response::from_string(html);
                    resp.add_header(
                        Header::from_bytes(b"Content-Type", b"text/html; charset=utf-8").unwrap(),
                    );
                    let _ = req.respond(resp);
                } else {
                    let mut resp =
                        Response::from_string("Not Found").with_status_code(StatusCode(404));
                    let _ = req.respond(resp);
                }
            }
            Err(e) => {
                eprintln!("[DEMO] http error: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

fn rand_range(min: usize, max: usize) -> usize {
    if max <= min {
        return min;
    }
    let span = (max - min) as u64;
    (min as u64 + (rand::random::<u64>() % (span + 1))) as usize
}

fn mean_interval_ms(rate_per_min: u32) -> u64 {
    (60_000.0 / (rate_per_min.max(1) as f64)).round() as u64
}

// ========================= NEW TRAY-LITE HELPERS =========================

fn ensure_identity_silent() -> anyhow::Result<String> {
    // Creates ~/.hsip/identity.json automatically if missing
    let pid = auth_identity::peer_id_b64()?;
    Ok(pid)
}

fn ensure_daemon_running() -> anyhow::Result<()> {
    // Ask current exe to spawn its own "daemon" child.
    // The daemon should single-instance itself on bind; multiple spawns are harmless.
    let exe = std::env::current_exe()?;
    let _child = Command::new(exe).arg("daemon").spawn()?;
    // brief backoff to let ports/IPC bind
    thread::sleep(Duration::from_millis(400));
    Ok(())
}

fn origin_allowed(req: &tiny_http::Request) -> bool {
    // Dev escape hatch:
    //   set HSIP_DEV_LOCAL=1 to allow curl/Postman without Origin
    let dev_ok = std::env::var("HSIP_DEV_LOCAL").ok().as_deref() == Some("1");

    let mut origin: Option<String> = None;
    for h in req.headers() {
        if h.field.equiv("Origin") {
            origin = Some(h.value.to_string());
            break;
        }
    }

    match origin {
        Some(o) => {
            if o.starts_with("moz-extension://") {
                true
            } else {
                dev_ok
            }
        }
        None => dev_ok,
    }
}

fn start_local_consent_http() {
    // Minimal dependency: tiny_http (sync). We isolate it on 127.0.0.1 only.
    thread::spawn(|| {
        let server = match tiny_http::Server::http(CONSENT_HTTP_ADDR) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[TRAY] bind {} failed: {}", CONSENT_HTTP_ADDR, e);
                return;
            }
        };

        loop {
            match server.recv() {
                Ok(mut req) => {
                    let method = req.method().as_str().to_string();
                    let url = req.url().to_string();

                    // --- CORS preflight (always allowed) ---
                    if method == "OPTIONS" {
                        let mut resp = tiny_http::Response::from_string("");
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Access-Control-Allow-Origin"[..],
                                &b"*"[..],
                            )
                            .unwrap(),
                        );
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Access-Control-Allow-Methods"[..],
                                &b"GET, POST, OPTIONS"[..],
                            )
                            .unwrap(),
                        );
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Access-Control-Allow-Headers"[..],
                                &b"Content-Type, Authorization"[..],
                            )
                            .unwrap(),
                        );
                        let resp = resp.with_status_code(tiny_http::StatusCode(204));
                        let _ = req.respond(resp);
                        continue;
                    }

                    // --- Gate sensitive endpoints by Origin ---
                    let is_protected_path = url == "/consent"
                        || url == "/status"
                        || url == "/verify"
                        || url.starts_with("/verify?");
                    if is_protected_path && !origin_allowed(&req) {
                        let mut resp = tiny_http::Response::from_string(
                            r#"{"ok":false,"error":"forbidden origin"}"#,
                        )
                        .with_status_code(tiny_http::StatusCode(403));
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        );
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Access-Control-Allow-Origin"[..],
                                &b"*"[..],
                            )
                            .unwrap(),
                        );
                        let _ = req.respond(resp);
                        continue;
                    }

                    if method == "POST" && url == "/consent" {
                        // Body: { "scopes": ["login", ...], "aud": "app.example" }
                        let mut body = String::new();
                        let _ = req.as_reader().read_to_string(&mut body);

                        #[derive(serde::Deserialize)]
                        struct In {
                            scopes: Option<Vec<String>>,
                            aud: Option<String>,
                        }

                        let input: In = serde_json::from_str(&body).unwrap_or(In {
                            scopes: None,
                            aud: None,
                        });
                        let scopes_v = input.scopes.unwrap_or_else(|| vec!["login".into()]);
                        let aud_s = input.aud.unwrap_or_else(|| "local".into());
                        let scope_strs: Vec<&str> = scopes_v.iter().map(|s| s.as_str()).collect();

                        // TODO: Replace with native consent dialog before issuance.
                        let token = auth_tokens::issue_consent(&scope_strs, 300, &aud_s)
                            .unwrap_or_else(|_| "ERR".to_string());

                        let resp_json = serde_json::json!({ "token": token });
                        let mut resp = tiny_http::Response::from_string(
                            serde_json::to_string(&resp_json).unwrap(),
                        );
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        );
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Access-Control-Allow-Origin"[..],
                                &b"*"[..],
                            )
                            .unwrap(),
                        );
                        let _ = req.respond(resp);
                    } else if method == "POST" && url == "/verify" {
                        // Body: { "token": "eyJ..." }
                        let mut body = String::new();
                        let _ = req.as_reader().read_to_string(&mut body);

                        #[derive(serde::Deserialize)]
                        struct InVerify {
                            token: String,
                        }

                        let out = match serde_json::from_str::<InVerify>(&body) {
                            Ok(v) => match verify_local_token_str(&v.token) {
                                Ok(json) => json,
                                Err(e) => {
                                    serde_json::json!({ "ok": false, "error": e.to_string() })
                                        .to_string()
                                }
                            },
                            Err(e) => {
                                serde_json::json!({ "ok": false, "error": format!("bad json: {e}") })
                                    .to_string()
                            }
                        };

                        let mut resp = tiny_http::Response::from_string(out);
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        );
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Access-Control-Allow-Origin"[..],
                                &b"*"[..],
                            )
                            .unwrap(),
                        );
                        let _ = req.respond(resp);
                    } else if method == "GET" && url.starts_with("/verify?") {
                        // Quick GET variant: /verify?token=...
                        let token = url
                            .splitn(2, '?')
                            .nth(1)
                            .and_then(|q| q.split('&').find(|kv| kv.starts_with("token=")))
                            .and_then(|kv| kv.splitn(2, '=').nth(1))
                            .map(|v| {
                                percent_encoding::percent_decode_str(v)
                                    .decode_utf8_lossy()
                                    .to_string()
                            });

                        let out = match token {
                            Some(t) => match verify_local_token_str(&t) {
                                Ok(json) => json,
                                Err(e) => {
                                    serde_json::json!({ "ok": false, "error": e.to_string() })
                                        .to_string()
                                }
                            },
                            None => {
                                serde_json::json!({ "ok": false, "error": "missing token param" })
                                    .to_string()
                            }
                        };

                        let mut resp = tiny_http::Response::from_string(out);
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        );
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Access-Control-Allow-Origin"[..],
                                &b"*"[..],
                            )
                            .unwrap(),
                        );
                        let _ = req.respond(resp);
                    } else if method == "GET" && url == "/status" {
                        let pid = auth_identity::peer_id_b64().unwrap_or_else(|_| "<none>".into());
                        let resp_json = serde_json::json!({ "ok": true, "peer": pid });
                        let mut resp = tiny_http::Response::from_string(
                            serde_json::to_string(&resp_json).unwrap(),
                        );
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        );
                        resp.add_header(
                            tiny_http::Header::from_bytes(
                                &b"Access-Control-Allow-Origin"[..],
                                &b"*"[..],
                            )
                            .unwrap(),
                        );
                        let _ = req.respond(resp);
                    } else {
                        let _ = req.respond(tiny_http::Response::from_string("ok"));
                    }
                }
                Err(e) => {
                    eprintln!("[TRAY] http error: {}", e);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    });
}

// ========================= LOCAL TOKEN VERIFIER =========================

fn verify_local_token_str(tok_in: &str) -> anyhow::Result<String> {
    use anyhow::{anyhow, Result};
    use base64::Engine;
    use ed25519_dalek::{Signature, VerifyingKey};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Header {
        alg: String,
        kid: String,
        #[allow(dead_code)]
        typ: Option<String>,
    }
    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        sub: String,
        aud: String,
        iat: i64,
        exp: i64,
        scopes: Vec<String>,
    }

    // 1) sanitize: trim + strip quotes + accept {"token": "..."} input
    let s = tok_in.trim();
    let s = s
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(s);
    let token_str = if s.starts_with('{') {
        #[derive(Deserialize)]
        struct Wrapper {
            token: String,
        }
        let w: Wrapper = serde_json::from_str(s).map_err(|_| anyhow!("bad token wrapper JSON"))?;
        w.token.trim().to_string()
    } else {
        s.to_string()
    };

    // 2) split into 3 non-empty parts; tolerate accidental trailing dot
    let parts: Vec<&str> = token_str.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() != 3 {
        return Err(anyhow!("bad token format"));
    }
    let (h_b64, p_b64, s_b64) = (parts[0], parts[1], parts[2]);

    // 3) base64url (no pad) decode
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let h_raw = url.decode(h_b64)?;
    let p_raw = url.decode(p_b64)?;
    let sig_raw = url.decode(s_b64)?;

    // 4) parse JSON
    let header: Header = serde_json::from_slice(&h_raw)?;
    let claims: Claims = serde_json::from_slice(&p_raw)?;
    if header.alg != "EdDSA" {
        return Err(anyhow!("unsupported alg: {}", header.alg));
    }

    // 5) verify Ed25519 over the exact signing input "h.p"
    let signing_input = format!("{}.{}", h_b64, p_b64);
    let vk_bytes = hex::decode(&header.kid)?;
    if vk_bytes.len() != 32 {
        return Err(anyhow!("kid not 32 bytes"));
    }
    let vk = VerifyingKey::from_bytes(&vk_bytes.try_into().map_err(|_| anyhow!("kid size"))?)?;
    let sig = Signature::from_bytes(&sig_raw.try_into().map_err(|_| anyhow!("sig size"))?);
    vk.verify_strict(signing_input.as_bytes(), &sig)?;

    let out = serde_json::json!({
        "ok": true,
        "kid": header.kid,
        "aud": claims.aud,
        "exp": claims.exp,
        "scopes": claims.scopes,
        "iss": claims.iss,
        "sub": claims.sub
    });
    Ok(out.to_string())
}
