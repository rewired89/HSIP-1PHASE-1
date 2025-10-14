// crates/hsip-cli/src/main.rs

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};

use hsip_core::consent::{
    build_request, build_response, cid_hex, verify_request, verify_response, ConsentRequest,
    ConsentResponse,
};
use hsip_core::identity::{generate_keypair, peer_id_from_pubkey, sk_to_hex, vk_to_hex};
use hsip_core::keystore::{load_keypair, save_keypair};

use hsip_net::hello::build_hello;
use hsip_net::udp::hello::{listen_hello, send_hello};
use hsip_net::udp::{listen_control, send_consent_request, send_consent_response};

// --- encrypted export/import deps ---
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

// --- cover/decoy (local thread) ---
use rand::RngCore;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

// --- session demo + wait-reply path (sealed frames over UDP) ---
use hsip_session::{Ephemeral, PeerLabel, Session};
use std::net::UdpSocket as StdUdpSocket;
use x25519_dalek::PublicKey as XPublicKey;

mod cmd_rep;
mod config;

#[derive(Parser)]
#[command(name = "hsip", version, about = "HSIP command-line")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // --- Identity ---
    Keygen,
    Init,
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

    // --- Consent (UDP) ---
    ConsentListen {
        #[arg(long, default_value = "0.0.0.0:40405")]
        addr: String,
        #[arg(long, default_value_t = false)]
        enforce_rep: bool,
        #[arg(long, default_value_t = -6)]
        threshold: i32,

        // ---- cover/decoy toggles (optional) ----
        /// Enable decoy/cover traffic to this same addr
        #[arg(long, default_value_t = false)]
        cover: bool,
        /// Average number of decoy packets per minute
        #[arg(long, default_value_t = 90)]
        cover_rate_per_min: u32,
        /// Minimum payload size (bytes)
        #[arg(long, default_value_t = 256)]
        cover_min_size: usize,
        /// Maximum payload size (bytes)
        #[arg(long, default_value_t = 1200)]
        cover_max_size: usize,
        /// Jitter around mean interval (± milliseconds)
        #[arg(long, default_value_t = 800)]
        cover_jitter_ms: u64,
        /// Print a progress line every N packets (0 = silent)
        #[arg(long, default_value_t = 0u64)]
        cover_verbose_every: u64,
    },
    ConsentSendRequest {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "req.json")]
        file: String,

        /// Wait for a sealed CONSENT_RESPONSE and print it
        #[arg(long, default_value_t = false)]
        wait_reply: bool,

        /// Max milliseconds to wait for reply when --wait-reply is set
        #[arg(long, default_value_t = 3000)]
        wait_timeout_ms: u64,
    },
    ConsentSendResponse {
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "resp.json")]
        file: String,
    },

    /// Create and sign a CONSENT_RESPONSE for a given request JSON.
    /// Requester peer is auto-read from request JSON; --requester-peer is a fallback.
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

        /// Enable sealed cover traffic (indistinguishable decoys) to the peer
        #[arg(long, default_value_t = false)]
        cover: bool,

        /// Decoy packets per minute (avg)
        #[arg(long, default_value_t = 60)]
        cover_rate_per_min: u32,

        /// Min payload size (bytes)
        #[arg(long, default_value_t = 256)]
        cover_min_size: usize,

        /// Max payload size (bytes)
        #[arg(long, default_value_t = 1200)]
        cover_max_size: usize,

        /// Jitter around mean interval (± ms)
        #[arg(long, default_value_t = 800)]
        cover_jitter_ms: u64,

        /// Print progress every N packets (0=silent)
        #[arg(long, default_value_t = 20u64)]
        cover_verbose_every: u64,
    },

    /// Minimal UDP session sender: handshakes with listener, then sends sealed frames.
    SessionSend {
        /// Listener address to handshake with
        #[arg(long, default_value = "127.0.0.1:50505")]
        to: String,

        /// Number of sealed data packets to send after handshake
        #[arg(long, default_value_t = 10)]
        packets: u32,

        /// Min/Max sealed payload sizes
        #[arg(long, default_value_t = 128)]
        min_size: usize,
        #[arg(long, default_value_t = 512)]
        max_size: usize,
    },

    // --- Reputation ---
    Rep(cmd_rep::RepArgs),
}

fn main() {
    if let Err(e) = config::apply() {
        eprintln!("[config] warning: {e}");
    }

    let cli = Cli::parse();

    match cli.command {
        // ===== Identity =====
        Commands::Keygen => {
            let (sk, vk) = generate_keypair();
            let peer_id = peer_id_from_pubkey(&vk);
            println!("PeerID: {}", peer_id);
            println!("PublicKey(hex): {}", vk_to_hex(&vk));
            println!("SecretKey(hex): {}", sk_to_hex(&sk));
            println!("\nNOTE: Keep SecretKey private.");
        }
        Commands::Init => {
            let (sk, vk) = generate_keypair();
            let peer_id = peer_id_from_pubkey(&vk);
            save_keypair(&sk, &vk).expect("save keystore");
            println!("Saved identity.");
            println!("PeerID: {}", peer_id);
        }
        Commands::Whoami => match load_keypair() {
            Ok((_sk, vk)) => {
                let pid = peer_id_from_pubkey(&vk);
                println!("PeerID: {}", pid);
                println!("PublicKey(hex): {}", vk_to_hex(&vk));
            }
            Err(e) => eprintln!("No identity found or failed to load: {e}"),
        },

        // ----- Plain export/import -----
        Commands::KeyExport { out } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            let peer_id = peer_id_from_pubkey(&vk);
            let default_out: PathBuf = dirs::home_dir().unwrap().join(".hsip").join("id.json");
            let out_path = out.map(PathBuf::from).unwrap_or(default_out);

            let json = serde_json::json!({
                "version": 1,
                "peer_id": peer_id,
                "sk_hex": sk_to_hex(&sk),
                "vk_hex": vk_to_hex(&vk),
                "note": "KEEP THIS FILE PRIVATE. Anyone with sk_hex can impersonate you."
            });
            fs::create_dir_all(out_path.parent().unwrap()).ok();
            fs::write(&out_path, serde_json::to_string_pretty(&json).unwrap())
                .expect("write export");

            println!("Exported identity to {}", out_path.display());
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
            println!("Imported identity. PeerID: {}", pid);
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

            // Derive key with Argon2id → PHC string contains params + salt
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let ph = argon2
                .hash_password(pass.as_bytes(), &salt)
                .expect("argon2 hash");
            // FIX: keep the owned String alive before borrowing bytes
            let hash_str = ph.hash.unwrap();
            let key_material = hash_str.as_bytes();
            assert!(key_material.len() >= 32);
            let key = Key::from_slice(&key_material[0..32]);

            // AEAD encrypt with random 96-bit nonce
            let cipher = ChaCha20Poly1305::new(key);
            let mut nonce_bytes = [0u8; 12];
            OsRng
                .try_fill(&mut nonce_bytes)
                .expect("failed to fill nonce");
            let nonce = Nonce::from_slice(&nonce_bytes);

            let sk_hex = sk_to_hex(&sk);
            let ct = cipher.encrypt(nonce, sk_hex.as_bytes()).expect("encrypt");

            let out_json = serde_json::json!({
                "version": 1,
                "peer_id": peer_id,
                "vk_hex": vk_to_hex(&vk),
                "kdf": "argon2id",
                "argon2": ph.to_string(), // includes params + salt
                "nonce_b64": B64.encode(nonce_bytes),
                "ciphertext_b64": B64.encode(ct),
                "note": "Encrypted export. Keep file private, remember your passphrase."
            });

            fs::create_dir_all(out_path.parent().unwrap()).ok();
            fs::write(&out_path, serde_json::to_string_pretty(&out_json).unwrap())
                .expect("write export enc");

            println!("Encrypted identity exported to {}", out_path.display());
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

            // Parse PHC string (has params + salt) and re-derive a key with the same salt
            let parsed_ph = PasswordHash::new(ph_s).expect("parse argon2 hash");
            let salt = parsed_ph.salt.expect("no salt in PHC");
            let argon2 = Argon2::default();
            let ph2 = argon2
                .hash_password(pass.as_bytes(), salt)
                .expect("argon2 re-hash");
            // FIX: hold the String before borrowing
            let hash_str2 = ph2.hash.unwrap();
            let key_material = hash_str2.as_bytes();
            assert!(key_material.len() >= 32);
            let key = Key::from_slice(&key_material[0..32]);

            let nonce_bytes = B64.decode(nonce_b64).expect("b64 nonce");
            let ct = B64.decode(ct_b64).expect("b64 ct");

            let cipher = ChaCha20Poly1305::new(key);
            let pt = cipher
                .decrypt(Nonce::from_slice(&nonce_bytes), ct.as_ref())
                .expect("decrypt");

            let sk_hex = String::from_utf8(pt).expect("utf8");
            let sk_bytes = hex::decode(sk_hex).expect("sk_hex decode");
            assert_eq!(sk_bytes.len(), 32, "sk_hex must be 32 bytes");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&sk_bytes);
            let sk = SigningKey::from_bytes(&arr);
            let vk = VerifyingKey::from(&sk);

            save_keypair(&sk, &vk).expect("save keystore");
            let pid = peer_id_from_pubkey(&vk);
            println!("Encrypted identity imported. PeerID: {}", pid);
        }

        // ===== Hello =====
        Commands::Hello => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            let hello = build_hello(&sk, &vk, now_ms());
            let json = serde_json::to_string_pretty(&hello).unwrap();
            println!("{}", json);
        }
        Commands::HelloListen { addr } => {
            if let Err(e) = listen_hello(&addr) {
                eprintln!("listen error: {e}");
            }
        }
        Commands::HelloSend { to } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            if let Err(e) = send_hello(&sk, &vk, &to, now_ms()) {
                eprintln!("send error: {e}");
            } else {
                println!("HELLO sent to {}", to);
            }
        }

        // ===== Consent (local files) =====
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
            println!("Wrote {}", out);
        }
        Commands::ConsentVerify { file } => {
            let data = fs::read(&file).expect("read file");
            let req: ConsentRequest = serde_json::from_slice(&data).expect("parse json");
            match verify_request(&req) {
                Ok(()) => println!("[OK] consent request is valid"),
                Err(e) => println!("[BAD] consent request invalid: {e}"),
            }
        }

        // ===== Consent over UDP =====
        Commands::ConsentListen {
            addr,
            enforce_rep,
            threshold,

            // cover toggles
            cover,
            cover_rate_per_min,
            cover_min_size,
            cover_max_size,
            cover_jitter_ms,
            cover_verbose_every,
        } => {
            if enforce_rep {
                std::env::set_var("HSIP_ENFORCE_REP", "1");
            }
            std::env::set_var("HSIP_REP_THRESHOLD", threshold.to_string());

            // Start background decoy thread if requested
            let _cover_handle = if cover {
                println!(
                    "[hsip] cover ON → {} | ~{} pkt/min | sizes {}–{} | jitter ±{} ms",
                    addr, cover_rate_per_min, cover_min_size, cover_max_size, cover_jitter_ms
                );
                let to_addr = addr.clone();
                Some(thread::spawn(move || {
                    let sock =
                        UdpSocket::bind("0.0.0.0:0").expect("bind ephemeral UDP socket for cover");
                    let mut buf = vec![0u8; cover_max_size.max(cover_min_size)];
                    let mut sent: u64 = 0;

                    let mean_ms = if cover_rate_per_min == 0 {
                        60_000
                    } else {
                        (60_000f64 / (cover_rate_per_min as f64)).round() as u64
                    };

                    loop {
                        // size ∈ [min, max]
                        let size = if cover_max_size <= cover_min_size {
                            cover_min_size
                        } else {
                            cover_min_size
                                + rand::thread_rng()
                                    .gen_range(0..=(cover_max_size - cover_min_size))
                        };

                        OsRng.fill_bytes(&mut buf[..size]);

                        let Ok((_n, _peer)) = sock.recv_from(&mut buf) else {
                            return;
                        };

                        sent += 1;
                        if cover_verbose_every > 0 && sent.is_multiple_of(cover_verbose_every) {
                            println!(
                                "(cover) sent {} decoys (last={} bytes) → {}",
                                sent, size, to_addr
                            );
                        }

                        // sleep ≈ mean ± jitter (uniform)
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

            if let Err(e) = listen_control(&addr) {
                eprintln!("consent listen error: {e}");
            }
        }

        // === NEW: --wait-reply implementation here ===
        Commands::ConsentSendRequest {
            to,
            file,
            wait_reply,
            wait_timeout_ms,
        } => {
            let bytes = std::fs::read(&file).expect("read request json");
            let req: ConsentRequest = serde_json::from_slice(&bytes).expect("parse request json");

            if !wait_reply {
                // old path
                if let Err(e) = send_consent_request(&to, &req) {
                    eprintln!("send consent request error: {e}");
                } else {
                    println!("CONSENT_REQUEST sent to {}", to);
                }
                return;
            }

            // --- Wait-reply path (manual sealed handshake + send + wait) ---
            let payload = serde_json::to_vec(&req).expect("encode req");

            let sock = StdUdpSocket::bind("0.0.0.0:0").expect("bind sender");
            sock.set_read_timeout(Some(std::time::Duration::from_millis(wait_timeout_ms))) // wait for reply
                .expect("set timeout");

            // 1) E1
            let eph = Ephemeral::generate();
            let our_pub = eph.public();
            let mut e1 = [0u8; 1 + 32];
            e1[0] = TAG_E1;
            e1[1..].copy_from_slice(our_pub.as_bytes());
            sock.send_to(&e1, &to).expect("send E1");

            // 2) E2
            let mut buf = [0u8; 64];
            let (n, _peer) = sock.recv_from(&mut buf).expect("recv");
            if n < 1 + 32 || buf[0] != TAG_E2 {
                panic!("unexpected handshake response");
            }
            let mut srv_pub_bytes = [0u8; 32];
            srv_pub_bytes.copy_from_slice(&buf[1..33]);
            let srv_pub = XPublicKey::from(srv_pub_bytes);

            // 3) Build session
            let label = PeerLabel {
                label: b"CONSENTv1".to_vec(),
            };
            let shared = eph.into_shared(&srv_pub);
            let mut sess = Session::from_shared_secret(shared, Some(&label));

            // 4) Send sealed request
            let ct = sess.seal(AAD_CONTROL, &payload);
            let mut packet = Vec::with_capacity(1 + ct.len());
            packet.push(TAG_D);
            packet.extend_from_slice(&ct);
            sock.send_to(&packet, &to).expect("send sealed D");
            println!("[control-send] sealed {} bytes → {}", payload.len(), to);

            // 5) Wait for a sealed D (response)
            let mut rbuf = vec![0u8; 65535];
            match sock.recv_from(&mut rbuf) {
                Ok((rn, _p)) if rn >= 1 && rbuf[0] == TAG_D => {
                    let ct = &rbuf[1..rn];
                    match sess.open(AAD_CONTROL, ct) {
                        Ok(pt) => {
                            // Try to parse as ConsentResponse
                            match serde_json::from_slice::<ConsentResponse>(&pt) {
                                Ok(resp) => {
                                    println!(
                                        "[control-send] reply: decision='{}' ttl_ms={} request_hash={}",
                                        resp.decision, resp.ttl_ms, resp.request_hash_hex
                                    );
                                }
                                Err(_) => {
                                    // show JSON anyway
                                    let s = String::from_utf8_lossy(&pt);
                                    println!("[control-send] reply (json): {}", s);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[control-send] failed to open reply: {e:?}");
                        }
                    }
                }
                Ok((_rn, _p)) => {
                    eprintln!("[control-send] unexpected frame while waiting for reply");
                }
                Err(e) => {
                    eprintln!(
                        "[control-send] no reply within {} ms ({e})",
                        wait_timeout_ms
                    );
                }
            }
        }

        Commands::ConsentSendResponse { to, file } => {
            let bytes = std::fs::read(&file).expect("read response json");
            let resp: ConsentResponse =
                serde_json::from_slice(&bytes).expect("parse response json");
            if let Err(e) = send_consent_response(&to, &resp) {
                eprintln!("send consent response error: {e}");
            } else {
                println!("CONSENT_RESPONSE sent to {}", to);
            }
        }

        // ===== Consent Respond (local) with policy debug
        Commands::ConsentRespond {
            request,
            decision,
            ttl_ms,
            out,
            enforce_rep,
            requester_peer,
            threshold,
        } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");

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
                "[PolicyDebug] enforce={} (flag={} env={} cfg={}), threshold={}, requester='{}', log='{}'",
                effective_enforce, enforce_rep, env_enforce, cfg_enforce, block_threshold, requester_peer_id, log_path.display()
            );

            let mut final_decision = decision.clone();

            if effective_enforce && !requester_peer_id.is_empty() {
                let store =
                    hsip_reputation::store::Store::open(log_path.clone()).expect("open rep log");
                let score = store.compute_score(&requester_peer_id).unwrap_or(0);
                eprintln!(
                    "[PolicyDebug] computed score for {} = {}",
                    requester_peer_id, score
                );

                if score < block_threshold {
                    eprintln!(
                        "[Policy] requester {} has score {} < {} → auto-deny",
                        requester_peer_id, score, block_threshold
                    );
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
                } else {
                    eprintln!(
                        "[Policy] requester {} score {} ≥ {} → allow",
                        requester_peer_id, score, block_threshold
                    );
                }
            } else if effective_enforce && requester_peer_id.is_empty() {
                eprintln!(
                    "[Policy] enforcement enabled but requester peer missing; skipping enforcement"
                );
            } else {
                eprintln!("[PolicyDebug] enforcement disabled");
            }

            let resp = build_response(&sk, &vk, &req, &final_decision, ttl_ms, now_ms())
                .expect("build response");
            let json = serde_json::to_string_pretty(&resp).unwrap();
            fs::write(&out, json).expect("write response");
            println!("Wrote {}", out);
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
                Ok(()) => println!("[OK] consent response is valid and bound to request"),
                Err(e) => println!("[BAD] consent response invalid: {e}"),
            }
        }

        // ===== Session demo: listener (sealed frames over UDP) =====
        Commands::SessionListen {
            addr,
            cover,
            cover_rate_per_min,
            cover_min_size,
            cover_max_size,
            cover_jitter_ms,
            cover_verbose_every,
        } => {
            // Bind UDP
            let sock = StdUdpSocket::bind(&addr).expect("bind listener");
            sock.set_nonblocking(true).ok();
            println!("[session-listen] bound on {}", addr);

            // 1) Wait for E1 from client (client eph pubkey)
            let mut buf = vec![0u8; 4096];
            let (_n, peer) = loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, p)) if n > 32 && buf[0] == TAG_E1 => break (n, p),
                    Ok((_n, _p)) => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("recv E1: {e}"),
                }
            };
            let mut peer_pub_bytes = [0u8; 32];
            peer_pub_bytes.copy_from_slice(&buf[1..33]);
            let peer_pub = XPublicKey::from(peer_pub_bytes);

            // 2) Generate our eph, derive SHARED ONCE, build two sessions (RX & TX), send E2 ONCE
            let eph = Ephemeral::generate();
            let our_pub = eph.public();
            let label = PeerLabel {
                label: b"CONSENTv1".to_vec(),
            };

            // Consume eph to derive shared secret
            let shared = eph.into_shared(&peer_pub);

            // Two independent sessions from the SAME shared secret:
            let mut sess_rx = Session::from_shared_secret(shared, Some(&label));
            let mut sess_tx = Session::from_shared_secret(shared, Some(&label));

            // Send E2 once
            let mut e2 = [0u8; 1 + 32];
            e2[0] = TAG_E2;
            e2[1..].copy_from_slice(our_pub.as_bytes());
            sock.send_to(&e2, peer).ok();
            println!("[session-listen] handshake with {} complete", peer);

            // 3) Optional sealed cover to the same peer (uses sess_tx)
            let cover_handle = if cover {
                println!(
                    "[session-listen] cover ON → {} | ~{} pkt/min | sizes {}–{} | jitter ±{} ms",
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

                        let ct = sess_tx.seal(b"type=DATA", &payload); // sealed like real data
                        let mut packet = Vec::with_capacity(1 + ct.len());
                        packet.push(TAG_D);
                        packet.extend_from_slice(&ct);
                        let _ = sock_tx.send_to(&packet, to_addr);

                        sent += 1;
                        if verbose_every > 0 && sent.is_multiple_of(verbose_every) {
                            println!(
                                "(cover) sent {} decoys (last={} bytes) → {}",
                                sent, size, to_addr
                            );
                        }

                        // sleep ≈ mean ± jitter
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

            // 4) Receive sealed D frames and open with sess_rx
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, p)) if n >= 1 && buf[0] == TAG_D => {
                        let ct = &buf[1..n];
                        match sess_rx.open(b"type=DATA", ct) {
                            Ok(pt) => {
                                println!("[session-listen] opened {} bytes from {}", pt.len(), p);
                            }
                            Err(e) => eprintln!("[session-listen] open error from {p}: {e:?}"),
                        }
                    }
                    Ok((_n, _p)) => { /* ignore other frames */ }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => {
                        eprintln!("recv error: {e}");
                        break;
                    }
                }
            }

            if let Some(h) = cover_handle {
                let _ = h.join();
            }
        }

        // ===== Session demo: sender =====
        Commands::SessionSend {
            to,
            packets,
            min_size,
            max_size,
        } => {
            // bind ephemeral UDP
            let sock = StdUdpSocket::bind("0.0.0.0:0").expect("bind sender");
            sock.set_nonblocking(true).ok();

            // 1) Create eph + send E1
            let eph = Ephemeral::generate();
            let our_pub = eph.public();
            let mut e1 = [0u8; 1 + 32];
            e1[0] = TAG_E1;
            e1[1..].copy_from_slice(our_pub.as_bytes());
            sock.send_to(&e1, &to).expect("send E1");

            // 2) Wait for E2
            let mut buf = vec![0u8; 4096];
            let (_n, _peer) = loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, p)) if n > 32 && buf[0] == TAG_E2 => break (n, p),
                    Ok((_n, _p)) => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("recv E2: {e}"),
                }
            };
            let mut srv_pub_bytes = [0u8; 32];
            srv_pub_bytes.copy_from_slice(&buf[1..33]);
            let srv_pub = XPublicKey::from(srv_pub_bytes);

            // 3) Build session (client side)
            let label = PeerLabel {
                label: b"CONSENTv1".to_vec(),
            };
            let mut sess = Session::from_handshake(eph, &srv_pub, Some(&label));
            println!("[session-send] handshake with {} complete", to);

            // 4) Send sealed data frames
            for i in 1..=packets {
                let size = rand_range(min_size, max_size);
                let mut payload = vec![0u8; size];
                rand::rngs::OsRng.fill_bytes(&mut payload);

                let ct = sess.seal(b"type=DATA", &payload);
                let mut packet = Vec::with_capacity(1 + ct.len());
                packet.push(TAG_D);
                packet.extend_from_slice(&ct);

                sock.send_to(&packet, &to).ok();
                println!("[session-send] sent {i}/{packets} ({} bytes payload)", size);

                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            println!("[session-send] done.");
        }

        // ===== Reputation =====
        Commands::Rep(args) => cmd_rep::run_rep(args).expect("rep command failed"),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

// === Session/Control wire tags used by both demos and wait-reply ===
const TAG_E1: u8 = 0xE1;
const TAG_E2: u8 = 0xE2;
const TAG_D: u8 = 0xD0;

// Control-plane AAD (must match listener)
const AAD_CONTROL: &[u8] = b"type=CONTROL";

fn rand_range(min: usize, max: usize) -> usize {
    if max <= min {
        return min;
    }
    let span = (max - min) as u64;
    (min as u64 + (rand::random::<u64>() % (span + 1))) as usize
}

fn mean_interval_ms(rate_per_min: u32) -> u64 {
    let r = rate_per_min.max(1) as f64;
    (60_000.0 / r).round() as u64
}
