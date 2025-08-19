use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};

use hsip_core::consent::{
    build_request, build_response, verify_request, verify_response, cid_hex, ConsentRequest,
    ConsentResponse,
};
use hsip_core::identity::{generate_keypair, peer_id_from_pubkey, sk_to_hex, vk_to_hex};
use hsip_core::keystore::{load_keypair, save_keypair};

use hsip_net::hello::build_hello;
use hsip_net::udp::{
    listen_control, listen_hello, send_consent_request, send_consent_response, send_hello,
};

// --- encrypted export/import deps ---
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString, PasswordHash};
use rand::rngs::OsRng;
use rand::Rng; // for try_fill
use chacha20poly1305::{ChaCha20Poly1305, aead::{Aead, KeyInit}, Key, Nonce};
use rpassword::prompt_password;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hex;

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
    KeyExport { #[arg(long)] out: Option<String> },

    /// Import identity from plaintext JSON
    KeyImport { #[arg(long)] file: String },

    /// Export identity encrypted with a passphrase (Argon2id + ChaCha20-Poly1305)
    KeyExportEnc { #[arg(long)] out: Option<String> },

    /// Import encrypted identity (prompts for passphrase)
    KeyImportEnc { #[arg(long)] file: String },

    // --- Hello ---
    Hello,
    Listen { #[arg(long, default_value = "0.0.0.0:40404")] addr: String },
    Send { #[arg(long)] to: String },

    // --- Consent (local) ---
    ConsentRequest {
        #[arg(long)] file: String,
        #[arg(long)] purpose: String,
        #[arg(long)] expires_ms: u64,
        #[arg(long, default_value = "consent_request.json")] out: String,
    },
    ConsentVerify { #[arg(long, default_value = "consent_request.json")] file: String },

    // --- Consent (UDP) ---
    ConsentListen {
        #[arg(long, default_value = "0.0.0.0:40405")] addr: String,
        #[arg(long, default_value_t = false)] enforce_rep: bool,
        #[arg(long, default_value_t = -6)] threshold: i32,
    },
    ConsentSendRequest { #[arg(long)] to: String, #[arg(long, default_value = "req.json")] file: String },
    ConsentSendResponse { #[arg(long)] to: String, #[arg(long, default_value = "resp.json")] file: String },

    /// Create and sign a CONSENT_RESPONSE for a given request JSON.
    /// Requester peer is auto-read from request JSON; --requester-peer is a fallback.
    ConsentRespond {
        #[arg(long, default_value = "req.json")] request: String,
        #[arg(long)] decision: String,
        #[arg(long, default_value_t = 0)] ttl_ms: u64,
        #[arg(long, default_value = "resp.json")] out: String,
        #[arg(long, default_value_t = false)] enforce_rep: bool,
        #[arg(long)] requester_peer: Option<String>,
        #[arg(long, default_value_t = -6)] threshold: i32,
    },
    ConsentVerifyResponse {
        #[arg(long, default_value = "req.json")] request: String,
        #[arg(long, default_value = "resp.json")] response: String,
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
            OsRng.try_fill(&mut nonce_bytes).expect("failed to fill nonce");
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

            let ph_s = v.get("argon2").and_then(|x| x.as_str()).expect("missing argon2");
            let nonce_b64 = v.get("nonce_b64").and_then(|x| x.as_str()).expect("missing nonce_b64");
            let ct_b64 = v.get("ciphertext_b64").and_then(|x| x.as_str()).expect("missing ciphertext_b64");

            let pass = prompt_password("Passphrase: ").expect("read pass");

            // Parse PHC string (has params + salt) and re-derive a key with the same salt
            let parsed_ph = PasswordHash::new(ph_s).expect("parse argon2 hash");
            let salt = parsed_ph.salt.expect("no salt in PHC");
            let argon2 = Argon2::default();
            let ph2 = argon2.hash_password(pass.as_bytes(), salt).expect("argon2 re-hash");
            // FIX: hold the String before borrowing
            let hash_str2 = ph2.hash.unwrap();
            let key_material = hash_str2.as_bytes();
            assert!(key_material.len() >= 32);
            let key = Key::from_slice(&key_material[0..32]);

            let nonce_bytes = B64.decode(nonce_b64).expect("b64 nonce");
            let ct = B64.decode(ct_b64).expect("b64 ct");

            let cipher = ChaCha20Poly1305::new(key);
            let pt = cipher.decrypt(Nonce::from_slice(&nonce_bytes), ct.as_ref())
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
        Commands::Listen { addr } => {
            if let Err(e) = listen_hello(&addr) {
                eprintln!("listen error: {e}");
            }
        }
        Commands::Send { to } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            if let Err(e) = send_hello(&sk, &vk, &to, now_ms()) {
                eprintln!("send error: {e}");
            } else {
                println!("HELLO sent to {}", to);
            }
        }

        // ===== Consent (local files) =====
        Commands::ConsentRequest { file, purpose, expires_ms, out } => {
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
        Commands::ConsentListen { addr, enforce_rep, threshold } => {
            if enforce_rep { std::env::set_var("HSIP_ENFORCE_REP", "1"); }
            std::env::set_var("HSIP_REP_THRESHOLD", threshold.to_string());
            if let Err(e) = listen_control(&addr) {
                eprintln!("consent listen error: {e}");
            }
        }
        Commands::ConsentSendRequest { to, file } => {
            let bytes = std::fs::read(&file).expect("read request json");
            let req: ConsentRequest = serde_json::from_slice(&bytes).expect("parse request json");
            if let Err(e) = send_consent_request(&to, &req) {
                eprintln!("send consent request error: {e}");
            } else {
                println!("CONSENT_REQUEST sent to {}", to);
            }
        }
        Commands::ConsentSendResponse { to, file } => {
            let bytes = std::fs::read(&file).expect("read response json");
            let resp: ConsentResponse = serde_json::from_slice(&bytes).expect("parse response json");
            if let Err(e) = send_consent_response(&to, &resp) {
                eprintln!("send consent response error: {e}");
            } else {
                println!("CONSENT_RESPONSE sent to {}", to);
            }
        }

        // ===== Consent Respond (local) with policy debug
        Commands::ConsentRespond { request, decision, ttl_ms, out, enforce_rep, requester_peer, threshold } => {
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
            let cfg_enforce = cfg.as_ref().and_then(|c| c.policy.enforce_rep).unwrap_or(false);
            let effective_enforce = enforce_rep || env_enforce || cfg_enforce;

            let env_thresh = std::env::var("HSIP_REP_THRESHOLD").ok().and_then(|s| s.parse::<i32>().ok());
            let cfg_thresh  = cfg.as_ref().and_then(|c| c.policy.rep_threshold);
            let block_threshold = env_thresh.or(cfg_thresh).unwrap_or(threshold);

            let log_path: PathBuf = dirs::home_dir().unwrap().join(".hsip").join("reputation.log");
            eprintln!(
                "[PolicyDebug] enforce={} (flag={} env={} cfg={}), threshold={}, requester='{}', log='{}'",
                effective_enforce, enforce_rep, env_enforce, cfg_enforce, block_threshold, requester_peer_id, log_path.display()
            );

            let mut final_decision = decision.clone();

            if effective_enforce && !requester_peer_id.is_empty() {
                let store = hsip_reputation::store::Store::open(log_path.clone()).expect("open rep log");
                let score = store.compute_score(&requester_peer_id).unwrap_or(0);
                eprintln!("[PolicyDebug] computed score for {} = {}", requester_peer_id, score);

                if score < block_threshold {
                    eprintln!("[Policy] requester {} has score {} < {} → auto-deny",
                        requester_peer_id, score, block_threshold);
                    final_decision = "deny".to_string();

                    let (my_sk, my_vk) = load_keypair().expect("load identity");
                    let my_peer = peer_id_from_pubkey(&my_vk);
                    let _ = store.append(
                        &my_sk, &my_peer, &requester_peer_id,
                        hsip_reputation::store::DecisionType::MISBEHAVIOR,
                        1,
                        "POLICY_THRESHOLD",
                        "Auto-deny due to low reputation score",
                        vec![],
                        Some("7d".to_string()),
                    );
                } else {
                    eprintln!("[Policy] requester {} score {} ≥ {} → allow", requester_peer_id, score, block_threshold);
                }
            } else if effective_enforce && requester_peer_id.is_empty() {
                eprintln!("[Policy] enforcement enabled but requester peer missing; skipping enforcement");
            } else {
                eprintln!("[PolicyDebug] enforcement disabled");
            }

            let resp = build_response(&sk, &vk, &req, &final_decision, ttl_ms, now_ms()).expect("build response");
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
