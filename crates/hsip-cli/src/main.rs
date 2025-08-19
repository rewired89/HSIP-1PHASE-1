use clap::{Parser, Subcommand};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};

use hsip_core::identity::{generate_keypair, peer_id_from_pubkey, sk_to_hex, vk_to_hex};
use hsip_core::keystore::{load_keypair, save_keypair};
use hsip_core::consent::{
    build_request,
    build_response,
    verify_request,
    verify_response,
    cid_hex,
    ConsentRequest,
    ConsentResponse,
};

use hsip_net::hello::build_hello;
use hsip_net::udp::{
    listen_hello,
    send_hello,
    listen_control,           // consent over UDP listener
    send_consent_request,     // send CONSENT_REQUEST over UDP
    send_consent_response,    // send CONSENT_RESPONSE over UDP
};

use hsip_reputation::{append_decision, verify_log, read_all, Decision};

#[derive(Parser)]
#[command(name = "hsip", version, about = "HSIP command-line")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair and print PeerID
    Keygen,

    /// Generate + save identity to local keystore (dev plaintext)
    Init,

    /// Show current identity (from keystore)
    Whoami,

    /// Build and print a HELLO message using saved identity
    Hello,

    /// Listen for HELLO packets on UDP (default 0.0.0.0:40404)
    Listen {
        #[arg(long, default_value = "0.0.0.0:40404")]
        addr: String,
    },

    /// Send a HELLO to a UDP address, e.g. 192.168.1.10:40404
    Send {
        #[arg(long)]
        to: String,
    },

    /// Create a signed CONSENT_REQUEST for a file
    ConsentRequest {
        #[arg(long)]
        file: String,
        #[arg(long)]
        purpose: String,
        /// Absolute expiry time in ms since epoch
        #[arg(long)]
        expires_ms: u64,
        /// Where to write JSON (default: ./consent_request.json)
        #[arg(long, default_value = "consent_request.json")]
        out: String,
    },

    /// Verify a CONSENT_REQUEST JSON file
    ConsentVerify {
        #[arg(long, default_value = "consent_request.json")]
        file: String,
    },

    // === Consent over UDP ===

    /// Listen for HELLO + CONSENT messages on UDP (control plane)
    ConsentListen {
        #[arg(long, default_value = "0.0.0.0:40405")]
        addr: String,
    },

    /// Send a CONSENT_REQUEST JSON to an address
    ConsentSendRequest {
        #[arg(long)]
        to: String,
        /// Path to a ConsentRequest JSON (e.g., req.json)
        #[arg(long, default_value = "req.json")]
        file: String,
    },

    /// Send a CONSENT_RESPONSE JSON to an address
    ConsentSendResponse {
        #[arg(long)]
        to: String,
        /// Path to a ConsentResponse JSON (e.g., resp.json)
        #[arg(long, default_value = "resp.json")]
        file: String,
    },

    // === Response creation/verification (local) ===

    /// Create and sign a CONSENT_RESPONSE for a given request JSON
    ConsentRespond {
        /// Path to the request JSON you are responding to
        #[arg(long, default_value = "req.json")]
        request: String,
        /// "allow" or "deny"
        #[arg(long)]
        decision: String,
        /// Time-to-live in ms if decision=allow, else 0
        #[arg(long, default_value_t = 0)]
        ttl_ms: u64,
        /// Output path for the response JSON
        #[arg(long, default_value = "resp.json")]
        out: String,
    },

    /// Verify a CONSENT_RESPONSE against its request
    ConsentVerifyResponse {
        /// Path to the request JSON
        #[arg(long, default_value = "req.json")]
        request: String,
        /// Path to the response JSON
        #[arg(long, default_value = "resp.json")]
        response: String,
    },

    // === Reputation log (local, signed, hash-chained) ===

    /// Append a local, signed decision to the reputation log
    RepAppend {
        /// "allow" or "deny"
        #[arg(long)]
        decision: String,
        /// TTL in ms (required if decision=allow)
        #[arg(long, default_value_t = 0)]
        ttl_ms: u64,
        /// Content CID hex
        #[arg(long)]
        cid: String,
        /// Purpose string
        #[arg(long)]
        purpose: String,
        /// Requester PeerID (who asked)
        #[arg(long)]
        requester: String,
        /// Log file path
        #[arg(long, default_value = "reputation.log")]
        log: String,
    },

    /// Verify the reputation log chain and signatures
    RepVerify {
        #[arg(long, default_value = "reputation.log")]
        log: String,
    },

    /// Print the reputation log as pretty JSON
    RepShow {
        #[arg(long, default_value = "reputation.log")]
        log: String,
    },
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        // ===== Identity / Hello =====
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

        Commands::Whoami => {
            match load_keypair() {
                Ok((_sk, vk)) => {
                    let pid = peer_id_from_pubkey(&vk);
                    println!("PeerID: {}", pid);
                    println!("PublicKey(hex): {}", vk_to_hex(&vk));
                }
                Err(e) => eprintln!("No identity found or failed to load: {e}"),
            }
        }

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
        Commands::ConsentListen { addr } => {
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
            let resp: ConsentResponse =
                serde_json::from_slice(&bytes).expect("parse response json");
            if let Err(e) = send_consent_response(&to, &resp) {
                eprintln!("send consent response error: {e}");
            } else {
                println!("CONSENT_RESPONSE sent to {}", to);
            }
        }

        // ===== Response creation / verification =====
        Commands::ConsentRespond { request, decision, ttl_ms, out } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");

            let req_bytes = fs::read(&request).expect("read request file");
            let req: ConsentRequest = serde_json::from_slice(&req_bytes).expect("parse request");

            let resp = build_response(&sk, &vk, &req, &decision, ttl_ms, now_ms())
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

        // ===== Reputation log =====
        Commands::RepAppend { decision, ttl_ms, cid, purpose, requester, log } => {
            let (sk, vk) = load_keypair().expect("load identity first via `hsip init`");
            let dec = match decision.as_str() {
                "allow" => Decision::Allow { ttl_ms },
                "deny"  => Decision::Deny,
                other   => { eprintln!("invalid --decision {other} (use allow|deny)"); return; }
            };
            let entry = append_decision(
                &log,
                &sk,
                &vk,
                now_ms(),
                dec,
                cid,
                purpose,
                requester
            ).expect("append decision");
            println!("{}", serde_json::to_string_pretty(&entry).unwrap());
        }

        Commands::RepVerify { log } => {
            match verify_log(&log) {
                Ok(()) => println!("[OK] reputation log valid"),
                Err(e) => println!("[BAD] reputation log invalid: {e}"),
            }
        }

        Commands::RepShow { log } => {
            match read_all(&log) {
                Ok(items) => println!("{}", serde_json::to_string_pretty(&items).unwrap()),
                Err(e) => eprintln!("read error: {e}"),
            }
        }
    }
}
