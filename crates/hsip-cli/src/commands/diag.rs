use anyhow::{anyhow, Result};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use hsip_core::identity::{peer_id_from_pubkey, vk_to_hex};
use hsip_core::keystore::load_keypair;
use hsip_session::{PeerLabel, Session};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::config;

/// Run `hsip diag`
pub fn run_diag() -> Result<()> {
    println!("=== HSIP DIAGNOSTICS (v0.2.0-mvp) ===\n");

    print_identity_section()?;
    print_config_section();
    print_env_section();
    print_endpoints_section();

    println!();
    nonce_replay_selftest()?;

    println!("\n[DIAG] done.");
    Ok(())
}

// ---------------- IDENTITY ----------------

fn print_identity_section() -> Result<()> {
    println!("--- Identity ---");
    match load_keypair() {
        Ok((_sk, vk)) => {
            let pid = peer_id_from_pubkey(&vk);
            println!("  PeerID:           {}", pid);
            println!("  PublicKey (hex):  {}", vk_to_hex(&vk));
        }
        Err(e) => {
            println!("  (no identity found)");
            println!("  hint: run `hsip init` first. error: {e}");
        }
    }
    Ok(())
}

// ---------------- CONFIG ----------------

fn print_config_section() {
    println!("\n--- Config ---");
    match config::read_config() {
        Ok(Some(_cfg)) => {
            // We don't assume any fields on Config, just confirm it loaded.
            println!("  config:           loaded (user config active)");
        }
        Ok(None) => {
            println!("  config:           <none> (using built-in defaults)");
        }
        Err(e) => {
            println!("  config:           ERROR: {e}");
        }
    }
}

// ---------------- ENV VARS ----------------

fn print_env_section() {
    println!("\n--- Environment ---");

    print_env_var("HSIP_ENFORCE_REP");
    print_env_var("HSIP_REP_THRESHOLD");
    print_env_var("HSIP_DEV_LOCAL");
    print_env_var("HSIP_LOG");

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    println!("  now_ms:           {}", now_ms);
}

fn print_env_var(name: &str) {
    match env::var(name) {
        Ok(v) => println!("  {name} = {v}"),
        Err(_) => println!("  {name} = <unset>"),
    }
}

// ---------------- ENDPOINTS SUMMARY ----------------

fn print_endpoints_section() {
    println!("\n--- Local endpoints (default demos) ---");
    println!("  HELLO demo:         127.0.0.1:40404");
    println!("  HANDSHAKE demo:     127.0.0.1:9000");
    println!("  SESSION demo:       127.0.0.1:50505");
    println!("  PING demo:          127.0.0.1:51515");
    println!("  CONSENT control:    0.0.0.0:40405");
    println!("  Status daemon:      127.0.0.1:8787");
    println!("  Identity broker:    127.0.0.1:9100");
    println!("  Tray /consent API:  127.0.0.1:9389");
    println!("  HSIP demo site:     127.0.0.1:8080");
}

// ---------------- NONCE / REPLAY SELF-TEST ----------------

fn nonce_replay_selftest() -> Result<()> {
    println!("--- Nonce / replay self-test ---");

    // Fake shared secret for a local Session instance
    let mut shared = [0u8; 32];
    OsRng.fill_bytes(&mut shared);

    let label = PeerLabel {
        label: b"NONCE_TEST".to_vec(),
    };

    // One session for sender and one for receiver, like normal
    let mut sess_tx = Session::from_shared_secret(shared, Some(&label))
        .map_err(|e| anyhow!("from_shared_secret(tx): {e:?}"))?;
    let mut sess_rx = Session::from_shared_secret(shared, Some(&label))
        .map_err(|e| anyhow!("from_shared_secret(rx): {e:?}"))?;

    // Random payload
    let mut payload = [0u8; 48];
    OsRng.fill_bytes(&mut payload);

    // Seal once
    let ct = sess_tx
        .seal(b"type=TEST", &payload)
        .map_err(|e| anyhow!("seal: {e:?}"))?;

    // 1st open should succeed
    let pt1 = sess_rx
        .open(b"type=TEST", &ct)
        .map_err(|e| anyhow!("open(1st) failed: {e:?}"))?;

    if pt1 != payload {
        println!("  [FAIL] decrypted payload mismatch on first open");
        return Err(anyhow!("decrypted payload mismatch"));
    }

    // 2nd open of same ciphertext should FAIL (replay)
    match sess_rx.open(b"type=TEST", &ct) {
        Ok(_) => {
            println!(
                "  [WARN] replay accepted (open(2nd) succeeded) – check Session anti-replay config"
            );
        }
        Err(_e) => {
            println!("  [OK] replay rejected as expected (open(2nd) failed)");
        }
    }

    println!("  [OK] nonce / replay self-test completed.");
    Ok(())
}
