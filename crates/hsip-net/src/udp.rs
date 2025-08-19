use std::net::UdpSocket;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json;

use crate::hello::{build_hello, verify_hello, Hello};
use hsip_core::consent::{ConsentRequest, ConsentResponse, verify_request};

/// Send a HELLO message to `to` (e.g., "127.0.0.1:40404")
pub fn send_hello(
    sk: &SigningKey,
    vk: &VerifyingKey,
    to: &str,
    now_ms: u64,
) -> Result<(), String> {
    let hello = build_hello(sk, vk, now_ms);
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_write_timeout(Some(Duration::from_secs(2))).ok();

    let data = serde_json::to_vec(&hello).map_err(|e| e.to_string())?;
    sock.send_to(&data, to).map_err(|e| e.to_string())?;
    Ok(())
}

/// Listen only for HELLO messages on `addr` (e.g., "0.0.0.0:40404")
pub fn listen_hello(addr: &str) -> Result<(), String> {
    let sock = UdpSocket::bind(addr).map_err(|e| e.to_string())?;
    sock.set_read_timeout(None).ok();
    println!("Listening for HSIP HELLO on udp://{addr}");

    let mut buf = [0u8; 65535];
    loop {
        let (n, src) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
        let data = &buf[..n];

        match serde_json::from_slice::<Hello>(data) {
            Ok(h) => match verify_hello(&h) {
                Ok(()) => println!("[OK] from {src} peer_id={}", h.peer_id),
                Err(e) => println!("[BAD] from {src}: {e}"),
            },
            Err(_) => {
                let preview = String::from_utf8_lossy(&data[..data.len().min(120)]);
                println!("[UNKNOWN] from {src}: {}", preview);
            }
        }
    }
}

/// Send a CONSENT_REQUEST JSON to `to`
pub fn send_consent_request(to: &str, req: &ConsentRequest) -> Result<(), String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_write_timeout(Some(Duration::from_secs(2))).ok();

    let data = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    sock.send_to(&data, to).map_err(|e| e.to_string())?;
    Ok(())
}

/// Send a CONSENT_RESPONSE JSON to `to`
pub fn send_consent_response(to: &str, resp: &ConsentResponse) -> Result<(), String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_write_timeout(Some(Duration::from_secs(2))).ok();

    let data = serde_json::to_vec(resp).map_err(|e| e.to_string())?;
    sock.send_to(&data, to).map_err(|e| e.to_string())?;
    Ok(())
}

/// Listen for any HSIP control JSON (HELLO, CONSENT_REQUEST, CONSENT_RESPONSE)
/// Use a different port than listen_hello(), e.g., "0.0.0.0:40405"
pub fn listen_control(addr: &str) -> Result<(), String> {
    let sock = UdpSocket::bind(addr).map_err(|e| e.to_string())?;
    sock.set_read_timeout(None).ok();
    println!("Listening for HSIP control on udp://{addr}");

    let mut buf = [0u8; 65535];
    loop {
        let (n, src) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
        let data = &buf[..n];

        // 1) HELLO
        if let Ok(h) = serde_json::from_slice::<Hello>(data) {
            match verify_hello(&h) {
                Ok(()) => println!("[HELLO OK] from {src} peer_id={}", h.peer_id),
                Err(e) => println!("[HELLO BAD] from {src}: {e}"),
            }
            continue;
        }

        // 2) CONSENT_REQUEST
        if let Ok(req) = serde_json::from_slice::<ConsentRequest>(data) {
            match verify_request(&req) {
                Ok(()) => println!(
                    "[CONSENT_REQUEST OK] from {src} cid={} purpose={} exp_ms={}",
                    req.content_cid_hex, req.purpose, req.expires_ms
                ),
                Err(e) => println!("[CONSENT_REQUEST BAD] from {src}: {e}"),
            }
            continue;
        }

        // 3) CONSENT_RESPONSE (cannot fully verify without the matching request)
        if let Ok(resp) = serde_json::from_slice::<ConsentResponse>(data) {
            println!(
                "[CONSENT_RESPONSE recv] from {src} decision={} ttl_ms={} ts_ms={}",
                resp.decision, resp.ttl_ms, resp.ts_ms
            );
            continue;
        }

        // Fallback: unknown JSON
        let preview = String::from_utf8_lossy(&data[..data.len().min(160)]);
        println!("[UNKNOWN JSON] from {src}: {}", preview);
    }
}
