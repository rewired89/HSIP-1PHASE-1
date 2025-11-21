// crates/hsip-gateway/src/main.rs

mod proxy;
mod classify;
mod metrics;

use crate::proxy::{run_proxy, ProxyConfig};

fn main() {
    // Very small env-based config so you don't need flags yet.
    let listen_addr =
        std::env::var("HSIP_GATEWAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let connect_timeout_ms = std::env::var("HSIP_GATEWAY_CONNECT_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5_000);

    let cfg = ProxyConfig {
        listen_addr,
        connect_timeout_ms,
    };

    eprintln!(
        "[gateway] starting HSIP Web Gateway on {} (timeout={}ms)",
        cfg.listen_addr, cfg.connect_timeout_ms
    );

    if let Err(e) = run_proxy(cfg) {
        eprintln!("[gateway] fatal error: {e:#}");
        std::process::exit(1);
    }
}
