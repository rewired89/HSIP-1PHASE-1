mod proxy;

use crate::proxy::{run_proxy, Config};
use anyhow::Result;

fn main() -> Result<()> {
    // Allow overriding via env if you ever want:
    //   HSIP_GATEWAY_LISTEN=0.0.0.0:8080
    //   HSIP_GATEWAY_TIMEOUT_MS=8000
    let listen =
        std::env::var("HSIP_GATEWAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let timeout_ms = std::env::var("HSIP_GATEWAY_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5000);

    let cfg = Config {
        listen_addr: listen,
        connect_timeout_ms: timeout_ms,
    };

    println!("[gateway] starting with cfg: {:?}", cfg);
    run_proxy(cfg)
}
