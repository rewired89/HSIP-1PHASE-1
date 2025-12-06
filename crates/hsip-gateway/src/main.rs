mod proxy;

use crate::proxy::{run_proxy, Config};
use anyhow::Result;

fn main() -> Result<()> {
    let gateway_config = build_gateway_configuration();
    
    println!("[gateway] Initializing with configuration: {:?}", gateway_config);
    
    run_proxy(gateway_config)
}

fn build_gateway_configuration() -> Config {
    let listen_address = read_listen_address();
    let connection_timeout = read_timeout_configuration();

    Config {
        listen_addr: listen_address,
        connect_timeout_ms: connection_timeout,
    }
}

fn read_listen_address() -> String {
    std::env::var("HSIP_GATEWAY_LISTEN")
        .unwrap_or_else(|_| String::from("127.0.0.1:8080"))
}

fn read_timeout_configuration() -> u64 {
    std::env::var("HSIP_GATEWAY_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5000)
}
