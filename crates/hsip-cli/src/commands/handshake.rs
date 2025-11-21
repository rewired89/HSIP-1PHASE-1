// crates/hsip-cli/src/commands/handshake.rs

use anyhow::Result;
use hsip_net::handshake_io::{recv_and_verify_hello, send_hello};

/// Listener side: bind UDP and wait for a demo HELLO.
pub fn run_listen(addr: &str) -> Result<()> {
    // recv_and_verify_hello returns std::io::Result<()>, so we use `?`
    // and wrap the final value in Ok(...) to satisfy anyhow::Result.
    Ok(recv_and_verify_hello(addr)?)
}

/// Sender side: send a demo HELLO to the given addr.
pub fn run_connect(addr: &str) -> Result<()> {
    // Same deal here: lift std::io::Error into anyhow::Error via `?`.
    Ok(send_hello(addr)?)
}
