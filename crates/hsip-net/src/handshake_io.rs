use std::io::Result;
use std::net::UdpSocket;

/// Block until a demo HELLO is received on `bind_addr`, then print it and exit.
///
/// Example:
///   hsip-cli handshake-listen --addr 127.0.0.1:9000
pub fn recv_and_verify_hello(bind_addr: &str) -> Result<()> {
    // Bind UDP socket
    let socket = UdpSocket::bind(bind_addr)?;
    println!("👂 Listening on {bind_addr} for HELLO...");

    // Just wait forever until we get *something*
    let mut buf = [0u8; 1500];
    let (n, peer) = socket.recv_from(&mut buf)?;

    println!("[HANDSHAKE] got demo HELLO from {peer} ({n} bytes)");
    Ok(())
}

/// Send a tiny demo HELLO datagram to `dest_addr`.
///
/// Example:
///   hsip-cli handshake-connect --addr 127.0.0.1:9000
pub fn send_hello(dest_addr: &str) -> Result<()> {
    // Ephemeral UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    // Fixed demo payload for now; later we’ll plug in real HELLO.
    const DEMO_HELLO: &[u8] = b"HSIP_DEMO_HELLO_v1";

    println!("➡️  Sending HELLO to {dest_addr}...");
    let sent = socket.send_to(DEMO_HELLO, dest_addr)?;
    println!(
        "[HANDSHAKE] sent demo HELLO ({} bytes) → {}",
        sent, dest_addr
    );
    println!("Done.");
    Ok(())
}
