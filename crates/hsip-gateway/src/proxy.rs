// crates/hsip-gateway/src/proxy.rs
//
// Minimal HTTP/HTTPS proxy with basic domain blocking.
// Browser -> HSIP Gateway (this) -> Internet.
//
// - HTTP:  parses request line + Host header
// - HTTPS: handles CONNECT and tunnels bytes
// - Blocking: simple host-based denylist (neverssl.com, trackers, etc.)

use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    /// Where the gateway listens, e.g. "127.0.0.1:8080".
    pub listen_addr: String,
    /// Upstream connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".into(),
            connect_timeout_ms: 5000,
        }
    }
}

/// Start the proxy loop (blocking).
pub fn run_proxy(cfg: Config) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen_addr)?;
    println!("[gateway] listening on {}", cfg.listen_addr);

    loop {
        let (client, addr) = listener.accept()?;
        let cfg_clone = cfg.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_client(client, addr, &cfg_clone) {
                eprintln!("[gateway] client {addr} error: {e:?}");
            }
        });
    }
}

/// Simple denylist of domains HSIP should block at the gateway.
fn is_blocked_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();

    // Very small starter list so you can see blocks.
    const BLOCKED: &[&str] = &[
        "neverssl.com",
        "doubleclick.net",
        "google-analytics.com",
        "ads.google.com",
        "tracking.test",
    ];

    // Exact match or subdomain match.
    for b in BLOCKED {
        let b = b.to_ascii_lowercase();
        if host == b || host.ends_with(&format!(".{b}")) {
            return true;
        }
    }

    false
}

/// Send a small 403 response back to the browser.
fn send_blocked_response(mut client: &mut TcpStream, host: &str) -> Result<()> {
    let body = format!(
        "<html><body><h1>HSIP blocked</h1>\
         <p>Destination <code>{}</code> is blocked by HSIP gateway.</p>\
         </body></html>",
        host
    );
    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    client.write_all(resp.as_bytes())?;
    client.flush()?;
    Ok(())
}

/// Extract host for blocking:
/// - CONNECT: "example.com:443" -> "example.com"
/// - HTTP: use `Host:` header if present.
fn extract_host_for_block(method: &str, target: &str, req_str: &str) -> Option<String> {
    let method_up = method.to_ascii_uppercase();

    if method_up == "CONNECT" {
        // CONNECT host:port
        if let Some((h, _port)) = target.split_once(':') {
            return Some(h.trim().to_string());
        }
        return Some(target.trim().to_string());
    }

    // For plain HTTP, prefer Host: header.
    for line in req_str.lines() {
        if let Some(rest) = line.strip_prefix("Host:") {
            return Some(rest.trim().to_string());
        }
    }

    None
}

fn handle_client(mut client: TcpStream, addr: SocketAddr, cfg: &Config) -> Result<()> {
    client
        .set_read_timeout(Some(Duration::from_millis(2000)))
        .ok();
    client
        .set_write_timeout(Some(Duration::from_millis(2000)))
        .ok();

    // Read the HTTP request (or CONNECT line).
    let mut req = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = client.read(&mut buf)?;
        if n == 0 {
            break;
        }
        req.extend_from_slice(&buf[..n]);
        if req.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if req.len() > 64 * 1024 {
            return Err(anyhow!("request too large"));
        }
    }

    if req.is_empty() {
        return Ok(());
    }

    // Use a clone so we don't keep a borrow on `req`.
    let req_clone = req.clone();
    let req_str = String::from_utf8_lossy(&req_clone);

    // First line: "METHOD target HTTP/1.1"
    let first_line = req_str
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty request"))?;
    let (method, target, version) = parse_request_line(first_line)?;

    // === BLOCKING LAYER ===
    if let Some(host) = extract_host_for_block(&method, &target, &req_str) {
        if is_blocked_host(&host) {
            println!("[gateway] BLOCK {} from {}", host, addr);
            send_blocked_response(&mut client, &host)?;
            return Ok(());
        }
    }

    // === ROUTING ===
    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(method, target, version, req, client, cfg)
    } else {
        handle_plain_http(method, target, version, req, client, cfg)
    }
}

/// Parse "METHOD target HTTP/x.y".
fn parse_request_line(line: &str) -> Result<(String, String, String)> {
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("no method in request line"))?;
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("no target in request line"))?;
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("no version in request line"))?;
    Ok((method.to_string(), target.to_string(), version.to_string()))
}

/// Handle HTTPS CONNECT tunnel.
fn handle_connect(
    _method: String,
    target: String,
    _version: String,
    _req: Vec<u8>,
    mut client: TcpStream,
    cfg: &Config,
) -> Result<()> {
    // target like "example.com:443"
    let addr = resolve_target(&target)?;
    let mut server =
        TcpStream::connect_timeout(&addr, Duration::from_millis(cfg.connect_timeout_ms))?;
    server
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .ok();
    server
        .set_write_timeout(Some(Duration::from_millis(5000)))
        .ok();

    // 200 Connection Established
    let resp = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    client.write_all(resp)?;
    client.flush()?;

    // Tunnel bytes in both directions
    std::thread::spawn({
        let mut client = client.try_clone()?;
        let mut server = server.try_clone()?;
        move || {
            let _ = std::io::copy(&mut client, &mut server);
        }
    });

    let _ = std::io::copy(&mut server, &mut client);
    Ok(())
}

/// Handle plain HTTP (GET, POST, etc.).
fn handle_plain_http(
    _method: String,
    target: String,
    _version: String,
    req: Vec<u8>,
    mut client: TcpStream,
    cfg: &Config,
) -> Result<()> {
    // target can be absolute ("http://host/path") or relative ("/path").
    // We prefer Host header, but for upstream TCP we just need host:port.
    let host = extract_host_from_request(&req)?;

    let addr = format!("{host}:80");
    let addr = resolve_target(&addr)?;
    let mut server =
        TcpStream::connect_timeout(&addr, Duration::from_millis(cfg.connect_timeout_ms))?;
    server
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .ok();
    server
        .set_write_timeout(Some(Duration::from_millis(5000)))
        .ok();

    // Send original request to upstream.
    server.write_all(&req)?;
    server.flush()?;

    // Relay response back to client.
    let _ = std::io::copy(&mut server, &mut client);
    Ok(())
}

fn extract_host_from_request(req: &[u8]) -> Result<String> {
    let s = String::from_utf8_lossy(req);
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Host:") {
            return Ok(rest.trim().to_string());
        }
    }
    Err(anyhow!("no Host header in HTTP request"))
}

fn resolve_target(target: &str) -> Result<SocketAddr> {
    let mut addrs = target.to_socket_addrs()?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("could not resolve {target}"))
}
