// crates/hsip-gateway/src/proxy.rs

//! Minimal HTTP/HTTPS proxy for HSIP Web Gateway.
//!
//! Phase 2.0: proxy + basic blocking using classify.rs.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use crate::classify::{classify, DecisionKind, ProtoKind, RequestInfo};

/// Runtime config for the proxy.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Address to listen on, e.g. "127.0.0.1:8080".
    pub listen_addr: String,
    /// Connect timeout in milliseconds for upstream servers.
    pub connect_timeout_ms: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".to_string(),
            connect_timeout_ms: 5_000,
        }
    }
}

/// Entry point: run the proxy loop (blocking).
pub fn run_proxy(cfg: ProxyConfig) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen_addr)
        .with_context(|| format!("bind proxy on {}", cfg.listen_addr))?;
    listener
        .set_nonblocking(false)
        .context("set_nonblocking(false)")?;

    eprintln!("[gateway] HTTP proxy listening on {}", cfg.listen_addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg_clone = cfg.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, cfg_clone) {
                        eprintln!("[gateway] client error: {e:#}");
                    }
                });
            }
            Err(e) => {
                eprintln!("[gateway] accept error: {e}");
            }
        }
    }

    Ok(())
}

/// Handle a single client connection.
fn handle_client(mut client: TcpStream, cfg: ProxyConfig) -> Result<()> {
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    client
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();

    // Read enough bytes to capture the HTTP request line + headers.
    let mut buf = [0u8; 8192];
    let mut req = Vec::new();

    loop {
        let n = client.read(&mut buf)?;
        if n == 0 {
            break;
        }
        req.extend_from_slice(&buf[..n]);

        // Stop at end of headers: \r\n\r\n
        if req.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        if req.len() > 64 * 1024 {
            return Err(anyhow!("request header too large"));
        }
    }

    if req.is_empty() {
        return Ok(());
    }

    // Convert to an owned String so we don't keep a borrow of `req`.
    let req_str: String = String::from_utf8_lossy(&req).into_owned();

    // Parse the start line: METHOD SP TARGET SP VERSION
    let mut lines = req_str.split("\r\n");
    let start_line = lines.next().unwrap_or("");
    let mut parts = start_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        eprintln!("[gateway] CONNECT {target} {version}");
        handle_connect(method, target, version, req, client, cfg)
    } else {
        eprintln!("[gateway] {method} {target} {version}");
        handle_plain_http(method, target, version, req, client, cfg)
    }
}

/// Handle HTTPS-style CONNECT tunnel.
fn handle_connect(
    _method: &str,
    target: &str,
    version: &str,
    _raw_req: Vec<u8>,
    client: TcpStream,
    cfg: ProxyConfig,
) -> Result<()> {
    // target is usually "host:port"
    let mut parts = target.rsplitn(2, ':'); // split from the right
    let port_str = parts.next().unwrap_or("443");
    let host = parts.next().unwrap_or(target);
    let port: u16 = port_str.parse().unwrap_or(443);

    // === classification ===
    let info = RequestInfo {
        host: host.to_string(),
        port,
        path: "/".to_string(),
        proto: ProtoKind::Https,
    };
    let decision = classify(&info);

    if let DecisionKind::Block = decision.kind {
        let reason = decision.reason.unwrap_or_else(|| "blocked".to_string());
        eprintln!("[gateway] BLOCK CONNECT {}:{} → {reason}", host, port);
        send_blocked_connect(client, version, &reason)?;
        return Ok(());
    }

    let addr_str = format!("{host}:{port}");
    let addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("no address for {addr_str}"))?;

    let mut server = TcpStream::connect_timeout(
        &addr,
        Duration::from_millis(cfg.connect_timeout_ms),
    )
    .with_context(|| format!("connect to upstream {addr_str}"))?;

    server
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();
    server
        .set_write_timeout(Some(Duration::from_secs(30)))
        .ok();

    // Tell the client the tunnel is established.
    let resp = format!("{version} 200 Connection Established\r\n\r\n");
    let mut client_write = client.try_clone()?;
    client_write.write_all(resp.as_bytes())?;
    client_write.flush()?;

    // Now just tunnel bytes in both directions.
    tunnel_bidirectional(client, server);

    Ok(())
}

/// Handle normal HTTP requests (GET/POST/...)
fn handle_plain_http(
    _method: &str,
    target: &str,
    _version: &str,
    raw_req: Vec<u8>,
    client: TcpStream,
    cfg: ProxyConfig,
) -> Result<()> {
    // Extract Host header to know where to connect.
    let req_str = String::from_utf8_lossy(&raw_req).into_owned();
    let host_header = extract_host(&req_str).ok_or_else(|| anyhow!("missing Host header"))?;

    // Default port 80 unless host already includes ":port".
    let (hostname, port) = split_host_port(&host_header, 80);

    // Derive a path from the target (best effort).
    let path = if let Some(idx) = target.find('/') {
        target[idx..].to_string()
    } else {
        "/".to_string()
    };

    // === classification ===
    let info = RequestInfo {
        host: hostname.clone(),
        port,
        path,
        proto: ProtoKind::Http,
    };
    let decision = classify(&info);

    if let DecisionKind::Block = decision.kind {
        let reason = decision.reason.unwrap_or_else(|| "blocked".to_string());
        eprintln!(
            "[gateway] BLOCK HTTP {}:{} {} → {reason}",
            hostname, port, info.path
        );
        send_blocked_http(client, &reason)?;
        return Ok(());
    }

    let addr_str = format!("{hostname}:{port}");
    let addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("no address for {addr_str}"))?;

    let mut server = TcpStream::connect_timeout(
        &addr,
        Duration::from_millis(cfg.connect_timeout_ms),
    )
    .with_context(|| format!("connect to upstream {addr_str}"))?;

    server
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();
    server
        .set_write_timeout(Some(Duration::from_secs(30)))
        .ok();

    // Forward the initial request bytes (headers + maybe some body).
    server.write_all(&raw_req)?;
    server.flush()?;

    // Now stream the rest in both directions.
    tunnel_bidirectional(client, server);

    Ok(())
}

/// Extract the Host header from an HTTP request string.
fn extract_host(req: &str) -> Option<String> {
    for line in req.lines() {
        // Host: example.com
        if let Some(rest) = line.strip_prefix("Host:") {
            return Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix("host:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Split "host:port" into (host, port), or use default port if none present.
fn split_host_port(host: &str, default_port: u16) -> (String, u16) {
    if let Some(idx) = host.rfind(':') {
        let (h, p) = host.split_at(idx);
        if let Ok(port) = p.trim_start_matches(':').parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (host.to_string(), default_port)
}

/// Bi-directional copy between client and server.
fn tunnel_bidirectional(client: TcpStream, server: TcpStream) {
    // Clone streams so we can read/write in parallel.
    let mut client_read = match client.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[gateway] client clone failed: {e}");
            return;
        }
    };
    let mut server_read = match server.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[gateway] server clone failed: {e}");
            return;
        }
    };

    // Thread: client -> server
    let mut server_write = server;
    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut server_write);
    });

    // Current thread: server -> client
    let mut client_write = client;
    let _ = std::io::copy(&mut server_read, &mut client_write);

    let _ = t1.join();
}

/// Send a small HTTP 403 for blocked plain HTTP requests.
fn send_blocked_http(mut client: TcpStream, reason: &str) -> Result<()> {
    let body = format!(
        "HSIP Web Gateway blocked this request.\nReason: {}\n",
        reason
    );
    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
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

/// Send a minimal response for blocked CONNECT tunnels.
fn send_blocked_connect(mut client: TcpStream, version: &str, reason: &str) -> Result<()> {
    let body = format!(
        "HSIP Web Gateway blocked this TLS tunnel.\nReason: {}\n",
        reason
    );
    let resp = format!(
        "{version} 403 Forbidden\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
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
