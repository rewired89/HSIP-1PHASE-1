use anyhow::Result;
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use tray_icon::{TrayIcon, TrayIconBuilder};

#[derive(Deserialize)]
#[allow(dead_code)]
struct Status {
    protected: bool,
    active_sessions: u32,
    egress_peer: String,
    cipher: String,
    since: String,
    bytes_in: u64,
    bytes_out: u64,
    path: Vec<String>,
}

fn solid_icon(width: u32, height: u32, rgba: [u8; 4]) -> tray_icon::Icon {
    let mut buf = vec![0u8; (width * height * 4) as usize];
    for px in buf.chunks_exact_mut(4) {
        px.copy_from_slice(&rgba);
    }
    tray_icon::Icon::from_rgba(buf, width, height).expect("icon")
}

fn get_status() -> Result<Status> {
    let mut stream = TcpStream::connect("127.0.0.1:8787")?;
    let req = "GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;

    // Split headers/body
    let body = match resp.split("\r\n\r\n").nth(1) {
        Some(b) => b,
        None => return Err(anyhow::anyhow!("bad http response")),
    };

    let s: Status = serde_json::from_str(body)?;
    Ok(s)
}

fn main() -> Result<()> {
    // Minimal tray (no menu, no notifications)
    let red = solid_icon(16, 16, [200, 0, 0, 255]);
    let green = solid_icon(16, 16, [0, 200, 0, 255]);

    // IMPORTANT: tray-icon 0.21.x expects an Icon (not Option) on with_icon
    let tray: TrayIcon = TrayIconBuilder::new()
        .with_tooltip("HSIP: starting…")
        .with_icon(red.clone())
        .build()
        .expect("tray");

    loop {
        match get_status() {
            Ok(s) => {
                // set_icon takes Option<Icon> on 0.21.x
                tray.set_icon(Some(green.clone())).ok();
                let tt = format!(
                    "HSIP ✓  {} | sess={} | egress={}",
                    s.cipher, s.active_sessions, s.egress_peer
                );
                tray.set_tooltip(Some(&tt)).ok();
            }
            Err(_) => {
                tray.set_icon(Some(red.clone())).ok();
                tray.set_tooltip(Some("HSIP ✗ offline")).ok();
            }
        }

        thread::sleep(Duration::from_secs(3));
    }
}

#[allow(dead_code)]
fn run_tray_ui() -> anyhow::Result<()> {
    // TODO: move your existing tray setup/start code here.
    // For now, keep the process alive:
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
