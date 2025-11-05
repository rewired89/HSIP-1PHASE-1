use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub peer_id: String,
    pub addr: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Directory {
    pub peers: Vec<PeerEntry>,
}

fn dir_path() -> PathBuf {
    dirs::home_dir().unwrap().join(".hsip").join("peers.json")
}

pub fn list() -> Directory {
    let p = dir_path();
    if !p.exists() {
        return Directory::default();
    }
    let s = fs::read_to_string(p).unwrap_or_default();
    serde_json::from_str(&s).unwrap_or_default()
}

pub fn save(d: &Directory) {
    let p = dir_path();
    std::fs::create_dir_all(p.parent().unwrap()).ok();
    fs::write(p, serde_json::to_string_pretty(d).unwrap()).ok();
}

pub fn add(peer_id: String, addr: String) {
    let mut d = list();
    if !d.peers.iter().any(|e| e.peer_id == peer_id) {
        d.peers.push(PeerEntry { peer_id, addr });
        save(&d);
    }
}

pub fn remove(peer_id: String) {
    let mut d = list();
    d.peers.retain(|e| e.peer_id != peer_id);
    save(&d);
}
