//! Minimal persistence helpers for HSIP sessions.
//!
//! JSON helpers (`write_json/read_json`) and raw blob helpers (`save_blob/load_blob`)
//! live here so `hsip-cli` and `hsip-net` can persist resume tokens, last-seen data,
//! or small artifacts under a common state dir:
//!
//!   Windows: %USERPROFILE%\.hsip\state\
//!   Unix:    $HOME/.hsip/state\
//!   Or override with `HSIP_HOME`, which becomes: `$HSIP_HOME/state/`

use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Where we store all HSIP state on disk:
///   - If env var `HSIP_HOME` is set, use `$HSIP_HOME/state/`.
///   - Else `%USERPROFILE%\.hsip\state\` (Windows) or `$HOME/.hsip/state/` (Unix).
#[must_use]
pub fn state_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HSIP_HOME") {
        return PathBuf::from(home).join("state");
    }
    let mut base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.push(".hsip");
    base.push("state");
    base
}

/// Convenience: return a path under `state_dir()` for a logical file name.
#[must_use]
pub fn path_for(name: &str) -> PathBuf {
    state_dir().join(name)
}

/// Ensure directory exists (idempotent) and return it.
pub fn ensure_dir() -> io::Result<PathBuf> {
    let dir = state_dir();
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Atomically write pretty JSON under `state_dir() / name`.
pub fn write_json<T: Serialize>(name: &str, value: &T) -> io::Result<()> {
    let dir = ensure_dir()?;

    let tmp_path = dir.join(format!("{name}.tmp"));
    let final_path = dir.join(name);

    // write to temp
    let mut f = fs::File::create(&tmp_path)?;
    let s = serde_json::to_string_pretty(value)
        .map_err(|e| io::Error::other(format!("serialize: {e}")))?;
    f.write_all(s.as_bytes())?;
    f.flush()?;

    // best-effort durability where supported
    #[cfg(unix)]
    {
        let _ = f.sync_all();
        if let Ok(dir_fd) = fs::File::open(&dir) {
            let _ = dir_fd.sync_all();
        }
    }

    // atomic rename
    fs::rename(&tmp_path, &final_path)?;

    Ok(())
}

/// Read JSON from `state_dir() / name`. Returns `None` if missing or parse fails.
#[must_use]
pub fn read_json<T: DeserializeOwned>(name: &str) -> Option<T> {
    let path = path_for(name);
    let mut s = String::new();
    let mut f = fs::File::open(&path).ok()?;
    f.read_to_string(&mut s).ok()?;
    serde_json::from_str(&s).ok()
}

/// Best-effort delete `state_dir() / name`.
pub fn remove(name: &str) -> io::Result<()> {
    let path = path_for(name);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

// ===== Raw blob helpers (used by hsip-cli SessionSave/SessionLoad) =====

/// Save raw bytes atomically to `state_dir() / name`.
pub fn save_blob(name: &str, data: &[u8]) -> io::Result<()> {
    let dir = ensure_dir()?;
    let tmp_path = dir.join(format!("{name}.tmp"));
    let final_path = dir.join(name);

    let mut f = fs::File::create(&tmp_path)?;
    f.write_all(data)?;
    f.flush()?;

    #[cfg(unix)]
    {
        let _ = f.sync_all();
        if let Ok(dir_fd) = fs::File::open(&dir) {
            let _ = dir_fd.sync_all();
        }
    }

    fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

/// Load raw bytes from `state_dir() / name`.
pub fn load_blob(name: &str) -> io::Result<Vec<u8>> {
    let path = path_for(name);
    fs::read(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Demo {
        peer: String,
        ts_ms: u64,
    }

    #[test]
    fn roundtrip_json_ok() -> io::Result<()> {
        let _ = ensure_dir();
        let name = "test_roundtrip.json";
        let v = Demo {
            peer: "peer_abc".into(),
            ts_ms: 123,
        };
        write_json(name, &v)?;
        let got: Option<Demo> = read_json(name);
        assert_eq!(got, Some(v));
        let _ = remove(name);
        Ok(())
    }

    #[test]
    fn blob_save_load_ok() -> io::Result<()> {
        let _ = ensure_dir();
        let name = "blob.bin";
        let data = b"hello world";
        save_blob(name, data)?;
        let got = load_blob(name)?;
        assert_eq!(got, data);
        let _ = remove(name);
        Ok(())
    }
}
