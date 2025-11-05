use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use dirs::config_dir;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct StoredKey {
    pub_hex: String,
    priv_hex: String, // plaintext for now (dev mode)
}

#[must_use]
fn store_path() -> PathBuf {
    let mut p = config_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push("HSIP");
    let _ = fs::create_dir_all(&p);
    p.push("keystore.json");
    p
}

/// Save keypair in a local JSON file (DEV MODE: plaintext secret key).
///
/// # Errors
/// Returns `Err(String)` if serialization fails, the file cannot be created,
/// permissions cannot be set (Unix best-effort), or writing to disk fails.
pub fn save_keypair(sk: &SigningKey, vk: &VerifyingKey) -> Result<(), String> {
    let obj = StoredKey {
        pub_hex: hex::encode(vk.as_bytes()),
        priv_hex: hex::encode(sk.to_bytes()),
    };
    let json = serde_json::to_string_pretty(&obj).map_err(|e| e.to_string())?;

    let path = store_path();
    let mut f = fs::File::create(&path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = f.metadata() {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&path, perms);
        }
    }
    f.write_all(json.as_bytes()).map_err(|e| e.to_string())
}

/// Load keypair from local JSON file.
///
/// # Errors
/// Returns `Err(String)` if the keystore file cannot be opened or read,
/// the JSON fails to parse, the secret key hex is invalid or wrong length,
/// or the reconstructed public key does not match the stored one.
pub fn load_keypair() -> Result<(SigningKey, VerifyingKey), String> {
    let path = store_path();
    let mut f = fs::File::open(&path).map_err(|e| format!("open keystore: {e}"))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf).map_err(|e| e.to_string())?;

    let obj: StoredKey = serde_json::from_str(&buf).map_err(|e| e.to_string())?;
    let priv_bytes = hex::decode(obj.priv_hex).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = priv_bytes
        .try_into()
        .map_err(|_| "wrong secret key length".to_string())?;

    // ed25519-dalek v2: construct from the 32-byte seed and derive verifying key
    let sk = SigningKey::from_bytes(&arr);
    let vk = sk.verifying_key();

    if hex::encode(vk.as_bytes()) != obj.pub_hex {
        return Err("keystore pubkey mismatch".into());
    }
    Ok((sk, vk))
}
