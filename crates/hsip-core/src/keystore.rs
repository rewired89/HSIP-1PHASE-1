use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use dirs::config_dir;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct KeyPairStorage {
    pub_hex: String,
    priv_hex: String,
}

// Compute path to keystore file in user configuration directory
#[must_use]
fn keystore_file_location() -> PathBuf {
    let base_config_dir = config_dir().unwrap_or_else(|| PathBuf::from("."));
    let hsip_dir = base_config_dir.join("HSIP");
    
    // Ensure directory exists
    let _ = fs::create_dir_all(&hsip_dir);
    
    hsip_dir.join("keystore.json")
}

// Persist keypair to local JSON file (DEV MODE: plaintext private key)
// # Errors
// Returns error if JSON serialization fails, file cannot be created,
// permissions cannot be set (Unix only), or disk write fails
pub fn save_keypair(
    signing_key: &SigningKey,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    let storage_object = KeyPairStorage {
        pub_hex: hex::encode(verifying_key.as_bytes()),
        priv_hex: hex::encode(signing_key.to_bytes()),
    };

    let json_content = serde_json::to_string_pretty(&storage_object)
        .map_err(|e| e.to_string())?;

    let file_path = keystore_file_location();
    let mut file_handle = fs::File::create(&file_path).map_err(|e| e.to_string())?;

    // Set restrictive permissions on Unix systems
    #[cfg(unix)]
    apply_unix_file_permissions(&file_path);

    file_handle
        .write_all(json_content.as_bytes())
        .map_err(|e| e.to_string())
}

#[cfg(unix)]
fn apply_unix_file_permissions(path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    
    if let Ok(mut file) = fs::File::open(path) {
        if let Ok(metadata) = file.metadata() {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}

// Retrieve keypair from local JSON file
// # Errors
// Returns error if keystore file cannot be opened/read,
// JSON parsing fails, private key hex is invalid or wrong length,
// or reconstructed public key doesn't match stored value
pub fn load_keypair() -> Result<(SigningKey, VerifyingKey), String> {
    let file_path = keystore_file_location();
    let mut file_handle = fs::File::open(&file_path)
        .map_err(|e| format!("Failed to open keystore: {e}"))?;

    let mut file_content = String::new();
    file_handle
        .read_to_string(&mut file_content)
        .map_err(|e| e.to_string())?;

    let storage: KeyPairStorage = serde_json::from_str(&file_content)
        .map_err(|e| e.to_string())?;

    let private_key_bytes = hex::decode(storage.priv_hex).map_err(|e| e.to_string())?;
    let private_key_array: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| "Private key must be exactly 32 bytes")?;

    // Construct signing key from 32-byte seed and derive verifying key
    let signing_key = SigningKey::from_bytes(&private_key_array);
    let verifying_key = signing_key.verifying_key();

    // Verify stored public key matches derived key
    if hex::encode(verifying_key.as_bytes()) != storage.pub_hex {
        return Err("Keystore public key mismatch detected".into());
    }

    Ok((signing_key, verifying_key))
}
