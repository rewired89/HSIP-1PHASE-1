use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fs;
use std::path::PathBuf;

fn path() -> PathBuf {
    let home = dirs::home_dir().expect("home");
    home.join(".hsip").join("id_auth.json")
}

pub fn load() -> Result<(SigningKey, VerifyingKey)> {
    let p = path();
    let s = fs::read_to_string(&p)?;
    let v: serde_json::Value = serde_json::from_str(&s)?;
    let sk_hex = v["sk_hex"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing sk_hex"))?;
    let sk_bytes = hex::decode(sk_hex)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sk_bytes[..32]);
    let sk = SigningKey::from_bytes(&seed);
    let vk = VerifyingKey::from(&sk);
    Ok((sk, vk))
}

pub fn save(sk: &SigningKey, vk: &VerifyingKey) -> Result<()> {
    let p = path();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).ok();
    }
    let json = serde_json::json!({
        "version": 1,
        "sk_hex": hex::encode(sk.to_bytes()),      // 32B seed
        "vk_hex": hex::encode(vk.to_bytes()),      // 32B pub
        "note": "HSIP auth identity (device-local). KEEP PRIVATE."
    });
    fs::write(&p, serde_json::to_string_pretty(&json)?)?;
    Ok(())
}
