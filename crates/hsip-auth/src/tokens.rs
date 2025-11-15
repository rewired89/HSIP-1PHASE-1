use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use base64::Engine; // trait for .encode()
use sha2::{Digest, Sha256};

use crate::identity::{ensure_device_identity, public_key_hex};

#[derive(Serialize)]
struct JwsHeader { alg: &'static str, typ: &'static str, kid: String }

#[derive(Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    scopes: Vec<String>,
}

/// Issue a compact JWT-like consent token: base64url(header).base64url(payload).base64url(sig)
pub fn issue_consent(scopes: &[&str], ttl_secs: u64, aud: &str) -> Result<String> {
    let (sk, _vk): (SigningKey, _) = ensure_device_identity()?;
    let kid = public_key_hex()?; // key id = pubkey hex

    let now = OffsetDateTime::now_utc();
    let iat = now.unix_timestamp();
    let exp = (now + Duration::seconds(ttl_secs as i64)).unix_timestamp();

    let claims = Claims {
        iss: "hsip-device".into(),
        sub: "device".into(),
        aud: aud.into(),
        iat,
        exp,
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
    };

    let header = JwsHeader { alg: "EdDSA", typ: "JWT", kid };
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let h = enc.encode(serde_json::to_vec(&header)?);
    let p = enc.encode(serde_json::to_vec(&claims)?);

    // Sign "h.p" with ed25519
    let signing_input = format!("{}.{}", &h, &p);
    let sig = sk.sign(signing_input.as_bytes());

    // Optional: SHA-256 over signing input (not strictly needed for EdDSA, but ok to leave out)
    let _digest = Sha256::digest(signing_input.as_bytes());

    let s = enc.encode(sig.to_bytes());
    Ok(format!("{}.{}.{}", h, p, s))
}
