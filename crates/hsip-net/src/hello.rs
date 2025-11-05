use base64::Engine; // trait for .encode()
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use hsip_core::identity::peer_id_from_pubkey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Hello {
    #[serde(rename = "type")]
    pub msg_type: String, // "HELLO"
    pub peer_id: String,     // derived from pubkey (blake3 -> base32[26])
    pub pub_key_hex: String, // hex(32B)
    pub caps: Vec<String>,
    pub ts: u64,       // unix ms
    pub nonce: String, // base64(12 bytes)
    pub sig: String,   // hex(64B ed25519 signature)
}

#[must_use]
fn caps_detect() -> Vec<String> {
    vec![
        "pqc=0".into(),
        "dtn=1".into(),
        "mesh=1".into(),
        "sat=0".into(),
        "consent=1".into(),
    ]
}

#[must_use]
fn preimage(peer_id: &str, pub_key_hex: &str, caps: &[String], ts: u64, nonce_b64: &str) -> String {
    format!(
        "HELLO|{}|{}|{}|{}|{}",
        peer_id,
        pub_key_hex,
        caps.join(","),
        ts,
        nonce_b64
    )
}

/// Build a signed HELLO message bound to capabilities and a random nonce.
///
/// # Returns
/// A fully populated `Hello` struct ready to send.
#[must_use]
pub fn build_hello(sk: &SigningKey, vk: &VerifyingKey, now_ms: u64) -> Hello {
    let peer_id = peer_id_from_pubkey(vk);
    let pub_key_hex = hex::encode(vk.as_bytes());

    // 12-byte random nonce → base64 (no pad)
    let mut n = [0u8; 12];
    OsRng.fill_bytes(&mut n);
    let nonce_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(n);

    let caps = caps_detect();

    let pre = preimage(&peer_id, &pub_key_hex, &caps, now_ms, &nonce_b64);
    let sig = sk.sign(pre.as_bytes());
    let sig_hex = hex::encode(sig.to_bytes());

    Hello {
        msg_type: "HELLO".into(),
        peer_id,
        pub_key_hex,
        caps,
        ts: now_ms,
        nonce: nonce_b64,
        sig: sig_hex,
    }
}

/// Verify a HELLO message’s signature and identity binding.
///
/// # Errors
/// Returns an error string if:
/// - the public key hex is malformed or wrong length,
/// - the derived PeerID doesn’t match the provided public key,
/// - or the signature verification fails.
pub fn verify_hello(h: &Hello) -> Result<(), String> {
    // 1) Rebuild verifying key from pub_key_hex
    let bytes = hex::decode(&h.pub_key_hex).map_err(|e| format!("bad pub key hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| String::from("pub key wrong length"))?;
    let vk = VerifyingKey::from_bytes(&arr).map_err(|e| format!("vk error: {e}"))?;

    // 2) Check peer_id matches pubkey
    let expect_pid = peer_id_from_pubkey(&vk);
    if expect_pid != h.peer_id {
        return Err(String::from("peer_id does not match public key"));
    }

    // 3) Verify signature over canonical preimage
    let pre = preimage(&h.peer_id, &h.pub_key_hex, &h.caps, h.ts, &h.nonce);
    let sig_bytes = hex::decode(&h.sig).map_err(|e| format!("sig hex error: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| String::from("sig len"))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(pre.as_bytes(), &sig)
        .map_err(|e: SignatureError| format!("verify failed: {e}"))?;

    Ok(())
}
