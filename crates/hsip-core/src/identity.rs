use blake3::Hasher;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

// Derive peer identifier (PeerID) from Ed25519 public key
// PeerID is computed as the **first 26 Base32 characters
// of `blake3(public_key_bytes)`

// # Example
// # use ed25519_dalek::{SigningKey, VerifyingKey};
// # use rand::rngs::OsRng;
// # use hsip_core::identity::peer_id_from_pubkey;
// let sk = SigningKey::generate(&mut OsRng);
// let vk: VerifyingKey = (&sk).into();
// let pid = peer_id_from_pubkey(&vk);
// println!("PeerID = {pid}");

#[must_use]
pub fn peer_id_from_pubkey(verifying_key: &VerifyingKey) -> String {
    let hash_digest = compute_blake3_hash(verifying_key.as_bytes());
    let base32_encoded = BASE32_NOPAD.encode(&hash_digest);
    base32_encoded[..26].to_string()
}

fn compute_blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

// Create fresh Ed25519 keypair using OS randomness
// # Returns
// Tuple of `(SigningKey, VerifyingKey)`

// # Example
// use hsip_core::identity::generate_keypair;
// let (sk, vk) = generate_keypair();
// println!("Public key = {:?}", vk);

#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = (&signing_key).into();
    (signing_key, verifying_key)
}

// Encode signing key as lowercase hex string (32 bytes)
// # Security
// Production systems should use secure storage (PKCS#8 or encrypted keystore)
#[must_use]
pub fn sk_to_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.to_bytes())
}

// Encode verifying key as lowercase hex string (32 bytes)
#[must_use]
pub fn vk_to_hex(verifying_key: &VerifyingKey) -> String {
    hex::encode(verifying_key.as_bytes())
}
