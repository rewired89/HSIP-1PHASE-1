use blake3::Hasher;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// PeerID is first 26 Base32 chars of blake3(public_key)
pub fn peer_id_from_pubkey(vk: &VerifyingKey) -> String {
    let mut hasher = Hasher::new();
    hasher.update(vk.as_bytes());
    let digest = hasher.finalize(); // 32 bytes
    let b32 = BASE32_NOPAD.encode(digest.as_bytes());
    b32[..26].to_string()
}

/// Generate a fresh Ed25519 keypair (uses OS RNG).
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk: VerifyingKey = (&sk).into();
    (sk, vk)
}

/// Serialize keys as hex (simple for now). In prod we'll use secure storage/PKCS#8.
pub fn sk_to_hex(sk: &SigningKey) -> String {
    hex::encode(sk.to_bytes()) // 32 bytes secret
}
pub fn vk_to_hex(vk: &VerifyingKey) -> String {
    hex::encode(vk.as_bytes()) // 32 bytes public
}
