use blake3::Hasher;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// Compute a peer identifier (PeerID) from an Ed25519 verifying key.
///
/// The PeerID is defined as the **first 26 Base32 characters**
/// of `blake3(public_key_bytes)`.
///
/// # Example
/// ```
/// # use ed25519_dalek::{SigningKey, VerifyingKey};
/// # use rand::rngs::OsRng;
/// # use hsip_core::identity::peer_id_from_pubkey;
/// let sk = SigningKey::generate(&mut OsRng);
/// let vk: VerifyingKey = (&sk).into();
/// let pid = peer_id_from_pubkey(&vk);
/// println!("PeerID = {pid}");
/// ```
#[must_use]
pub fn peer_id_from_pubkey(vk: &VerifyingKey) -> String {
    let mut hasher = Hasher::new();
    hasher.update(vk.as_bytes());
    let digest = hasher.finalize(); // 32 bytes
    let b32 = BASE32_NOPAD.encode(digest.as_bytes());
    b32[..26].to_string()
}

/// Generate a fresh Ed25519 keypair using the OS random generator.
///
/// # Returns
/// `(SigningKey, VerifyingKey)` tuple.
///
/// # Example
/// ```
/// use hsip_core::identity::generate_keypair;
/// let (sk, vk) = generate_keypair();
/// println!("Public key = {:?}", vk);
/// ```
#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk: VerifyingKey = (&sk).into();
    (sk, vk)
}

/// Serialize a secret key as lowercase hex (32 bytes).
///
/// # Security
/// This is **not encrypted**. Only use for development or testing.
/// For production, use secure storage (e.g. PKCS#8 or encrypted keystore).
#[must_use]
pub fn sk_to_hex(sk: &SigningKey) -> String {
    hex::encode(sk.to_bytes())
}

/// Serialize a verifying key as lowercase hex (32 bytes).
#[must_use]
pub fn vk_to_hex(vk: &VerifyingKey) -> String {
    hex::encode(vk.as_bytes())
}
