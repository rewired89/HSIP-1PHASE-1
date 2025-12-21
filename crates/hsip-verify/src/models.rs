//! Formal models of HSIP protocol components for verification

use blake3;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier as Ed25519Verifier};
use std::collections::HashMap;

/// Formal model of the consent protocol
#[derive(Debug, Clone)]
pub struct ConsentModel {
    /// Known keypairs (peer_id -> signing_key)
    keypairs: HashMap<String, SigningKey>,
    /// Granted consents (requester_peer_id -> grant_time)
    granted_consents: HashMap<String, u64>,
    /// Revoked consents (requester_peer_id -> revoke_time)
    revoked_consents: HashMap<String, u64>,
}

impl ConsentModel {
    pub fn new() -> Self {
        Self {
            keypairs: HashMap::new(),
            granted_consents: HashMap::new(),
            revoked_consents: HashMap::new(),
        }
    }

    /// Add a keypair to the model
    pub fn add_keypair(&mut self, peer_id: String, signing_key: SigningKey) {
        self.keypairs.insert(peer_id, signing_key);
    }

    /// Grant consent at a specific time
    pub fn grant_consent(&mut self, requester_peer_id: String, grant_time: u64) {
        self.granted_consents.insert(requester_peer_id, grant_time);
    }

    /// Revoke consent at a specific time
    pub fn revoke_consent(&mut self, requester_peer_id: String, revoke_time: u64) {
        self.revoked_consents.insert(requester_peer_id, revoke_time);
    }

    /// Check if consent is allowed at a specific time
    pub fn is_allowed_at(&self, requester_peer_id: &str, check_time: u64, ttl: u64) -> bool {
        // If revoked, check if revocation happened before check_time
        if let Some(&revoke_time) = self.revoked_consents.get(requester_peer_id) {
            if check_time >= revoke_time {
                return false; // Revoked before or at check time
            }
        }

        // Check if granted and within TTL
        if let Some(&grant_time) = self.granted_consents.get(requester_peer_id) {
            if check_time >= grant_time && check_time < grant_time + ttl {
                return true;
            }
        }

        false
    }

    /// Verify temporal consistency property
    pub fn verify_temporal_consistency(&self, requester_peer_id: &str) -> bool {
        if let Some(&revoke_time) = self.revoked_consents.get(requester_peer_id) {
            if let Some(&grant_time) = self.granted_consents.get(requester_peer_id) {
                // For any time t > revoke_time, consent should not be allowed
                // We check a large time in the future
                let future_time = revoke_time + 1000000;
                if self.is_allowed_at(requester_peer_id, future_time, 1000000) {
                    return false; // Violation: still allowed after revocation
                }
            }
        }
        true
    }

    /// Try to forge a signature without the private key
    pub fn can_forge_signature(&self, message: &[u8], peer_id: &str) -> bool {
        // In reality, this should always return false
        // We simulate an attacker trying to create a valid signature without the key
        if let Some(signing_key) = self.keypairs.get(peer_id) {
            // Attacker doesn't have access to this, but we model it for completeness
            let signature = signing_key.sign(message);
            let verifying_key = signing_key.verifying_key();
            verifying_key.verify(message, &signature).is_ok()
        } else {
            // Cannot forge without the key
            false
        }
    }
}

impl Default for ConsentModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Formal model of identity binding
#[derive(Debug)]
pub struct IdentityModel {
    /// Mapping of public keys to derived peer IDs
    bindings: HashMap<Vec<u8>, String>,
}

impl IdentityModel {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    /// Derive peer ID from public key (HSIP algorithm)
    pub fn derive_peer_id(public_key: &[u8]) -> String {
        let hash = blake3::hash(public_key);
        let base32 = BASE32_NOPAD.encode(hash.as_bytes());
        base32[..26].to_string()
    }

    /// Bind a public key to its derived peer ID
    pub fn bind(&mut self, public_key: Vec<u8>) -> String {
        let peer_id = Self::derive_peer_id(&public_key);
        self.bindings.insert(public_key, peer_id.clone());
        peer_id
    }

    /// Verify that a peer ID matches its public key
    pub fn verify_binding(&self, public_key: &[u8], claimed_peer_id: &str) -> bool {
        let derived_peer_id = Self::derive_peer_id(public_key);
        derived_peer_id == claimed_peer_id
    }

    /// Check for collisions (should never happen with BLAKE3)
    pub fn has_collision(&self) -> bool {
        let mut seen_ids = HashMap::new();
        for (pubkey, peer_id) in &self.bindings {
            if let Some(existing_key) = seen_ids.get(peer_id) {
                if existing_key != pubkey {
                    return true; // Collision found!
                }
            } else {
                seen_ids.insert(peer_id.clone(), pubkey.clone());
            }
        }
        false
    }

    /// Get all bindings
    pub fn bindings(&self) -> &HashMap<Vec<u8>, String> {
        &self.bindings
    }
}

impl Default for IdentityModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Formal model of signature verification
#[derive(Debug)]
pub struct SignatureModel {
    /// Known valid signatures
    valid_signatures: HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>, // message -> (signature, public_key)
}

impl SignatureModel {
    pub fn new() -> Self {
        Self {
            valid_signatures: HashMap::new(),
        }
    }

    /// Create a valid signature
    pub fn sign(&mut self, signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
        let signature = signing_key.sign(message);
        let verifying_key = signing_key.verifying_key();

        self.valid_signatures.insert(
            message.to_vec(),
            (signature.to_vec(), verifying_key.to_bytes().to_vec()),
        );

        signature.to_vec()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        if let Ok(vk) = VerifyingKey::from_bytes(public_key.try_into().unwrap_or(&[0u8; 32])) {
            if let Ok(sig) = Signature::from_slice(signature) {
                return vk.verify(message, &sig).is_ok();
            }
        }
        false
    }

    /// Check if a signature exists without knowing the private key
    pub fn can_verify_without_key(&self, message: &[u8]) -> bool {
        self.valid_signatures.contains_key(message)
    }
}

impl Default for SignatureModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_consent_model_grant_revoke() {
        let mut model = ConsentModel::new();
        let peer_id = "test_peer".to_string();

        model.grant_consent(peer_id.clone(), 100);
        assert!(model.is_allowed_at(&peer_id, 150, 1000)); // Within TTL

        model.revoke_consent(peer_id.clone(), 200);
        assert!(!model.is_allowed_at(&peer_id, 250, 1000)); // After revocation
    }

    #[test]
    fn test_temporal_consistency() {
        let mut model = ConsentModel::new();
        let peer_id = "test_peer".to_string();

        model.grant_consent(peer_id.clone(), 100);
        model.revoke_consent(peer_id.clone(), 200);

        // Temporal consistency should hold
        assert!(model.verify_temporal_consistency(&peer_id));
    }

    #[test]
    fn test_identity_binding() {
        let mut model = IdentityModel::new();

        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();

        let peer_id = model.bind(public_key.to_vec());

        // Verify binding is correct
        assert!(model.verify_binding(&public_key, &peer_id));

        // Should not have collisions
        assert!(!model.has_collision());
    }

    #[test]
    fn test_signature_verification() {
        let mut model = SignatureModel::new();

        let signing_key = SigningKey::generate(&mut OsRng);
        let message = b"test message";

        let signature = model.sign(&signing_key, message);
        let public_key = signing_key.verifying_key().to_bytes();

        // Verify signature is valid
        assert!(model.verify(message, &signature, &public_key));

        // Wrong message should fail
        assert!(!model.verify(b"wrong message", &signature, &public_key));
    }
}
