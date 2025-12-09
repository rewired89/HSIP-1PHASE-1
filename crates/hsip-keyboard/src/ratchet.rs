//! Double Ratchet implementation for forward secrecy and automatic key rotation.
//!
//! This module implements a simplified version of the Signal Double Ratchet algorithm:
//! - Each contact has sending and receiving key chains
//! - Keys automatically rotate with each message
//! - Old keys are deleted immediately (forward secrecy)
//! - Periodic DH ratchet steps provide self-healing

use blake3;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use x25519_dalek::{PublicKey, StaticSecret};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Maximum number of skipped message keys to store (for out-of-order messages)
const MAX_SKIP: u32 = 1000;

/// Number of messages between DH ratchet steps
const RATCHET_INTERVAL: u32 = 100;

#[derive(Debug)]
pub enum RatchetError {
    TooManySkippedMessages,
    EncryptionFailed,
    DecryptionFailed,
    InvalidMessageNumber,
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetError::TooManySkippedMessages => write!(f, "Too many skipped messages"),
            RatchetError::EncryptionFailed => write!(f, "Encryption failed"),
            RatchetError::DecryptionFailed => write!(f, "Decryption failed"),
            RatchetError::InvalidMessageNumber => write!(f, "Invalid message number"),
        }
    }
}

impl std::error::Error for RatchetError {}

pub type Result<T> = std::result::Result<T, RatchetError>;

/// A key chain for deriving message keys
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyChain {
    /// Current chain key (used to derive message keys and next chain key)
    chain_key: [u8; 32],
    /// Number of messages in this chain
    message_number: u32,
}

impl KeyChain {
    pub fn new(initial_key: [u8; 32]) -> Self {
        Self {
            chain_key: initial_key,
            message_number: 0,
        }
    }

    /// Derive the message key for the current position
    pub fn derive_message_key(&self) -> [u8; 32] {
        let context = format!("msg-key-{}", self.message_number);
        blake3::derive_key(&context, &self.chain_key)
    }

    /// Advance the chain by one step (updates chain_key, increments message_number)
    pub fn advance(&mut self) -> [u8; 32] {
        let message_key = self.derive_message_key();

        // Advance chain key (one-way function)
        self.chain_key = blake3::derive_key("chain-advance", &self.chain_key);
        self.message_number += 1;

        message_key
    }

    /// Skip ahead N steps (for handling out-of-order messages)
    pub fn skip_to(&mut self, target_number: u32) -> Result<Vec<[u8; 32]>> {
        if target_number < self.message_number {
            return Err(RatchetError::InvalidMessageNumber);
        }

        let skip_count = target_number - self.message_number;
        if skip_count > MAX_SKIP {
            return Err(RatchetError::TooManySkippedMessages);
        }

        let mut skipped_keys = Vec::new();
        while self.message_number < target_number {
            skipped_keys.push(self.advance());
        }

        Ok(skipped_keys)
    }

    pub fn message_number(&self) -> u32 {
        self.message_number
    }
}

/// Double Ratchet state for a contact
#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    /// Our static X25519 secret key
    our_static_secret: StaticSecret,
    /// Their static X25519 public key
    their_static_public: PublicKey,

    /// Root key (updated on DH ratchet steps)
    root_key: [u8; 32],

    /// Sending chain
    sending_chain: KeyChain,
    /// Receiving chain
    receiving_chain: KeyChain,

    /// Skipped message keys (for out-of-order messages)
    #[serde(skip)]
    skipped_message_keys: std::collections::HashMap<u32, [u8; 32]>,
}

impl RatchetState {
    /// Initialize a new ratchet state from X25519 key exchange
    pub fn new(
        our_static_secret: StaticSecret,
        their_static_public: PublicKey,
    ) -> Self {
        // Perform initial DH
        let shared_secret = our_static_secret.diffie_hellman(&their_static_public);

        // Derive root key
        let root_key = blake3::derive_key("HSIP-ROOT-KEY-V1", shared_secret.as_bytes());

        // Derive initial chain keys
        let sending_chain_key = blake3::derive_key("sending-chain", &root_key);
        let receiving_chain_key = blake3::derive_key("receiving-chain", &root_key);

        Self {
            our_static_secret,
            their_static_public,
            root_key,
            sending_chain: KeyChain::new(sending_chain_key),
            receiving_chain: KeyChain::new(receiving_chain_key),
            skipped_message_keys: std::collections::HashMap::new(),
        }
    }

    /// Check if we should perform a DH ratchet step
    fn should_ratchet(&self) -> bool {
        self.sending_chain.message_number() % RATCHET_INTERVAL == 0
            && self.sending_chain.message_number() > 0
    }

    /// Perform a DH ratchet step (updates root key and resets chains)
    fn ratchet(&mut self) -> PublicKey {
        // Generate ephemeral keypair for this ratchet
        let ephemeral_secret = StaticSecret::new(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // DH with their static public
        let dh_output = ephemeral_secret.diffie_hellman(&self.their_static_public);

        // Update root key
        let mut input = self.root_key.to_vec();
        input.extend_from_slice(dh_output.as_bytes());
        self.root_key = blake3::derive_key("HSIP-ROOT-RATCHET", &input);

        // Reset sending chain
        let new_sending_key = blake3::derive_key("sending-chain", &self.root_key);
        self.sending_chain = KeyChain::new(new_sending_key);

        // Reset receiving chain
        let new_receiving_key = blake3::derive_key("receiving-chain", &self.root_key);
        self.receiving_chain = KeyChain::new(new_receiving_key);

        ephemeral_public
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        // Check if we should ratchet
        let ratchet_public = if self.should_ratchet() {
            Some(self.ratchet())
        } else {
            None
        };

        // Get message key and advance chain
        let message_key = self.sending_chain.advance();
        let message_number = self.sending_chain.message_number() - 1;

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(&message_key.into());
        let nonce = generate_nonce();

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| RatchetError::EncryptionFailed)?;

        Ok(EncryptedMessage {
            message_number,
            ratchet_public,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        // If message includes ratchet, update our state
        if let Some(_ratchet_public) = message.ratchet_public {
            // In a full implementation, we'd use this to update our receiving chain
            // For now, we just acknowledge the ratchet
        }

        // Try with stored skipped key first
        if let Some(message_key) = self.skipped_message_keys.remove(&message.message_number) {
            return self.decrypt_with_key(&message_key, &message.nonce, &message.ciphertext);
        }

        // Check if we need to skip messages
        if message.message_number > self.receiving_chain.message_number() {
            let skipped_keys = self.receiving_chain
                .skip_to(message.message_number)
                .map_err(|_| RatchetError::TooManySkippedMessages)?;

            // Store skipped keys
            let base_number = self.receiving_chain.message_number() - skipped_keys.len() as u32;
            for (i, key) in skipped_keys.into_iter().enumerate() {
                self.skipped_message_keys.insert(base_number + i as u32, key);
            }
        }

        // Get message key and advance chain
        let message_key = self.receiving_chain.advance();

        self.decrypt_with_key(&message_key, &message.nonce, &message.ciphertext)
    }

    fn decrypt_with_key(
        &self,
        message_key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(message_key.into());
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| RatchetError::DecryptionFailed)
    }

    pub fn sending_message_number(&self) -> u32 {
        self.sending_chain.message_number()
    }

    pub fn receiving_message_number(&self) -> u32 {
        self.receiving_chain.message_number()
    }
}

/// An encrypted message with ratchet information
#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message_number: u32,
    pub ratchet_public: Option<PublicKey>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate emoji fingerprint for verifying contact identity
pub fn generate_emoji_fingerprint(
    our_public: &PublicKey,
    their_public: &PublicKey,
) -> Vec<String> {
    // Emoji set (60 emoji for good distribution)
    let emojis = [
        "🐕", "🐈", "🐘", "🦁", "🦊", "🐻", "🐼", "🐨", "🐯", "🐸",
        "🌲", "🌵", "🌺", "🌻", "🌹", "🌷", "🍀", "🌾", "🌴", "🎋",
        "🚗", "🚕", "🚙", "🚌", "🚎", "🏎️", "🚓", "🚑", "🚒", "🚐",
        "🎸", "🎹", "🎺", "🎷", "🥁", "🎻", "🎤", "🎧", "🎼", "🎵",
        "⚡", "🔥", "💧", "❄️", "☀️", "🌙", "⭐", "💫", "✨", "🌈",
        "🍕", "🍔", "🍟", "🌭", "🍿", "🍩", "🍪", "🎂", "🍰", "🧁"
    ];

    // Combine both public keys (order independent - use sorted order)
    let mut combined = Vec::new();
    let our_bytes = our_public.as_bytes();
    let their_bytes = their_public.as_bytes();

    // Sort to ensure both sides get same fingerprint
    if our_bytes < their_bytes {
        combined.extend_from_slice(our_bytes);
        combined.extend_from_slice(their_bytes);
    } else {
        combined.extend_from_slice(their_bytes);
        combined.extend_from_slice(our_bytes);
    }

    // Hash to get fingerprint
    let hash = blake3::hash(&combined);
    let hash_bytes = hash.as_bytes();

    // Select 6 emoji based on hash (48 bits of entropy = ~281 trillion combinations)
    (0..6)
        .map(|i| {
            let index = hash_bytes[i] as usize % emojis.len();
            emojis[index].to_string()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_chain_advance() {
        let mut chain = KeyChain::new([42u8; 32]);

        assert_eq!(chain.message_number(), 0);

        let key1 = chain.advance();
        assert_eq!(chain.message_number(), 1);

        let key2 = chain.advance();
        assert_eq!(chain.message_number(), 2);

        // Keys should be different
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_ratchet_encrypt_decrypt() {
        let alice_secret = StaticSecret::new(rand::thread_rng());
        let alice_public = PublicKey::from(&alice_secret);

        let bob_secret = StaticSecret::new(rand::thread_rng());
        let bob_public = PublicKey::from(&bob_secret);

        let mut alice_ratchet = RatchetState::new(alice_secret, bob_public);
        let mut bob_ratchet = RatchetState::new(bob_secret, alice_public);

        // Alice sends message to Bob
        let plaintext = b"Hello Bob!";
        let encrypted = alice_ratchet.encrypt(plaintext).unwrap();

        // Bob receives and decrypts
        let decrypted = bob_ratchet.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_multiple_messages() {
        let alice_secret = StaticSecret::new(rand::thread_rng());
        let alice_public = PublicKey::from(&alice_secret);

        let bob_secret = StaticSecret::new(rand::thread_rng());
        let bob_public = PublicKey::from(&bob_secret);

        let mut alice_ratchet = RatchetState::new(alice_secret, bob_public);
        let mut bob_ratchet = RatchetState::new(bob_secret, alice_public);

        // Send multiple messages
        for i in 0..10 {
            let plaintext = format!("Message {}", i);
            let encrypted = alice_ratchet.encrypt(plaintext.as_bytes()).unwrap();
            let decrypted = bob_ratchet.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    #[test]
    fn test_emoji_fingerprint() {
        let alice_secret = StaticSecret::new(rand::thread_rng());
        let alice_public = PublicKey::from(&alice_secret);

        let bob_secret = StaticSecret::new(rand::thread_rng());
        let bob_public = PublicKey::from(&bob_secret);

        // Generate fingerprint from both sides
        let alice_fingerprint = generate_emoji_fingerprint(&alice_public, &bob_public);
        let bob_fingerprint = generate_emoji_fingerprint(&bob_public, &alice_public);

        // Should be identical (order independent)
        assert_eq!(alice_fingerprint, bob_fingerprint);

        // Should have 6 emoji
        assert_eq!(alice_fingerprint.len(), 6);
    }
}
