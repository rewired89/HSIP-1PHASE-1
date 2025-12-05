//! Encryption and decryption using HSIP protocol.

use crate::{HSIPMessage, Result, HSIPKeyboardError};
use hsip_session::SessionCipher;
use rand::RngCore;

/// Encrypt a plaintext message with a session key.
pub fn encrypt_message(
    plaintext: &str,
    session_key: &[u8; 32],
    sender_peer_id: &[u8; 32],
) -> Result<HSIPMessage> {
    // Generate random nonce
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Create session cipher
    let cipher = SessionCipher::from_key(session_key);

    // Encrypt with AAD
    let aad = b"HSIP-KEYBOARD-v1";
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes(), aad)
        .map_err(|e| {
            HSIPKeyboardError::Encryption(format!("Session cipher encrypt failed: {}", e))
        })?;

    // Split ciphertext and tag
    let tag_offset = ciphertext.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[tag_offset..]);

    let payload = ciphertext[..tag_offset].to_vec();

    Ok(HSIPMessage::new(*sender_peer_id, nonce, payload, tag))
}

/// Decrypt an HSIP message with a session key.
pub fn decrypt_message(
    message: &HSIPMessage,
    session_key: &[u8; 32],
) -> Result<String> {
    // Create session cipher
    let cipher = SessionCipher::from_key(session_key);

    // Reconstruct ciphertext + tag
    let mut full_ciphertext = message.ciphertext.clone();
    full_ciphertext.extend_from_slice(&message.tag);

    // Decrypt with AAD
    let aad = b"HSIP-KEYBOARD-v1";
    let plaintext = cipher
        .decrypt(&message.nonce, &full_ciphertext, aad)
        .map_err(|e| {
            HSIPKeyboardError::Decryption(format!("Session cipher decrypt failed: {}", e))
        })?;

    // Convert to string
    String::from_utf8(plaintext).map_err(|e| {
        HSIPKeyboardError::Decryption(format!("Invalid UTF-8: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = "Hello, HSIP Keyboard!";
        let session_key = [42u8; 32];
        let peer_id = [1u8; 32];

        // Encrypt
        let message = encrypt_message(plaintext, &session_key, &peer_id).unwrap();

        // Decrypt
        let decrypted = decrypt_message(&message, &session_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let plaintext = "Secret message";
        let session_key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let peer_id = [1u8; 32];

        // Encrypt with correct key
        let message = encrypt_message(plaintext, &session_key, &peer_id).unwrap();

        // Try to decrypt with wrong key
        let result = decrypt_message(&message, &wrong_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_randomness() {
        let session_key = [42u8; 32];
        let peer_id = [1u8; 32];

        let msg1 = encrypt_message("test", &session_key, &peer_id).unwrap();
        let msg2 = encrypt_message("test", &session_key, &peer_id).unwrap();

        // Nonces should be different
        assert_ne!(msg1.nonce, msg2.nonce);

        // Both should decrypt correctly
        assert_eq!(decrypt_message(&msg1, &session_key).unwrap(), "test");
        assert_eq!(decrypt_message(&msg2, &session_key).unwrap(), "test");
    }
}
