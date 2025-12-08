//! HSIP message formatting and parsing.

use crate::{Result, HSIPKeyboardError};
use serde::{Deserialize, Serialize};

/// Format for displaying encrypted messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageFormat {
    /// Compact: 🔒base64...
    Compact,

    /// Verbose: 🔒 [HSIP] base64... + decrypt link
    Verbose,

    /// Stealth: just base64 (no emoji)
    Stealth,
}

/// HSIP encrypted message structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSIPMessage {
    /// Protocol version
    pub version: u8,

    /// Sender's PeerID (32 bytes Blake3 hash)
    pub sender_peer_id: [u8; 32],

    /// Nonce for ChaCha20-Poly1305 (12 bytes)
    pub nonce: [u8; 12],

    /// Encrypted payload
    pub ciphertext: Vec<u8>,

    /// Authentication tag (16 bytes)
    pub tag: [u8; 16],
}

impl HSIPMessage {
    /// Create a new HSIP message.
    pub fn new(
        sender_peer_id: [u8; 32],
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
        tag: [u8; 16],
    ) -> Self {
        Self {
            version: 1,
            sender_peer_id,
            nonce,
            ciphertext,
            tag,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version (1 byte)
        bytes.push(self.version);

        // Sender PeerID (32 bytes)
        bytes.extend_from_slice(&self.sender_peer_id);

        // Nonce (12 bytes)
        bytes.extend_from_slice(&self.nonce);

        // Tag (16 bytes)
        bytes.extend_from_slice(&self.tag);

        // Ciphertext (variable length)
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 61 {
            // 1 + 32 + 12 + 16 = 61 bytes minimum
            return Err(HSIPKeyboardError::InvalidFormat(
                "Message too short".to_string(),
            ));
        }

        let version = bytes[0];
        if version != 1 {
            return Err(HSIPKeyboardError::InvalidFormat(format!(
                "Unsupported version: {}",
                version
            )));
        }

        let mut sender_peer_id = [0u8; 32];
        sender_peer_id.copy_from_slice(&bytes[1..33]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[33..45]);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&bytes[45..61]);

        let ciphertext = bytes[61..].to_vec();

        Ok(Self {
            version,
            sender_peer_id,
            nonce,
            tag,
            ciphertext,
        })
    }

    /// Format as string for display.
    pub fn format(&self, format: MessageFormat, message_id: Option<&str>) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(self.to_bytes());

        match format {
            MessageFormat::Compact => {
                format!("🔒{}", encoded)
            }
            MessageFormat::Verbose => {
                let mut result = String::from("🔒 [HSIP Encrypted Message]\n");

                if let Some(id) = message_id {
                    result.push_str(&format!("Decrypt: hsip://m/{}\n", id));
                    result.push_str(&format!(
                        "Or visit: hsip://decrypt?id={}\n\n",
                        id
                    ));
                }

                result.push_str(&encoded);
                result
            }
            MessageFormat::Stealth => encoded,
        }
    }

    /// Parse from formatted string.
    pub fn parse(text: &str) -> Result<Self> {
        // Try different formats
        let encoded = if text.starts_with("🔒") {
            // Compact or verbose format
            let lines: Vec<&str> = text.lines().collect();

            // Find the line with base64 data (longest line)
            lines
                .iter()
                .max_by_key(|line| line.len())
                .and_then(|line| {
                    let trimmed = line.trim();
                    // Remove emoji if present
                    if trimmed.starts_with("🔒") {
                        Some(&trimmed[4..]) // Skip emoji (4 bytes UTF-8)
                    } else {
                        Some(trimmed)
                    }
                })
                .ok_or_else(|| {
                    HSIPKeyboardError::InvalidFormat("No base64 data found".to_string())
                })?
        } else {
            // Stealth format (just base64)
            text.trim()
        };

        // Decode base64
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| HSIPKeyboardError::InvalidFormat(format!("Base64 decode error: {}", e)))?;

        // Parse bytes
        Self::from_bytes(&bytes)
    }

    /// Check if text contains an HSIP message.
    pub fn contains_hsip_message(text: &str) -> bool {
        text.contains("🔒") || text.contains("[HSIP")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = HSIPMessage::new(
            [0u8; 32],
            [1u8; 12],
            vec![2u8; 100],
            [3u8; 16],
        );

        let bytes = msg.to_bytes();
        let parsed = HSIPMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, msg.version);
        assert_eq!(parsed.sender_peer_id, msg.sender_peer_id);
        assert_eq!(parsed.nonce, msg.nonce);
        assert_eq!(parsed.tag, msg.tag);
        assert_eq!(parsed.ciphertext, msg.ciphertext);
    }

    #[test]
    fn test_message_formatting() {
        let msg = HSIPMessage::new(
            [0u8; 32],
            [1u8; 12],
            vec![2u8; 50],
            [3u8; 16],
        );

        // Compact format
        let compact = msg.format(MessageFormat::Compact, None);
        assert!(compact.starts_with("🔒"));

        // Verbose format
        let verbose = msg.format(MessageFormat::Verbose, Some("abc123"));
        assert!(verbose.contains("[HSIP"));
        assert!(verbose.contains("hsip://m/abc123"));

        // Stealth format
        let stealth = msg.format(MessageFormat::Stealth, None);
        assert!(!stealth.contains("🔒"));
    }

    #[test]
    fn test_message_parsing() {
        let msg = HSIPMessage::new(
            [0u8; 32],
            [1u8; 12],
            vec![2u8; 50],
            [3u8; 16],
        );

        // Test compact format
        let formatted = msg.format(MessageFormat::Compact, None);
        let parsed = HSIPMessage::parse(&formatted).unwrap();
        assert_eq!(parsed.ciphertext, msg.ciphertext);

        // Test verbose format
        let formatted = msg.format(MessageFormat::Verbose, Some("abc123"));
        let parsed = HSIPMessage::parse(&formatted).unwrap();
        assert_eq!(parsed.ciphertext, msg.ciphertext);

        // Test stealth format
        let formatted = msg.format(MessageFormat::Stealth, None);
        let parsed = HSIPMessage::parse(&formatted).unwrap();
        assert_eq!(parsed.ciphertext, msg.ciphertext);
    }

    #[test]
    fn test_contains_hsip_message() {
        assert!(HSIPMessage::contains_hsip_message("🔒abc123"));
        assert!(HSIPMessage::contains_hsip_message("Check this [HSIP message"));
        assert!(!HSIPMessage::contains_hsip_message("Normal text"));
    }
}
