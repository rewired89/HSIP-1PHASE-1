//! HSIP routing logic for intercepted messages.

use crate::{InterceptConfig, Result, InterceptError};
use hsip_core::identity::PeerID;
use tracing::{info, warn};

/// Routes messages through HSIP protocol.
pub struct HSIPRouter {
    config: InterceptConfig,
    // Will integrate with hsip-core components
}

impl HSIPRouter {
    /// Create a new HSIP router.
    pub async fn new(config: &InterceptConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Open HSIP Messenger window for a recipient.
    ///
    /// This will:
    /// 1. Resolve recipient to PeerID (if possible)
    /// 2. Initiate consent handshake
    /// 3. Open messenger UI
    /// 4. Start encrypted session
    pub async fn open_messenger(&self, recipient: Option<String>) -> Result<()> {
        info!("Opening HSIP Messenger for recipient: {:?}", recipient);

        if let Some(recipient_info) = recipient {
            // Try to resolve to PeerID
            let peer_id = self.resolve_recipient(&recipient_info).await?;

            if let Some(peer_id) = peer_id {
                self.start_session_with_peer(peer_id).await?;
            } else {
                // Show manual entry UI
                self.open_messenger_manual(Some(recipient_info)).await?;
            }
        } else {
            // No recipient info, open blank messenger
            self.open_messenger_manual(None).await?;
        }

        Ok(())
    }

    /// Resolve a recipient string to a PeerID.
    ///
    /// This can use:
    /// - Local contact book
    /// - DHT lookup (future)
    /// - QR code scanning
    /// - Deep link parsing
    async fn resolve_recipient(&self, recipient: &str) -> Result<Option<PeerID>> {
        // Check if it's already a PeerID
        if recipient.starts_with("peer_") {
            // Try to parse as PeerID
            // TODO: Implement proper PeerID parsing from hsip-core
            warn!("PeerID parsing not yet implemented");
            return Ok(None);
        }

        // Check local contact book
        if let Some(peer_id) = self.lookup_contact(recipient).await? {
            return Ok(Some(peer_id));
        }

        // Future: DHT lookup
        // Future: Deep link resolution

        Ok(None)
    }

    /// Look up a contact in the local contact book.
    async fn lookup_contact(&self, name: &str) -> Result<Option<PeerID>> {
        // TODO: Implement contact book integration
        // For now, return None (manual entry required)
        Ok(None)
    }

    /// Start an HSIP session with a known peer.
    async fn start_session_with_peer(&self, peer_id: PeerID) -> Result<()> {
        info!("Starting HSIP session with peer: {:?}", peer_id);

        // TODO: Integrate with hsip-core session management
        // 1. Send consent request
        // 2. Wait for consent response
        // 3. Establish ephemeral session
        // 4. Open messenger UI with active session

        warn!("Session establishment not yet implemented");
        Ok(())
    }

    /// Open messenger with manual recipient entry.
    async fn open_messenger_manual(&self, hint: Option<String>) -> Result<()> {
        info!("Opening messenger with manual entry (hint: {:?})", hint);

        // TODO: Open messenger UI
        // Platform-specific implementation needed

        #[cfg(target_os = "windows")]
        {
            crate::windows::open_messenger_window(hint).await?;
        }

        #[cfg(target_os = "android")]
        {
            crate::android::open_messenger_activity(hint).await?;
        }

        Ok(())
    }

    /// Send a message through HSIP.
    pub async fn send_message(&self, peer_id: PeerID, message: String) -> Result<()> {
        info!("Sending message via HSIP to {:?}", peer_id);

        // TODO: Implement message sending via hsip-session
        // 1. Check if session exists and is valid
        // 2. If not, establish new session
        // 3. Encrypt message with session key
        // 4. Send via hsip-net

        warn!("Message sending not yet implemented");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_router_creation() {
        let config = InterceptConfig::default();
        let router = HSIPRouter::new(&config).await;
        assert!(router.is_ok());
    }

    #[tokio::test]
    async fn test_recipient_resolution() {
        let config = InterceptConfig::default();
        let router = HSIPRouter::new(&config).await.unwrap();

        // Test with PeerID format
        let result = router.resolve_recipient("peer_abc123").await;
        assert!(result.is_ok());

        // Test with unknown format
        let result = router.resolve_recipient("alice").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Should return None (needs manual entry)
    }
}
