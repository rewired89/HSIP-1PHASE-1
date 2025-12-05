//! Session management for HSIP Keyboard.

use crate::{Result, HSIPKeyboardError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Session information for a contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: String,

    /// Contact's PeerID
    pub peer_id: [u8; 32],

    /// Display name (e.g., "Alice Smith")
    pub display_name: String,

    /// Derived session key (32 bytes)
    pub session_key: [u8; 32],

    /// Session creation timestamp
    pub created_at: i64,

    /// Session expiry timestamp
    pub expires_at: i64,

    /// Message counter (for rekeying)
    pub message_count: u32,

    /// Whether this session is active
    pub is_active: bool,
}

impl Session {
    /// Create a new session.
    pub fn new(
        peer_id: [u8; 32],
        display_name: String,
        session_key: [u8; 32],
        duration_seconds: i64,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Generate session ID from peer_id
        let id = format!("sess_{}", hex::encode(&peer_id[..8]));

        Self {
            id,
            peer_id,
            display_name,
            session_key,
            created_at: now,
            expires_at: now + duration_seconds,
            message_count: 0,
            is_active: true,
        }
    }

    /// Check if session is expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        now >= self.expires_at
    }

    /// Check if session needs rekeying (>1000 messages or expired).
    pub fn needs_rekey(&self) -> bool {
        self.message_count >= 1000 || self.is_expired()
    }

    /// Increment message counter.
    pub fn increment_counter(&mut self) {
        self.message_count += 1;
    }
}

/// Session manager for storing and retrieving sessions.
pub struct SessionManager {
    sessions: HashMap<String, Session>,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Add a new session.
    pub fn add_session(&mut self, session: Session) {
        self.sessions.insert(session.id.clone(), session);
    }

    /// Get session by ID.
    pub fn get_session(&self, session_id: &str) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    /// Get mutable session by ID.
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(session_id)
    }

    /// Find session by peer ID.
    pub fn find_by_peer_id(&self, peer_id: &[u8; 32]) -> Option<&Session> {
        self.sessions
            .values()
            .find(|s| &s.peer_id == peer_id && s.is_active)
    }

    /// List all active sessions.
    pub fn list_active(&self) -> Vec<&Session> {
        self.sessions
            .values()
            .filter(|s| s.is_active && !s.is_expired())
            .collect()
    }

    /// Remove expired sessions.
    pub fn cleanup_expired(&mut self) {
        self.sessions.retain(|_, s| !s.is_expired() || s.is_active);
    }

    /// Deactivate a session.
    pub fn deactivate(&mut self, session_id: &str) -> Result<()> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.is_active = false;
            Ok(())
        } else {
            Err(HSIPKeyboardError::SessionNotFound(session_id.to_string()))
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let peer_id = [1u8; 32];
        let session = Session::new(
            peer_id,
            "Alice".to_string(),
            [42u8; 32],
            86400, // 24 hours
        );

        assert_eq!(session.display_name, "Alice");
        assert!(!session.is_expired());
        assert!(!session.needs_rekey());
    }

    #[test]
    fn test_session_rekey() {
        let peer_id = [1u8; 32];
        let mut session = Session::new(
            peer_id,
            "Bob".to_string(),
            [42u8; 32],
            86400,
        );

        // Simulate sending many messages
        for _ in 0..1001 {
            session.increment_counter();
        }

        assert!(session.needs_rekey());
    }

    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new();

        let peer_id1 = [1u8; 32];
        let session1 = Session::new(
            peer_id1,
            "Alice".to_string(),
            [42u8; 32],
            86400,
        );

        let peer_id2 = [2u8; 32];
        let session2 = Session::new(
            peer_id2,
            "Bob".to_string(),
            [43u8; 32],
            86400,
        );

        manager.add_session(session1.clone());
        manager.add_session(session2.clone());

        // Find by peer ID
        let found = manager.find_by_peer_id(&peer_id1);
        assert!(found.is_some());
        assert_eq!(found.unwrap().display_name, "Alice");

        // List active
        let active = manager.list_active();
        assert_eq!(active.len(), 2);

        // Deactivate
        manager.deactivate(&session1.id).unwrap();
        let active = manager.list_active();
        assert_eq!(active.len(), 1);
    }
}
