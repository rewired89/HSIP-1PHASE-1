// HSIP network protocol implementation
// Handles connection establishment, handshakes, and UDP transport

// Consent caching layer for authorization decisions
pub mod consent_cache;

// Protocol guard mechanisms for security validation
pub mod guard;

// Handshake I/O operations and state management
pub mod handshake_io;

// HELLO message handling and peer discovery
pub mod hello;

// UDP transport layer implementation
pub mod udp;

// Network subsystem organization
pub mod protocol {
    pub use super::hello;
    pub use super::handshake_io;
}

pub mod transport {
    //! Transport layer abstractions
    pub use super::udp;
}

pub mod security {
    //! Security enforcement layers
    pub use super::guard;
    pub use super::consent_cache;
}
