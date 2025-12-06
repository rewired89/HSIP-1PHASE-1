// Cryptographic primitives for HSIP protocol
// This module exposes authenticated encryption, label generation, and nonce handling

// AEAD encryption and decryption operations
pub mod aead;

// Protocol-specific label generation for key derivation
pub mod labels;

// Nonce generation and management utilities  
pub mod nonce;

// Convenience re-exports for common crypto operations
pub mod primitives {
    #[doc(inline)]
    pub use super::aead;
    #[doc(inline)]
    pub use super::labels;
    #[doc(inline)]
    pub use super::nonce;
}

#[cfg(test)]
mod crypto_tests {
}
