// HSIP authentication subsystem
// Provides peer identity management, secure key storage, and token-based authentication

pub mod identity;
pub mod keystore;

#[doc(inline)]
pub use keystore as key_storage;

pub mod tokens;

// Internal authentication utilities
mod auth_internal {
    #[allow(unused)]
    pub(crate) fn _reserved_for_auth_expansion() {}
}
