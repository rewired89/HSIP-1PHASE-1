//! Core HSIP types and helpers.

#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]

pub mod consent;
pub mod crypto {
    pub mod aead;
    pub mod labels;
    pub mod nonce;
}
pub mod identity;
pub mod keystore;
pub mod wire {
    pub mod prefix;
}
