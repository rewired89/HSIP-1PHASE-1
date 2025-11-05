//! Minimal public surface for the reputation crate: expose the persistence store
//! and its primary types.

#![allow(non_camel_case_types)] // keep SPAM/VERIFIED_ID/etc without warnings

pub mod store;

// Convenient re-exports so downstream crates can `use hsip_reputation::Store;`
pub use store::{DecisionType, Event, Evidence, Store};
