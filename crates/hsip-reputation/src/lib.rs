// Minimal public surface: expose the persistence store.

#![allow(non_camel_case_types)] // keep SPAM/VERIFIED_ID/etc without warnings

pub mod store;

// Optional: convenient re-exports
pub use store::{DecisionType, Event, Evidence, Store};
