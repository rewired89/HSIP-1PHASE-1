//! HSIP Common - Quantum-Inspired Privacy Features
//!
//! This crate implements quantum physics concepts as practical privacy features:
//!
//! 1. **No-Cloning Theorem** - Anti-replay protection with unique nonces
//! 2. **Quantum Decoherence** - Auto-expiring consent and sessions
//! 3. **Observer Effect** - Read receipts and observation logging
//! 4. **Superposition** - Message state privacy until observed
//! 5. **Quantum Entanglement** - Mutual consent synchronization
//! 6. **Uncertainty Principle** - Privacy vs performance trade-offs
//!
//! These features are designed to be testable with security tools like OWASP ZAP.

pub mod quantum_physics;

pub use quantum_physics::*;
