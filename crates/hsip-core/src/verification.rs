//! Protocol initialization with formal verification
//!
//! This module provides an initialization hook that runs formal verification
//! of critical security properties using Z3 SMT solver.
//!
//! Verification is only enabled when the "verification" feature is active.

#[cfg(feature = "verification")]
use hsip_verify::{Verifier, VerificationConfig};

/// Initialize HSIP protocol with formal verification
///
/// This function should be called at application startup to verify
/// critical security properties before the protocol handles any real traffic.
///
/// # Security Properties Verified
///
/// 1. **Consent Non-Forgery**: Consent cannot be forged without the private key
/// 2. **Temporal Consistency**: Revocation is temporally consistent
/// 3. **Identity Binding**: Peer IDs are cryptographically bound to public keys
///
/// # Performance
///
/// Verification runs at startup only, not per-transaction, to avoid runtime overhead.
/// Typical verification time is 1-5 seconds depending on solver timeout configuration.
///
/// # Example
///
/// ```rust,no_run
/// use hsip_core::verification::initialize_with_verification;
///
/// fn main() {
///     // Run formal verification at startup
///     let verification_passed = initialize_with_verification(true);
///
///     if !verification_passed {
///         eprintln!("⚠️  Security property verification failed!");
///         // In production, you might want to abort here
///         std::process::exit(1);
///     }
///
///     // Continue with normal protocol operation
///     println!("✅ HSIP initialized with verified security properties");
/// }
/// ```
#[cfg(feature = "verification")]
pub fn initialize_with_verification(verbose: bool) -> bool {
    let config = VerificationConfig {
        timeout_ms: 5000,
        generate_counterexamples: true,
        verbosity: if verbose { 2 } else { 1 },
    };

    let verifier = Verifier::new(config);
    let report = verifier.verify_all();

    if verbose {
        println!("{}", report);
    }

    // Return true only if all properties are proven
    if !report.all_proven() {
        eprintln!("\n❌ HSIP formal verification FAILED!");
        eprintln!("Some security properties could not be proven.");

        if report.has_violations() {
            eprintln!("⚠️  CRITICAL: Security property violations detected!");
            for (name, result) in report.results() {
                if result.is_violated() {
                    eprintln!("  - {}: VIOLATED", name);
                }
            }
        }

        return false;
    }

    if verbose {
        println!("✅ All HSIP security properties formally verified!");
    }

    true
}

/// Stub for non-verification builds
#[cfg(not(feature = "verification"))]
pub fn initialize_with_verification(_verbose: bool) -> bool {
    eprintln!("⚠️  Formal verification is not enabled (compile with --features verification)");
    true // Don't block initialization if verification isn't compiled in
}

/// Quick initialization check (runs verification in fast mode)
#[cfg(feature = "verification")]
pub fn quick_verification_check() -> bool {
    let config = VerificationConfig {
        timeout_ms: 2000, // Faster timeout
        generate_counterexamples: false, // Skip counterexamples for speed
        verbosity: 0, // Quiet
    };

    let verifier = Verifier::new(config);
    let report = verifier.verify_all();

    report.all_proven()
}

#[cfg(not(feature = "verification"))]
pub fn quick_verification_check() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "verification")]
    fn test_initialization_with_verification() {
        // This should pass (all properties proven)
        let result = initialize_with_verification(true);
        assert!(result, "Verification should succeed");
    }

    #[test]
    #[cfg(feature = "verification")]
    fn test_quick_verification() {
        let result = quick_verification_check();
        assert!(result, "Quick verification should succeed");
    }

    #[test]
    #[cfg(not(feature = "verification"))]
    fn test_verification_stub() {
        // When verification is disabled, should still return true
        let result = initialize_with_verification(false);
        assert!(result);
    }
}
