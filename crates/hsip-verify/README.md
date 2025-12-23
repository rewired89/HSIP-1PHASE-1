# HSIP Formal Verification

Formal verification of HSIP (Hyper Secure Identity Protocol) security properties using Z3 SMT solver.

## Overview

This crate provides **symbolic verification** of critical security properties in HSIP using the Z3 Satisfiability Modulo Theories (SMT) solver. It proves mathematical guarantees about the protocol's security without relying on empirical testing alone.

## Security Properties Verified

### 1. Consent Non-Forgery
**Property**: A valid consent signature can only be created by the holder of the private key.

**Formal Specification**:
```
∀ consent, sig. valid(consent, sig, pk) ⟹ ∃ sk. sign(sk, consent) = sig ∧ derive(sk) = pk
```

**Implication**: Attackers cannot forge consent tokens without compromising the private key.

### 2. Temporal Consistency
**Property**: Once consent is revoked at time t, it remains revoked for all future times.

**Formal Specification**:
```
∀ t1, t2. (revoked_at(t1) ∧ t2 > t1) ⟹ ¬allowed_at(t2)
```

**Implication**: Revocation is permanent and cannot be bypassed through timing attacks.

### 3. Identity Binding Soundness
**Property**: Each peer ID uniquely identifies a single public key (collision resistance).

**Formal Specification**:
```
∀ peer_id, pk1, pk2. (peer_id = derive(pk1) ∧ peer_id = derive(pk2)) ⟹ pk1 = pk2
```

**Implication**: Identity cannot be spoofed through hash collisions.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HSIP Application                     │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              hsip_core::verification                    │
│         (Protocol initialization hook)                  │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                  hsip-verify                            │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Verifier (Main verification engine)             │  │
│  └──────────────────┬────────────────────────────────┘  │
│                     │                                    │
│     ┌───────────────┼───────────────┐                   │
│     ▼               ▼               ▼                    │
│  ┌────────┐  ┌────────────┐  ┌──────────┐              │
│  │ Models │  │ Properties │  │ Z3 SMT   │              │
│  │        │  │            │  │ Solver   │              │
│  └────────┘  └────────────┘  └──────────┘              │
│                                                          │
│  • ConsentModel    • SecurityProperty                   │
│  • IdentityModel   • PropertyResult                     │
│  • SignatureModel  • Counterexample                     │
└─────────────────────────────────────────────────────────┘
                      │
                      ▼
              [Verification Report]
```

## Usage

### Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
hsip-core = { version = "0.1", features = ["verification"] }
```

Run verification at startup:

```rust
use hsip_core::verification::initialize_with_verification;

fn main() {
    // Run formal verification at startup
    let verification_passed = initialize_with_verification(true);

    if !verification_passed {
        eprintln!("⚠️  Security property verification failed!");
        std::process::exit(1);
    }

    println!("✅ HSIP initialized with verified security properties");

    // Continue with normal protocol operation...
}
```

### Advanced Usage

For fine-grained control:

```rust
use hsip_verify::{Verifier, VerificationConfig};

let config = VerificationConfig {
    timeout_ms: 10000,              // 10 seconds per property
    generate_counterexamples: true, // Generate counterexamples on failure
    verbosity: 2,                   // Verbose output
};

let verifier = Verifier::new(config);
let report = verifier.verify_all();

if report.all_proven() {
    println!("✅ All properties proven!");
} else if report.has_violations() {
    eprintln!("❌ Security violations detected!");
    for (name, result) in report.results() {
        println!("{}: {}", name, result);
    }
}
```

### Running Tests

```bash
# Run all verification tests
cargo test -p hsip-verify

# Run with verbose output
cargo test -p hsip-verify -- --nocapture

# Run specific test
cargo test -p hsip-verify test_consent_non_forgery

# Run example
cargo run -p hsip-verify --example verify_hsip
```

## Performance Considerations

### Verification Timing
- **Per property**: ~0.5-2 seconds (depending on SMT solver)
- **Total verification**: ~1-5 seconds for all properties
- **Recommended timeout**: 5-10 seconds per property

### When to Run
✅ **DO** run verification:
- At protocol initialization (startup)
- In CI/CD pipelines
- Before deploying security-critical updates
- During security audits

❌ **DO NOT** run verification:
- Per transaction (too slow)
- In hot paths
- On every consent request

### Production Deployment

For production systems, verification is **optional** but recommended:

1. **Development/Testing**: Enable verification
   ```bash
   cargo build --features verification
   ```

2. **Production**: Disable for performance (after verification in testing)
   ```bash
   cargo build --release
   ```

3. **Continuous Verification**: Run in CI/CD
   ```yaml
   # .github/workflows/verify.yml
   - name: Run formal verification
     run: cargo test -p hsip-verify --features verification
   ```

## Technical Details

### Z3 SMT Solver Integration

The verification engine uses Z3 to model:
- **Bitvectors** (BV): Ed25519 keys (256-bit), signatures (512-bit)
- **Integers** (Int): Timestamps, TTL values
- **Booleans** (Bool): Logical properties
- **Constraints**: Security properties as SMT formulas

### Verification Approach

1. **Model Construction**: Create symbolic models of protocol components
2. **Property Encoding**: Encode security properties as SMT constraints
3. **Negation**: Try to find counterexamples (SAT = violation found)
4. **Proof**: UNSAT result proves property holds ∀ inputs

### Example: Consent Non-Forgery

```rust
// Symbolic variables
let consent_hash = BV::new_const(&ctx, "consent_hash", 256);
let signature = BV::new_const(&ctx, "signature", 512);
let public_key = BV::new_const(&ctx, "public_key", 256);

// Try to forge signature without private key
let can_forge = Bool::new_const(&ctx, "can_forge");
solver.assert(&can_forge);

// Check satisfiability
match solver.check() {
    SatResult::Unsat => /* Property proven! */,
    SatResult::Sat => /* Violation found */,
    SatResult::Unknown => /* Timeout */,
}
```

## Counterexample Generation

When a property fails, the verifier generates detailed counterexamples:

```rust
Counterexample for: Temporal Consistency
═════════════════════════════════════════════════════
Consent still allowed after revocation time

Details:
  • revoke_time: 1800
  • check_time: 1900
  • description: Consent still allowed after revocation time
```

## Limitations

### Current Scope
- ✅ Consent protocol properties
- ✅ Identity binding
- ✅ Temporal consistency
- ⚠️  Does NOT verify cryptographic primitives themselves (assumes correct Ed25519, BLAKE3)

### Known Limitations
1. **Cryptographic Assumptions**: Assumes Ed25519 and BLAKE3 are secure (industry standard)
2. **Model Abstractions**: Simplifies some aspects (e.g., network timing)
3. **SMT Solver Limits**: May timeout on very complex properties

### Future Work
- Integration with Tamarin Prover for protocol-level verification
- Post-quantum cryptography verification (Kyber/Dilithium)
- Session key derivation properties
- Full DeepProbLog integration for probabilistic verification

## References

- **Z3 Solver**: [https://github.com/Z3Prover/z3](https://github.com/Z3Prover/z3)
- **SMT-LIB**: [http://smtlib.cs.uiowa.edu/](http://smtlib.cs.uiowa.edu/)
- **Ed25519**: [RFC 8032](https://tools.ietf.org/html/rfc8032)
- **BLAKE3**: [https://github.com/BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3)

## License

Same as HSIP project.

## Contributing

Contributions welcome! Areas of interest:
- Additional security properties
- Performance optimizations
- Integration with other proof systems
- Counterexample visualization

---

**Note**: This is formal verification of protocol logic, not a substitute for:
- Code audits
- Penetration testing
- Side-channel analysis
- Implementation vulnerability scanning

Use in combination with traditional security practices for defense-in-depth.
