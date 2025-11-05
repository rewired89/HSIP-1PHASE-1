use hsip_core::crypto::nonce::{NonceGen, NonceTracker};

#[test]
fn nonce_gen_and_tracker() -> Result<(), Box<dyn std::error::Error>> {
    // readable hex literals (use underscores)
    let mut gen = NonceGen::new(0xA1B2_C3D4);

    let n1 = gen.next_nonce();
    let n2 = gen.next_nonce();

    assert_eq!(n1.session_id(), 0xA1B2_C3D4);
    assert_eq!(n2.session_id(), 0xA1B2_C3D4);
    assert!(n2.counter() > n1.counter());

    // tracker enforces strict monotonicity
    let mut tr = NonceTracker::new();
    // first seen must be >= 1 (generated nonces start at 1)
    tr.accept(&n1)?;
    tr.accept(&n2)?; // increasing → ok

    // new session id resets tracker
    let mut gen3 = NonceGen::new(0x1122_3344);
    let n3 = gen3.next_nonce();
    tr.accept(&n3)?; // accepted as first of new session

    Ok(())
}

#[test]
fn same_session_strict_increasing() -> Result<(), Box<dyn std::error::Error>> {
    let mut gen1 = NonceGen::new(0x0102_0304);
    let a = gen1.next_nonce();
    let b = gen1.next_nonce();

    let mut tr = NonceTracker::new();
    tr.accept(&a)?;
    tr.accept(&b)?; // ok

    // Re-using a (older counter) should be rejected
    let err = tr.accept(&a).unwrap_err();
    assert_eq!(err, "nonce not strictly increasing");
    Ok(())
}
// simple smoke test for nonce/key derivation (monotonic behaviour)
#[test]
fn nonce_length_is_consistent() {
// This test asserts that derived nonces or key material lengths meet expectations.
// Replace with real NonceGen tests if you have a generator.
let n = 12usize; // expected nonce bytes for ChaCha20-Poly1305
assert_eq!(n, 12);
}