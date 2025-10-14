// Run: cargo test -p hsip-core --test nonce_integrity
use hsip_core::crypto::nonce::{NonceGen, NonceTracker};

#[test]
fn generator_is_monotonic() {
    let mut gen = NonceGen::new(0xA1B2C3D4);
    let n1 = gen.next_nonce();
    let n2 = gen.next_nonce();

    assert_eq!(n1.session_id(), 0xA1B2C3D4);
    assert_eq!(n2.session_id(), 0xA1B2C3D4);
    assert!(n2.counter() > n1.counter());
}

#[test]
fn tracker_accepts_increasing_rejects_dup_and_decreasing() {
    let mut gen = NonceGen::new(0x01020304);
    let n1 = gen.next_nonce(); // counter = 1
    let n2 = gen.next_nonce(); // counter = 2

    let mut tr = NonceTracker::new();
    assert!(tr.accept(&n1).is_ok());
    assert!(tr.accept(&n2).is_ok());

    // duplicate should fail
    assert!(tr.accept(&n2).is_err());

    // decreasing should fail
    let mut gen2 = NonceGen::new(0x01020304);
    let n0 = gen2.next_nonce(); // counter = 1 again (smaller than last_counter=2)

    assert!(tr.accept(&n0).is_err());

    // new session resets tracker (accepts if counter >= 1)
    let mut gen3 = NonceGen::new(0x11223344);
    let m1 = gen3.next_nonce(); // counter = 1

    assert!(tr.accept(&m1).is_ok());
}
