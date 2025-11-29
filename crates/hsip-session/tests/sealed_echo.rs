// crates/hsip-session/tests/sealed_echo.rs
use hsip_session::{Ephemeral, PeerLabel, Session};

#[test]
fn sealed_echo_roundtrip() {
    // Generate two ephemeral keypairs
    let eph1 = Ephemeral::generate();
    let pk1 = eph1.public(); // cache BEFORE consuming

    let eph2 = Ephemeral::generate();
    let pk2 = eph2.public(); // cache BEFORE consuming

    // Derive shared secrets (into_shared consumes self)
    let s1 = eph1
        .into_shared(&pk2)
        .expect("derive shared secret from eph1");

    let s2 = eph2
        .into_shared(&pk1)
        .expect("derive shared secret from eph2");

    // Both sides must match
    assert_eq!(s1, s2, "shared secrets must match");

    // Build sessions from the shared secret (same label on both ends)
    let label = PeerLabel {
        label: b"TEST".to_vec(),
    };
    let mut sess1 = Session::from_shared_secret(s1, Some(&label)).expect("sess1");
    let mut sess2 = Session::from_shared_secret(s2, Some(&label)).expect("sess2");

    // Seal/Open roundtrip
    let aad = b"type=TEST";
    let pt = b"hello world";

    let ct = sess1.seal(aad, pt).expect("seal");
    let out = sess2.open(aad, &ct).expect("open");

    assert_eq!(&out[..], pt, "plaintext must roundtrip");
}
