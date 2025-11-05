use hsip_session::{Ephemeral, PeerLabel, Session};


#[test]
fn seal_open_roundtrip() {
let eph = Ephemeral::generate();
let other = Ephemeral::generate();
let s1 = eph.into_shared(&other.public()).unwrap();
let s2 = other.into_shared(&eph.public()).unwrap();


let label = PeerLabel { label: b"TEST".to_vec() };
let mut sess1 = Session::from_shared_secret(s1, Some(&label)).unwrap();
let mut sess2 = Session::from_shared_secret(s2, Some(&label)).unwrap();


let pt = b"hello world";
let ct = sess1.seal(b"type=TEST", pt).unwrap();
let out = sess2.open(b"type=TEST", &ct).unwrap();
assert_eq!(out, pt);
}