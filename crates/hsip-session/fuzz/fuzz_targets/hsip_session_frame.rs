#![no_main]
use libfuzzer_sys::fuzz_target;

use hsip_session::{PeerLabel, Session};

fuzz_target!(|data: &[u8]| {
    // Fixed shared secret to keep the fuzzer deterministic.
    let shared = [0x42u8; 32];
    let label = PeerLabel { label: b"FUZZ".to_vec() };
    let mut sess = Session::from_shared_secret(shared, Some(&label));

    // Split the fuzzer input into (aad, frame) in a simple way:
    // - If we have at least 1 byte, the first byte is aad_len (capped)
    // - Next aad_len bytes are aad
    // - Remainder is treated as "nonce||ct" (what Session::open expects)
    if data.is_empty() {
        return;
    }
    let aad_len = core::cmp::min(data[0] as usize, data.len().saturating_sub(1));
    let aad = &data[1..1 + aad_len];
    let frame = &data[1 + aad_len..];

    // The goal here is "no panics" under any input.
    // We ignore the result; we only care that it never crashes or UB.
    let _ = sess.open(aad, frame);
});
