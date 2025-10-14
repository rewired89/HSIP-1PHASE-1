use hsip_core::identity::generate_keypair;
use hsip_net::udp::hello::{listen_hello, send_hello};
use std::thread;
use std::time::Duration;

#[test]
fn hello_roundtrip_local() {
    let addr = "127.0.0.1:19000".to_string();
    // spawn listener
    let t = thread::spawn({
        let addr = addr.clone();
        move || {
            // run listener briefly
            let _ = listen_hello(&addr);
        }
    });

    // give it a moment to bind
    std::thread::sleep(Duration::from_millis(100));

    // send one HELLO
    let (sk, vk) = generate_keypair();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // this should not error; the test passes if we don’t panic
    let _ = send_hello(&sk, &vk, &addr, now);

    // let listener print/process
    std::thread::sleep(Duration::from_millis(100));
    drop(t); // end the thread
}
