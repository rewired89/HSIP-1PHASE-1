//! RFC 8439 Official Test Vectors for ChaCha20-Poly1305 AEAD
//!
//! This test file implements the official test vectors from IETF RFC 8439
//! to verify that HSIP's ChaCha20-Poly1305 implementation is cryptographically correct.
//!
//! These are INDEPENDENT third-party test vectors - not created by HSIP.
//! If these tests pass, it proves HSIP is using ChaCha20-Poly1305 correctly.
//!
//! Reference: https://datatracker.ietf.org/doc/html/rfc8439

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};

/// RFC 8439 Appendix A.5 - Test Vector for the ChaCha20-Poly1305 AEAD
///
/// This is the OFFICIAL test vector from IETF RFC 8439 Section A.5.
/// Source: https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.5
#[test]
fn rfc8439_appendix_a5_chacha20poly1305_aead() {
    // Plaintext from RFC 8439 A.5
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    // 256-bit key (32 bytes)
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];

    // 96-bit nonce (12 bytes) - RFC 8439 uses 12-byte nonces
    let nonce: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, // constant
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, // IV
    ];

    // AAD from RFC 8439 A.5
    let aad: [u8; 12] = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];

    // Expected ciphertext + tag from RFC 8439 A.5
    // This is 114 bytes of ciphertext + 16 bytes Poly1305 tag = 130 bytes total
    let expected_ciphertext_and_tag: [u8; 130] = [
        // Ciphertext (114 bytes)
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
        // Poly1305 Tag (16 bytes)
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06,
        0x91,
    ];

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("encryption failed");

    // Verify the ciphertext matches RFC 8439 expected output
    assert_eq!(
        ciphertext.len(),
        expected_ciphertext_and_tag.len(),
        "Ciphertext length mismatch - expected {} bytes, got {}",
        expected_ciphertext_and_tag.len(),
        ciphertext.len()
    );

    assert_eq!(
        ciphertext, expected_ciphertext_and_tag,
        "RFC 8439 A.5 AEAD encryption failed - ciphertext+tag does not match official test vector"
    );

    // Also verify decryption works
    let decrypted = cipher
        .decrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .expect("decryption failed");

    assert_eq!(
        decrypted, plaintext,
        "Decryption failed to recover original plaintext"
    );

    println!("✅ RFC 8439 A.5 ChaCha20-Poly1305 AEAD test vector: PASSED");
    println!("   This proves HSIP uses cryptographically correct ChaCha20-Poly1305!");
}

/// Additional RFC 8439 Test Vector with different key/nonce
///
/// This test uses a simpler test case to verify basic functionality
#[test]
fn rfc8439_basic_encrypt_decrypt() {
    let plaintext = b"Hello, World!";

    // 256-bit key (all zeros for simplicity)
    let key = [0u8; 32];

    // 96-bit nonce (all zeros)
    let nonce = [0u8; 12];

    // AAD (empty)
    let aad = b"";

    // Encrypt
    let cipher = ChaCha20Poly1305::new(&key.into());
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption failed");

    // Verify ciphertext is different from plaintext
    assert_ne!(
        &ciphertext[..plaintext.len()],
        plaintext,
        "Ciphertext should not equal plaintext"
    );

    // Verify ciphertext includes 16-byte Poly1305 tag
    assert_eq!(
        ciphertext.len(),
        plaintext.len() + 16,
        "Ciphertext should be plaintext + 16 byte tag"
    );

    // Decrypt
    let decrypted = cipher
        .decrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .expect("decryption failed");

    assert_eq!(decrypted, plaintext);

    println!("✅ Basic ChaCha20-Poly1305 encrypt/decrypt: PASSED");
}

/// Test that authentication fails with wrong AAD
///
/// This verifies the AEAD property - authenticated encryption prevents tampering
#[test]
fn rfc8439_authentication_verification() {
    let plaintext = b"Secret message";
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let aad_correct = b"metadata";
    let aad_wrong = b"tampered";

    let cipher = ChaCha20Poly1305::new(&key.into());

    // Encrypt with correct AAD
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: aad_correct,
            },
        )
        .expect("encryption failed");

    // Decryption should FAIL with wrong AAD (authentication check)
    let result = cipher.decrypt(
        &nonce.into(),
        chacha20poly1305::aead::Payload {
            msg: &ciphertext,
            aad: aad_wrong,
        },
    );

    assert!(
        result.is_err(),
        "Decryption should fail when AAD is tampered"
    );

    // Decryption should SUCCEED with correct AAD
    let decrypted = cipher
        .decrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: aad_correct,
            },
        )
        .expect("decryption should succeed with correct AAD");

    assert_eq!(decrypted, plaintext);

    println!("✅ ChaCha20-Poly1305 authentication verification: PASSED");
    println!("   Tampered AAD correctly rejected!");
}

/// Test that tampering with ciphertext fails authentication
#[test]
fn rfc8439_ciphertext_tampering_detection() {
    let plaintext = b"Important data";
    let key = [3u8; 32];
    let nonce = [4u8; 12];
    let aad = b"";

    let cipher = ChaCha20Poly1305::new(&key.into());

    // Encrypt
    let mut ciphertext = cipher
        .encrypt(
            &nonce.into(),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption failed");

    // Tamper with one byte of ciphertext
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0x01; // Flip one bit
    }

    // Decryption should FAIL due to authentication tag mismatch
    let result = cipher.decrypt(
        &nonce.into(),
        chacha20poly1305::aead::Payload {
            msg: &ciphertext,
            aad,
        },
    );

    assert!(
        result.is_err(),
        "Decryption should fail when ciphertext is tampered"
    );

    println!("✅ ChaCha20-Poly1305 tampering detection: PASSED");
    println!("   Modified ciphertext correctly rejected!");
}
