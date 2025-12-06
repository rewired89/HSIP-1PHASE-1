//! iOS FFI bindings for HSIP keyboard.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use crate::{crypto, message::{HSIPMessage, MessageFormat}};

/// Initialize HSIP for iOS.
#[no_mangle]
pub extern "C" fn hsip_ios_init() -> bool {
    // Initialize logging for iOS (if needed)
    true
}

/// Encrypt a message.
///
/// # Arguments
/// * `plaintext` - UTF-8 C string
/// * `session_key` - 32-byte session key
/// * `peer_id` - 32-byte peer ID
///
/// # Returns
/// Formatted HSIP message string (caller must free with hsip_ios_free_string)
#[no_mangle]
pub extern "C" fn hsip_ios_encrypt(
    plaintext: *const c_char,
    session_key: *const u8,
    peer_id: *const u8,
) -> *mut c_char {
    if plaintext.is_null() || session_key.is_null() || peer_id.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        // Convert C string to Rust string
        let c_str = CStr::from_ptr(plaintext);
        let plaintext_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        // Convert session key
        let session_key_slice = std::slice::from_raw_parts(session_key, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(session_key_slice);

        // Convert peer ID
        let peer_id_slice = std::slice::from_raw_parts(peer_id, 32);
        let mut pid = [0u8; 32];
        pid.copy_from_slice(peer_id_slice);

        // Encrypt
        let message = match crypto::encrypt_message(plaintext_str, &key, &pid) {
            Ok(msg) => msg,
            Err(_) => return std::ptr::null_mut(),
        };

        // Format as compact (same as Android)
        let formatted = message.format(MessageFormat::Compact, None);

        // Return as C string
        match CString::new(formatted) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Decrypt a message.
///
/// # Arguments
/// * `encrypted` - Formatted HSIP message string (e.g., "🔒abc...")
/// * `session_key` - 32-byte session key
///
/// # Returns
/// Plaintext UTF-8 C string (caller must free), or null if decryption fails
#[no_mangle]
pub extern "C" fn hsip_ios_decrypt(
    encrypted: *const c_char,
    session_key: *const u8,
) -> *mut c_char {
    if encrypted.is_null() || session_key.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        // Convert C string to Rust string
        let c_str = CStr::from_ptr(encrypted);
        let encrypted_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        // Parse HSIP message
        let message = match HSIPMessage::parse(encrypted_str) {
            Ok(msg) => msg,
            Err(_) => return std::ptr::null_mut(),
        };

        // Convert session key
        let session_key_slice = std::slice::from_raw_parts(session_key, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(session_key_slice);

        // Decrypt
        let plaintext = match crypto::decrypt_message(&message, &key) {
            Ok(text) => text,
            Err(_) => return std::ptr::null_mut(),
        };

        // Return as C string
        match CString::new(plaintext) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Check if text contains an HSIP message.
///
/// # Arguments
/// * `text` - UTF-8 C string to check
///
/// # Returns
/// true if HSIP message detected (🔒 or [HSIP] found)
#[no_mangle]
pub extern "C" fn hsip_ios_contains_message(text: *const c_char) -> bool {
    if text.is_null() {
        return false;
    }

    unsafe {
        let c_str = CStr::from_ptr(text);
        if let Ok(text_str) = c_str.to_str() {
            HSIPMessage::contains_hsip_message(text_str)
        } else {
            false
        }
    }
}

/// Free a C string allocated by Rust.
///
/// # Safety
/// Must only be called on strings returned by hsip_ios_encrypt or hsip_ios_decrypt.
#[no_mangle]
pub extern "C" fn hsip_ios_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_ios_encrypt_decrypt() {
        let plaintext = CString::new("Hello from iOS!").unwrap();
        let session_key = [42u8; 32];
        let peer_id = [1u8; 32];

        // Encrypt
        let encrypted = hsip_ios_encrypt(
            plaintext.as_ptr(),
            session_key.as_ptr(),
            peer_id.as_ptr(),
        );

        assert!(!encrypted.is_null());

        let encrypted_str = unsafe { CStr::from_ptr(encrypted).to_str().unwrap() };
        println!("Encrypted: {}", encrypted_str);

        // Should start with 🔒
        assert!(encrypted_str.starts_with("🔒"));

        // Decrypt
        let decrypted = hsip_ios_decrypt(encrypted, session_key.as_ptr());
        assert!(!decrypted.is_null());

        let decrypted_str = unsafe { CStr::from_ptr(decrypted).to_str().unwrap() };
        assert_eq!(decrypted_str, "Hello from iOS!");

        // Cleanup
        hsip_ios_free_string(encrypted);
        hsip_ios_free_string(decrypted);
    }

    #[test]
    fn test_ios_contains_message() {
        let normal_text = CString::new("Normal message").unwrap();
        assert!(!hsip_ios_contains_message(normal_text.as_ptr()));

        let hsip_text = CString::new("🔒abc123").unwrap();
        assert!(hsip_ios_contains_message(hsip_text.as_ptr()));
    }
}
