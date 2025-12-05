//! JNI bridge for Android integration.

#[cfg(target_os = "android")]
use jni::JNIEnv;

#[cfg(target_os = "android")]
use jni::objects::{JClass, JString, JByteArray};

#[cfg(target_os = "android")]
use jni::sys::{jbyteArray, jstring};

use crate::{crypto, message::{HSIPMessage, MessageFormat}};

/// Initialize the HSIP keyboard library.
///
/// Java signature: `public static native boolean initialize();`
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_io_hsip_keyboard_HSIPEngine_nativeInitialize(
    _env: JNIEnv,
    _class: JClass,
) -> bool {
    // Initialize Android logger
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("HSIP-Keyboard"),
    );

    log::info!("HSIP Keyboard initialized");
    true
}

/// Encrypt a plaintext message.
///
/// Java signature:
/// `public static native byte[] nativeEncrypt(String plaintext, byte[] sessionKey, byte[] peerID);`
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_io_hsip_keyboard_HSIPEngine_nativeEncrypt(
    mut env: JNIEnv,
    _class: JClass,
    plaintext: JString,
    session_key: JByteArray,
    peer_id: JByteArray,
) -> jbyteArray {
    // Convert JString to Rust string
    let plaintext_str: String = match env.get_string(&plaintext) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("Failed to convert plaintext: {}", e);
            return JByteArray::default().into_raw();
        }
    };

    // Convert session key
    let session_key_bytes = match env.convert_byte_array(&session_key) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to convert session key: {}", e);
            return JByteArray::default().into_raw();
        }
    };

    if session_key_bytes.len() != 32 {
        log::error!("Invalid session key length: {}", session_key_bytes.len());
        return JByteArray::default().into_raw();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&session_key_bytes);

    // Convert peer ID
    let peer_id_bytes = match env.convert_byte_array(&peer_id) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to convert peer ID: {}", e);
            return JByteArray::default().into_raw();
        }
    };

    if peer_id_bytes.len() != 32 {
        log::error!("Invalid peer ID length: {}", peer_id_bytes.len());
        return JByteArray::default().into_raw();
    }

    let mut pid = [0u8; 32];
    pid.copy_from_slice(&peer_id_bytes);

    // Encrypt
    let message = match crypto::encrypt_message(&plaintext_str, &key, &pid) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Encryption failed: {}", e);
            return JByteArray::default().into_raw();
        }
    };

    // Serialize to bytes
    let bytes = message.to_bytes();

    // Convert to Java byte array
    match env.byte_array_from_slice(&bytes) {
        Ok(array) => array.into_raw(),
        Err(e) => {
            log::error!("Failed to create byte array: {}", e);
            JByteArray::default().into_raw()
        }
    }
}

/// Decrypt an HSIP message.
///
/// Java signature:
/// `public static native String nativeDecrypt(byte[] encrypted, byte[] sessionKey);`
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_io_hsip_keyboard_HSIPEngine_nativeDecrypt(
    mut env: JNIEnv,
    _class: JClass,
    encrypted: JByteArray,
    session_key: JByteArray,
) -> jstring {
    // Convert encrypted bytes
    let encrypted_bytes = match env.convert_byte_array(&encrypted) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to convert encrypted bytes: {}", e);
            return JString::default().into_raw();
        }
    };

    // Parse HSIP message
    let message = match HSIPMessage::from_bytes(&encrypted_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Failed to parse HSIP message: {}", e);
            return JString::default().into_raw();
        }
    };

    // Convert session key
    let session_key_bytes = match env.convert_byte_array(&session_key) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to convert session key: {}", e);
            return JString::default().into_raw();
        }
    };

    if session_key_bytes.len() != 32 {
        log::error!("Invalid session key length: {}", session_key_bytes.len());
        return JString::default().into_raw();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&session_key_bytes);

    // Decrypt
    let plaintext = match crypto::decrypt_message(&message, &key) {
        Ok(text) => text,
        Err(e) => {
            log::error!("Decryption failed: {}", e);
            return JString::default().into_raw();
        }
    };

    // Convert to Java string
    match env.new_string(&plaintext) {
        Ok(jstr) => jstr.into_raw(),
        Err(e) => {
            log::error!("Failed to create Java string: {}", e);
            JString::default().into_raw()
        }
    }
}

/// Format an encrypted message for display.
///
/// Java signature:
/// `public static native String nativeFormatMessage(byte[] encrypted, int format, String messageId);`
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_io_hsip_keyboard_HSIPEngine_nativeFormatMessage(
    mut env: JNIEnv,
    _class: JClass,
    encrypted: JByteArray,
    format: i32,
    message_id: JString,
) -> jstring {
    // Convert encrypted bytes
    let encrypted_bytes = match env.convert_byte_array(&encrypted) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to convert encrypted bytes: {}", e);
            return JString::default().into_raw();
        }
    };

    // Parse HSIP message
    let message = match HSIPMessage::from_bytes(&encrypted_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Failed to parse HSIP message: {}", e);
            return JString::default().into_raw();
        }
    };

    // Convert format
    let msg_format = match format {
        0 => MessageFormat::Compact,
        1 => MessageFormat::Verbose,
        2 => MessageFormat::Stealth,
        _ => MessageFormat::Compact,
    };

    // Convert message ID (optional)
    let msg_id = if !message_id.is_null() {
        match env.get_string(&message_id) {
            Ok(s) => Some(s.into()),
            Err(_) => None,
        }
    } else {
        None
    };

    // Format message
    let formatted = message.format(msg_format, msg_id.as_deref());

    // Convert to Java string
    match env.new_string(&formatted) {
        Ok(jstr) => jstr.into_raw(),
        Err(e) => {
            log::error!("Failed to create Java string: {}", e);
            JString::default().into_raw()
        }
    }
}

/// Parse an HSIP message from text.
///
/// Java signature:
/// `public static native byte[] nativeParseMessage(String text);`
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_io_hsip_keyboard_HSIPEngine_nativeParseMessage(
    mut env: JNIEnv,
    _class: JClass,
    text: JString,
) -> jbyteArray {
    // Convert text
    let text_str: String = match env.get_string(&text) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("Failed to convert text: {}", e);
            return JByteArray::default().into_raw();
        }
    };

    // Parse message
    let message = match HSIPMessage::parse(&text_str) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Failed to parse message: {}", e);
            return JByteArray::default().into_raw();
        }
    };

    // Serialize to bytes
    let bytes = message.to_bytes();

    // Convert to Java byte array
    match env.byte_array_from_slice(&bytes) {
        Ok(array) => array.into_raw(),
        Err(e) => {
            log::error!("Failed to create byte array: {}", e);
            JByteArray::default().into_raw()
        }
    }
}

/// Check if text contains an HSIP message.
///
/// Java signature:
/// `public static native boolean nativeContainsHSIPMessage(String text);`
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_io_hsip_keyboard_HSIPEngine_nativeContainsHSIPMessage(
    mut env: JNIEnv,
    _class: JClass,
    text: JString,
) -> bool {
    // Convert text
    let text_str: String = match env.get_string(&text) {
        Ok(s) => s.into(),
        Err(_) => return false,
    };

    // Check for HSIP message
    HSIPMessage::contains_hsip_message(&text_str)
}
