//! Windows utility functions.

/// Convert Rust string to wide string (UTF-16) for Windows APIs.
pub fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convert wide string (UTF-16) from Windows APIs to Rust string.
pub fn from_wide_string(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_conversion() {
        let original = "Hello, HSIP! 🔒";
        let wide = to_wide_string(original);
        let back = from_wide_string(&wide);

        assert_eq!(back, original);
    }
}
