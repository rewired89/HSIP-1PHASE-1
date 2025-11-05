//! HSIP wire prefix used to quickly reject non-HSIP packets.
//! Layout at the very start of every HSIP UDP packet:
//! [ 0..4  ] = b"HSIP"
//! [ 4..6  ] = version (`u16`, big-endian)

pub const HSIP_MAGIC: &[u8; 4] = b"HSIP";
pub const HSIP_VER: u16 = 0x0002; // match your current wire version
pub const PREFIX_LEN: usize = 6;

/// Append HSIP prefix to an outgoing packet buffer.
pub fn write_prefix(buf: &mut Vec<u8>) {
    buf.extend_from_slice(HSIP_MAGIC);
    buf.extend_from_slice(&HSIP_VER.to_be_bytes());
}

/// Check if an incoming packet starts with a valid HSIP prefix.
#[inline]
#[must_use]
pub fn check_prefix(pkt: &[u8]) -> bool {
    if pkt.len() < PREFIX_LEN {
        return false;
    }
    let ok_magic = &pkt[0..4] == HSIP_MAGIC;
    let ok_ver = u16::from_be_bytes([pkt[4], pkt[5]]) == HSIP_VER;
    ok_magic && ok_ver
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_prefix_ok() {
        let mut v = Vec::new();
        write_prefix(&mut v);
        assert!(check_prefix(&v));
        // Corrupt magic
        let mut bad = v.clone();
        bad[0] ^= 0xFF;
        assert!(!check_prefix(&bad));
        // Corrupt version
        let mut bad2 = v;
        bad2[5] ^= 0x01;
        assert!(!check_prefix(&bad2));
    }
}
