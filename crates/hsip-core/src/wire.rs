//! Shared wire-level constants used across hsip crates (cli, net, session, etc.)


pub const TAG_E1: u8 = 0xE1;
pub const TAG_E2: u8 = 0xE2;
pub const TAG_D: u8 = 0xD0;


pub const AAD_CONTROL: &[u8] = b"type=CONTROL";
pub const AAD_PING: &[u8] = b"type=PING";


// Canonical label for consent sessions
pub const LABEL_CONSENT: &[u8] = b"CONSENTv1";


// Useful sizes & limits
pub const MAX_FRAME_SIZE: usize = 65535; // matches UDP max
pub const DEFAULT_CONTROL_PORT: &str = "0.0.0.0:40405";