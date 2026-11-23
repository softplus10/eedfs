use hmac::{Hmac, Mac};
use sha2::Sha256;
/// Inputs have domain-specific fixed lengths; no ambiguous concatenated strings.
pub fn digest(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts all key lengths");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
pub(super) fn name(key: &[u8; 32], parts: &[&[u8]]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest(key, parts) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}
