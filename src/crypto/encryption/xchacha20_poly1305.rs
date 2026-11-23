use crate::crypto::SecretKey;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
pub(super) fn cipher(key: &SecretKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new((&key.0).into())
}
