use crate::crypto::SecretKey;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit};
pub(super) fn cipher(key: &SecretKey) -> Aes256GcmSiv {
    Aes256GcmSiv::new((&key.0).into())
}
