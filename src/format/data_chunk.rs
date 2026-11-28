//! Compact chunks have no independent algorithm descriptor or frame.
//! The authenticated inode supplies the AEAD suite and expected plaintext length.
use super::{common::object_aad, header::Algorithm};
use crate::crypto::{Error, Result, encryption};

pub const VERSION: u16 = 2;
/// Decoder resource limit, not a persisted per-file chunk sizing policy.
pub const MAX_CHUNK_PLAINTEXT: usize = 64 * 1024 * 1024;

/// Wire representation: nonce || ciphertext || 16-byte authentication tag.
/// Parse is structural only; call crypto::objects::open_chunk to authenticate.
pub struct DataChunkObject<'a> {
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
}
impl<'a> DataChunkObject<'a> {
    pub fn decode(bytes: &'a [u8], algorithm: &Algorithm, expected_len: u32) -> Result<Self> {
        let n = encryption::nonce_size(algorithm)?;
        if expected_len == 0
            || expected_len as usize > MAX_CHUNK_PLAINTEXT
            || bytes.len() != n + expected_len as usize + encryption::TAG_SIZE
        {
            return Err(Error::Invalid("chunk length"));
        }
        Ok(Self {
            nonce: &bytes[..n],
            ciphertext: &bytes[n..],
        })
    }
}
pub fn aad(
    filesystem_id: &[u8; 16],
    object_key: &str,
    algorithm: &Algorithm,
    nonce: &[u8],
    expected_len: u32,
) -> Result<Vec<u8>> {
    Ok(object_aad(
        b"CoCryptFS/data-chunk\0",
        VERSION,
        filesystem_id,
        object_key,
        &(algorithm, nonce, expected_len),
    )?)
}
