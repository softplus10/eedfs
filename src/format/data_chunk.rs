//! Data-chunk envelope and authentication context. No encryption or S3 operations.

use super::{
    codec,
    common::{MAX_METADATA_SIZE, object_aad, validate_extensions},
    header::{Extension, FormatError, MAX_EXTENSIONS, SealedRegion},
};
use codec::bounded;
use serde::{Deserialize, Serialize};
type Result<T> = std::result::Result<T, FormatError>;

pub const VERSION: u16 = 1;
pub const MAX_CHUNK_PLAINTEXT: usize = 64 * 1024 * 1024;
pub const MAX_CHUNK_CIPHERTEXT: usize = MAX_CHUNK_PLAINTEXT + 64;
pub const MAX_CHUNK_SIZE: usize = MAX_CHUNK_PLAINTEXT + MAX_METADATA_SIZE;
const CHUNK_MAGIC: &[u8; 8] = b"EEDFSCHK";

/// Immutable chunk envelope. The tag is part of protected.ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataChunkObject {
    pub protected: SealedRegion<MAX_CHUNK_CIPHERTEXT>,
    #[serde(deserialize_with = "bounded::<_, _, MAX_EXTENSIONS>")]
    pub extensions: Vec<Extension>,
}

impl DataChunkObject {
    fn validate(&self) -> Result<()> {
        self.protected.validate()?;
        validate_extensions(&self.extensions)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        codec::frame(CHUNK_MAGIC, VERSION, MAX_CHUNK_SIZE, self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self = codec::unframe(CHUNK_MAGIC, VERSION, MAX_CHUNK_SIZE, bytes)?;
        value.validate()?;
        Ok(value)
    }
    /// Stable across file-offset changes: bind immutable object identity, not logical offset.
    pub fn aad(&self, filesystem_id: &[u8; 16], object_key: &str) -> Result<Vec<u8>> {
        self.protected.validate_descriptor()?;
        validate_extensions(&self.extensions)?;
        object_aad(
            b"EEDFS/data-chunk\0",
            VERSION,
            filesystem_id,
            object_key,
            &(
                &self.protected.algorithm,
                &self.protected.nonce,
                &self.extensions,
            ),
        )
    }
}
