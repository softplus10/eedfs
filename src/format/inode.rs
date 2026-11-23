//! Inode envelope and minimal inline/chunk-reference body. No filesystem operations.

use super::{
    codec,
    common::{MAX_METADATA_SIZE, object_aad, validate_extensions},
    header::{Extension, FormatError, MAX_EXTENSIONS, SealedRegion},
};
use codec::bounded;
use serde::{Deserialize, Serialize};
type Result<T> = std::result::Result<T, FormatError>;
use super::data_chunk::{DataChunkObject, MAX_CHUNK_PLAINTEXT};
use codec::{bounded_bytes, object_key, serialize_bytes};
use std::fmt;

pub const VERSION: u16 = 1;
pub const FILE: u8 = 1;
pub const DIRECTORY: u8 = 2;
pub const MAX_INLINE_SIZE: usize = 64 * 1024;
pub const MAX_CHUNK_REFERENCES: usize = 4096;
pub const MAX_INODE_SIZE: usize = MAX_METADATA_SIZE;
const INODE_MAGIC: &[u8; 8] = b"EEDFSINO";
const BODY_MAGIC: &[u8; 8] = b"EEDFSINB";

/// Public S3 inode envelope: a wrapped per-inode key and a separately sealed body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeObject {
    pub wrapped_inode_key: SealedRegion,
    pub protected: SealedRegion,
    #[serde(deserialize_with = "bounded::<_, _, MAX_EXTENSIONS>")]
    pub extensions: Vec<Extension>,
}

/// Minimal plaintext inode. Its contents must be encrypted before upload.
/// No extent tree, directory-entry schema, POSIX attributes or separate DEK yet.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeBody {
    pub id: [u8; 16],
    pub kind: u8,
    pub generation: u64,
    pub content: InodeContent,
    #[serde(deserialize_with = "bounded::<_, _, MAX_EXTENSIONS>")]
    pub extensions: Vec<Extension>,
}
impl fmt::Debug for InodeBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InodeBody")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("generation", &self.generation)
            .field("content", &self.content)
            .field("extension_count", &self.extensions.len())
            .finish()
    }
}

/// Persisted enum tags are fixed by schema v1: Inline=0, Chunks=1.
/// Reordering/inserting variants is a format change, not an implementation detail.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InodeContent {
    Inline(
        #[serde(
            serialize_with = "serialize_bytes",
            deserialize_with = "bounded_bytes::<_, MAX_INLINE_SIZE>"
        )]
        Vec<u8>,
    ),
    Chunks(
        #[serde(deserialize_with = "bounded::<_, _, MAX_CHUNK_REFERENCES>")] Vec<ChunkReference>,
    ),
}
impl fmt::Debug for InodeContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(bytes) => f.debug_struct("Inline").field("len", &bytes.len()).finish(),
            Self::Chunks(chunks) => f
                .debug_struct("Chunks")
                .field("count", &chunks.len())
                .finish(),
        }
    }
}

/// References are concatenated in list order. Object names are explicit so a
/// recipient does not need the filesystem-wide secret naming key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkReference {
    #[serde(deserialize_with = "object_key")]
    pub object_key: String,
    pub plaintext_len: u64,
}
impl ChunkReference {
    fn validate(&self) -> Result<()> {
        codec::validate_object_key(&self.object_key)?;
        if self.plaintext_len == 0 || self.plaintext_len > MAX_CHUNK_PLAINTEXT as u64 {
            return Err(FormatError::Invalid("chunk plaintext length"));
        }
        Ok(())
    }
    /// Build the chunk's authentication context using this reference's exact S3 key.
    pub fn aad(&self, filesystem_id: &[u8; 16], chunk: &DataChunkObject) -> Result<Vec<u8>> {
        self.validate()?;
        chunk.aad(filesystem_id, &self.object_key)
    }
    /// Check after AEAD verification and decryption of the referenced chunk.
    pub fn validate_plaintext(&self, plaintext: &[u8]) -> Result<()> {
        self.validate()?;
        if plaintext.len() as u64 != self.plaintext_len {
            return Err(FormatError::Invalid("chunk plaintext length mismatch"));
        }
        Ok(())
    }
}
impl InodeContent {
    pub fn size(&self) -> Result<u64> {
        match self {
            Self::Inline(bytes) => {
                if bytes.len() > MAX_INLINE_SIZE {
                    return Err(FormatError::TooLarge);
                }
                Ok(bytes.len() as u64)
            }
            Self::Chunks(chunks) => {
                if chunks.is_empty() || chunks.len() > MAX_CHUNK_REFERENCES {
                    return Err(FormatError::Invalid("chunk reference count"));
                }
                chunks.iter().try_fold(0_u64, |size, chunk| {
                    chunk.validate()?;
                    size.checked_add(chunk.plaintext_len)
                        .ok_or(FormatError::TooLarge)
                })
            }
        }
    }
}

impl InodeObject {
    fn validate(&self) -> Result<()> {
        self.wrapped_inode_key.validate()?;
        self.protected.validate()?;
        validate_extensions(&self.extensions)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        codec::frame(INODE_MAGIC, VERSION, MAX_INODE_SIZE, self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self = codec::unframe(INODE_MAGIC, VERSION, MAX_INODE_SIZE, bytes)?;
        value.validate()?;
        Ok(value)
    }
    /// Bind to the caller's trusted filesystem and actual S3 key, including for root inodes.
    pub fn wrapping_aad(&self, filesystem_id: &[u8; 16], object_key: &str) -> Result<Vec<u8>> {
        self.wrapped_inode_key.validate_descriptor()?;
        validate_extensions(&self.extensions)?;
        object_aad(
            b"EEDFS/inode-key\0",
            VERSION,
            filesystem_id,
            object_key,
            &(
                &self.wrapped_inode_key.algorithm,
                &self.wrapped_inode_key.nonce,
                &self.extensions,
            ),
        )
    }
    /// Wrapped-key ciphertext is bound to the body; the body's own ciphertext is excluded.
    pub fn protected_aad(&self, filesystem_id: &[u8; 16], object_key: &str) -> Result<Vec<u8>> {
        self.wrapped_inode_key.validate()?;
        self.protected.validate_descriptor()?;
        validate_extensions(&self.extensions)?;
        object_aad(
            b"EEDFS/inode-body\0",
            VERSION,
            filesystem_id,
            object_key,
            &(
                &self.wrapped_inode_key,
                &self.protected.algorithm,
                &self.protected.nonce,
                &self.extensions,
            ),
        )
    }
}
impl InodeBody {
    fn validate(&self) -> Result<()> {
        if self.kind != FILE && self.kind != DIRECTORY {
            return Err(FormatError::Invalid("inode kind"));
        }
        self.content.size()?;
        validate_extensions(&self.extensions)
    }
    pub fn size(&self) -> Result<u64> {
        self.content.size()
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        codec::frame(BODY_MAGIC, VERSION, MAX_INODE_SIZE, self)
    }
    /// Parse only after authenticating/decrypting the inode's protected region.
    pub fn decode(plaintext: &[u8]) -> Result<Self> {
        let value: Self = codec::unframe(BODY_MAGIC, VERSION, MAX_INODE_SIZE, plaintext)?;
        value.validate()?;
        Ok(value)
    }
}
