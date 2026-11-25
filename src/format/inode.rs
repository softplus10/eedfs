//! Inode envelope and minimal inline/chunk-run body. No filesystem operations.

use super::{
    codec,
    common::{MAX_METADATA_SIZE, object_aad, validate_extensions},
    header::{Extension, FormatError, MAX_EXTENSIONS, NamingConfig, SealedRegion},
};
use codec::bounded;
use serde::{Deserialize, Serialize};
type Result<T> = std::result::Result<T, FormatError>;
use super::data_chunk::MAX_CHUNK_PLAINTEXT;
use codec::{bounded_bytes, serialize_bytes};
use std::fmt;

pub const VERSION: u16 = 6;
pub const FILE: u8 = 1;
pub const DIRECTORY: u8 = 2;
pub const SYMLINK: u8 = 3;
pub const MAX_MUTATIONS: usize = 4096;
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
/// Includes numeric ownership, permissions and basic timestamps; no extent tree.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeBody {
    pub id: [u8; 16],
    pub kind: u8,
    pub generation: u64,
    pub content: InodeContent,
    pub metadata: super::metadata::Metadata,
    pub lease: Option<DirectoryLease>,
    pub deleted: bool,
    pub nlink: u32,

    #[serde(deserialize_with = "bounded::<_, _, MAX_MUTATIONS>")]
    pub mutations: Vec<Mutation>,
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
            .field("metadata", &self.metadata)
            .field("lease", &self.lease)
            .field("extension_count", &self.extensions.len())
            .finish()
    }
}

/// An inode-local namespace lease. The enclosing object's ETag fences each write.
/// No operation identifier, transaction log, or automatic recovery is persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryLease {
    pub owner: [u8; 16],
    pub expires_at: super::metadata::Timestamp,
}

/// Recent committed byte mutations detect overlap even for equal-byte/ABA writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mutation {
    pub generation: u64,
    pub size_changed: bool,
    pub attribute_fields: u8,
    #[serde(deserialize_with = "bounded::<_, _, 65536>")]
    pub ranges: Vec<(u64, u64)>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hole {
    pub offset: u64,
    pub len: u64,
}

/// Persisted enum tags are fixed by schema v6: Inline=0, Chunks=1.
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
    Chunks(ChunkedContent),
}
impl fmt::Debug for InodeContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(bytes) => f.debug_struct("Inline").field("len", &bytes.len()).finish(),
            Self::Chunks(chunks) => f
                .debug_struct("Chunks")
                .field("run_count", &chunks.runs.len())
                .finish(),
        }
    }
}

/// Per-file settings are encrypted inside the inode. Encryption settings are
/// shared with the inode envelope and are deliberately not repeated here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkedContent {
    pub naming: NamingConfig,
    #[serde(deserialize_with = "bounded::<_, _, MAX_CHUNK_REFERENCES>")]
    pub runs: Vec<ChunkRun>,
    #[serde(deserialize_with = "bounded::<_, _, MAX_CHUNK_REFERENCES>")]
    pub holes: Vec<Hole>,
}

/// Fresh allocation ID per newly written run. COW edits split/reuse old runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRun {
    pub allocation_id: [u8; 16],
    pub first_chunk: u64,
    #[serde(deserialize_with = "bounded::<_, _, MAX_CHUNK_REFERENCES>")]
    pub plaintext_lengths: Vec<u32>,
}
impl ChunkedContent {
    pub fn size(&self) -> Result<u64> {
        self.naming.algorithm.validate()?;
        if (self.runs.is_empty() && self.holes.is_empty())
            || self.holes.len() > MAX_CHUNK_REFERENCES
            || self.runs.len() > MAX_CHUNK_REFERENCES
        {
            return Err(FormatError::Invalid("chunk configuration"));
        }
        let mut count = 0usize;
        let mut size = 0u64;
        for run in &self.runs {
            if run.plaintext_lengths.is_empty() {
                return Err(FormatError::Invalid("empty chunk run"));
            }
            run.first_chunk
                .checked_add(run.plaintext_lengths.len() as u64 - 1)
                .ok_or(FormatError::Invalid("chunk index overflow"))?;
            count = count
                .checked_add(run.plaintext_lengths.len())
                .ok_or(FormatError::TooLarge)?;
            if count > MAX_CHUNK_REFERENCES {
                return Err(FormatError::TooLarge);
            }
            for &len in &run.plaintext_lengths {
                if len == 0 || len as usize > MAX_CHUNK_PLAINTEXT {
                    return Err(FormatError::Invalid("chunk plaintext length"));
                }
                size = size
                    .checked_add(u64::from(len))
                    .ok_or(FormatError::TooLarge)?;
            }
        }
        let mut cursor = 0u64;
        let mut hole_index = 0;
        for len in self.runs.iter().flat_map(|r| &r.plaintext_lengths) {
            while let Some(h) = self.holes.get(hole_index) {
                if h.len == 0 || h.offset < cursor {
                    return Err(FormatError::Invalid("hole layout"));
                }
                if h.offset != cursor {
                    break;
                }
                cursor = cursor.checked_add(h.len).ok_or(FormatError::TooLarge)?;
                hole_index += 1;
            }
            cursor = cursor
                .checked_add(u64::from(*len))
                .ok_or(FormatError::TooLarge)?;
        }
        while let Some(h) = self.holes.get(hole_index) {
            if h.len == 0 || h.offset != cursor {
                return Err(FormatError::Invalid("hole layout"));
            }
            cursor = cursor.checked_add(h.len).ok_or(FormatError::TooLarge)?;
            hole_index += 1;
        }
        if cursor > i64::MAX as u64 {
            return Err(FormatError::TooLarge);
        }
        Ok(cursor)
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
            Self::Chunks(chunks) => chunks.size(),
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
        if !matches!(self.kind, FILE | DIRECTORY | SYMLINK) {
            return Err(FormatError::Invalid("inode kind"));
        }
        if let Some(lease) = &self.lease {
            if self.kind != DIRECTORY || lease.owner == [0; 16] {
                return Err(FormatError::Invalid("directory lease"));
            }
            lease.expires_at.to_system_time()?;
        }
        if self.deleted && self.kind != DIRECTORY {
            return Err(FormatError::Invalid("deleted directory"));
        }
        if self.kind == SYMLINK
            && !matches!(&self.content, InodeContent::Inline(b) if !b.is_empty() && !b.contains(&0) && b.len() <= 4096)
        {
            return Err(FormatError::Invalid("symlink target"));
        }
        if self.mutations.len() > MAX_MUTATIONS {
            return Err(FormatError::TooLarge);
        }
        let mut previous = 0;
        for m in &self.mutations {
            if m.generation <= previous
                || m.generation > self.generation
                || m.attribute_fields & !31 != 0
                || m.ranges.len() > 65536
                || m.ranges.iter().any(|(a, b)| a >= b || *b > i64::MAX as u64)
            {
                return Err(FormatError::Invalid("mutation history"));
            }
            previous = m.generation;
        }
        let mut ranges = Vec::new();
        let mut fields = 0u8;
        let mut size_record = false;
        for m in &self.mutations {
            if fields & m.attribute_fields != 0 || (size_record && m.size_changed) {
                return Err(FormatError::Invalid("duplicate mutation fields"));
            }
            fields |= m.attribute_fields;
            size_record |= m.size_changed;
            ranges.extend(m.ranges.iter().copied());
            if ranges.len() > 65536 {
                return Err(FormatError::TooLarge);
            }
        }
        ranges.sort_unstable();
        if ranges.windows(2).any(|p| p[0].1 > p[1].0) {
            return Err(FormatError::Invalid("overlapping mutation ranges"));
        }
        self.content.size()?;
        self.metadata.validate()?;
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
