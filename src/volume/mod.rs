//! Experimental encrypted S3 volume. Publication is durable at commit, not write().
use crate::{
    crypto::{self, SecretKey, encryption, kdf, naming, objects},
    format::{
        directory::{Directory, Entry},
        header::{Algorithm, Header, NamingConfig},
        inode::{self, InodeBody, InodeContent, InodeObject},
    },
    storage::s3::{Connection, ConnectionError, PutResult},
};
use std::{
    fmt,
    fs::OpenOptions,
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
};

#[derive(Debug)]
pub enum Error {
    Other(ConnectionError),
    Conflict,
    Exists,
    Missing,
    NotDirectory,
    Invalid,
    TooLarge,
    NotEmpty,
    Permission,
    IsDirectory,
    Unsupported,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(e) => e.fmt(f),
            v => write!(f, "{v:?}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<ConnectionError> for Error {
    fn from(e: ConnectionError) -> Self {
        Self::Other(e)
    }
}
impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Self::Other(e.into())
    }
}
impl From<crate::format::header::FormatError> for Error {
    fn from(e: crate::format::header::FormatError) -> Self {
        Self::Other(e.into())
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Other(e.into())
    }
}
impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::Other(e.into())
    }
}
pub type Result<T> = std::result::Result<T, Error>;
mod lease;
mod metadata;
mod namespace;
pub use lease::Lease;
mod session;
pub mod snapshots;
pub use metadata::MetadataUpdate;
pub use session::FileSession;

pub struct Volume {
    pub fs_id: [u8; 16],
    pub root: [u8; 16],
    connection: Connection,
    prefix: String,
    master: SecretKey,
    names: NamingConfig,
    suite: Algorithm,
    pub chunk_size: usize,
    pub parallelism: usize,
}
#[derive(Clone)]
pub struct Loaded {
    pub body: InodeBody,
    pub key: Arc<SecretKey>,
    pub suite: Algorithm,
    pub etag: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Piece {
    offset: u64,
    len: u32,
    allocation: [u8; 16],
    index: u64,
}
fn pieces(body: &InodeBody) -> Vec<Piece> {
    let mut result = Vec::new();
    let mut offset = 0;
    if let InodeContent::Chunks(c) = &body.content {
        let mut holes = c.holes.iter().peekable();
        for run in &c.runs {
            for (i, &len) in run.plaintext_lengths.iter().enumerate() {
                while let Some(h) = holes.peek() {
                    if h.offset != offset {
                        break;
                    }
                    offset += h.len;
                    holes.next();
                }
                result.push(Piece {
                    offset,
                    len,
                    allocation: run.allocation_id,
                    index: run.first_chunk + i as u64,
                });
                offset += u64::from(len);
            }
        }
    }
    result
}
impl Volume {
    fn validate_policy(prefix: &str, chunk_size: usize, parallelism: usize) -> Result<()> {
        if prefix.is_empty()
            || !prefix.ends_with('/')
            || prefix.len() > 800
            || !(inode::MAX_INLINE_SIZE..=crate::format::data_chunk::MAX_CHUNK_PLAINTEXT)
                .contains(&chunk_size)
            || !(1..=32).contains(&parallelism)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub async fn format(
        connection: Connection,
        prefix: String,
        password: &[u8],
        chunk_size: usize,
        parallelism: usize,
    ) -> Result<Arc<Self>> {
        Self::format_with_metadata(
            connection,
            prefix,
            password,
            chunk_size,
            parallelism,
            crate::format::metadata::Metadata::new(0, 0, 0o755),
        )
        .await
    }
    pub async fn format_with_metadata(
        connection: Connection,
        prefix: String,
        password: &[u8],
        chunk_size: usize,
        parallelism: usize,
        metadata: crate::format::metadata::Metadata,
    ) -> Result<Arc<Self>> {
        Self::validate_policy(&prefix, chunk_size, parallelism)?;
        if connection
            .get(&format!("{prefix}header"), crate::format::header::MAX_SIZE)
            .await?
            .is_some()
        {
            return Err(Error::Exists);
        }
        let suite = encryption::algorithm(encryption::XCHACHA20_POLY1305)?;
        let root = crypto::random_array()?;
        let (header, unlocked) = objects::create_header(
            password,
            root,
            &suite,
            &kdf::argon2id::Parameters::recommended()?,
        )?;
        let volume = Arc::new(Self {
            fs_id: header.filesystem_id,
            root,
            connection,
            prefix,
            master: unlocked.master_key,
            names: unlocked.config.naming.clone(),
            suite,
            chunk_size,
            parallelism,
        });
        volume
            .create_inode(root, inode::DIRECTORY, metadata)
            .await?;
        match volume
            .connection
            .put(&format!("{}header", volume.prefix), header.encode()?, None)
            .await?
        {
            PutResult::Applied(_) => Ok(volume),
            PutResult::Conflict => Err(Error::Exists),
        }
    }
    pub async fn open(
        connection: Connection,
        prefix: String,
        password: &[u8],
        chunk_size: usize,
        parallelism: usize,
    ) -> Result<Arc<Self>> {
        Self::validate_policy(&prefix, chunk_size, parallelism)?;
        let stored = connection
            .get(&format!("{prefix}header"), crate::format::header::MAX_SIZE)
            .await?
            .ok_or(Error::Missing)?;
        let header = Header::decode(&stored.bytes)?;
        let unlocked = objects::unlock_header(&header, password, &header.keyslots[0].id)?;
        let volume = Arc::new(Self {
            fs_id: header.filesystem_id,
            root: unlocked.config.root_inode,
            connection,
            prefix,
            master: unlocked.master_key,
            names: unlocked.config.naming.clone(),
            suite: header.protected.algorithm,
            chunk_size,
            parallelism,
        });
        volume.load(volume.root).await?;
        Ok(volume)
    }
    pub fn inode_name(&self, id: &[u8; 16]) -> Result<String> {
        Ok(format!(
            "{}{}",
            self.prefix,
            naming::inode(&self.names, &self.fs_id, id)?
        ))
    }
    fn chunk_name(&self, config: &NamingConfig, piece: &Piece) -> Result<String> {
        Ok(format!(
            "{}{}",
            self.prefix,
            naming::chunk(config, &self.fs_id, &piece.allocation, piece.index)?
        ))
    }
    pub async fn inode_etag(&self, id: [u8; 16]) -> Result<String> {
        Ok(self.connection.head_etag(&self.inode_name(&id)?).await?)
    }
    pub async fn load(&self, id: [u8; 16]) -> Result<Loaded> {
        let name = self.inode_name(&id)?;
        let stored = self
            .connection
            .get(&name, inode::MAX_INODE_SIZE)
            .await?
            .ok_or(Error::Missing)?;
        let object = InodeObject::decode(&stored.bytes)?;
        let (key, body) = objects::open_inode(&self.master, &self.fs_id, &name, &id, &object)?;
        Ok(Loaded {
            body,
            key: Arc::new(key),
            suite: object.protected.algorithm,
            etag: stored.etag,
        })
    }
    async fn publish(
        &self,
        loaded: &Loaded,
        body: &InodeBody,
        expected: Option<&str>,
    ) -> Result<String> {
        // Lease holders write through Lease; ordinary callers cannot bypass it.
        if body.lease.is_some() || loaded.body.lease.is_some() {
            return Err(Error::Conflict);
        }
        self.publish_raw(loaded, body, expected).await
    }
    async fn publish_raw(
        &self,
        loaded: &Loaded,
        body: &InodeBody,
        expected: Option<&str>,
    ) -> Result<String> {
        let name = self.inode_name(&body.id)?;
        let object = objects::seal_inode(
            &self.master,
            &loaded.key,
            &self.fs_id,
            &name,
            &loaded.suite,
            body,
        )?;
        match self
            .connection
            .put(&name, object.encode()?, expected)
            .await?
        {
            PutResult::Applied(etag) => Ok(etag),
            PutResult::Conflict => Err(Error::Conflict),
        }
    }
    async fn create_inode(
        &self,
        id: [u8; 16],
        kind: u8,
        metadata: crate::format::metadata::Metadata,
    ) -> Result<Loaded> {
        let content = if kind == inode::DIRECTORY {
            Directory::default().encode()?
        } else {
            Vec::new()
        };
        self.create_inode_content(id, kind, metadata, content).await
    }
    async fn create_inode_content(
        &self,
        id: [u8; 16],
        kind: u8,
        metadata: crate::format::metadata::Metadata,
        content: Vec<u8>,
    ) -> Result<Loaded> {
        let mut loaded = Loaded {
            body: InodeBody {
                id,
                kind,
                generation: 0,
                metadata,
                lease: None,
                deleted: false,
                nlink: if kind == inode::DIRECTORY { 2 } else { 1 },

                mutations: vec![],
                content: InodeContent::Inline(content),
                extensions: vec![],
            },
            key: Arc::new(SecretKey::generate()?),
            suite: self.suite.clone(),
            etag: String::new(),
        };
        loaded.etag = self.publish(&loaded, &loaded.body, None).await?;
        Ok(loaded)
    }
    pub async fn list(&self, id: [u8; 16]) -> Result<Vec<Entry>> {
        let loaded = self.load(id).await?;
        if loaded.body.deleted {
            return Err(Error::Missing);
        }
        if loaded.body.kind != inode::DIRECTORY {
            return Err(Error::NotDirectory);
        }
        let InodeContent::Inline(bytes) = loaded.body.content else {
            return Err(Error::Invalid);
        };
        Ok(Directory::decode(&bytes)?.entries)
    }
    pub async fn update_metadata(
        &self,
        id: [u8; 16],
        update: &MetadataUpdate,
        actor: (u32, u32),
    ) -> Result<Loaded> {
        let baseline = self.load(id).await?;
        let desired = update.apply(&baseline.body.metadata, actor)?;
        for _ in 0..16 {
            let mut loaded = match self.load_writable(id).await {
                Ok(l) => l,
                Err(Error::Conflict) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            if update.is_empty() {
                return Ok(loaded);
            }
            let mut body = loaded.body.clone();
            update.apply(&body.metadata, actor)?;
            let different = update.different_fields(&desired, &body.metadata);
            if body.mutations.iter().any(|m| {
                m.generation > baseline.body.generation && m.attribute_fields & different != 0
            }) {
                return Err(Error::Conflict);
            }
            body.metadata = update.rebase(&baseline.body.metadata, &body.metadata, &desired)?;
            body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
            let generation = body.generation;
            record_mutation(
                &mut body,
                inode::Mutation {
                    generation,
                    size_changed: false,
                    attribute_fields: update.fields(),
                    ranges: vec![],
                },
            )?;
            match self.publish(&loaded, &body, Some(&loaded.etag)).await {
                Ok(etag) => {
                    loaded.body = body;
                    loaded.etag = etag;
                    return Ok(loaded);
                }
                Err(Error::Conflict) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict)
    }
    pub fn file(self: &Arc<Self>, loaded: Loaded, cache_dir: &Path) -> Result<FileSession> {
        if loaded.body.kind != inode::FILE {
            return Err(Error::IsDirectory);
        }
        std::fs::create_dir_all(cache_dir)?;
        let path = cache_dir.join(format!(
            "eedfs-{}",
            naming::inode(&self.names, &self.fs_id, &crypto::random_array()?)?
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        std::fs::remove_file(path)?; // anonymous plaintext spool, removed automatically on process exit
        let size = loaded.body.size()?;
        file.set_len(size)?;
        if let InodeContent::Inline(bytes) = &loaded.body.content {
            file.write_all_at(bytes, 0)?;
        }
        Ok(FileSession::new(
            self.clone(),
            loaded,
            file,
            size,
            cache_dir.to_owned(),
        ))
    }
}

/// Compact last-writer versions, not a bounded-age history. Old handles can
/// still merge untouched ranges after arbitrarily many unrelated commits.
fn record_mutation(body: &mut InodeBody, mut next: inode::Mutation) -> Result<()> {
    next.ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (a, b) in next.ranges {
        if let Some(last) = merged.last_mut()
            && a <= last.1
        {
            last.1 = last.1.max(b);
        } else {
            merged.push((a, b));
        }
    }
    next.ranges = merged;
    for old in &mut body.mutations {
        if next.size_changed {
            old.size_changed = false;
        }
        old.attribute_fields &= !next.attribute_fields;
        let mut remaining = Vec::new();
        for &(a, b) in &old.ranges {
            let mut cursor = a;
            let first = next.ranges.partition_point(|&(_, end)| end <= a);
            for &(x, y) in &next.ranges[first..] {
                if x >= b {
                    break;
                }
                if cursor < x {
                    remaining.push((cursor, x));
                }
                cursor = cursor.max(y).min(b);
            }
            if cursor < b {
                remaining.push((cursor, b));
            }
        }
        old.ranges = remaining;
    }
    body.mutations
        .retain(|m| !m.ranges.is_empty() || m.size_changed || m.attribute_fields != 0);
    body.mutations.push(next);
    if body.mutations.len() > inode::MAX_MUTATIONS
        || body.mutations.iter().map(|m| m.ranges.len()).sum::<usize>() > 65536
    {
        return Err(Error::TooLarge);
    }
    Ok(())
}
