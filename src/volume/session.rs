//! Per-open-file write generations and bounded immutable-chunk upload pipeline.
use super::{Error, Loaded, Piece, Result, Volume, pieces};
use crate::{
    crypto::{self, naming, objects},
    format::{
        header::NamingConfig,
        inode::{self, ChunkRun, ChunkedContent, InodeContent},
    },
    storage::s3::PutResult,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::unix::fs::FileExt,
    sync::Arc,
};
use tokio::task::{JoinError, JoinSet};
use zeroize::Zeroizing;

type ReadTasks = JoinSet<Result<(usize, Piece, Zeroizing<Vec<u8>>)>>;
type UploadResult = std::result::Result<(Piece, Result<()>), JoinError>;
struct Staged {
    piece: Piece,
    ready: bool,
}

pub struct FileSession {
    volume: Arc<Volume>,
    pub base: Loaded,
    file: File,
    pub size: u64,
    visible_size: u64,
    cached: BTreeSet<usize>,
    dirty_base: BTreeSet<usize>,
    staged: BTreeMap<u64, Staged>,
    uploads: JoinSet<(Piece, Result<()>)>,
    upload_error: Option<Error>,
    naming: Option<NamingConfig>,
    allocation: Option<[u8; 16]>,
    next_chunk: u64,
    changed: bool,
}
impl FileSession {
    pub(super) fn new(volume: Arc<Volume>, base: Loaded, file: File, size: u64) -> Self {
        Self {
            volume,
            base,
            file,
            size,
            visible_size: size,
            cached: BTreeSet::new(),
            dirty_base: BTreeSet::new(),
            staged: BTreeMap::new(),
            uploads: JoinSet::new(),
            upload_error: None,
            naming: None,
            allocation: None,
            next_chunk: 0,
            changed: false,
        }
    }
    async fn ensure(&mut self, start: u64, end: u64) -> Result<()> {
        let InodeContent::Chunks(config) = &self.base.body.content else {
            return Ok(());
        };
        let naming = config.naming.clone();
        let all = pieces(&self.base.body);
        let selected: Vec<_> = all
            .iter()
            .enumerate()
            .filter(|(_, p)| p.offset < end && p.offset + u64::from(p.len) > start)
            .map(|(i, _)| i)
            .collect();
        let mut wanted = BTreeSet::new();
        for i in selected {
            for (j, p) in all.iter().enumerate().skip(i).take(4) {
                if !self.cached.contains(&j) && p.offset < self.visible_size {
                    wanted.insert(j);
                }
            }
        }
        let mut tasks = JoinSet::new();
        for i in wanted {
            let piece = all[i].clone();
            let name = self.volume.chunk_name(&naming, &piece)?;
            let key = self.base.key.clone();
            let suite = self.base.suite.clone();
            let volume = self.volume.clone();
            tasks.spawn(async move {
                let bytes = volume
                    .connection
                    .get(&name, piece.len as usize + 64)
                    .await?
                    .ok_or(Error::Missing)?
                    .bytes;
                let plaintext =
                    objects::open_chunk(&key, &volume.fs_id, &name, &suite, piece.len, &bytes)?;
                Ok::<_, Error>((i, piece, plaintext))
            });
            if tasks.len() >= self.volume.parallelism {
                self.receive_read(&mut tasks).await?;
            }
        }
        while !tasks.is_empty() {
            self.receive_read(&mut tasks).await?;
        }
        Ok(())
    }
    async fn receive_read(&mut self, tasks: &mut ReadTasks) -> Result<()> {
        let (i, p, bytes) = tasks.join_next().await.ok_or(Error::Invalid)???;
        let len = (self.visible_size - p.offset).min(u64::from(p.len)) as usize;
        self.file.write_all_at(&bytes[..len], p.offset)?;
        self.cached.insert(i);
        Ok(())
    }
    pub async fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        let len = self.size.saturating_sub(offset).min(size as u64) as usize;
        if len == 0 {
            return Ok(Vec::new());
        }
        self.ensure(offset, offset + len as u64).await?;
        let mut bytes = vec![0; len];
        self.file.read_exact_at(&mut bytes, offset)?;
        Ok(bytes)
    }
    /// Buffer first, then snapshot complete append chunks for background upload.
    /// Waiting for a queue slot is bounded-memory backpressure, not publication.
    pub async fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::TooLarge)?;
        self.check_size(end)?;
        self.ensure(offset, end).await?;
        self.file.write_all_at(bytes, offset)?;
        for (i, p) in pieces(&self.base.body).iter().enumerate() {
            if p.offset < end && p.offset + u64::from(p.len) > offset {
                self.dirty_base.insert(i);
            }
        }
        // Uploaded snapshots are immutable: later writes invalidate references,
        // never mutate the bytes owned by an in-flight task.
        self.staged.retain(|_, s| {
            s.piece.offset >= end || s.piece.offset + u64::from(s.piece.len) <= offset
        });
        self.size = self.size.max(end);
        self.changed = true;
        // Data was accepted locally. Any later pipeline failure must remain
        // observable at fsync/flush, even if write() itself returns success.
        if let Err(e) = self.seal_gaps(false).await {
            self.record_error(e);
        }
        Ok(bytes.len())
    }
    fn check_size(&self, size: u64) -> Result<()> {
        if size.div_ceil(self.volume.chunk_size as u64) > inode::MAX_CHUNK_REFERENCES as u64 {
            Err(Error::TooLarge)
        } else {
            Ok(())
        }
    }
    pub fn resize(&mut self, size: u64) -> Result<()> {
        self.check_size(size)?;
        if size == self.size {
            return Ok(());
        }
        self.file.set_len(size)?;
        self.visible_size = self.visible_size.min(size);
        self.staged
            .retain(|_, s| s.piece.offset + u64::from(s.piece.len) <= size);
        self.size = size;
        self.changed = true;
        Ok(())
    }
    fn record_error(&mut self, error: Error) {
        if self.upload_error.is_none() {
            self.upload_error = Some(error);
        }
    }
    fn receive_upload(&mut self, result: UploadResult) {
        match result {
            Ok((piece, result)) => {
                let current = self
                    .staged
                    .get(&piece.offset)
                    .is_some_and(|s| s.piece == piece);
                match result {
                    Ok(()) => {
                        if current {
                            self.staged.get_mut(&piece.offset).unwrap().ready = true;
                        }
                    }
                    Err(e) => {
                        if current {
                            self.staged.remove(&piece.offset);
                        }
                        self.record_error(e);
                    }
                }
            }
            Err(e) => {
                // A panicked/cancelled task lacks its piece identity. Discard
                // uncertain references; a later retry can re-read local bytes.
                self.staged.retain(|_, s| s.ready);
                self.record_error(e.into());
            }
        }
    }
    fn poll_uploads(&mut self) {
        while let Some(result) = self.uploads.try_join_next() {
            self.receive_upload(result);
        }
    }
    async fn drain_uploads(&mut self) {
        while let Some(result) = self.uploads.join_next().await {
            self.receive_upload(result);
        }
    }
    fn reusable(&self) -> Vec<Piece> {
        let mut result: Vec<_> = pieces(&self.base.body)
            .into_iter()
            .enumerate()
            .filter(|(i, p)| {
                !self.dirty_base.contains(i)
                    && p.offset + u64::from(p.len) <= self.visible_size
                    && p.offset + u64::from(p.len) <= self.size
            })
            .map(|(_, p)| p)
            .collect();
        result.extend(self.staged.values().map(|s| s.piece.clone()));
        result.sort_by_key(|p| p.offset);
        result
    }
    fn gaps(&self) -> Vec<(u64, u64)> {
        let mut cursor = 0;
        let mut gaps = Vec::new();
        for p in self.reusable() {
            if cursor < p.offset {
                gaps.push((cursor, p.offset));
            }
            cursor = p.offset + u64::from(p.len);
        }
        if cursor < self.size {
            gaps.push((cursor, self.size));
        }
        gaps
    }
    fn ensure_naming(&mut self) -> Result<()> {
        if self.naming.is_none() {
            self.naming = Some(match &self.base.body.content {
                InodeContent::Chunks(c) => c.naming.clone(),
                _ => NamingConfig {
                    algorithm: naming::algorithm()?,
                    key: crypto::random_array()?,
                },
            });
        }
        if self.allocation.is_none() {
            self.allocation = Some(crypto::random_array()?);
        }
        Ok(())
    }
    async fn stage(&mut self, offset: u64, len: u32) -> Result<()> {
        self.poll_uploads();
        while self.uploads.len() >= self.volume.parallelism {
            let result = self.uploads.join_next().await.ok_or(Error::Invalid)?;
            self.receive_upload(result);
        }
        if self.upload_error.is_some() {
            return Ok(());
        }
        self.ensure_naming()?;
        let plain = Zeroizing::new(self.read(offset, len as usize).await?);
        let piece = Piece {
            offset,
            len,
            allocation: self.allocation.ok_or(Error::Invalid)?,
            index: self.next_chunk,
        };
        self.next_chunk = self.next_chunk.checked_add(1).ok_or(Error::TooLarge)?;
        let name = self
            .volume
            .chunk_name(self.naming.as_ref().ok_or(Error::Invalid)?, &piece)?;
        let key = self.base.key.clone();
        let suite = self.base.suite.clone();
        let volume = self.volume.clone();
        let upload_piece = piece.clone();
        self.uploads.spawn(async move {
            let result = async {
                let fs = volume.fs_id;
                let encrypt_name = name.clone();
                let bytes = tokio::task::spawn_blocking(move || {
                    objects::seal_chunk(&key, &fs, &encrypt_name, &suite, &plain)
                })
                .await??;
                match volume.connection.put(&name, bytes, None).await? {
                    PutResult::Applied(_) => Ok(()),
                    PutResult::Conflict => Err(Error::Conflict),
                }
            }
            .await;
            (upload_piece, result)
        });
        self.staged.insert(
            offset,
            Staged {
                piece,
                ready: false,
            },
        );
        Ok(())
    }
    /// Only newly appended full chunks are sealed eagerly. Existing regions
    /// remain mutable until fsync, preserving the existing overwrite policy.
    async fn seal_gaps(&mut self, finalize: bool) -> Result<()> {
        self.poll_uploads();
        if self.upload_error.is_some() || self.size <= inode::MAX_INLINE_SIZE as u64 {
            return Ok(());
        }
        let append_start = match &self.base.body.content {
            InodeContent::Chunks(_) => self.base.body.size()?,
            _ => 0,
        };
        for (mut start, end) in self.gaps() {
            if !finalize {
                start = start.max(append_start);
            }
            while start < end {
                let len = (end - start).min(self.volume.chunk_size as u64) as u32;
                if !finalize && (len as usize) < self.volume.chunk_size {
                    break;
                }
                self.stage(start, len).await?;
                if self.upload_error.is_some() {
                    return Ok(());
                }
                start += u64::from(len);
            }
        }
        Ok(())
    }
    /// Caller serializes this barrier with writes. FUSE holds the per-file
    /// session mutex through publication: later writes enter the next generation.
    pub async fn commit(&mut self) -> Result<()> {
        self.poll_uploads();
        if self.changed
            && let Err(e) = self.seal_gaps(true).await
        {
            self.record_error(e);
        }
        self.drain_uploads().await;
        if let Some(error) = self.upload_error.take() {
            return Err(error);
        }
        if !self.changed {
            return Ok(());
        }
        let content = if self.size <= inode::MAX_INLINE_SIZE as u64 {
            InodeContent::Inline(self.read(0, self.size as usize).await?)
        } else {
            let next = self.reusable();
            if next.len() > inode::MAX_CHUNK_REFERENCES {
                return Err(Error::TooLarge);
            }
            // No dangling reference may become visible, even after task failure.
            let mut cursor = 0;
            let mut runs: Vec<ChunkRun> = Vec::new();
            for p in next {
                if p.offset != cursor {
                    return Err(Error::Invalid);
                }
                cursor += u64::from(p.len);
                if let Some(last) = runs.last_mut()
                    && last.allocation_id == p.allocation
                    && last.first_chunk + last.plaintext_lengths.len() as u64 == p.index
                {
                    last.plaintext_lengths.push(p.len);
                    continue;
                }
                runs.push(ChunkRun {
                    allocation_id: p.allocation,
                    first_chunk: p.index,
                    plaintext_lengths: vec![p.len],
                });
            }
            if cursor != self.size || self.staged.values().any(|s| !s.ready) {
                return Err(Error::Invalid);
            }
            let naming = match &self.naming {
                Some(n) => n.clone(),
                None => match &self.base.body.content {
                    InodeContent::Chunks(c) => c.naming.clone(),
                    _ => return Err(Error::Invalid),
                },
            };
            InodeContent::Chunks(ChunkedContent { naming, runs })
        };
        let mut body = self.base.body.clone();
        body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
        body.content = content;
        let etag = self
            .volume
            .publish(&self.base, &body, Some(&self.base.etag))
            .await?;
        self.base.body = body;
        self.base.etag = etag;
        self.visible_size = self.size;
        self.cached.clear();
        self.dirty_base.clear();
        self.staged.clear();
        self.naming = None;
        self.allocation = None;
        self.next_chunk = 0;
        self.changed = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
