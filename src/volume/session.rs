//! Client working-state generations and bounded immutable-chunk upload pipeline.
use super::{Error, Loaded, MetadataUpdate, Piece, Result, Volume, pieces};
use crate::{
    crypto::{self, naming, objects},
    format::{
        header::NamingConfig,
        inode::{self, ChunkRun, ChunkedContent, Hole, InodeContent, Mutation},
        metadata::{Metadata, Timestamp},
    },
    storage::s3::PutResult,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::fd::AsRawFd,
    os::unix::fs::FileExt,
    path::PathBuf,
    sync::Arc,
};
use tokio::task::{JoinError, JoinSet};
use zeroize::Zeroizing;

type ReadTasks = JoinSet<Result<(u64, Piece, Zeroizing<Vec<u8>>, super::resources::Memory)>>;
type UploadResult = std::result::Result<(Piece, Result<()>), JoinError>;
struct Staged {
    piece: Piece,
    ready: bool,
}

pub struct FileSession {
    volume: Arc<Volume>,
    pub base: Loaded,
    file: File,
    spool: super::resources::Spool,
    working_memory: super::resources::Memory,
    pub size: u64,
    visible_size: u64,
    cached: BTreeSet<u64>,
    dirty_base: BTreeSet<u64>,
    staged: BTreeMap<u64, Staged>,
    uploads: JoinSet<(Piece, Result<()>)>,
    upload_error: Option<Error>,
    naming: Option<NamingConfig>,
    allocation: Option<[u8; 16]>,
    next_chunk: u64,
    changed: bool,
    cache_dir: PathBuf,
    pub metadata: Metadata,
    attributes: MetadataUpdate,
    attributes_actor: Option<(u32, u32)>,
    ranges: Vec<(u64, u64)>,
    append_generation: bool,
    resized: bool,
    holes: Vec<(u64, u64)>,
    resize_ranges: Vec<(u64, u64)>,
    local_generations: BTreeSet<u64>,
    cached_pending: bool,
    failed_barrier: bool,
}
impl FileSession {
    /// A new local handle joins this inode's working state. Clean states can
    /// adopt a newer server version; pending writes/errors must remain visible
    /// to all local handles until their commit barrier resolves them.
    pub async fn validate_open(&mut self) -> Result<()> {
        if !self.changed
            && self.upload_error.is_none()
            && self.uploads.is_empty()
            && self.volume.inode_etag(self.base.body.id).await? != self.base.etag
        {
            self.refresh(false).await?;
        }
        Ok(())
    }
    pub(super) fn new(
        volume: Arc<Volume>,
        base: Loaded,
        file: File,
        size: u64,
        cache_dir: PathBuf,
    ) -> Result<Self> {
        let mut spool = super::resources::Spool::new(volume.resources.clone());
        if size <= inode::MAX_INLINE_SIZE as u64 {
            spool.charge(0, size)?;
        }
        let metadata = base.body.metadata.clone();
        let holes = match &base.body.content {
            InodeContent::Chunks(c) => c
                .holes
                .iter()
                .map(|h| (h.offset, h.offset + h.len))
                .collect(),
            _ => vec![],
        };
        let working_memory = volume.resources.memory(0)?;
        Ok(Self {
            working_memory,
            spool,
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
            cache_dir,
            metadata,
            attributes: MetadataUpdate::default(),
            attributes_actor: None,
            ranges: Vec::new(),
            append_generation: false,
            resized: false,
            holes,
            resize_ranges: vec![],
            local_generations: BTreeSet::new(),
            cached_pending: false,
            failed_barrier: false,
        })
    }
    fn account_metadata(&mut self, extra: usize) -> Result<()> {
        let count = self.cached.len()
            + self.dirty_base.len()
            + self.staged.len()
            + self.holes.len()
            + self.ranges.len()
            + self.resize_ranges.len()
            + extra;
        self.working_memory
            .resize((count as u64).checked_mul(128).ok_or(Error::TooLarge)?)
    }
    fn evict_clean_spool(&mut self) -> Result<()> {
        if self.changed || self.size <= inode::MAX_INLINE_SIZE as u64 {
            return Ok(());
        }
        // Failure to punch leaves the accounting intact; it must not turn a
        // confirmed remote commit into a failed barrier.
        let result = unsafe {
            libc::fallocate(
                self.file.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                0,
                self.size as i64,
            )
        };
        if result == 0 {
            self.spool.clear();
            self.cached.clear();
            self.account_metadata(0)?;
        }
        Ok(())
    }
    fn charge_spool(&mut self, start: u64, end: u64) -> Result<()> {
        self.spool.charge(start, end)
    }
    pub async fn prepare(&mut self) -> Result<()> {
        if !matches!(self.base.body.content, InodeContent::Indexed(_)) {
            return self.account_metadata(0);
        }
        self.volume.hydrate_file(&mut self.base).await?;
        self.prune_local_generations();
        if let InodeContent::Chunks(c) = &self.base.body.content {
            self.holes.extend(c.holes.iter().filter_map(|h| {
                let end = (h.offset + h.len).min(self.visible_size.min(self.size));
                (h.offset < end).then_some((h.offset, end))
            }));
            self.holes.sort_unstable();
            let mut merged: Vec<(u64, u64)> = vec![];
            for (a, b) in self.holes.drain(..) {
                if let Some(last) = merged.last_mut()
                    && a <= last.1
                {
                    last.1 = last.1.max(b);
                } else {
                    merged.push((a, b));
                }
            }
            self.holes = merged;
        }
        self.account_metadata(0)
    }
    async fn ensure(&mut self, start: u64, end: u64) -> Result<()> {
        match self.ensure_once(start, end).await {
            Err(Error::NoSpace) if !self.changed => {
                self.evict_clean_spool()?;
                self.ensure_once(start, end).await
            }
            result => result,
        }
    }
    async fn ensure_once(&mut self, start: u64, end: u64) -> Result<()> {
        let (naming, all, _index_memory) = match &self.base.body.content {
            InodeContent::Chunks(c) => (c.naming.clone(), pieces(&self.base.body), vec![]),
            InodeContent::Indexed(root) if root.size > inode::MAX_INLINE_SIZE as u64 => {
                let naming = root.naming.clone();
                let (pieces, memory) = self
                    .volume
                    .indexed_read_pieces(&self.base, start, end)
                    .await?;
                (naming, pieces, memory)
            }
            _ => return Ok(()),
        };
        let selected: Vec<_> = all
            .iter()
            .enumerate()
            .filter(|(_, p)| p.offset < end && p.offset + u64::from(p.len) > start)
            .map(|(i, _)| i)
            .collect();
        let mut wanted = BTreeSet::new();
        for i in selected {
            for (j, p) in all.iter().enumerate().skip(i).take(4) {
                if !self.cached.contains(&p.offset) && p.offset < self.visible_size {
                    wanted.insert(j);
                }
            }
        }
        let reservation: Vec<_> = wanted
            .iter()
            .map(|&i| {
                let p = &all[i];
                (
                    p.offset,
                    (p.offset + u64::from(p.len)).min(self.visible_size),
                )
            })
            .collect();
        self.spool.charge_many(&reservation)?;
        let mut tasks = JoinSet::new();
        for i in wanted {
            let piece = all[i].clone();
            let name = self.volume.chunk_name(&naming, &piece)?;
            let key = self.base.key.clone();
            let suite = self.base.suite.clone();
            let volume = self.volume.clone();
            tasks.spawn(async move {
                let memory = volume
                    .resources
                    .work_memory(u64::from(piece.len) * 3 + 256)?;
                let bytes = volume
                    .connection
                    .get_data(&name, piece.len as usize + 64)
                    .await?
                    .ok_or(Error::ChunkMissing)?
                    .bytes;
                let plaintext =
                    objects::open_chunk(&key, &volume.fs_id, &name, &suite, piece.len, &bytes)?;
                Ok::<_, Error>((piece.offset, piece, plaintext, memory))
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
        let (i, p, bytes, _memory) = tasks.join_next().await.ok_or(Error::Invalid)???;
        let len = (self.visible_size - p.offset).min(u64::from(p.len)) as usize;
        self.file.write_all_at(&bytes[..len], p.offset)?;
        self.account_metadata(1)?;
        self.cached.insert(i);
        Ok(())
    }
    pub async fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        for _ in 0..16 {
            match self.read_once(offset, size).await {
                Err(Error::ChunkMissing) => self.refresh(true).await?,
                result => return result,
            }
        }
        Err(Error::Conflict)
    }
    // Internal reads stay on one baseline. Publication must rebase the entire
    // generation, rather than changing its references halfway through sealing.
    async fn read_once(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
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
        self.write_from(offset, bytes, None).await
    }
    /// Page cache dirties may predate a clean-open refresh. Check their oldest
    /// possible origin so writeback cannot silently replace a remote edit.
    pub async fn write_cached(&mut self, offset: u64, bytes: &[u8], origin: u64) -> Result<usize> {
        let result = self.write_from(offset, bytes, Some(origin)).await;
        match &result {
            Ok(n) if *n > 0 => self.cached_pending = true,
            Err(_) => self.failed_barrier = true,
            _ => {}
        }
        result
    }
    /// munmap can deliver new pages after the final descriptor's flush. Only
    /// those unattempted generations may commit on release; failed barriers
    /// require an explicit retry and must not be hidden by teardown.
    pub fn needs_release_commit(&self) -> bool {
        self.changed && self.cached_pending && !self.failed_barrier
    }
    async fn write_from(
        &mut self,
        offset: u64,
        bytes: &[u8],
        origin: Option<u64>,
    ) -> Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        for _ in 0..16 {
            match self.prepare().await {
                Err(Error::ChunkMissing) => {
                    self.refresh(true).await?;
                    continue;
                }
                result => result?,
            }
            if let Some(origin) = origin {
                let end = offset
                    .checked_add(bytes.len() as u64)
                    .ok_or(Error::TooLarge)?;
                if self.base.body.mutations.iter().any(|m| {
                    m.generation > origin
                        && !self.local_generations.contains(&m.generation)
                        && m.ranges.iter().any(|&(a, b)| a < end && offset < b)
                }) {
                    return Err(Error::Conflict);
                }
            }
            match self.write_once(offset, bytes).await {
                Err(Error::ChunkMissing) => self.refresh(true).await?,
                result => return result,
            }
        }
        Err(Error::Conflict)
    }
    async fn write_once(&mut self, offset: u64, bytes: &[u8]) -> Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::TooLarge)?;
        self.check_size(end)?;
        if self.ranges.len() >= 65536 {
            return Err(Error::TooLarge);
        }
        if matches!(self.spool.charge(offset, end), Err(Error::NoSpace)) && !self.changed {
            self.evict_clean_spool()?;
        }
        self.spool.charge(offset, end)?;
        self.ensure(offset, end).await?;
        self.charge_spool(offset, end)?;
        let affected: Vec<_> = pieces(&self.base.body)
            .into_iter()
            .filter(|p| {
                p.offset < end
                    && p.offset + u64::from(p.len) > offset
                    && !self.dirty_base.contains(&p.offset)
            })
            .collect();
        self.account_metadata(affected.len() + 8)?;
        if offset > self.size {
            self.add_hole(self.size, offset);
        }
        self.remove_hole(offset, end);
        self.file.write_all_at(bytes, offset)?;
        for p in &affected {
            if p.offset < end && p.offset + u64::from(p.len) > offset {
                self.dirty_base.insert(p.offset);
            }
        }
        // Uploaded snapshots are immutable: later writes invalidate references,
        // never mutate the bytes owned by an in-flight task.
        self.staged.retain(|_, s| {
            s.piece.offset >= end || s.piece.offset + u64::from(s.piece.len) <= offset
        });
        self.append_generation |= end > self.base.body.size()?;
        self.ranges.push((offset, end));
        self.ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        self.ranges = merged;
        self.metadata.mtime = Timestamp::now();
        self.metadata.ctime = self.metadata.mtime;
        self.attributes.mtime = None;
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
        if size > i64::MAX as u64 {
            Err(Error::TooLarge)
        } else {
            Ok(())
        }
    }
    fn add_hole(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        self.holes.push((start, end));
        self.holes.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (a, b) in self.holes.drain(..) {
            if let Some(last) = merged.last_mut()
                && a <= last.1
            {
                last.1 = last.1.max(b);
            } else {
                merged.push((a, b));
            }
        }
        self.holes = merged;
    }
    fn remove_hole(&mut self, start: u64, end: u64) {
        let mut next = Vec::new();
        for &(a, b) in &self.holes {
            if b <= start || a >= end {
                next.push((a, b));
                continue;
            }
            if a < start {
                next.push((a, start));
            }
            if end < b {
                next.push((end, b));
            }
        }
        self.holes = next;
    }
    pub fn resize(&mut self, size: u64) -> Result<()> {
        self.check_size(size)?;
        if size == self.size {
            return Ok(());
        }
        self.account_metadata(4)?;
        self.file.set_len(size)?;
        self.spool.truncate(size);
        self.resize_ranges
            .push((self.size.min(size), self.size.max(size)));
        if size > self.size {
            self.add_hole(self.size, size);
        } else {
            self.remove_hole(size, u64::MAX);
            self.ranges = self
                .ranges
                .iter()
                .filter_map(|&(a, b)| (a < size).then_some((a, b.min(size))))
                .collect();
        }
        self.visible_size = self.visible_size.min(size);
        self.staged
            .retain(|_, s| s.piece.offset + u64::from(s.piece.len) <= size);
        self.size = size;
        self.resized = true;
        self.metadata.mtime = Timestamp::now();
        self.metadata.ctime = self.metadata.mtime;
        self.attributes.mtime = None;
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
            .filter(|(_, p)| {
                !self.dirty_base.contains(&p.offset)
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
        let mut covered: Vec<_> = self
            .reusable()
            .into_iter()
            .map(|p| (p.offset, p.offset + u64::from(p.len)))
            .collect();
        covered.extend(self.holes.iter().copied());
        covered.sort_unstable();
        let mut cursor = 0;
        let mut gaps = Vec::new();
        for (a, b) in covered {
            if cursor < a {
                gaps.push((cursor, a));
            }
            cursor = cursor.max(b);
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
        self.account_metadata(1)?;
        let memory = self
            .volume
            .resources
            .work_memory(u64::from(len) * 3 + 256)?;
        let plain = Zeroizing::new(self.read_once(offset, len as usize).await?);
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
            let _memory = memory;
            let result = async {
                let fs = volume.fs_id;
                let encrypt_name = name.clone();
                let bytes = tokio::task::spawn_blocking(move || {
                    objects::seal_chunk(&key, &fs, &encrypt_name, &suite, &plain)
                })
                .await??;
                match volume.connection.put_data(&name, bytes, None).await? {
                    PutResult::Applied(_) => Ok(()),
                    PutResult::Conflict => {
                        Err(Error::Other("immutable chunk name collision".into()))
                    }
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
            InodeContent::Chunks(_) | InodeContent::Indexed(_) => self.base.body.size()?,
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
    pub fn clear_setid(&mut self) {
        let mode = self.metadata.mode & !0o6000;
        if mode != self.metadata.mode {
            self.metadata.mode = mode;
            self.attributes.mode = Some(mode);
            self.changed = true;
        }
    }
    pub fn allocated_size(&self) -> u64 {
        if let InodeContent::Indexed(root) = &self.base.body.content {
            return root.allocated.min(self.size);
        }
        self.size - self.holes.iter().map(|(a, b)| b - a).sum::<u64>()
    }
    pub fn is_dirty(&self) -> bool {
        self.changed
    }
    pub fn update_metadata(&mut self, update: &MetadataUpdate, actor: (u32, u32)) -> Result<()> {
        if update.is_empty() {
            return Ok(());
        }
        self.metadata = update.apply(&self.metadata, actor)?;
        self.attributes.accumulate(update);
        self.attributes_actor = Some(actor);
        self.changed = true;
        Ok(())
    }
    /// Append/resize conflicts retain first-CAS-wins. Ordinary disjoint byte
    /// writes merge using persisted mutation history, including within one chunk.
    pub async fn commit(&mut self) -> Result<()> {
        let result = self.commit_generation().await;
        self.failed_barrier = result.is_err();
        if result.is_ok() {
            self.cached_pending = false;
        }
        result
    }
    async fn commit_generation(&mut self) -> Result<()> {
        for _ in 0..16 {
            match self.commit_once().await {
                Ok(()) => return Ok(()),
                Err(Error::Conflict) => self.refresh(false).await?,
                Err(Error::ChunkMissing) => self.refresh(true).await?,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict)
    }
    /// Retire cached bytes as a unit, preserving only explicit local changes.
    /// Drain uploads first so replacing the session cannot hide a latched error.
    async fn refresh(&mut self, missing_chunk: bool) -> Result<()> {
        self.drain_uploads().await;
        let mut unavailable = None;
        for _ in 0..16 {
            let latest = self.volume.load(self.base.body.id).await?;
            if (missing_chunk && latest.etag == self.base.etag)
                || unavailable.as_ref() == Some(&latest.etag)
            {
                // The current committed version itself is missing data. A reload
                // cannot repair it; do not loop or turn it into zero-filled bytes.
                return Err(Error::ChunkMissing);
            }
            let etag = latest.etag.clone();
            let candidate = if self.changed {
                self.rebase(latest).await
            } else {
                self.volume.file(latest, &self.cache_dir)
            };
            match candidate {
                Ok(mut candidate) => {
                    candidate.cached_pending = self.cached_pending;
                    candidate.failed_barrier = self.failed_barrier;
                    candidate.local_generations = std::mem::take(&mut self.local_generations);
                    candidate.prune_local_generations();
                    if let Some(error) = self.upload_error.take() {
                        candidate.record_error(error);
                    }
                    *self = candidate;
                    return Ok(());
                }
                // Another successful commit may have retired this baseline
                // while we were loading it. Retry without dropping local edits.
                Err(Error::ChunkMissing) => unavailable = Some(etag),
                Err(error) => return Err(error),
            }
        }
        Err(Error::Conflict)
    }
    async fn rebase(&self, mut latest: Loaded) -> Result<Self> {
        self.volume.hydrate_file(&mut latest).await?;
        let original_size = self.base.body.size()?;
        let latest_size = latest.body.size()?;
        let different_fields = self
            .attributes
            .different_fields(&self.metadata, &latest.body.metadata);
        let local: Vec<_> = self
            .ranges
            .iter()
            .chain(&self.resize_ranges)
            .copied()
            .collect();
        for mutation in latest
            .body
            .mutations
            .iter()
            .filter(|m| m.generation > self.base.body.generation)
        {
            if (mutation.attribute_fields & different_fields != 0)
                || ((self.resized || self.append_generation) && mutation.size_changed)
                || mutation
                    .ranges
                    .iter()
                    .any(|&(a, b)| local.iter().any(|&(x, y)| a < y && x < b))
            {
                return Err(Error::Conflict);
            }
        }
        if !self.resized
            && self.ranges.iter().any(|&(_, b)| b > latest_size)
            && !self.append_generation
        {
            return Err(Error::Conflict);
        }
        if latest.suite != self.base.suite || latest.key.0 != self.base.key.0 {
            return Err(Error::Conflict);
        }
        if let Some(actor) = self.attributes_actor {
            self.attributes.apply(&latest.body.metadata, actor)?;
        }
        let next_metadata = self.attributes.rebase(
            &self.base.body.metadata,
            &latest.body.metadata,
            &self.metadata,
        )?;
        let mut candidate = self.volume.file(latest, &self.cache_dir)?;
        if self.resized {
            if self.visible_size < original_size {
                candidate.resize(self.visible_size)?;
            }
            candidate.resize(self.size)?;
        }
        for &(start, end) in &self.ranges {
            if end > candidate.size && !self.append_generation && !self.resized {
                return Err(Error::Conflict);
            }
            let mut offset = start;
            while offset < end {
                let len = (end - offset).min(1024 * 1024) as usize;
                let mut bytes = Zeroizing::new(vec![0; len]);
                self.file.read_exact_at(&mut bytes, offset)?;
                candidate.write_once(offset, &bytes).await?;
                offset += len as u64;
            }
        }
        candidate.metadata = next_metadata;
        if !self.ranges.is_empty() && self.attributes.mtime.is_none() {
            candidate.metadata.mtime = Timestamp::now();
        }
        candidate.metadata.ctime = Timestamp::now();
        candidate.resize_ranges = self.resize_ranges.clone();
        candidate.resized = self.resized;
        candidate.append_generation = self.append_generation;
        candidate.attributes = self.attributes.clone();
        candidate.attributes_actor = self.attributes_actor;
        candidate.changed = true;
        Ok(candidate)
    }
    async fn commit_once(&mut self) -> Result<()> {
        if !self.changed && self.upload_error.is_none() && self.uploads.is_empty() {
            return Ok(());
        }
        self.prepare().await?;
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
            InodeContent::Inline(self.read_once(0, self.size as usize).await?)
        } else {
            self.ensure_naming()?;
            let next = self.reusable();
            if next.len() > crate::format::file_index::MAX_ENTRIES as usize {
                return Err(Error::TooLarge);
            }
            // No dangling reference may become visible, even after task failure.
            let mut cursor = 0;
            let mut runs: Vec<ChunkRun> = Vec::new();
            for p in next {
                if p.offset < cursor {
                    return Err(Error::Invalid);
                }
                cursor = p.offset + u64::from(p.len);
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
            if cursor > self.size || self.staged.values().any(|s| !s.ready) {
                return Err(Error::Invalid);
            }
            let naming = match &self.naming {
                Some(n) => n.clone(),
                None => match &self.base.body.content {
                    InodeContent::Chunks(c) => c.naming.clone(),
                    _ => return Err(Error::Invalid),
                },
            };
            let chunks = ChunkedContent {
                naming,
                runs,
                holes: self
                    .holes
                    .iter()
                    .map(|&(a, b)| Hole {
                        offset: a,
                        len: b - a,
                    })
                    .collect(),
            };
            if chunks.size()? != self.size {
                return Err(Error::Invalid);
            }
            InodeContent::Chunks(chunks)
        };
        let mut body = self.base.body.clone();
        body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
        body.content = content;
        body.metadata = self.metadata.clone();
        let mut ranges = self.ranges.clone();
        ranges.extend(self.resize_ranges.iter().copied());
        if !ranges.is_empty() || !self.attributes.is_empty() {
            super::record_mutation(
                &mut body,
                Mutation {
                    generation: self
                        .base
                        .body
                        .generation
                        .checked_add(1)
                        .ok_or(Error::TooLarge)?,
                    size_changed: self.resized || self.append_generation,
                    attribute_fields: self.attributes.fields(),
                    ranges,
                },
            )?;
        }
        let retired = self.retired_chunks(&body)?;
        self.base = self.volume.publish_file(&self.base, body).await?;
        self.local_generations.insert(self.base.body.generation);
        self.prune_local_generations();
        self.visible_size = self.size;
        self.cached.clear();
        self.dirty_base.clear();
        self.staged.clear();
        self.naming = None;
        self.allocation = None;
        self.next_chunk = 0;
        self.changed = false;
        self.ranges.clear();
        self.attributes = MetadataUpdate::default();
        self.attributes_actor = None;
        self.append_generation = false;
        self.resized = false;
        self.resize_ranges.clear();
        // This CAS succeeded. Future writers must build on its references;
        // stale writers cannot republish chunks retired from this predecessor.
        self.volume.delete_objects(retired).await;
        // Shrinking accounting after publication cannot fail.
        let _ = self.account_metadata(0);
        self.evict_clean_spool()?;
        Ok(())
    }

    fn retired_chunks(&self, next: &inode::InodeBody) -> Result<BTreeSet<String>> {
        let names = |body: &inode::InodeBody| -> Result<BTreeSet<String>> {
            let InodeContent::Chunks(config) = &body.content else {
                return Ok(BTreeSet::new());
            };
            pieces(body)
                .iter()
                .map(|p| self.volume.chunk_name(&config.naming, p))
                .collect()
        };
        let mut retired = names(&self.base.body)?;
        let retained = names(next)?;
        retired.retain(|name| !retained.contains(name));
        Ok(retired)
    }
    fn prune_local_generations(&mut self) {
        if matches!(self.base.body.content, InodeContent::Indexed(_)) {
            return;
        }
        // Only generations still represented by the bounded mutation map can
        // affect a later cached write; covered history never reappears.
        let retained: BTreeSet<_> = self
            .base
            .body
            .mutations
            .iter()
            .map(|m| m.generation)
            .collect();
        self.local_generations.retain(|g| retained.contains(g));
    }
}

#[cfg(test)]
mod tests;
