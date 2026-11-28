//! Writable adapter. Close queues writeback; fsync acknowledges S3 persistence.
use cocryptfs::{
    format::{directory::Entry, inode, metadata::Metadata},
    volume::{Error, FileSession, Loaded, Volume, snapshots::Snapshots, writeback::Writeback},
};
use fuser::*;
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
pub(super) const TTL: Duration = Duration::ZERO;
pub(super) const DIRECTORY_TTL: Duration = Duration::from_secs(1);
#[derive(Clone)]
pub(super) struct Node {
    pub(super) id: [u8; 16],
    pub(super) kind: u8,
    pub(super) parent: u64,
    lookups: u64,
    opens: usize,
}
pub(super) type Session = Arc<Mutex<FileSession>>;
struct OpenFile {
    session: Session,
    id: [u8; 16],
    generation: Option<u64>,
    ino: u64,
    _memory: cocryptfs::volume::resources::Memory,
}
struct LocalFile {
    session: Weak<Mutex<FileSession>>,
    generations: BTreeMap<u64, usize>,
    handles: usize,
}
#[derive(Clone)]
pub(super) struct DirCursor {
    pub id: [u8; 16],
    pub ino: INodeNo,
    pub parent: INodeNo,
    pub offset: u64,
    pub after: Option<String>,
    pub _memory: Arc<cocryptfs::volume::resources::Memory>,
}
pub(super) struct State {
    pub(super) nodes: HashMap<u64, Node>,
    pub(super) ids: HashMap<[u8; 16], u64>,
    pub(super) next_handle: u64,
    handles: HashMap<u64, OpenFile>,
    // Handles own the working state. Weak entries let the last close release
    // its spool while serializing concurrent opens onto one state per inode.
    files: HashMap<[u8; 16], LocalFile>,
    pub(super) max_nodes: usize,
    pub(super) directories: HashMap<u64, DirCursor>,
}
pub struct S3Filesystem {
    pub(super) volume: Arc<Volume>,
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) state: Mutex<State>,
    pub(super) cache: PathBuf,
    pub(super) snapshots: Arc<Snapshots>,
    pub(super) writeback: Arc<Writeback>,
    poller: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}
impl S3Filesystem {
    pub fn new(
        volume: Arc<Volume>,
        runtime: tokio::runtime::Runtime,
        cache: PathBuf,
        poll_interval: Duration,
    ) -> Self {
        let root = Node {
            id: volume.root,
            kind: inode::DIRECTORY,
            parent: 1,
            lookups: 1,
            opens: 0,
        };
        let snapshots = Arc::new(Snapshots::new(volume.clone()));
        let writeback = Writeback::new(volume.resources.clone(), snapshots.clone());
        let writer = runtime.spawn(
            writeback
                .clone()
                .run(runtime.handle().clone(), volume.parallelism),
        );
        let polling = snapshots.clone();
        let poller = runtime.spawn(async move {
            let mut interval = tokio::time::interval(poll_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                polling.poll_once().await;
            }
        });
        Self {
            volume,
            runtime,
            state: Mutex::new(State {
                nodes: HashMap::from([(1, root.clone())]),
                ids: HashMap::from([(root.id, 1)]),
                next_handle: 1,
                handles: HashMap::new(),
                files: HashMap::new(),
                directories: HashMap::new(),
                max_nodes: 65_536,
            }),
            cache,
            snapshots,
            writeback,
            poller,
            writer,
        }
    }
    pub(super) fn creation_metadata(
        &self,
        parent: [u8; 16],
        owner: Owner,
        mode: u32,
        umask: u32,
        kind: u8,
    ) -> Result<Metadata, Error> {
        let parent = self.runtime.block_on(self.volume.load(parent))?;
        let inherit = parent.body.metadata.mode & 0o2000 != 0;
        let mut mode = (mode & !umask & 0o7777) as u16;
        if inherit && kind == inode::DIRECTORY {
            mode |= 0o2000;
        }
        Ok(Metadata::new(
            owner.uid,
            if inherit {
                parent.body.metadata.gid
            } else {
                owner.gid
            },
            mode,
        ))
    }
    pub(super) fn node(&self, ino: INodeNo) -> Result<Node, Error> {
        self.state
            .lock()
            .unwrap()
            .nodes
            .get(&ino.0)
            .cloned()
            .ok_or(Error::Missing)
    }
    pub fn set_node_limit(&self, limit: usize) -> Result<(), Error> {
        if limit < 2 {
            return Err(Error::Invalid);
        }
        self.writeback.set_limit(limit)?;
        self.state.lock().unwrap().max_nodes = limit;
        Ok(())
    }
    pub(super) fn register(&self, parent: INodeNo, entry: &Entry) -> Result<INodeNo, Error> {
        self.register_node(parent, entry, true)
    }
    pub(super) fn register_node(
        &self,
        parent: INodeNo,
        entry: &Entry,
        lookup: bool,
    ) -> Result<INodeNo, Error> {
        let mut s = self.state.lock().unwrap();
        if let Some(&ino) = s.ids.get(&entry.id) {
            let n = s.nodes.get_mut(&ino).ok_or(Error::Missing)?;
            if entry.kind == inode::DIRECTORY {
                n.parent = parent.0;
            }
            if lookup {
                n.lookups = n.lookups.checked_add(1).ok_or(Error::TooLarge)?;
            }
            return Ok(INodeNo(ino));
        }
        if s.nodes.len() >= s.max_nodes {
            let stale = s.nodes.iter().find_map(|(&ino, n)| {
                (ino != 1 && n.lookups == 0 && n.opens == 0).then_some((ino, n.id))
            });
            if let Some((ino, id)) = stale {
                s.nodes.remove(&ino);
                s.ids.remove(&id);
            } else {
                return Err(Error::NoMemory);
            }
        }
        // Keep st_ino stable after FORGET/cache eviction. The 128-bit object
        // identity remains authoritative; never alias an observed hash collision.
        use sha2::Digest;
        let digest = sha2::Sha256::digest(entry.id);
        let ino = 2 + (u64::from_le_bytes(digest[..8].try_into().unwrap()) % (i64::MAX as u64 - 1));
        if s.nodes.get(&ino).is_some_and(|n| n.id != entry.id) {
            return Err(Error::Other("FUSE inode-number hash collision".into()));
        }
        s.ids.insert(entry.id, ino);
        s.nodes.insert(
            ino,
            Node {
                id: entry.id,
                kind: entry.kind,
                parent: parent.0,
                lookups: u64::from(lookup),
                opens: 0,
            },
        );
        Ok(INodeNo(ino))
    }
    pub(super) fn forget_node(&self, ino: INodeNo, count: u64) {
        let mut s = self.state.lock().unwrap();
        if ino.0 == 1 {
            return;
        }
        if let Some(n) = s.nodes.get_mut(&ino.0) {
            n.lookups = n.lookups.saturating_sub(count);
            if n.lookups == 0 && n.opens == 0 {
                let id = n.id;
                s.nodes.remove(&ino.0);
                s.ids.remove(&id);
            }
        }
    }
    pub(super) fn pin_node(&self, ino: INodeNo) -> Result<(), Error> {
        let mut s = self.state.lock().unwrap();
        s.nodes.get_mut(&ino.0).ok_or(Error::Missing)?.opens += 1;
        Ok(())
    }
    pub(super) fn unpin_node(&self, ino: INodeNo) {
        let mut s = self.state.lock().unwrap();
        if let Some(n) = s.nodes.get_mut(&ino.0) {
            n.opens = n.opens.saturating_sub(1);
            if ino.0 != 1 && n.opens == 0 && n.lookups == 0 {
                let id = n.id;
                s.nodes.remove(&ino.0);
                s.ids.remove(&id);
            }
        }
    }
    pub(super) fn session(&self, ino: INodeNo) -> Result<Session, Error> {
        Ok(self.shared_session(ino, None)?.0)
    }
    fn active_session(&self, id: &[u8; 16]) -> Option<Session> {
        self.state
            .lock()
            .unwrap()
            .files
            .get(id)
            .and_then(|file| file.session.upgrade())
    }
    /// Backend I/O happens outside the global map lock. Recheck after loading
    /// so two concurrent first opens never install independent working states.
    fn shared_session(
        &self,
        ino: INodeNo,
        loaded: Option<Loaded>,
    ) -> Result<(Session, bool), Error> {
        let node = self.node(ino)?;
        if let Some(session) = self.active_session(&node.id) {
            return Ok((session, true));
        }
        let loaded = match loaded {
            Some(loaded) => loaded,
            None => self.runtime.block_on(self.snapshots.open(node.id))?,
        };
        let candidate = Arc::new(Mutex::new(self.volume.file(loaded, &self.cache)?));
        loop {
            let mut state = self.state.lock().unwrap();
            if let Some(session) = state
                .files
                .get(&node.id)
                .and_then(|file| file.session.upgrade())
            {
                return Ok((session, true));
            }
            if state.files.len() >= state.max_nodes {
                state
                    .files
                    .retain(|_, file| file.handles != 0 || file.session.strong_count() != 0);
                if state.files.len() >= state.max_nodes {
                    drop(state);
                    if self.runtime.block_on(self.writeback.wait_for_progress()) {
                        continue;
                    }
                    return Err(Error::NoMemory);
                }
            }
            let tracked = match self.writeback.track(node.id, &candidate) {
                Err(Error::NoMemory) => {
                    drop(state);
                    if self.runtime.block_on(self.writeback.wait_for_progress()) {
                        continue;
                    }
                    return Err(Error::NoMemory);
                }
                other => other?,
            };
            let reused = !Arc::ptr_eq(&tracked, &candidate);
            state.files.insert(
                node.id,
                LocalFile {
                    session: Arc::downgrade(&tracked),
                    generations: BTreeMap::new(),
                    handles: 0,
                },
            );
            return Ok((tracked, reused));
        }
    }
    pub(super) fn handle(&self, fh: FileHandle) -> Result<Session, Error> {
        self.state
            .lock()
            .unwrap()
            .handles
            .get(&fh.0)
            .map(|handle| handle.session.clone())
            .ok_or(Error::Missing)
    }
    pub(super) fn cache_handle(&self, fh: FileHandle) -> Result<(Session, u64), Error> {
        let state = self.state.lock().unwrap();
        let handle = state.handles.get(&fh.0).ok_or(Error::Missing)?;
        // The kernel may choose another writable mapping's FH for a dirty
        // page. Fence against the oldest mmap-capable (O_RDWR) open, rather
        // than the guessed FH. Read-only/private mappings cannot dirty the file.
        let generation = *state
            .files
            .get(&handle.id)
            .and_then(|file| file.generations.first_key_value())
            .ok_or(Error::Missing)?
            .0;
        Ok((handle.session.clone(), generation))
    }
    pub(super) fn release_handle(&self, fh: FileHandle) {
        let mut state = self.state.lock().unwrap();
        let Some(handle) = state.handles.remove(&fh.0) else {
            return;
        };
        let last = if let Some(file) = state.files.get_mut(&handle.id) {
            file.handles -= 1;
            if let Some(generation) = handle.generation
                && let Some(count) = file.generations.get_mut(&generation)
            {
                *count -= 1;
                if *count == 0 {
                    file.generations.remove(&generation);
                }
            }
            file.handles == 0
        } else {
            false
        };
        drop(state);
        if last {
            // Mapped writes can arrive after the descriptor's earlier FLUSH.
            // Retain and enqueue without waiting on an in-flight inode commit.
            if let Err(error) = self.writeback.submit(handle.id, &handle.session) {
                log::error!("final release writeback remains pending: {error}");
            }
        }
        self.snapshots.unpin(handle.id);
        self.unpin_node(INodeNo(handle.ino));
        let mut state = self.state.lock().unwrap();
        if state
            .files
            .get(&handle.id)
            .is_some_and(|file| file.handles == 0)
            && Arc::strong_count(&handle.session) == 1
        {
            state.files.remove(&handle.id);
        }
        let id = handle.id;
        drop(state);
        drop(handle);
        self.writeback.forget_closed(id);
    }
    pub(super) fn add_handle(
        &self,
        ino: INodeNo,
        loaded: Option<Loaded>,
        // The kernel retains per-open-description flags and supplies them to
        // write callbacks; sharing inode data does not share O_APPEND/O_SYNC.
        flags: OpenFlags,
    ) -> Result<FileHandle, Error> {
        let memory = self.volume.resources.memory(1024)?;
        let (session, reused) = self.shared_session(ino, loaded)?;
        let (id, generation) = {
            let mut working = session.lock().unwrap();
            if reused {
                self.runtime.block_on(working.validate_open())?;
            }
            self.snapshots.pin(&working.base);
            (
                working.base.body.id,
                (flags.0 & libc::O_ACCMODE == libc::O_RDWR).then_some(working.base.body.generation),
            )
        };
        self.pin_node(ino)?;
        let mut s = self.state.lock().unwrap();
        let fh = s.next_handle;
        s.next_handle += 1;
        s.files.get_mut(&id).expect("active local file").handles += 1;
        if let Some(generation) = generation {
            *s.files
                .get_mut(&id)
                .expect("active local file")
                .generations
                .entry(generation)
                .or_default() += 1;
        }
        s.handles.insert(
            fh,
            OpenFile {
                session,
                id,
                generation,
                ino: ino.0,
                _memory: memory,
            },
        );
        Ok(FileHandle(fh))
    }
    pub(super) fn attr(
        &self,
        ino: INodeNo,
        kind: u8,
        size: u64,
        m: &Metadata,
        nlink: u32,
        allocated: u64,
    ) -> Result<FileAttr, Error> {
        Ok(FileAttr {
            ino,
            size,
            blocks: allocated.div_ceil(512),
            atime: m.atime.to_system_time()?,
            mtime: m.mtime.to_system_time()?,
            ctime: m.ctime.to_system_time()?,
            crtime: m.created.to_system_time()?,
            kind: file_type(kind),
            perm: m.mode,
            nlink,
            uid: m.uid,
            gid: m.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }
    pub(super) fn getattr_inner(&self, ino: INodeNo) -> Result<FileAttr, Error> {
        let node = self.node(ino)?;
        if node.kind == inode::FILE
            && let Some(session) = self.active_session(&node.id)
        {
            return self.session_attr(ino, &session);
        }
        let loaded = self.runtime.block_on(self.volume.load(node.id))?;
        let size = if node.kind == inode::DIRECTORY {
            0
        } else {
            loaded.body.size()?
        };
        self.attr(
            ino,
            node.kind,
            size,
            &loaded.body.metadata,
            loaded.body.nlink,
            allocation_size(&loaded.body),
        )
    }
    pub(super) fn getattr_handle(&self, ino: INodeNo, fh: FileHandle) -> Result<FileAttr, Error> {
        let s = self.handle(fh)?;
        self.session_attr(ino, &s)
    }
    pub(super) fn loaded_attr(&self, ino: INodeNo, loaded: &Loaded) -> Result<FileAttr, Error> {
        if loaded.body.kind == inode::FILE
            && let Some(session) = self.active_session(&loaded.body.id)
        {
            let s = session.lock().unwrap();
            return self.attr(
                ino,
                inode::FILE,
                s.size,
                &s.metadata,
                loaded.body.nlink,
                s.allocated_size(),
            );
        }
        self.attr(
            ino,
            loaded.body.kind,
            if loaded.body.kind == inode::DIRECTORY {
                0
            } else {
                loaded.body.size()?
            },
            &loaded.body.metadata,
            loaded.body.nlink,
            allocation_size(&loaded.body),
        )
    }
    fn session_attr(&self, ino: INodeNo, session: &Session) -> Result<FileAttr, Error> {
        let s = session.lock().unwrap();
        let nlink = self
            .runtime
            .block_on(self.volume.load(s.base.body.id))?
            .body
            .nlink;
        self.attr(
            ino,
            inode::FILE,
            s.size,
            &s.metadata,
            nlink,
            s.allocated_size(),
        )
    }
    pub(super) fn commit(&self, fh: FileHandle) -> Result<(), Error> {
        let (id, _session) = self.writeback_handle(fh)?;
        self.runtime.block_on(self.writeback.sync(id))
    }
    fn writeback_handle(&self, fh: FileHandle) -> Result<([u8; 16], Session), Error> {
        self.state
            .lock()
            .unwrap()
            .handles
            .get(&fh.0)
            .map(|h| (h.id, h.session.clone()))
            .ok_or(Error::Missing)
    }
    pub(super) fn flush(&self, fh: FileHandle) -> Result<(), Error> {
        let (id, session) = self.writeback_handle(fh)?;
        self.writeback.submit(id, &session)
    }
    pub fn writeback_status(&self) -> Arc<Writeback> {
        self.writeback.clone()
    }
    pub(super) fn shutdown(&self) {
        self.poller.abort();
        if let Err(error) = self.runtime.block_on(self.writeback.shutdown()) {
            log::error!("mount shutdown has uncommitted data: {error}");
        }
    }
}
pub(super) fn errno(error: Error) -> Errno {
    log::debug!("S3 filesystem operation failed: {error}");
    match error {
        Error::Unsupported => Errno::EOPNOTSUPP,
        Error::NoSpace => Errno::ENOSPC,
        Error::NoMemory => Errno::ENOMEM,
        Error::IsDirectory => Errno::EISDIR,
        Error::Permission => Errno::EPERM,
        Error::Conflict => Errno::EAGAIN,
        Error::Exists => Errno::EEXIST,
        Error::Missing => Errno::ENOENT,
        Error::ChunkMissing => Errno::EIO,
        Error::NotDirectory => Errno::ENOTDIR,
        Error::Invalid => Errno::EINVAL,
        Error::TooLarge => Errno::EFBIG,
        Error::NotEmpty => Errno::ENOTEMPTY,
        Error::Other(e) => {
            if let Some(code) = e
                .downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error())
            {
                return Errno::from_i32(code);
            }
            log::error!("S3 filesystem I/O failed: {e}");
            Errno::EIO
        }
    }
}

impl Drop for S3Filesystem {
    fn drop(&mut self) {
        self.shutdown();
        self.writer.abort();
    }
}

pub(super) fn file_type(kind: u8) -> FileType {
    match kind {
        inode::DIRECTORY => FileType::Directory,
        inode::SYMLINK => FileType::Symlink,
        _ => FileType::RegularFile,
    }
}

pub(super) fn allocation_size(body: &inode::InodeBody) -> u64 {
    match &body.content {
        inode::InodeContent::Inline(b) => b.len() as u64,
        inode::InodeContent::Indexed(root) => root.allocated,
        inode::InodeContent::Chunks(c) => c
            .runs
            .iter()
            .flat_map(|r| &r.plaintext_lengths)
            .map(|n| u64::from(*n))
            .sum(),
    }
}
