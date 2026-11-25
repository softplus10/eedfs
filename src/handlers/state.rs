//! Writable prototype adapter. S3 persistence is acknowledged on fsync/flush.
use eedfs::{
    format::{directory::Entry, inode, metadata::Metadata},
    volume::{Error, FileSession, Loaded, Volume, snapshots::Snapshots},
};
use fuser::*;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
pub(super) const TTL: Duration = Duration::ZERO;
#[derive(Clone)]
pub(super) struct Node {
    pub(super) id: [u8; 16],
    pub(super) kind: u8,
    pub(super) parent: u64,
}
pub(super) type Session = Arc<Mutex<FileSession>>;
pub(super) type DirEntries = Vec<(INodeNo, FileType, String)>;
pub(super) struct State {
    pub(super) nodes: HashMap<u64, Node>,
    pub(super) ids: HashMap<[u8; 16], u64>,
    pub(super) next_inode: u64,
    pub(super) next_handle: u64,
    pub(super) handles: HashMap<u64, Session>,
    pub(super) directories: HashMap<u64, DirEntries>,
}
pub struct S3Filesystem {
    pub(super) volume: Arc<Volume>,
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) state: Mutex<State>,
    pub(super) cache: PathBuf,
    pub(super) snapshots: Arc<Snapshots>,
    poller: tokio::task::JoinHandle<()>,
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
        };
        let snapshots = Arc::new(Snapshots::new(volume.clone()));
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
                next_inode: 2,
                next_handle: 1,
                handles: HashMap::new(),
                directories: HashMap::new(),
            }),
            cache,
            snapshots,
            poller,
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
    pub(super) fn register(&self, parent: INodeNo, entry: &Entry) -> INodeNo {
        let mut s = self.state.lock().unwrap();
        if let Some(&ino) = s.ids.get(&entry.id) {
            if entry.kind == inode::DIRECTORY
                && let Some(n) = s.nodes.get_mut(&ino)
            {
                n.parent = parent.0;
            }
            return INodeNo(ino);
        }
        let ino = s.next_inode;
        s.next_inode += 1;
        s.ids.insert(entry.id, ino);
        s.nodes.insert(
            ino,
            Node {
                id: entry.id,
                kind: entry.kind,
                parent: parent.0,
            },
        );
        INodeNo(ino)
    }
    pub(super) fn session(&self, ino: INodeNo) -> Result<Session, Error> {
        let node = self.node(ino)?;
        let loaded = self.runtime.block_on(self.volume.load(node.id))?;
        Ok(Arc::new(Mutex::new(self.volume.file(loaded, &self.cache)?)))
    }
    pub(super) fn handle(&self, fh: FileHandle) -> Result<Session, Error> {
        self.state
            .lock()
            .unwrap()
            .handles
            .get(&fh.0)
            .cloned()
            .ok_or(Error::Missing)
    }
    pub(super) fn add_handle(
        &self,
        ino: INodeNo,
        loaded: Option<Loaded>,
        _flags: OpenFlags,
    ) -> Result<FileHandle, Error> {
        let loaded = match loaded {
            Some(l) => l,
            None => self
                .runtime
                .block_on(self.snapshots.open(self.node(ino)?.id))?,
        };
        let session = Arc::new(Mutex::new(self.volume.file(loaded.clone(), &self.cache)?));
        self.snapshots.pin(&loaded);
        let mut s = self.state.lock().unwrap();
        let fh = s.next_handle;
        s.next_handle += 1;
        s.handles.insert(fh, session);
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
        let s = s.lock().unwrap();
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
        let session = self.handle(fh)?;
        let mut session = session.lock().unwrap();
        self.runtime.block_on(session.commit())?;
        self.snapshots.published(&session.base);
        Ok(())
    }
}
pub(super) fn errno(error: Error) -> Errno {
    log::debug!("S3 filesystem operation failed: {error}");
    match error {
        Error::Unsupported => Errno::EOPNOTSUPP,
        Error::IsDirectory => Errno::EISDIR,
        Error::Permission => Errno::EPERM,
        Error::Conflict => Errno::EAGAIN,
        Error::Exists => Errno::EEXIST,
        Error::Missing => Errno::ENOENT,
        Error::NotDirectory => Errno::ENOTDIR,
        Error::Invalid => Errno::EINVAL,
        Error::TooLarge => Errno::EFBIG,
        Error::NotEmpty => Errno::ENOTEMPTY,
        Error::Other(e) => {
            log::error!("S3 filesystem I/O failed: {e}");
            Errno::EIO
        }
    }
}

impl Drop for S3Filesystem {
    fn drop(&mut self) {
        self.poller.abort();
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
        inode::InodeContent::Chunks(c) => c
            .runs
            .iter()
            .flat_map(|r| &r.plaintext_lengths)
            .map(|n| u64::from(*n))
            .sum(),
    }
}
