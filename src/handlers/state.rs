//! Writable prototype adapter. S3 persistence is acknowledged on fsync/flush.
use eedfs::{
    format::{directory::Entry, inode},
    volume::{Error, FileSession, Loaded, Volume},
};
use fuser::*;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
    time::{Duration, UNIX_EPOCH},
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
    pub(super) active: HashMap<u64, Weak<Mutex<FileSession>>>,
    pub(super) handles: HashMap<u64, Session>,
    pub(super) directories: HashMap<u64, DirEntries>,
}
pub struct S3Filesystem {
    pub(super) volume: Arc<Volume>,
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) state: Mutex<State>,
    pub(super) cache: PathBuf,
    pub(super) uid: u32,
    pub(super) gid: u32,
}
impl S3Filesystem {
    pub fn new(
        volume: Arc<Volume>,
        runtime: tokio::runtime::Runtime,
        cache: PathBuf,
        uid: u32,
        gid: u32,
    ) -> Self {
        let root = Node {
            id: volume.root,
            kind: inode::DIRECTORY,
            parent: 1,
        };
        Self {
            volume,
            runtime,
            state: Mutex::new(State {
                nodes: HashMap::from([(1, root.clone())]),
                ids: HashMap::from([(root.id, 1)]),
                next_inode: 2,
                next_handle: 1,
                active: HashMap::new(),
                handles: HashMap::new(),
                directories: HashMap::new(),
            }),
            cache,
            uid,
            gid,
        }
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
        if let Some(s) = self
            .state
            .lock()
            .unwrap()
            .active
            .get(&ino.0)
            .and_then(Weak::upgrade)
        {
            return Ok(s);
        }
        let node = self.node(ino)?;
        let loaded = self.runtime.block_on(self.volume.load(node.id))?;
        let candidate = Arc::new(Mutex::new(self.volume.file(loaded, &self.cache)?));
        let mut state = self.state.lock().unwrap();
        if let Some(s) = state.active.get(&ino.0).and_then(Weak::upgrade) {
            return Ok(s);
        }
        state.active.insert(ino.0, Arc::downgrade(&candidate));
        Ok(candidate)
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
    ) -> Result<FileHandle, Error> {
        let session = if let Some(loaded) = loaded {
            Arc::new(Mutex::new(self.volume.file(loaded, &self.cache)?))
        } else {
            self.session(ino)?
        };
        let mut s = self.state.lock().unwrap();
        let fh = s.next_handle;
        s.next_handle += 1;
        s.active.insert(ino.0, Arc::downgrade(&session));
        s.handles.insert(fh, session);
        Ok(FileHandle(fh))
    }
    pub(super) fn attr(&self, ino: INodeNo, kind: u8, size: u64) -> FileAttr {
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: if kind == inode::DIRECTORY {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if kind == inode::DIRECTORY {
                0o755
            } else {
                0o644
            },
            nlink: if kind == inode::DIRECTORY { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
    pub(super) fn getattr_inner(&self, ino: INodeNo) -> Result<FileAttr, Error> {
        let node = self.node(ino)?;
        if node.kind == inode::DIRECTORY {
            return Ok(self.attr(ino, node.kind, 0));
        }
        let active = self
            .state
            .lock()
            .unwrap()
            .active
            .get(&ino.0)
            .and_then(Weak::upgrade);
        let size = if let Some(s) = active {
            s.lock().unwrap().size
        } else {
            self.runtime
                .block_on(self.volume.load(node.id))?
                .body
                .size()?
        };
        Ok(self.attr(ino, node.kind, size))
    }
    pub(super) fn commit(&self, fh: FileHandle) -> Result<(), Error> {
        let session = self.handle(fh)?;
        self.runtime.block_on(session.lock().unwrap().commit())
    }
}
pub(super) fn errno(error: Error) -> Errno {
    log::debug!("S3 filesystem operation failed: {error}");
    match error {
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
