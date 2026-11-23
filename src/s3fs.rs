//! Writable prototype adapter. S3 persistence is acknowledged on fsync/flush.
use eedfs::{
    format::{directory::Entry, inode},
    volume::{Error, FileSession, Loaded, Volume},
};
use fuser::*;
use std::{
    collections::HashMap,
    ffi::OsStr,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const TTL: Duration = Duration::ZERO;
#[derive(Clone)]
struct Node {
    id: [u8; 16],
    kind: u8,
    parent: u64,
}
type Session = Arc<Mutex<FileSession>>;
type DirEntries = Vec<(INodeNo, FileType, String)>;
struct State {
    nodes: HashMap<u64, Node>,
    ids: HashMap<[u8; 16], u64>,
    next_inode: u64,
    next_handle: u64,
    active: HashMap<u64, Weak<Mutex<FileSession>>>,
    handles: HashMap<u64, Session>,
    directories: HashMap<u64, DirEntries>,
}
pub struct S3Filesystem {
    volume: Arc<Volume>,
    runtime: tokio::runtime::Runtime,
    state: Mutex<State>,
    cache: PathBuf,
    uid: u32,
    gid: u32,
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
    fn node(&self, ino: INodeNo) -> Result<Node, Error> {
        self.state
            .lock()
            .unwrap()
            .nodes
            .get(&ino.0)
            .cloned()
            .ok_or(Error::Missing)
    }
    fn register(&self, parent: INodeNo, entry: &Entry) -> INodeNo {
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
    fn session(&self, ino: INodeNo) -> Result<Session, Error> {
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
    fn handle(&self, fh: FileHandle) -> Result<Session, Error> {
        self.state
            .lock()
            .unwrap()
            .handles
            .get(&fh.0)
            .cloned()
            .ok_or(Error::Missing)
    }
    fn add_handle(&self, ino: INodeNo, loaded: Option<Loaded>) -> Result<FileHandle, Error> {
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
    fn attr(&self, ino: INodeNo, kind: u8, size: u64) -> FileAttr {
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
    fn getattr_inner(&self, ino: INodeNo) -> Result<FileAttr, Error> {
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
    fn commit(&self, fh: FileHandle) -> Result<(), Error> {
        let session = self.handle(fh)?;
        self.runtime.block_on(session.lock().unwrap().commit())
    }
}
fn errno(error: Error) -> Errno {
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
impl Filesystem for S3Filesystem {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        let _ = config.set_max_write(1024 * 1024);
        Ok(())
    }
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let result = (|| {
            let node = self.node(parent)?;
            let name = name.to_str().ok_or(Error::Invalid)?;
            let entries = self.runtime.block_on(self.volume.list(node.id))?;
            let entry = entries
                .iter()
                .find(|e| e.name == name)
                .ok_or(Error::Missing)?;
            let ino = self.register(parent, entry);
            self.getattr_inner(ino)
        })();
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.getattr_inner(ino) {
            Ok(a) => reply.attr(&TTL, &a),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        _kill_suid_gid: bool,
        _owner: Owner,
        reply: ReplyCreate,
    ) {
        let result = (|| {
            let p = self.node(parent)?;
            let name = name.to_str().ok_or(Error::Invalid)?;
            let loaded = self
                .runtime
                .block_on(self.volume.create(p.id, name, inode::FILE))?;
            let ino = self.register(
                parent,
                &Entry {
                    name: name.into(),
                    id: loaded.body.id,
                    kind: inode::FILE,
                },
            );
            let fh = self.add_handle(ino, Some(loaded))?;
            Ok::<_, Error>((self.attr(ino, inode::FILE, 0), fh))
        })();
        match result {
            Ok((a, fh)) => reply.created(&TTL, &a, Generation(0), fh, FopenFlags::FOPEN_DIRECT_IO),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            let p = self.node(parent)?;
            let name = name.to_str().ok_or(Error::Invalid)?;
            let loaded = self
                .runtime
                .block_on(self.volume.create(p.id, name, inode::DIRECTORY))?;
            let ino = self.register(
                parent,
                &Entry {
                    name: name.into(),
                    id: loaded.body.id,
                    kind: inode::DIRECTORY,
                },
            );
            Ok::<_, Error>(self.attr(ino, inode::DIRECTORY, 0))
        })();
        match result {
            Ok(a) => reply.entry(&TTL, &a, Generation(0)),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn open(
        &self,
        _req: &Request,
        ino: INodeNo,
        _flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        match self.add_handle(ino, None) {
            Ok(fh) => reply.opened(fh, FopenFlags::FOPEN_DIRECT_IO),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let result = (|| {
            let s = self.handle(fh)?;
            self.runtime
                .block_on(s.lock().unwrap().read(offset, size as usize))
        })();
        match result {
            Ok(bytes) => reply.data(&bytes),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let result = (|| {
            let s = self.handle(fh)?;
            let mut session = s.lock().unwrap();
            // Kernel supplies the append offset; cross-client append is still OCC.
            let n = self.runtime.block_on(session.write(offset, data))?;
            if flags.0 & (libc::O_SYNC | libc::O_DSYNC) != 0 {
                self.runtime.block_on(session.commit())?;
            }
            Ok::<_, Error>(n)
        })();
        match result {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        match self.commit(fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.commit(fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.state.lock().unwrap().handles.remove(&fh.0);
        reply.ok();
    }
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        _kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        if mode.is_some() || uid.is_some() || gid.is_some() || atime.is_some() || mtime.is_some() {
            reply.error(Errno::EOPNOTSUPP);
            return;
        }
        let result = (|| {
            if let Some(size) = size {
                let s = if let Some(fh) = fh {
                    self.handle(fh)?
                } else {
                    self.session(ino)?
                };
                let mut session = s.lock().unwrap();
                session.resize(size)?;
                if fh.is_none() {
                    self.runtime.block_on(session.commit())?;
                }
                return Ok(self.attr(ino, inode::FILE, session.size));
            }
            self.getattr_inner(ino)
        })();
        match result {
            Ok(a) => reply.attr(&TTL, &a),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = (|| {
            let p = self.node(parent)?;
            self.runtime.block_on(
                self.volume
                    .unlink(p.id, name.to_str().ok_or(Error::Invalid)?),
            )
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let result = (|| {
            let node = self.node(ino)?;
            let entries = self.runtime.block_on(self.volume.list(node.id))?;
            let mut snapshot = vec![
                (ino, FileType::Directory, ".".into()),
                (INodeNo(node.parent), FileType::Directory, "..".into()),
            ];
            for e in entries {
                let number = self.register(ino, &e);
                snapshot.push((
                    number,
                    if e.kind == inode::DIRECTORY {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    },
                    e.name,
                ));
            }
            let mut s = self.state.lock().unwrap();
            let fh = s.next_handle;
            s.next_handle += 1;
            s.directories.insert(fh, snapshot);
            Ok::<_, Error>(FileHandle(fh))
        })();
        match result {
            Ok(fh) => reply.opened(fh, FopenFlags::empty()),
            Err(e) => reply.error(errno(e)),
        }
    }
    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let s = self.state.lock().unwrap();
        let Some(entries) = s.directories.get(&fh.0) else {
            reply.error(Errno::EBADF);
            return;
        };
        for (i, (ino, kind, name)) in entries.iter().enumerate() {
            let cookie = i as u64 + 1;
            if cookie > offset && reply.add(*ino, cookie, *kind, name) {
                break;
            }
        }
        reply.ok();
    }
    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.state.lock().unwrap().directories.remove(&fh.0);
        reply.ok();
    }
    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }
}
