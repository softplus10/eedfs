//! File-operation handlers; storage semantics live in volume::session.
// These signatures intentionally mirror the FUSE callbacks.
#![allow(clippy::too_many_arguments)]
use super::state::*;
use eedfs::{
    format::{directory::Entry, inode},
    volume::Error,
};
use fuser::*;
use std::ffi::OsStr;
use std::time::SystemTime;
impl S3Filesystem {
    pub(super) fn handle_getattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        match self.getattr_inner(ino) {
            Ok(a) => reply.attr(&TTL, &a),
            Err(e) => reply.error(errno(e)),
        }
    }
    pub(super) fn handle_create(
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
    pub(super) fn handle_open(
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
    pub(super) fn handle_read(
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
    pub(super) fn handle_write(
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
    pub(super) fn handle_flush(
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
    pub(super) fn handle_fsync(
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
    pub(super) fn handle_release(
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
    pub(super) fn handle_setattr(
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
}
