//! FUSE trait wiring; operation bodies and adapter state live in sibling modules.
pub mod development;
mod directory;
mod file;
mod permissions;
mod state;
use fuser::*;
pub use state::S3Filesystem;
use std::{ffi::OsStr, time::SystemTime};
impl Filesystem for S3Filesystem {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        let _ = config.set_max_write(1024 * 1024);
        Ok(())
    }
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        self.handle_lookup(_req, parent, name, reply)
    }
    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        self.handle_getattr(_req, ino, _fh, reply)
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
        self.handle_create(
            _req,
            parent,
            name,
            _mode,
            _umask,
            _flags,
            _kill_suid_gid,
            _owner,
            reply,
        )
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
        self.handle_mkdir(_req, parent, name, _mode, _umask, _owner, reply)
    }
    fn open(
        &self,
        _req: &Request,
        ino: INodeNo,
        _flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        self.handle_open(_req, ino, _flags, _kill_suid_gid, reply)
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
        self.handle_read(_req, _ino, fh, offset, size, _flags, _lock_owner, reply)
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
        self.handle_write(
            _req,
            _ino,
            fh,
            offset,
            data,
            _write_flags,
            flags,
            _lock_owner,
            reply,
        )
    }
    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        self.handle_flush(_req, _ino, fh, _owner, reply)
    }
    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.handle_fsync(_req, _ino, fh, _datasync, reply)
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
        self.handle_release(_req, _ino, fh, _flags, _owner, _flush, reply)
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
        self.handle_setattr(
            _req,
            ino,
            mode,
            uid,
            gid,
            size,
            atime,
            mtime,
            _ctime,
            fh,
            _crtime,
            _chgtime,
            _bkuptime,
            _flags,
            _kill_suid_gid,
            reply,
        )
    }
    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.handle_unlink(_req, parent, name, reply)
    }
    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        self.handle_opendir(_req, ino, _flags, reply)
    }
    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        self.handle_readdir(_req, _ino, fh, offset, reply)
    }
    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.handle_releasedir(_req, _ino, fh, _flags, reply)
    }
    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.handle_fsyncdir(_req, _ino, _fh, _datasync, reply)
    }
}
