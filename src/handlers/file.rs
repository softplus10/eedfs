//! File-operation handlers; storage semantics live in volume::session.
// These signatures intentionally mirror the FUSE callbacks.
#![allow(clippy::too_many_arguments)]
use super::state::*;
use eedfs::{
    format::metadata::Timestamp,
    format::{directory::Entry, inode},
    volume::{Error, MetadataUpdate},
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
        match if self.node(ino).is_ok_and(|n| n.kind == inode::FILE)
            && let Some(fh) = _fh
        {
            self.getattr_handle(ino, fh)
        } else {
            self.getattr_inner(ino)
        } {
            Ok(a) => reply.attr(
                if a.kind == FileType::Directory {
                    &DIRECTORY_TTL
                } else {
                    &TTL
                },
                &a,
            ),
            Err(e) => reply.error(errno(e)),
        }
    }
    pub(super) fn handle_create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        _kill_suid_gid: bool,
        owner: Owner,
        reply: ReplyCreate,
    ) {
        let result = (|| {
            let p = self.node(parent)?;
            let name = name.to_str().ok_or(Error::Invalid)?;
            let loaded = self
                .runtime
                .block_on(self.volume.create_inheriting_metadata(
                    p.id,
                    name,
                    inode::FILE,
                    eedfs::format::metadata::Metadata::new(
                        owner.uid,
                        owner.gid,
                        (mode & !umask & 0o7777) as u16,
                    ),
                ))?;
            let ino = self.register(
                parent,
                &Entry {
                    name: name.into(),
                    id: loaded.body.id,
                    kind: inode::FILE,
                },
            )?;
            // CREATE already owns the just-published inode. Avoid another S3
            // GET solely to build its reply (one network round trip per file).
            let attr = self.attr(
                ino,
                inode::FILE,
                loaded.body.size()?,
                &loaded.body.metadata,
                loaded.body.nlink,
                allocation_size(&loaded.body),
            );
            let fh = match self.add_handle(ino, Some(loaded), OpenFlags(flags)) {
                Ok(fh) => fh,
                Err(e) => {
                    self.forget_node(ino, 1);
                    return Err(e);
                }
            };
            match attr {
                Ok(attr) => Ok((attr, fh)),
                Err(e) => {
                    self.release_handle(fh);
                    self.forget_node(ino, 1);
                    Err(e)
                }
            }
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
        match self.add_handle(ino, None, _flags) {
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
            let memory = self.volume.resources.work_memory(u64::from(size) + 256)?;
            let bytes = self
                .runtime
                .block_on(s.lock().unwrap().read(offset, size as usize))?;
            Ok::<_, Error>((bytes, memory))
        })();
        match result {
            Ok((bytes, _memory)) => reply.data(&bytes),
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
        write_flags: WriteFlags,
        flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let result = (|| {
            // Mapped page writeback is positioned I/O, even if its chosen file
            // handle was opened O_APPEND/O_SYNC. The following FSYNC, including
            // msync(MS_SYNC), supplies the commit barrier for mapped writes.
            let page_writeback = write_flags.contains(WriteFlags::FUSE_WRITE_CACHE);
            let (s, origin) = if page_writeback {
                let (session, generation) = self.cache_handle(fh)?;
                (session, Some(generation))
            } else {
                (self.handle(fh)?, None)
            };
            loop {
                let mut session = s.lock().unwrap();
                let position = if !page_writeback && flags.0 & libc::O_APPEND != 0 {
                    session.size
                } else {
                    offset
                };
                let result = match origin {
                    Some(generation) => self
                        .runtime
                        .block_on(session.write_cached(position, data, generation)),
                    None => self.runtime.block_on(session.write(position, data)),
                };
                let n = match result {
                    Err(error @ (Error::NoSpace | Error::NoMemory)) => {
                        drop(session);
                        if self.runtime.block_on(self.writeback.wait_for_progress()) {
                            continue;
                        }
                        return Err(error);
                    }
                    other => other?,
                };
                if n > 0 && _req.uid() != Some(0) {
                    session.clear_setid();
                }
                if !page_writeback && flags.0 & (libc::O_SYNC | libc::O_DSYNC) != 0 {
                    let id = session.base.body.id;
                    drop(session);
                    self.runtime.block_on(self.writeback.sync(id))?;
                }
                return Ok::<_, Error>(n);
            }
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
        match self.flush(fh) {
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
        self.release_handle(fh);
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
        if _flags.is_some() {
            reply.error(Errno::EOPNOTSUPP);
            return;
        }
        let result = (|| {
            let actor = super::permissions::actor(_req, gid)?;
            let time = |t: Option<TimeOrNow>| -> Result<Option<Timestamp>, Error> {
                Ok(match t {
                    None => None,
                    Some(TimeOrNow::Now) => Some(Timestamp::now()),
                    Some(TimeOrNow::SpecificTime(t)) => Some(Timestamp::from_system_time(t)?),
                })
            };
            let update = MetadataUpdate {
                mode: mode.map(|m| (m & 0o7777) as u16),
                uid,
                gid,
                atime: time(atime)?,
                mtime: time(mtime)?,
            };
            let node = self.node(ino)?;
            if node.kind != inode::FILE {
                if size.is_some() {
                    return Err(Error::Invalid);
                }
                let loaded = self
                    .runtime
                    .block_on(self.volume.update_metadata(node.id, &update, actor))?;
                return self.attr(
                    ino,
                    node.kind,
                    if node.kind == inode::DIRECTORY {
                        0
                    } else {
                        loaded.body.size()?
                    },
                    &loaded.body.metadata,
                    loaded.body.nlink,
                    allocation_size(&loaded.body),
                );
            }
            let s = if let Some(fh) = fh {
                self.handle(fh)?
            } else {
                self.session(ino)?
            };
            let mut session = s.lock().unwrap();
            let was_dirty = session.is_dirty();
            if let Some(size) = size {
                self.runtime.block_on(session.prepare())?;
                session.resize(size)?;
                if _kill_suid_gid || actor.0 != 0 {
                    session.clear_setid();
                }
            }
            session.update_metadata(&update, actor)?;
            let barrier = fh.is_none() || !update.is_empty();
            let attr = self.attr(
                ino,
                inode::FILE,
                session.size,
                &session.metadata,
                session.base.body.nlink,
                session.allocated_size(),
            )?;
            drop(session);
            if barrier {
                if was_dirty {
                    // Copy tools commonly set timestamps before close. Keep
                    // those changes with the pending data without forcing fsync.
                    self.writeback.submit(node.id, &s)?;
                } else {
                    self.runtime.block_on(self.writeback.sync(node.id))?;
                }
            }
            drop(s);
            self.writeback.forget_closed(node.id);
            Ok(attr)
        })();
        match result {
            Ok(a) => reply.attr(&TTL, &a),
            Err(e) => reply.error(errno(e)),
        }
    }
}
