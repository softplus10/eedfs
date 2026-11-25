//! Directory and namespace FUSE handlers.
// These signatures intentionally mirror the FUSE callbacks.
#![allow(clippy::too_many_arguments)]
use super::state::*;
use eedfs::{
    format::{directory::Entry, inode},
    volume::Error,
};
use fuser::*;
use std::ffi::OsStr;
impl S3Filesystem {
    pub(super) fn handle_lookup(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
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
    pub(super) fn handle_mkdir(
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
    pub(super) fn handle_unlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        reply: ReplyEmpty,
    ) {
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
    pub(super) fn handle_opendir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _flags: OpenFlags,
        reply: ReplyOpen,
    ) {
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
    pub(super) fn handle_readdir(
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
    pub(super) fn handle_releasedir(
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
    pub(super) fn handle_fsyncdir(
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
