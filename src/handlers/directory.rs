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
        mode: u32,
        umask: u32,
        owner: Owner,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            let p = self.node(parent)?;
            let name = name.to_str().ok_or(Error::Invalid)?;
            let loaded = self.runtime.block_on(self.volume.create_with_metadata(
                p.id,
                name,
                inode::DIRECTORY,
                self.creation_metadata(p.id, owner, mode, umask, inode::DIRECTORY)?,
            ))?;
            let ino = self.register(
                parent,
                &Entry {
                    name: name.into(),
                    id: loaded.body.id,
                    kind: inode::DIRECTORY,
                },
            );
            self.attr(
                ino,
                inode::DIRECTORY,
                0,
                &loaded.body.metadata,
                loaded.body.nlink,
                allocation_size(&loaded.body),
            )
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
    pub(super) fn handle_rmdir(&self, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = (|| {
            self.runtime.block_on(
                self.volume
                    .rmdir(self.node(parent)?.id, name.to_str().ok_or(Error::Invalid)?),
            )
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }
    pub(super) fn handle_rename(
        &self,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let result = (|| {
            if flags.bits() & !libc::RENAME_NOREPLACE != 0 {
                return Err(Error::Unsupported);
            }
            self.runtime.block_on(self.volume.rename(
                self.node(parent)?.id,
                name.to_str().ok_or(Error::Invalid)?,
                self.node(newparent)?.id,
                newname.to_str().ok_or(Error::Invalid)?,
                flags.bits() != 0,
            ))
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }
    pub(super) fn handle_link(
        &self,
        ino: INodeNo,
        parent: INodeNo,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            let l = self.runtime.block_on(self.volume.link(
                self.node(ino)?.id,
                self.node(parent)?.id,
                name.to_str().ok_or(Error::Invalid)?,
            ))?;
            let number = self.register(
                parent,
                &Entry {
                    name: name.to_str().ok_or(Error::Invalid)?.into(),
                    id: l.body.id,
                    kind: l.body.kind,
                },
            );
            self.getattr_inner(number)
        })();
        match result {
            Ok(a) => reply.entry(&TTL, &a, Generation(0)),
            Err(e) => reply.error(errno(e)),
        }
    }
    pub(super) fn handle_symlink(
        &self,
        parent: INodeNo,
        name: &OsStr,
        target: &std::path::Path,
        owner: Owner,
        reply: ReplyEntry,
    ) {
        use std::os::unix::ffi::OsStrExt;
        let result = (|| {
            let name = name.to_str().ok_or(Error::Invalid)?;
            let l = self.runtime.block_on(self.volume.symlink(
                self.node(parent)?.id,
                name,
                target.as_os_str().as_bytes(),
                self.creation_metadata(self.node(parent)?.id, owner, 0o777, 0, inode::SYMLINK)?,
            ))?;
            let number = self.register(
                parent,
                &Entry {
                    name: name.into(),
                    id: l.body.id,
                    kind: inode::SYMLINK,
                },
            );
            self.getattr_inner(number)
        })();
        match result {
            Ok(a) => reply.entry(&TTL, &a, Generation(0)),
            Err(e) => reply.error(errno(e)),
        }
    }
    pub(super) fn handle_readlink(&self, ino: INodeNo, reply: ReplyData) {
        let result = (|| {
            self.runtime
                .block_on(self.volume.readlink(self.node(ino)?.id))
        })();
        match result {
            Ok(b) => reply.data(&b),
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
                snapshot.push((number, file_type(e.kind), e.name));
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
