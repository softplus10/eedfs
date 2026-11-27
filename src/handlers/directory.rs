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
// Let a file manager consume attributes delivered by READDIRPLUS. A zero TTL
// would expire them before its immediately following stat and repeat the GETs.
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
            let entry = self
                .runtime
                .block_on(self.volume.lookup(node.id, name))?
                .ok_or(Error::Missing)?;
            let ino = self.register(parent, &entry)?;
            let result = self.getattr_inner(ino);
            if result.is_err() {
                self.forget_node(ino, 1);
            }
            result
        })();
        match result {
            Ok(attr) => reply.entry(
                if attr.kind == FileType::Directory {
                    &DIRECTORY_TTL
                } else {
                    &TTL
                },
                &attr,
                Generation(0),
            ),
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
            let loaded = self
                .runtime
                .block_on(self.volume.create_inheriting_metadata(
                    p.id,
                    name,
                    inode::DIRECTORY,
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
                    kind: inode::DIRECTORY,
                },
            )?;
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
            )?;
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
            )?;
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
            let loaded = self.runtime.block_on(self.volume.load(node.id))?;
            if loaded.body.kind != inode::DIRECTORY {
                return Err(Error::NotDirectory);
            }
            let memory = std::sync::Arc::new(self.volume.resources.memory(1280)?);
            self.pin_node(ino)?;
            let mut s = self.state.lock().unwrap();
            let fh = s.next_handle;
            s.next_handle += 1;
            s.directories.insert(
                fh,
                DirCursor {
                    id: node.id,
                    ino,
                    parent: INodeNo(node.parent),
                    offset: 0,
                    after: None,
                    _memory: memory,
                },
            );
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
        reply: ReplyDirectory,
    ) {
        let mut reply = Some(reply);
        let result = (|| {
            let mut cursor = self
                .state
                .lock()
                .unwrap()
                .directories
                .get(&fh.0)
                .cloned()
                .ok_or(Error::Missing)?;
            if cursor.offset != offset {
                cursor.offset = 0;
                cursor.after = None;
            }
            // Seeking backwards or to an arbitrary cookie replays bounded batches.
            while cursor.offset < offset {
                if cursor.offset < 2 {
                    cursor.offset += 1;
                    continue;
                }
                let batch = self.runtime.block_on(self.volume.directory_after(
                    cursor.id,
                    cursor.after.as_deref(),
                    128,
                ))?;
                if batch.is_empty() {
                    reply.take().unwrap().ok();
                    return Ok(());
                }
                for entry in batch {
                    if cursor.offset == offset {
                        break;
                    }
                    cursor.after = Some(entry.name);
                    cursor.offset += 1;
                }
            }
            while cursor.offset < 2 {
                let (ino, name) = if cursor.offset == 0 {
                    (cursor.ino, ".")
                } else {
                    (cursor.parent, "..")
                };
                if reply
                    .as_mut()
                    .unwrap()
                    .add(ino, cursor.offset + 1, FileType::Directory, name)
                {
                    self.state.lock().unwrap().directories.insert(fh.0, cursor);
                    reply.take().unwrap().ok();
                    return Ok(());
                }
                cursor.offset += 1;
            }
            let entries = self.runtime.block_on(self.volume.directory_after(
                cursor.id,
                cursor.after.as_deref(),
                128,
            ))?;
            for entry in entries {
                let number = self.register_node(cursor.ino, &entry, false)?;
                if reply.as_mut().unwrap().add(
                    number,
                    cursor.offset + 1,
                    file_type(entry.kind),
                    &entry.name,
                ) {
                    break;
                }
                cursor.offset += 1;
                cursor.after = Some(entry.name);
            }
            self.state.lock().unwrap().directories.insert(fh.0, cursor);
            reply.take().unwrap().ok();
            Ok::<_, Error>(())
        })();
        if let Err(e) = result {
            reply.take().unwrap().error(errno(e));
        }
    }
    pub(super) fn handle_readdirplus(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectoryPlus,
    ) {
        let mut reply = Some(reply);
        // Register lookup references only for entries actually returned. Keep
        // unreturned references refundable if a later attribute fails.
        let mut registered = Vec::new();
        let result = (|| {
            let mut cursor = self
                .state
                .lock()
                .unwrap()
                .directories
                .get(&fh.0)
                .cloned()
                .ok_or(Error::Missing)?;
            if cursor.offset != offset {
                cursor.offset = 0;
                cursor.after = None;
            }
            while cursor.offset < offset {
                if cursor.offset < 2 {
                    cursor.offset += 1;
                    continue;
                }
                let entries = self.runtime.block_on(self.volume.directory_after(
                    cursor.id,
                    cursor.after.as_deref(),
                    128,
                ))?;
                if entries.is_empty() {
                    reply.take().unwrap().ok();
                    return Ok(());
                }
                for entry in entries {
                    if cursor.offset == offset {
                        break;
                    }
                    cursor.after = Some(entry.name);
                    cursor.offset += 1;
                }
            }
            while cursor.offset < 2 {
                let (ino, name) = if cursor.offset == 0 {
                    (cursor.ino, ".")
                } else {
                    (cursor.parent, "..")
                };
                let attr = self.getattr_inner(ino)?;
                if reply.as_mut().unwrap().add(
                    ino,
                    cursor.offset + 1,
                    name,
                    &DIRECTORY_TTL,
                    &attr,
                    Generation(0),
                ) {
                    self.state.lock().unwrap().directories.insert(fh.0, cursor);
                    reply.take().unwrap().ok();
                    return Ok(());
                }
                cursor.offset += 1;
            }
            // Bound both memory and speculative requests, even for tiny FUSE
            // buffers. Attributes are fetched in parallel, without extra parent
            // lookups for each child. Normal CAS validation remains unchanged.
            let entries = self.runtime.block_on(self.volume.directory_after(
                cursor.id,
                cursor.after.as_deref(),
                self.volume.parallelism.min(8),
            ))?;
            let loaded = self.runtime.block_on(async {
                let mut jobs = tokio::task::JoinSet::new();
                for (i, entry) in entries.iter().enumerate() {
                    let volume = self.volume.clone();
                    let id = entry.id;
                    jobs.spawn(async move { (i, volume.load(id).await) });
                }
                let mut loaded = vec![None; entries.len()];
                while let Some(result) = jobs.join_next().await {
                    let (i, result) = result?;
                    match result {
                        Ok(value) => loaded[i] = Some(value),
                        Err(Error::Missing) => {} // concurrent unlink
                        Err(e) => return Err(e),
                    }
                }
                Ok::<_, Error>(loaded)
            })?;
            for (entry, loaded) in entries.into_iter().zip(loaded) {
                if let Some(loaded) = loaded {
                    let ino = self.register(cursor.ino, &entry)?;
                    registered.push(ino);
                    let attr = self.loaded_attr(ino, &loaded)?;
                    if reply.as_mut().unwrap().add(
                        ino,
                        cursor.offset + 1,
                        &entry.name,
                        &DIRECTORY_TTL,
                        &attr,
                        Generation(0),
                    ) {
                        self.forget_node(ino, 1);
                        registered.pop();
                        break;
                    }
                }
                cursor.offset += 1;
                cursor.after = Some(entry.name);
            }
            self.state.lock().unwrap().directories.insert(fh.0, cursor);
            reply.take().unwrap().ok();
            Ok::<_, Error>(())
        })();
        if let Err(e) = result {
            for ino in registered {
                self.forget_node(ino, 1);
            }
            reply.take().unwrap().error(errno(e));
        }
    }
    pub(super) fn handle_releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        let cursor = self.state.lock().unwrap().directories.remove(&fh.0);
        if let Some(cursor) = cursor {
            self.unpin_node(cursor.ino);
        }
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
