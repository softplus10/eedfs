//! Read-only FUSE scaffold. Storage, encryption and distributed commits follow later.

use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};

const ROOT: INodeNo = INodeNo::ROOT;
const INFO: INodeNo = INodeNo(2);
const TTL: Duration = Duration::from_secs(1);
const CONTENT: &[u8] = b"EEDFS development filesystem\nS3 persistence and encryption are not connected to this FUSE scaffold yet.\n";

pub struct DevFilesystem {
    uid: u32,
    gid: u32,
}

impl DevFilesystem {
    pub fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }

    fn attr(&self, ino: INodeNo) -> Option<FileAttr> {
        let (kind, size, perm, nlink) = if ino == ROOT {
            (FileType::Directory, 0, 0o555, 2)
        } else if ino == INFO {
            (FileType::RegularFile, CONTENT.len() as u64, 0o444, 1)
        } else {
            return None;
        };
        Some(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }
}

impl Filesystem for DevFilesystem {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT && name == OsStr::new("README.txt") {
            reply.entry(&TTL, &self.attr(INFO).unwrap(), Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.attr(ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT {
            reply.error(if ino == INFO {
                Errno::ENOTDIR
            } else {
                Errno::ENOENT
            });
            return;
        }
        let entries = [
            (ROOT, FileType::Directory, "."),
            (ROOT, FileType::Directory, ".."),
            (INFO, FileType::RegularFile, "README.txt"),
        ];
        // Filter cookies before casting so even an out-of-range u64 is harmless.
        for (index, (ino, kind, name)) in entries.into_iter().enumerate() {
            let cookie = index as u64 + 1;
            if cookie > offset && reply.add(ino, cookie, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if ino == INFO {
            let start = offset.min(CONTENT.len() as u64) as usize;
            let end = start.saturating_add(size as usize).min(CONTENT.len());
            reply.data(&CONTENT[start..end]);
        } else {
            reply.error(if ino == ROOT {
                Errno::EISDIR
            } else {
                Errno::ENOENT
            });
        }
    }
}
