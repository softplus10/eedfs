# Namespace operations and inode-local leases

FUSE rename, rmdir, regular-file hard links, symlink and readlink are implemented.
There is no operation ID, transaction journal, recovery worker or automatic
roll-forward / rollback of interrupted namespace operations. Physical GC remains
separate work.

## Lease state

The encrypted inode body contains `lease: Option<DirectoryLease>` with
`DirectoryLease { owner:[u8;16], expires_at:Timestamp }`. Only directory inodes
may have a lease. Each acquisition generates a fresh random owner token. This is
an ownership token, not an operation ID. The current inode ETag fences writes;
no separate epoch is stored.

Acquisition, renewal, directory writes and release all use conditional PUT against
the holder's exact current ETag. A stale holder never reloads/rebases its writes
onto the successor's ETag. Default validity is 30 seconds. Explicit duration APIs
accept more than four seconds up to five minutes. There is no heartbeat worker.
The holder stops two seconds before expiry; takeover starts two seconds after.
The protocol assumes relative client clock error within two seconds.

Normal directory edits and metadata updates reject active leases, with bounded
contention retries. After expiry, an ordinary writer may CAS-clear the lease.
This invalidates a previous holder without inspecting its interrupted operation.
Reads continue while leased. Lease-only writes increment generation but do not
change POSIX timestamps; directory content changes update mtime and ctime.

Leases needed by one operation are acquired in inode-ID order. Partial acquisition
is released before retry; retries are bounded to 16. Directory topology changes
(mkdir, directory rename, rmdir) additionally acquire the root inode lease. This
serializes ancestry changes so two concurrent moves cannot both pass stale cycle
checks. A directory move also leases every directory in the source subtree and
revalidates the subtree after acquisition. Moving an ancestor therefore changes
the ETag of every potentially stale descendant writer, fencing delayed writes
after lease expiry. This costs O(number of descendant directories) lease PUTs;
large directory-tree moves are deliberately not a constant-cost operation.
Ordinary file data writes and unrelated regular-file entry edits do not
acquire the topology lease. File rename leases only its involved parent directories.

A request already in flight cannot be cancelled by a local clock check. A timeout
is not proof that a PUT was not applied. ETag fencing protects an inode after its
successor has changed that inode; several leases do not create an atomic S3
multi-object transaction. Multi-object operations can report failure after partial
publication, especially around lease expiry or network failures.

## Rename and directory removal

- Same-directory rename replaces entries in one directory inode CAS.
- Cross-directory rename first publishes the destination reference, then removes
  the expected source reference. No data copy or re-encryption is required.
- A pre-existing regular-file destination is replaced; directory replacement
  requires an empty directory, and file/directory type mismatches fail.
- Renaming between two links to the same inode is a no-op. `RENAME_NOREPLACE`
  rejects existing destinations; exchange/whiteout flags are unsupported.
- Endpoint entry identities are checked again after lease acquisition. Unrelated
  entry edits can retry; a changed source or destination returns EAGAIN.
- Directory movement checks descendants while topology is serialized, rejecting
  self/descendant destinations. Ordinary directory hard links are forbidden.
- rmdir checks emptiness while holding the child and parent leases. It marks the
  child inode `deleted=true` before removing the parent entry. This terminal mark
  prevents stale creators from inserting children after the lease expires.

A failed cross-directory rename may leave both names. An interrupted rmdir may
leave a deleted directory inode still referenced by its parent. These states are
intentionally not repaired automatically. Lease expiry does not undo them or
resurrect a deleted directory.

## Links, unlink and snapshots

Hard links refer to the same inode ID, with no copy. Stored `nlink` is updated
with inode CAS; directory link counts are derived from their immediate directory
children. Unlink immediately removes the expected name. An open file retains its
snapshot, may continue writing/fsync, and never recreates the removed name.
Replacing a destination preserves handles to the displaced inode in the same way.

Directory publication and a file's nlink update are separate S3 writes. A crash
or failed request between them can leave an inaccurate count. Counts are for
filesystem reporting, not a GC safety authority. Decrements saturate at zero so
manually unlinking residual names is still possible after a partial operation. No objects are physically deleted.

Symlinks store their raw nonempty target bytes inline in an encrypted inode
(kind 3), bounded to 4096 bytes without NUL. The kernel resolves relative and
absolute paths; dangling links are supported. Link contents are not interpreted
as S3 names. Filenames remain UTF-8, matching the current directory format.

## Validation

Unit fault injection verifies destination-first partial rename, unrecovered
directory removal and stale-creator rejection. Concurrency tests cover competing
ancestry changes and different/same-name creates. The real three-mount runner
checks rename replacement, old destination handles, hard-link counts, open-unlink
writes, relative/absolute/dangling symlinks, directory replacement/cycle rejection,
and repeated namespace contention from three clients.
