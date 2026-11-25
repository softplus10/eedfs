# File concurrency, snapshots and numeric permissions

This fixes the four selected policies. Namespace transactions, application file locks, mmap,
large indexes and GC remain separate work.

## Disjoint writes

A stale inode CAS does not automatically fail an ordinary data write. The client
loads the latest inode and performs a content-based three-way merge using its
baseline snapshot, the latest snapshot and the exact locally written byte ranges.

- Local ranges whose baseline bytes still match the latest bytes can be reapplied.
- This works for different ranges inside the same encrypted chunk, and for inline files.
- Latest bytes outside those local ranges and unrelated latest metadata are preserved.
- Conflicting ranges return EAGAIN. No arbitrary last-writer overwrite is performed.
- CAS/merge retry is bounded to 16 attempts. The local spool survives a failed sync.
- The implementation compares content, not a persisted per-operation history. A
  remote write that leaves/restores the baseline bytes is indistinguishable from
  no content change. This is not a serializable transaction/history guarantee.

Actual written ranges are coalesced per generation and bounded to 65,536 intervals.
The existing flat chunk-reference limit also remains. Local truncate/resize
conflicts and observed remote shrink conflicts remain conservatively rejected;
this does not introduce a new truncate concurrency policy.

## Append: first successful CAS wins

Competing append generations from the same baseline do not relocate/retry at a
new EOF. The first successful inode CAS wins; an appender observing a changed
baseline size gets EAGAIN. Invocation time and client clocks do not determine
order. The losing caller must handle the error and reopen before reapplying data.

An append can merge with a disjoint existing-region overwrite or unrelated
metadata edit if the baseline size did not change. Conversely, an existing-region
write can preserve another client's newly appended tail. Locally sequential
O_APPEND writes use the opened session's EOF. No global clock, reservation
service, distributed lock or additional cross-client identity is introduced.

## Open snapshots and polling

Each open file handle has its own snapshot/session. Duplicated OS descriptors
that refer to the same FUSE handle share it, but a separate open gets a separate
snapshot, including within the same mount. A reader stays on its old immutable
references until close. A writer sees its buffered writes and adopts a successful
merged result when it commits.

A latest-inode cache pins IDs while handles are open. Every five seconds by
default, bounded background HEAD requests check their ETags; changed inodes are
fetched, authenticated and cached. Old open sessions are not replaced. Failed
polls keep their existing snapshots and log errors. No reader safety or global
GC lease is inferred from these local pins.

`mount-s3 --inode-poll-seconds N` adjusts the interval (minimum one second).
New opens validate the server version even between polls: a cached body can be
reused after a matching HEAD, otherwise it is fetched. Thus closing/reopening
observes the current committed version without waiting for the next poll.
A new open still requires the backend to respond; offline opens are not promised.

Path attributes use current committed metadata; handle-specific attributes use
that handle's snapshot/current local writer state. FUSE direct I/O and zero
attribute/entry TTL remain enabled. No cross-client live view is imposed on an
already opened file.

## Persisted metadata and permissions

Inode format **v5** retains encrypted `Metadata` in the inode body:

```
Metadata {
  uid:u32, gid:u32, mode:u16,
  atime:Timestamp, mtime:Timestamp, ctime:Timestamp, created:Timestamp,
}
Timestamp { seconds:i64, nanos:u32 }
```

Mode stores permission/special bits only (0..07777); inode kind remains separate.
UID/GID 0xffffffff and nanoseconds >=1e9 are invalid. Timestamp conversion is
checked, including pre-epoch values. Size is still derived from content.

Creation uses the kernel-provided numeric owner, requested mode and umask.
Setgid directories pass their GID to children; new subdirectories inherit setgid.
The formatted root belongs to the effective UID/GID of the formatting process.
chmod, chown/chgrp and explicit atime/mtime updates persist through inode CAS.
ctime is maintained automatically; created time is preserved. Writes/resize
update mtime/ctime. Reads do not cause persisted atime writes (`noatime`).

Metadata syscalls commit their inode/session before returning, including pending
writes in a file session where applicable. Independent attribute fields are
preserved during file CAS rebasing; conflicting explicit fields are rejected
unless their requested value is already present. Ownership is checked again when
an explicit attribute update is rebased. Non-root writes clear set-id bits.

All mounts use kernel `default_permissions` with the stored numeric UID/GID/mode.
Local supplementary groups participate in kernel DAC; a non-root owner's chgrp
also validates supplementary numeric groups from the kernel request's local PID
and fsuid. This does not resolve usernames or contact other clients.

Other local users require explicit `--allow-other`; the mount owner alone is
allowed by default. Non-root mounts may require the host's existing FUSE
`user_allow_other` configuration. The application does not modify that setting.
No idmapped-mount capability is requested. Mounts remain nosuid/nodev.

The same numeric UID/GID means the same owner/group across clients. This is a
trusted-client model, not remote per-user authentication: a holder of the volume
keys and S3 write credentials can construct its own metadata. There is no account
mapping, identity service, per-user key isolation or server-side numeric DAC.

ACLs, xattrs, hard links, directory link-count maintenance, rename/rmdir, mmap,
storage-capacity reporting, rollback protection and reclamation are not added.

## Compatibility and validation

Header v4, directory payload v1 and data chunks v2 are unchanged. Inode envelopes
and bodies are v5 so older clients cannot silently ignore directory lease state.
The prototype rejects earlier inode versions; no automatic migration is provided.
Recreate disposable older test volumes. Opening validates the root inode before
mounting so unsupported versions fail early.

Unit tests cover disjoint/overlap cases within one chunk, inline merge, append
ordering, mixed append/overwrite merge, metadata ownership checks, attribute
preservation and snapshot cache polling. Real MinIO tests and three mounted
clients verify the same policies and metadata persistence. Local root-run mounted
checks additionally switch numeric users/groups, validate DAC denial, owner/group
reporting and supplementary-group chgrp without a cross-client identity lookup.

## Namespace policy update

The selected rename, unlink, link and sparse policies and the implemented
inode-local lease API are recorded in [directory leases](directory-leases.md).
No operation ID or interrupted-operation recovery is used. The lease primitive
does not yet expose rename/rmdir/hard-link/symlink callbacks or sparse extents.
