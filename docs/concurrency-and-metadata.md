# File concurrency, snapshots and numeric permissions

This fixes the four selected policies. Namespace transactions, application file locks,
online orphan/inode reclamation remain separate work. Large
directories use the [encrypted B+tree index](directory-index.md).
Memory mappings and msync follow the [mapping contract](memory-mapping.md).

## Disjoint writes

A stale inode CAS loads the latest inode and checks committed byte-range history.
Disjoint writes merge, including within one chunk and inline data. Overlapping
writes return EAGAIN even when the new bytes equal the old bytes, or another
writer restored the old bytes (ABA). No last-writer overwrite is performed.

The inode stores a compact last-writer interval map, including the last EOF
change and explicit attribute-field changes. New commits replace covered ranges
and field versions, retaining older untouched intervals. Old handles therefore
remain mergeable after arbitrarily many unrelated commits; there is no age cutoff
or retained-history floor. Equal-byte and ABA changes remain detectable. This is
conflict metadata, not an operation journal. Small maps are inline; larger maps promote to the encrypted
[file version tree](file-index.md), bounded to 1,000,000 intervals and the mount's
managed memory budget.
CAS/merge retry is bounded to 16 attempts. Local data survives a failed fsync while
the shared local inode state remains open. Metadata uses field-based merge: independent fields are preserved; equal
requested values are successful. Automatic mtime/ctime changes do not introduce
conflicts between otherwise disjoint writes.

## Truncate and sparse ranges

Shrink conflicts with writes in the removed range but merges with untouched
prefix writes. Competing EOF-changing operations, including truncate versus
append, allow only the first successful CAS. A prefix writer can preserve a
remote shrink if its own range remains valid. Shrink then extension reads as zero
and never revives the discarded bytes.

Sparse ranges use inode-local `Hole { offset:u64, len:u64 }` records with no S3
data objects. All-hole files have an empty chunk-run list. Holes interleave with
actual chunk boundaries; writes split holes and upload only actual data ranges.
`st_blocks` reports committed data bytes rather than logical hole size. Logical
length is bounded by i64::MAX; indexed files can hold up to 1,000,000 actual extents; gaps represent holes.

## Append: first successful CAS wins

Competing cross-client append generations from the same baseline do not relocate/retry at a
new EOF. The first successful inode CAS wins; an appender observing a changed
baseline size gets EAGAIN. Invocation time and client clocks do not determine
order. The losing caller must handle the error and reopen before reapplying data.

An append can merge with a disjoint existing-region overwrite or unrelated
metadata edit if the baseline size did not change. Conversely, an existing-region
write can preserve another client's newly appended tail. Locally sequential
O_APPEND writes within one mount serialize on its shared inode state and use
that state's current EOF, even across independent opens. No global clock, reservation
service, distributed lock or additional cross-client identity is introduced.

## Open snapshots and polling

All FUSE handles for one inode within one mount share its working state and
anonymous spool, including hard-link aliases and independent opens. Successful
local writes, resize and attribute changes are visible to other local handles
and path/handle stat before fsync. File offsets and status flags belong to the
kernel's individual open file descriptions; dup retains its usual shared offset.
The last handle releases the spool when no operations still hold it; a live
mapping retains its handle even after the application's FD closes.

Different mounts keep independent working states and coordinate committed
changes through inode CAS. Cached bytes in one client can remain old until a
refresh. The low-level Volume::file API still constructs an explicit independent
working session; the FUSE adapter supplies per-mount sharing.
Superseded chunks are deleted after inode CAS; open handles do not prevent
deletion. See the [writeback contract](writeback.md#retired-chunks-and-stale-sessions).

A latest-inode cache pins IDs while handles are open. Every five seconds by
default, bounded background HEAD requests check their ETags; changed inodes are
fetched, authenticated and cached. Polling alone does not replace open sessions;
a chunk 404 can refresh them while preserving nonconflicting local changes. Failed
polls keep their existing snapshots and log errors. No reader safety or global
GC lease is inferred from these local pins.

`mount-s3 --inode-poll-seconds N` adjusts the interval (minimum one second).
An open joining a clean local inode validates the server ETag and, if changed,
replaces the working state for all its local handles. An open joining a dirty
inode sees accepted local changes without silently rebasing, discarding or
committing them; cross-client conflicts are resolved/reported by the barrier.
Cold opens validate the server version through the latest-inode cache. No
cross-client offline-open guarantee is made.

Path and handle attributes use the shared local state while it is active;
otherwise path attributes load committed metadata. Link counts are read from the
backend to reflect namespace edits. FUSE direct I/O and zero
attribute/entry TTL remain enabled. No cross-client live view is imposed on an
already opened file.

## Persisted metadata and permissions

Inode format **v7** retains encrypted `Metadata` in the inode body:

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

ACLs, xattrs, application file locks, fallocate, fixed-capacity statfs reporting,
rollback protection and online orphan/inode reclamation are unsupported. An
[offline collector](garbage-collection.md) inspects and sweeps unreachable objects. Superseded
committed chunks are reclaimed after CAS. Namespace operations are
specified in [directory leases](directory-leases.md).

## Compatibility and validation

Header v4, directory payload v1 and data chunks v2 are unchanged. Inode envelopes
and bodies are v7 so older clients cannot silently ignore file-index state.
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

Rename, rmdir, hard links and symlinks are connected to FUSE, using the rules in
[directory leases](directory-leases.md). No operation ID or interrupted-operation
recovery is used. Online orphan/inode reclamation remains deferred. Open snapshots do
not protect chunks excluded by a successful inode CAS.
