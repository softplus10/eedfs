# File writeback contract

This document fixes the current write/fsync/append/error/close contract. The selected [concurrency and metadata policies](concurrency-and-metadata.md)
extend this contract. Namespace transactions remain separate work; orphan/inode
sweeping is provided by the [offline collector](garbage-collection.md).
Inode v7 stores ownership, permissions and timestamps.

## write

Ordinary successful `write()` means the bytes are accepted into the client's
anonymous plaintext spool. It does not promise remote durability or publish a new
inode version. New append data is sealed into immutable snapshots as complete
writer-policy-sized chunks become available. Encryption and create-only S3 PUTs
run in the background while subsequent writes proceed.

The per-file upload window is bounded by `--parallelism`; a full window applies
backpressure before taking another chunk snapshot. Snapshot data is owned by the
upload task, so a later overwrite cannot mutate bytes already being encrypted or
sent. An overwritten snapshot is removed from the proposed references; its remote
object can remain unreferenced if it was never committed. Existing-region overwrites remain
buffered until fsync; this change does not define a new random-write policy.

The spool retains accepted uncommitted bytes locally. Managed
[resource budgets](resources-and-usage.md) bound resident spool ranges and buffers.
Clean committed ranges can be evicted; unpublished dirty data is preserved. There
is no encrypted local cache or crash recovery of uncommitted writes. Reads and local spool writes may fail directly. A failure
discovered after bytes were buffered is latched for fsync and already-known close errors, even
when the corresponding write returned its accepted byte count.

`O_SYNC`/`O_DSYNC` writes invoke the commit barrier before returning, preserving
the stronger synchronous-write behavior.

## fsync and write generations

The FUSE adapter serializes operations using a per-inode working-state mutex
within each mount. The fsync cut is the moment it acquires that mutex: all
previously accepted writes through any local handle belong to its generation.
A competing local write waits and enters the next generation after the barrier
completes. Independent opens and hard-link aliases share data, size, attributes
and spool; FD offsets/flags remain kernel-managed. Different inodes progress
independently. Different mounts retain independent working states and synchronize
through inode CAS/merge. An fsync through any local handle commits the shared inode's pending generation,
including data accepted through another handle. Close only schedules that work.
This implementation does not accept concurrent later writes into another buffer
while that inode's fsync is waiting.

For mapped writes, Linux drains the relevant dirty pages before sending FUSE
fsync. The adapter's mutex boundary includes the page writes it has accepted;
dirty pages still held only by the kernel are not yet spool writes. See
[memory mapping](memory-mapping.md) for MS_SYNC, partial ranges and conflicts.

For a successful fsync:

1. Seal any remaining short regions, including an incomplete append tail.
2. Await the generation's background uploads and newly sealed chunks.
3. Reject the generation if any upload/preparation failed; do not publish references
   to missing or uncertain uploads.
4. Publish the encrypted inode with its original ETag using `If-Match`.
5. Return success only after the inode publication succeeds.

Uploaded but uncommitted chunks do not become filesystem-visible through the old
inode. An fsync on an unchanged, error-free session performs no new publication.
Small inline files publish their bytes in the inode without separate data chunks.
An fsync success relies on the object store honoring its successful PUT contract;
local tests cannot establish a remote provider's storage durability guarantees.

## Retired chunks and stale sessions

After a successful inode CAS, compare the exact CAS predecessor's chunk object
names with the new inode's names and delete only the excluded objects. Cleanup
uses bounded parallel S3 DELETE requests. Failures are logged and do not turn a
successful publication into a failed fsync. A crash before cleanup can leak
objects; there is no cleanup journal or recovery worker. Uploaded but never
committed chunks and unlinked inodes are not swept by this mechanism.

Chunk names are never reused. A stale writer must rebase on the latest inode
after a failed CAS; it cannot restore references from its old baseline. Mutation
history detects overlaps and ABA without fetching retired data. Rebased commits
retire references from their actual CAS predecessor, not their initial snapshot.

Local inode working states do not retain remote chunks. A chunk GET returning 404 reloads the
inode and retries against its new references, with bounded retries. A clean
session replaces its entire spool/cache and adopts the new size, holes and
metadata. A dirty session checks conflicts and reapplies only its local writes,
resize and explicit attributes to the latest version. Conflicts preserve local
changes and return EAGAIN. Upload errors remain latched across refresh.

Internal sealing reads use one baseline; if a chunk disappears, the commit
rebases the whole generation. If a missing chunk is still referenced by the same
current inode ETag, the operation returns an I/O error instead of repeatedly
reloading or substituting zeroes. Missing inodes remain distinct from missing
chunk data. Cached/inline data can remain old until close or a refresh; no stable
snapshot or whole-file version consistency across separate reads is promised.
Within one mount, refresh replaces the state seen by all handles of that inode.
New opens validate clean working states, while dirty states preserve accepted
local changes and latched errors for the next commit barrier.

## Append after a partial fsync

Committed chunk references remain immutable regardless of whether the last chunk
reached the writer's target size. Pure append starts a new chunk run; it does not
fill or rewrite that last committed chunk:

```
write 3 MiB -> fsync -> [3 MiB]
append 2 MiB -> fsync -> [same 3 MiB] [new 2 MiB]
append 8 MiB -> background PUT -> fsync -> [same 3 MiB] [same 2 MiB] [new 8 MiB]
```

Inline files can transition to chunked storage. Explicitly overwriting an old
region still uses COW. This is per-client sequential append behavior, not a new
cross-client atomic `O_APPEND` or same-file merge guarantee.

Frequent small fsyncs create many small references. Files promote into an
[encrypted extent tree](file-index.md), bounded to 1,000,000 extent records and the
configured managed-memory budget. No minimum stored chunk size was introduced.

## Errors and retry

Background encryption/PUT and inode commit errors remain latched in the mount-local
writeback queue. An fsync first reports a previously unobserved background failure;
a subsequent explicit fsync can retry. Another close does not retry that failure.
The barrier drains its upload tasks, including obsolete snapshots, and reports
failure without publishing a new inode. After the error has been observed, an
explicit retry can upload missing regions from the preserved local spool and
reuse successful snapshots. An inode publication error leaves staged chunks available. A stale CAS can
rebase disjoint byte ranges against the latest snapshot; conflicting data,
append size changes and conservative resize conflicts return EAGAIN.

An unmergeable stale inode ETag returns `EAGAIN`. Other I/O/encryption failures reach FUSE as
errors. A failed operation can leave orphan objects, and a transport failure can
have an ambiguous server-side outcome. No rollback or successful-notification
claim is inferred from an error. The existing exact-byte PUT readback resolves
some ambiguous requests; it is not a crash-recovery protocol.

## Close and shutdown

FUSE `flush` schedules an inode commit and returns without acquiring its working
state mutex or waiting for S3. It can report an already-known failure. A successful
close means the work is queued, not that the inode CAS succeeded. Final `release`
also schedules writeback to include mapped pages delivered after an earlier
flush. Neither `close` nor `munmap` is a durability barrier.

The queue takes strong ownership of the session, spool, staged chunks and latched
errors before the last handle goes away. Reopening the same inode on that mount
joins this state; closing and reopening does not discard a conflicting generation.
One commit at a time holds the inode mutex, while different inodes commit in
parallel, bounded by `--parallelism` and the mount-wide S3 request budget.
Explicit fsync waits for its queued generation; O_SYNC/O_DSYNC keep the same
synchronous guarantee. New closes do not silently retry a failed generation.

Queue bookkeeping is reserved before accepting a file session, charged to managed
memory (1 KiB per tracked inode), and bounded by `--max-cached-inodes`. Existing
memory and spool budgets bound pending bytes. Resource-rejected writes and queue
admission can wait for queued work to free space, always outside inode/global
registry locks. If no queued work can make progress, the existing ENOMEM/ENOSPC
limits still apply; a single unclosed file larger than the dirty budget still
needs batched fsync or a larger budget.

Dirty-file timestamp/attribute updates remain with the buffered data and schedule
writeback, so a copy tool setting mtime does not implicitly fsync all its data.
Standalone metadata changes on a clean file keep their synchronous publication.
Namespace creation/link/rename operations still perform their normal ETag CAS.

On normal unmount, the mount process stops admission and drains queued commits.
A failed generation is reported without retry and makes the mount process exit
nonzero. FUSE's destroy callback cannot return a storage error to `fusermount -u`;
the unmount command can finish before the mount process has drained. Wait for the
mount process and check its exit status. Linux ordinary FUSE mounts also do not
forward `syncfs(2)` to the filesystem; do not use a successful shell `sync` as a
substitute for explicit file fsync or waiting for mount-process shutdown. The
syncfs callback handles connections that do forward that operation.

A crash, forced process termination, or mount shutdown with failed commits can
lose uncommitted data. There is no local recovery journal. In particular an
external `mv` may remove its source after close while destination writeback is
still pending. Use explicit fsync when durable completion is required.

## Code and validation

The asynchronous-close implementation passed 119 default Rust tests, six real
MinIO tests, all 13 mmap checks, the mounted namespace/scaling/GC regressions,
and rustfmt/clippy/release builds. Five queue tests cover blocked commits,
cross-inode progress, closed-session ownership, retained failures and explicit
retry, bounded resources, and reclaiming clean bookkeeping.
`scripts/check-async-close.py` additionally gates real S3 requests beneath actual
FUSE mounts: close and dirty-file timestamp updates return while PUT is blocked;
fsync and O_SYNC/O_DSYNC wait; normal shutdown drains; failed shutdown is nonzero.
The release build also passed a 1 GiB plus 171-small-file close-only workload,
normal shutdown and complete remount/hash verification on local MinIO. Those
results include shutdown drain; close timing alone is not a durability measurement.

- `src/handlers/mod.rs`: FUSE trait wiring.
- `src/handlers/file.rs`: file callbacks, including write/fsync/flush/close.
- `src/handlers/directory.rs`: directory callbacks.
- `src/handlers/state.rs`: FUSE inode/handle mapping and per-file session sharing.
- `src/volume/session.rs`: buffers, immutable snapshots, bounded uploads, barriers.
- `src/volume/writeback.rs`: bounded cross-inode queue, retained failures and shutdown drain.
- `src/volume/mod.rs`: encrypted inode/directory loading and CAS publication.
- `src/storage/s3.rs`: pooled SDK transport and bounded conditional object I/O.

Controlled loopback S3 tests gate uploads and inject PUT errors. They verify
pre-fsync invisibility, a waiting fsync, bounded backpressure, immutable in-flight
snapshots, truncate/re-extend zeroing, error delivery, retries and unchanged old
append references. Real MinIO tests also verify 3 MiB fsync followed by 2 MiB
append without replacing the first reference. Mounted-client checks exercise
mid-stream fsync visibility and eventual background publication after close.

Retirement tests cover excluded versus retained references, failed publication,
failed/idempotent deletion, cleanup delayed across a later commit, same-chunk
stale merges and overlap rejection. Refresh tests cover cached-index invalidation,
inline/sparse EOF changes, local dirty data/metadata/resize preservation, latched
upload errors and a missing chunk in the current committed version. Real MinIO
checks exercise stale readers after retirement; the three-mount runner forces a
404 beyond the prefetch window and verifies that earlier cached bytes refresh too.

Transport fault tests also cover a lost chunk PUT response resolved by exact
readback, a connection dropped before chunk publication with a successful retry,
a lost inode PUT response confirmed before cleanup, an applied inode PUT whose
failed readback leaves an explicitly ambiguous error without deleting old chunks,
and a truncated chunk download that never enters the plaintext cache.

Mounted local-sharing checks cover pre-fsync reads/stat/resize through separate
opens and hard-link aliases, independent FD flags/offsets and dup offsets,
O_TRUNC visibility to existing readers, clean-open adoption of remote versions,
eight concurrent cold opens and eight local appenders. Workers keep handles open
until all local reads succeed and another mount confirms that uncommitted data
is still invisible. A successful explicit fsync publishes the shared generation; close publication is eventual.
