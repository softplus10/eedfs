# File writeback contract

This document fixes the current write/fsync/append/error/close contract. The selected [concurrency and metadata policies](concurrency-and-metadata.md)
extend this contract. Namespace transactions and GC remain separate work.
Inode v6 stores ownership, permissions and timestamps.

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
object can remain unreferenced until future GC. Existing-region overwrites remain
buffered until fsync; this change does not define a new random-write policy.

The spool still keeps the open file's logical contents locally. Pipeline uploads
do not implement cache eviction, encrypted local caching, or crash recovery of
uncommitted writes. Reads and local spool writes may fail directly. A failure
discovered after bytes were buffered is latched for the next fsync/flush, even
when the corresponding write returned its accepted byte count.

`O_SYNC`/`O_DSYNC` writes invoke the commit barrier before returning, preserving
the stronger synchronous-write behavior.

## fsync and write generations

The FUSE adapter serializes operations using a per-open-session mutex. The fsync
cut is the moment it acquires that mutex: all previously accepted writes belong
to its generation. A competing write through that same handle waits and enters
the next generation after the barrier completes. Other opens use their own
snapshots and synchronize through inode CAS/merge. Different opens have independent snapshots/sessions and can progress; duplicated
descriptors of the same FUSE handle share the session.
This implementation does not accept concurrent later writes into another buffer
while the same handle's fsync is waiting.

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

Frequent small fsyncs create many small references. The existing flat 4,096-chunk
limit still applies; the format needs a larger index before supporting arbitrary
fragmentation. No minimum stored chunk size or per-file maximum was introduced.

## Errors and retry

Background encryption/PUT errors are retained until fsync/flush reports failure.
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

## Close

FUSE `flush` attempts the same commit barrier on descriptor close and returns its
error to the caller. `release` disposes of handles/resources; it does not hide a
flush failure by silently retrying publication. Applications must check close
errors and use explicit fsync when they need a durability confirmation before
closing. Crash/process termination before successful fsync/flush can lose local
buffered writes; cleanup of anonymous spool files is automatic.

## Code and validation

- `src/handlers/mod.rs`: FUSE trait wiring.
- `src/handlers/file.rs`: file callbacks, including write/fsync/flush/close.
- `src/handlers/directory.rs`: directory callbacks.
- `src/handlers/state.rs`: FUSE inode/handle mapping and per-file session sharing.
- `src/volume/session.rs`: buffers, immutable snapshots, bounded uploads, barriers.
- `src/volume/mod.rs`: encrypted inode/directory loading and CAS publication.
- `src/storage/s3.rs`: pooled SDK transport and bounded conditional object I/O.

Controlled loopback S3 tests gate uploads and inject PUT errors. They verify
pre-fsync invisibility, a waiting fsync, bounded backpressure, immutable in-flight
snapshots, truncate/re-extend zeroing, error delivery, retries and unchanged old
append references. Real MinIO tests also verify 3 MiB fsync followed by 2 MiB
append without replacing the first reference. Mounted-client checks exercise
mid-stream fsync visibility and successful close without a final explicit fsync.
