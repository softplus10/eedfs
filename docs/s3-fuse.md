# Experimental S3/FUSE volume

The `format` and `mount-s3` commands connect the existing encrypted header,
inode and compact chunk formats to real S3 object operations. `mount` retains the
old read-only development scaffold. This is a filesystem prototype, not a full
POSIX implementation or a production NAS.

## Local MinIO setup

The validation used MinIO's pinned upstream source tag because its old public
container images and binary download were unavailable in this environment:

```sh
go install github.com/minio/minio@RELEASE.2025-04-22T22-12-26Z
# Set test-only MINIO_ROOT_USER and MINIO_ROOT_PASSWORD privately first.
"$(go env GOPATH)/bin/minio" server /private/disposable-minio-data \
  --address 127.0.0.1:19000 --console-address 127.0.0.1:19001
```

Use the same values for `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY`, set
`S3_ENDPOINT_URL=http://127.0.0.1:19000`, `S3_REGION=us-east-1`,
`S3_FORCE_PATH_STYLE=true` and a disposable `S3_BUCKET`. Initialize once with
`format --create-bucket` before running the tests below. Go source builds identify
the binary as DEVELOPMENT.GOGET; the pinned tag identifies the source version.

## Run against a disposable S3-compatible bucket

Supply provider-issued credentials only through `S3_ACCESS_KEY_ID` and
`S3_SECRET_ACCESS_KEY` (optional `S3_SESSION_TOKEN`). No AWS credential chain.
Configure `S3_BUCKET`, `S3_ENDPOINT_URL`, `S3_REGION`, `S3_FORCE_PATH_STYLE` as for
`s3 check`. A prefix names one volume and must end with `/`.

Omit `--password-file` for hidden input on the controlling terminal. `format`
asks for the new password twice; `mount-s3` and `gc` ask once. `change-password`
asks for the current password and asks for the new password twice, unless the
respective `--password-file`/`--new-password-file` is supplied. `EEDFS_PASSWORD_FILE`
also selects file input. A process with no controlling terminal must supply the
file options; redirected stdin is not used for password input.

```sh
# For unattended use, prepare a private password file outside the repository.
cargo build --release --locked
target/release/eedfs format --password-file /private/password --prefix test/
mkdir -p /tmp/eedfs-mount /private/eedfs-cache
target/release/eedfs mount-s3 /tmp/eedfs-mount \
  --password-file /private/password --prefix test/ \
  --cache-dir /private/eedfs-cache
# In another terminal: write files, fsync, read them, then unmount.
fusermount3 -u /tmp/eedfs-mount
```

`format` refuses an existing header and never overwrites a volume. The optional
`--create-bucket` flag explicitly creates a bucket for test/development setup;
it is not accepted by `mount-s3`. It uses the simple CreateBucket request suitable
for MinIO/us-east-1, not AWS location-constraint provisioning in other regions.
Mounting unlocks the first keyslot. A password file is interpreted as bytes with
one trailing LF and optional preceding CR removed; empty passwords are rejected.
`change-password --prefix test/ --password-file /private/old-password
--new-password-file /private/new-password` replaces that slot with one exact
header CAS. It preserves the master key, naming keys, file objects and other
slots; existing mounts remain usable. A competing header edit is reported as a
conflict, not silently overwritten. Old cached headers/master keys are not revoked.

Writer policy: `--chunk-size` defaults to 8 MiB, accepted range 64 KiB–64 MiB.
It is not persisted as a per-file maximum. Existing variable-size chunks remain
readable with a different writer policy. `--parallelism` defaults to 8 (1–32),
bounding each file upload queue and download batch. `--threads` defaults to 8
FUSE workers (1–64). The shared SDK client pools HTTP connections. Uploads use
shared byte buffers rather than cloning entire ciphertext payloads for retries.
The production client explicitly uses standard SDK retries (at most three
attempts). `--timeout-seconds` defaults to 120 and bounds each S3 operation,
including its retries, rather than a whole file copy. Increasing this setting
cannot fix a sustained outage or inadequate upload bandwidth. Failed PUT logs
include the data/metadata class, byte count, elapsed time and SDK error; an
ambiguous result still requires exact-byte readback, never an unconditional
overwrite or rebase onto a newer ETag.

File creation reuses the parent read for setgid inheritance and the initial
name check, and builds the CREATE reply from the newly published inode. This
saves two sequential metadata GETs per regular-file creation. Directory listing
supports READDIRPLUS/AUTO when offered by the kernel: up to eight child inodes
are read in parallel and returned with their attributes, avoiding a separate
parent lookup for each child. Normal READDIR remains available. READDIRPLUS
attributes and entries, and ordinary directory lookup/getattr replies, have a
one-second TTL so the immediately following stat can reuse them and repeated
path traversal need not reload every ancestor. Other replies retain zero TTL. Remote directory metadata may
therefore remain old for that interval. This does not change the ETag publication
rules. Small-file operations still pay for individual S3
metadata requests and commits, so local-disk latency should not be expected.

For a disposable-bucket transfer regression, run:

```sh
python3 scripts/check-transfers.py --binary target/release/eedfs \
  --password-file /private/password --work-dir /tmp/eedfs-transfer-check
```

This creates a unique volume, writes a 1 GiB file using close as its commit
barrier, creates 171 mixed small files, remounts, times a cold listing with
attributes, and verifies all file hashes. It leaves its isolated volume prefix
in the test bucket; it does not operate on an existing mounted volume. Local
MinIO timings do not predict provider latency or prove an R2 timeout is resolved.

The release build passed this close-only 1 GiB/171-file regression with full
remount/hash verification on local MinIO. A separate counting HTTP proxy test
with 40 files reduced cold enumeration-plus-stat GETs from 298 with zero TTL
to 51 with the directory/READDIRPLUS one-second TTL. These request counts are
local proxy results, not R2 request counts.

A separate isolated R2 volume also passed the 1 GiB/171-file close, remount and
complete hash verification using the release build. The observed timings were
124.6 seconds for the large-file write including close, 379.1 seconds for the
171 mixed small-file writes including close, and 16.6 seconds for cold
enumeration with attributes. This was one run, without a pre-change R2 baseline;
it proves that workload completed, not that all provider timeouts are fixed.
Per-file metadata round trips remain a substantial small-file bottleneck.

See [resource budgets](resources-and-usage.md) for mount-wide memory, spool,
S3 request and inode-registry limits.

## Supported behavior

- Nested directories with encrypted inline entries or immutable B+tree pages.
- Create/open, read/write, partial overwrite, truncate, sparse zero-filled gaps,
  unlink (including open files), rename/replacement, rmdir, hard links, symlinks,
  directory listing, fsync/flush and remount persistence.
- Small files inline in inodes, larger files stored as independently encrypted
  immutable chunks. Separate derived keys for inode bodies and chunk data.
- Read/private/shared memory mappings and msync; see the
  [mapping contract](memory-mapping.md). S3 mounts require a Linux kernel
  advertising FUSE `DIRECT_IO_ALLOW_MMAP`.
- Ordinary reads/writes use FUSE direct I/O; mapped pages are kernel-managed.
  Handles in one mount share an inode working state/spool, so local writes,
  truncate and metadata changes are visible across separate opens and hard links
  before fsync. Different mounts retain independent states. A chunk 404 reloads
  the latest inode, preserving nonconflicting local changes; old snapshots are not
  protected from post-commit chunk deletion. Cached and inline bytes can remain old.
  Opens validate clean local states and join dirty states without losing local data.
  Attribute/entry TTL is zero except for one-second READDIRPLUS and directory
  lookup/getattr replies.
- Local staging uses anonymous mode-0600 files outside the mount; plaintext spool
  contents consume local disk while handles are open. File names are immediately
  unlinked, so releasing the last handle/mapping or process exit releases the spool. Local
  OS page cache may retain plaintext in memory; this is not a remote encrypted cache.
- Uploads are bounded and concurrent; downloads prefetch up to four adjacent old
  chunks for a read range. CPU encryption runs in Tokio blocking workers.

## Commit and conflict behavior

`write()` acknowledges local buffering and queues complete append chunks for
background encryption/upload. `fsync()` seals the remaining short tail, waits for
uploads (`If-None-Match:*`) and publishes the inode using its original ETag
(`If-Match`). A committed partial tail is preserved on later append. Existing
regions are rewritten with COW when overwritten. The per-file mutex defines the
fsync generation boundary; later writes to that file wait for the barrier.
Background failures are retained for fsync/flush. Close attempts the same barrier.

See the [writeback contract](writeback.md) for precise acceptance, publication,
backpressure, error and close semantics. Chunk sizing is a writer policy, not free
small-write performance. Unreferenced uploads can be reclaimed by the
[offline collector](garbage-collection.md).

Stale cross-client writers merge disjoint byte ranges, including within one chunk.
Overlapping writes (including equal-byte writes) and competing append size changes
return `EAGAIN`. Staged changes remain while that mount's inode working state is
open. To discard an unmergeable generation, close all local handles to that inode,
then reopen and reapply against a fresh version. Close-time flush
errors must be checked, and applications should use explicit fsync to observe
conflicts. No application file lock or cross-client atomic append is provided.

Directory insert/remove operations reload the latest parent and retry ETag CAS
up to 16 times, preserving independent entry edits. New inode objects are staged
before linking their directory entry. Identical-byte GET readback resolves a PUT
retry that lost a successful response; unresolved network errors are reported,
not converted into successful commits. The code does not promise recovery of
operations after a client process crash.

## Directory payload v1

A directory inode has kind=2 and Inline content containing a canonical framed
Postcard `Directory { entries: Vec<Entry> }`. Magic `EEDFSDIR`, version=1, standard
16-byte prefix. `Entry { name: String, id:[u8;16], kind:u8 }`. Names are UTF-8,
1–255 bytes, exclude `/`, NUL, `.` and `..`; entries sort strictly by name.
At most 1,024 entries and 64 KiB encoded fit inline. Larger directories promote
to the [directory v2 B+tree](directory-index.md), currently bounded to 1,000,000
entries. Names and IDs remain encrypted in the inode or its pages. There are no
unencrypted S3 filename manifests. Ordinary edits and same-directory rename
copy affected paths and publish one directory inode CAS.

## Deliberate limits

Numeric uid/gid, mode, basic timestamps, chmod/chown and utimes are supported.
See [concurrency and metadata](concurrency-and-metadata.md) for the exact merge,
append, polling and DAC rules. `--inode-poll-seconds` defaults to five seconds;
`--allow-other` explicitly enables other local users while retaining kernel checks.
Rename, rmdir, hard links and symlinks are supported as described in
[directory leases](directory-leases.md). ACLs, xattrs, application locks and
fallocate are unsupported. No cross-directory atomic transaction is promised.
Successful inode commits delete chunks excluded from their exact CAS predecessor.
Deletion failure or interruption can leak objects without failing the commit.
Post-commit cleanup requires S3 DeleteObject permission; denied deletes are
logged and leave the retired objects in storage.
Unlinked inodes and never-committed uploads remain in S3 until
[offline collection](garbage-collection.md); no online/automatic sweep exists.
Link counts are not a reclamation authority after partial failures.
Sparse holes create no data objects. Large files use the [extent/version trees](file-index.md);
logical size is bounded by i64::MAX and each tree by 1,000,000 records.
[Local budgets and s3 usage](resources-and-usage.md) bound managed resources and
report current stored bytes without a shared write counter. Fixed-capacity statfs, rollback protection, encrypted
local cache, key rotation UI or sharing service is included.

## Validation and benchmark

```sh
# Existing disposable bucket and credentials required:
cargo test --locked --test volume_minio -- --ignored --test-threads=1
python3 scripts/bench-s3-fuse.py --binary target/release/eedfs \
  --password-file /private/password --work-dir /tmp/eedfs-test \
  --output /tmp/eedfs-results.json --benchmark --large-mib 10240
cargo run --release --locked --example s3_bench -- --mib 1024 --jobs 8
```

The Python runner creates a unique volume prefix and three actual FUSE mounts,
checks correctness, stops all clients for offline collection, and verifies reads
after remount. Reachable objects remain for inspection. Use a disposable bucket. Benchmarks include
write staging **and remote fsync**, checksum-verified reads after remount, warm
open-handle reads, shared-directory small-file creation, random 4 KiB overwrite
with fsync, and three-client writes. Warm reads use the local spool; remounted
reads clear client caches but not MinIO's OS cache. The direct S3 baseline includes
SDK/checksum overhead and verified object reads, without FUSE or encryption.

The manual `S3 and FUSE integration` GitHub workflow builds a pinned MinIO source
tag and runs real-store tests plus mounted correctness checks. It runs separately
from default CI, whose real-S3 tests are explicitly ignored without a service.
