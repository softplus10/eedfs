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

```sh
# Prepare a private password file outside the repository first.
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

Writer policy: `--chunk-size` defaults to 8 MiB, accepted range 64 KiB–64 MiB.
It is not persisted as a per-file maximum. Existing variable-size chunks remain
readable with a different writer policy. `--parallelism` defaults to 8 (1–32),
bounding each commit's in-flight uploads/downloads. `--threads` defaults to 8
FUSE workers (1–64). The shared SDK client pools HTTP connections. Uploads use
shared byte buffers rather than cloning entire ciphertext payloads for retries.

## Supported behavior

- Nested directories with encrypted inline directory entries.
- Create/open, read/write, partial overwrite, truncate, sparse zero-filled gaps,
  file unlink, directory listing, fsync/flush and remount persistence.
- Small files inline in inodes, larger files stored as independently encrypted
  immutable chunks. Separate derived keys for inode bodies and chunk data.
- FUSE direct I/O prevents the kernel page cache from hiding remote consistency.
  Open handles share a per-client session. Reads of an open handle see its snapshot;
  a new open after the last close reloads the inode. Attribute/entry TTL is zero.
- Local staging uses anonymous mode-0600 files outside the mount; plaintext spool
  contents consume local disk while handles are open. File names are immediately
  unlinked, so closing the last handle or process exit releases the spool. Local
  OS page cache may retain plaintext in memory; this is not a remote encrypted cache.
- Uploads are bounded and concurrent; downloads prefetch up to four adjacent old
  chunks for a read range. CPU encryption runs in Tokio blocking workers.

## Commit and conflict behavior

`write()` acknowledges local staging. Successful `fsync()` or `flush()` waits for
new chunks (`If-None-Match:*`) and then publishes the inode with its original
ETag (`If-Match`). Only changed writer-sized regions are rewritten when old
chunks align; unmodified chunks are reused. Partial overwrites of a large chunk
therefore incur read/modify/write amplification. A new allocation ID is generated
for each commit's new chunk run. The chunk size is a policy tradeoff, not free
small-write performance.

A stale same-file writer gets `EAGAIN`; no automatic merge of same-file data is
claimed. Its staged local changes remain until the handle is closed. The caller
must close/reopen and reapply changes against a fresh version. Close-time flush
errors must be checked, and applications should use explicit fsync to observe
conflicts. No distributed lock or cross-client atomic append is provided.

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
At most 1,024 entries and 64 KiB encoded per directory. Names and IDs are encrypted
inside the directory inode. There are no unencrypted S3 filename manifests.

## Deliberate limits

Fixed mount-owner identity, file mode 0644 and directory mode 0755; requested
creation modes are not persisted. chmod/chown/utimes, timestamps, xattrs,
symlinks, hard links, mmap/writeback cache, locks, rename, rmdir and POSIX atomic
namespace transactions are not implemented. File unlink removes only its directory
entry. No safe GC/reclamation exists: unlinked inodes, old chunks and failed staged
writes remain in S3. Duplicate create attempts may leave unlinked inode objects.
The flat inode index allows at most 4,096 chunks; writer policy bounds writable
file size accordingly. No storage capacity report, rollback protection, encrypted
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
checks correctness, and unmounts them on exit. It leaves remote objects for
inspection because no GC exists. Use a disposable bucket. Benchmarks include
write staging **and remote fsync**, checksum-verified reads after remount, warm
open-handle reads, shared-directory small-file creation, random 4 KiB overwrite
with fsync, and three-client writes. Warm reads use the local spool; remounted
reads clear client caches but not MinIO's OS cache. The direct S3 baseline includes
SDK/checksum overhead and verified object reads, without FUSE or encryption.

The manual `S3 and FUSE integration` GitHub workflow builds a pinned MinIO source
tag and runs real-store tests plus mounted correctness checks. It runs separately
from default CI, whose real-S3 tests are explicitly ignored without a service.
