# Mount-local resource budgets and usage scans

Resource accounting is local to each `Volume`/mount. No inode scan, shared S3
counter or extra remote commit is needed to allocate a buffer or stage a write.
Different mounts have independent budgets; these options are not a volume quota.

| mount-s3 option | Default | Scope |
| --- | --- | --- |
| `--memory-mib` | 512 | Managed data buffers and estimated inode/index working metadata |
| `--spool-mib` | 4096 | Resident anonymous spool ranges across all files |
| `--s3-requests` | 64 | Total concurrent S3 operations across the shared client |
| `--max-cached-inodes` | 65536 | FUSE inode registry, including referenced and open inodes |

`--parallelism` still bounds each file pipeline. The shared S3 request budget
reserves up to four slots for metadata/control operations, separately from data
transfers, so a blocked chunk upload does not consume the last HEAD/inode slot.
PUT error readback releases its original request permit before acquiring another.

Managed memory reservations are acquired before data download/encryption and
metadata hydration. Persistent metadata uses conservative estimates; one quarter
of the budget is reserved from ordinary allocations for transient I/O/commit
work. Reservation failure returns ENOMEM rather than waiting while holding an
inode mutex and preventing the barrier that would release resources. This is not
an exact process-RSS limit: allocator overhead, SDK buffers, kernel mmap/page
cache and application memory are outside it. OS/container memory limits remain
separate. Password unlocking uses the separate bounded Argon2 policy before
these runtime budgets apply. A maximum-sized chunk needs enough memory for its transient buffers.

Spool ranges are charged in 4 KiB units, merging overlaps. Logical sparse size is
not charged as resident bytes. Reserve space before accepting new data; exhaustion
returns ENOSPC without discarding previously accepted bytes. Truncate/last close
release charges. Successful large-file commits punch out clean committed spool
ranges; clean read caches can also be evicted when another operation needs space.
A spool filesystem supporting Linux hole punching is needed for this eviction;
failed punching keeps the charge, conservatively. Dirty and unpublished data are
never evicted. Applications writing more than the configured dirty budget must
fsync in batches, or configure a larger budget. The benchmark runner explicitly
increases the spool budget for requested large-file benchmarks.

Lookup references are decremented through FUSE FORGET; live file/directory
handles pin their inode registry entries. Zero-reference directory listing entries
can be evicted at the registry limit. Stable inode numbers derive from object
identity; observed hash collisions fail rather than aliasing two identities.
A full registry of still-referenced entries returns ENOMEM. The limit includes the
root and must be at least two.

Directory handles keep a bounded cursor instead of materializing every entry.
Tree-backed readdir retrieves lexicographic batches of at most 128 entries.
Sequential traversal uses its last name; backwards/arbitrary cookies replay
bounded batches. A long backwards seek may therefore take linear work. Concurrent
namespace edits do not provide a stable directory snapshot. Small inline
directories still decode their bounded inline payload.

## Remote current-object usage

```sh
eedfs s3 usage --prefix test/
```

With the normal S3 environment configured, this read-only command sums current
object sizes from paginated ListObjectsV2 responses. It does not GET inode or data
bodies and performs no PUT. `--max-objects` defaults to 1,000,000 and aborts rather
than returning a partial total. The shared connection caches its most recent
prefix result for 60 seconds; separate CLI invocations create fresh connections.
The output includes a scan timestamp. Listing is not an atomic snapshot during
concurrent activity, and current-object bytes include ciphertext, metadata,
unpublished/orphan objects and any foreign keys under the prefix. Historical S3
versions and provider billing overhead are excluded.

Exact logical regular-file size is separately available from offline `gc`, with
hard-linked inodes counted once. No fixed total capacity, strict remote quota or
atomic global byte counter is inferred. FUSE statfs still reports unknown/zero
capacity; the usage command is the supported explicit usage report.

Validation includes cross-file spool pressure, dirty-data preservation, reservation
release, metadata request progress while data is blocked, failed PUT readback with
a one-slot data budget, bounded tree directory batches and cached usage without
inode GETs. Mounted checks enumerate 1,199 entries with a 64-inode registry, seek
backwards in a directory, exercise a 1 MiB spool budget and verify subsequent
commits and clean-cache eviction.

The 2026-11-27 validation passed 111 default Rust tests, six real MinIO tests,
rustfmt, clippy with warnings denied, build and the development FUSE smoke test.
Mounted validation passed 13 mmap scenarios, 1,050 append/fsync generations,
1,199 directory entries with a 64-inode registry, directory seek and the 1 MiB
spool limit. Offline GC removed 283 unreachable objects; the indexed file
checksum and existing mapped/sparse contents were verified again after remount.
