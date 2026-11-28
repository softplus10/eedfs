# Namespace, sparse and concurrency validation — 2026-11-26

This change connects the selected filesystem policies to real FUSE callbacks:
rename/replacement, rmdir, hard links, symlinks, open-file unlink, object-free
sparse ranges, truncate merging/conflicts, and inode-local leases. Different
names/byte ranges/explicit metadata fields merge; conflicting changes return
EAGAIN. Equal explicit metadata values succeed. Byte/attribute ABA is detected
using a compact last-writer interval/field map, with no age-based history cutoff.
No operation ID, interrupted-operation recovery, or physical GC is implemented.

Source: the commit containing this report (parent `618fb02`). The [raw result](namespace-2026-11-26.json)
includes SHA-256 fingerprints of the measured data-path files. Final namespace-only
edge fixes were checked in a subsequent three-mount run; the data path is unchanged.

## Environment

- Local workstation, **not Proxmox**: Intel Core Ultra 7 155H.
- Linux 6.12.0-211.67.1.el10_2.x86_64, XFS on LUKS.
- Rootless privileged Podman development container, Rust 1.100.0 release build.
- MinIO built from pinned upstream source `RELEASE.2025-04-22T22-12-26Z`
  (binary reports DEVELOPMENT.GOGET, Go 1.27.3).
- HTTP loopback, client/server on the same machine and backing storage.
- 8 MiB writer chunks, parallelism 8, XChaCha20-Poly1305, three real FUSE mounts.
- One measured sample, uncontrolled OS/storage caches. Remount clears client
  caches only. These numbers do not measure physical NIC throughput.

## Correctness

67 default tests and five real MinIO integration tests passed. The final source
also passed fmt, clippy with warnings denied, release build and the read-only
FUSE smoke test. The three-mount runner passed all 23 correctness checks, including:

- Destination replacement while an old destination handle retains its snapshot.
- Cross-directory and same-directory rename, directory replacement, cycle rejection.
- Hard-link identity/counts and unlink of the last name while an open writer keeps
  reading and fsyncing without recreating a name.
- Relative, absolute and dangling symbolic links across clients.
- A 16 GiB logical all-hole file with zero committed data blocks; writing six bytes
  in its middle stores only actual data. The HTTP fixture separately verifies that
  pure extension/shrink/re-extension uploads zero data objects.
- Twelve rounds of three simultaneous same-file commits to disjoint ranges.
- Thirty-six rounds of three-client create/move/link/unlink namespace contention.
- First-CAS-wins append/overlap, opened-reader snapshot retention through polling,
  numeric uid/gid/mode, DAC denial and supplementary-group chgrp.

Fault injection verifies that an interrupted cross-directory rename leaves both
names without automatic repair. Interrupted rmdir preserves its terminal deleted
inode mark, preventing stale creators from resurrecting it. Other unit tests cover
create versus rmdir races, competing directory moves, equal-byte/ABA overlap,
metadata equal-value success, and a handle merging after 70 unrelated commits.

## Performance

All reported writes include the remote fsync commit; reads are checksum verified.
The 10 GiB write took 29.33 s including streaming uploads, with the
final fsync taking 0.096 s. The small final barrier is not the total
network time: network/backpressure runs during write().

| Case | Result |
| --- | ---: |
| 10 GiB sequential write + fsync | 349.1 MiB/s |
| 10 GiB read after client remount | 186.6 MiB/s |
| 10 GiB warm open-handle read | 607.1 MiB/s |
| Three writers, 512 MiB each, aggregate + fsync | 404.7 MiB/s |
| Three clients create 60 × 4 KiB files in one directory | 42.2 files/s |
| 64 MiB write using 4 KiB syscalls + fsync | 141.6 MiB/s |
| 32 × random 4 KiB overwrite, each followed by fsync | 8.57 ops/s |

These are single-run measurements, not a controlled speed comparison with earlier
reports. Random overwrite still rewrites affected immutable chunks; an 8 MiB
writer policy is expensive for isolated 4 KiB fsync workloads.

## Remaining limits

GC/distributed reader protection, xattrs, application file locks, mmap and fallocate
remain excluded. Cross-directory rename is not a multi-object atomic transaction;
partial failures and advisory link counts are documented in [namespace semantics](../directory-leases.md).
Directory movement leases the source's descendant directories as well as parent
and root inodes, so large tree moves incur O(descendant directories) lease I/O.
The flat metadata bounds remain: 1024 entries/directory, 4096 actual chunks and
4096 holes/file, 4096 last-writer groups / 65,536 intervals, and 1 MiB inode frames.
Inode v6 rejects experimental v1–v5; there is no automatic migration.

## Reproduction

Use a disposable MinIO bucket and explicit S3_* credentials. No production
credentials or test passwords are stored in this report.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --release --locked
cargo test --locked --test volume_minio -- --ignored --test-threads=1
python3 scripts/bench-s3-fuse.py --binary target/release/cocryptfs \
  --password-file /private/password --work-dir /tmp/cocryptfs-namespace \
  --output /tmp/cocryptfs-namespace.json --benchmark --large-mib 10240
./scripts/smoke-fuse.sh
```
