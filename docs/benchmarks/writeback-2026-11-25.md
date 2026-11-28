# Streaming writeback validation — 2026-11-25

Source: `7edfa3e`. [Raw results](writeback-2026-11-25.json),
[writeback contract](../writeback.md), [historical pre-pipeline run](s3-fuse-2026-11-24.md).

Complete append chunks now upload during writes. fsync seals the partial tail,
waits for that file's uploads and commits its inode. Committed partial chunks are
not filled or rewritten by pure append. FUSE handlers moved to `src/handlers/`,
file state to `src/volume/`, S3 transport to `src/storage/`; wire formats are unchanged.

## Correctness

- 47 default tests passed, including six controlled S3 upload-gate/failure tests;
  strict Clippy, formatting and the retained read-only mount smoke passed.
- Three explicitly invoked real-MinIO tests passed. They cover conditional PUT,
  COW/sparse/truncate/conflict behavior and 3 MiB fsync followed by 2 MiB append,
  preserving the original committed chunk references.
- Three mounted processes checked cross-client data, nested directories,
  overwrite/truncate/sparse gaps, stale-writer EAGAIN, unlink, remount, mid-stream
  fsync visibility and successful close without a final explicit fsync.
- The 10 GiB file matched its complete SHA-256 after remount and on warm reread.
  Each concurrent 512 MiB writer's file matched when read through another mount.
- Controlled fixture tests verified upload before inode publication, a blocked
  fsync, bounded queue backpressure, immutable in-flight snapshots, zeroing after
  truncate/re-extend, background error delivery and retry without redundant PUTs.
  Fault injection uses a loopback S3 fixture, not modified MinIO internals.

## Environment and method

Same development machine class as the historical run: Intel Core Ultra 7 155H,
22 visible logical CPUs, Linux, rootless privileged Podman/Alpine, Rust 1.100.0,
portable release build (thin LTO, one codegen unit). Real single-drive MinIO from
upstream `RELEASE.2025-04-22T22-12-26Z` source, HTTP loopback. MinIO objects and local
plaintext spools share the XFS/LUKS filesystem. No CPU affinity, OS cache drop,
physical network or TLS measurement. Host load/caches are uncontrolled.

XChaCha20-Poly1305, 8 MiB append target, eight in-flight uploads and eight FUSE
workers per mount. Each row is one run, not a median. FUSE direct I/O is enabled.
Write timings include local writes, backpressure/encryption/uploads, checksum
calculation, final remote fsync and close. `write_seconds` replaces the runner's
old `stage_seconds` label: it is no longer a local-only phase. Read timings start
after open; remount clears client state but not server OS caches. Warm reads use
the same handle's plaintext spool, not another S3 download.

## Measurements

| Workload | Seconds | MiB/s |
|---|---:|---:|
| 10 GiB write + fsync | 33.50 | 305.7 |
| 10 GiB read after remount | 62.08 | 165.0 |
| 10 GiB warm same-handle read | 23.41 | 437.5 |
| 3 × 512 MiB write + fsync, aggregate | 3.26 | 471.5 |
| 64 MiB in 4 KiB writes + final fsync | 0.34 | 188.5 |

The 10 GiB write spent **33.38 seconds in write calls** and
**0.118 seconds in final fsync**. Network/crypto work occurs
inside and alongside write processing; a short final fsync does not imply that
the data reached S3 at an unlimited rate.

Shared-directory creation of 60 fsynced 4 KiB files across three clients:
**51.2 files/s**.
32 random 4 KiB overwrites with fsync after each:
**9.34 operations/s**. Existing-region
COW and its chunk amplification were not redesigned in this change.

## Interpretation

The implementation demonstrates the agreed write/commit behavior. It does not
establish a large throughput gain or 500 MiB/s single-client performance. The
historical run took 34.93 seconds for 10 GiB versus 33.50 seconds here,
but these are uncontrolled single runs on different days, not a controlled A/B
comparison. Read and aggregate-write values also vary; they are reported in full
rather than attributed to an unmeasured cause. Profiling is still needed to split
spool I/O, copying, encryption, FUSE and S3 overhead.

The scope excludes new same-file merge, atomic cross-client append, read-cache
coherence policies, rename transactions, POSIX metadata or GC. All temporary test
mounts and the disposable MinIO store are cleaned up after validation.

## Reproduce

With MinIO and the disposable bucket configured as in the [S3/FUSE guide](../s3-fuse.md):

```sh
cargo test --locked --all-targets
cargo test --locked --test volume_minio -- --ignored --test-threads=1
cargo build --release --locked --bin cocryptfs
python3 scripts/bench-s3-fuse.py --binary target/release/cocryptfs \
  --password-file /private/password --work-dir /tmp/cocryptfs-writeback \
  --output /tmp/writeback.json --benchmark --large-mib 10240
```
