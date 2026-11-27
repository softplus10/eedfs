# Memory mapping on S3 mounts

S3 mounts support read mappings, `MAP_PRIVATE`, writable `MAP_SHARED`, and
`msync`. The Linux kernel must advertise FUSE `DIRECT_IO_ALLOW_MMAP` through
extended INIT negotiation; mounting fails with `EOPNOTSUPP` otherwise. Ordinary
read/write operations retain direct I/O. FUSE writeback-cache mode is not enabled.

## Visibility and durability

Shared mappings of the same inode in one mount use the kernel's shared mapped
pages. Changes become visible to other local mappings immediately. Kernel page
writeback delivers positioned writes into the inode's shared plaintext spool;
ordinary direct reads/writes synchronize overlapping mapped pages through Linux
FUSE. A page write is positioned even if the kernel selects an `O_APPEND` or
`O_SYNC` handle for it.

`msync(MS_SYNC)` drains the selected dirty pages and invokes the existing FUSE
fsync barrier. That barrier waits for uploads and publishes the inode using
`If-Match`. It can also commit other writes already accepted into that inode's
spool. `fsync(fd)` drains mapped writes before the same barrier.
`MS_ASYNC` does not acknowledge remote durability; use a later successful
`MS_SYNC` or fsync when confirmation is required.

`MAP_PRIVATE` modifications never become file writes. Mapping does not extend a
file, and final-page writeback preserves EOF. Access to pages beyond a truncation
in the same mount produces the kernel's usual `SIGBUS` behavior.

A mapping keeps its FUSE handle and working state alive after its original FD is
closed. New mapped writes can therefore arrive after that descriptor's close-time
flush. On the final release, new unattempted mapped writes receive a best-effort
commit; errors are logged. Release never silently retries a failed writeback or
commit barrier. `munmap` provides no durability/error acknowledgement: use explicit
msync/fsync before unmapping to observe success or failure.

## Remote changes and conflicts

Different mounts remain independent. Already mapped pages can remain stale after
a remote commit. Metadata polling is not distributed shared-memory synchronization
and does not promise to refresh a live mapping within the polling interval.
Reopening/remapping a clean file can adopt the latest inode; mappings are not
stable snapshots or guaranteed live remote views.

Dirty page writes use the existing inode mutation history to reject remote
overlap, including changes adopted during a later clean open or disjoint merge.
Kernel writeback can cover a whole page, so conflicts are conservatively detected
at page granularity even when the application changed only a few bytes. Linux can
select another writable mapping's handle for writeback; the adapter therefore
tracks the oldest open `O_RDWR` generation for the inode. An old writable FD can
conservatively fence a newer mapping even if that FD has no mapping. Read-only
opens do not impose this fence. This local bookkeeping is not an application file
lock and introduces no remote coordination service.

Generations committed by the same local working state are excluded from this
remote-overlap check, so repeated msync calls on a long-lived mapping work.
Rejected writeback reaches msync/fsync as an error (`EAGAIN`, or an I/O error
reported by the kernel). A failed generation is not automatically relocated,
overwritten or retried at final release.

Ordinary write and pure append policies remain as specified in the
[writeback contract](writeback.md) and [concurrency policy](concurrency-and-metadata.md).
This feature changes no stored object format and adds no journal, recovery
protocol, external dependency, or application `fcntl`/`flock` support.

## Validation

`scripts/check-mmap.py` exercises three actual mounts. It checks inline and chunked
read/private/shared mappings, direct I/O coherence, partial and repeated msync,
MS_ASYNC followed by fsync, append/sync flags, mappings surviving FD close, final
unmap, rename/open-unlink, partial EOF pages, truncate/SIGBUS, remote overlap after
reopen, old read-only mappings, and stale pages after a disjoint partial msync.
`scripts/bench-s3-fuse.py` runs these checks before its existing mounted regressions.
Session tests also inject missing chunks and failed commit barriers to verify
origin rechecking and the final-release retry guard.

Validation on Linux 6.12 with loopback MinIO passed all 13 mapping checks and
the 32 existing mounted regression groups. The 96 default Rust tests, five
real-store MinIO tests, development FUSE smoke test, rustfmt, clippy with warnings
denied, and build also passed. This validates the tested kernel/store combination;
other S3 providers still need their conditional-write compatibility checks.
