# Inode-local directory leases

Directory leases are stored inside the encrypted inode body, not in a separate
S3 object. This is namespace coordination, not application-visible file locking.
There is no operation ID, journal, recovery worker, or automatic roll-forward or
rollback of interrupted operations.

## Stored state and fencing

```
lease: Option<DirectoryLease>
DirectoryLease { owner: [u8;16], expires_at: Timestamp }
```

Each acquisition generates a new nonzero random owner token. The token identifies
a lease holder only; it does not describe an operation or its progress. The inode
ETag is the write fence, so no separately persisted epoch is needed. Only directory
inodes may contain a lease. Leases, ownership tokens and deadlines are encrypted
and authenticated with the rest of the inode body.

`Volume::acquire_directory_lease` attempts one conditional PUT against the loaded
inode ETag. An active lease or competing CAS returns `Conflict` (`EAGAIN` in the
FUSE adapter); it does not wait indefinitely. Default validity is 30 seconds.
`acquire_directory_lease_for` and `renew_directory_lease` accept durations greater
than four seconds and no greater than five minutes.

A `Lease` retains its exact current ETag privately. `write_leased_directory`,
renewal and release use that ETag, never a refreshed ETag belonging to another
holder. Every successful mutation updates the handle's ETag. A stale holder's CAS
therefore fails after takeover. Renewal is explicit, with no heartbeat task.
Dropping a handle does not perform network I/O: its lease simply expires.

The holder stops using a lease two seconds before its deadline. Another writer
can take over two seconds after the deadline. The protocol assumes relative clock
error bounded by two seconds; it does not synchronize client clocks. Suspended
holders must recheck their deadline before each mutation. Clock checks cannot
cancel a PUT already in flight: a timeout/error is not proof that a write was not
applied. ETag fencing prevents it from overwriting a successor's committed version.

Normal directory edits and directory metadata updates reject active leases.
After expiry and the clock margin, an ordinary edit may first clear the lease
using an inode CAS. That invalidates the old holder's ETag without inspecting or
repairing any prior namespace operation. Reads remain available while leased.
Lease-only transitions increment inode generation but do not update POSIX times;
actual directory content changes update mtime and ctime.

## Selected namespace behavior

The following policies are agreed, but the new lease API does not itself add the
FUSE rename, rmdir, hard-link or symlink callbacks:

- Different names in one directory may merge and retry. Competing changes to the
  same entry allow the first successful CAS to win. Conditional removal must
  verify the expected entry identity, not just its name.
- A same-directory rename can replace entries in one inode CAS. A cross-directory
  regular-file rename publishes the destination reference first, then removes
  the source reference. Destination replacement follows POSIX type/empty-directory
  rules. Existing references to the displaced inode remain usable.
- An interrupted cross-directory rename may leave both names present. Do not
  automatically undo or finish it. A failure after destination publication can
  have visible effects even when the caller receives an error.
- Unlink removes a name immediately; open file handles retain their snapshots and
  may continue writing without recreating the name. Physical reclamation is deferred.
- General regular-file hard links and symbolic links are selected for support.
  Application-visible file locks, xattrs, mmap and fallocate remain unsupported.
- Zero-filled sparse ranges should have no corresponding S3 data object. Shrink
  followed by extension must never expose discarded bytes.

For an operation needing several leases, acquire them in a deterministic inode-ID
order. Recheck every held lease before each write; stop on any expired lease or
failed CAS. Holding several leases is not an atomic multi-object transaction.
In particular, stale multi-object writes, concurrent directory ancestry changes,
and a create racing with directory removal need a complete callback protocol;
preflight HEAD checks alone do not solve them. No guarantee for those operations
is claimed by the lease primitive.

Without operation recovery, directory deletion also needs a persistent terminal
state: once removal has committed, expiry must not make the removed directory
writable again. An unfinished deletion can otherwise strand a directory, or a
stale creator can publish an unreachable child. A terminal state is not currently
implemented. No rmdir or directory-move callback is exposed until these rules are
implemented; the lease primitive must not be mistaken for their implementation.

## Compatibility and checks

Inode envelope/body version is now **5**. Versions 1–4 are rejected; recreate
experimental volumes rather than silently ignoring lease state. Header v4,
directory payload v1 and chunk v2 are unchanged.

Tests exercise simultaneous acquisition, active-holder exclusion, renewal and
release, expired takeover, ordinary editing after expiry, stale-holder write /
renew / release rejection, format validation and old-schema rejection. They use
the existing loopback conditional-PUT fixture, with persisted expired timestamps
instead of long wall-clock sleeps.
