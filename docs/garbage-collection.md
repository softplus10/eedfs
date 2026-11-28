# Offline object inspection and collection

`cocryptfs gc` reports reachable and unreferenced objects in one volume prefix.
It does not repair namespace operations, replay writes, restore open files, or
change any live inode/header. It adds no journal, remote counter, or service.

```sh
# Use the same S3 environment as format/mount-s3. Reporting performs no DELETE.
cocryptfs gc --prefix test/ --password-file /private/password

# First stop ALL clients of this volume, including mappings and upload workers.
# Keep them stopped until the command finishes.
cocryptfs gc --prefix test/ --password-file /private/password --offline --delete
```

`--offline` asserts that the operator has stopped every client; it does not stop
or discover clients. Deletion requires both flags. Read-only inspection during
activity can fail or produce a report that immediately becomes stale. Successful
inspection does not authorize an online sweep. In particular, root reachability
cannot protect unlinked-but-open files, mapped files or unpublished uploads.

## Scan and deletion

1. Authenticate the current header and verify its root/naming configuration
   against the opened volume.
2. Inventory the prefix using paginated S3 ListObjectsV2 (key, ETag and size).
3. Walk from the root. Authenticate reachable inodes and directory B+tree pages;
   preserve all their referenced objects. Deduplicate inode IDs, including hard
   links. Follow directory entries but not symlink pathname targets. Link counts
   are never used to decide reclamation.
4. Require every referenced object to appear in the inventory. Verify file chunk
   stored lengths against their authenticated inode references. Missing references,
   invalid metadata, inconsistent inode kinds or observed ETag changes abort the
   scan before any deletion. Data chunk payloads are not downloaded/authenticated:
   this command is not a full data-integrity scrub.
5. Repeat the inventory and require exact equality before any DELETE.
6. With both deletion flags, HEAD-check each candidate against its inventoried
   ETag, then issue a standard DELETE. Concurrency is bounded by the volume's
   parallelism. An error stops the sweep and is reported; already completed or
   in-flight deletions may have taken effect. Rerunning is safe while still offline.

The second inventory and pre-delete ETag checks detect some accidental concurrent
changes; they cannot close races with a client that resumes during collection.
HEAD followed by DELETE is not atomic. No conditional-DELETE capability is assumed:
the pinned MinIO release used in validation ignores DELETE's If-Match header.
Immutable object ETags do not change merely because a new inode starts referencing
the object. Offline operation remains a necessary precondition.

Each volume must own its prefix exclusively. The header is always retained.
Unreferenced direct children named with exactly 64 lowercase hexadecimal digits
are reserved CoCryptFS objects and are eligible for deletion. Other keys, including
nested prefixes and unrelated readable names, are reported as ignored and kept.
The collector does not decrypt unreachable inode objects before removing them.

`--max-objects N` bounds inventory size (default 100,000, including ignored keys).
Exceeding the bound or encountering duplicate/incomplete inventory entries aborts
before deletion. Inventories and live marks remain in memory; directory traversal
currently uses the existing materialized listings. Large installations may need
an explicit larger bound and sufficient memory. There is no saved deletion plan
that could accidentally be applied after the volume resumes activity.

## Sizes and permissions

The report includes current listed bytes, reachable stored bytes, unreferenced
bytes, and logical regular-file bytes. Hard links count once; sparse holes count
toward logical size. Listed bytes include ciphertext/metadata and any ignored
keys. Byte totals describe the listed current objects, not provider billing.
The tool does not enforce a volume quota or update a shared usage counter.

Required S3 operations are ListObjectsV2 and GetObject, plus HeadObject and
DeleteObject for sweeping. Bucket version history and multipart uploads are outside this tool's
scope. In a versioned bucket, deleting a current key may only add a delete marker;
reported deleted bytes do not establish that historical storage was reclaimed.
See the official [list](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html)
and [delete](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html)
contracts for these S3 operations.

## Validation

Loopback tests cover paginated inventories, indexed directories, hard-link
deduplication, inline/chunked/sparse files, dangling symlinks, ignored keys,
inspection without mutation, repeat collection, size limits, missing references,
invalid/denied metadata, changed inventories, stale pre-delete ETags, denied
deletion and malformed list responses. Real-store tests exercise conditional
PUT, pre-delete ETag checks and preservation of chunked data. The mounted runner stops all clients,
inspects, sweeps, then remounts to check indexed directories, mapped-file results
and sparse data.

The 2026-11-26 Linux 6.12/MinIO validation passed 101 default Rust tests, six
real-store tests, rustfmt, clippy with warnings denied, build and the development
FUSE smoke test. Mounted validation included the 13 mapping scenarios and the
existing regression groups. Offline collection removed 321 unreachable objects
from the disposable mounted-test volume; indexed directories, mapped results and
sparse contents remained readable after remount.
