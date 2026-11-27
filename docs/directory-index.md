# Encrypted directory index

Small directories retain the existing `EEDFSDIR` v1 sorted inline payload, at
most 1,024 entries and 64 KiB encoded. An edit exceeding either bound promotes
the directory to an immutable B+tree. Names remain UTF-8 and 1–255 bytes.

The directory inode still uses inode v7 with Inline content. An `EEDFSDIR` v2
root descriptor replaces the v1 payload for indexed directories:

```
Root { child: Child, height:u8, entries:u64 }
Child { first:String, page:PageRef }
PageRef { id:[u8;16], len:u32 }
```

`first` is the subtree's minimum name. Height zero identifies a leaf root.
The current policy bounds a directory to 1,000,000 entries and height to six.
This is a format/resource limit, not a benchmark claim for that scale.

Each page has an `EEDFSDPG` v1 frame containing a fixed-tag Postcard enum:
`Leaf(Vec<Entry>)` (tag 0) or `Branch(Vec<Child>)` (tag 1). Leaves and branches
contain 1–64 items in strict name order, with a 64 KiB plaintext cap. Reference
lengths, depth, name ordering and total listing counts are checked. Listing also
rejects repeated page IDs. Empty directories use the v1 inline payload.

Pages use the inode's chunk encryption key/profile and chunk v2 AEAD framing.
Their S3 names use the header's secret naming configuration, a fresh random
128-bit allocation ID per page and chunk index zero. AAD binds the filesystem,
actual object key, profile and plaintext length. Neither names nor plaintext
page indexes are published outside encryption.

## Publication and concurrency

Lookup reads only the root-to-leaf path. Entry insertion/removal copies the
affected leaf and its ancestor path into new immutable objects; overfull pages
split. Empty pages are pruned and a root with one remaining child collapses.
Deletion does not eagerly redistribute or merge partially populated pages.

After all new pages have uploaded, one ETag-conditional directory inode PUT
publishes the root. Only a confirmed successful CAS permits deleting excluded
pages. A stale writer retries against the latest root instead of restoring an
old page reference. A 404 while reading a superseded tree reloads the inode and
retries, bounded to 16 attempts. A missing page still referenced by an unchanged
current inode is an I/O error.

Namespace operations retain their existing inode-local lease rules. Batched
edits, including same-directory rename/replacement, stage path copies and publish
them with one exact lease ETag CAS. Cross-directory rename still publishes the
destination first and is not atomic across parents. Ancestry checks still visit
the affected directory subtree under the topology lease.

Full directory listing remains O(number of pages). FUSE directory handles use
bounded name cursors and read at most 128 entries per batch; the bulk Volume::list
API still materializes the entry list for callers that request it. The bulk `write_leased_directory` API rebuilds an index;
ordinary namespace callbacks use path edits. There is no interrupted-operation
recovery or online orphan sweep. Unpublished pages and failed cleanup can leak
objects; an [offline collector](garbage-collection.md) can reclaim them.

## Compatibility

Header v4, inode v7, inline directory v1 and data chunk v2 remain unchanged.
New clients read existing inline volumes and promote directories when necessary.
Older clients reject directory v2 payloads; do not mix them with indexed writers.
File extents and mutation history use a separate [file index](file-index.md).

## Validation

Loopback tests build a 4,100-entry height-two tree, bound lookup request count,
split a full leaf/branch without rewriting the whole directory, and check failed
page upload/publication, stale CAS, empty-leaf pruning and root collapse. Indexed
namespace tests cover rename within/across parents, hard links, subdirectories
and concurrent creates. Codec tests reject invalid bounds, ordering, truncation
and trailing bytes.

The real MinIO/FUSE runner creates 1,200 files through three mounts, checks
boundary lookups, listing, rename and unlink, then replaces the password while
mounts are active. The old password is rejected and a new-password remount reads
the indexed directory. Password tests also verify unchanged file objects and
master/naming keys, preserved existing mounts and one winner for competing changes.
