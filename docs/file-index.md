# File extent and last-writer indexes

Inode v7 adds `Indexed(FileRoot)` (enum tag 2). Existing inline and flat chunk
representations retain tags 0 and 1. Header v4, directory payloads and chunk v2
remain unchanged. Clients reject inode v1–v6; no automatic migration is provided.
Existing experimental volumes need an explicit migration/export using their old
client, or recreation. Never mix old and new clients on an active volume.

From the current inode v7 baseline onward, preserve backward compatibility:
new clients must continue reading and writing existing volumes. Routine client
upgrades must not silently rewrite a volume into a representation its existing
clients cannot read. Preserve wire tags, cryptographic algorithm IDs, key
derivation labels and authenticated framing. Any future incompatible extension
requires an explicit, separately documented opt-in upgrade with client capability
checks and a migration path; rejecting the previous version is not a routine
upgrade strategy.

Small files retain the flat representation. Publication promotes a file when it
exceeds 1,024 chunk references, 512 mutation groups, 2,048 last-writer intervals,
or the inline inode encoding no longer fits. Indexed files remain indexed even
when subsequently truncated. Their small data bytes can still be inline.

```
FileRoot {
  size:u64, allocated:u64, naming:NamingConfig,
  extents:Option<Root>, versions:Option<Root>,
  flags:[u64;6], inline:Vec<u8>,
}
Root { child:Child, height:u8 }
Child { first:u64, end:u64, count:u64, id:[u8;16], len:u32 }
Page = Leaf(Vec<Record>) | Branch(Vec<Child>)
Record { start:u64, end:u64, value:Value }
Value = Extent { allocation:[u8;16], index:u64 } | Version(u64)
```

Each tree has at most 1,000,000 records, fanout 128, height at most six, and
64 KiB plaintext pages. These are format/resource bounds, not verified workload
scale. `start..end` ranges and child spans are ordered and nonoverlapping;
child counts and bounds must match the authenticated page. Pages use an
`EEDFSFPG` v1 frame. Leaf and branch tags are 0/1; extent and version tags are 0/1.
Pages are encrypted with the inode's chunk key/profile and compact chunk v2
framing. Names use a key derived from the inode key with HKDF label
`EEDFS/v1/file-index-name`, the HMAC-SHA256 chunk naming domain, a fresh allocation
ID and chunk index zero. File roots never disclose the volume naming key. No unencrypted extent manifest is added.

Extent keys are absolute logical file offsets. Gaps represent sparse zeroes and
consume no data object. Extents refer to whole immutable chunks; this change does
not introduce slice references or change overwrite/append chunk policy. File size
and committed allocated bytes are authenticated in the root descriptor, so stat
need not read the tree. For indexed inline data, extents are absent and allocated
size equals inline length. Large all-hole files have no extent root.

The separate version tree stores last-writer generations for byte intervals,
including intervals beyond current EOF after truncation. Six scalar versions
track EOF and explicit mode/uid/gid/atime/mtime changes. In an indexed wire inode,
the old flat `mutations` vector must be empty. There is no bounded-age history
cutoff; equal-byte edits and ABA retain the existing conflict semantics.

## Reads, writes and publication

Cold reads retrieve only the index paths intersecting their byte range and the
required chunks. Opening and stat read only the inode descriptor. Small indexed
inline data needs no extent page. Active flat/expanded sessions retain the normal
bounded prefetch behavior; a cold indexed read does not prefetch the whole tree.

The first write/merge in a session materializes the file's extent and version
metadata into working maps. This metadata is charged to the mount's managed
memory budget before loading it. Publication compares the resulting records and
batches all changed keys into COW leaf/ancestor edits. Unchanged pages are reused;
a point edit does not upload the entire index. Writers currently read/materialize
the complete metadata index once per cold working state; writer-side lazy maps
and streaming GC remain future performance improvements. The configured memory
budget can reject an index smaller than the format maximum.

New immutable chunks and index pages must upload before the inode's one If-Match
CAS. A failure retains the old root and never deletes predecessor pages/chunks.
Only a confirmed successful CAS permits deletion of exact excluded predecessor
references. Partial failures may leave unpublished pages for offline GC. Metadata
and link updates preserve the file roots. Old readers encountering retired pages
refresh the inode with the same bounded retry/error rules as retired data chunks.
No volume-wide counter, journal, new server, or application lock is introduced.

## Validation

Loopback tests construct files with 5,000 real encrypted chunk objects and 5,000
last-writer groups, verify bounded cold read requests, page reuse on point edits,
disjoint merge/overlap, sparse shrink/re-extension, missing pages, failed inode
publication, retry and offline GC. Codec tests cover canonical framing, bounds,
ordering, summaries and old-version rejection. Mounted checks perform 1,050
append/fsync generations, checksum the file and verify it again after GC/remount.

The 2026-11-27 run passed the full 111-test default Rust suite and six real-store
tests. Actual mounted validation completed 1,050 append/fsync generations and
verified the resulting checksum before and after offline GC/remount. These runs
used Linux 6.12 and the pinned MinIO server; the format maximum is not a benchmark
claim for 1,000,000-record files.
