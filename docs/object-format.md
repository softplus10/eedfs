# Inode v6 and data-chunk v2 formats

Experimental; inode v1–v5 are rejected. Inode v6 adds sparse holes, mutation
history, link counts, symbolic links and terminal directory deletion, retaining
the encrypted directory lease and numeric POSIX metadata. Header remains v4.
Code lives in `src/format/{header,inode,data_chunk}.rs`. The experimental
[S3/FUSE layer](s3-fuse.md) implements inline directory entries and conditional
object publication and basic POSIX metadata. Multi-object transactions remain deferred.

## Inode envelope

`EEDFSINO` + the 16-byte framing convention in [header format](header-format.md),
version 6, followed by canonical Postcard:

```
InodeObject {
  wrapped_inode_key: SealedRegion,
  protected: SealedRegion,          // profile shared by inode body AND its chunks
  extensions: Vec<Extension>,
}
```

The random 32-byte inode key is wrapped using a master-key-derived wrapping key.
Distinct body and chunk keys are derived from that inode key using HKDF. Wrapping
and body profiles are independently described by the envelope. Creation currently
uses the selected AEAD for both. Both supported AEADs are allowed for wrapping.

Decrypted body has its own `EEDFSINB` frame, version 6:

```
InodeBody {
  id: [u8;16], kind:u8, generation:u64,
  content: InodeContent,
  metadata: Metadata,
  lease: Option<DirectoryLease>,
  deleted:bool, nlink:u32,
  mutations:Vec<Mutation>,
  extensions: Vec<Extension>,
}
DirectoryLease { owner:[u8;16], expires_at:Timestamp }
Mutation { generation:u64, size_changed:bool, attribute_fields:u8, ranges:Vec<(u64,u64)> }
InodeContent = Inline(Vec<u8>) | Chunks(ChunkedContent)
ChunkedContent {
  naming: NamingConfig,             // per-file secret, not the global naming key
  runs: Vec<ChunkRun>,
  holes:Vec<Hole>,
}
Hole { offset:u64, len:u64 }
ChunkRun {
  allocation_id:[u8;16],            // fresh per newly allocated chunk run
  first_chunk:u64,
  plaintext_lengths:Vec<u32>,
}
```

Postcard enum tags are fixed: Inline=0, Chunks=1. Kind: file=1, directory=2, symlink=3;
directory payload encoding is specified in the [S3/FUSE guide](s3-fuse.md). Runs concatenate in vector order, skipping ordered hole ranges at chunk boundaries.
A run's count is its length-vector size. Prefix sums map variable-size chunks to
file offsets. File size is computed, not duplicated. Empty files use Inline([]); all-hole files can have no runs.
COW updates split/reuse old runs and allocate new IDs for new runs. Naming inputs
are allocation ID plus chunk number, not file offset or inode generation.

Limits: inode frame <=1 MiB; inline <=64 KiB; at most 4096 total chunk references
and 4096 runs; each run nonempty, chunk lengths 1 byte through 64 MiB (an implementation safety limit).
At most 4096 hole descriptors are stored; holes have positive lengths and cannot overlap chunks. Logical size must fit i64. No per-file maximum or end index is stored. The last index is first_chunk plus
the length-vector size minus one; chunk sizing is a writer policy.
Index addition and size sums are checked. The current flat list therefore has a
scalability ceiling; a larger index is future work. Object extensions have at most
4096 bytes each and otherwise follow the header extension rules.

## Compact data chunks

```
nonce | ciphertext | tag
```

There is **no magic, frame, version, algorithm descriptor, or extension array in
chunk bytes**. The authenticated inode envelope supplies the suite, and its body
supplies the expected plaintext length. This context is mandatory for parsing.
XChaCha20-Poly1305 overhead is 24+16=40 bytes, AES-256-GCM-SIV overhead is 12+16=28.
Chunks are borrowed slices when parsed; authentication produces owned plaintext.

All chunks referenced by an inode use its common encryption profile. Changing
that profile requires rewriting the referenced chunks. Each encryption uses a
fresh OS-generated nonce. Nonce/tag bytes are per object; profile parameters are
fixed per inode. Shared recipients need the inode location, inode key, filesystem
ID and expected inode ID; the encrypted inode gives them chunk naming information.
No sharing service or grant serialization is implemented.

## Authentication context

AAD is raw domain then canonical Postcard tuple. Version is u16; expected chunk
plaintext length is u32. `metadata` in these contexts excludes the region's own
ciphertext. Every context binds the trusted filesystem ID and exact S3 key.

- `EEDFS/inode-key\0`: `(6, fs_id, object_key,
  (wrapping_algorithm, wrapping_nonce, extensions))`.
- `EEDFS/inode-body\0`: `(6, fs_id, object_key,
  (full_wrapped_key_region, body_algorithm, body_nonce, extensions))`.
- `EEDFS/data-chunk\0`: `(2, fs_id, object_key,
  (common_algorithm, chunk_nonce, expected_plaintext_length))`.

Chunk AAD excludes logical file offset/generation to allow immutable reuse.
AEAD prevents swapping locations or metadata, but does not prevent replay of an
entire old, valid inode/header. Generation alone does not solve rollback.

## Publication boundary

Future storage integration must upload new chunks create-only (`If-None-Match:*`)
then publish the inode with ETag `If-Match`. On conflict, rebase/merge while
retaining staged chunks. Raw S3 ETags are concurrency tokens, not AEAD integrity
checks. The S3/FUSE prototype implements conditional publication and parent-directory
CAS retry. Disjoint same-file writes are merged; append conflicts use first-CAS-wins.
GC remains future work. Interrupted namespace operations are not automatically recovered.

Metadata fields and snapshot/merge policies are defined in
[concurrency and metadata](concurrency-and-metadata.md).

Directory-only lease acquisition and ETag fencing are described in
[directory leases](directory-leases.md). No automatic operation recovery is implemented.

Mutation records form a compact last-writer map, ordered by generation. Byte
intervals do not overlap across records; EOF and each explicit attribute bit have
only one last-writer record. Bits 0..4 identify mode, uid, gid, atime and mtime.
The map has no age cutoff; bounds are 4096 records, 65,536 total intervals and the
inode frame size. See the concurrency contract for merge and ABA semantics.
