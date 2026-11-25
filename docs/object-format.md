# Inode v4 and data-chunk v2 formats

Experimental; inode v1–v3 are rejected. Inode v4 adds numeric ownership,
permissions and timestamps. Header is independently versioned at v4.
Code lives in `src/format/{header,inode,data_chunk}.rs`. The experimental
[S3/FUSE layer](s3-fuse.md) implements inline directory entries and conditional
object publication. POSIX metadata and multi-object transactions remain deferred.

## Inode envelope

`EEDFSINO` + the 16-byte framing convention in [header format](header-format.md),
version 4, followed by canonical Postcard:

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

Decrypted body has its own `EEDFSINB` frame, version 4:

```
InodeBody {
  id: [u8;16], kind:u8, generation:u64,
  content: InodeContent,
  metadata: Metadata,
  extensions: Vec<Extension>,
}
InodeContent = Inline(Vec<u8>) | Chunks(ChunkedContent)
ChunkedContent {
  naming: NamingConfig,             // per-file secret, not the global naming key
  runs: Vec<ChunkRun>,
}
ChunkRun {
  allocation_id:[u8;16],            // fresh per newly allocated chunk run
  first_chunk:u64,
  plaintext_lengths:Vec<u32>,
}
```

Postcard enum tags are fixed: Inline=0, Chunks=1. Kind: file=1, directory=2;
directory payload encoding is specified in the [S3/FUSE guide](s3-fuse.md). Runs concatenate in vector order.
A run's count is its length-vector size. Prefix sums map variable-size chunks to
file offsets. File size is computed, not duplicated. Empty files use Inline([]).
COW updates split/reuse old runs and allocate new IDs for new runs. Naming inputs
are allocation ID plus chunk number, not file offset or inode generation.

Limits: inode frame <=1 MiB; inline <=64 KiB; at most 4096 total chunk references
and 4096 runs; each run nonempty, chunk lengths 1 byte through 64 MiB (an implementation safety limit).
No per-file maximum or end index is stored. The last index is first_chunk plus
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

- `EEDFS/inode-key\0`: `(4, fs_id, object_key,
  (wrapping_algorithm, wrapping_nonce, extensions))`.
- `EEDFS/inode-body\0`: `(4, fs_id, object_key,
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
Crash recovery and GC remain future work.

Metadata fields and snapshot/merge policies are defined in
[concurrency and metadata](concurrency-and-metadata.md).
