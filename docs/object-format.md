# Inode and data-chunk object formats, version 1

These codecs specify stored envelopes and a minimal inode body. They use the
same Serde/Postcard encoding, canonical decoding, extension rules, and bounded
allocation helpers as the header. The header remains byte-compatible v3; object
versions are independent. No encryption, key derivation, HMAC naming, S3 object
GET/PUT, FUSE file operations, or garbage collection is implemented here.

## Framing

Every container has a 16-byte prefix:

```text
magic[8] | version:u16 LE (=1) | flags:u16 LE (=0) | payload_len:u32 LE
Postcard payload, in the field order shown below
```

Magic values are `EEDFSINO` for stored inode envelopes, `EEDFSINB` for plaintext
inode bodies, and `EEDFSCHK` for stored data-chunk envelopes. The inode body is
encoded only as input to encryption; it is not uploaded as a separate object.
Exact lengths, canonical Postcard encoding, type magic, and version are enforced.

## Stored inode envelope

```text
InodeObject {
    wrapped_inode_key: SealedRegion,
    protected: SealedRegion,
    extensions: Vec<Extension>,
}
SealedRegion {
    algorithm: Algorithm,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>, // appended authentication tag included
}
Algorithm { id:u16, parameters:Vec<u8> }
Extension { kind:u16, required:bool, value:Vec<u8> }
```

The master-key-derived wrapping key will unwrap a per-inode key. Separate
purpose-derived keys from that inode key will protect the inode body and its
data chunks. Key generation, derivation labels, actual cryptographic algorithms,
and suite-specific checks remain future crypto-layer work. Both sealed regions
have independent nonces and tags, and each envelope identifies its algorithm
rather than relying on mutable header defaults.

The stable inode object key is the inode's publication point. Later writers can
upload immutable chunks and conditionally replace the inode with `If-Match`.
New chunks must use create-only PUT (`If-None-Match: *`) to preserve immutability.
The codec does not perform this transaction or retries.

## Minimal plaintext inode

```text
InodeBody {
    id: [u8;16],
    kind: u8,           // 1=file, 2=directory
    generation: u64,
    content: InodeContent,
    extensions: Vec<Extension>,
}
InodeContent =
    Inline(Vec<u8>)             // fixed Postcard variant tag 0
  | Chunks(Vec<ChunkReference>) // fixed Postcard variant tag 1

ChunkReference {
    object_key: String,
    plaintext_len: u64,
}
```

Only inline data and a flat ordered list of whole-chunk references are included.
There are no POSIX ownership/mode/timestamps, directory-entry schema, share-name
field, extent offsets/slices, sparse ranges, tree indexes, snapshots, reflinks,
or per-chunk key records. These require further design rather than speculative
fields in this initial format. Directory content is opaque bytes at this stage;
kind 2 does not mean directory operations are implemented.

Postcard encodes structs in field order with no field names/count. The content
variant tags **0 and 1 are part of the v1 schema**: declaration reordering or
inserting a variant is not allowed without format evolution. Other integers use
Postcard unsigned varints; fixed byte arrays are raw bytes. Inline/chunk byte
blobs use Serde's bulk-byte API, preserving the same Postcard representation as
`Vec<u8>` while avoiding per-byte operations for large ciphertexts.

Size is derived, not separately persisted: inline byte length or the checked sum
of referenced plaintext lengths. Chunk references concatenate in list order,
with no gaps or overlaps to describe. Empty files use `Inline([])`; an empty
chunk list or zero-length chunk reference is rejected. Repeated references to the
same immutable object are permitted.

Each reference stores the **actual S3 object key**, so a file-sharing recipient
need not receive the filesystem-wide naming key. The future naming module can
compute keys from allocation IDs/chunk numbers; this reference format does not
require recomputing names or deriving identity from them.

## Data chunk envelope and reference linkage

```text
DataChunkObject {
    protected: SealedRegion<MAX_CHUNK_CIPHERTEXT>,
    extensions: Vec<Extension>,
}
```

The const-generic SealedRegion limit affects resource validation, not wire fields.
Header/inode metadata retain their 1 MiB ciphertext budget; chunk ciphertext can
exceed that budget, including the 8 MiB sizes discussed during design.
The decrypted chunk payload is raw bytes: it has no extra container or inode data.

A future read path will:

1. Authenticate/decrypt the inode, then decode `InodeBody`.
2. For `Inline`, use those bytes directly. For `Chunks`, fetch each listed key.
3. Decode `DataChunkObject` and build its AAD with `ChunkReference::aad`.
4. Authenticate/decrypt with the file's chunk-data key and the stored nonce.
5. Call `ChunkReference::validate_plaintext` on the verified plaintext, then
   concatenate in reference order.

The helper checks exact length, not cryptographic authenticity: AEAD verification
must precede use of the plaintext. The tests use already-known plaintext fixtures,
not a fake encryption implementation or a live S3 service.

Logical overwrite can replace an affected whole chunk with a new immutable object
and publish an updated reference list. Inline-to-chunks and chunks-to-inline
transitions preserve inode ID and change only content/generation. This supports
a future COW publication protocol, not a completed COW filesystem. Old data is
not deleted automatically; reader-safe reclamation remains separate work.

## Authentication context

Context values must come from the caller's trusted header/reference and the exact
S3 key used for access, not solely from unauthenticated object fields. Root inodes
need no public inode ID: the header already supplies their authenticated object
location. After decryption, the body ID should also match a directory reference
when one is available.

Each AAD consists of a raw domain label including its trailing zero byte followed
by this Postcard tuple. No discovery prefix is part of AAD.

```text
inode key wrapping:
"EEDFS/inode-key\0" || Postcard((
    VERSION, filesystem_id, object_key,
    (wrapping_algorithm, wrapping_nonce, inode_extensions)
))

inode body:
"EEDFS/inode-body\0" || Postcard((
    VERSION, filesystem_id, object_key,
    (wrapped_inode_key, body_algorithm, body_nonce, inode_extensions)
))

data chunk:
"EEDFS/data-chunk\0" || Postcard((
    VERSION, filesystem_id, object_key,
    (chunk_algorithm, chunk_nonce, chunk_extensions)
))
```

VERSION is u16; filesystem_id is 16 bytes; object_key is a UTF-8 string. Domain
separation prevents cross-type use. The wrapped key's ciphertext is excluded
from its own AAD, but included in the body's AAD. Body/chunk ciphertext is already
authenticated by AEAD and excluded from its own AAD. Pre-encryption AAD construction
permits the corresponding ciphertext field to be empty.

Chunk AAD deliberately excludes current file offset and inode generation, allowing
an immutable object to remain valid when referenced at a different offset. No
storage naming key is needed to build AAD. Updating an inode's wrapped key or its
extensions changes the body's AAD and therefore requires fresh body authentication.
AEAD alone does not prevent replay of an old valid object; generation is not a
trusted monotonic counter or a replacement for ETag concurrency control.

## Initial limits and validation

| Item | Limit |
| --- | --- |
| Inode envelope / encoded inode body | 1 MiB |
| Inline content | 64 KiB |
| Flat chunk reference list | 4096 entries |
| Each chunk's plaintext length in a reference | 1 byte–64 MiB |
| Chunk ciphertext | 64 MiB + 64 bytes tag allowance |
| Complete chunk envelope | 65 MiB |
| Nonce / algorithm parameters | 64 bytes / 4096 bytes |
| Each object extension value | 4096 bytes |
| Extensions per container | 64 |
| S3 object key | 1–1024 UTF-8 bytes |

These are initial format/resource caps, not writer chunk-size/inline policies.
The flat list cannot describe arbitrarily large/fragmented files; an index format
is intentionally deferred. Algorithm implementations must enforce actual nonce,
key and tag lengths and verify that decrypted payloads fit their references.

Bytes are borrowed from input and length-checked before being copied; sequence
counts are checked before allocations. Encoder size measurement occurs before
output allocation. Unknown optional extensions survive re-encoding; unknown
required ones, duplicate/out-of-order extension IDs, unknown inode kinds/content
tags, malformed lengths, trailing bytes and noncanonical encodings are rejected.
`InodeBody`/`InodeContent` debug output reports lengths/counts rather than file
contents. Plaintext body buffers still require future secret-lifetime management.
