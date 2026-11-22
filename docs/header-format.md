# EEDFS binary header, version 1

This specifies the initial header container and its extensibility rules.
`src/format/header.rs` implements the codec using the Rust standard library only:
no Serde, JSON, native struct dumps, or new dependencies. This is an early format,
not a claim of a completed or reviewed cryptographic protocol.

The codec does **not** derive keys, encrypt, authenticate, upload, or unlock a
filesystem. Ciphertext and algorithm parameters are bounded opaque bytes. A
successfully decoded header remains untrusted until authenticated by a future
cryptographic implementation. No CLI currently writes these headers.

## Contents

The public header contains the filesystem ID, an array of keyslots, the encrypted
configuration envelope, and optional extension records. Each keyslot contains a
stable slot ID, a KDF descriptor, a master-key wrapping envelope, and extensions.
The master key itself must never be stored in plaintext in the public header.

The protected configuration contains **only the root inode's S3 object key and
default inode/data encryption descriptors**, plus extensions. It is serialized,
then encrypted into the public header's protected region. It is not a separate
S3 object. It contains no root inode key: the root inode envelope will carry its
own master-key-wrapped inode key. Endpoint, bucket, credentials, directory
contents, inode layout, and chunk indexes are outside this format.

## Integer and byte encoding

All integers use fixed-width unsigned little-endian encoding. No native `usize`,
pointers, padding, Rust enum layout, or alignment requirements appear on disk.
A `blob` is `length: u32` followed by exactly that many bytes. Strings are UTF-8
blobs. IDs are opaque 16-byte values, with no dependence on a UUID library.

Both outer containers start with:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | Magic: ASCII `EEDFSHDR` or `EEDFSCFG` |
| 8 | 2 | Format version: 1 |
| 10 | 2 | Reserved flags: 0 |
| 12 | 4 | Body length, excluding this 16-byte prefix |
| 16 | variable | Body |

The exact declared length is required. Trailing bytes, unknown versions, and
nonzero reserved flags are errors.

## TLV records

A record is `type: u16, flags: u16, length: u32, value: [u8; length]`.
Flag bit 0 means required; all other flag bits must be zero. Required core
records occur exactly once, in the order below, with flags equal to 1.

Extension types range from `0x8000` to `0xffff`. They follow the core fields in
strictly increasing type order; duplicates are errors. An unknown optional
extension (flags 0) is retained byte-for-byte in the model and on re-encoding.
An unknown required extension (flags 1) is rejected. Writers in this version
create optional extensions only. Future changes affecting security or semantics
must use understood required fields/extensions or a new format version, rather
than hiding mandatory behavior in an optional field.

These rules apply separately to the public header, each keyslot's extension
tail, and the protected configuration. Updates must preserve unrecognized
optional extensions, including inside unchanged keyslots.

## Public header body

1. Filesystem ID: 16 raw bytes.
2. Required record type 1: keyslot array.
3. Required record type 2: protected `SealedRegion`.
4. Optional extension records.

The keyslot array begins with a `u32` count, then one blob per slot. Each slot
blob contains:

1. Slot ID: 16 raw bytes, unique within the header.
2. KDF `Algorithm` descriptor.
3. `SealedRegion` containing the wrapped master key.
4. Optional extension records.

An `Algorithm` descriptor is `id: u16, parameters: blob`. Zero is reserved.
KDF and AEAD IDs occupy separate namespaces. Algorithm implementations must
specify the parameter schema and validate supported IDs, parameter versions,
key sizes, and resource limits before use. This codec deliberately preserves
unknown nonzero algorithm descriptors for inspection and transport; this does
**not** make an unknown algorithm usable. Algorithm registry assignments and
algorithm-specific parameter codecs will be specified with the crypto code.
The golden fixtures use synthetic ID 1 descriptors, not operational crypto.

A `SealedRegion` is:

1. AEAD `Algorithm` descriptor.
2. Nonce: blob.
3. Ciphertext with its authentication tag appended: blob.

The wrapping and configuration encryptions each have their own nonce and tag.
Nonces are not secret. The minimum encoded ciphertext/tag length is 16 bytes;
the exact nonce/tag/key lengths must be checked by the selected algorithm.
For the proposed XChaCha20-Poly1305 suite, these will be a 24-byte nonce and a
16-byte tag. This container alone does not enforce or implement that suite.

## Protected configuration body

1. Required record type 1: root inode object key, UTF-8, 1–1024 bytes.
2. Required record type 2: inode encryption `Algorithm` followed by data
   encryption `Algorithm`.
3. Optional extension records.

The descriptors contain filesystem defaults, not reusable encryption nonces.
Every inode/chunk encryption must use its own nonce as required by its suite.
Defaults apply to newly created objects. Future inode/chunk envelopes must carry
an explicit suite ID or an immutable configuration-version reference; changing
these defaults must not reinterpret existing ciphertext under a different suite.
Names and extent mappings remain in the future inode/directory formats.

## Authentication inputs

The codec defines canonical additional authenticated data (AAD) byte strings.
These are inputs to AEAD, **not** authentication tags, hashes, or signatures.
The domain labels include the terminating zero byte. All fields use the same
encodings and extension order defined above.

`Keyslot::wrapping_aad(filesystem_id)`:

```text
"EEDFS/keyslot\0"
version: u16
filesystem ID: 16 bytes
slot ID: 16 bytes
KDF descriptor
wrapping algorithm descriptor
wrapping nonce: blob
slot extensions: TLV sequence
```

`Header::protected_aad()`:

```text
"EEDFS/header-config\0"
version: u16
filesystem ID: 16 bytes
keyslot array: blob (including the wrapped keys and their envelopes)
protected-region algorithm descriptor
protected-region nonce: blob
header extensions: TLV sequence
```

A future crypto layer must derive distinct master-key-based keys for header
protection and other purposes; it must not reuse a key/nonce pair for different
plaintexts. Wrapped-key ciphertext is excluded from its own AAD, and protected
configuration ciphertext is excluded from its own AAD: AEAD already authenticates
the ciphertext. The format version, known flags, and length rules are enforced
by the parser; interpretation-changing public metadata is bound by the AAD.

Adding/removing/reordering slots or changing public metadata requires generating
new protected-region ciphertext/tag with a fresh nonce. Changing a slot's own
wrapping metadata requires rewrapping that slot too. A subsequent S3 update must
use the previously observed ETag in a conditional PUT. AAD does not provide
rollback protection; a valid old header can still be replayed without an
external trusted freshness mechanism. Slot removal cannot revoke an already
copied old header/master key.

## Limits and defensive decoding

- At most 1 MiB per complete encoded header or protected configuration.
- 1–64 keyslots with unique slot IDs.
- At most 4096 parameter bytes per algorithm descriptor.
- At most 64 nonce bytes and 64 extensions per extension container.
- Lengths must fit in the enclosing slice before data is copied.
- Before invoking a KDF, the future unlock layer must validate and bound its
  memory, work, parallelism, and output length. These are not validated by merely
  decoding an opaque algorithm descriptor.

Neither ciphertext nor KDF parameters should be logged by production callers.
Future cryptographic APIs should also manage secret-memory lifetime explicitly.

## Compatibility tests

`tests/header_format.rs` checks independently generated little-endian golden
fixtures, every truncated prefix, malformed lengths, duplicate IDs/fields,
optional-extension preservation, mandatory-extension rejection, size limits,
and the public-metadata/AAD relationship. Fixture ciphertext and tags are fake;
these tests are not encryption tests.
