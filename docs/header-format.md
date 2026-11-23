# EEDFS binary header, version 3

Version 3 adds a naming algorithm descriptor and a 32-byte naming key to the
protected configuration. The public header/keyslot model is unchanged. Serde
and the stable Postcard 1.x binary format serialize payloads and authentication inputs.
Only the 16-byte discovery prefix is hand-encoded. No JSON or native Rust memory
layout appears on disk. Postcard uses only its `alloc` feature; Serde provides
derives. These are purposeful dependencies for serialization, not cryptography.

Version 1 used an experimental hand-written TLV encoding; version 2 introduced
Postcard without naming configuration. Version 3 rejects both older container
versions explicitly instead of silently interpreting different schemas. No header
upload/unlock workflow has shipped, and no migration tool is provided. Older
fixtures remain as version-rejection regression inputs.

The codec does **not** derive keys, encrypt, authenticate, upload, or unlock a
filesystem. Decoded ciphertext and algorithm parameters remain untrusted.

## Logical contents

The public header contains a filesystem ID, keyslot array, encrypted configuration
envelope, and extensions. Each slot has a stable ID, KDF descriptor, wrapped
master-key envelope, and extensions. Plaintext master keys do not belong here.

The protected configuration contains the **root inode's S3 object key, default
inode/data encryption descriptors, and secret naming configuration**, plus
extensions. It is encoded and then encrypted into the header, not stored as
another S3 object. The root inode will carry its own wrapped inode key. S3 credentials, endpoint, bucket, directory
contents, inode internals, and chunk indexes are outside this format.

## Discovery prefix

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `EEDFSHDR` or `EEDFSCFG` |
| 8 | 2 | Container version: 3, unsigned little-endian |
| 10 | 2 | Reserved flags: 0 |
| 12 | 4 | Postcard payload length, unsigned little-endian |
| 16 | variable | Postcard payload |

The complete input must match the declared length exactly. The decoder also
rejects bytes left after the Postcard value and noncanonical encodings by
comparing against a re-serialization. Unknown versions and flags are errors.

## Postcard schema

Fields below are encoded in the listed order. Postcard structs/tuples have no
field names or field count. Unsigned integers use Postcard's unsigned varints;
`u8` and fixed byte arrays are raw bytes. Strings and vectors have varint length
prefixes. Rust struct memory layout, pointers, padding, and native enum positions
are never stored.

```text
Header {
    filesystem_id: [u8; 16],
    keyslots: Vec<Keyslot>,
    protected: SealedRegion,
    extensions: Vec<Extension>,
}
Keyslot {
    id: [u8; 16],
    kdf: Algorithm,
    wrapped_master_key: SealedRegion,
    extensions: Vec<Extension>,
}
Algorithm {
    id: u16,
    parameters: Vec<u8>,
}
SealedRegion {
    algorithm: Algorithm,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}
Extension {
    kind: u16,
    required: bool,
    value: Vec<u8>,
}
ProtectedConfig {
    root_inode: String,
    inode_encryption: Algorithm,
    data_encryption: Algorithm,
    naming: NamingConfig,
    extensions: Vec<Extension>,
}
NamingConfig {
    algorithm: Algorithm,
    key: [u8; 32],
}
```

A change to these core fields/order/types requires a container version change.
Adding a Rust field or a `serde(default)` does not automatically provide wire
compatibility. Compatible additions use the existing extension vectors. The
Postcard specification guarantees stability of its format, not evolution of an
application schema.

## Algorithm-specific parameters versus extensions

`Algorithm.parameters` is owned by the selected algorithm, not a global bag of
extensions. KDF, AEAD, and naming-scheme IDs have separate namespaces; zero is reserved. Stable
numeric IDs will be assigned when the cryptographic implementations are added.
Unknown nonzero descriptors survive container decoding, but cannot be executed.
The golden fixtures' ID 1 descriptors and ciphertext are synthetic test data.

`Algorithm::from_parameters(id, schema_version, &typed_parameters)` stores a
Postcard tuple `(schema_version: u16, typed_parameters)`, bounded to 4096 bytes.
`decode_parameters::<T>(expected_id, expected_schema_version)` requires the
expected ID/version, exact consumption, and canonical encoding. The algorithm
module defines `T`, its supported version, resource bounds, and semantic checks.
Generic decoding does not run a KDF or prove the parameters are safe to use.

For example, a future Argon2id parameter struct would contain a salt and memory,
iteration, and parallelism settings. An AEAD with no algorithm-specific settings
can use a unit struct. Every slot can select different algorithms/settings; the
header container need not grow another Rust enum variant for each algorithm.
Do not serialize an implementation enum's positional discriminant as a stable
algorithm ID. Incompatible parameter changes require a new understood parameter
schema version or algorithm ID.

Nonce and tag are **not extensions or static algorithm parameters**: each
`SealedRegion` has its own nonce, and ciphertext includes the appended tag.
Wrapping and protected-configuration encryption therefore have separate nonces
and tags. Defaults do not contain reusable nonces. Future inode/chunk envelopes
must identify their suite or immutable configuration version so changing defaults
does not reinterpret existing ciphertext.

Extensions are separate application-format additions. Types are unique,
strictly increasing, and in `0x8000..=0xffff`. Unknown optional records are
preserved, including those inside keyslots; unknown required records are rejected.
Current writers emit optional records only. Security-critical behavior must not
be hidden in an optional record an old reader can ignore.

## Protected naming configuration

The fixed 32-byte naming key is part of `ProtectedConfig` only, never a public
header field or a keyslot parameter. The crypto layer must generate it from an
OS-backed cryptographically secure RNG at filesystem creation. This codec neither
generates keys nor measures their entropy. A zero-key prohibition would not
prove random generation, so the container does not attempt that check.

The proposed initial naming scheme is HMAC-SHA256 with canonical, domain-separated
inputs for inode and allocation/chunk identifiers and a specified text encoding
for the result. The naming module must assign its scheme ID and parameter version
and define the entire naming convention, not just the underlying hash. HMAC
calculation, name input encoding, and scheme registry assignment remain future
crypto work. Synthetic fixture IDs/keys are not production credentials.

Keeping the naming key independent lets a future master-key rotation preserve
object names, provided the same naming key is retained. Changing a password slot
already leaves the master/naming keys unchanged. Sharing should transmit object
locators in the shared inode rather than revealing the filesystem-wide naming
key. HMAC naming does not hide object sizes, timing, or repeated accesses.

`NamingConfig` redacts its key in `Debug`, also when printed through its parent
`ProtectedConfig`. The plaintext serialized payload still contains the secret:
encode it only as input to encryption, never upload/log it directly. Secret
zeroization/lifetime management remains future crypto-layer work.

## Authentication inputs

These are canonical AAD inputs to future AEAD code, not MACs or signatures.
Domain labels are raw ASCII including their terminating zero byte. Remaining
values are encoded as the following Postcard tuples, with no discovery prefix.

`Keyslot::wrapping_aad(filesystem_id)`:

```text
raw "EEDFS/keyslot\0" || Postcard((
    container_version: u16,
    filesystem_id: [u8; 16],
    slot_id: [u8; 16],
    kdf: Algorithm,
    wrapping_algorithm: Algorithm,
    wrapping_nonce: Vec<u8>,
    slot_extensions: Vec<Extension>,
))
```

`Header::protected_aad()`:

```text
raw "EEDFS/header-config\0" || Postcard((
    container_version: u16,
    filesystem_id: [u8; 16],
    keyslots: Vec<Keyslot>,
    protected_algorithm: Algorithm,
    protected_nonce: Vec<u8>,
    header_extensions: Vec<Extension>,
))
```

Ciphertext is excluded from its own AAD because AEAD authenticates it directly.
The protected configuration's AAD includes the wrapped-key ciphertexts as part
of the slot array. Valid flags, canonical encoding, and exact lengths are enforced
by the parser; interpretation-changing metadata is bound by the AAD.

Adding/removing/reordering slots or changing public metadata requires fresh
protected-region encryption/authentication. Changing a slot's wrapping metadata
requires rewrapping that slot as well. A future S3 header update must use ETag
conditional PUT. Separate purpose-derived keys and fresh nonces remain mandatory.
Valid old headers can still be replayed without external trusted freshness; slot
removal cannot revoke an already copied header/master key.

## Defensive decoding and limits

- 1 MiB per complete encoded header/configuration.
- 1–64 slots with unique IDs; 64 extensions per extension container.
- 4096 parameter bytes and 64 nonce bytes per descriptor/envelope.
- UTF-8 root inode object key, 1–1024 bytes.
- At least 16 ciphertext/tag bytes; exact suite lengths are future crypto checks.

Serde sequence visitors reject excessive declared vector lengths before reserving
memory and enforce bounds as elements are read. The root-key visitor validates
its borrowed string before allocating. Input size and framing are checked before
Postcard decoding. Encoding measures the serialized size with Postcard's `Size`
flavor before allocating the output. Validation remains an application concern;
using a serialization library does not replace it. Algorithm-specific deserializers
must likewise bound allocations and KDF memory/work before invocation.

Use the public `encode`/`decode` methods for stored containers, not bare
`postcard::from_bytes::<Header>`: bare Serde decoding bypasses the framing and
semantic checks. Likewise, plaintext `ProtectedConfig` must never be uploaded.

## Tests

Golden fixtures are independently encoded against the documented Postcard schema.
Regression tests cover truncation, trailing/noncanonical bytes, resource limits,
IDs/versions, optional/required extensions, typed algorithm parameter schemas,
naming configuration/key roundtrips and debug redaction, and AAD binding. Fixture ciphertext/tags are fake. No test claims to validate an
actual encryption algorithm.

References: [Postcard wire format](https://postcard.jamesmunns.com/wire-format),
[Serde data model](https://serde.rs/data-model.html).
