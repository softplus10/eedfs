# Cryptographic profiles

Implemented using RustCrypto crates, without custom cryptographic primitives.
This is an experimental implementation, not an audited filesystem.

## Explicit IDs and parameter schemas

IDs are scoped to their category; schema version is u16=1. Parameter payloads
are Postcard `(schema_version, typed_parameters)` tuples.

| Category | ID | Algorithm | Typed parameters |
|---|---:|---|---|
| Encryption | 1 | XChaCha20-Poly1305 (default choice) | unit `()` |
| Encryption | 2 | AES-256-GCM-SIV | unit `()` |
| Password KDF | 1 | Argon2id v19, output 32 bytes | `salt:[u8;16], memory_kib:u32, iterations:u32, parallelism:u32` |
| Naming | 1 | HMAC-SHA256, lowercase hex, fixed domains | unit `()` |

Both AEADs use 32-byte keys and 16-byte tags. Nonces are 24 and 12 bytes,
respectively. Wrapping uses AEAD, not AES-KW or XTS. The same encryption modules
serve wrapping, inode bodies and chunks. Unsupported IDs or parameter versions
are errors; there is no silent fallback. The low-level API takes an explicit
profile; applications should select ID 1 unless they deliberately choose ID 2.
Random nonces are always generated even for the misuse-resistant GCM-SIV suite.
Applications must still respect per-key usage limits; neither suite permits
unbounded key lifetime. Selection does not imply FIPS validation.

Argon2id defaults: 64 MiB, 3 iterations, 4 lanes, random 16-byte salt (RFC 9106's
second recommended option). Current local resource policy accepts 8–256 MiB,
1–10 iterations, and 1–16 lanes. The lower allowed settings exist for tests and
compatibility, not as a password-hardening recommendation. Unknown KDFs and
resource requests outside policy are rejected before allocation. Applications
must separately bound simultaneous unlock requests.

## Key hierarchy

```
password --Argon2id--> KEK --AEAD unwrap--> master key
master --HKDF--> header configuration key
master --HKDF--> inode wrapping key --AEAD unwrap--> inode key
inode key --HKDF--> inode body key
inode key --HKDF--> chunk data key
inode key --HKDF--> file-index naming key
```

HKDF-SHA256 is fixed by the format, not password-selectable. Salt is the
16-byte filesystem ID. Info labels, without terminating NUL, are:
`CoCryptFS/v1/header-config`, `CoCryptFS/v1/inode-wrapping`,
`CoCryptFS/v1/inode-body`, `CoCryptFS/v1/data-chunk`, `CoCryptFS/v1/file-index-name`.
Purpose separation does not add stored per-object keys. The independent random
inode naming key lives in the protected header; the independent random chunk
naming key lives inside a file's encrypted inode. Master and inode keys are random
32-byte values. IDs and nonces use OS randomness. Key wrappers and decrypted
serialized buffers are zeroized on drop; naming keys redact Debug and zeroize on
drop. Decoded plaintext inode content belongs to the caller and is not
implicitly wiped. Rust cannot guarantee removal of every compiler/register copy.

## Object naming

Exact HMAC message inputs, concatenated as bytes:

- inode: `b"CoCryptFS/inode-name/v1\0" || filesystem_id[16] || inode_id[16]`
- chunk: `b"CoCryptFS/chunk-name/v1\0" || filesystem_id[16] || allocation_id[16] || index:u64LE`

Output: full 32-byte digest rendered as 64 lowercase hex characters, without
an inode/chunk type prefix. Inputs after the domain have fixed widths. The S3
prefix, if any, is applied by the caller; AAD must bind the full actual S3 key.
HMAC is deterministic, so access repetition, timing and object sizes remain
visible. Naming secrecy is not an access-pattern hiding system.

## Tests and boundaries

Known answers: RFC 4231 HMAC-SHA256, RFC 8452 AES-256-GCM-SIV, independent
libsodium XChaCha20-Poly1305 and libargon2 output. Integration tests exercise
header unlock, wrapped inode keys, shared inode access, variable-size chunk
reassembly, metadata/AAD/ciphertext tampering and resource rejection for both AEADs.
No security claim follows from round-trip tests alone.

Password replacement is available through `change-password`: it rewraps the same
master key with fresh salt/nonces, reseals the keyslot-authenticating header and
publishes one ETag CAS. It does not revoke cached headers/master keys. Other
keyslots are preserved. There is no master-key rotation, key revocation,
authenticated sharing grant, rollback protection, multi-object directory
transaction or orphan/inode sweep yet. The experimental
[S3/FUSE pipeline](s3-fuse.md) now uses these helpers for object storage.
Password/KEK changes can rewrap the master key without rewriting file chunks.
Changing an inode's body/chunk encryption profile requires rewriting chunks that
remain referenced. Public algorithm descriptors must be authenticated through AAD.

## References

- [RustCrypto XChaCha20-Poly1305](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/)
- [RustCrypto AES-GCM-SIV](https://docs.rs/aes-gcm-siv/0.11.1/aes_gcm_siv/)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- [HKDF RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)
- [HMAC test vectors RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html)
- [AES-GCM-SIV RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html)
