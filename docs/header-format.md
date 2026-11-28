# Header format v4

Experimental, incompatible with v1–v3. Old versions are rejected, not migrated.
The stable locator is the S3 object key `header` (under a caller-selected prefix).
All integers in the 16-byte framing prefix are little endian:

```
magic[8] | version:u16 | flags:u16=0 | payload_length:u32 | Postcard payload
```

Frame magic uses `COCFS` as the compact CoCryptFS prefix, preserving the fixed
eight-byte field. Magic is `COCFSHDR` for Header and `COCFSCFG` for decrypted
ProtectedConfig.
Canonical Postcard encoding is required, including no trailing bytes. Struct
field order and enum variant order are part of the schema. Rust memory layouts
are never written to disk. IDs use random 16-byte values, not an allocation counter.

```
Header {
  filesystem_id: [u8;16],
  keyslots: Vec<Keyslot>,
  protected: SealedRegion,
  extensions: Vec<Extension>,
}
Keyslot {
  id: [u8;16],
  kdf: Algorithm,
  wrapped_master_key: SealedRegion,
  extensions: Vec<Extension>,
}
ProtectedConfig {                       // encrypted, never stored in plaintext
  root_inode: [u8;16],
  naming: NamingConfig,                 // inode names only
  extensions: Vec<Extension>,
}
NamingConfig { algorithm: Algorithm, key: [u8;32] }
Algorithm { id: u16, parameters: Vec<u8> }
SealedRegion { algorithm: Algorithm, nonce: Vec<u8>, ciphertext: Vec<u8> }
Extension { kind:u16, required:bool, value:Vec<u8> }
```

Ciphertext includes the AEAD tag. `parameters` encodes a Postcard tuple
`(parameter_schema_version:u16, typed_parameters)`; it is not JSON. ID namespaces
are separate for encryption, password KDF, and naming. See [crypto](crypto.md)
for assigned IDs and schemas. Unknown descriptors can be parsed but never executed.
The global default inode/chunk encryption descriptors were removed in v4:
each inode owns its common body/chunk encryption profile.

## Authentication and unlock

Password -> Argon2id -> KEK -> unwrap random 32-byte master key.
HKDF derives a separate header configuration key from the master key. The protected
configuration locates root via `HMAC(inode naming key, domain || filesystem ID || root ID)`.
The root inode carries its own wrapped key; its key is not duplicated here.

AAD is a raw domain prefix followed by the canonical Postcard tuple below:

- `CoCryptFS/keyslot\0`: `(4, filesystem_id, slot_id, kdf, wrapping_algorithm,
  wrapping_nonce, slot_extensions)`.
- `CoCryptFS/header-config\0`: `(4, filesystem_id, keyslots, protected_algorithm,
  protected_nonce, header_extensions)`.

Version is serialized as u16. Wrapped-key ciphertexts are bound by the protected
config's AAD; ciphertext is excluded from its own AAD. Modifying slots or public
header metadata requires resealing the protected config with a fresh nonce.
The unlock API selects one explicit slot; it does not run every supplied KDF.
Header creation/unlock is implemented in memory. Password changes, slot editing,
S3 publication, rollback protection, and revocation workflows remain future work.

## Limits and extensions

Header and protected plaintext frames: at most 1 MiB each. Keyslots: 1–64,
unique IDs. Parameter bytes: at most 4096. Nonce: at most 64 bytes structurally;
crypto enforces the suite's exact size. Ciphertext: at least a 16-byte tag.
Extensions: at most 64, increasing unique kinds >= 0x8000; unknown optional
extensions are preserved, unknown required extensions are rejected. Lengths are
bounded before allocation. A parsed ciphertext is not authenticated until unlock.
