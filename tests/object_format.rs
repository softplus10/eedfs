use eedfs::format::{
    MAX_OBJECT_EXTENSION,
    data_chunk::{DataChunkObject, MAX_CHUNK_PLAINTEXT},
    header::{Algorithm, Extension, FormatError, SealedRegion},
    inode::*,
};
use serde::Serialize;

// Synthetic ciphertext/tag values. No test implements or claims real encryption.
fn sealed<const N: usize>(size: usize) -> SealedRegion<N> {
    SealedRegion {
        algorithm: Algorithm {
            id: 1,
            parameters: vec![],
        },
        nonce: vec![0x33; 24],
        ciphertext: vec![0x55; size],
    }
}
fn inode() -> InodeObject {
    InodeObject {
        wrapped_inode_key: sealed(48),
        protected: sealed(32),
        extensions: vec![],
    }
}
fn body() -> InodeBody {
    InodeBody {
        id: [0x22; 16],
        kind: FILE,
        generation: 7,
        content: InodeContent::Inline(b"hello".to_vec()),
        extensions: vec![],
    }
}
fn chunk(size: usize) -> DataChunkObject {
    DataChunkObject {
        protected: sealed(size),
        extensions: vec![],
    }
}
fn reference(key: &str, size: u64) -> ChunkReference {
    ChunkReference {
        object_key: key.to_owned(),
        plaintext_len: size,
    }
}
fn chunks() -> InodeBody {
    InodeBody {
        content: InodeContent::Chunks(vec![reference("chunk-a", 5), reference("chunk-b", 6)]),
        ..body()
    }
}
fn golden(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}
fn unchecked<T: Serialize>(magic: &[u8; 8], value: &T) -> Vec<u8> {
    let payload = postcard::to_allocvec(value).unwrap();
    let mut bytes = magic.to_vec();
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

#[test]
fn matches_independently_encoded_wire_fixtures() {
    let bytes = golden(include_str!("fixtures/inode-object-v1.hex"));
    assert_eq!(inode().encode().unwrap(), bytes);
    assert_eq!(InodeObject::decode(&bytes).unwrap(), inode());
    let bytes = golden(include_str!("fixtures/inode-inline-v1.hex"));
    assert_eq!(body().encode().unwrap(), bytes);
    assert_eq!(InodeBody::decode(&bytes).unwrap(), body());
    let bytes = golden(include_str!("fixtures/inode-chunks-v1.hex"));
    assert_eq!(chunks().encode().unwrap(), bytes);
    assert_eq!(InodeBody::decode(&bytes).unwrap(), chunks());
    let bytes = golden(include_str!("fixtures/data-chunk-v1.hex"));
    assert_eq!(chunk(32).encode().unwrap(), bytes);
    assert_eq!(DataChunkObject::decode(&bytes).unwrap(), chunk(32));
}

#[test]
fn links_inode_references_to_serialized_chunks_in_file_order() {
    let value = InodeBody::decode(&chunks().encode().unwrap()).unwrap();
    assert_eq!(value.size().unwrap(), 11);
    // Fetch results by opaque S3 key. Plaintext fixtures stand in for a future AEAD layer.
    let stored = std::collections::BTreeMap::from([
        (
            "chunk-a",
            (chunk(21).encode().unwrap(), b"hello".as_slice()),
        ),
        (
            "chunk-b",
            (chunk(22).encode().unwrap(), b" world".as_slice()),
        ),
    ]);
    let InodeContent::Chunks(refs) = value.content else {
        panic!("expected chunk references")
    };
    let mut output = Vec::new();
    for entry in refs {
        let (bytes, plaintext) = &stored[entry.object_key.as_str()];
        let object = DataChunkObject::decode(bytes).unwrap();
        assert_eq!(
            entry.aad(&[1; 16], &object).unwrap(),
            object.aad(&[1; 16], &entry.object_key).unwrap()
        );
        entry.validate_plaintext(plaintext).unwrap();
        output.extend_from_slice(plaintext);
    }
    assert_eq!(output, b"hello world");
}

#[test]
fn inline_and_chunk_reference_transitions_keep_identity_and_cow_history() {
    let before = body();
    let before_bytes = before.encode().unwrap();
    let mut after = before.clone();
    after.generation += 1;
    after.content = chunks().content;
    let after = InodeBody::decode(&after.encode().unwrap()).unwrap();
    assert_eq!(after.id, before.id);
    assert_eq!(after.size().unwrap(), 11);
    assert_eq!(InodeBody::decode(&before_bytes).unwrap(), before);
    let mut replaced = after.clone();
    let InodeContent::Chunks(ref mut refs) = replaced.content else {
        panic!()
    };
    refs[1] = reference("new-cow-chunk", 3);
    assert_eq!(replaced.size().unwrap(), 8);
    let InodeContent::Chunks(old_refs) = after.content else {
        panic!()
    };
    assert_eq!(old_refs[1].object_key, "chunk-b");
}

#[test]
fn rejects_all_truncated_prefixes_and_cross_type_objects() {
    for bytes in [
        inode().encode().unwrap(),
        body().encode().unwrap(),
        chunk(32).encode().unwrap(),
    ] {
        for end in 0..bytes.len() {
            let input = &bytes[..end];
            assert!(InodeObject::decode(input).is_err());
            assert!(InodeBody::decode(input).is_err());
            assert!(DataChunkObject::decode(input).is_err());
        }
    }
    assert!(InodeObject::decode(&chunk(32).encode().unwrap()).is_err());
    assert!(DataChunkObject::decode(&inode().encode().unwrap()).is_err());
}

#[test]
fn rejects_wrong_kind_invalid_reference_lengths_and_keys() {
    let mut value = body();
    value.kind = 0;
    assert!(value.encode().is_err());
    assert!(InodeBody::decode(&unchecked(b"EEDFSINB", &value)).is_err());
    for invalid in [
        reference("", 1),
        reference("x", 0),
        reference("x", MAX_CHUNK_PLAINTEXT as u64 + 1),
        reference(&"x".repeat(1025), 1),
    ] {
        value.kind = FILE;
        value.content = InodeContent::Chunks(vec![invalid]);
        assert!(value.encode().is_err());
        assert!(InodeBody::decode(&unchecked(b"EEDFSINB", &value)).is_err());
    }
    value.content = InodeContent::Chunks(vec![]);
    assert!(value.encode().is_err());
    value.content = InodeContent::Inline(vec![]);
    assert_eq!(value.size().unwrap(), 0);
    assert!(value.encode().is_ok());
    assert!(
        reference("chunk-a", 5)
            .validate_plaintext(b"wrong length")
            .is_err()
    );
}

#[test]
fn limits_inline_bytes_and_reference_allocations() {
    let mut value = body();
    value.content = InodeContent::Inline(vec![0; MAX_INLINE_SIZE + 1]);
    assert!(value.encode().is_err());
    assert!(InodeBody::decode(&unchecked(b"EEDFSINB", &value)).is_err());
    value.content = InodeContent::Chunks(vec![reference("x", 1); MAX_CHUNK_REFERENCES + 1]);
    assert!(value.encode().is_err());
    assert!(InodeBody::decode(&unchecked(b"EEDFSINB", &value)).is_err());
}

#[test]
fn eight_mib_chunks_are_supported_without_relaxing_inode_limits() {
    let object = chunk(8 * 1024 * 1024 + 16);
    let bytes = object.encode().unwrap();
    let decoded = DataChunkObject::decode(&bytes).unwrap();
    assert_eq!(decoded, object);
    let mut oversized_inode = inode();
    oversized_inode.protected.ciphertext = vec![0; MAX_INODE_SIZE + 1];
    assert!(oversized_inode.encode().is_err());
    // Reject a length claim above the chunk budget without allocating the claimed payload.
    let mut bytes = chunk(32).encode().unwrap();
    bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(DataChunkObject::decode(&bytes).is_err());
}

#[test]
fn authenticated_context_binds_location_and_metadata_but_not_file_offset() {
    let value = inode();
    let fs = [1; 16];
    let key_aad = value.wrapping_aad(&fs, "inode-a").unwrap();
    let body_aad = value.protected_aad(&fs, "inode-a").unwrap();
    assert_ne!(key_aad, body_aad);
    assert_ne!(body_aad, value.protected_aad(&fs, "inode-b").unwrap());
    assert_ne!(body_aad, value.protected_aad(&[2; 16], "inode-a").unwrap());
    let mut changed = value.clone();
    changed.wrapped_inode_key.ciphertext[0] ^= 1;
    assert_ne!(body_aad, changed.protected_aad(&fs, "inode-a").unwrap());
    changed = value;
    changed.protected.ciphertext[0] ^= 1;
    assert_eq!(body_aad, changed.protected_aad(&fs, "inode-a").unwrap());
    let value = chunk(32);
    let aad = value.aad(&fs, "chunk-a").unwrap();
    assert_ne!(aad, value.aad(&fs, "chunk-b").unwrap());
    assert_ne!(aad, value.aad(&[2; 16], "chunk-a").unwrap());
    let mut changed = value.clone();
    changed.protected.nonce[0] ^= 1;
    assert_ne!(aad, changed.aad(&fs, "chunk-a").unwrap());
    changed = value;
    changed.protected.ciphertext[0] ^= 1;
    assert_eq!(aad, changed.aad(&fs, "chunk-a").unwrap());
    assert!(changed.aad(&fs, "").is_err());
}

#[test]
fn optional_extensions_roundtrip_and_unknown_required_ones_fail() {
    let extension = Extension {
        kind: 0x8000,
        required: false,
        value: vec![1, 2],
    };
    let mut value = inode();
    value.extensions.push(extension.clone());
    assert_eq!(
        InodeObject::decode(&value.encode().unwrap()).unwrap(),
        value
    );
    value.extensions[0].required = true;
    assert_eq!(
        InodeObject::decode(&unchecked(b"EEDFSINO", &value)),
        Err(FormatError::RequiredExtension(0x8000))
    );
    let mut value = body();
    value.extensions.push(extension.clone());
    assert_eq!(InodeBody::decode(&value.encode().unwrap()).unwrap(), value);
    let mut value = chunk(32);
    value.extensions.push(extension);
    assert_eq!(
        DataChunkObject::decode(&value.encode().unwrap()).unwrap(),
        value
    );
}

#[test]
fn debug_redacts_inline_contents() {
    let value = body();
    assert!(!format!("{value:?}").contains("104, 101, 108, 108, 111"));
    assert!(!format!("{:?}", value.content).contains("104, 101, 108, 108, 111"));
}

#[test]
fn rejects_wrong_versions_flags_noncanonical_data_and_oversized_extensions() {
    let mut bytes = body().encode().unwrap();
    bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        InodeBody::decode(&bytes),
        Err(FormatError::UnsupportedVersion(2))
    );
    let mut bytes = body().encode().unwrap();
    bytes[10] = 1;
    assert!(InodeBody::decode(&bytes).is_err());
    let mut bytes = body().encode().unwrap();
    bytes[34] = 2; // Unknown content tag, after id, kind and generation.
    assert!(InodeBody::decode(&bytes).is_err());
    let mut bytes = body().encode().unwrap();
    bytes.push(0);
    let len = (bytes.len() - 16) as u32;
    bytes[12..16].copy_from_slice(&len.to_le_bytes());
    assert!(InodeBody::decode(&bytes).is_err());
    let mut value = chunk(32);
    value.extensions.push(Extension {
        kind: 0x8000,
        required: false,
        value: vec![0; MAX_OBJECT_EXTENSION + 1],
    });
    assert!(value.encode().is_err());
    assert!(DataChunkObject::decode(&unchecked(b"EEDFSCHK", &value)).is_err());
}

#[test]
fn mutations_never_panic_and_accepted_objects_stay_canonical() {
    for original in [
        inode().encode().unwrap(),
        body().encode().unwrap(),
        chunks().encode().unwrap(),
        chunk(32).encode().unwrap(),
    ] {
        for index in 0..original.len() {
            for byte in [0, 1, 127, 255] {
                let mut changed = original.clone();
                changed[index] = byte;
                if let Ok(value) = InodeObject::decode(&changed) {
                    assert_eq!(value.encode().unwrap(), changed);
                }
                if let Ok(value) = InodeBody::decode(&changed) {
                    assert_eq!(value.encode().unwrap(), changed);
                }
                if let Ok(value) = DataChunkObject::decode(&changed) {
                    assert_eq!(value.encode().unwrap(), changed);
                }
            }
        }
    }
}
