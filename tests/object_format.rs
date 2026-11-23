use eedfs::{
    crypto::encryption,
    format::{
        data_chunk::DataChunkObject,
        header::{Algorithm, Extension, FormatError, NamingConfig, SealedRegion},
        inode::*,
    },
};
fn naming() -> NamingConfig {
    NamingConfig {
        algorithm: Algorithm {
            id: 1,
            parameters: vec![],
        },
        key: [7; 32],
    }
}
fn body() -> InodeBody {
    InodeBody {
        id: [2; 16],
        kind: FILE,
        generation: 7,
        content: InodeContent::Inline(b"hello".to_vec()),
        extensions: vec![],
    }
}
fn chunks() -> ChunkedContent {
    ChunkedContent {
        naming: naming(),
        runs: vec![ChunkRun {
            allocation_id: [3; 16],
            first_chunk: 0,
            plaintext_lengths: vec![5, 6],
        }],
    }
}
fn object() -> InodeObject {
    let region = SealedRegion {
        algorithm: Algorithm {
            id: 1,
            parameters: vec![],
        },
        nonce: vec![3; 24],
        ciphertext: vec![5; 48],
    };
    InodeObject {
        wrapped_inode_key: region.clone(),
        protected: region,
        extensions: vec![],
    }
}
fn unchecked<T: serde::Serialize>(magic: &[u8; 8], value: &T) -> Vec<u8> {
    let payload = postcard::to_allocvec(value).unwrap();
    let mut bytes = magic.to_vec();
    bytes.extend(VERSION.to_le_bytes());
    bytes.extend([0, 0]);
    bytes.extend((payload.len() as u32).to_le_bytes());
    bytes.extend(payload);
    bytes
}
#[test]
fn inline_and_chunk_runs_roundtrip_and_cow_keeps_old_body() {
    let old = body();
    let bytes = old.encode().unwrap();
    let mut next = old.clone();
    next.generation += 1;
    next.content = InodeContent::Chunks(chunks());
    assert_eq!(next.size().unwrap(), 11);
    assert_eq!(InodeBody::decode(&next.encode().unwrap()).unwrap(), next);
    assert_eq!(InodeBody::decode(&bytes).unwrap(), old);
    let InodeContent::Chunks(ref mut content) = next.content else {
        panic!()
    };
    content.runs[0].plaintext_lengths.pop();
    content.runs.push(ChunkRun {
        allocation_id: [4; 16],
        first_chunk: 0,
        plaintext_lengths: vec![3],
    });
    assert_eq!(next.size().unwrap(), 8);
}
#[test]
fn truncation_canonical_mutations_and_version_checks() {
    for original in [body().encode().unwrap(), object().encode().unwrap()] {
        for end in 0..original.len() {
            assert!(InodeBody::decode(&original[..end]).is_err());
            assert!(InodeObject::decode(&original[..end]).is_err());
        }
        for i in 0..original.len() {
            for byte in [0, 1, 127, 255] {
                let mut b = original.clone();
                b[i] = byte;
                if let Ok(v) = InodeBody::decode(&b) {
                    assert_eq!(v.encode().unwrap(), b);
                }
                if let Ok(v) = InodeObject::decode(&b) {
                    assert_eq!(v.encode().unwrap(), b);
                }
            }
        }
    }
    let mut b = body().encode().unwrap();
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        InodeBody::decode(&b),
        Err(FormatError::UnsupportedVersion(1))
    );
    let mut b = body().encode().unwrap();
    b[34] = 2;
    assert!(InodeBody::decode(&b).is_err());
    let mut b = body().encode().unwrap();
    b[10] = 1;
    assert!(InodeBody::decode(&b).is_err());
}
#[test]
fn run_limits_and_index_overflow_are_checked_on_decode_too() {
    let mut invalid = Vec::new();
    let mut c = chunks();
    c.runs.clear();
    invalid.push(c);
    let mut c = chunks();
    c.runs[0].plaintext_lengths.clear();
    invalid.push(c);
    let mut c = chunks();
    c.runs[0].first_chunk = u64::MAX;
    invalid.push(c);
    let mut c = chunks();
    c.runs[0].plaintext_lengths = vec![0];
    invalid.push(c);
    let mut c = chunks();
    c.runs[0].plaintext_lengths = vec![eedfs::format::data_chunk::MAX_CHUNK_PLAINTEXT as u32 + 1];
    invalid.push(c);
    let mut c = chunks();
    c.runs[0].plaintext_lengths = vec![1; MAX_CHUNK_REFERENCES + 1];
    invalid.push(c);
    let mut c = chunks();
    c.runs = vec![c.runs[0].clone(); MAX_CHUNK_REFERENCES];
    invalid.push(c);
    for c in invalid {
        let b = InodeBody {
            content: InodeContent::Chunks(c),
            ..body()
        };
        assert!(b.encode().is_err());
        assert!(InodeBody::decode(&unchecked(b"EEDFSINB", &b)).is_err());
    }
}
#[test]
fn inline_limit_kind_extensions_and_debug_redaction() {
    let mut b = body();
    b.kind = 0;
    assert!(b.encode().is_err());
    b = body();
    b.content = InodeContent::Inline(vec![0; MAX_INLINE_SIZE + 1]);
    assert!(b.encode().is_err());
    assert!(InodeBody::decode(&unchecked(b"EEDFSINB", &b)).is_err());
    b = body();
    b.extensions.push(Extension {
        kind: 0x8000,
        required: false,
        value: vec![1],
    });
    assert_eq!(InodeBody::decode(&b.encode().unwrap()).unwrap(), b);
    b.extensions[0].required = true;
    assert!(b.encode().is_err());
    assert!(!format!("{:?}", body()).contains("104, 101"));
    assert!(format!("{:?}", chunks()).contains("REDACTED"));
}
#[test]
fn compact_chunk_wire_is_exact_and_borrowed() {
    for id in [encryption::XCHACHA20_POLY1305, encryption::AES256_GCM_SIV] {
        let a = encryption::algorithm(id).unwrap();
        let n = encryption::nonce_size(&a).unwrap();
        let bytes = vec![5; n + 8 * 1024 * 1024 + 16];
        let chunk = DataChunkObject::decode(&bytes, &a, 8 * 1024 * 1024).unwrap();
        assert_eq!(chunk.nonce.len(), n);
        assert_eq!(chunk.nonce.as_ptr(), bytes.as_ptr());
        assert!(DataChunkObject::decode(&bytes[..bytes.len() - 1], &a, 8 * 1024 * 1024).is_err());
        assert!(DataChunkObject::decode(&bytes, &a, 1).is_err());
        assert!(DataChunkObject::decode(&bytes, &a, 0).is_err());
    }
}
#[test]
fn inode_aad_binds_filesystem_location_and_wrapped_key() {
    let v = object();
    let aad = v.protected_aad(&[1; 16], "inode-a").unwrap();
    assert_ne!(aad, v.protected_aad(&[1; 16], "inode-b").unwrap());
    assert_ne!(aad, v.protected_aad(&[2; 16], "inode-a").unwrap());
    let mut changed = v.clone();
    changed.wrapped_inode_key.ciphertext[0] ^= 1;
    assert_ne!(aad, changed.protected_aad(&[1; 16], "inode-a").unwrap());
    let mut changed = v;
    changed.protected.ciphertext[0] ^= 1;
    assert_eq!(aad, changed.protected_aad(&[1; 16], "inode-a").unwrap());
}

#[test]
fn v3_matches_independently_encoded_fixtures() {
    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|v| u8::from_str_radix(v, 16).unwrap())
            .collect()
    }
    assert_eq!(
        body().encode().unwrap(),
        hex(include_str!("fixtures/inode-inline-v3.hex"))
    );
    assert_eq!(
        object().encode().unwrap(),
        hex(include_str!("fixtures/inode-object-v3.hex"))
    );
    let b = InodeBody {
        content: InodeContent::Chunks(chunks()),
        ..body()
    };
    assert_eq!(
        b.encode().unwrap(),
        hex(include_str!("fixtures/inode-chunks-v3.hex"))
    );
    assert_eq!(
        InodeBody::decode(&hex(include_str!("fixtures/inode-inline-v1.hex"))),
        Err(FormatError::UnsupportedVersion(1))
    );
    assert_eq!(
        InodeObject::decode(&hex(include_str!("fixtures/inode-object-v1.hex"))),
        Err(FormatError::UnsupportedVersion(1))
    );
}

#[test]
fn previous_inode_version_is_rejected_and_lengths_need_no_file_maximum() {
    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|v| u8::from_str_radix(v, 16).unwrap())
            .collect()
    }
    assert_eq!(
        InodeBody::decode(&hex(include_str!("fixtures/inode-chunks-v2.hex"))),
        Err(FormatError::UnsupportedVersion(2))
    );
    assert_eq!(
        InodeObject::decode(&hex(include_str!("fixtures/inode-object-v2.hex"))),
        Err(FormatError::UnsupportedVersion(2))
    );
    let mut content = chunks();
    content.runs[0].first_chunk = u64::MAX;
    content.runs[0].plaintext_lengths = vec![eedfs::format::data_chunk::MAX_CHUNK_PLAINTEXT as u32];
    let b = InodeBody {
        content: InodeContent::Chunks(content),
        ..body()
    };
    assert_eq!(InodeBody::decode(&b.encode().unwrap()).unwrap(), b);
}
