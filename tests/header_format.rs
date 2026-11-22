use eedfs::format::header::{
    Algorithm, Extension, FormatError, Header, Keyslot, MAX_PARAMETERS, MAX_SIZE, ProtectedConfig,
    SealedRegion,
};

// Synthetic ciphertext/tag bytes: these fixtures test serialization, not encryption.
fn algorithm(id: u16) -> Algorithm {
    Algorithm {
        id,
        parameters: Vec::new(),
    }
}
fn sealed(ciphertext_len: usize) -> SealedRegion {
    SealedRegion {
        algorithm: algorithm(1),
        nonce: vec![0x33; 24],
        ciphertext: vec![0x55; ciphertext_len],
    }
}
fn header() -> Header {
    Header {
        filesystem_id: [0x11; 16],
        keyslots: vec![Keyslot {
            id: [0x22; 16],
            kdf: algorithm(1),
            wrapped_master_key: sealed(48),
            extensions: Vec::new(),
        }],
        protected: sealed(32),
        extensions: Vec::new(),
    }
}
fn config() -> ProtectedConfig {
    ProtectedConfig {
        root_inode: "root-object-key".into(),
        inode_encryption: algorithm(1),
        data_encryption: algorithm(1),
        extensions: Vec::new(),
    }
}
fn golden(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[test]
fn header_matches_independently_encoded_wire_fixture() {
    let bytes = golden(include_str!("fixtures/header-v1.hex"));
    assert_eq!(header().encode().unwrap(), bytes);
    assert_eq!(Header::decode(&bytes).unwrap(), header());
}

#[test]
fn protected_config_matches_wire_fixture_without_a_root_key_field() {
    let bytes = golden(include_str!("fixtures/header-config-v1.hex"));
    assert_eq!(config().encode().unwrap(), bytes);
    assert_eq!(ProtectedConfig::decode(&bytes).unwrap(), config());
}

#[test]
fn rejects_every_truncated_prefix_and_trailing_bytes() {
    let bytes = header().encode().unwrap();
    for end in 0..bytes.len() {
        assert!(
            Header::decode(&bytes[..end]).is_err(),
            "prefix length {end}"
        );
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(Header::decode(&extra).is_err());
    let bytes = config().encode().unwrap();
    for end in 0..bytes.len() {
        assert!(ProtectedConfig::decode(&bytes[..end]).is_err());
    }
}

#[test]
fn preserves_optional_extensions_at_all_levels() {
    let extension = Extension {
        kind: 0x8001,
        value: vec![0, 255, 7],
    };
    let mut value = header();
    value.extensions.push(extension.clone());
    value.keyslots[0].extensions.push(extension.clone());
    let bytes = value.encode().unwrap();
    assert_eq!(Header::decode(&bytes).unwrap().encode().unwrap(), bytes);
    let mut value = config();
    value.extensions.push(extension);
    let bytes = value.encode().unwrap();
    assert_eq!(
        ProtectedConfig::decode(&bytes).unwrap().encode().unwrap(),
        bytes
    );
}

#[test]
fn rejects_unknown_required_extensions() {
    let mut value = header();
    value.extensions.push(Extension {
        kind: 0x8001,
        value: vec![7],
    });
    let mut bytes = value.encode().unwrap();
    let flags = bytes.len() - 9 + 2;
    bytes[flags..flags + 2].copy_from_slice(&1_u16.to_le_bytes());
    assert_eq!(
        Header::decode(&bytes),
        Err(FormatError::RequiredExtension(0x8001))
    );
}

#[test]
fn rejects_duplicate_and_out_of_order_extensions() {
    let extension = Extension {
        kind: 0x8001,
        value: Vec::new(),
    };
    let mut value = header();
    value.extensions = vec![extension.clone(), extension];
    assert!(value.encode().is_err());
    value.extensions[0].kind = 0x8002;
    assert!(value.encode().is_err());
    value.extensions.pop();
    value.extensions[0].kind = 2;
    assert!(value.encode().is_err());
}

#[test]
fn rejects_bad_framing_and_unbounded_lengths_before_allocation() {
    let bytes = header().encode().unwrap();
    let mut bad = bytes.clone();
    bad[0] ^= 1;
    assert!(Header::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[8..10].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        Header::decode(&bad),
        Err(FormatError::UnsupportedVersion(2))
    );
    let mut bad = bytes.clone();
    bad[10] = 1;
    assert!(Header::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Header::decode(&bad).is_err());
    let mut bad = bytes;
    bad[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Header::decode(&bad).is_err());
    assert_eq!(
        Header::decode(&vec![0; MAX_SIZE + 1]),
        Err(FormatError::TooLarge)
    );
}

#[test]
fn rejects_duplicate_slots_on_encode_and_decode() {
    let mut value = header();
    value.keyslots.push(value.keyslots[0].clone());
    assert!(value.encode().is_err());
    value.keyslots[1].id = [0x44; 16];
    let mut bytes = value.encode().unwrap();
    let position = bytes
        .windows(16)
        .position(|window| window == [0x44; 16])
        .unwrap();
    bytes[position..position + 16].fill(0x22);
    assert!(Header::decode(&bytes).is_err());
    value.keyslots.clear();
    assert!(value.encode().is_err());
}

#[test]
fn bounds_algorithm_parameters_and_rejects_short_tags() {
    let mut value = header();
    value.protected.algorithm.parameters = vec![0; MAX_PARAMETERS + 1];
    assert!(value.encode().is_err());
    value.protected.algorithm.parameters.clear();
    value.protected.ciphertext = vec![0; 15];
    assert!(value.encode().is_err());
    value.protected.ciphertext = vec![0; 16];
    value.protected.nonce = vec![0; 65];
    assert!(value.encode().is_err());
}

#[test]
fn root_locator_must_fit_an_s3_object_key() {
    let mut value = config();
    value.root_inode.clear();
    assert!(value.encode().is_err());
    value.root_inode = "x".repeat(1025);
    assert!(value.encode().is_err());
    let mut bytes = config().encode().unwrap();
    bytes[24] = 0xff; // First byte of the required root object's UTF-8 key.
    assert!(ProtectedConfig::decode(&bytes).is_err());
}

#[test]
fn unknown_algorithm_descriptors_are_preserved_but_not_executed() {
    let mut value = header();
    value.protected.algorithm = Algorithm {
        id: 0x7fff,
        parameters: vec![1, 2, 3],
    };
    assert_eq!(Header::decode(&value.encode().unwrap()).unwrap(), value);
}

#[test]
fn authentication_inputs_bind_public_metadata_and_use_separate_domains() {
    let original = header();
    let expected = original.protected_aad().unwrap();
    let mut changes = Vec::new();
    let mut changed = original.clone();
    changed.filesystem_id[0] ^= 1;
    changes.push(changed);
    let mut changed = original.clone();
    changed.keyslots[0].id[0] ^= 1;
    changes.push(changed);
    let mut changed = original.clone();
    changed.keyslots[0].kdf.parameters.push(1);
    changes.push(changed);
    let mut changed = original.clone();
    changed.keyslots[0].wrapped_master_key.ciphertext[0] ^= 1;
    changes.push(changed);
    let mut changed = original.clone();
    changed.protected.algorithm.id += 1;
    changes.push(changed);
    let mut changed = original.clone();
    changed.protected.nonce[0] ^= 1;
    changes.push(changed);
    let mut changed = original.clone();
    changed.extensions.push(Extension {
        kind: 0x8000,
        value: vec![1],
    });
    changes.push(changed);
    for changed in changes {
        assert_ne!(changed.protected_aad().unwrap(), expected);
    }
    let slot_aad = original.keyslots[0]
        .wrapping_aad(&original.filesystem_id)
        .unwrap();
    assert_ne!(slot_aad, expected);
    let mut changed = original.clone();
    changed.keyslots[0].kdf.id += 1;
    assert_ne!(
        changed.keyslots[0]
            .wrapping_aad(&original.filesystem_id)
            .unwrap(),
        slot_aad
    );
    // Ciphertext is authenticated by AEAD itself, not recursively included in its AAD.
    let mut changed = original;
    changed.protected.ciphertext[0] ^= 1;
    assert_eq!(changed.protected_aad().unwrap(), expected);
}

#[test]
fn mutated_inputs_never_panic_and_accepted_headers_remain_canonical() {
    let fixture = header().encode().unwrap();
    for index in 0..fixture.len() {
        for replacement in [0, 1, 127, 255] {
            let mut bytes = fixture.clone();
            bytes[index] = replacement;
            if let Ok(decoded) = Header::decode(&bytes) {
                assert_eq!(decoded.encode().unwrap(), bytes);
            }
        }
    }
}
