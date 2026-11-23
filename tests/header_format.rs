use eedfs::format::header::{
    Algorithm, Extension, FormatError, Header, Keyslot, MAX_PARAMETERS, MAX_SIZE, NamingConfig,
    ProtectedConfig, SealedRegion, VERSION,
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
        root_inode: [0x44; 16],
        naming: NamingConfig {
            algorithm: algorithm(1),
            key: [0x77; 32],
        },
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
    let bytes = golden(include_str!("fixtures/header-v4.hex"));
    assert_eq!(header().encode().unwrap(), bytes);
    assert_eq!(Header::decode(&bytes).unwrap(), header());
}

#[test]
fn protected_config_matches_wire_fixture_without_a_root_key_field() {
    let bytes = golden(include_str!("fixtures/header-config-v4.hex"));
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
        required: false,
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
        required: false,
        kind: 0x8001,
        value: vec![7],
    });
    value.extensions[0].required = true;
    assert_eq!(value.encode(), Err(FormatError::RequiredExtension(0x8001)));
    assert_eq!(
        Header::decode(&unchecked_frame(b"EEDFSHDR", &value)),
        Err(FormatError::RequiredExtension(0x8001))
    );
}

#[test]
fn rejects_duplicate_and_out_of_order_extensions() {
    let extension = Extension {
        required: false,
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
    bad[8..10].copy_from_slice(&(VERSION + 1).to_le_bytes());
    assert_eq!(
        Header::decode(&bad),
        Err(FormatError::UnsupportedVersion(VERSION + 1))
    );
    let mut bad = bytes.clone();
    bad[10] = 1;
    assert!(Header::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Header::decode(&bad).is_err());
    // An enormous declared slot count in a tiny payload must fail before allocation.
    let mut body = vec![0x11; 16];
    body.extend_from_slice(&[0xff; 9]);
    body.push(1);
    assert!(Header::decode(&frame_body(b"EEDFSHDR", &body)).is_err());
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
    assert!(Header::decode(&unchecked_frame(b"EEDFSHDR", &value)).is_err());
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
fn root_is_a_fixed_size_inode_id() {
    let mut value = config();
    value.root_inode = [0; 16];
    assert_eq!(
        ProtectedConfig::decode(&value.encode().unwrap()).unwrap(),
        value
    );
    assert_eq!(
        value.encode().unwrap().len(),
        config().encode().unwrap().len()
    );
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
        required: false,
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

fn frame_body(magic: &[u8; 8], body: &[u8]) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}
fn unchecked_frame<T: serde::Serialize>(magic: &[u8; 8], value: &T) -> Vec<u8> {
    frame_body(magic, &postcard::to_allocvec(value).unwrap())
}

#[test]
fn old_experimental_formats_are_rejected_explicitly() {
    for (fixture, version) in [
        (include_str!("fixtures/header-v1.hex"), 1),
        (include_str!("fixtures/header-v2.hex"), 2),
        (include_str!("fixtures/header-v3.hex"), 3),
    ] {
        assert_eq!(
            Header::decode(&golden(fixture)),
            Err(FormatError::UnsupportedVersion(version))
        );
    }
    let old = golden(include_str!("fixtures/header-config-v2.hex"));
    assert_eq!(
        ProtectedConfig::decode(&old),
        Err(FormatError::UnsupportedVersion(2))
    );
}

#[test]
fn rejects_oversized_deserialized_parameters_and_roots() {
    let mut value = header();
    value.keyslots[0].kdf.parameters = vec![0; MAX_PARAMETERS + 1];
    assert!(Header::decode(&unchecked_frame(b"EEDFSHDR", &value)).is_err());
    let mut bytes = config().encode().unwrap();
    bytes.remove(16);
    assert!(ProtectedConfig::decode(&bytes).is_err());
}

#[test]
fn rejects_noncanonical_varints_and_bytes_inside_the_frame() {
    let mut bytes = header().encode().unwrap();
    // The first algorithm ID follows the filesystem ID, slot count and slot ID.
    assert_eq!(bytes[49], 1);
    bytes.splice(49..50, [0x81, 0x00]);
    let len = (bytes.len() - 16) as u32;
    bytes[12..16].copy_from_slice(&len.to_le_bytes());
    assert!(Header::decode(&bytes).is_err());
    let mut bytes = header().encode().unwrap();
    bytes.push(0);
    let len = (bytes.len() - 16) as u32;
    bytes[12..16].copy_from_slice(&len.to_le_bytes());
    assert!(Header::decode(&bytes).is_err());
}

#[test]
fn algorithm_parameters_have_their_own_typed_schema() {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestKdfParameters {
        salt: [u8; 16],
        iterations: u32,
    }
    // Test-only numeric ID; actual algorithm assignments remain future crypto work.
    let params = TestKdfParameters {
        salt: [7; 16],
        iterations: 3,
    };
    let descriptor = Algorithm::from_parameters(42, 1, &params).unwrap();
    assert_eq!(
        descriptor
            .decode_parameters::<TestKdfParameters>(42, 1)
            .unwrap(),
        params
    );
    assert!(
        descriptor
            .decode_parameters::<TestKdfParameters>(43, 1)
            .is_err()
    );
    assert!(
        descriptor
            .decode_parameters::<TestKdfParameters>(42, 2)
            .is_err()
    );
    assert!(Algorithm::from_parameters(42, 0, &params).is_err());
    let mut noncanonical = descriptor.clone();
    noncanonical.parameters.splice(0..1, [0x81, 0x00]);
    assert!(
        noncanonical
            .decode_parameters::<TestKdfParameters>(42, 1)
            .is_err()
    );
    let mut trailing = descriptor;
    trailing.parameters.push(0);
    assert!(
        trailing
            .decode_parameters::<TestKdfParameters>(42, 1)
            .is_err()
    );
}

#[test]
fn naming_key_and_scheme_roundtrip_in_protected_configuration() {
    let original = config();
    let mut changed = original.clone();
    changed.naming.key[0] ^= 1;
    assert_ne!(original.encode().unwrap(), changed.encode().unwrap());
    assert_eq!(
        ProtectedConfig::decode(&changed.encode().unwrap()).unwrap(),
        changed
    );
    changed.naming.algorithm = Algorithm::from_parameters(77, 1, &()).unwrap();
    assert_eq!(
        ProtectedConfig::decode(&changed.encode().unwrap()).unwrap(),
        changed
    );
}

#[test]
fn invalid_naming_descriptors_are_rejected_on_encode_and_decode() {
    let mut value = config();
    value.naming.algorithm.id = 0;
    assert!(value.encode().is_err());
    assert!(ProtectedConfig::decode(&unchecked_frame(b"EEDFSCFG", &value)).is_err());
    value.naming.algorithm.id = 1;
    value.naming.algorithm.parameters = vec![0; MAX_PARAMETERS + 1];
    assert!(value.encode().is_err());
    assert!(ProtectedConfig::decode(&unchecked_frame(b"EEDFSCFG", &value)).is_err());
}

#[test]
fn debug_output_redacts_the_naming_secret_including_in_parent_config() {
    let value = config();
    let secret = format!("{:?}", value.naming.key);
    for debug in [format!("{:?}", value.naming), format!("{value:?}")] {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&secret));
    }
}
