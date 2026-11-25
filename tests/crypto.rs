use eedfs::{
    crypto::{self, SecretKey, encryption as enc, kdf, naming, objects},
    format::{
        header::{Header, NamingConfig},
        inode::*,
    },
};
fn suites() -> [u16; 2] {
    [enc::XCHACHA20_POLY1305, enc::AES256_GCM_SIV]
}
fn params() -> kdf::argon2id::Parameters {
    kdf::argon2id::Parameters {
        salt: [7; 16],
        memory_kib: 8192,
        iterations: 1,
        parallelism: 1,
    }
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn rfc4231_hmac_sha256_vector() {
    assert_eq!(
        naming::hmac_sha256::digest(&[0x0b; 20], &[b"Hi There"]).to_vec(),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}
#[test]
fn rfc8452_aes256_gcm_siv_empty_vector() {
    let mut key = [0; 32];
    key[0] = 1;
    let mut nonce = [0; 12];
    nonce[0] = 3;
    let mut bytes = vec![];
    enc::encrypt_in_place(
        &enc::algorithm(enc::AES256_GCM_SIV).unwrap(),
        &SecretKey::from_bytes(key),
        &nonce,
        &[],
        &mut bytes,
    )
    .unwrap();
    assert_eq!(bytes, hex("07f5f4169bbf55a8400cd47ea6fd400f"));
}
#[test]
fn suites_authenticate_ciphertext_aad_nonce_key_and_reject_resealing() {
    for id in suites() {
        let alg = enc::algorithm(id).unwrap();
        let key = SecretKey::generate().unwrap();
        let mut r = enc::region(alg.clone()).unwrap();
        enc::seal(&mut r, &key, b"aad", b"secret").unwrap();
        assert_eq!(&**enc::open(&r, &key, b"aad").unwrap(), b"secret");
        assert!(enc::seal(&mut r, &key, b"aad", b"again").is_err());
        assert!(enc::open(&r, &key, b"other").is_err());
        assert!(enc::open(&r, &SecretKey::generate().unwrap(), b"aad").is_err());
        for i in 0..r.ciphertext.len() {
            let mut c = r.clone();
            c.ciphertext[i] ^= 1;
            assert!(enc::open(&c, &key, b"aad").is_err());
        }
        let mut c = r;
        c.nonce[0] ^= 1;
        assert!(enc::open(&c, &key, b"aad").is_err());
    }
}
#[test]
fn password_header_inode_chunk_and_sharing_roundtrip_with_cow() {
    for id in suites() {
        let suite = enc::algorithm(id).unwrap();
        let root = crypto::random_array().unwrap();
        let (header, _) =
            objects::create_header(b"test password", root, &suite, &params()).unwrap();
        let header = Header::decode(&header.encode().unwrap()).unwrap();
        let unlocked =
            objects::unlock_header(&header, b"test password", &header.keyslots[0].id).unwrap();
        assert_eq!(unlocked.config.root_inode, root);
        assert!(objects::unlock_header(&header, b"wrong", &header.keyslots[0].id).is_err());
        let fs = header.filesystem_id;
        let inode_name = naming::inode(&unlocked.config.naming, &fs, &root).unwrap();
        let inode_key = SecretKey::generate().unwrap();
        let config = ChunkedContent {
            naming: NamingConfig {
                algorithm: naming::algorithm().unwrap(),
                key: crypto::random_array().unwrap(),
            },
            runs: vec![ChunkRun {
                allocation_id: crypto::random_array().unwrap(),
                first_chunk: 10,
                plaintext_lengths: vec![5, 6],
            }],
        };
        let mut stored = std::collections::BTreeMap::new();
        for (index, plain) in [b"hello".as_slice(), b" world"].iter().enumerate() {
            let name = naming::chunk(
                &config.naming,
                &fs,
                &config.runs[0].allocation_id,
                10 + index as u64,
            )
            .unwrap();
            stored.insert(
                name.clone(),
                objects::seal_chunk(&inode_key, &fs, &name, &suite, plain).unwrap(),
            );
        }
        let body = InodeBody {
            id: root,
            kind: FILE,
            generation: 1,
            metadata: Default::default(),
            lease: None,
            content: InodeContent::Chunks(config),
            extensions: vec![],
        };
        let obj = objects::seal_inode(
            &unlocked.master_key,
            &inode_key,
            &fs,
            &inode_name,
            &suite,
            &body,
        )
        .unwrap();
        let obj = InodeObject::decode(&obj.encode().unwrap()).unwrap();
        let (reader_key, read_body) =
            objects::open_inode(&unlocked.master_key, &fs, &inode_name, &root, &obj).unwrap();
        assert_eq!(read_body, body);
        assert_eq!(
            objects::open_shared_inode(&inode_key, &fs, &inode_name, &root, &obj).unwrap(),
            body
        );
        assert!(
            objects::open_inode(&unlocked.master_key, &fs, "wrong-location", &root, &obj).is_err()
        );
        assert!(objects::open_shared_inode(&inode_key, &fs, &inode_name, &[0; 16], &obj).is_err());
        let InodeContent::Chunks(config) = &read_body.content else {
            panic!()
        };
        let mut plaintext = Vec::new();
        for (offset, &len) in config.runs[0].plaintext_lengths.iter().enumerate() {
            let name = naming::chunk(
                &config.naming,
                &fs,
                &config.runs[0].allocation_id,
                10 + offset as u64,
            )
            .unwrap();
            let bytes = &stored[&name];
            plaintext.extend_from_slice(
                &objects::open_chunk(
                    &reader_key,
                    &fs,
                    &name,
                    &obj.protected.algorithm,
                    len,
                    bytes,
                )
                .unwrap(),
            );
            assert!(objects::open_chunk(&reader_key, &fs, "swapped", &suite, len, bytes).is_err());
            assert!(objects::open_chunk(&reader_key, &fs, &name, &suite, len + 1, bytes).is_err());
            for pos in [0, bytes.len() - 1] {
                let mut corrupt = bytes.clone();
                corrupt[pos] ^= 1;
                assert!(
                    objects::open_chunk(&reader_key, &fs, &name, &suite, len, &corrupt).is_err()
                );
            }
        }
        assert_eq!(plaintext, b"hello world");
        // Fresh encryption of the same inode body does not reuse nonces.
        let next = objects::seal_inode(
            &unlocked.master_key,
            &inode_key,
            &fs,
            &inode_name,
            &suite,
            &body,
        )
        .unwrap();
        assert_ne!(next.protected.nonce, obj.protected.nonce);
        assert_ne!(next.wrapped_inode_key.nonce, obj.wrapped_inode_key.nonce);
    }
}
#[test]
fn domains_and_contexts_are_distinct() {
    let fs = [1; 16];
    let key = SecretKey::from_bytes([2; 32]);
    let body = kdf::derive(&key, &fs, kdf::Purpose::InodeBody).unwrap();
    let data = kdf::derive(&key, &fs, kdf::Purpose::DataChunk).unwrap();
    let a = enc::algorithm(1).unwrap();
    let mut r = enc::region(a).unwrap();
    enc::seal(&mut r, &body, b"", b"test").unwrap();
    assert!(enc::open(&r, &data, b"").is_err());
    let cfg = NamingConfig {
        algorithm: naming::algorithm().unwrap(),
        key: [3; 32],
    };
    let name = naming::inode(&cfg, &fs, &[4; 16]).unwrap();
    assert_eq!(name.len(), 64);
    assert_eq!(name, naming::inode(&cfg, &fs, &[4; 16]).unwrap());
    assert_ne!(name, naming::chunk(&cfg, &fs, &[4; 16], 0).unwrap());
    assert_ne!(name, naming::inode(&cfg, &[2; 16], &[4; 16]).unwrap());
    assert_ne!(
        naming::chunk(&cfg, &fs, &[4; 16], 0).unwrap(),
        naming::chunk(&cfg, &fs, &[5; 16], 0).unwrap()
    );
}
#[test]
fn untrusted_resource_requests_and_unknown_suites_are_rejected() {
    let mut p = params();
    p.memory_kib = u32::MAX;
    let descriptor = eedfs::format::header::Algorithm::from_parameters(1, 1, &p).unwrap();
    assert!(kdf::argon2id::derive(b"password", &descriptor).is_err());
    assert!(enc::algorithm(999).is_err());
    let mut a = enc::algorithm(1).unwrap();
    a.parameters.push(0);
    assert!(enc::nonce_size(&a).is_err());
}

#[test]
fn independent_libsodium_and_libargon2_vectors() {
    let mut lines = include_str!("fixtures/crypto-vectors.txt")
        .lines()
        .filter(|l| !l.starts_with('#'));
    let key = SecretKey::from_bytes(std::array::from_fn(|i| i as u8));
    let nonce: Vec<u8> = (0..24).collect();
    let mut msg = b"EEDFS independent vector".to_vec();
    enc::encrypt_in_place(
        &enc::algorithm(1).unwrap(),
        &key,
        &nonce,
        b"filesystem/object/context",
        &mut msg,
    )
    .unwrap();
    assert_eq!(msg, hex(lines.next().unwrap()));
    // Exercise the KDF output without exposing SecretKey bytes through its public API.
    let actual = kdf::argon2id::derive(b"password", &params().algorithm().unwrap()).unwrap();
    let expected = SecretKey::from_bytes(hex(lines.next().unwrap()).try_into().unwrap());
    let a = enc::algorithm(1).unwrap();
    let mut r = enc::region(a).unwrap();
    enc::seal(&mut r, &actual, b"", b"KDF known answer").unwrap();
    assert_eq!(
        &**enc::open(&r, &expected, b"").unwrap(),
        b"KDF known answer"
    );
}

#[test]
fn header_public_metadata_and_body_tampering_fail_unlock() {
    let suite = enc::algorithm(1).unwrap();
    let (header, _) = objects::create_header(b"password", [2; 16], &suite, &params()).unwrap();
    let slot = header.keyslots[0].id;
    let mut changes = Vec::new();
    let mut h = header.clone();
    h.filesystem_id[0] ^= 1;
    changes.push(h);
    let mut h = header.clone();
    h.keyslots[0].wrapped_master_key.ciphertext[0] ^= 1;
    changes.push(h);
    let mut h = header.clone();
    h.protected.ciphertext[0] ^= 1;
    changes.push(h);
    let mut h = header.clone();
    h.protected.nonce[0] ^= 1;
    changes.push(h);
    let mut h = header;
    h.keyslots[0].kdf.parameters[1] ^= 1;
    changes.push(h);
    for h in changes {
        assert!(objects::unlock_header(&h, b"password", &slot).is_err());
    }
}
