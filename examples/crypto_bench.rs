//! Reproducible CPU/memory microbenchmark; no S3, disk or FUSE I/O.
use clap::Parser;
use eedfs::{
    crypto::{SecretKey, encryption as enc, kdf, naming, objects},
    format::{header::NamingConfig, inode::*},
};
use std::{hint::black_box, time::Instant};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 64)]
    mib_per_sample: usize,
    #[arg(long, default_value_t = 3)]
    samples: usize,
    /// Also encrypt a 10 GiB logical stream per suite, retaining only one chunk.
    #[arg(long)]
    ten_gib: bool,
}
fn measure(
    mut f: impl FnMut(),
    iterations: usize,
    bytes: usize,
    samples: usize,
    label: &str,
    size: usize,
    workers: usize,
) {
    f(); // warm-up
    let mut times = Vec::new();
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..iterations {
            f();
        }
        times.push(start.elapsed().as_secs_f64());
    }
    times.sort_by(f64::total_cmp);
    let seconds = times[times.len() / 2];
    println!(
        "{label},{size},{workers},{iterations},{:.6},{:.3},{:.3},{:.6},{:.6}",
        seconds,
        bytes as f64 / 1048576.0 / seconds,
        iterations as f64 / seconds,
        times[0],
        times[times.len() - 1]
    );
}
fn main() {
    let args = Args::parse();
    assert!(args.samples > 0 && args.mib_per_sample > 0);
    let target = args.mib_per_sample.checked_mul(1048576).unwrap();
    println!(
        "operation,chunk_bytes,workers,iterations,median_seconds,mib_per_second,ops_per_second,min_seconds,max_seconds"
    );
    let fs = [1; 16];
    let key = SecretKey::generate().unwrap();
    let naming = NamingConfig {
        algorithm: naming::algorithm().unwrap(),
        key: [3; 32],
    };
    let mut counter = 0;
    measure(
        || {
            counter += 1;
            black_box(naming::chunk(&naming, &fs, &[4; 16], counter).unwrap());
        },
        100_000,
        0,
        args.samples,
        "hmac_name",
        0,
        1,
    );
    let b = InodeBody {
        id: [2; 16],
        kind: FILE,
        generation: 1,
        metadata: Default::default(),
        lease: None,
        deleted: false,
        nlink: 1,

        mutations: vec![],
        content: InodeContent::Chunks(ChunkedContent {
            naming: naming.clone(),
            holes: vec![],
            runs: vec![ChunkRun {
                allocation_id: [4; 16],
                first_chunk: 0,
                plaintext_lengths: vec![8 * 1048576; 1280],
            }],
        }),
        extensions: vec![],
    };
    let encoded = b.encode().unwrap();
    eprintln!("10 GiB/1280-chunk inode body: {} bytes", encoded.len());
    measure(
        || {
            black_box(b.encode().unwrap());
        },
        10_000,
        encoded.len() * 10_000,
        args.samples,
        "inode_encode_1280_chunks",
        encoded.len(),
        1,
    );
    measure(
        || {
            black_box(InodeBody::decode(&encoded).unwrap());
        },
        10_000,
        encoded.len() * 10_000,
        args.samples,
        "inode_decode_1280_chunks",
        encoded.len(),
        1,
    );
    let p = kdf::argon2id::Parameters::recommended()
        .unwrap()
        .algorithm()
        .unwrap();
    measure(
        || {
            black_box(kdf::argon2id::derive(b"benchmark password", &p).unwrap());
        },
        1,
        0,
        args.samples,
        "argon2id_64MiB_t3_p4",
        0,
        1,
    );
    for (id, label) in [
        (enc::XCHACHA20_POLY1305, "xchacha20"),
        (enc::AES256_GCM_SIV, "aes256_gcm_siv"),
    ] {
        let suite = enc::algorithm(id).unwrap();
        for size in [4096, 65536, 1048576, 8 * 1048576] {
            let plain = vec![0x5a; size];
            let count = (target / size).max(1);
            let mut buffer = Vec::with_capacity(size + 16);
            buffer.extend_from_slice(&plain);
            let raw_key = SecretKey::generate().unwrap();
            let mut nonce_counter = 0u64;
            let mut nonce = vec![0; enc::nonce_size(&suite).unwrap()];
            measure(
                || {
                    nonce_counter += 1;
                    nonce[..8].copy_from_slice(&nonce_counter.to_le_bytes());
                    enc::encrypt_in_place(&suite, &raw_key, &nonce, b"bench-aad", &mut buffer)
                        .unwrap();
                    black_box(&buffer);
                    buffer.truncate(size);
                },
                count,
                count * size,
                args.samples,
                &format!("{label}_aead_encrypt_in_place"),
                size,
                1,
            );
            let cipher =
                objects::seal_chunk(&key, &fs, "benchmark-object", &suite, &plain).unwrap();
            assert_eq!(
                &**objects::open_chunk(&key, &fs, "benchmark-object", &suite, size as u32, &cipher)
                    .unwrap(),
                plain
            );
            measure(
                || {
                    black_box(
                        objects::seal_chunk(&key, &fs, "benchmark-object", &suite, &plain).unwrap(),
                    );
                },
                count,
                count * size,
                args.samples,
                &format!("{label}_chunk_seal"),
                size,
                1,
            );
            measure(
                || {
                    black_box(
                        objects::open_chunk(
                            &key,
                            &fs,
                            "benchmark-object",
                            &suite,
                            size as u32,
                            &cipher,
                        )
                        .unwrap(),
                    );
                },
                count,
                count * size,
                args.samples,
                &format!("{label}_chunk_open"),
                size,
                1,
            );
            // Includes task creation/join and three independent keys. No shared mutable state.
            measure(
                || {
                    std::thread::scope(|scope| {
                        for _ in 0..3 {
                            let suite = &suite;
                            let plain = &plain;
                            scope.spawn(move || {
                                let key = SecretKey::generate().unwrap();
                                for _ in 0..count {
                                    black_box(
                                        objects::seal_chunk(
                                            &key,
                                            &fs,
                                            "benchmark-object",
                                            suite,
                                            plain,
                                        )
                                        .unwrap(),
                                    );
                                }
                            });
                        }
                    });
                },
                1,
                3 * count * size,
                args.samples,
                &format!("{label}_chunk_seal_parallel"),
                size,
                3,
            );
        }
        if args.ten_gib {
            let size = 8 * 1048576;
            let plain = vec![0x5a; size];
            let count = 10 * 1024 * 1024 * 1024usize / size;
            measure(
                || {
                    black_box(
                        objects::seal_chunk(&key, &fs, "benchmark-object", &suite, &plain).unwrap(),
                    );
                },
                count,
                10 * 1024 * 1024 * 1024usize,
                1,
                &format!("{label}_10GiB_stream_seal"),
                size,
                1,
            );
        }
    }
}
