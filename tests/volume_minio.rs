//! Requires a disposable S3 bucket. Run explicitly with --ignored --test-threads=1.
use eedfs::{
    crypto,
    format::{
        directory::{Directory, Entry},
        inode,
    },
    storage::s3::{Connection, ConnectionConfig, PutResult},
    volume::{Error, Volume},
};
use std::{sync::Arc, time::Duration};
fn connection() -> Connection {
    Connection::new(ConnectionConfig {
        bucket: std::env::var("S3_BUCKET").unwrap(),
        region: "us-east-1".into(),
        endpoint_url: Some(std::env::var("S3_ENDPOINT_URL").unwrap()),
        force_path_style: true,
        timeout: Duration::from_secs(60),
    })
    .unwrap()
}
fn prefix() -> String {
    format!(
        "test-{:x}/",
        u128::from_le_bytes(crypto::random_array().unwrap())
    )
}
#[test]
fn directory_payload_validates_names_order_and_framing() {
    let d = Directory {
        entries: vec![Entry {
            name: "hello".into(),
            id: [1; 16],
            kind: inode::FILE,
        }],
    };
    assert_eq!(Directory::decode(&d.encode().unwrap()).unwrap(), d);
    for name in ["", "..", "x/y", "a\0b"] {
        let invalid = Directory {
            entries: vec![Entry {
                name: name.into(),
                ..d.entries[0].clone()
            }],
        };
        assert!(invalid.encode().is_err());
    }
    for end in 0..d.encode().unwrap().len() {
        assert!(Directory::decode(&d.encode().unwrap()[..end]).is_err());
    }
}
#[tokio::test]
#[ignore = "requires a disposable real S3/MinIO bucket"]
async fn conditional_put_rejects_stale_versions() {
    let c = connection();
    let key = format!("{}object", prefix());
    let PutResult::Applied(first) = c.put(&key, vec![1], None).await.unwrap() else {
        panic!()
    };
    assert!(matches!(
        c.put(&key, vec![2], None).await.unwrap(),
        PutResult::Conflict
    ));
    let PutResult::Applied(_) = c.put(&key, vec![2], Some(&first)).await.unwrap() else {
        panic!()
    };
    assert!(matches!(
        c.put(&key, vec![3], Some(&first)).await.unwrap(),
        PutResult::Conflict
    ));
    assert_eq!(c.get(&key, 1).await.unwrap().unwrap().bytes, vec![2]);
    assert!(c.get(&key, 0).await.is_err());
}

#[tokio::test]
#[ignore = "requires a disposable real S3/MinIO bucket"]
async fn offline_gc_reports_sweeps_and_preserves_live_data() {
    use eedfs::volume::GcOptions;
    let c = connection();
    let prefix = prefix();
    let volume = Volume::format(c.clone(), prefix.clone(), b"gc integration", 128 * 1024, 4)
        .await
        .unwrap();
    let loaded = volume
        .create(volume.root, "live", inode::FILE)
        .await
        .unwrap();
    let id = loaded.body.id;
    let cache = std::env::temp_dir().join(format!("eedfs-gc-{}", std::process::id()));
    let mut file = volume.file(loaded, &cache).unwrap();
    file.write(0, &vec![7; 150_000]).await.unwrap();
    file.commit().await.unwrap();
    drop(file);
    let unused = format!("{prefix}{}", "c".repeat(64));
    let PutResult::Applied(old) = c.put(&unused, vec![1], None).await.unwrap() else {
        panic!()
    };
    let PutResult::Applied(_) = c.put(&unused, vec![2], Some(&old)).await.unwrap() else {
        panic!()
    };
    assert!(c.delete_checked(&unused, &old).await.is_err());
    assert_eq!(c.get(&unused, 1).await.unwrap().unwrap().bytes, vec![2]);
    let report = volume.collect_garbage(GcOptions::default()).await.unwrap();
    assert_eq!(report.unreferenced_objects, 1);
    assert_eq!(report.deleted_objects, 0);
    assert_eq!(report.logical_file_bytes, 150_000);
    let report = volume
        .collect_garbage(GcOptions {
            delete: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(report.deleted_objects, 1);
    assert!(c.get(&unused, 1).await.unwrap().is_none());
    assert_eq!(
        volume
            .collect_garbage(GcOptions::default())
            .await
            .unwrap()
            .unreferenced_objects,
        0
    );
    let mut file = volume.file(volume.load(id).await.unwrap(), &cache).unwrap();
    assert_eq!(file.read(0, 150_000).await.unwrap(), vec![7; 150_000]);
    drop(file);
    // Ordinary deletion remains idempotent for already missing objects.
    c.delete(&unused).await.unwrap();
    std::fs::remove_dir(cache).unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable real S3/MinIO bucket"]
async fn persistence_cow_sparse_truncate_conflicts_and_directory_merge() {
    let c = connection();
    let prefix = prefix();
    let password = b"integration password";
    let volume = Volume::format(c.clone(), prefix.clone(), password, 128 * 1024, 4)
        .await
        .unwrap();
    assert!(
        Volume::format(c.clone(), prefix.clone(), password, 128 * 1024, 4)
            .await
            .is_err()
    );
    assert!(
        Volume::open(c.clone(), prefix.clone(), b"wrong", 128 * 1024, 4)
            .await
            .is_err()
    );
    let cache = std::env::temp_dir().join(format!("eedfs-test-{}", std::process::id()));
    let loaded = volume
        .create(volume.root, "data", inode::FILE)
        .await
        .unwrap();
    let id = loaded.body.id;
    let mut file = volume.file(loaded, &cache).unwrap();
    let plain: Vec<u8> = (0..400_000).map(|i| (i % 251) as u8).collect();
    file.write(0, &plain).await.unwrap();
    file.commit().await.unwrap();
    drop(file);
    // New client uses a different write policy. Stored chunks remain variable-sized.
    let other = Volume::open(c.clone(), prefix.clone(), password, 256 * 1024, 4)
        .await
        .unwrap();
    let mut reader = other.file(other.load(id).await.unwrap(), &cache).unwrap();
    assert_eq!(reader.read(0, plain.len()).await.unwrap(), plain);
    reader.write(140_000, b"changed").await.unwrap();
    reader.commit().await.unwrap();
    let mut expected = plain.clone();
    expected[140_000..140_007].copy_from_slice(b"changed");
    assert_eq!(reader.read(0, expected.len()).await.unwrap(), expected);
    reader.resize(10).unwrap();
    reader.resize(400_000).unwrap();
    reader.commit().await.unwrap();
    let got = reader.read(0, 400_000).await.unwrap();
    assert_eq!(&got[..10], &plain[..10]);
    assert!(got[10..].iter().all(|&b| b == 0));
    reader.write(700_000, b"tail").await.unwrap();
    reader.commit().await.unwrap();
    assert_eq!(
        reader.read(699_990, 14).await.unwrap(),
        [vec![0; 10], b"tail".to_vec()].concat()
    );
    reader.resize(0).unwrap();
    reader.commit().await.unwrap();
    assert_eq!(other.load(id).await.unwrap().body.size().unwrap(), 0);
    let mut a = volume.file(volume.load(id).await.unwrap(), &cache).unwrap();
    let mut b = other.file(other.load(id).await.unwrap(), &cache).unwrap();
    a.write(0, b"winner").await.unwrap();
    b.write(0, b"loser").await.unwrap();
    a.commit().await.unwrap();
    assert!(matches!(b.commit().await, Err(Error::Conflict)));
    let mut latest = volume.file(volume.load(id).await.unwrap(), &cache).unwrap();
    assert_eq!(latest.read(0, 6).await.unwrap(), b"winner");
    let mut jobs = tokio::task::JoinSet::new();
    for client in 0..3 {
        let volume = Arc::clone(&volume);
        jobs.spawn(async move {
            for i in 0..10 {
                volume
                    .create(volume.root, &format!("client-{client}-{i}"), inode::FILE)
                    .await?;
            }
            Ok::<_, Error>(())
        });
    }
    while let Some(result) = jobs.join_next().await {
        result.unwrap().unwrap();
    }
    assert_eq!(volume.list(volume.root).await.unwrap().len(), 31);
    volume.unlink(volume.root, "data").await.unwrap();
    assert_eq!(volume.list(volume.root).await.unwrap().len(), 30);
    // Unlinked inode survives for existing readers; reclamation is deferred.
    assert!(volume.load(id).await.is_ok());
    let root = c
        .get(
            &volume.inode_name(&volume.root).unwrap(),
            inode::MAX_INODE_SIZE,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!root.bytes.windows(8).any(|w| w == b"client-0"));
    std::fs::remove_dir(cache).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable real S3/MinIO bucket"]
async fn partial_fsync_append_keeps_previously_committed_chunk_references() {
    let volume = Volume::format(connection(), prefix(), b"append test", 8 * 1024 * 1024, 4)
        .await
        .unwrap();
    let cache = std::env::temp_dir().join(format!("eedfs-append-{}", std::process::id()));
    let loaded = volume
        .create(volume.root, "append", inode::FILE)
        .await
        .unwrap();
    let id = loaded.body.id;
    let mut file = volume.file(loaded, &cache).unwrap();
    let first = vec![1; 3 * 1024 * 1024];
    file.write(0, &first).await.unwrap();
    assert_eq!(volume.load(id).await.unwrap().body.size().unwrap(), 0);
    file.commit().await.unwrap();
    let inode::InodeContent::Chunks(before) = volume.load(id).await.unwrap().body.content else {
        panic!()
    };
    assert_eq!(before.runs[0].plaintext_lengths, vec![3 * 1024 * 1024]);
    let second = vec![2; 2 * 1024 * 1024];
    file.write(first.len() as u64, &second).await.unwrap();
    assert_eq!(
        volume.load(id).await.unwrap().body.size().unwrap(),
        first.len() as u64
    );
    file.commit().await.unwrap();
    let inode::InodeContent::Chunks(after) = volume.load(id).await.unwrap().body.content else {
        panic!()
    };
    assert_eq!(&after.runs[..before.runs.len()], &before.runs);
    assert_eq!(after.runs[1].plaintext_lengths, vec![2 * 1024 * 1024]);
    let mut reader = volume.file(volume.load(id).await.unwrap(), &cache).unwrap();
    assert_eq!(
        reader.read(0, first.len() + second.len()).await.unwrap(),
        [first, second].concat()
    );
    std::fs::remove_dir(cache).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable real S3/MinIO bucket"]
async fn three_clients_merge_disjoint_bytes_and_refresh_retired_reader_snapshot() {
    let c = connection();
    let prefix = prefix();
    let password = b"merge test";
    let first = Volume::format(c.clone(), prefix.clone(), password, 128 * 1024, 4)
        .await
        .unwrap();
    let second = Volume::open(c.clone(), prefix.clone(), password, 128 * 1024, 4)
        .await
        .unwrap();
    let third = Volume::open(c, prefix, password, 128 * 1024, 4)
        .await
        .unwrap();
    let cache = std::env::temp_dir().join(format!("eedfs-merge-{}", std::process::id()));
    let loaded = first
        .create(first.root, "shared", inode::FILE)
        .await
        .unwrap();
    let id = loaded.body.id;
    let mut original = first.file(loaded, &cache).unwrap();
    original.write(0, &vec![0; 400_000]).await.unwrap();
    original.commit().await.unwrap();
    let snapshot = third.load(id).await.unwrap();
    let mut reader = third.file(snapshot.clone(), &cache).unwrap();
    let pins = eedfs::volume::snapshots::Snapshots::new(third.clone());
    pins.pin(&snapshot);
    let mut a = first.file(first.load(id).await.unwrap(), &cache).unwrap();
    let mut b = second.file(second.load(id).await.unwrap(), &cache).unwrap();
    a.write(100, b"first").await.unwrap();
    b.write(200, b"second").await.unwrap();
    a.commit().await.unwrap();
    b.commit().await.unwrap();
    pins.poll_once().await;
    assert!(pins.latest(id).unwrap().body.generation > snapshot.body.generation);
    assert_eq!(reader.read(100, 5).await.unwrap(), b"first");
    assert_eq!(reader.read(200, 6).await.unwrap(), b"second");
    let mut fresh = third.file(third.load(id).await.unwrap(), &cache).unwrap();
    assert_eq!(fresh.read(100, 5).await.unwrap(), b"first");
    assert_eq!(fresh.read(200, 6).await.unwrap(), b"second");
    let mut a = first.file(first.load(id).await.unwrap(), &cache).unwrap();
    let mut b = second.file(second.load(id).await.unwrap(), &cache).unwrap();
    a.write(a.size, b"late").await.unwrap();
    b.write(b.size, b"early").await.unwrap();
    b.commit().await.unwrap();
    assert!(matches!(a.commit().await, Err(Error::Conflict)));
    pins.unpin(id);
    std::fs::remove_dir(cache).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a disposable real S3/MinIO bucket"]
async fn directory_lease_excludes_other_clients_until_release() {
    let c = connection();
    let prefix = prefix();
    let a = Volume::format(c.clone(), prefix.clone(), b"lease test", 128 * 1024, 4)
        .await
        .unwrap();
    let b = Volume::open(c.clone(), prefix.clone(), b"lease test", 128 * 1024, 4)
        .await
        .unwrap();
    let other = Volume::open(c, prefix, b"lease test", 128 * 1024, 4)
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        a.acquire_directory_lease(a.root),
        b.acquire_directory_lease(b.root)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let mut holder = left.or(right).unwrap();
    assert!(matches!(
        other.create(other.root, "blocked", inode::FILE).await,
        Err(Error::Conflict)
    ));
    a.renew_directory_lease(&mut holder, Duration::from_secs(30))
        .await
        .unwrap();
    a.write_leased_directory(&mut holder, &Directory::default())
        .await
        .unwrap();
    b.release_directory_lease(holder).await.unwrap();
    other
        .create(other.root, "after-release", inode::FILE)
        .await
        .unwrap();
    assert_eq!(a.list(a.root).await.unwrap()[0].name, "after-release");
    assert!(b.load(b.root).await.unwrap().body.lease.is_none());
}
