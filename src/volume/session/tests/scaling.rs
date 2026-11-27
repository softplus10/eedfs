use super::*;
use crate::{
    format::{directory::Entry, header::NamingConfig},
    volume::{GcOptions, resources::Limits},
};

#[tokio::test]
async fn inherited_create_reuses_parent_read_and_keeps_setgid_rules() {
    let server = Server::new();
    let v = Volume::format_with_metadata(
        Connection::test_client(&server.endpoint),
        "unit/".into(),
        b"inherit test",
        128 * 1024,
        2,
        crate::format::metadata::Metadata::new(10, 42, 0o2775),
    )
    .await
    .unwrap();
    let before = server.state.get_requests.load(Ordering::SeqCst);
    let file = v
        .create_inheriting_metadata(
            v.root,
            "file",
            inode::FILE,
            crate::format::metadata::Metadata::new(11, 12, 0o640),
        )
        .await
        .unwrap();
    assert_eq!(file.body.metadata.gid, 42);
    assert_eq!(file.body.metadata.uid, 11);
    assert_eq!(file.body.metadata.mode, 0o640);
    assert_eq!(server.state.get_requests.load(Ordering::SeqCst) - before, 2);
    let directory = v
        .create_inheriting_metadata(
            v.root,
            "dir",
            inode::DIRECTORY,
            crate::format::metadata::Metadata::new(11, 12, 0o750),
        )
        .await
        .unwrap();
    assert_eq!(directory.body.metadata.gid, 42);
    assert_eq!(directory.body.metadata.mode, 0o2750);
}

#[tokio::test]
async fn conditional_upload_retry_keeps_bytes_and_does_not_rebase_stale_etag() {
    let server = Server::new();
    let connection = Connection::test_client_attempts(&server.endpoint, 3);
    // The server stores the chunk and drops the successful response. The SDK
    // retries the same create-only PUT; readback must resolve its ensuing 412.
    *server.state.lose_put_once.lock().unwrap() = Some((false, true));
    let bytes = vec![37; 128 * 1024];
    let etag = match connection
        .put_data("unit/retry", bytes.clone(), None)
        .await
        .unwrap()
    {
        PutResult::Applied(etag) => etag,
        PutResult::Conflict => panic!("lost success was not resolved"),
    };
    assert_eq!(server.state.completed.load(Ordering::SeqCst), 1);
    assert_eq!(server.state.started.load(Ordering::SeqCst), 2);
    assert!(matches!(
        connection
            .put_data("unit/retry", b"updated".to_vec(), Some(&etag))
            .await
            .unwrap(),
        PutResult::Applied(_)
    ));
    assert!(matches!(
        connection
            .put_data("unit/retry", b"stale".to_vec(), Some(&etag))
            .await
            .unwrap(),
        PutResult::Conflict
    ));
    assert_eq!(
        connection
            .get_data("unit/retry", bytes.len())
            .await
            .unwrap()
            .unwrap()
            .bytes,
        b"updated"
    );
}

async fn large(server: &Server) -> (Arc<Volume>, [u8; 16]) {
    let v = Volume::format(
        Connection::test_client(&server.endpoint),
        "unit/".into(),
        b"index test",
        128 * 1024,
        2,
    )
    .await
    .unwrap();
    let loaded = v.create(v.root, "large", inode::FILE).await.unwrap();
    let id = loaded.body.id;
    let naming = NamingConfig {
        algorithm: naming::algorithm().unwrap(),
        key: [71; 32],
    };
    let allocation = [72; 16];
    let mut body = loaded.body.clone();
    body.generation = 6000;
    body.content = InodeContent::Chunks(ChunkedContent {
        naming: naming.clone(),
        runs: vec![ChunkRun {
            allocation_id: allocation,
            first_chunk: 0,
            plaintext_lengths: vec![128; 5000],
        }],
        holes: vec![],
    });
    body.mutations = (1..=5000)
        .map(|generation| Mutation {
            generation,
            size_changed: generation == 5000,
            attribute_fields: 0,
            ranges: vec![(generation * 64, generation * 64 + 1)],
        })
        .collect();
    let mut stored = Vec::new();
    for index in 0..5000 {
        let piece = Piece {
            offset: index * 128,
            len: 128,
            allocation,
            index,
        };
        let name = v.chunk_name(&naming, &piece).unwrap();
        let bytes = objects::seal_chunk(
            &loaded.key,
            &v.fs_id,
            &name,
            &loaded.suite,
            &[(index % 251) as u8; 128],
        )
        .unwrap();
        stored.push((name, (bytes, format!("\"data-{index}\""))));
    }
    server.state.objects.lock().unwrap().extend(stored);
    v.publish_file(&loaded, body).await.unwrap();
    (v, id)
}
#[tokio::test]
async fn large_extent_and_version_trees_read_by_path_copy_edits_and_survive_gc() {
    let server = Server::new();
    let (v, id) = large(&server).await;
    let loaded = v.load(id).await.unwrap();
    assert!(matches!(loaded.body.content, InodeContent::Indexed(_)));
    assert!(loaded.body.encode().unwrap().len() < 4096);
    let before = server.state.get_requests.load(Ordering::SeqCst);
    let mut f = v.file(loaded, &server.cache).unwrap();
    assert_eq!(
        f.read(1234 * 128 + 7, 6).await.unwrap(),
        vec![(1234 % 251) as u8; 6]
    );
    assert!(server.state.get_requests.load(Ordering::SeqCst) - before <= 5);
    let read_requests = server.state.get_requests.load(Ordering::SeqCst);
    f.commit().await.unwrap();
    assert_eq!(
        server.state.get_requests.load(Ordering::SeqCst),
        read_requests
    );
    f.prepare().await.unwrap();
    assert!(f.base.body.mutations.len() > 4096);
    let old_pages = v.index_page_names(&f.base).unwrap();
    let puts = server.state.started.load(Ordering::SeqCst);
    f.write(2000 * 128 + 3, b"changed").await.unwrap();
    f.commit().await.unwrap();
    assert!(server.state.started.load(Ordering::SeqCst) - puts < 14);
    let pages = v.index_page_names(&f.base).unwrap();
    assert!(old_pages.iter().filter(|p| pages.contains(p)).count() > old_pages.len() - 10);
    drop(f);
    let report = v.collect_garbage(GcOptions::default()).await.unwrap();
    assert_eq!(report.live_inodes, 2);
    assert_eq!(report.unreferenced_objects, 0);
    let mut read = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    assert_eq!(read.read(2000 * 128 + 3, 7).await.unwrap(), b"changed");
}
#[tokio::test]
async fn indexed_history_keeps_disjoint_merge_overlap_and_sparse_resize_rules() {
    let server = Server::new();
    let (v, id) = large(&server).await;
    let mut a = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    let mut b = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    a.write(0, b"first!").await.unwrap();
    b.write(128 * 3000, b"other!").await.unwrap();
    b.commit().await.unwrap();
    a.commit().await.unwrap();
    let mut loser = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    let mut winner = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    loser.write(0, b"loser!").await.unwrap();
    winner.write(0, b"winner").await.unwrap();
    winner.commit().await.unwrap();
    assert!(matches!(loser.commit().await, Err(Error::Conflict)));
    drop(loser);
    drop(winner);
    drop(a);
    drop(b);
    let mut f = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    f.resize(128).unwrap();
    f.resize(1 << 34).unwrap();
    f.commit().await.unwrap();
    assert_eq!(f.read(0, 6).await.unwrap(), b"winner");
    assert_eq!(f.read(128, 64).await.unwrap(), vec![0; 64]);
    assert_eq!(f.allocated_size(), 128);
    f.resize(4).unwrap();
    f.commit().await.unwrap();
    assert_eq!(f.read(0, 8).await.unwrap(), b"winn");
}
#[tokio::test]
async fn mount_budgets_preserve_dirty_data_release_spool_and_fail_before_publication() {
    let server = Server::new();
    let (v, mut a) = server.file().await;
    v.resources
        .configure(Limits {
            memory_bytes: 4 * 1024 * 1024,
            spool_bytes: 4096,
        })
        .unwrap();
    a.write(0, b"accepted").await.unwrap();
    assert!(matches!(
        a.write(8192, b"rejected").await,
        Err(Error::NoSpace)
    ));
    assert_eq!(a.size, 8);
    assert_eq!(a.read(0, 8).await.unwrap(), b"accepted");
    a.commit().await.unwrap();
    let other = v
        .create_inode([5; 16], inode::FILE, Default::default())
        .await
        .unwrap();
    let mut other = v.file(other, &server.cache).unwrap();
    assert!(matches!(
        other.write(0, b"blocked").await,
        Err(Error::NoSpace)
    ));
    assert_eq!(other.size, 0);
    drop(other);
    assert_eq!(v.resources.usage().1, 4096);
    a.resize(0).unwrap();
    a.commit().await.unwrap();
    assert_eq!(v.resources.usage().1, 0);
    v.resources
        .configure(Limits {
            memory_bytes: 4 * 1024 * 1024,
            spool_bytes: 512 * 1024,
        })
        .unwrap();
    a.write(0, &vec![5; 200_000]).await.unwrap();
    a.commit().await.unwrap();
    assert_eq!(v.resources.usage().1, 0);
    assert_eq!(a.read(0, 6).await.unwrap(), vec![5; 6]);
    drop(a);
    assert_eq!(v.resources.usage().1, 0);
    let guard = v.resources.memory(2 * 1024 * 1024).unwrap();
    assert!(matches!(
        v.resources.memory(2 * 1024 * 1024),
        Err(Error::NoMemory)
    ));
    let progress = v.resources.work_memory(1024 * 1024).unwrap();
    drop(progress);
    drop(guard);
}
#[tokio::test]
async fn directory_batches_are_bounded_and_usage_never_downloads_inodes() {
    let server = Server::new();
    let (v, _) = server.file().await;
    v.create_inode(v.root, inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    let mut lease = v.acquire_directory_lease(v.root).await.unwrap();
    let directory = crate::format::directory::Directory {
        entries: (0..4100)
            .map(|i| Entry {
                name: format!("item-{i:05}"),
                id: [4; 16],
                kind: inode::FILE,
            })
            .collect(),
    };
    v.write_leased_directory(&mut lease, &directory)
        .await
        .unwrap();
    v.release_directory_lease(lease).await.unwrap();
    let before = server.state.get_requests.load(Ordering::SeqCst);
    let batch = v
        .directory_after(v.root, Some("item-03000"), 64)
        .await
        .unwrap();
    assert_eq!(batch.len(), 64);
    assert_eq!(batch[0].name, "item-03001");
    assert!(server.state.get_requests.load(Ordering::SeqCst) - before < 9);
    let gets = server.state.get_requests.load(Ordering::SeqCst);
    let first = v.connection.usage("unit/", 100_000).await.unwrap();
    let lists = server.state.list_requests.load(Ordering::SeqCst);
    let cached = v.connection.usage("unit/", 100_000).await.unwrap();
    assert_eq!(first.bytes, cached.bytes);
    assert_eq!(server.state.list_requests.load(Ordering::SeqCst), lists);
    assert_eq!(server.state.get_requests.load(Ordering::SeqCst), gets);
}

#[tokio::test]
async fn shared_request_budget_leaves_control_capacity_and_releases_failed_put_permits() {
    let server = Server::new();
    let (v, _) = server.file().await;
    let c = Connection::test_client(&server.endpoint)
        .with_request_limit(2)
        .unwrap();
    let started = server.state.started.load(Ordering::SeqCst);
    *server.state.block.lock().unwrap() = true;
    let first = c.clone();
    let one = tokio::spawn(async move {
        first
            .put_data("unit/pipeline-one", vec![1; 1024], None)
            .await
    });
    wait_for(|| server.state.started.load(Ordering::SeqCst) > started).await;
    let second = c.clone();
    let two = tokio::spawn(async move {
        second
            .put_data("unit/pipeline-two", vec![2; 1024], None)
            .await
    });
    tokio::time::timeout(
        Duration::from_secs(2),
        c.head_etag(&v.inode_name(&[4; 16]).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(server.state.started.load(Ordering::SeqCst), started + 1);
    server.release();
    one.await.unwrap().unwrap();
    two.await.unwrap().unwrap();
    server.state.deny_chunks.store(true, Ordering::SeqCst);
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            c.put_data("unit/denied", vec![3; 1024], None)
        )
        .await
        .unwrap()
        .is_err()
    );
}
#[tokio::test]
async fn indexed_missing_pages_and_failed_inode_publication_preserve_the_previous_tree() {
    let server = Server::new();
    let (v, id) = large(&server).await;
    let loaded = v.load(id).await.unwrap();
    let previous = loaded.etag.clone();
    let InodeContent::Indexed(root) = &loaded.body.content else {
        panic!()
    };
    let key = v
        .file_page_name(&loaded, &root.versions.as_ref().unwrap().child)
        .unwrap();
    let page = server.state.objects.lock().unwrap().remove(&key).unwrap();
    let mut cold = v.file(loaded, &server.cache).unwrap();
    assert_eq!(cold.read(0, 3).await.unwrap(), vec![0; 3]);
    assert!(matches!(
        cold.write(0, b"x").await,
        Err(Error::ChunkMissing)
    ));
    assert_eq!(v.inode_etag(id).await.unwrap(), previous);
    server.state.objects.lock().unwrap().insert(key, page);
    drop(cold);
    let mut f = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    f.prepare().await.unwrap();
    let pages = v.index_page_names(&f.base).unwrap();
    *server.state.inode.lock().unwrap() = v.inode_name(&id).unwrap();
    f.write(0, b"local!").await.unwrap();
    server.state.deny_inode.store(true, Ordering::SeqCst);
    assert!(f.commit().await.is_err());
    assert_eq!(v.inode_etag(id).await.unwrap(), previous);
    {
        let objects = server.state.objects.lock().unwrap();
        assert!(pages.iter().all(|key| objects.contains_key(key)));
    }
    server.state.deny_inode.store(false, Ordering::SeqCst);
    f.commit().await.unwrap();
    drop(f);
    let inspected = v.collect_garbage(GcOptions::default()).await.unwrap();
    assert!(inspected.unreferenced_objects > 0);
    v.collect_garbage(GcOptions {
        delete: true,
        ..Default::default()
    })
    .await
    .unwrap();
    let mut f = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    assert_eq!(f.read(0, 6).await.unwrap(), b"local!");
}

#[tokio::test]
async fn exhausted_metadata_budget_does_not_change_sparse_layout_before_acceptance() {
    let server = Server::new();
    let (v, mut f) = server.file().await;
    f.resize(512 * 1024).unwrap();
    f.commit().await.unwrap();
    v.resources
        .configure(Limits {
            memory_bytes: 4 * 1024 * 1024,
            spool_bytes: 1024 * 1024,
        })
        .unwrap();
    let before = f.holes.clone();
    let usage = v.resources.usage().0;
    let full = v.resources.memory(3 * 1024 * 1024 - usage - 512).unwrap();
    assert!(matches!(
        f.write(4096, b"rejected").await,
        Err(Error::NoMemory)
    ));
    assert_eq!(f.holes, before);
    assert!(!f.is_dirty());
    drop(full);
    f.write(4096, b"accepted").await.unwrap();
    f.commit().await.unwrap();
    assert_eq!(f.read(4096, 8).await.unwrap(), b"accepted");
}

#[tokio::test]
async fn indexed_inline_history_never_discloses_the_volume_naming_key() {
    let server = Server::new();
    let (v, f) = server.file().await;
    let mut body = f.base.body.clone();
    body.generation = 600;
    body.content = InodeContent::Inline(vec![7; 4096]);
    body.mutations = (1..=600)
        .map(|generation| Mutation {
            generation,
            size_changed: false,
            attribute_fields: 0,
            ranges: vec![(generation * 2, generation * 2 + 1)],
        })
        .collect();
    let stored = v.publish_file(&f.base, body).await.unwrap();
    let cold = v.load(stored.body.id).await.unwrap();
    let InodeContent::Indexed(root) = &cold.body.content else {
        panic!()
    };
    assert_ne!(root.naming.key, v.names.key);
    assert!(root.extents.is_none());
    let child = &root.versions.as_ref().unwrap().child;
    let first = v.file_page_name(&cold, child).unwrap();
    let mut different = cold.clone();
    different.key = Arc::new(SecretKey::generate().unwrap());
    assert_ne!(first, v.file_page_name(&different, child).unwrap());
    let mut read = v.file(cold, &server.cache).unwrap();
    assert_eq!(read.read(12, 6).await.unwrap(), vec![7; 6]);
    read.prepare().await.unwrap();
    assert_eq!(read.base.body.mutations.len(), 600);
}
