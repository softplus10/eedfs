use super::*;
use crate::format::{
    directory::{Directory, Entry},
    directory_tree::{Page, Root},
};

async fn indexed(server: &Server, count: usize) -> (Arc<Volume>, Directory) {
    let (volume, _) = server.file().await;
    let root = volume
        .create_inode(volume.root, inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    *server.state.inode.lock().unwrap() = volume.inode_name(&root.body.id).unwrap();
    let directory = Directory {
        entries: (0..count)
            .map(|i| Entry {
                name: format!("item-{i:06}"),
                id: (i as u128 + 128).to_le_bytes(),
                kind: inode::FILE,
            })
            .collect(),
    };
    let mut lease = volume.acquire_directory_lease(volume.root).await.unwrap();
    volume
        .write_leased_directory(&mut lease, &directory)
        .await
        .unwrap();
    volume.release_directory_lease(lease).await.unwrap();
    (volume, directory)
}

#[tokio::test]
async fn indexed_directory_uses_bounded_lookup_and_cow_path_splits() {
    let server = Server::new();
    let (v, original) = indexed(&server, 4100).await;
    let before = v.load(v.root).await.unwrap();
    let InodeContent::Inline(bytes) = &before.body.content else {
        panic!()
    };
    let root = Root::decode(bytes).unwrap();
    assert_eq!(root.height, 2);
    let gets = server.state.get_requests.load(Ordering::SeqCst);
    assert_eq!(
        v.lookup(v.root, "item-002000").await.unwrap(),
        Some(original.entries[2000].clone())
    );
    assert!(server.state.get_requests.load(Ordering::SeqCst) - gets <= 8);
    assert!(v.lookup(v.root, "before-first").await.unwrap().is_none());
    assert_eq!(v.list(v.root).await.unwrap(), original.entries);
    let uploads = server.state.completed.load(Ordering::SeqCst);
    let added = Entry {
        name: "item-000000a".into(),
        id: [66; 16],
        kind: inode::FILE,
    };
    v.edit_entry(v.root, &added.name, None, Some(added.clone()))
        .await
        .unwrap();
    // Splitting a full leaf and branch must not rewrite all 4,100 entries.
    assert!(server.state.completed.load(Ordering::SeqCst) - uploads < 10);
    assert_eq!(v.lookup(v.root, &added.name).await.unwrap(), Some(added));
    assert_eq!(v.list(v.root).await.unwrap().len(), 4101);
    let objects = server.state.objects.lock().unwrap();
    let old_root_name = v
        .chunk_name(
            &v.names,
            &Piece {
                offset: 0,
                len: root.child.page.len,
                allocation: root.child.page.id,
                index: 0,
            },
        )
        .unwrap();
    assert!(!objects.contains_key(&old_root_name));
}

#[tokio::test]
async fn indexed_namespace_rename_links_subdirectories_and_concurrent_creates() {
    let server = Server::new();
    let (v, _) = indexed(&server, 1100).await;
    let real = v.create(v.root, "real", inode::FILE).await.unwrap();
    v.rename(v.root, "real", v.root, "moved", false)
        .await
        .unwrap();
    assert!(v.lookup(v.root, "real").await.unwrap().is_none());
    assert_eq!(
        v.lookup(v.root, "moved").await.unwrap().unwrap().id,
        real.body.id
    );
    let destination = v
        .create(v.root, "destination", inode::DIRECTORY)
        .await
        .unwrap();
    v.rename(v.root, "moved", destination.body.id, "moved", false)
        .await
        .unwrap();
    assert!(v.lookup(v.root, "moved").await.unwrap().is_none());
    v.rename(destination.body.id, "moved", v.root, "moved", false)
        .await
        .unwrap();
    v.rmdir(v.root, "destination").await.unwrap();
    v.link(real.body.id, v.root, "alias").await.unwrap();
    assert_eq!(v.load(real.body.id).await.unwrap().body.nlink, 2);
    v.unlink(v.root, "moved").await.unwrap();
    v.unlink(v.root, "alias").await.unwrap();
    v.create(v.root, "sub", inode::DIRECTORY).await.unwrap();
    assert_eq!(v.load(v.root).await.unwrap().body.nlink, 3);
    v.rmdir(v.root, "sub").await.unwrap();
    assert_eq!(v.load(v.root).await.unwrap().body.nlink, 2);
    let (a, b) = tokio::join!(
        v.create(v.root, "client-a", inode::FILE),
        v.create(v.root, "client-b", inode::FILE)
    );
    a.unwrap();
    b.unwrap();
    assert!(v.lookup(v.root, "client-a").await.unwrap().is_some());
    assert!(v.lookup(v.root, "client-b").await.unwrap().is_some());
    assert_eq!(v.list(v.root).await.unwrap().len(), 1102);
}

#[tokio::test]
async fn indexed_directory_failed_upload_or_cas_keeps_committed_pages_and_stale_cas_fails() {
    let server = Server::new();
    let (v, _) = indexed(&server, 1100).await;
    let before = v.load(v.root).await.unwrap();
    let deletes = server.state.delete_started.load(Ordering::SeqCst);
    let extra = Entry {
        name: "extra".into(),
        id: [44; 16],
        kind: inode::FILE,
    };
    server.state.deny_chunks.store(true, Ordering::SeqCst);
    assert!(
        v.edit_entry(v.root, &extra.name, None, Some(extra.clone()))
            .await
            .is_err()
    );
    server.state.deny_chunks.store(false, Ordering::SeqCst);
    server.state.deny_inode.store(true, Ordering::SeqCst);
    assert!(
        v.edit_entry(v.root, &extra.name, None, Some(extra.clone()))
            .await
            .is_err()
    );
    server.state.deny_inode.store(false, Ordering::SeqCst);
    assert_eq!(v.load(v.root).await.unwrap().etag, before.etag);
    assert_eq!(server.state.delete_started.load(Ordering::SeqCst), deletes);
    assert_eq!(v.list(v.root).await.unwrap().len(), 1100);
    let (staged, _) = v
        .prepare_directory_edit(&before, &extra.name, &None, Some(extra.clone()))
        .await
        .unwrap();
    v.create(v.root, "winner", inode::FILE).await.unwrap();
    let mut stale = before.body.clone();
    stale.generation += 1;
    stale.content = staged;
    assert!(matches!(
        v.publish(&before, &stale, Some(&before.etag)).await,
        Err(Error::Conflict)
    ));
    assert!(v.lookup(v.root, "extra").await.unwrap().is_none());
    assert!(v.lookup(v.root, "winner").await.unwrap().is_some());
    // Reusing a superseded snapshot now finds retired pages; it cannot restore them.
    assert!(matches!(
        v.prepare_directory_edit(&before, &extra.name, &None, Some(extra.clone()))
            .await,
        Err(Error::ChunkMissing)
    ));
}

#[tokio::test]
async fn indexed_directory_prunes_empty_leaf_collapses_root_and_becomes_empty_inline() {
    let server = Server::new();
    let (v, _) = server.file().await;
    let loaded = v
        .create_inode(v.root, inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    let entries: Vec<_> = ["a", "b", "c"]
        .into_iter()
        .map(|name| Entry {
            name: name.into(),
            id: [1; 16],
            kind: inode::FILE,
        })
        .collect();
    let left = v
        .write_page(&loaded, Page::Leaf(entries[..1].to_vec()))
        .await
        .unwrap();
    let right = v
        .write_page(&loaded, Page::Leaf(entries[1..].to_vec()))
        .await
        .unwrap();
    let parent = v
        .write_page(&loaded, Page::Branch(vec![left, right]))
        .await
        .unwrap();
    let mut body = loaded.body.clone();
    body.generation += 1;
    body.content = InodeContent::Inline(
        Root {
            child: parent,
            height: 1,
            entries: 3,
        }
        .encode()
        .unwrap(),
    );
    v.publish(&loaded, &body, Some(&loaded.etag)).await.unwrap();
    v.edit_entry(v.root, "a", Some(entries[0].clone()), None)
        .await
        .unwrap();
    let loaded = v.load(v.root).await.unwrap();
    let InodeContent::Inline(bytes) = loaded.body.content else {
        panic!()
    };
    assert_eq!(Root::decode(&bytes).unwrap().height, 0);
    v.edit_entry(v.root, "b", Some(entries[1].clone()), None)
        .await
        .unwrap();
    v.edit_entry(v.root, "c", Some(entries[2].clone()), None)
        .await
        .unwrap();
    assert!(v.list(v.root).await.unwrap().is_empty());
    let loaded = v.load(v.root).await.unwrap();
    let InodeContent::Inline(bytes) = loaded.body.content else {
        panic!()
    };
    assert!(Directory::decode(&bytes).unwrap().entries.is_empty());
}

#[tokio::test]
async fn password_change_only_updates_header_and_existing_mount_can_keep_writing() {
    let server = Server::new();
    let connection = Connection::test_client(&server.endpoint);
    let prefix = "password/";
    let v = Volume::format(connection.clone(), prefix.into(), b"old", 128 * 1024, 2)
        .await
        .unwrap();
    let loaded = v.create(v.root, "file", inode::FILE).await.unwrap();
    let mut file = v.file(loaded, &server.cache).unwrap();
    file.write(0, &vec![7; 128 * 1024]).await.unwrap();
    file.commit().await.unwrap();
    let before = server.state.objects.lock().unwrap().clone();
    assert!(
        Volume::change_password(connection.clone(), prefix, b"wrong", b"new")
            .await
            .is_err()
    );
    assert_eq!(*server.state.objects.lock().unwrap(), before);
    Volume::change_password(connection.clone(), prefix, b"old", b"new")
        .await
        .unwrap();
    {
        let after = server.state.objects.lock().unwrap();
        assert_eq!(after.len(), before.len());
        for (name, object) in &before {
            if name != "password/header" {
                assert_eq!(after.get(name), Some(object));
            }
        }
    }
    assert!(
        Volume::open(connection.clone(), prefix.into(), b"old", 128 * 1024, 2)
            .await
            .is_err()
    );
    let reopened = Volume::open(connection, prefix.into(), b"new", 128 * 1024, 2)
        .await
        .unwrap();
    assert_eq!(reopened.fs_id, v.fs_id);
    assert_eq!(reopened.root, v.root);
    file.write(0, b"after").await.unwrap();
    file.commit().await.unwrap();
    let mut reader = reopened
        .file(
            reopened.load(file.base.body.id).await.unwrap(),
            &server.cache,
        )
        .unwrap();
    assert_eq!(reader.read(0, 5).await.unwrap(), b"after");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn competing_password_changes_have_one_winner_and_never_overwrite_it() {
    let server = Server::new();
    let connection = Connection::test_client(&server.endpoint);
    let prefix = "password-race/";
    Volume::format(connection.clone(), prefix.into(), b"old", 128 * 1024, 2)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        Volume::change_password(connection.clone(), prefix, b"old", b"one"),
        Volume::change_password(connection.clone(), prefix, b"old", b"two")
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let (winner, loser) = if a.is_ok() {
        (b"one", b"two")
    } else {
        (b"two", b"one")
    };
    Volume::open(connection.clone(), prefix.into(), winner, 128 * 1024, 2)
        .await
        .unwrap();
    assert!(
        Volume::open(connection, prefix.into(), loser, 128 * 1024, 2)
            .await
            .is_err()
    );
}
