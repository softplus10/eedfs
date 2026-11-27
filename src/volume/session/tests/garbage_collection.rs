use super::*;
use crate::{
    format::directory::{Directory, Entry},
    volume::GcOptions,
};

async fn volume(server: &Server) -> Arc<Volume> {
    Volume::format(
        Connection::test_client(&server.endpoint),
        "unit/".into(),
        b"gc test",
        128 * 1024,
        2,
    )
    .await
    .unwrap()
}
fn sweep() -> GcOptions {
    GcOptions {
        delete: true,
        ..Default::default()
    }
}
fn orphan(server: &Server) -> String {
    let key = format!("unit/{}", "a".repeat(64));
    server
        .state
        .objects
        .lock()
        .unwrap()
        .insert(key.clone(), (vec![9; 7], "\"orphan\"".into()));
    key
}

#[tokio::test]
async fn offline_gc_marks_indexed_pages_hardlinks_sparse_files_and_preserves_foreign_keys() {
    let server = Server::new();
    let v = volume(&server).await;
    let loaded = v.create(v.root, "data", inode::FILE).await.unwrap();
    let id = loaded.body.id;
    let mut file = v.file(loaded, &server.cache).unwrap();
    file.write(0, &vec![3; 180_000]).await.unwrap();
    file.write(1_000_000, b"tail").await.unwrap();
    file.commit().await.unwrap();
    let contents = file.base.body.clone();
    drop(file);
    let small = v.create(v.root, "small", inode::FILE).await.unwrap();
    let mut file = v.file(small.clone(), &server.cache).unwrap();
    file.write(0, b"inline").await.unwrap();
    file.commit().await.unwrap();
    drop(file);
    let link = v
        .symlink(v.root, "symbolic", b"missing/target", Default::default())
        .await
        .unwrap();
    let mut entries: Vec<_> = (0..1100)
        .map(|i| Entry {
            name: format!("alias-{i:06}"),
            id,
            kind: inode::FILE,
        })
        .collect();
    entries.push(Entry {
        name: "small".into(),
        id: small.body.id,
        kind: inode::FILE,
    });
    entries.push(Entry {
        name: "symbolic".into(),
        id: link.body.id,
        kind: inode::SYMLINK,
    });
    let mut lease = v.acquire_directory_lease(v.root).await.unwrap();
    v.write_leased_directory(&mut lease, &Directory { entries })
        .await
        .unwrap();
    v.release_directory_lease(lease).await.unwrap();
    let root = v.load(v.root).await.unwrap();
    let pages = v.directory_pages(&root).await.unwrap().1;
    assert!(!pages.is_empty());
    let unused = orphan(&server);
    let mut dead = v
        .file(
            v.create(v.root, "dead", inode::FILE).await.unwrap(),
            &server.cache,
        )
        .unwrap();
    dead.write(0, &vec![4; 140_000]).await.unwrap();
    dead.commit().await.unwrap();
    let mut garbage = chunk_names(&v, &dead.base.body);
    garbage.push(v.inode_name(&dead.base.body.id).unwrap());
    drop(dead);
    v.unlink(v.root, "dead").await.unwrap();
    let pages = v
        .directory_pages(&v.load(v.root).await.unwrap())
        .await
        .unwrap()
        .1;
    let before = {
        let mut objects = server.state.objects.lock().unwrap();
        objects.insert("unit/notes.txt".into(), (vec![1], "\"foreign\"".into()));
        objects.insert(
            format!("other/{}", "b".repeat(64)),
            (vec![2], "\"outside\"".into()),
        );
        objects.clone()
    };
    server.state.list_page_size.store(2, Ordering::SeqCst);
    let deletes = server.state.delete_started.load(Ordering::SeqCst);
    let report = v.collect_garbage(GcOptions::default()).await.unwrap();
    assert_eq!(server.state.delete_started.load(Ordering::SeqCst), deletes);
    assert_eq!(*server.state.objects.lock().unwrap(), before);
    assert_eq!(report.live_inodes, 4);
    assert_eq!(report.logical_file_bytes, 1_000_010);
    assert_eq!(report.ignored_objects, 1);
    assert_eq!(report.unreferenced_objects, garbage.len() + 1);
    assert!(server.state.list_requests.load(Ordering::SeqCst) > 2);
    let report = v.collect_garbage(sweep()).await.unwrap();
    assert_eq!(report.deleted_objects, garbage.len() + 1);
    {
        let objects = server.state.objects.lock().unwrap();
        for key in garbage.iter().chain([&unused]) {
            assert!(!objects.contains_key(key));
        }
        for key in pages.iter().chain(chunk_names(&v, &contents).iter()) {
            assert!(objects.contains_key(key));
        }
        assert!(objects.contains_key("unit/notes.txt"));
        assert!(objects.contains_key(&format!("other/{}", "b".repeat(64))));
    }
    assert_eq!(v.collect_garbage(sweep()).await.unwrap().deleted_objects, 0);
    let mut read = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    assert_eq!(read.read(999_999, 5).await.unwrap(), b"\0tail");
}

#[tokio::test]
async fn offline_gc_aborts_before_deletion_on_inventory_limit_missing_references_and_bad_metadata()
{
    let server = Server::new();
    let v = volume(&server).await;
    let unused = orphan(&server);
    assert!(
        v.collect_garbage(GcOptions {
            delete: true,
            max_objects: 1
        })
        .await
        .is_err()
    );
    let loaded = v.create(v.root, "data", inode::FILE).await.unwrap();
    let mut file = v.file(loaded, &server.cache).unwrap();
    file.write(0, &vec![1; 140_000]).await.unwrap();
    file.commit().await.unwrap();
    let chunk = chunk_names(&v, &file.base.body).remove(0);
    let original = server.state.objects.lock().unwrap().remove(&chunk).unwrap();
    assert!(v.collect_garbage(sweep()).await.is_err());
    server
        .state
        .objects
        .lock()
        .unwrap()
        .insert(chunk.clone(), (vec![0], original.1.clone()));
    assert!(v.collect_garbage(sweep()).await.is_err());
    server.state.objects.lock().unwrap().insert(chunk, original);
    let root_key = v.inode_name(&v.root).unwrap();
    let original = server
        .state
        .objects
        .lock()
        .unwrap()
        .get(&root_key)
        .unwrap()
        .clone();
    server
        .state
        .objects
        .lock()
        .unwrap()
        .get_mut(&root_key)
        .unwrap()
        .0[0] ^= 1;
    assert!(v.collect_garbage(sweep()).await.is_err());
    server
        .state
        .objects
        .lock()
        .unwrap()
        .insert(root_key.clone(), original);
    *server.state.deny_get_once.lock().unwrap() = Some(root_key);
    assert!(v.collect_garbage(sweep()).await.is_err());
    assert_eq!(server.state.delete_started.load(Ordering::SeqCst), 0);
    assert!(server.state.objects.lock().unwrap().contains_key(&unused));
}

#[tokio::test]
async fn offline_gc_rechecks_inventory_and_checks_candidate_etags_before_deletion() {
    let server = Server::new();
    let v = volume(&server).await;
    let unused = orphan(&server);
    *server.state.change_on_list.lock().unwrap() = Some((2, unused.clone()));
    assert!(matches!(
        v.collect_garbage(sweep()).await,
        Err(Error::Conflict)
    ));
    assert_eq!(server.state.delete_started.load(Ordering::SeqCst), 0);
    assert!(
        v.connection
            .delete_checked(&unused, "\"orphan\"")
            .await
            .is_err()
    );
    assert!(server.state.objects.lock().unwrap().contains_key(&unused));
    v.connection
        .delete_checked(&unused, "\"concurrent-change\"")
        .await
        .unwrap();
    v.connection.delete(&unused).await.unwrap();
}

#[tokio::test]
async fn offline_gc_delete_error_is_visible_and_rerunning_sweep_is_safe() {
    let server = Server::new();
    let v = volume(&server).await;
    let unused = orphan(&server);
    server.state.deny_delete.store(true, Ordering::SeqCst);
    assert!(v.collect_garbage(sweep()).await.is_err());
    assert!(server.state.objects.lock().unwrap().contains_key(&unused));
    server.state.deny_delete.store(false, Ordering::SeqCst);
    assert_eq!(v.collect_garbage(sweep()).await.unwrap().deleted_objects, 1);
    assert_eq!(v.collect_garbage(sweep()).await.unwrap().deleted_objects, 0);
}

#[tokio::test]
async fn inventory_rejects_malformed_pagination_scope_and_sizes() {
    let server = Server::new();
    let connection = Connection::test_client(&server.endpoint);
    for contents in [
        "<IsTruncated>true</IsTruncated>",
        "<IsTruncated>true</IsTruncated><NextContinuationToken>0</NextContinuationToken>",
        "<IsTruncated>false</IsTruncated><Contents><Key>outside/key</Key><ETag>x</ETag><Size>1</Size></Contents>",
        "<IsTruncated>false</IsTruncated><Contents><Key>unit/key</Key><ETag>x</ETag><Size>-1</Size></Contents>",
        "<IsTruncated>false</IsTruncated><Contents><Key>unit/key</Key><Size>1</Size></Contents>",
    ] {
        *server.state.list_override.lock().unwrap() =
            Some(format!("<ListBucketResult>{contents}</ListBucketResult>"));
        assert!(connection.list_page("unit/", Some("0")).await.is_err());
    }
}
