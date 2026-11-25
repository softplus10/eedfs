//! Deterministic loopback S3 fixture with controllable upload gates/failures.
use super::*;
use crate::{
    crypto::{SecretKey, encryption},
    format::{
        header::NamingConfig,
        inode::{FILE, InodeBody},
    },
    storage::s3::Connection,
};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

struct State {
    objects: Mutex<HashMap<String, (Vec<u8>, String)>>,
    inode: Mutex<String>,
    block: Mutex<bool>,
    gate: Condvar,
    deny_chunks: AtomicBool,
    deny_inode: AtomicBool,
    deny_put_once: Mutex<Option<(String, usize)>>,
    started: AtomicUsize,
    completed: AtomicUsize,
    serial: AtomicUsize,
    stop: AtomicBool,
}
struct Server {
    endpoint: String,
    state: Arc<State>,
    worker: Option<thread::JoinHandle<()>>,
    cache: PathBuf,
}
impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(State {
            objects: Mutex::new(HashMap::new()),
            inode: Mutex::new(String::new()),
            block: Mutex::new(false),
            gate: Condvar::new(),
            deny_chunks: AtomicBool::new(false),
            deny_inode: AtomicBool::new(false),
            deny_put_once: Mutex::new(None),
            started: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            serial: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
        });
        let shared = state.clone();
        let worker = thread::spawn(move || {
            let mut workers = Vec::new();
            while !shared.stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let s = shared.clone();
                        workers.push(thread::spawn(move || {
                            let _ = serve(socket, &s);
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
            for w in workers {
                w.join().unwrap();
            }
        });
        let cache = std::env::temp_dir().join(format!(
            "eedfs-pipeline-{:x}",
            u128::from_le_bytes(crypto::random_array().unwrap())
        ));
        Self {
            endpoint,
            state,
            worker: Some(worker),
            cache,
        }
    }
    fn release(&self) {
        *self.state.block.lock().unwrap() = false;
        self.state.gate.notify_all();
    }
    async fn file(&self) -> (Arc<Volume>, FileSession) {
        let volume = Arc::new(Volume {
            fs_id: [1; 16],
            root: [2; 16],
            connection: Connection::test_client(&self.endpoint),
            prefix: "unit/".into(),
            master: SecretKey::generate().unwrap(),
            names: NamingConfig {
                algorithm: naming::algorithm().unwrap(),
                key: [3; 32],
            },
            suite: encryption::algorithm(1).unwrap(),
            chunk_size: 128 * 1024,
            parallelism: 2,
        });
        let mut loaded = Loaded {
            body: InodeBody {
                id: [4; 16],
                kind: FILE,
                generation: 0,
                metadata: Default::default(),
                lease: None,
                deleted: false,
                nlink: 1,

                mutations: vec![],
                content: InodeContent::Inline(vec![]),
                extensions: vec![],
            },
            key: Arc::new(SecretKey::generate().unwrap()),
            suite: encryption::algorithm(1).unwrap(),
            etag: String::new(),
        };
        *self.state.inode.lock().unwrap() = volume.inode_name(&loaded.body.id).unwrap();
        loaded.etag = volume.publish(&loaded, &loaded.body, None).await.unwrap();
        let session = volume.file(loaded, &self.cache).unwrap();
        (volume, session)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        self.release();
        self.worker.take().unwrap().join().unwrap();
        let _ = std::fs::remove_dir(&self.cache);
    }
}
fn serve(mut stream: TcpStream, s: &State) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let fields: Vec<_> = first.split_whitespace().collect();
    if fields.len() < 2 {
        return Ok(());
    }
    let method = fields[0];
    let key = fields[1]
        .split('?')
        .next()
        .unwrap()
        .strip_prefix("/test/")
        .unwrap()
        .to_owned();
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let n: usize = headers
        .get("content-length")
        .map_or(0, |v| v.parse().unwrap());
    let mut body = vec![0; n];
    reader.read_exact(&mut body)?;
    let is_inode = key == *s.inode.lock().unwrap();
    let (status, bytes, etag) = match method {
        "HEAD" => match s.objects.lock().unwrap().get(&key).cloned() {
            Some((_, e)) => (200, Vec::new(), Some(e)),
            None => (404, Vec::new(), None),
        },
        "GET" => match s.objects.lock().unwrap().get(&key).cloned() {
            Some((b, e)) => (200, b, Some(e)),
            None => (404, b"<Error><Code>NoSuchKey</Code></Error>".to_vec(), None),
        },
        "PUT" => {
            if !is_inode {
                s.started.fetch_add(1, Ordering::SeqCst);
                let mut gate = s.block.lock().unwrap();
                while *gate && !s.stop.load(Ordering::SeqCst) {
                    gate = s.gate.wait(gate).unwrap();
                }
            }
            let forced = {
                let mut rule = s.deny_put_once.lock().unwrap();
                if let Some((wanted, left)) = rule.as_mut() {
                    if wanted == &key {
                        *left -= 1;
                        if *left == 0 {
                            *rule = None;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if forced
                || (!is_inode && s.deny_chunks.load(Ordering::SeqCst))
                || (is_inode && s.deny_inode.load(Ordering::SeqCst))
            {
                (
                    403,
                    b"<Error><Code>AccessDenied</Code></Error>".to_vec(),
                    None,
                )
            } else {
                let mut objects = s.objects.lock().unwrap();
                let stale = headers
                    .get("if-match")
                    .is_some_and(|e| objects.get(&key).is_none_or(|(_, old)| e != old));
                let exists = headers.contains_key("if-none-match") && objects.contains_key(&key);
                if stale || exists {
                    (
                        412,
                        b"<Error><Code>PreconditionFailed</Code></Error>".to_vec(),
                        None,
                    )
                } else {
                    let etag = format!("\"v{}\"", s.serial.fetch_add(1, Ordering::SeqCst));
                    objects.insert(key, (body, etag.clone()));
                    if !is_inode {
                        s.completed.fetch_add(1, Ordering::SeqCst);
                    }
                    (200, Vec::new(), Some(etag))
                }
            }
        }
        _ => (400, Vec::new(), None),
    };
    write!(
        stream,
        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\n",
        bytes.len()
    )?;
    if let Some(e) = etag {
        write!(stream, "ETag: {e}\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(&bytes)
}
async fn wait_for(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uploads_precede_fsync_and_partial_append_preserves_committed_chunks() {
    let server = Server::new();
    let (volume, mut file) = server.file().await;
    let id = file.base.body.id;
    let bytes = vec![7; 128 * 1024 + 37];
    assert_eq!(file.write(0, &bytes).await.unwrap(), bytes.len());
    wait_for(|| server.state.completed.load(Ordering::SeqCst) >= 1).await;
    assert_eq!(volume.load(id).await.unwrap().body.size().unwrap(), 0);
    file.commit().await.unwrap();
    let before = pieces(&file.base.body);
    assert_eq!(
        before.iter().map(|p| p.len).collect::<Vec<_>>(),
        vec![128 * 1024, 37]
    );
    file.write(bytes.len() as u64, b"appended").await.unwrap();
    file.commit().await.unwrap();
    let after = pieces(&file.base.body);
    assert_eq!(&after[..2], before);
    assert_eq!(after[2].len, 8);
    let mut reader = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    assert_eq!(
        reader.read(0, bytes.len() + 8).await.unwrap(),
        [bytes, b"appended".to_vec()].concat()
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fsync_waits_for_its_uploads_and_later_writes_form_another_generation() {
    let server = Server::new();
    let (volume, mut file) = server.file().await;
    let id = file.base.body.id;
    *server.state.block.lock().unwrap() = true;
    file.write(0, &vec![1; 128 * 1024]).await.unwrap();
    wait_for(|| server.state.started.load(Ordering::SeqCst) > 0).await;
    let commit = tokio::spawn(async move {
        let result = file.commit().await;
        (file, result)
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!commit.is_finished());
    assert_eq!(volume.load(id).await.unwrap().body.size().unwrap(), 0);
    server.release();
    let (mut file, result) = commit.await.unwrap();
    result.unwrap();
    assert_eq!(file.base.body.generation, 1);
    file.write(file.size, b"next").await.unwrap();
    assert_eq!(
        volume.load(id).await.unwrap().body.size().unwrap(),
        128 * 1024
    );
    file.commit().await.unwrap();
    assert_eq!(file.base.body.generation, 2);
    assert_eq!(pieces(&file.base.body)[1].len, 4);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_snapshots_cannot_be_mutated_or_resurrected_after_truncate() {
    let server = Server::new();
    let (volume, mut file) = server.file().await;
    let id = file.base.body.id;
    *server.state.block.lock().unwrap() = true;
    file.write(0, &vec![1; 128 * 1024]).await.unwrap();
    file.write(0, &[9]).await.unwrap();
    server.release();
    file.commit().await.unwrap();
    let mut reader = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    let bytes = reader.read(0, 128 * 1024).await.unwrap();
    assert_eq!(bytes[0], 9);
    assert!(bytes[1..].iter().all(|&b| b == 1));
    *server.state.block.lock().unwrap() = true;
    file.write(file.size, &vec![3; 128 * 1024]).await.unwrap();
    file.resize(10).unwrap();
    file.resize(300_000).unwrap();
    server.release();
    file.commit().await.unwrap();
    let mut reader = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    let bytes = reader.read(0, 300_000).await.unwrap();
    assert_eq!(bytes[0], 9);
    assert!(bytes[1..10].iter().all(|&b| b == 1));
    assert!(bytes[10..].iter().all(|&b| b == 0));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn background_failure_is_reported_at_fsync_and_retry_keeps_local_data() {
    let server = Server::new();
    let (volume, mut file) = server.file().await;
    let id = file.base.body.id;
    server.state.deny_chunks.store(true, Ordering::SeqCst);
    let bytes = vec![5; 128 * 1024];
    assert_eq!(file.write(0, &bytes).await.unwrap(), bytes.len());
    wait_for(|| server.state.started.load(Ordering::SeqCst) > 0).await;
    assert!(file.commit().await.is_err());
    assert_eq!(volume.load(id).await.unwrap().body.size().unwrap(), 0);
    server.state.deny_chunks.store(false, Ordering::SeqCst);
    file.commit().await.unwrap();
    let mut reader = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    assert_eq!(reader.read(0, bytes.len()).await.unwrap(), bytes);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_inode_commit_never_reports_success_and_retry_reuses_uploaded_chunks() {
    let server = Server::new();
    let (volume, mut file) = server.file().await;
    let id = file.base.body.id;
    file.write(0, &vec![6; 128 * 1024]).await.unwrap();
    wait_for(|| server.state.completed.load(Ordering::SeqCst) > 0).await;
    server.state.deny_inode.store(true, Ordering::SeqCst);
    assert!(file.commit().await.is_err());
    assert_eq!(volume.load(id).await.unwrap().body.size().unwrap(), 0);
    let uploads = server.state.started.load(Ordering::SeqCst);
    server.state.deny_inode.store(false, Ordering::SeqCst);
    file.commit().await.unwrap();
    assert_eq!(server.state.started.load(Ordering::SeqCst), uploads);
    assert_eq!(
        volume.load(id).await.unwrap().body.size().unwrap(),
        128 * 1024
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_upload_window_backpressures_writes_without_publishing_the_inode() {
    let server = Server::new();
    let (volume, mut file) = server.file().await;
    let id = file.base.body.id;
    *server.state.block.lock().unwrap() = true;
    file.write(0, &vec![1; 256 * 1024]).await.unwrap();
    wait_for(|| server.state.started.load(Ordering::SeqCst) == 2).await;
    let writer = tokio::spawn(async move {
        let result = file.write(file.size, &vec![2; 128 * 1024]).await;
        (file, result)
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!writer.is_finished());
    assert_eq!(server.state.started.load(Ordering::SeqCst), 2);
    assert_eq!(volume.load(id).await.unwrap().body.size().unwrap(), 0);
    server.release();
    let (mut file, result) = writer.await.unwrap();
    assert_eq!(result.unwrap(), 128 * 1024);
    file.commit().await.unwrap();
    assert_eq!(
        volume.load(id).await.unwrap().body.size().unwrap(),
        384 * 1024
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disjoint_writes_merge_inside_one_chunk_and_overlaps_conflict() {
    let server = Server::new();
    let (volume, mut original) = server.file().await;
    let id = original.base.body.id;
    original.write(0, &vec![0; 256 * 1024]).await.unwrap();
    original.commit().await.unwrap();
    let mut a = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    let mut b = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    a.write(100, b"aaaa").await.unwrap();
    b.write(200, b"bbbb").await.unwrap();
    a.commit().await.unwrap();
    b.commit().await.unwrap();
    let mut reader = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    assert_eq!(reader.read(100, 4).await.unwrap(), b"aaaa");
    assert_eq!(reader.read(200, 4).await.unwrap(), b"bbbb");
    let mut a = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    let mut b = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    a.write(100, b"1111").await.unwrap();
    b.write(102, b"2222").await.unwrap();
    a.commit().await.unwrap();
    assert!(matches!(b.commit().await, Err(Error::Conflict)));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inline_disjoint_merge_and_append_first_cas_wins() {
    let server = Server::new();
    let (volume, mut original) = server.file().await;
    let id = original.base.body.id;
    original.write(0, &[0; 100]).await.unwrap();
    original.commit().await.unwrap();
    let mut a = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    let mut b = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    a.write(0, b"one").await.unwrap();
    b.write(10, b"two").await.unwrap();
    b.commit().await.unwrap();
    a.commit().await.unwrap();
    let mut a = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    let mut b = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    a.write(100, b"loser").await.unwrap();
    b.write(100, b"winner").await.unwrap();
    b.commit().await.unwrap();
    assert!(matches!(a.commit().await, Err(Error::Conflict)));
    let mut reader = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    assert_eq!(reader.read(100, 10).await.unwrap(), b"winner");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_permissions_persist_and_merge_preserves_other_fields() {
    use crate::volume::MetadataUpdate;
    let server = Server::new();
    let (volume, mut file) = server.file().await;
    let id = file.base.body.id;
    file.update_metadata(
        &MetadataUpdate {
            uid: Some(1000),
            gid: Some(2000),
            mode: Some(0o640),
            ..Default::default()
        },
        (0, 0),
    )
    .unwrap();
    file.commit().await.unwrap();
    assert!(
        file.update_metadata(
            &MetadataUpdate {
                mode: Some(0o777),
                ..Default::default()
            },
            (1001, 2000)
        )
        .is_err()
    );
    assert!(
        file.update_metadata(
            &MetadataUpdate {
                uid: Some(1001),
                ..Default::default()
            },
            (1000, 2000)
        )
        .is_err()
    );
    file.update_metadata(
        &MetadataUpdate {
            mode: Some(0o600),
            ..Default::default()
        },
        (1000, 2000),
    )
    .unwrap();
    file.commit().await.unwrap();
    let loaded = volume.load(id).await.unwrap();
    assert_eq!(
        (
            loaded.body.metadata.uid,
            loaded.body.metadata.gid,
            loaded.body.metadata.mode
        ),
        (1000, 2000, 0o600)
    );
    file.write(0, &[0; 100]).await.unwrap();
    file.commit().await.unwrap();
    let mut writer = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    writer.write(0, b"data").await.unwrap();
    volume
        .update_metadata(
            id,
            &MetadataUpdate {
                mode: Some(0o640),
                ..Default::default()
            },
            (1000, 2000),
        )
        .await
        .unwrap();
    writer.commit().await.unwrap();
    let final_inode = volume.load(id).await.unwrap();
    assert_eq!(final_inode.body.metadata.mode, 0o640);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_advances_latest_cache_without_changing_open_snapshot() {
    use crate::volume::snapshots::Snapshots;
    let server = Server::new();
    let (volume, mut writer) = server.file().await;
    let id = writer.base.body.id;
    writer.write(0, b"old").await.unwrap();
    writer.commit().await.unwrap();
    let loaded = volume.load(id).await.unwrap();
    let registry = Snapshots::new(volume.clone());
    registry.pin(&loaded);
    let old = registry.latest(id).unwrap();
    let mut reader = volume.file(loaded, &server.cache).unwrap();
    writer.write(0, b"new").await.unwrap();
    writer.commit().await.unwrap();
    let reopened_before_poll = registry.open(id).await.unwrap();
    assert!(reopened_before_poll.body.generation > old.body.generation);
    registry.poll_once().await;
    assert!(registry.latest(id).unwrap().body.generation > old.body.generation);
    assert_eq!(reader.read(0, 3).await.unwrap(), b"old");
    let mut reopened = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    assert_eq!(reopened.read(0, 3).await.unwrap(), b"new");
    registry.unpin(id);
    assert!(registry.latest(id).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn append_and_disjoint_existing_write_merge_but_two_appends_do_not() {
    let server = Server::new();
    let (volume, mut initial) = server.file().await;
    let id = initial.base.body.id;
    initial.write(0, &[0; 100]).await.unwrap();
    initial.commit().await.unwrap();
    let mut overwrite = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    let mut append = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    overwrite.write(0, b"new").await.unwrap();
    append.write(100, b"tail").await.unwrap();
    overwrite.commit().await.unwrap();
    append.commit().await.unwrap();
    let mut reader = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    assert_eq!(reader.read(0, 3).await.unwrap(), b"new");
    assert_eq!(reader.read(100, 4).await.unwrap(), b"tail");
}

#[tokio::test]
async fn directory_lease_blocks_mutations_and_can_be_renewed_and_released() {
    let server = Server::new();
    let (v, _) = server.file().await;
    let dir = v
        .create_inode([9; 16], inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    let id = dir.body.id;
    let mut lease = v.acquire_directory_lease(id).await.unwrap();
    assert!(matches!(
        v.acquire_directory_lease(id).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        v.create(id, "blocked", inode::FILE).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        v.update_metadata(
            id,
            &MetadataUpdate {
                mode: Some(0o700),
                ..Default::default()
            },
            (0, 0)
        )
        .await,
        Err(Error::Conflict)
    ));
    let original = lease.inode().etag.clone();
    v.renew_directory_lease(&mut lease, Duration::from_secs(30))
        .await
        .unwrap();
    assert_ne!(lease.inode().etag, original);
    v.write_leased_directory(&mut lease, &crate::format::directory::Directory::default())
        .await
        .unwrap();
    v.release_directory_lease(lease).await.unwrap();
    v.create(id, "allowed", inode::FILE).await.unwrap();
    assert!(v.load(id).await.unwrap().body.lease.is_none());
}

#[tokio::test]
async fn expired_lease_takeover_fences_stale_holder_without_recovering_its_changes() {
    let server = Server::new();
    let (v, _) = server.file().await;
    let dir = v
        .create_inode([9; 16], inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    let mut old = v.acquire_directory_lease(dir.body.id).await.unwrap();
    // Persist an already expired lease, without waiting for wall-clock expiry.
    // The local old handle still believes its original lease is valid. This
    // exercises fencing independently of the owner's local expiration check.
    let mut expired = old.inode().body.clone();
    expired.lease.as_mut().unwrap().expires_at = Timestamp::default();
    v.publish_raw(old.inode(), &expired, Some(&old.inode().etag))
        .await
        .unwrap();
    let mut next = v.acquire_directory_lease(dir.body.id).await.unwrap();
    assert_ne!(
        old.inode().body.lease.as_ref().unwrap().owner,
        next.inode().body.lease.as_ref().unwrap().owner
    );
    let directory = crate::format::directory::Directory::default();
    assert!(matches!(
        v.write_leased_directory(&mut old, &directory).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        v.renew_directory_lease(&mut old, Duration::from_secs(30))
            .await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        v.release_directory_lease(old).await,
        Err(Error::Conflict)
    ));
    v.write_leased_directory(&mut next, &directory)
        .await
        .unwrap();
    v.release_directory_lease(next).await.unwrap();
}

#[tokio::test]
async fn ordinary_edit_retires_expired_lease_and_acquisition_race_has_one_winner() {
    let server = Server::new();
    let (v, _) = server.file().await;
    let dir = v
        .create_inode([9; 16], inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        v.acquire_directory_lease(dir.body.id),
        v.acquire_directory_lease(dir.body.id)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let lease = a.or(b).unwrap();
    let mut expired = lease.inode().body.clone();
    expired.lease.as_mut().unwrap().expires_at = Timestamp::default();
    v.publish_raw(lease.inode(), &expired, Some(&lease.inode().etag))
        .await
        .unwrap();
    v.create(dir.body.id, "after-expiry", inode::FILE)
        .await
        .unwrap();
    assert!(v.load(dir.body.id).await.unwrap().body.lease.is_none());
    assert!(matches!(
        v.release_directory_lease(lease).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        v.acquire_directory_lease([4; 16]).await,
        Err(Error::NotDirectory)
    ));
    assert!(matches!(
        v.acquire_directory_lease_for(dir.body.id, Duration::from_secs(1))
            .await,
        Err(Error::Invalid)
    ));
}

#[tokio::test]
async fn sparse_extents_do_not_upload_zero_objects_and_survive_split_shrink_extend() {
    let server = Server::new();
    let (v, mut f) = server.file().await;
    let id = f.base.body.id;
    let before = server.state.started.load(Ordering::SeqCst);
    f.resize(1 << 34).unwrap();
    f.commit().await.unwrap();
    assert_eq!(server.state.started.load(Ordering::SeqCst), before);
    let InodeContent::Chunks(c) = &f.base.body.content else {
        panic!()
    };
    assert!(c.runs.is_empty());
    assert_eq!(c.holes.len(), 1);
    let mut f = v.file(v.load(id).await.unwrap(), &server.cache).unwrap();
    assert_eq!(f.read((1 << 34) - 16, 16).await.unwrap(), vec![0; 16]);
    f.write(1 << 33, b"middle").await.unwrap();
    f.commit().await.unwrap();
    assert_eq!(server.state.started.load(Ordering::SeqCst), before + 1);
    assert_eq!(
        f.read((1 << 33) - 3, 12).await.unwrap(),
        b"\0\0\0middle\0\0\0"
    );
    f.resize(1 << 32).unwrap();
    f.commit().await.unwrap();
    f.resize(1 << 34).unwrap();
    f.commit().await.unwrap();
    assert_eq!(f.read(1 << 33, 6).await.unwrap(), vec![0; 6]);
    assert_eq!(server.state.started.load(Ordering::SeqCst), before + 1);
}

#[tokio::test]
async fn shrink_merges_prefix_edits_but_conflicts_with_removed_bytes_and_append() {
    let server = Server::new();
    let (v, mut seed) = server.file().await;
    seed.write(0, &vec![3; 300_000]).await.unwrap();
    seed.commit().await.unwrap();
    let base = seed.base.clone();
    let mut truncate = v.file(base.clone(), &server.cache).unwrap();
    let mut prefix = v.file(base.clone(), &server.cache).unwrap();
    truncate.resize(200_000).unwrap();
    prefix.write(10, b"prefix").await.unwrap();
    prefix.commit().await.unwrap();
    truncate.commit().await.unwrap();
    assert_eq!(truncate.size, 200_000);
    assert_eq!(truncate.read(10, 6).await.unwrap(), b"prefix");
    let mut old = v.file(base.clone(), &server.cache).unwrap();
    old.write(250_000, b"gone").await.unwrap();
    assert!(matches!(old.commit().await, Err(Error::Conflict)));
    let base = truncate.base.clone();
    let mut a = v.file(base.clone(), &server.cache).unwrap();
    let mut b = v.file(base, &server.cache).unwrap();
    a.resize(100_000).unwrap();
    b.write(200_000, b"append").await.unwrap();
    a.commit().await.unwrap();
    assert!(matches!(b.commit().await, Err(Error::Conflict)));
    let mut a = v.file(a.base.clone(), &server.cache).unwrap();
    let mut b = v.file(a.base.clone(), &server.cache).unwrap();
    a.resize(90_000).unwrap();
    b.resize(80_000).unwrap();
    b.commit().await.unwrap();
    assert!(matches!(a.commit().await, Err(Error::Conflict)));
}

#[tokio::test]
async fn equal_byte_and_aba_writes_still_conflict_and_metadata_equal_values_succeed() {
    let server = Server::new();
    let (v, mut seed) = server.file().await;
    seed.write(0, b"abcdef").await.unwrap();
    seed.commit().await.unwrap();
    let mut a = v.file(seed.base.clone(), &server.cache).unwrap();
    let mut b = v.file(seed.base.clone(), &server.cache).unwrap();
    a.write(0, b"a").await.unwrap();
    b.write(0, b"a").await.unwrap();
    a.commit().await.unwrap();
    assert!(matches!(b.commit().await, Err(Error::Conflict)));
    let mut stale = v.file(a.base.clone(), &server.cache).unwrap();
    stale.write(1, b"Z").await.unwrap();
    a.write(1, b"X").await.unwrap();
    a.commit().await.unwrap();
    a.write(1, b"b").await.unwrap();
    a.commit().await.unwrap();
    assert!(matches!(stale.commit().await, Err(Error::Conflict)));
    let mut a = v.file(a.base.clone(), &server.cache).unwrap();
    let mut b = v.file(a.base.clone(), &server.cache).unwrap();
    let update = MetadataUpdate {
        mode: Some(0o600),
        ..Default::default()
    };
    a.update_metadata(&update, (0, 0)).unwrap();
    b.update_metadata(&update, (0, 0)).unwrap();
    a.commit().await.unwrap();
    b.commit().await.unwrap();
}

#[tokio::test]
async fn namespace_links_rename_replacement_symlink_and_deleted_directory() {
    let server = Server::new();
    let (v, _) = server.file().await;
    v.create_inode(v.root, inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    let a = v
        .create(v.root, "a", inode::DIRECTORY)
        .await
        .unwrap()
        .body
        .id;
    let b = v
        .create(v.root, "b", inode::DIRECTORY)
        .await
        .unwrap()
        .body
        .id;
    let file = v.create(a, "file", inode::FILE).await.unwrap();
    let mut open = v.file(file.clone(), &server.cache).unwrap();
    open.write(0, b"old snapshot").await.unwrap();
    open.commit().await.unwrap();
    v.link(file.body.id, b, "alias").await.unwrap();
    assert_eq!(v.load(file.body.id).await.unwrap().body.nlink, 2);
    v.unlink(a, "file").await.unwrap();
    assert_eq!(v.load(file.body.id).await.unwrap().body.nlink, 1);
    assert_eq!(open.read(0, 12).await.unwrap(), b"old snapshot");
    v.unlink(b, "alias").await.unwrap();
    open.write(0, b"new").await.unwrap();
    open.commit().await.unwrap();
    assert_eq!(open.base.body.nlink, 0);
    assert!(v.list(b).await.unwrap().is_empty());
    let source = v.create(a, "source", inode::FILE).await.unwrap();
    let target = v.create(b, "target", inode::FILE).await.unwrap();
    assert!(matches!(
        v.rename(a, "source", b, "target", true).await,
        Err(Error::Exists)
    ));
    v.rename(a, "source", b, "target", false).await.unwrap();
    assert!(v.list(a).await.unwrap().is_empty());
    assert_eq!(v.list(b).await.unwrap()[0].id, source.body.id);
    assert_eq!(v.load(target.body.id).await.unwrap().body.nlink, 0);
    v.rename(b, "target", b, "renamed", false).await.unwrap();
    let sym = v
        .symlink(a, "sym", b"../b/renamed", Default::default())
        .await
        .unwrap();
    assert_eq!(v.readlink(sym.body.id).await.unwrap(), b"../b/renamed");
    assert!(matches!(v.rmdir(v.root, "a").await, Err(Error::NotEmpty)));
    v.unlink(a, "sym").await.unwrap();
    v.rmdir(v.root, "a").await.unwrap();
    assert!(v.load(a).await.unwrap().body.deleted);
    assert!(matches!(
        v.create(a, "resurrect", inode::FILE).await,
        Err(Error::Missing)
    ));
    let c = v.create(b, "c", inode::DIRECTORY).await.unwrap().body.id;
    assert!(matches!(
        v.rename(v.root, "b", c, "cycle", false).await,
        Err(Error::Invalid)
    ));
    let d = v
        .create(v.root, "d", inode::DIRECTORY)
        .await
        .unwrap()
        .body
        .id;
    v.rename(b, "c", v.root, "d", false).await.unwrap();
    assert!(v.load(d).await.unwrap().body.deleted);
}

#[tokio::test]
async fn interrupted_rename_leaves_both_names_and_rmdir_never_resurrects() {
    let server = Server::new();
    let (v, _) = server.file().await;
    v.create_inode(v.root, inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    let a = v
        .create(v.root, "a", inode::DIRECTORY)
        .await
        .unwrap()
        .body
        .id;
    let b = v
        .create(v.root, "b", inode::DIRECTORY)
        .await
        .unwrap()
        .body
        .id;
    let source = v.create(a, "source", inode::FILE).await.unwrap();
    *server.state.deny_put_once.lock().unwrap() = Some((v.inode_name(&a).unwrap(), 2));
    assert!(v.rename(a, "source", b, "target", false).await.is_err());
    assert_eq!(v.list(a).await.unwrap()[0].id, source.body.id);
    assert_eq!(v.list(b).await.unwrap()[0].id, source.body.id);
    v.unlink(a, "source").await.unwrap();
    v.unlink(b, "target").await.unwrap();
    let empty = v
        .create(v.root, "empty", inode::DIRECTORY)
        .await
        .unwrap()
        .body
        .id;
    *server.state.deny_put_once.lock().unwrap() = Some((v.inode_name(&v.root).unwrap(), 2));
    assert!(v.rmdir(v.root, "empty").await.is_err());
    assert!(v.load(empty).await.unwrap().body.deleted);
    assert!(matches!(
        v.create(empty, "hidden", inode::FILE).await,
        Err(Error::Missing)
    ));
}

#[tokio::test]
async fn competing_directory_moves_cannot_make_a_cycle_and_disjoint_entries_survive() {
    let server = Server::new();
    let (v, _) = server.file().await;
    v.create_inode(v.root, inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    let a = v
        .create(v.root, "a", inode::DIRECTORY)
        .await
        .unwrap()
        .body
        .id;
    let b = v
        .create(v.root, "b", inode::DIRECTORY)
        .await
        .unwrap()
        .body
        .id;
    let (left, right) = tokio::join!(
        v.rename(v.root, "a", b, "a", false),
        v.rename(v.root, "b", a, "b", false)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let (a, b, c) = tokio::join!(
        v.create(v.root, "one", inode::FILE),
        v.create(v.root, "two", inode::FILE),
        v.create(v.root, "three", inode::FILE)
    );
    assert!(a.is_ok() && b.is_ok() && c.is_ok());
    let (a, b) = tokio::join!(
        v.create(v.root, "same", inode::FILE),
        v.create(v.root, "same", inode::FILE)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
}

#[tokio::test]
async fn old_handle_merges_after_many_commits_and_metadata_aba_is_detected() {
    let server = Server::new();
    let (v, mut current) = server.file().await;
    current.write(0, &[0; 128]).await.unwrap();
    current.commit().await.unwrap();
    let mut stale = v.file(current.base.clone(), &server.cache).unwrap();
    stale.write(0, b"X").await.unwrap();
    for i in 1..=70 {
        current.write(i, &[i as u8]).await.unwrap();
        current.commit().await.unwrap();
    }
    stale.commit().await.unwrap();
    assert_eq!(stale.read(0, 2).await.unwrap(), b"X\x01");
    let mut stale = v.file(stale.base.clone(), &server.cache).unwrap();
    stale
        .update_metadata(
            &MetadataUpdate {
                mode: Some(0o600),
                ..Default::default()
            },
            (0, 0),
        )
        .unwrap();
    v.update_metadata(
        stale.base.body.id,
        &MetadataUpdate {
            mode: Some(0o700),
            ..Default::default()
        },
        (0, 0),
    )
    .await
    .unwrap();
    v.update_metadata(
        stale.base.body.id,
        &MetadataUpdate {
            mode: Some(0o644),
            ..Default::default()
        },
        (0, 0),
    )
    .await
    .unwrap();
    assert!(matches!(stale.commit().await, Err(Error::Conflict)));
    let base = v.load(stale.base.body.id).await.unwrap();
    let mut equal = v.file(base, &server.cache).unwrap();
    equal
        .update_metadata(
            &MetadataUpdate {
                mode: Some(0o644),
                ..Default::default()
            },
            (0, 0),
        )
        .unwrap();
    v.update_metadata(
        equal.base.body.id,
        &MetadataUpdate {
            mode: Some(0o600),
            ..Default::default()
        },
        (0, 0),
    )
    .await
    .unwrap();
    v.update_metadata(
        equal.base.body.id,
        &MetadataUpdate {
            mode: Some(0o644),
            ..Default::default()
        },
        (0, 0),
    )
    .await
    .unwrap();
    equal.commit().await.unwrap();
}

#[tokio::test]
async fn create_racing_rmdir_never_publishes_an_unreachable_child() {
    let server = Server::new();
    let (v, _) = server.file().await;
    v.create_inode(v.root, inode::DIRECTORY, Default::default())
        .await
        .unwrap();
    for i in 0..12 {
        let name = format!("dir-{i}");
        let d = v
            .create(v.root, &name, inode::DIRECTORY)
            .await
            .unwrap()
            .body
            .id;
        let (removed, created) =
            tokio::join!(v.rmdir(v.root, &name), v.create(d, "child", inode::FILE));
        assert_ne!(removed.is_ok(), created.is_ok());
        if created.is_ok() {
            assert!(!v.load(d).await.unwrap().body.deleted);
            v.unlink(d, "child").await.unwrap();
            v.rmdir(v.root, &name).await.unwrap();
        } else {
            assert!(v.load(d).await.unwrap().body.deleted);
        }
    }
    let f = v.create(v.root, "same-path", inode::FILE).await.unwrap();
    assert!(matches!(
        v.rename(v.root, "same-path", v.root, "same-path", true)
            .await,
        Err(Error::Exists)
    ));
    assert_eq!(v.load(f.body.id).await.unwrap().body.nlink, 1);
}
