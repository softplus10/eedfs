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
            if (!is_inode && s.deny_chunks.load(Ordering::SeqCst))
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
