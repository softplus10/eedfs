use super::*;
use crate::volume::{
    resources::Limits,
    snapshots::Snapshots,
    writeback::{Session, Writeback},
};

#[tokio::test]
async fn completed_session_bookkeeping_is_released_after_last_external_reference() {
    let server = Server::new();
    let (volume, session) = server.file().await;
    let session = Arc::new(Mutex::new(session));
    let id = session.lock().unwrap().base.body.id;
    let (queue, worker) = start(&volume, 1);
    queue.track(id, &session).unwrap();
    queue.sync(id).await.unwrap();
    drop(session);
    let before = volume.resources.usage().0;
    queue.forget_closed(id);
    assert_eq!(volume.resources.usage().0, before - 1024);
    queue.shutdown().await.unwrap();
    worker.await.unwrap();
}

async fn write(session: &Session, bytes: &[u8]) -> Result<usize> {
    let session = session.clone();
    let bytes = bytes.to_vec();
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || runtime.block_on(session.lock().unwrap().write(0, &bytes)))
        .await?
}

fn start(
    volume: &Arc<Volume>,
    parallelism: usize,
) -> (Arc<Writeback>, tokio::task::JoinHandle<()>) {
    let queue = Writeback::new(
        volume.resources.clone(),
        Arc::new(Snapshots::new(volume.clone())),
    );
    let worker = tokio::spawn(
        queue
            .clone()
            .run(tokio::runtime::Handle::current(), parallelism),
    );
    (queue, worker)
}
async fn second(volume: &Arc<Volume>, server: &Server) -> Session {
    let loaded = volume
        .create_inode([17; 16], FILE, Default::default())
        .await
        .unwrap();
    Arc::new(Mutex::new(volume.file(loaded, &server.cache).unwrap()))
}
async fn inode_blocked(server: &Server, before: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.state.inode_started.load(Ordering::SeqCst) == before {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn close_is_nonblocking_retains_state_and_other_inode_can_fsync() {
    let server = Server::new();
    let (volume, a) = server.file().await;
    let a = Arc::new(Mutex::new(a));
    let b = second(&volume, &server).await;
    let (queue, worker) = start(&volume, 2);
    let aid = a.lock().unwrap().base.body.id;
    let bid = b.lock().unwrap().base.body.id;
    queue.track(aid, &a).unwrap();
    queue.track(bid, &b).unwrap();
    write(&a, b"first").await.unwrap();
    write(&b, b"second").await.unwrap();
    *server.state.block_inode.lock().unwrap() = true;
    let before = server.state.inode_started.load(Ordering::SeqCst);
    queue.submit(aid, &a).unwrap();
    let weak = Arc::downgrade(&a);
    drop(a); // the final application handle has gone
    inode_blocked(&server, before).await;
    let retained = weak.upgrade().expect("closed writeback lost its spool");
    assert!(Arc::ptr_eq(
        &queue.track(aid, &retained).unwrap(),
        &retained
    ));
    // Scheduling another close for the same blocked inode must not lock it.
    queue.submit(aid, &retained).unwrap();
    tokio::time::timeout(Duration::from_secs(5), queue.sync(bid))
        .await
        .unwrap()
        .unwrap();
    let mut remote = volume
        .file(volume.load(bid).await.unwrap(), &server.cache)
        .unwrap();
    assert_eq!(remote.read(0, 6).await.unwrap(), b"second");
    let barrier = queue.sync(aid);
    tokio::pin!(barrier);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut barrier)
            .await
            .is_err()
    );
    server.release();
    tokio::time::timeout(Duration::from_secs(5), barrier)
        .await
        .unwrap()
        .unwrap();
    drop(retained);
    queue.shutdown().await.unwrap();
    worker.await.unwrap();
    assert!(weak.upgrade().is_none());
    assert!(queue.shutdown_result().is_ok());
}

#[tokio::test]
async fn failed_closed_inode_survives_and_requires_observation_before_explicit_retry() {
    let server = Server::new();
    let (volume, a) = server.file().await;
    let a = Arc::new(Mutex::new(a));
    let id = a.lock().unwrap().base.body.id;
    let (queue, worker) = start(&volume, 2);
    queue.track(id, &a).unwrap();
    write(&a, b"retained").await.unwrap();
    server.state.deny_inode.store(true, Ordering::SeqCst);
    queue.submit(id, &a).unwrap();
    let weak = Arc::downgrade(&a);
    drop(a);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let session = weak.upgrade().expect("failed writeback was discarded");
            if queue.submit(id, &session).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    let attempts = server.state.inode_started.load(Ordering::SeqCst);
    server.state.deny_inode.store(false, Ordering::SeqCst);
    // A now-healthy backend must not hide the previous unobserved error.
    assert!(queue.sync(id).await.is_err());
    assert_eq!(server.state.inode_started.load(Ordering::SeqCst), attempts);
    assert!(queue.submit(id, &weak.upgrade().unwrap()).is_err());
    queue.sync(id).await.unwrap();
    assert!(weak.upgrade().is_none());
    let mut remote = volume
        .file(volume.load(id).await.unwrap(), &server.cache)
        .unwrap();
    assert_eq!(remote.read(0, 8).await.unwrap(), b"retained");
    queue.shutdown().await.unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn unmount_drains_successes_and_reports_failed_closed_files_without_retry() {
    let server = Server::new();
    let (volume, a) = server.file().await;
    let a = Arc::new(Mutex::new(a));
    let id = a.lock().unwrap().base.body.id;
    let (queue, worker) = start(&volume, 1);
    queue.track(id, &a).unwrap();
    write(&a, b"not durable").await.unwrap();
    server.state.deny_inode.store(true, Ordering::SeqCst);
    queue.submit(id, &a).unwrap();
    let weak = Arc::downgrade(&a);
    drop(a);
    assert!(queue.shutdown().await.is_err());
    worker.await.unwrap();
    assert!(queue.shutdown_result().is_err());
    assert!(weak.upgrade().is_some());
    assert_eq!(server.state.inode_started.load(Ordering::SeqCst), 2); // create + one attempt
    assert!(queue.sync(id).await.is_err()); // a stopped mount cannot accept retries
}

#[tokio::test]
async fn queue_bound_and_spool_backpressure_release_closed_resources() {
    let server = Server::new();
    let (volume, a) = server.file().await;
    let a = Arc::new(Mutex::new(a));
    let b = second(&volume, &server).await;
    let aid = a.lock().unwrap().base.body.id;
    let bid = b.lock().unwrap().base.body.id;
    volume
        .resources
        .configure(Limits {
            memory_bytes: 16 * 1024 * 1024,
            spool_bytes: 4096,
        })
        .unwrap();
    let (queue, worker) = start(&volume, 1);
    queue.set_limit(2).unwrap();
    queue.track(aid, &a).unwrap();
    queue.track(bid, &b).unwrap();
    assert!(matches!(queue.track([99; 16], &b), Err(Error::NoMemory)));
    write(&a, &[3; 4096]).await.unwrap();
    *server.state.block_inode.lock().unwrap() = true;
    let before = server.state.inode_started.load(Ordering::SeqCst);
    queue.submit(aid, &a).unwrap();
    drop(a);
    inode_blocked(&server, before).await;
    assert!(matches!(write(&b, b"b").await, Err(Error::NoSpace)));
    let progress = queue.wait_for_progress();
    tokio::pin!(progress);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut progress)
            .await
            .is_err()
    );
    server.release();
    assert!(progress.await);
    write(&b, b"b").await.unwrap();
    queue.submit(bid, &b).unwrap();
    drop(b);
    queue.shutdown().await.unwrap();
    worker.await.unwrap();
    assert!(!queue.wait_for_progress().await);
}
