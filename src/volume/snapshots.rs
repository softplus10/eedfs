//! Open snapshot pins and a polled latest-inode cache. Never mutates pinned data.
use super::{Loaded, Volume};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
struct Entry {
    latest: Arc<Loaded>,
    handles: usize,
}
pub struct Snapshots {
    volume: Arc<Volume>,
    entries: Mutex<HashMap<[u8; 16], Entry>>,
}
impl Snapshots {
    pub fn new(volume: Arc<Volume>) -> Self {
        Self {
            volume,
            entries: Mutex::new(HashMap::new()),
        }
    }
    /// New opens validate the server version even between periodic polls.
    pub async fn open(&self, id: [u8; 16]) -> super::Result<Loaded> {
        if let Some(cached) = self.latest(id)
            && self.volume.inode_etag(id).await? == cached.etag
        {
            return Ok((*cached).clone());
        }
        self.volume.load(id).await
    }
    pub fn pin(&self, loaded: &Loaded) {
        let mut entries = self.entries.lock().unwrap();
        let e = entries.entry(loaded.body.id).or_insert_with(|| Entry {
            latest: Arc::new(loaded.clone()),
            handles: 0,
        });
        if loaded.body.generation >= e.latest.body.generation {
            e.latest = Arc::new(loaded.clone());
        }
        e.handles += 1;
    }
    pub fn unpin(&self, id: [u8; 16]) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(e) = entries.get_mut(&id) {
            e.handles -= 1;
            if e.handles == 0 {
                entries.remove(&id);
            }
        }
    }
    pub fn latest(&self, id: [u8; 16]) -> Option<Arc<Loaded>> {
        self.entries
            .lock()
            .unwrap()
            .get(&id)
            .map(|e| e.latest.clone())
    }
    pub fn published(&self, loaded: &Loaded) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(e) = entries.get_mut(&loaded.body.id)
            && loaded.body.generation >= e.latest.body.generation
        {
            e.latest = Arc::new(loaded.clone());
        }
    }
    pub async fn poll_once(&self) {
        let entries: Vec<_> = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|(id, e)| (*id, e.latest.etag.clone()))
            .collect();
        let mut jobs = tokio::task::JoinSet::new();
        for (id, etag) in entries {
            let volume = self.volume.clone();
            jobs.spawn(async move {
                if volume.inode_etag(id).await? != etag {
                    Ok::<_, super::Error>(Some(volume.load(id).await?))
                } else {
                    Ok(None)
                }
            });
            if jobs.len() >= self.volume.parallelism {
                self.receive(&mut jobs).await;
            }
        }
        while !jobs.is_empty() {
            self.receive(&mut jobs).await;
        }
    }
    async fn receive(&self, jobs: &mut tokio::task::JoinSet<super::Result<Option<Loaded>>>) {
        match jobs.join_next().await {
            Some(Ok(Ok(Some(loaded)))) => self.published(&loaded),
            Some(Ok(Ok(None))) => {}
            Some(Ok(Err(e))) => log::warn!("inode snapshot poll failed: {e}"),
            Some(Err(e)) => log::warn!("inode snapshot poll task failed: {e}"),
            None => {}
        }
    }
}
