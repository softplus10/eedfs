//! Offline reachability scan and sweep. Never repairs namespace state.
use super::{Error, Result, Volume, pieces};
use crate::{
    crypto::{encryption, kdf},
    format::{
        header::{Header, ProtectedConfig},
        inode::{self, InodeContent},
    },
    storage::s3::ListedObject,
};
use std::collections::{BTreeMap, BTreeSet};

pub struct GcOptions {
    pub delete: bool,
    /// Bound inventory/mark memory; exceeding the limit aborts before deletion.
    pub max_objects: usize,
}
impl Default for GcOptions {
    fn default() -> Self {
        Self {
            delete: false,
            max_objects: 100_000,
        }
    }
}
#[derive(Debug, Default)]
pub struct GcReport {
    pub listed_objects: usize,
    pub listed_bytes: u64,
    pub live_inodes: usize,
    pub live_objects: usize,
    pub live_bytes: u64,
    /// Regular-file logical bytes, counting hard-linked inodes once.
    pub logical_file_bytes: u64,
    pub ignored_objects: usize,
    pub unreferenced_objects: usize,
    pub unreferenced_bytes: u64,
    pub deleted_objects: usize,
    pub deleted_bytes: u64,
}
type Inventory = BTreeMap<String, ListedObject>;

fn add(total: &mut u64, value: u64) -> Result<()> {
    *total = total.checked_add(value).ok_or(Error::TooLarge)?;
    Ok(())
}
fn mark(live: &mut BTreeSet<String>, inventory: &Inventory, key: String) -> Result<()> {
    if !inventory.contains_key(&key) {
        return Err(Error::Other(
            format!("GC: referenced object missing from inventory: {key}").into(),
        ));
    }
    live.insert(key);
    Ok(())
}
fn owned_key(prefix: &str, key: &str) -> bool {
    key.strip_prefix(prefix).is_some_and(|name| {
        name.len() == 64
            && name
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
impl Volume {
    async fn gc_inventory(&self, max: usize) -> Result<Inventory> {
        if max == 0 {
            return Err(Error::Invalid);
        }
        let mut inventory = BTreeMap::new();
        let mut token = None;
        loop {
            let page = self
                .connection
                .list_page(&self.prefix, token.as_deref())
                .await?;
            for object in page.objects {
                if inventory.len() >= max {
                    return Err(Error::Other(
                        "GC inventory exceeds --max-objects; nothing deleted".into(),
                    ));
                }
                if inventory.insert(object.key.clone(), object).is_some() {
                    return Err(Error::Other(
                        "GC inventory repeated an object; nothing deleted".into(),
                    ));
                }
            }
            match page.next {
                Some(next) => token = Some(next),
                None => return Ok(inventory),
            }
        }
    }
    /// All clients, including unlinked open files/mappings and upload workers,
    /// MUST be stopped for the entire scan/sweep. ETags detect some violations,
    /// but cannot turn this protocol into an online collector.
    pub async fn collect_garbage(&self, options: GcOptions) -> Result<GcReport> {
        let header_key = format!("{}header", self.prefix);
        let stored = self
            .connection
            .get(&header_key, crate::format::header::MAX_SIZE)
            .await?
            .ok_or(Error::Missing)?;
        let header = Header::decode(&stored.bytes)?;
        if header.filesystem_id != self.fs_id {
            return Err(Error::Conflict);
        }
        // Authenticate current root/naming against this Volume's master key.
        let key = kdf::derive(&self.master, &self.fs_id, kdf::Purpose::Header)?;
        let plain = encryption::open(&header.protected, &key, &header.protected_aad()?)?;
        let config = ProtectedConfig::decode(&plain)?;
        if config.root_inode != self.root || config.naming != self.names {
            return Err(Error::Conflict);
        }
        let inventory = self.gc_inventory(options.max_objects).await?;
        if inventory
            .get(&header_key)
            .is_none_or(|o| o.etag != stored.etag)
        {
            return Err(Error::Conflict);
        }
        let mut live = BTreeSet::new();
        mark(&mut live, &inventory, header_key)?;
        let mut seen = BTreeMap::from([(self.root, inode::DIRECTORY)]);
        let mut todo = vec![(self.root, inode::DIRECTORY)];
        let mut report = GcReport {
            listed_objects: inventory.len(),
            ..Default::default()
        };
        while let Some((id, kind)) = todo.pop() {
            let name = self.inode_name(&id)?;
            mark(&mut live, &inventory, name.clone())?;
            let mut loaded = self.load(id).await?;
            self.hydrate_file(&mut loaded).await?;
            for page in self.index_page_names(&loaded)? {
                mark(&mut live, &inventory, page)?;
            }
            if loaded.body.kind != kind || loaded.body.deleted {
                return Err(Error::Invalid);
            }
            if inventory[&name].etag != loaded.etag {
                return Err(Error::Conflict);
            }
            match kind {
                inode::DIRECTORY => {
                    let (directory, pages) = self.directory_pages(&loaded).await?;
                    for page in pages {
                        mark(&mut live, &inventory, page)?;
                    }
                    for entry in directory.entries {
                        if let Some(previous) = seen.get(&entry.id) {
                            if *previous != entry.kind {
                                return Err(Error::Invalid);
                            }
                        } else {
                            // Deduplicate before queueing: many hard-link names
                            // must not create an unbounded traversal queue.
                            if seen.len() >= inventory.len() {
                                return Err(Error::Invalid);
                            }
                            seen.insert(entry.id, entry.kind);
                            todo.push((entry.id, entry.kind));
                        }
                    }
                }
                inode::FILE => {
                    add(&mut report.logical_file_bytes, loaded.body.size()?)?;
                    if let InodeContent::Chunks(chunks) = &loaded.body.content {
                        for piece in pieces(&loaded.body) {
                            let name = self.chunk_name(&chunks.naming, &piece)?;
                            mark(&mut live, &inventory, name.clone())?;
                            let expected = u64::from(piece.len)
                                + encryption::nonce_size(&loaded.suite)? as u64
                                + encryption::TAG_SIZE as u64;
                            if inventory[&name].size != expected {
                                return Err(Error::Invalid);
                            }
                        }
                    }
                }
                inode::SYMLINK => {} // Do not follow pathname targets.
                _ => return Err(Error::Invalid),
            }
        }
        report.live_inodes = seen.len();
        report.live_objects = live.len();
        let mut candidates = Vec::new();
        for (name, object) in &inventory {
            add(&mut report.listed_bytes, object.size)?;
            if live.contains(name) {
                add(&mut report.live_bytes, object.size)?;
            } else if owned_key(&self.prefix, name) {
                report.unreferenced_objects += 1;
                add(&mut report.unreferenced_bytes, object.size)?;
                candidates.push(object);
            } else {
                report.ignored_objects += 1;
            }
        }
        // Re-list before any DELETE. Fail closed on observed concurrent changes
        // or incomplete inventories. This is deliberately not an online lock.
        if inventory != self.gc_inventory(options.max_objects).await? {
            return Err(Error::Conflict);
        }
        if options.delete {
            let mut jobs = tokio::task::JoinSet::new();
            for object in candidates {
                let connection = self.connection.clone();
                let object = object.clone();
                jobs.spawn(async move {
                    connection.delete_checked(&object.key, &object.etag).await
                        .map_err(|e| Error::Other(format!("GC delete failed for {}: {e}; earlier deletions may have completed", object.key).into()))?;
                    Ok::<_, Error>(object.size)
                });
                if jobs.len() >= self.parallelism {
                    add(&mut report.deleted_bytes, jobs.join_next().await.unwrap()??)?;
                    report.deleted_objects += 1;
                }
            }
            while let Some(result) = jobs.join_next().await {
                add(&mut report.deleted_bytes, result??)?;
                report.deleted_objects += 1;
            }
        }
        Ok(report)
    }
}
