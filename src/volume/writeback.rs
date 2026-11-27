//! Mount-local, bounded close writeback. No on-disk format or recovery journal.
use super::{
    Error, FileSession, Result,
    resources::{Memory, Resources},
    snapshots::Snapshots,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, Weak},
};
use tokio::{runtime::Handle, sync::Notify, task::JoinSet};

pub type Session = Arc<Mutex<FileSession>>;
type Id = [u8; 16];
struct Entry {
    session: Weak<Mutex<FileSession>>,
    pending: Option<Session>,
    requested: u64,
    finished: u64,
    running: bool,
    explicit: bool,
    queued: bool,
    waiters: usize,
    error: Option<Arc<Error>>,
    observed: bool,
    _memory: Memory,
}
struct State {
    entries: HashMap<Id, Entry>,
    limit: usize,
    stopping: bool,
    stopped: bool,
    fatal: Option<Arc<Error>>,
    ready: VecDeque<Id>,
}
pub struct Writeback {
    state: Mutex<State>,
    changed: Notify,
    resources: Arc<Resources>,
    snapshots: Arc<Snapshots>,
}

// Error owns non-cloneable SDK sources. Preserve errno-relevant variants for
// every observer, while retaining the original error in the queue until success.
fn copy_error(error: &Error) -> Error {
    match error {
        Error::Conflict => Error::Conflict,
        Error::Exists => Error::Exists,
        Error::Missing => Error::Missing,
        Error::ChunkMissing => Error::ChunkMissing,
        Error::NotDirectory => Error::NotDirectory,
        Error::Invalid => Error::Invalid,
        Error::TooLarge => Error::TooLarge,
        Error::NotEmpty => Error::NotEmpty,
        Error::Permission => Error::Permission,
        Error::IsDirectory => Error::IsDirectory,
        Error::Unsupported => Error::Unsupported,
        Error::NoSpace => Error::NoSpace,
        Error::NoMemory => Error::NoMemory,
        Error::Other(source) => {
            if let Some(code) = source
                .downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error())
            {
                Error::Other(std::io::Error::from_raw_os_error(code).into())
            } else {
                Error::Other(format!("background writeback: {source}").into())
            }
        }
    }
}
struct Waiter {
    queue: Arc<Writeback>,
    id: Id,
}
impl Drop for Waiter {
    fn drop(&mut self) {
        let mut state = self.queue.state.lock().unwrap();
        if let Some(entry) = state.entries.get_mut(&self.id) {
            entry.waiters -= 1;
        }
        Writeback::prune_one(&mut state, self.id);
    }
}
impl Writeback {
    pub fn new(resources: Arc<Resources>, snapshots: Arc<Snapshots>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                entries: HashMap::new(),
                limit: 65_536,
                stopping: false,
                stopped: false,
                fatal: None,
                ready: VecDeque::new(),
            }),
            changed: Notify::new(),
            resources,
            snapshots,
        })
    }
    pub fn set_limit(&self, limit: usize) -> Result<()> {
        if limit < 2 {
            return Err(Error::Invalid);
        }
        let mut state = self.state.lock().unwrap();
        Self::prune(&mut state);
        if state.entries.len() > limit {
            return Err(Error::NoMemory);
        }
        state.limit = limit;
        Ok(())
    }
    fn prune(state: &mut State) {
        state.entries.retain(|_, e| {
            e.pending.is_some() || e.running || e.waiters != 0 || e.session.strong_count() != 0
        });
    }
    fn prune_one(state: &mut State, id: Id) {
        if state.entries.get(&id).is_some_and(|e| {
            e.pending.is_none()
                && !e.running
                && !e.queued
                && e.waiters == 0
                && e.session.strong_count() == 0
        }) {
            state.entries.remove(&id);
        }
    }
    /// Pair with dropping the last external session reference. Either this or
    /// worker completion removes clean bookkeeping, regardless of the race.
    pub fn forget_closed(&self, id: Id) {
        Self::prune_one(&mut self.state.lock().unwrap(), id);
    }
    /// Reserve queue bookkeeping before an open can accept writes. Only weak
    /// ownership is needed until a flush/release schedules the inode.
    pub fn track(&self, id: Id, session: &Session) -> Result<Session> {
        let mut state = self.state.lock().unwrap();
        if state.stopping {
            return Err(Error::Other("mount is shutting down".into()));
        }
        Self::prune_one(&mut state, id);
        if let Some(session) = state.entries.get(&id).and_then(|e| e.session.upgrade()) {
            return Ok(session);
        }
        if state.entries.len() >= state.limit {
            Self::prune(&mut state);
            if state.entries.len() >= state.limit {
                return Err(Error::NoMemory);
            }
        }
        let memory = match self.resources.memory(1024) {
            Err(Error::NoMemory) => {
                Self::prune(&mut state);
                self.resources.memory(1024)?
            }
            other => other?,
        };
        state.entries.insert(
            id,
            Entry {
                session: Arc::downgrade(session),
                pending: None,
                requested: 0,
                finished: 0,
                running: false,
                explicit: false,
                queued: false,
                waiters: 0,
                error: None,
                observed: false,
                _memory: memory,
            },
        );
        Ok(session.clone())
    }
    /// Does not acquire the inode mutex or wait for network I/O. Known failures
    /// stay latched; another close must not silently retry a failed generation.
    pub fn submit(&self, id: Id, session: &Session) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(error) = &state.fatal {
            return Err(copy_error(error));
        }
        if state.stopping {
            return Err(Error::Other("mount is shutting down".into()));
        }
        let entry = state.entries.get_mut(&id).ok_or(Error::Missing)?;
        entry.pending = Some(session.clone());
        if let Some(error) = &entry.error {
            return Err(copy_error(error));
        }
        entry.requested = entry.requested.checked_add(1).ok_or(Error::TooLarge)?;
        if !entry.running && !entry.queued {
            entry.queued = true;
            state.ready.push_back(id);
        }
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }
    pub async fn sync(self: &Arc<Self>, id: Id) -> Result<()> {
        let target = {
            let mut state = self.state.lock().unwrap();
            if state.stopping {
                return Err(Error::Other("mount is shutting down".into()));
            }
            if let Some(error) = &state.fatal {
                return Err(copy_error(error));
            }
            let entry = state.entries.get_mut(&id).ok_or(Error::Missing)?;
            if let Some(error) = &entry.error
                && !entry.observed
            {
                entry.observed = true;
                return Err(copy_error(error));
            }
            entry.error = None;
            entry.observed = false;
            entry.pending = Some(entry.session.upgrade().ok_or(Error::Missing)?);
            entry.requested = entry.requested.checked_add(1).ok_or(Error::TooLarge)?;
            entry.explicit = true;
            entry.waiters += 1;
            let target = entry.requested;
            if !entry.running && !entry.queued {
                entry.queued = true;
                state.ready.push_back(id);
            }
            target
        };
        let _waiter = Waiter {
            queue: self.clone(),
            id,
        };
        self.changed.notify_waiters();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap();
                if let Some(error) = &state.fatal {
                    return Err(copy_error(error));
                }
                let entry = state.entries.get_mut(&id).ok_or(Error::Missing)?;
                if let Some(error) = &entry.error {
                    entry.observed = true;
                    return Err(copy_error(error));
                }
                if entry.finished >= target {
                    return Ok(());
                }
            }
            changed.await;
        }
    }
    /// Mount-wide explicit barrier, including closed inodes retained by errors.
    pub async fn sync_all(self: &Arc<Self>) -> Result<()> {
        let sessions: Vec<_> = self
            .state
            .lock()
            .unwrap()
            .entries
            .iter()
            .filter_map(|(id, entry)| entry.session.upgrade().map(|session| (*id, session)))
            .collect();
        let mut first = None;
        for (id, _session) in sessions {
            if let Err(error) = self.sync(id).await {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }
    /// Used only after a resource reservation rejected a write before accepting
    /// bytes. Callers release their inode mutex before waiting on other work.
    pub async fn wait_for_progress(&self) -> bool {
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        {
            let state = self.state.lock().unwrap();
            if state.fatal.is_some()
                || state.stopped
                || !state
                    .entries
                    .values()
                    .any(|e| e.running || (e.error.is_none() && e.requested > e.finished))
            {
                return false;
            }
        }
        changed.await;
        true
    }
    /// Stop admission and drain queued work. Failed entries are reported without
    /// automatic retry. The mount process can inspect shutdown_result afterward.
    pub async fn shutdown(&self) -> Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            if !state.stopping {
                state.stopping = true;
                let mut ready = Vec::new();
                for (id, entry) in &mut state.entries {
                    if entry.error.is_none()
                        && let Some(session) = entry.session.upgrade()
                    {
                        entry.pending = Some(session);
                        entry.requested = entry.requested.checked_add(1).ok_or(Error::TooLarge)?;
                        if !entry.running && !entry.queued {
                            entry.queued = true;
                            ready.push(*id);
                        }
                    }
                }
                state.ready.extend(ready);
            }
        }
        self.changed.notify_waiters();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.state.lock().unwrap().stopped {
                return self.shutdown_result();
            }
            changed.await;
        }
    }
    pub fn shutdown_result(&self) -> Result<()> {
        let state = self.state.lock().unwrap();
        if !state.stopped {
            return Err(Error::Other("writeback was not drained".into()));
        }
        if let Some(error) = &state.fatal {
            return Err(copy_error(error));
        }
        if let Some(error) = state.entries.values().find_map(|e| e.error.as_ref()) {
            return Err(copy_error(error));
        }
        Ok(())
    }
    /// One coordinator and a bounded set of blocking jobs. Inode mutexes never
    /// block Tokio's async workers, which must keep chunk uploads making progress.
    pub async fn run(self: Arc<Self>, runtime: Handle, parallelism: usize) {
        let mut jobs = JoinSet::new();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            while jobs.len() < parallelism.max(1) {
                let next = {
                    let mut state = self.state.lock().unwrap();
                    state.ready.pop_front().and_then(|id| {
                        let e = state.entries.get_mut(&id)?;
                        let session = e.pending.as_ref()?.clone();
                        e.queued = false;
                        e.running = true;
                        let explicit = std::mem::take(&mut e.explicit);
                        Some((id, e.requested, explicit, session))
                    })
                };
                let Some((id, target, explicit, session)) = next else {
                    break;
                };
                let runtime = runtime.clone();
                let snapshots = self.snapshots.clone();
                jobs.spawn_blocking(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let mut working = session.lock().unwrap();
                        let result = runtime.block_on(async {
                            if explicit {
                                working.commit().await
                            } else {
                                working.commit_background().await
                            }
                        });
                        if result.is_ok() {
                            snapshots.published(&working.base);
                        }
                        result
                    }))
                    .unwrap_or_else(|_| Err(Error::Other("writeback worker panicked".into())));
                    (id, target, result)
                });
            }
            {
                let mut state = self.state.lock().unwrap();
                if state.stopping && jobs.is_empty() {
                    state.stopped = true;
                    drop(state);
                    self.changed.notify_waiters();
                    return;
                }
            }
            if jobs.is_empty() {
                changed.await;
                continue;
            }
            tokio::select! {
                _ = changed => {},
                result = jobs.join_next() => {
                    let mut state = self.state.lock().unwrap();
                    match result {
                        Some(Ok((id, target, result))) => {
                            if let Some(entry) = state.entries.get_mut(&id) {
                                entry.running = false;
                                entry.finished = target;
                                if let Err(error) = result {
                                    log::error!("background inode commit failed ({id:02x?}): {error:?}");
                                    entry.error = Some(Arc::new(error));
                                    entry.observed = false;
                                } else if entry.finished >= entry.requested {
                                    entry.pending = None;
                                } else {
                                    entry.queued = true;
                                    state.ready.push_back(id);
                                }
                            }
                            Self::prune_one(&mut state, id);
                        },
                        _ => {
                            state.fatal = Some(Arc::new(Error::Other("writeback coordinator lost a worker".into())));
                            state.stopped = true;
                            drop(state);
                            self.changed.notify_waiters();
                            return;
                        }
                    }
                    drop(state);
                    self.changed.notify_waiters();
                }
            }
        }
    }
}
