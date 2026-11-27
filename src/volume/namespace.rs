//! Conditional namespace edits. Cross-directory rename is destination-first;
//! interrupted changes are intentionally not recovered.
use super::{Error, Lease, Loaded, Result, Volume};
use crate::{
    crypto,
    format::{
        directory::{Directory, Entry},
        inode::{self, InodeContent},
        metadata::{Metadata, Timestamp},
    },
};
use std::collections::BTreeSet;

fn validate_name(name: &str) -> Result<()> {
    Directory {
        entries: vec![Entry {
            name: name.into(),
            id: [1; 16],
            kind: inode::FILE,
        }],
    }
    .encode()?;
    Ok(())
}
fn guard(leases: &mut [Lease], id: [u8; 16]) -> Result<&mut Lease> {
    leases
        .iter_mut()
        .find(|l| l.inode().body.id == id)
        .ok_or(Error::Invalid)
}
fn check(leases: &[Lease]) -> Result<()> {
    for l in leases {
        l.check_owner_time()?;
    }
    Ok(())
}
async fn pause(attempt: u32) {
    tokio::time::sleep(std::time::Duration::from_millis(
        (5u64 << attempt.min(5)).min(160),
    ))
    .await;
}
impl Volume {
    async fn lock_directories(
        &self,
        ids: impl IntoIterator<Item = [u8; 16]>,
    ) -> Result<Vec<Lease>> {
        let ids: BTreeSet<_> = ids.into_iter().collect();
        for attempt in 0..16 {
            let mut held = Vec::new();
            let mut failure = None;
            for id in &ids {
                match self.acquire_directory_lease(*id).await {
                    Ok(l) => held.push(l),
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                }
            }
            if failure.is_none() {
                return Ok(held);
            }
            for l in held.into_iter().rev() {
                let _ = self.release_directory_lease(l).await;
            }
            match failure.unwrap() {
                Error::Conflict => pause(attempt).await,
                e => return Err(e),
            }
        }
        Err(Error::Conflict)
    }
    async fn unlock_directories(&self, held: Vec<Lease>, result: Result<()>) -> Result<()> {
        let mut failure = None;
        for l in held.into_iter().rev() {
            if let Err(e) = self.release_directory_lease(l).await {
                failure.get_or_insert(e);
            }
        }
        result?;
        if let Some(e) = failure {
            return Err(e);
        }
        Ok(())
    }
    pub(super) async fn edit_entry(
        &self,
        parent: [u8; 16],
        name: &str,
        expected: Option<Entry>,
        next: Option<Entry>,
    ) -> Result<()> {
        validate_name(name)?;
        for attempt in 0..16 {
            let loaded = match self.load_writable(parent).await {
                Ok(l) => l,
                Err(Error::Conflict) => {
                    pause(attempt).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let (content, retired) = match self
                .prepare_directory_edit(&loaded, name, &expected, next.clone())
                .await
            {
                Err(Error::ChunkMissing) if self.inode_etag(parent).await? != loaded.etag => {
                    continue;
                }
                result => result?,
            };
            let mut body = loaded.body.clone();
            body.content = content;
            body.nlink = body
                .nlink
                .checked_sub(u32::from(
                    expected
                        .as_ref()
                        .is_some_and(|e| e.kind == inode::DIRECTORY),
                ))
                .and_then(|n| {
                    n.checked_add(u32::from(
                        next.as_ref().is_some_and(|e| e.kind == inode::DIRECTORY),
                    ))
                })
                .ok_or(Error::TooLarge)?;
            body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
            body.metadata.mtime = Timestamp::now();
            body.metadata.ctime = body.metadata.mtime;
            match self.publish(&loaded, &body, Some(&loaded.etag)).await {
                Ok(_) => {
                    self.delete_objects(retired).await;
                    return Ok(());
                }
                Err(Error::Conflict) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict)
    }
    pub async fn create(&self, parent: [u8; 16], name: &str, kind: u8) -> Result<Loaded> {
        self.create_with_metadata(
            parent,
            name,
            kind,
            Metadata::new(
                0,
                0,
                if kind == inode::DIRECTORY {
                    0o755
                } else {
                    0o644
                },
            ),
        )
        .await
    }
    pub async fn create_with_metadata(
        &self,
        parent: [u8; 16],
        name: &str,
        kind: u8,
        metadata: Metadata,
    ) -> Result<Loaded> {
        if !matches!(kind, inode::FILE | inode::DIRECTORY) {
            return Err(Error::Invalid);
        }
        self.create_entry(parent, name, kind, metadata, None, None)
            .await
    }
    /// Apply POSIX setgid inheritance and reuse that parent read for lookup.
    /// The caller supplies the requested metadata after applying its umask.
    pub async fn create_inheriting_metadata(
        &self,
        parent: [u8; 16],
        name: &str,
        kind: u8,
        mut metadata: Metadata,
    ) -> Result<Loaded> {
        if !matches!(kind, inode::FILE | inode::DIRECTORY) {
            return Err(Error::Invalid);
        }
        let loaded = self.load(parent).await?;
        if loaded.body.metadata.mode & 0o2000 != 0 {
            metadata.gid = loaded.body.metadata.gid;
            if kind == inode::DIRECTORY {
                metadata.mode |= 0o2000;
            }
        }
        self.create_entry(parent, name, kind, metadata, None, Some(loaded))
            .await
    }
    async fn create_entry(
        &self,
        parent: [u8; 16],
        name: &str,
        kind: u8,
        metadata: Metadata,
        content: Option<Vec<u8>>,
        parent_snapshot: Option<Loaded>,
    ) -> Result<Loaded> {
        validate_name(name)?;
        let existing = match parent_snapshot {
            Some(loaded) => match self.lookup_loaded(&loaded, name).await {
                // A concurrent directory edit may have retired a tree page.
                Err(Error::ChunkMissing) => self.lookup(parent, name).await?,
                result => result?,
            },
            None => self.lookup(parent, name).await?,
        };
        if existing.is_some() {
            return Err(Error::Exists);
        }
        let loaded = if let Some(content) = content {
            self.create_inode_content(crypto::random_array()?, kind, metadata, content)
                .await?
        } else {
            self.create_inode(crypto::random_array()?, kind, metadata)
                .await?
        };
        let e = Entry {
            name: name.into(),
            id: loaded.body.id,
            kind,
        };
        if kind == inode::DIRECTORY {
            let mut held = self.lock_directories([self.root, parent]).await?;
            let result = async {
                let l = guard(&mut held, parent)?;
                self.edit_leased_directory(l, &[(name, None, Some(e))])
                    .await
            }
            .await;
            self.unlock_directories(held, result).await?;
        } else {
            self.edit_entry(parent, name, None, Some(e)).await?;
        }
        Ok(loaded)
    }
    pub async fn symlink(
        &self,
        parent: [u8; 16],
        name: &str,
        target: &[u8],
        metadata: Metadata,
    ) -> Result<Loaded> {
        if target.is_empty() || target.len() > 4096 || target.contains(&0) {
            return Err(Error::Invalid);
        }
        self.create_entry(
            parent,
            name,
            inode::SYMLINK,
            metadata,
            Some(target.to_vec()),
            None,
        )
        .await
    }
    pub async fn readlink(&self, id: [u8; 16]) -> Result<Vec<u8>> {
        let l = self.load(id).await?;
        if l.body.kind != inode::SYMLINK {
            return Err(Error::Invalid);
        }
        let InodeContent::Inline(bytes) = l.body.content else {
            return Err(Error::Invalid);
        };
        Ok(bytes)
    }
    async fn change_links(&self, id: [u8; 16], delta: i32) -> Result<Loaded> {
        for _ in 0..16 {
            let mut l = self.load_writable(id).await?;
            let mut b = l.body.clone();
            b.nlink = if delta < 0 {
                b.nlink.saturating_sub(delta.unsigned_abs())
            } else {
                b.nlink.checked_add(delta as u32).ok_or(Error::TooLarge)?
            };
            b.generation = b.generation.checked_add(1).ok_or(Error::TooLarge)?;
            b.metadata.ctime = Timestamp::now();
            match self.publish(&l, &b, Some(&l.etag)).await {
                Ok(e) => {
                    l.body = b;
                    l.etag = e;
                    return Ok(l);
                }
                Err(Error::Conflict) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict)
    }
    pub async fn link(&self, id: [u8; 16], parent: [u8; 16], name: &str) -> Result<Loaded> {
        validate_name(name)?;
        let l = self.load(id).await?;
        if l.body.kind == inode::DIRECTORY {
            return Err(Error::Permission);
        }
        if self.lookup(parent, name).await?.is_some() {
            return Err(Error::Exists);
        }
        self.change_links(id, 1).await?;
        if let Err(e) = self
            .edit_entry(
                parent,
                name,
                None,
                Some(Entry {
                    name: name.into(),
                    id,
                    kind: l.body.kind,
                }),
            )
            .await
        {
            let _ = self.change_links(id, -1).await;
            return Err(e);
        }
        self.load(id).await
    }
    pub async fn unlink(&self, parent: [u8; 16], name: &str) -> Result<()> {
        let e = self.lookup(parent, name).await?.ok_or(Error::Missing)?;
        if e.kind == inode::DIRECTORY {
            return Err(Error::IsDirectory);
        }
        self.edit_entry(parent, name, Some(e.clone()), None).await?;
        self.change_links(e.id, -1).await?;
        Ok(())
    }
    pub async fn rmdir(&self, parent: [u8; 16], name: &str) -> Result<()> {
        validate_name(name)?;
        let e = self.lookup(parent, name).await?.ok_or(Error::Missing)?;
        if e.kind != inode::DIRECTORY {
            return Err(Error::NotDirectory);
        }
        let mut held = self.lock_directories([self.root, parent, e.id]).await?;
        let result = async {
            if self
                .lookup_loaded(guard(&mut held, parent)?.inode(), name)
                .await?
                != Some(e.clone())
            {
                return Err(Error::Conflict);
            }
            check(&held)?;
            self.retire_directory(guard(&mut held, e.id)?).await?;
            check(&held)?;
            self.edit_leased_directory(guard(&mut held, parent)?, &[(name, Some(e), None)])
                .await
        }
        .await;
        self.unlock_directories(held, result).await
    }
    async fn directory_tree(&self, root: [u8; 16]) -> Result<BTreeSet<[u8; 16]>> {
        let mut todo = vec![root];
        let mut seen = BTreeSet::new();
        while let Some(id) = todo.pop() {
            if !seen.insert(id) {
                continue;
            }
            if seen.len() > 65536 {
                return Err(Error::TooLarge);
            }
            todo.extend(
                self.list(id)
                    .await?
                    .into_iter()
                    .filter(|e| e.kind == inode::DIRECTORY)
                    .map(|e| e.id),
            );
        }
        Ok(seen)
    }
    pub async fn rename(
        &self,
        parent: [u8; 16],
        name: &str,
        new_parent: [u8; 16],
        new_name: &str,
        no_replace: bool,
    ) -> Result<()> {
        validate_name(name)?;
        validate_name(new_name)?;
        let source = self.lookup(parent, name).await?.ok_or(Error::Missing)?;
        let target = self.lookup(new_parent, new_name).await?;
        if no_replace && target.is_some() {
            return Err(Error::Exists);
        }
        if parent == new_parent && name == new_name {
            return Ok(());
        }
        if target.as_ref().is_some_and(|e| e.id == source.id) {
            return Ok(());
        }
        if let Some(t) = &target {
            match (source.kind == inode::DIRECTORY, t.kind == inode::DIRECTORY) {
                (true, false) => return Err(Error::NotDirectory),
                (false, true) => return Err(Error::IsDirectory),
                _ => {}
            }
        }
        let topology = source.kind == inode::DIRECTORY;
        let tree = if topology {
            self.directory_tree(source.id).await?
        } else {
            BTreeSet::new()
        };
        if tree.contains(&new_parent) {
            return Err(Error::Invalid);
        }
        let mut ids = vec![parent, new_parent];
        if topology {
            ids.push(self.root);
            ids.extend(tree.iter().copied());
        }
        if let Some(t) = &target
            && t.kind == inode::DIRECTORY
        {
            ids.push(t.id);
        }
        let mut held = self.lock_directories(ids).await?;
        let result = async {
            if self
                .lookup_loaded(guard(&mut held, parent)?.inode(), name)
                .await?
                != Some(source.clone())
                || self
                    .lookup_loaded(guard(&mut held, new_parent)?.inode(), new_name)
                    .await?
                    != target
            {
                return Err(Error::Conflict);
            }
            if topology {
                let current_tree = self.directory_tree(source.id).await?;
                if current_tree.contains(&new_parent) {
                    return Err(Error::Invalid);
                }
                if current_tree != tree {
                    return Err(Error::Conflict);
                }
            }
            check(&held)?;
            if let Some(t) = &target
                && t.kind == inode::DIRECTORY
                && !self.directory_is_empty(guard(&mut held, t.id)?.inode())?
            {
                return Err(Error::NotEmpty);
            }
            let moved = Entry {
                name: new_name.into(),
                ..source.clone()
            };
            if parent == new_parent {
                check(&held)?;
                self.edit_leased_directory(
                    guard(&mut held, parent)?,
                    &[
                        (name, Some(source.clone()), None),
                        (new_name, target.clone(), Some(moved)),
                    ],
                )
                .await?;
            } else {
                check(&held)?;
                self.edit_leased_directory(
                    guard(&mut held, new_parent)?,
                    &[(new_name, target.clone(), Some(moved))],
                )
                .await?;
                check(&held)?;
                self.edit_leased_directory(
                    guard(&mut held, parent)?,
                    &[(name, Some(source.clone()), None)],
                )
                .await?;
            }
            if let Some(t) = &target
                && t.kind == inode::DIRECTORY
            {
                check(&held)?;
                self.retire_directory(guard(&mut held, t.id)?).await?;
            }
            if source.kind != inode::DIRECTORY {
                self.change_links(source.id, 0).await?;
            } else {
                check(&held)?;
                self.touch_directory(guard(&mut held, source.id)?).await?;
            }
            if let Some(t) = &target
                && t.kind != inode::DIRECTORY
            {
                self.change_links(t.id, -1).await?;
            }
            Ok(())
        }
        .await;
        self.unlock_directories(held, result).await
    }
}
