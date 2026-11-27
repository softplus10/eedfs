//! Immutable directory B+tree pages; only the directory inode CAS publishes them.
use super::{Error, Loaded, Piece, Result, Volume};
use crate::{
    crypto::{self, objects},
    format::{
        directory::{Directory, Entry, validate_entries},
        directory_tree::{Child, FANOUT, MAX_ENTRIES, MAX_HEIGHT, Page, PageRef, Root},
        inode::{self, InodeContent},
    },
    storage::s3::PutResult,
};
use std::collections::BTreeSet;

fn payload(loaded: &Loaded) -> Result<&[u8]> {
    if loaded.body.deleted {
        return Err(Error::Missing);
    }
    if loaded.body.kind != inode::DIRECTORY {
        return Err(Error::NotDirectory);
    }
    match &loaded.body.content {
        InodeContent::Inline(bytes) => Ok(bytes),
        _ => Err(Error::Invalid),
    }
}
fn edit(
    entries: &mut Vec<Entry>,
    name: &str,
    expected: &Option<Entry>,
    next: Option<Entry>,
) -> Result<()> {
    let index = entries.partition_point(|e| e.name.as_str() < name);
    let current = entries.get(index).filter(|e| e.name == name).cloned();
    if &current != expected {
        return Err(Error::Conflict);
    }
    if current.is_some() {
        entries.remove(index);
    }
    if let Some(entry) = next {
        entries.insert(index, entry);
    }
    Ok(())
}
impl Volume {
    fn page_name(&self, page: &PageRef) -> Result<String> {
        self.chunk_name(
            &self.names,
            &Piece {
                offset: 0,
                len: page.len,
                allocation: page.id,
                index: 0,
            },
        )
    }
    async fn read_page(&self, loaded: &Loaded, child: &Child, height: u8) -> Result<Page> {
        let name = self.page_name(&child.page)?;
        let bytes = self
            .connection
            .get(&name, child.page.len as usize + 64)
            .await?
            .ok_or(Error::ChunkMissing)?
            .bytes;
        let plain = objects::open_chunk(
            &loaded.key,
            &self.fs_id,
            &name,
            &loaded.suite,
            child.page.len,
            &bytes,
        )?;
        let page = Page::decode(&plain)?;
        if page.first() != child.first || (height == 0) != matches!(page, Page::Leaf(_)) {
            return Err(Error::Invalid);
        }
        Ok(page)
    }
    pub(super) async fn write_page(&self, loaded: &Loaded, page: Page) -> Result<Child> {
        let plain = zeroize::Zeroizing::new(page.encode()?);
        let mut id = crypto::random_array()?;
        while id == [0; 16] {
            id = crypto::random_array()?;
        }
        let reference = PageRef {
            id,
            len: plain.len() as u32,
        };
        let name = self.page_name(&reference)?;
        let bytes = objects::seal_chunk(&loaded.key, &self.fs_id, &name, &loaded.suite, &plain)?;
        match self.connection.put(&name, bytes, None).await? {
            PutResult::Applied(_) => Ok(Child {
                first: page.first().into(),
                page: reference,
            }),
            PutResult::Conflict => Err(Error::Other(
                "immutable directory page name collision".into(),
            )),
        }
    }
    async fn split_page(&self, loaded: &Loaded, page: Page) -> Result<Vec<Child>> {
        let (left, right) = match page {
            Page::Leaf(mut entries) => {
                let right = (entries.len() > FANOUT)
                    .then(|| Page::Leaf(entries.split_off(entries.len() / 2)));
                (Page::Leaf(entries), right)
            }
            Page::Branch(mut children) => {
                let right = (children.len() > FANOUT)
                    .then(|| Page::Branch(children.split_off(children.len() / 2)));
                (Page::Branch(children), right)
            }
        };
        let mut result = vec![self.write_page(loaded, left).await?];
        if let Some(right) = right {
            result.push(self.write_page(loaded, right).await?);
        }
        Ok(result)
    }
    pub(super) async fn lookup_loaded(&self, loaded: &Loaded, name: &str) -> Result<Option<Entry>> {
        let bytes = payload(loaded)?;
        if !Root::is_tree(bytes) {
            return Ok(Directory::decode(bytes)?
                .entries
                .into_iter()
                .find(|e| e.name == name));
        }
        let root = Root::decode(bytes)?;
        let mut child = root.child;
        let mut height = root.height;
        loop {
            match self.read_page(loaded, &child, height).await? {
                Page::Leaf(entries) => return Ok(entries.into_iter().find(|e| e.name == name)),
                Page::Branch(children) => {
                    let index = children
                        .partition_point(|c| c.first.as_str() <= name)
                        .saturating_sub(1);
                    child = children[index].clone();
                    height -= 1;
                }
            }
        }
    }
    pub async fn lookup(&self, id: [u8; 16], name: &str) -> Result<Option<Entry>> {
        for _ in 0..16 {
            let loaded = self.load(id).await?;
            match self.lookup_loaded(&loaded, name).await {
                Err(Error::ChunkMissing) if self.inode_etag(id).await? != loaded.etag => continue,
                result => return result,
            }
        }
        Err(Error::Conflict)
    }
    pub(super) async fn directory_pages(
        &self,
        loaded: &Loaded,
    ) -> Result<(Directory, Vec<String>)> {
        let bytes = payload(loaded)?;
        if !Root::is_tree(bytes) {
            return Ok((Directory::decode(bytes)?, vec![]));
        }
        let root = Root::decode(bytes)?;
        let mut todo = vec![(root.child, root.height)];
        let mut seen = BTreeSet::new();
        let mut entries = Vec::new();
        let mut names = Vec::new();
        while let Some((child, height)) = todo.pop() {
            if !seen.insert(child.page.id)
                || seen.len() as u64 > root.entries * (u64::from(root.height) + 1)
            {
                return Err(Error::Invalid);
            }
            names.push(self.page_name(&child.page)?);
            match self.read_page(loaded, &child, height).await? {
                Page::Leaf(leaf) => {
                    entries.extend(leaf);
                    if entries.len() as u64 > root.entries {
                        return Err(Error::Invalid);
                    }
                }
                Page::Branch(children) => {
                    todo.extend(children.into_iter().rev().map(|child| (child, height - 1)))
                }
            }
        }
        if entries.len() as u64 != root.entries {
            return Err(Error::Invalid);
        }
        validate_entries(&entries, MAX_ENTRIES as usize)?;
        Ok((Directory { entries }, names))
    }
    pub(super) async fn directory(&self, loaded: &Loaded) -> Result<Directory> {
        Ok(self.directory_pages(loaded).await?.0)
    }
    pub(super) fn directory_is_empty(&self, loaded: &Loaded) -> Result<bool> {
        let bytes = payload(loaded)?;
        if Root::is_tree(bytes) {
            Root::decode(bytes)?;
            Ok(false)
        } else {
            Ok(Directory::decode(bytes)?.entries.is_empty())
        }
    }
    pub(super) async fn prepare_directory(
        &self,
        loaded: &Loaded,
        directory: &Directory,
    ) -> Result<(InodeContent, Vec<String>)> {
        let (_, retired) = self.directory_pages(loaded).await?;
        Ok((self.build_directory(loaded, directory).await?, retired))
    }
    async fn build_directory(
        &self,
        loaded: &Loaded,
        directory: &Directory,
    ) -> Result<InodeContent> {
        validate_entries(&directory.entries, MAX_ENTRIES as usize)?;
        match directory.encode() {
            Ok(bytes) => return Ok(InodeContent::Inline(bytes)),
            Err(crate::format::header::FormatError::TooLarge) => {}
            Err(error) => return Err(error.into()),
        }
        let mut children = Vec::new();
        for entries in directory.entries.chunks(FANOUT) {
            children.push(
                self.write_page(loaded, Page::Leaf(entries.to_vec()))
                    .await?,
            );
        }
        let mut height = 0;
        while children.len() > 1 {
            let mut parents = Vec::new();
            for group in children.chunks(FANOUT) {
                parents.push(
                    self.write_page(loaded, Page::Branch(group.to_vec()))
                        .await?,
                );
            }
            children = parents;
            height += 1;
        }
        Ok(InodeContent::Inline(
            Root {
                child: children.remove(0),
                height,
                entries: directory.entries.len() as u64,
            }
            .encode()?,
        ))
    }
    /// Copy only the leaf and its ancestor path. No old page is overwritten.
    pub(super) async fn prepare_directory_edit(
        &self,
        loaded: &Loaded,
        name: &str,
        expected: &Option<Entry>,
        next: Option<Entry>,
    ) -> Result<(InodeContent, Vec<String>)> {
        let bytes = payload(loaded)?;
        if !Root::is_tree(bytes) {
            let mut directory = Directory::decode(bytes)?;
            edit(&mut directory.entries, name, expected, next)?;
            return Ok((self.build_directory(loaded, &directory).await?, vec![]));
        }
        let root = Root::decode(bytes)?;
        let count = root.entries - u64::from(expected.is_some()) + u64::from(next.is_some());
        if count > MAX_ENTRIES {
            return Err(Error::TooLarge);
        }
        let mut child = root.child;
        let mut height = root.height;
        let mut path = Vec::new();
        let mut retired = Vec::new();
        let mut promoted;
        loop {
            let page = self.read_page(loaded, &child, height).await?;
            retired.push(self.page_name(&child.page)?);
            match page {
                Page::Leaf(mut entries) => {
                    edit(&mut entries, name, expected, next)?;
                    promoted = if entries.is_empty() {
                        vec![]
                    } else {
                        self.split_page(loaded, Page::Leaf(entries)).await?
                    };
                    break;
                }
                Page::Branch(children) => {
                    let index = children
                        .partition_point(|c| c.first.as_str() <= name)
                        .saturating_sub(1);
                    child = children[index].clone();
                    path.push((children, index));
                    height -= 1;
                }
            }
        }
        let mut root_height = root.height;
        while let Some((mut children, index)) = path.pop() {
            children.splice(index..=index, promoted);
            promoted = if children.is_empty() {
                vec![]
            } else if path.is_empty() && children.len() == 1 {
                root_height -= 1;
                children
            } else {
                self.split_page(loaded, Page::Branch(children)).await?
            };
        }
        let content = if promoted.is_empty() {
            InodeContent::Inline(Directory::default().encode()?)
        } else {
            if promoted.len() > 1 {
                promoted = vec![self.write_page(loaded, Page::Branch(promoted)).await?];
                root_height += 1;
            }
            if root_height > MAX_HEIGHT {
                return Err(Error::TooLarge);
            }
            InodeContent::Inline(
                Root {
                    child: promoted.remove(0),
                    height: root_height,
                    entries: count,
                }
                .encode()?,
            )
        };
        Ok((content, retired))
    }
}

impl Volume {
    /// Return a bounded lexicographic batch, without materializing the directory.
    pub async fn directory_after(
        &self,
        id: [u8; 16],
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Entry>> {
        if limit == 0 || limit > 256 {
            return Err(Error::Invalid);
        }
        for _ in 0..16 {
            let loaded = self.load(id).await?;
            let result = async {
                let bytes = payload(&loaded)?;
                if !Root::is_tree(bytes) {
                    return Ok(Directory::decode(bytes)?
                        .entries
                        .into_iter()
                        .filter(|e| after.is_none_or(|a| e.name.as_str() > a))
                        .take(limit)
                        .collect());
                }
                let root = Root::decode(bytes)?;
                let mut todo = vec![(root.child, root.height)];
                let mut entries = vec![];
                while let Some((child, height)) = todo.pop() {
                    match self.read_page(&loaded, &child, height).await? {
                        Page::Leaf(leaf) => {
                            for entry in leaf {
                                if after.is_none_or(|a| entry.name.as_str() > a) {
                                    entries.push(entry);
                                    if entries.len() == limit {
                                        return Ok(entries);
                                    }
                                }
                            }
                        }
                        Page::Branch(children) => {
                            let first = after.map_or(0, |a| {
                                children
                                    .partition_point(|c| c.first.as_str() <= a)
                                    .saturating_sub(1)
                            });
                            todo.extend(
                                children
                                    .into_iter()
                                    .skip(first)
                                    .rev()
                                    .map(|c| (c, height - 1)),
                            );
                        }
                    }
                }
                Ok(entries)
            }
            .await;
            match result {
                Err(Error::ChunkMissing) if self.inode_etag(id).await? != loaded.etag => continue,
                result => return result,
            }
        }
        Err(Error::Conflict)
    }
}
