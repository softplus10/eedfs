//! Encrypted file-index pages and batched COW path edits.
use super::{Error, Loaded, Piece, Result, Volume};
use crate::{
    crypto::{self, objects},
    format::{
        file_index::{Child, FANOUT, FileRoot, MAX_ENTRIES, MAX_HEIGHT, Page, Record, Root, Value},
        inode::{self, ChunkRun, ChunkedContent, Hole, InodeContent, Mutation},
    },
    storage::s3::PutResult,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
#[derive(Clone)]
pub(super) struct IndexState {
    pub root: FileRoot,
    pub pages: BTreeMap<[u8; 16], Page>,
    _memory: Arc<super::resources::Memory>,
}
impl Volume {
    pub(super) fn file_page_name(&self, l: &Loaded, c: &Child) -> Result<String> {
        let key = crypto::kdf::derive(&l.key, &self.fs_id, crypto::kdf::Purpose::FileIndexNaming)?;
        let naming = crate::format::header::NamingConfig {
            algorithm: crypto::naming::algorithm()?,
            key: key.0,
        };
        self.chunk_name(
            &naming,
            &Piece {
                offset: 0,
                len: c.len,
                allocation: c.id,
                index: 0,
            },
        )
    }
    async fn index_page(
        &self,
        l: &Loaded,
        c: &Child,
        height: u8,
        cache: &mut BTreeMap<[u8; 16], Page>,
    ) -> Result<Page> {
        let p = if let Some(p) = cache.get(&c.id) {
            p.clone()
        } else {
            let name = self.file_page_name(l, c)?;
            let stored = self
                .connection
                .get(&name, c.len as usize + 64)
                .await?
                .ok_or(Error::ChunkMissing)?;
            let plain =
                objects::open_chunk(&l.key, &self.fs_id, &name, &l.suite, c.len, &stored.bytes)?;
            let p = Page::decode(&plain)?;
            cache.insert(c.id, p.clone());
            p
        };
        if p.bounds() != (c.first, c.end, c.count) || (height == 0) != matches!(p, Page::Leaf(_)) {
            return Err(Error::Invalid);
        }
        Ok(p)
    }
    async fn index_records(
        &self,
        l: &Loaded,
        root: &Option<Root>,
        cache: &mut BTreeMap<[u8; 16], Page>,
        range: Option<(u64, u64)>,
    ) -> Result<Vec<Record>> {
        let Some(root) = root else { return Ok(vec![]) };
        root.validate()?;
        let mut todo = vec![(root.child.clone(), root.height)];
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        while let Some((c, h)) = todo.pop() {
            if range.is_some_and(|(a, b)| c.end <= a || c.first >= b) {
                continue;
            }
            if !seen.insert(c.id)
                || seen.len() as u64 > root.child.count * (u64::from(root.height) + 1)
            {
                return Err(Error::Invalid);
            }
            match self.index_page(l, &c, h, cache).await? {
                Page::Leaf(records) => out.extend(
                    records
                        .into_iter()
                        .filter(|r| range.is_none_or(|(a, b)| r.end > a && r.start < b)),
                ),
                Page::Branch(children) => {
                    todo.extend(children.into_iter().rev().map(|c| (c, h - 1)))
                }
            }
        }
        if range.is_none() && out.len() as u64 != root.child.count {
            return Err(Error::Invalid);
        }
        Ok(out)
    }
    pub(super) async fn indexed_read_pieces(
        &self,
        l: &Loaded,
        start: u64,
        end: u64,
    ) -> Result<(Vec<Piece>, Vec<super::resources::Memory>)> {
        let InodeContent::Indexed(root) = &l.body.content else {
            return Err(Error::Invalid);
        };
        let mut todo = root
            .extents
            .iter()
            .map(|r| (r.child.clone(), r.height))
            .collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        let mut cache = BTreeMap::new();
        let mut pieces = vec![];
        let mut memory = vec![];
        while let Some((child, height)) = todo.pop() {
            if child.end <= start || child.first >= end {
                continue;
            }
            if !seen.insert(child.id) {
                return Err(Error::Invalid);
            }
            memory.push(
                self.resources
                    .work_memory(u64::from(child.len) * 8 + 1024)?,
            );
            match self.index_page(l, &child, height, &mut cache).await? {
                Page::Branch(children) => {
                    todo.extend(children.into_iter().rev().map(|c| (c, height - 1)))
                }
                Page::Leaf(records) => {
                    for r in records {
                        if r.end > start && r.start < end {
                            let Value::Extent { allocation, index } = r.value else {
                                return Err(Error::Invalid);
                            };
                            pieces.push(Piece {
                                offset: r.start,
                                len: (r.end - r.start) as u32,
                                allocation,
                                index,
                            });
                        }
                    }
                }
            }
        }
        Ok((pieces, memory))
    }
    pub(super) async fn hydrate_file(&self, l: &mut Loaded) -> Result<()> {
        let InodeContent::Indexed(root) = &l.body.content else {
            return Ok(());
        };
        let root = (**root).clone();
        let estimated = (root.extents.as_ref().map_or(0, |r| r.child.count)
            + root.versions.as_ref().map_or(0, |r| r.child.count))
        .checked_mul(512)
        .ok_or(Error::TooLarge)?
            + 4096;
        let memory = Arc::new(self.resources.memory(estimated)?);
        let mut cache = BTreeMap::new();
        let extents = self
            .index_records(l, &root.extents, &mut cache, None)
            .await?;
        let versions = self
            .index_records(l, &root.versions, &mut cache, None)
            .await?;
        let mut runs: Vec<ChunkRun> = vec![];
        let mut holes = vec![];
        let mut cursor = 0;
        let mut allocated = 0;
        for r in extents {
            let Value::Extent { allocation, index } = r.value else {
                return Err(Error::Invalid);
            };
            if r.start < cursor || r.end > root.size {
                return Err(Error::Invalid);
            };
            if cursor < r.start {
                holes.push(Hole {
                    offset: cursor,
                    len: r.start - cursor,
                });
            }
            if let Some(last) = runs.last_mut()
                && last.allocation_id == allocation
                && last.first_chunk + last.plaintext_lengths.len() as u64 == index
            {
                last.plaintext_lengths.push((r.end - r.start) as u32);
            } else {
                runs.push(ChunkRun {
                    allocation_id: allocation,
                    first_chunk: index,
                    plaintext_lengths: vec![(r.end - r.start) as u32],
                });
            }
            allocated += r.end - r.start;
            cursor = r.end;
        }
        let mut mutations: BTreeMap<u64, Mutation> = BTreeMap::new();
        for r in versions {
            let Value::Version(generation) = r.value else {
                return Err(Error::Invalid);
            };
            if generation > l.body.generation {
                return Err(Error::Invalid);
            };
            mutations
                .entry(generation)
                .or_insert(Mutation {
                    generation,
                    size_changed: false,
                    attribute_fields: 0,
                    ranges: vec![],
                })
                .ranges
                .push((r.start, r.end));
        }
        for (i, &g) in root.flags.iter().enumerate().filter(|(_, g)| **g != 0) {
            let m = mutations.entry(g).or_insert(Mutation {
                generation: g,
                size_changed: false,
                attribute_fields: 0,
                ranges: vec![],
            });
            if i == 0 {
                m.size_changed = true;
            } else {
                m.attribute_fields |= 1 << (i - 1);
            }
        }
        l.body.mutations = mutations.into_values().collect();
        if root.size <= inode::MAX_INLINE_SIZE as u64 {
            l.body.content = InodeContent::Inline(root.inline.clone());
        } else {
            if cursor < root.size {
                holes.push(Hole {
                    offset: cursor,
                    len: root.size - cursor,
                });
            }
            if allocated != root.allocated {
                return Err(Error::Invalid);
            };
            l.body.content = InodeContent::Chunks(ChunkedContent {
                naming: root.naming.clone(),
                runs,
                holes,
            });
        }
        l.index = Some(Arc::new(IndexState {
            root,
            pages: cache,
            _memory: memory,
        }));
        Ok(())
    }
    async fn write_index_page(
        &self,
        l: &Loaded,
        page: Page,
        cache: &mut BTreeMap<[u8; 16], Page>,
    ) -> Result<Child> {
        let plain = zeroize::Zeroizing::new(page.encode()?);
        let (first, end, count) = page.bounds();
        let id = crypto::random_array()?;
        let child = Child {
            first,
            end,
            count,
            id,
            len: plain.len() as u32,
        };
        child.validate()?;
        let name = self.file_page_name(l, &child)?;
        let bytes = objects::seal_chunk(&l.key, &self.fs_id, &name, &l.suite, &plain)?;
        match self.connection.put(&name, bytes, None).await? {
            PutResult::Applied(_) => {}
            PutResult::Conflict => return Err(Error::Conflict),
        }
        cache.insert(id, page);
        Ok(child)
    }
    fn edit_index<'a>(
        &'a self,
        l: &'a Loaded,
        c: Child,
        height: u8,
        changes: BTreeMap<u64, Option<Record>>,
        cache: &'a mut BTreeMap<[u8; 16], Page>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Child>>> + Send + 'a>> {
        Box::pin(async move {
            if changes.is_empty() {
                return Ok(vec![c]);
            }
            let original = self.index_page(l, &c, height, cache).await?;
            let pages = match &original {
                Page::Leaf(records) => {
                    let mut map: BTreeMap<_, _> =
                        records.iter().map(|r| (r.start, r.clone())).collect();
                    for (k, v) in changes {
                        if let Some(v) = v {
                            map.insert(k, v);
                        } else {
                            map.remove(&k);
                        }
                    }
                    let records: Vec<_> = map.into_values().collect();
                    records
                        .chunks(FANOUT)
                        .map(|v| Page::Leaf(v.to_vec()))
                        .collect::<Vec<_>>()
                }
                Page::Branch(children) => {
                    let mut edits: Vec<BTreeMap<u64, Option<Record>>> =
                        vec![BTreeMap::new(); children.len()];
                    for (key, value) in changes {
                        let i = children
                            .partition_point(|c| c.first <= key)
                            .saturating_sub(1);
                        edits[i].insert(key, value);
                    }
                    let mut next = vec![];
                    for (child, edits) in children.iter().zip(edits) {
                        next.extend(
                            self.edit_index(l, child.clone(), height - 1, edits, cache)
                                .await?,
                        );
                    }
                    next.chunks(FANOUT)
                        .map(|v| Page::Branch(v.to_vec()))
                        .collect()
                }
            };
            if pages.len() == 1 && pages[0] == original {
                return Ok(vec![c]);
            }
            let mut result = vec![];
            for p in pages {
                result.push(self.write_index_page(l, p, cache).await?);
            }
            Ok(result)
        })
    }
    async fn reconcile_index(
        &self,
        l: &Loaded,
        old: Option<Root>,
        records: Vec<Record>,
        cache: &mut BTreeMap<[u8; 16], Page>,
    ) -> Result<Option<Root>> {
        if records.len() as u64 > MAX_ENTRIES {
            return Err(Error::TooLarge);
        }
        if let Some(root) = old {
            let previous = self
                .index_records(l, &Some(root.clone()), cache, None)
                .await?;
            let next: BTreeMap<_, _> = records.into_iter().map(|r| (r.start, r)).collect();
            let previous: BTreeMap<_, _> = previous.into_iter().map(|r| (r.start, r)).collect();
            let mut changes = BTreeMap::new();
            for (&k, r) in &previous {
                if next.get(&k) != Some(r) {
                    changes.insert(k, next.get(&k).cloned());
                }
            }
            for (&k, r) in &next {
                if !previous.contains_key(&k) {
                    changes.insert(k, Some(r.clone()));
                }
            }
            let mut children = self
                .edit_index(l, root.child, root.height, changes, cache)
                .await?;
            let mut height = root.height;
            while children.len() > 1 {
                let mut parents = vec![];
                for group in children.chunks(FANOUT) {
                    parents.push(
                        self.write_index_page(l, Page::Branch(group.to_vec()), cache)
                            .await?,
                    );
                }
                children = parents;
                height += 1;
            }
            let Some(mut child) = children.pop() else {
                return Ok(None);
            };
            while height > 0 {
                match self.index_page(l, &child, height, cache).await? {
                    Page::Branch(v) if v.len() == 1 => {
                        child = v[0].clone();
                        height -= 1;
                    }
                    _ => break,
                }
            }
            if height > MAX_HEIGHT {
                return Err(Error::TooLarge);
            }
            Ok(Some(Root { child, height }))
        } else {
            let mut children = vec![];
            for group in records.chunks(FANOUT) {
                children.push(
                    self.write_index_page(l, Page::Leaf(group.to_vec()), cache)
                        .await?,
                );
            }
            let mut height = 0;
            while children.len() > 1 {
                let mut parents = vec![];
                for group in children.chunks(FANOUT) {
                    parents.push(
                        self.write_index_page(l, Page::Branch(group.to_vec()), cache)
                            .await?,
                    );
                }
                children = parents;
                height += 1;
            }
            Ok(children.pop().map(|child| Root { child, height }))
        }
    }
    pub(super) async fn publish_file(&self, l: &Loaded, body: inode::InodeBody) -> Result<Loaded> {
        let count = super::pieces(&body).len();
        let range_count: usize = body.mutations.iter().map(|m| m.ranges.len()).sum();
        if l.index.is_none()
            && count <= 1024
            && body.mutations.len() <= 512
            && range_count <= 2048
            && body.encode().is_ok()
        {
            let wire_memory = Arc::new(
                self.resources
                    .memory(body.encode()?.len() as u64 * 8 + 4096)?,
            );
            let etag = self.publish(l, &body, Some(&l.etag)).await?;
            return Ok(Loaded {
                _memory: wire_memory,
                body,
                etag,
                index: None,
                ..l.clone()
            });
        }
        let memory = Arc::new(
            self.resources
                .memory((count as u64 + range_count as u64) * 512 + 4096)?,
        );
        let old = l.index.as_ref().map(|i| &i.root);
        let mut cache = l
            .index
            .as_ref()
            .map(|i| i.pages.clone())
            .unwrap_or_default();
        let naming = match &body.content {
            InodeContent::Chunks(c) => c.naming.clone(),
            _ => match old {
                Some(root) => root.naming.clone(),
                None => crate::format::header::NamingConfig {
                    algorithm: crypto::naming::algorithm()?,
                    key: crypto::random_array()?,
                },
            },
        };
        let extents = super::pieces(&body)
            .into_iter()
            .map(|p| Record {
                start: p.offset,
                end: p.offset + u64::from(p.len),
                value: Value::Extent {
                    allocation: p.allocation,
                    index: p.index,
                },
            })
            .collect::<Vec<_>>();
        let allocated = extents.iter().map(|r| r.end - r.start).sum();
        let mut versions = vec![];
        let mut flags = [0; 6];
        for m in &body.mutations {
            if m.size_changed {
                flags[0] = m.generation;
            }
            for i in 0..5 {
                if m.attribute_fields & (1 << i) != 0 {
                    flags[i + 1] = m.generation;
                }
            }
            for &(start, end) in &m.ranges {
                versions.push(Record {
                    start,
                    end,
                    value: Value::Version(m.generation),
                });
            }
        }
        versions.sort_by_key(|r| r.start);
        let extents = self
            .reconcile_index(l, old.and_then(|r| r.extents.clone()), extents, &mut cache)
            .await?;
        let versions = self
            .reconcile_index(
                l,
                old.and_then(|r| r.versions.clone()),
                versions,
                &mut cache,
            )
            .await?;
        let inline = match &body.content {
            InodeContent::Inline(bytes) => bytes.clone(),
            _ => vec![],
        };
        let root = FileRoot {
            size: body.size()?,
            allocated: if inline.is_empty() {
                allocated
            } else {
                inline.len() as u64
            },
            naming,
            extents,
            versions,
            flags,
            inline,
        };
        root.validate(body.generation)?;
        let mut wire = body.clone();
        wire.content = InodeContent::Indexed(Box::new(root.clone()));
        wire.mutations.clear();
        // Authenticate all page summaries and retain only pages reachable from the new roots.
        let mut live_cache = BTreeMap::new();
        for r in [&root.extents, &root.versions].into_iter().flatten() {
            let mut todo = vec![(r.child.clone(), r.height)];
            while let Some((c, h)) = todo.pop() {
                let p = self.index_page(l, &c, h, &mut cache).await?;
                if let Page::Branch(v) = &p {
                    todo.extend(v.iter().cloned().map(|c| (c, h - 1)));
                }
                live_cache.insert(c.id, p);
            }
        }
        let retired: Vec<_> = l
            .index
            .iter()
            .flat_map(|i| i.pages.keys())
            .filter(|id| !live_cache.contains_key(*id))
            .map(|id| {
                let p = &l.index.as_ref().unwrap().pages[id];
                let (first, end, count) = p.bounds();
                self.file_page_name(
                    l,
                    &Child {
                        first,
                        end,
                        count,
                        id: *id,
                        len: p.encode()?.len() as u32,
                    },
                )
            })
            .collect::<Result<_>>()?;
        let wire_memory = Arc::new(
            self.resources
                .memory(wire.encode()?.len() as u64 * 8 + 4096)?,
        );
        let etag = self.publish(l, &wire, Some(&l.etag)).await?;
        self.delete_objects(retired).await;
        Ok(Loaded {
            _memory: wire_memory,
            body,
            etag,
            index: Some(Arc::new(IndexState {
                root,
                pages: live_cache,
                _memory: memory,
            })),
            ..l.clone()
        })
    }
    pub(super) fn index_page_names(&self, l: &Loaded) -> Result<Vec<String>> {
        let mut out = vec![];
        if let Some(i) = &l.index {
            for (&id, p) in &i.pages {
                let (first, end, count) = p.bounds();
                out.push(self.file_page_name(
                    l,
                    &Child {
                        first,
                        end,
                        count,
                        id,
                        len: p.encode()?.len() as u32,
                    },
                )?);
            }
        }
        Ok(out)
    }
}
