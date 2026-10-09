use super::*;

/// The caller obtains generation and all roots from one authoritative state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub generation: u64,
    pub journal_id: Hex<16>,
    pub kind: Kind,
    pub root: Option<Reference>,
}
impl Snapshot {
    #[cfg(test)]
    pub fn empty(journal_id: Hex<16>, kind: Kind) -> Self {
        Self {
            generation: 0,
            journal_id,
            kind,
            root: None,
        }
    }
}

/// Opaque to clients. Both the root and commit generation must still match.
#[derive(Clone, Debug)]
pub(crate) struct Cursor {
    snapshot: Snapshot,
    after: Key,
}

impl Journal<'_> {
    /// Validate every referenced page, including branches not visited by an
    /// ordinary lookup. Memory contains hashes plus at most one bounded DFS
    /// frontier, never the journal's complete bodies.
    pub(crate) fn validate_snapshot_pages(
        &mut self,
        snapshot: &Snapshot,
        reachable: &mut std::collections::BTreeSet<Hash>,
    ) -> Result<()> {
        self.pin(snapshot)?;
        let mut pending = snapshot
            .root
            .clone()
            .map(|r| vec![(r, true)])
            .unwrap_or_default();
        while let Some((reference, root)) = pending.pop() {
            let mut budget = ReadBudget::new(1)?;
            let page = self.load_page(&reference, snapshot.kind, root, None, &mut budget)?;
            if !reachable.insert(reference.hash) {
                // A tree cannot share a child: disjoint ordered ranges and
                // authenticated min/max descriptors require distinct pages.
                return Err(Error::Corrupt);
            }
            if reachable.len() as u64 > self.limits.objects {
                return Err(Error::ObjectLimit);
            }
            pending.extend(page.children.into_iter().rev().map(|r| (r, false)));
        }
        Ok(())
    }

    /// A failed mutation invalidates the entire staged batch. No disk writes
    /// happen here, and unchanged subtrees keep their existing references.
    pub fn insert(
        &mut self,
        batch: &mut Batch,
        snapshot: &Snapshot,
        entry: Entry,
        budget: &mut ReadBudget,
    ) -> Result<Snapshot> {
        let result = (|| {
            self.pin(snapshot)?;
            if batch.invalid || batch.journal_id != self.id {
                return Err(Error::InvalidBatch);
            }
            entry.validate(snapshot.kind)?;
            let roots = if let Some(root) = &snapshot.root {
                if root.level >= self.limits.depth {
                    return Err(Error::Limit);
                }
                self.insert_at(batch, root, snapshot.kind, entry, true, budget)?
            } else {
                vec![batch.page(
                    &Page::leaf(self.id, snapshot.kind, vec![entry]),
                    self.limits,
                )?]
            };
            let reference = if roots.len() == 1 {
                roots[0].clone()
            } else {
                let level = roots[0].level + 1;
                if level >= self.limits.depth {
                    return Err(Error::Limit);
                }
                batch.page(
                    &Page::branch(self.id, snapshot.kind, level, roots),
                    self.limits,
                )?
            };
            Ok(Snapshot {
                root: Some(reference),
                ..snapshot.clone()
            })
        })();
        if result.is_err() {
            batch.invalid = true;
        }
        result
    }

    fn insert_at(
        &mut self,
        batch: &mut Batch,
        reference: &Reference,
        kind: Kind,
        entry: Entry,
        root: bool,
        budget: &mut ReadBudget,
    ) -> Result<Vec<Reference>> {
        let mut page = self.load_page(reference, kind, root, Some(batch), budget)?;
        let split = if page.level == 0 {
            match page.records.binary_search_by(|old| old.key.cmp(&entry.key)) {
                Ok(index) if page.records[index] == entry => return Ok(vec![reference.clone()]),
                Ok(index) => page.records[index] = entry,
                Err(index) => page.records.insert(index, entry),
            }
            if page.records.len() > FANOUT {
                let right = page.records.split_off(MIN_OCCUPANCY);
                Some(Page::leaf(self.id, kind, right))
            } else {
                None
            }
        } else {
            let index = child_for(&page, &entry.key);
            let replacements =
                self.insert_at(batch, &page.children[index], kind, entry, false, budget)?;
            page.children.splice(index..=index, replacements);
            if page.children.len() > FANOUT {
                let right = page.children.split_off(MIN_OCCUPANCY);
                Some(Page::branch(self.id, kind, page.level, right))
            } else {
                None
            }
        };
        let mut references = vec![batch.page(&page, self.limits)?];
        if let Some(right) = split {
            references.push(batch.page(&right, self.limits)?);
        }
        Ok(references)
    }

    pub fn get(
        &mut self,
        snapshot: &Snapshot,
        key: &Key,
        budget: &mut ReadBudget,
    ) -> Result<Option<Value>> {
        self.pin(snapshot)?;
        key.validate(snapshot.kind)?;
        let mut walk = Walk::seek(self, snapshot, Some(key), budget)?;
        Ok(walk
            .next(self, snapshot.kind, budget)?
            .filter(|entry| entry.key == *key)
            .map(|entry| entry.value))
    }

    /// Validate a key against the complete prospective root before publication.
    pub fn staged_get(
        &mut self,
        batch: &Batch,
        snapshot: &Snapshot,
        key: &Key,
        budget: &mut ReadBudget,
    ) -> Result<Option<Value>> {
        self.pin(snapshot)?;
        key.validate(snapshot.kind)?;
        if batch.invalid || batch.journal_id != self.id {
            return Err(Error::InvalidBatch);
        }
        let Some(mut reference) = snapshot.root.clone() else {
            return Ok(None);
        };
        let mut root = true;
        loop {
            let page = self.load_page(&reference, snapshot.kind, root, Some(batch), budget)?;
            if page.level == 0 {
                return Ok(page
                    .records
                    .binary_search_by(|r| r.key.cmp(key))
                    .ok()
                    .map(|i| page.records[i].value.clone()));
            }
            reference = page.children[child_for(&page, key)].clone();
            root = false;
        }
    }

    /// Return up to 16 records. A full page has a continuation even if the next
    /// page is empty; this avoids an unbudgeted lookahead read to prove EOF.
    pub fn page(
        &mut self,
        snapshot: &Snapshot,
        start: Option<&Key>,
        cursor: Option<&Cursor>,
        limit: usize,
        budget: &mut ReadBudget,
    ) -> Result<(Vec<Entry>, Option<Cursor>)> {
        self.pin(snapshot)?;
        if limit == 0 || limit > 16 || (start.is_some() && cursor.is_some()) {
            return Err(Error::Limit);
        }
        if let Some(cursor) = cursor {
            if cursor.snapshot != *snapshot {
                return Err(Error::StaleCursor);
            }
        }
        let from = cursor.map(|c| &c.after).or(start);
        if let Some(key) = from {
            key.validate(snapshot.kind)?;
        }
        let mut walk = Walk::seek(self, snapshot, from, budget)?;
        let mut records = Vec::new();
        while records.len() < limit {
            let Some(entry) = walk.next(self, snapshot.kind, budget)? else {
                break;
            };
            if cursor.is_some_and(|cursor| entry.key <= cursor.after) {
                continue;
            }
            records.push(entry);
        }
        let continuation = if records.len() == limit {
            Some(Cursor {
                snapshot: snapshot.clone(),
                after: records.last().ok_or(Error::Corrupt)?.key.clone(),
            })
        } else {
            None
        };
        Ok((records, continuation))
    }
}

fn child_for(page: &Page, key: &Key) -> usize {
    // Follow the predecessor range even in a gap or beyond the largest key.
    // Descend to the boundary leaf before declaring absence, then visit its
    // successor through the same pinned root if necessary.
    page.children
        .partition_point(|child| child.min <= *key)
        .saturating_sub(1)
}

struct Walk {
    stack: Vec<(Page, usize)>,
    leaf: Vec<Entry>,
    position: usize,
}
impl Walk {
    fn seek(
        journal: &mut Journal<'_>,
        snapshot: &Snapshot,
        key: Option<&Key>,
        budget: &mut ReadBudget,
    ) -> Result<Self> {
        let mut walk = Self {
            stack: vec![],
            leaf: vec![],
            position: 0,
        };
        if let Some(root) = &snapshot.root {
            walk.descend(journal, root.clone(), snapshot.kind, true, key, budget)?;
        }
        Ok(walk)
    }
    fn descend(
        &mut self,
        journal: &mut Journal<'_>,
        mut reference: Reference,
        kind: Kind,
        mut root: bool,
        key: Option<&Key>,
        budget: &mut ReadBudget,
    ) -> Result<()> {
        loop {
            let page = journal.load_page(&reference, kind, root, None, budget)?;
            if page.level == 0 {
                self.position = key.map_or(0, |key| {
                    page.records.partition_point(|entry| entry.key < *key)
                });
                self.leaf = page.records;
                return Ok(());
            }
            let index = key.map_or(0, |key| child_for(&page, key));
            reference = page.children[index].clone();
            self.stack.push((page, index));
            root = false;
        }
    }
    fn next(
        &mut self,
        journal: &mut Journal<'_>,
        kind: Kind,
        budget: &mut ReadBudget,
    ) -> Result<Option<Entry>> {
        loop {
            if let Some(entry) = self.leaf.get(self.position) {
                self.position += 1;
                return Ok(Some(entry.clone()));
            }
            let Some((page, index)) = self.stack.pop() else {
                return Ok(None);
            };
            if let Some(next) = page.children.get(index + 1).cloned() {
                self.stack.push((page, index + 1));
                self.descend(journal, next, kind, false, None, budget)?;
            }
        }
    }
}
