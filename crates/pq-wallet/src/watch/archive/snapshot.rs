//! A coherent, read-only recovery view of existing watch/journal files.
//! This verifies structural authority, not completeness against an external
//! trusted backup receipt, current chain observations or a newer lost snapshot.
use super::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalSnapshotMetadata {
    pub generation: Option<u64>,
    pub journal_id: Option<Hex<16>>,
    pub reachable_objects: u64,
    pub retained_bytes: u64,
    pub retained_objects: u64,
    pub root_fingerprint: Hex<32>,
}

/// Keeps the allocator's exclusive borrow and lock alive throughout copying.
/// The caller must stream retained files into a new private staging directory
/// and validate the staged root again before atomic publication.
pub(crate) struct JournalSnapshot<'a> {
    watch: &'a mut WatchStore,
    metadata: JournalSnapshotMetadata,
}
impl JournalSnapshot<'_> {
    pub(crate) fn directory(&self) -> Result<&Path, Error> {
        self.watch.journal_path()
    }
    pub(crate) fn manifest(&self) -> &Manifest {
        self.watch.manifest()
    }
    pub(crate) fn receive_next(&self) -> u64 {
        self.watch.state.receive_next
    }
    pub(crate) fn change_next(&self) -> u64 {
        self.watch.state.payments.change_next
    }
    pub(crate) fn metadata(&self) -> &JournalSnapshotMetadata {
        &self.metadata
    }
}

impl WatchStore {
    pub(crate) fn journal_snapshot(&mut self) -> Result<JournalSnapshot<'_>, Error> {
        self.ready()?;
        let result = self.validate_snapshot();
        if matches!(result, Err(Error::JournalCorrupt | Error::Storage(_))) {
            self.poison();
        }
        let metadata = result?;
        Ok(JournalSnapshot {
            watch: self,
            metadata,
        })
    }

    fn validate_snapshot(&mut self) -> Result<JournalSnapshotMetadata, Error> {
        self.state.validate()?;
        let bytes = encode(&self.state)?;
        let mut hash = Sha256::new();
        hash.update(b"ZcashTransparentPQ/wallet-journal-root-receipt/v1\0");
        hash.update(&*bytes);
        let mut metadata = JournalSnapshotMetadata {
            generation: None,
            journal_id: None,
            reachable_objects: 0,
            retained_bytes: 0,
            retained_objects: 0,
            root_fingerprint: Hex(hash.finalize().into()),
        };
        let Some(root) = self.state.journal.clone() else {
            (metadata.retained_bytes, metadata.retained_objects) = Journal::orphan_usage(self)?;
            return Ok(metadata);
        };
        root.descriptor.validate(root.active.len())?;
        let manifest = self.state.manifest.clone();
        let change_next = self.state.payments.change_next;
        // Recount retained orphan and temporary files under the existing quotas;
        // a cached usage count cannot describe a newly exported directory.
        let mut journal =
            Journal::open(self, root.descriptor.journal_id, root.descriptor.limits())?;
        let mut reachable = BTreeSet::new();
        for kind in [
            Kind::Lineages,
            Kind::Aliases,
            Kind::Reservations,
            Kind::History,
        ] {
            journal.validate_snapshot_pages(&root.descriptor.snapshot(kind), &mut reachable)?;
        }
        let mut capabilities = BTreeMap::new();
        let mut active_seen = BTreeSet::new();
        let mut archived_without_history = BTreeSet::new();
        for kind in [
            Kind::Lineages,
            Kind::Aliases,
            Kind::Reservations,
            Kind::History,
        ] {
            let snapshot = root.descriptor.snapshot(kind);
            let mut cursor = None;
            let mut count = 0u64;
            loop {
                let mut budget = ReadBudget::new(4096)?;
                let (entries, next) =
                    journal.page(&snapshot, None, cursor.as_ref(), 16, &mut budget)?;
                for entry in entries {
                    validate_entry(
                        &mut journal,
                        &root,
                        &manifest,
                        change_next,
                        kind,
                        &entry,
                        count,
                        &mut capabilities,
                        &mut reachable,
                        &mut active_seen,
                        &mut archived_without_history,
                    )?;
                    count = count.checked_add(1).ok_or(Error::JournalLimit)?;
                }
                cursor = next;
                if cursor.is_none() {
                    break;
                }
            }
            if count != snapshot.root.as_ref().map_or(0, |r| r.count) {
                return Err(Error::JournalCorrupt);
            }
        }
        if active_seen.len() != root.active.len() || !archived_without_history.is_empty() {
            return Err(Error::JournalCorrupt);
        }
        metadata.generation = Some(root.descriptor.generation);
        metadata.journal_id = Some(root.descriptor.journal_id);
        metadata.reachable_objects = reachable.len() as u64;
        (metadata.retained_bytes, metadata.retained_objects) = journal.retained_usage();
        Ok(metadata)
    }
}

fn latest(
    journal: &mut Journal<'_>,
    descriptor: &Descriptor,
    lineage: Hex<32>,
) -> Result<(Hex<32>, Location, Hex<32>, u64), Error> {
    let mut budget = ReadBudget::new(4096)?;
    match journal.get(
        &descriptor.snapshot(Kind::Lineages),
        &Key::id(lineage),
        &mut budget,
    )? {
        Some(Value::Lineage {
            capability,
            location,
            proposal_id,
            revision,
        }) => Ok((capability, location, proposal_id, revision)),
        _ => Err(Error::JournalCorrupt),
    }
}

fn check_alias(
    journal: &mut Journal<'_>,
    descriptor: &Descriptor,
    id: Hex<32>,
    hash: Hex<32>,
    lineage: Hex<32>,
    revision: u64,
) -> Result<(), Error> {
    let mut budget = ReadBudget::new(4096)?;
    if journal.get(
        &descriptor.snapshot(Kind::Aliases),
        &Key::id(id),
        &mut budget,
    )? != Some(Value::Alias {
        capability: hash,
        lineage_id: lineage,
        revision,
    }) {
        return Err(Error::JournalCorrupt);
    }
    Ok(())
}

/// Each distinct predecessor is checked once; the object-count ceiling also
/// bounds malicious chains. Existing readers bound each capability to 1 MiB.
fn capability_chain(
    journal: &mut Journal<'_>,
    descriptor: &Descriptor,
    hash: Hex<32>,
    manifest: &Manifest,
    change_next: u64,
    checked: &mut BTreeMap<(Hex<32>, u64), Hex<32>>,
    reachable: &mut BTreeSet<Hex<32>>,
) -> Result<Capability, Error> {
    let first = journal.capability(hash, manifest, change_next)?;
    let mut current = first.clone();
    let mut current_hash = hash;
    loop {
        if let Some(previous_hash) = checked.get(&(current.lineage_id, current.revision)) {
            if *previous_hash != current_hash {
                return Err(Error::JournalCorrupt);
            }
            break;
        }
        if !reachable.insert(current_hash) || reachable.len() as u64 > journal.object_limit() {
            return Err(Error::JournalCorrupt);
        }
        // Every distinct approved proposal ID remains addressable after tip
        // refresh. Its alias can point at a newer capability with the same ID,
        // but can neither disappear nor refer to an older/different lineage.
        let mut budget = ReadBudget::new(4096)?;
        let Some(Value::Alias {
            capability: alias_hash,
            lineage_id,
            revision,
        }) = journal.get(
            &descriptor.snapshot(Kind::Aliases),
            &Key::id(current.proposal.id()?),
            &mut budget,
        )?
        else {
            return Err(Error::JournalCorrupt);
        };
        if lineage_id != current.lineage_id
            || revision < current.revision
            || (revision == current.revision && alias_hash != current_hash)
        {
            return Err(Error::JournalCorrupt);
        }
        checked.insert((current.lineage_id, current.revision), current_hash);
        let Some(previous_hash) = current.previous else {
            break;
        };
        let previous = journal.capability(previous_hash, manifest, change_next)?;
        let expected =
            previous.successor(previous_hash, &current.record(PaymentState::Prepared))?;
        if canonical::encode(&expected, 1024 * 1024)? != canonical::encode(&current, 1024 * 1024)? {
            return Err(Error::JournalCorrupt);
        }
        current = previous;
        current_hash = previous_hash;
    }
    Ok(first)
}

#[allow(clippy::too_many_arguments)]
fn validate_entry(
    journal: &mut Journal<'_>,
    root: &Root,
    manifest: &Manifest,
    change_next: u64,
    kind: Kind,
    entry: &Entry,
    sequence: u64,
    checked: &mut BTreeMap<(Hex<32>, u64), Hex<32>>,
    reachable: &mut BTreeSet<Hex<32>>,
    active_seen: &mut BTreeSet<Hex<32>>,
    archived_without_history: &mut BTreeSet<(Hex<32>, Hex<32>)>,
) -> Result<(), Error> {
    let descriptor = &root.descriptor;
    match (&entry.value, kind) {
        (
            Value::Lineage {
                capability: hash,
                location,
                proposal_id,
                revision,
            },
            Kind::Lineages,
        ) => {
            let cap = capability_chain(
                journal,
                descriptor,
                *hash,
                manifest,
                change_next,
                checked,
                reachable,
            )?;
            if entry.key != Key::id(cap.lineage_id)
                || *revision != cap.revision
                || *proposal_id != cap.proposal.id()?
            {
                return Err(Error::JournalCorrupt);
            }
            check_alias(
                journal,
                descriptor,
                *proposal_id,
                *hash,
                cap.lineage_id,
                *revision,
            )?;
            let active = root.active.iter().find(|a| a.lineage_id == cap.lineage_id);
            match (location, active) {
                (Location::Active, Some(active)) if active.capability == *hash => {
                    if !active_seen.insert(cap.lineage_id) {
                        return Err(Error::JournalCorrupt);
                    }
                    let mut budget = ReadBudget::new(4096)?;
                    validate_active(journal, None, descriptor, active, &cap, &mut budget)?;
                }
                (Location::Archived, None) => {
                    archived_without_history.insert((cap.lineage_id, *hash));
                }
                _ => return Err(Error::JournalCorrupt),
            }
            // Archived authority retains every original reservation too.
            for point in cap.proposal.points()? {
                let mut budget = ReadBudget::new(4096)?;
                if journal.get(
                    &descriptor.snapshot(Kind::Reservations),
                    &Key::reservation(point, cap.proposal.expiry()?, cap.lineage_id),
                    &mut budget,
                )? != Some(Value::Reservation)
                {
                    return Err(Error::JournalCorrupt);
                }
            }
        }
        (
            Value::Alias {
                capability: hash,
                lineage_id,
                revision,
            },
            Kind::Aliases,
        ) => {
            let cap = capability_chain(
                journal,
                descriptor,
                *hash,
                manifest,
                change_next,
                checked,
                reachable,
            )?;
            if cap.lineage_id != *lineage_id
                || cap.revision != *revision
                || entry.key != Key::id(cap.proposal.id()?)
            {
                return Err(Error::JournalCorrupt);
            }
            let (latest_hash, _, current_id, latest_revision) =
                latest(journal, descriptor, *lineage_id)?;
            if latest_revision < *revision
                || (latest_revision == *revision
                    && (latest_hash != *hash || entry.key != Key::id(current_id)))
            {
                return Err(Error::JournalCorrupt);
            }
        }
        (Value::Reservation, Kind::Reservations) => {
            let (point, expiry, lineage) = entry.key.reservation_parts()?;
            let (hash, _, id, revision) = latest(journal, descriptor, lineage)?;
            let cap = capability_chain(
                journal,
                descriptor,
                hash,
                manifest,
                change_next,
                checked,
                reachable,
            )?;
            if cap.lineage_id != lineage
                || cap.revision != revision
                || cap.proposal.id()? != id
                || cap.proposal.expiry()? != expiry
                || !cap.proposal.points()?.contains(&point)
            {
                return Err(Error::JournalCorrupt);
            }
        }
        (
            Value::History {
                capability: hash,
                lineage_id,
                proposal_id,
                ..
            },
            Kind::History,
        ) => {
            let cap = capability_chain(
                journal,
                descriptor,
                *hash,
                manifest,
                change_next,
                checked,
                reachable,
            )?;
            archived_without_history.remove(&(*lineage_id, *hash));
            if entry.key != Key::sequence(sequence)
                || cap.lineage_id != *lineage_id
                || cap.proposal.id()? != *proposal_id
            {
                return Err(Error::JournalCorrupt);
            }
            let mut budget = ReadBudget::new(4096)?;
            let Some(Value::Alias {
                capability: alias_hash,
                lineage_id: alias_lineage,
                revision,
            }) = journal.get(
                &descriptor.snapshot(Kind::Aliases),
                &Key::id(*proposal_id),
                &mut budget,
            )?
            else {
                return Err(Error::JournalCorrupt);
            };
            let (latest_hash, _, current_id, latest_revision) =
                latest(journal, descriptor, *lineage_id)?;
            if alias_lineage != *lineage_id
                || revision < cap.revision
                || latest_revision < revision
                || (revision == cap.revision && alias_hash != *hash)
                || (latest_revision == revision
                    && (latest_hash != alias_hash || current_id != *proposal_id))
            {
                return Err(Error::JournalCorrupt);
            }
        }
        _ => return Err(Error::JournalCorrupt),
    }
    Ok(())
}
