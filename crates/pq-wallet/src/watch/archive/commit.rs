//! Validate one journal delta, publish objects, then allow the caller to publish its root.
use super::*;

impl WatchStore {
    /// Stage all objects and validate the complete changed index relationships
    /// before publication. The caller publishes the root only after this returns.
    pub(in crate::watch) fn stage_v3(
        &mut self,
        candidate: &mut State,
        hook: &mut impl FnMut(StateStage) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut root = candidate.journal.take().ok_or(Error::JournalCorrupt)?;
        if root.active.len() > candidate.payments.records.len()
            || candidate.payments.change_next < self.state.payments.change_next
            || candidate.receive_next < self.state.receive_next
        {
            return Err(Error::JournalCorrupt);
        }
        let old_root = self.state.journal.clone();
        let migrating = old_root.is_none();
        if let Some(old) = &old_root {
            if old.descriptor.journal_id != root.descriptor.journal_id
                || canonical::encode(&old.descriptor, 4096)?
                    != canonical::encode(&root.descriptor, 4096)?
            {
                return Err(Error::JournalCorrupt);
            }
            let removed: BTreeSet<_> = old
                .active
                .iter()
                .filter(|old| !root.active.iter().any(|a| a.lineage_id == old.lineage_id))
                .map(|a| a.lineage_id)
                .collect();
            if removed != root.archives.iter().map(|a| a.lineage_id).collect()
                || removed.len() != root.archives.len()
            {
                return Err(Error::JournalCorrupt);
            }
        } else if !root.active.is_empty() || !root.archives.is_empty() {
            return Err(Error::JournalCorrupt);
        }
        let limits = root.descriptor.limits();
        let mut journal = if migrating {
            Journal::create(self, root.descriptor.journal_id, limits, |stage| {
                journal_hook(hook, stage)
            })?
        } else {
            Journal::resume(self, root.descriptor.journal_id, limits)?
        };
        let mut batch = Batch::new(root.descriptor.journal_id);
        let mut budget = ReadBudget::new(4096)?;
        let mut expected = Vec::new();
        for archived in &root.archives {
            let cap = journal.capability(
                archived.capability,
                &candidate.manifest,
                candidate.payments.change_next,
            )?;
            validate_active(
                &mut journal,
                None,
                &old_root.as_ref().ok_or(Error::JournalCorrupt)?.descriptor,
                archived,
                &cap,
                &mut budget,
            )?;
            if !inactive(archived.state) {
                return Err(Error::PaymentActive);
            }
            let checkpoint = archived.checkpoint.ok_or(Error::JournalCorrupt)?;
            let proposal_id = cap.proposal.id()?;
            let value = Value::Lineage {
                capability: archived.capability,
                location: Location::Archived,
                proposal_id,
                revision: cap.revision,
            };
            let key = Key::id(archived.lineage_id);
            root.descriptor.insert(
                &mut journal,
                &mut batch,
                Kind::Lineages,
                key.clone(),
                value.clone(),
                &mut budget,
            )?;
            expected.push((Kind::Lineages, key, value));
            let key = Key::sequence(root.descriptor.next_event);
            root.descriptor.next_event = root
                .descriptor
                .next_event
                .checked_add(1)
                .ok_or(Error::JournalLimit)?;
            let value = Value::History {
                capability: archived.capability,
                checkpoint,
                lineage_id: archived.lineage_id,
                proposal_id,
                state: archived.state,
            };
            root.descriptor.insert(
                &mut journal,
                &mut batch,
                Kind::History,
                key.clone(),
                value.clone(),
                &mut budget,
            )?;
            expected.push((Kind::History, key, value));
        }
        let mut unique = BTreeSet::new();
        for (index, record) in candidate.payments.records.iter().enumerate() {
            let id = record.proposal.id()?;
            let (cap, hash, checkpoint) = if let Some(active) = root.active.get(index) {
                if !unique.insert(active.lineage_id) {
                    return Err(Error::JournalCorrupt);
                }
                let old = journal.capability(
                    active.capability,
                    &candidate.manifest,
                    candidate.payments.change_next,
                )?;
                if old.lineage_id != active.lineage_id {
                    return Err(Error::JournalCorrupt);
                }
                let old_snapshot = old_root
                    .as_ref()
                    .ok_or(Error::JournalCorrupt)?
                    .descriptor
                    .snapshot(Kind::Lineages);
                let Some(Value::Lineage {
                    capability,
                    revision,
                    proposal_id,
                    location,
                }) = journal.get(&old_snapshot, &Key::id(old.lineage_id), &mut budget)?
                else {
                    return Err(Error::JournalCorrupt);
                };
                if capability != active.capability
                    || revision != old.revision
                    || proposal_id != old.proposal.id()?
                    || (location == Location::Active
                        && !old_root
                            .as_ref()
                            .unwrap()
                            .active
                            .iter()
                            .any(|a| a.lineage_id == active.lineage_id))
                {
                    return Err(Error::JournalCorrupt);
                }
                let same = old.proposal == record.proposal
                    && old.intent == record.intent
                    && old.partials == record.partials
                    && old.signed_transaction_hex == record.signed_transaction_hex;
                if same {
                    (
                        old,
                        active.capability,
                        if active.state == record.state {
                            active.checkpoint
                        } else {
                            None
                        },
                    )
                } else {
                    let cap = old.successor(active.capability, record)?;
                    let hash = batch.capability(
                        &cap,
                        &candidate.manifest,
                        candidate.payments.change_next,
                        limits,
                    )?;
                    (cap, hash, None)
                }
            } else {
                if !unique.insert(id) {
                    return Err(Error::JournalCorrupt);
                }
                if journal
                    .staged_get(
                        &batch,
                        &root.descriptor.snapshot(Kind::Aliases),
                        &Key::id(id),
                        &mut budget,
                    )?
                    .is_some()
                    || journal
                        .staged_get(
                            &batch,
                            &root.descriptor.snapshot(Kind::Lineages),
                            &Key::id(id),
                            &mut budget,
                        )?
                        .is_some()
                {
                    return Err(Error::JournalCorrupt);
                }
                let cap = Capability::initial(root.descriptor.journal_id, record)?;
                let hash = batch.capability(
                    &cap,
                    &candidate.manifest,
                    candidate.payments.change_next,
                    limits,
                )?;
                for point in record.proposal.points()? {
                    let key = Key::reservation(point, record.proposal.expiry()?, id);
                    root.descriptor.insert(
                        &mut journal,
                        &mut batch,
                        Kind::Reservations,
                        key.clone(),
                        Value::Reservation,
                        &mut budget,
                    )?;
                    expected.push((Kind::Reservations, key, Value::Reservation));
                }
                (cap, hash, None)
            };
            if let Some(Value::Alias { lineage_id, .. }) = journal.staged_get(
                &batch,
                &root.descriptor.snapshot(Kind::Aliases),
                &Key::id(id),
                &mut budget,
            )? {
                if lineage_id != cap.lineage_id {
                    return Err(Error::JournalCorrupt);
                }
            }
            for (kind, key, value) in [
                (
                    Kind::Lineages,
                    Key::id(cap.lineage_id),
                    Value::Lineage {
                        capability: hash,
                        location: Location::Active,
                        proposal_id: id,
                        revision: cap.revision,
                    },
                ),
                (
                    Kind::Aliases,
                    Key::id(id),
                    Value::Alias {
                        capability: hash,
                        lineage_id: cap.lineage_id,
                        revision: cap.revision,
                    },
                ),
            ] {
                root.descriptor.insert(
                    &mut journal,
                    &mut batch,
                    kind,
                    key.clone(),
                    value.clone(),
                    &mut budget,
                )?;
                expected.push((kind, key, value));
            }
            let active = Active {
                capability: hash,
                checkpoint,
                lineage_id: cap.lineage_id,
                state: record.state,
            };
            if index < root.active.len() {
                root.active[index] = active;
            } else {
                root.active.push(active);
            }
            // Independent of the insertion loop: each capability must have all
            // its original reservation keys in the complete prospective root.
            validate_active(
                &mut journal,
                Some(&batch),
                &root.descriptor,
                &root.active[index],
                &cap,
                &mut budget,
            )?;
        }
        for (kind, key, value) in expected {
            if journal.staged_get(&batch, &root.descriptor.snapshot(kind), &key, &mut budget)?
                != Some(value)
            {
                return Err(Error::JournalCorrupt);
            }
        }
        root.descriptor.generation = root
            .descriptor
            .generation
            .checked_add(1)
            .ok_or(Error::JournalLimit)?;
        root.descriptor.validate(root.active.len())?;
        root.archives.clear();
        candidate.journal = Some(root);
        // Root size is checked before publishing even an orphan object.
        encode(candidate)?;
        journal.publish(&batch, |stage| journal_hook(hook, stage))?;
        if migrating {
            journal.save_legacy(|stage| journal_hook(hook, stage))?;
        }
        Ok(())
    }
}

fn journal_hook(
    hook: &mut impl FnMut(StateStage) -> Result<(), Error>,
    stage: journal::Stage,
) -> Result<(), journal::Error> {
    hook(StateStage::Journal(stage)).map_err(|error| match error {
        Error::Storage(error) => journal::Error::Storage(error),
        _ => journal::Error::Corrupt,
    })
}
