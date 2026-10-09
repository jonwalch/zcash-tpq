//! One atomic root binds the bounded active book to immutable journal objects.
//! V2 remains readable; the first archive/capacity transition migrates under the
//! allocator lock. No observation or archive operation deletes a reservation.
use super::*;
use crate::journal;
use crate::{
    journal::{
        Batch, Capability, Entry, Journal, Key, Kind, Limits, Location, ReadBudget, Reference,
        Snapshot, Value,
    },
    manifest::bounded,
    payment::{PaymentState, MAX_PAYMENTS},
    Outpoint,
};
mod commit;
mod history;
mod snapshot;
pub use history::{
    PaymentDetails, PaymentHistoryEntry, PaymentHistoryPage, PaymentLocation, PaymentObservation,
};
pub(crate) use snapshot::{JournalSnapshot, JournalSnapshotMetadata};

use rand_core::{OsRng, RngCore};
use serde::Deserializer;
use std::collections::BTreeSet;

pub(super) const MAX_V3: usize = MAX_STATE + 16 * 1024;
const FORMAT: &str = "ZcashTransparentPQ/watch-state/v3";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Active {
    pub capability: Hex<32>,
    pub checkpoint: Option<Checkpoint>,
    pub lineage_id: Hex<32>,
    pub state: PaymentState,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Descriptor {
    aliases: Option<Reference>,
    generation: u64,
    history: Option<Reference>,
    journal_id: Hex<16>,
    lineages: Option<Reference>,
    next_event: u64,
    quota: u64,
    reservations: Option<Reference>,
}
impl Descriptor {
    fn new() -> Result<Self, Error> {
        let mut id = [0; 16];
        OsRng.try_fill_bytes(&mut id).map_err(|_| Error::Entropy)?;
        Ok(Self {
            aliases: None,
            generation: 0,
            history: None,
            journal_id: Hex(id),
            lineages: None,
            next_event: 0,
            quota: Limits::default().bytes,
            reservations: None,
        })
    }
    fn limits(&self) -> Limits {
        Limits {
            bytes: self.quota,
            ..Limits::default()
        }
    }
    fn snapshot(&self, kind: Kind) -> Snapshot {
        Snapshot {
            generation: self.generation,
            journal_id: self.journal_id,
            kind,
            root: match kind {
                Kind::Aliases => &self.aliases,
                Kind::History => &self.history,
                Kind::Lineages => &self.lineages,
                Kind::Reservations => &self.reservations,
            }
            .clone(),
        }
    }
    fn insert(
        &mut self,
        journal: &mut Journal<'_>,
        batch: &mut Batch,
        kind: Kind,
        key: Key,
        value: Value,
        budget: &mut ReadBudget,
    ) -> Result<(), Error> {
        if journal.staged_get(batch, &self.snapshot(kind), &key, budget)? == Some(value.clone()) {
            return Ok(());
        }
        let root = journal
            .insert(batch, &self.snapshot(kind), Entry { key, value }, budget)?
            .root;
        match kind {
            Kind::Aliases => self.aliases = root,
            Kind::History => self.history = root,
            Kind::Lineages => self.lineages = root,
            Kind::Reservations => self.reservations = root,
        }
        Ok(())
    }
    fn validate(&self, active: usize) -> Result<(), Error> {
        canonical::encode(self, 4096)?;
        let count = |root: &Option<Reference>| root.as_ref().map_or(0, |r| r.count);
        let n = count(&self.lineages);
        if self.quota == 0
            || self.quota > 8 * 1024 * 1024 * 1024
            || active as u64 > n
            || count(&self.aliases) < n
            || count(&self.reservations) < n
            || count(&self.reservations) > n.checked_mul(15).ok_or(Error::JournalCorrupt)?
            || count(&self.history) != self.next_event
        {
            return Err(Error::JournalCorrupt);
        }
        for kind in [
            Kind::Aliases,
            Kind::History,
            Kind::Lineages,
            Kind::Reservations,
        ] {
            if let Some(root) = self.snapshot(kind).root {
                root.validate(kind)?;
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Root {
    pub active: Vec<Active>,
    descriptor: Descriptor,
    /// Only populated after a fresh, stable trusted reconciliation.
    pub archives: Vec<Active>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payments {
    #[serde(deserialize_with = "active")]
    active: Vec<Active>,
    change_next: u64,
    journal: Descriptor,
}
fn active<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Active>, D::Error> {
    bounded::<D, Active, MAX_PAYMENTS>(d)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskState {
    format: String,
    manifest: Manifest,
    mode: WatchMode,
    payments: Payments,
    receive_next: u64,
    scan: Scan,
}

pub(crate) struct Resolved {
    pub capability: Capability,
    pub hash: Hex<32>,
    pub location: Location,
    pub current_id: Hex<32>,
}

impl WatchStore {
    /// Preserve an exact durable legacy recovery copy, then atomically publish
    /// v3. No signatures or observations are invented by migration.
    pub fn migrate_payment_journal(&mut self) -> Result<(), Error> {
        self.migrate_journal_with_hook(|_| Ok(()))
    }
    pub(crate) fn migrate_journal_with_hook(
        &mut self,
        hook: impl FnMut(StateStage) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.ready()?;
        if self.state.journal.is_some() {
            return Ok(());
        }
        let mut candidate = self.state.clone();
        candidate.journal = Some(Root {
            active: vec![],
            descriptor: Descriptor::new()?,
            archives: vec![],
        });
        self.commit_with_hook(candidate, hook)
    }

    pub(super) fn load_v3(&mut self) -> Result<(), Error> {
        let root = self.state.journal.clone().ok_or(Error::JournalCorrupt)?;
        root.descriptor.validate(root.active.len())?;
        let manifest = self.state.manifest.clone();
        let change_next = self.state.payments.change_next;
        let mut journal =
            Journal::resume(self, root.descriptor.journal_id, root.descriptor.limits())?;
        let mut budget = ReadBudget::new(4096)?;
        // Read every root even when there are no active payments. Missing
        // non-null roots are corruption, never an empty archive.
        for kind in [
            Kind::Aliases,
            Kind::History,
            Kind::Lineages,
            Kind::Reservations,
        ] {
            let snapshot = root.descriptor.snapshot(kind);
            if let Some(reference) = &snapshot.root {
                journal.get(&snapshot, &reference.min, &mut budget)?;
            }
        }
        let mut records = Vec::new();
        let mut ids = BTreeSet::new();
        for active in &root.active {
            if !ids.insert(active.lineage_id) {
                return Err(Error::JournalCorrupt);
            }
            let cap = journal.capability(active.capability, &manifest, change_next)?;
            validate_active(
                &mut journal,
                None,
                &root.descriptor,
                active,
                &cap,
                &mut budget,
            )?;
            records.push(cap.record(active.state));
        }
        drop(journal);
        self.state.payments.records = records;
        self.state.validate()
    }

    pub(crate) fn resolve_payment(
        &mut self,
        id: Hex<32>,
        budget: &mut ReadBudget,
    ) -> Result<Option<Resolved>, Error> {
        self.ready()?;
        let result = self.resolve_payment_inner(id, budget);
        if matches!(result, Err(Error::JournalCorrupt)) {
            self.poison();
        }
        result
    }
    fn resolve_payment_inner(
        &mut self,
        id: Hex<32>,
        budget: &mut ReadBudget,
    ) -> Result<Option<Resolved>, Error> {
        let Some(root) = self.state.journal.clone() else {
            return Ok(None);
        };
        let manifest = self.state.manifest.clone();
        let change_next = self.state.payments.change_next;
        let mut journal =
            Journal::resume(self, root.descriptor.journal_id, root.descriptor.limits())?;
        let Some(Value::Alias {
            capability: hash,
            lineage_id,
            revision,
        }) = journal.get(
            &root.descriptor.snapshot(Kind::Aliases),
            &Key::id(id),
            budget,
        )?
        else {
            return Ok(None);
        };
        let capability = journal.capability(hash, &manifest, change_next)?;
        if capability.lineage_id != lineage_id
            || capability.revision != revision
            || capability.proposal.id()? != id
        {
            return Err(Error::JournalCorrupt);
        }
        let Some(Value::Lineage {
            capability: latest_hash,
            location,
            proposal_id: current_id,
            revision: latest_revision,
        }) = journal.get(
            &root.descriptor.snapshot(Kind::Lineages),
            &Key::id(lineage_id),
            budget,
        )?
        else {
            return Err(Error::JournalCorrupt);
        };
        if latest_revision < revision
            || (current_id == id && (latest_hash != hash || latest_revision != revision))
        {
            return Err(Error::JournalCorrupt);
        }
        let active = root.active.iter().find(|a| a.lineage_id == lineage_id);
        if match location {
            Location::Active => active.is_none_or(|a| a.capability != latest_hash),
            Location::Archived => active.is_some(),
        } {
            return Err(Error::JournalCorrupt);
        }
        if journal.get(
            &root.descriptor.snapshot(Kind::Aliases),
            &Key::id(current_id),
            budget,
        )? != Some(Value::Alias {
            capability: latest_hash,
            lineage_id,
            revision: latest_revision,
        }) {
            return Err(Error::JournalCorrupt);
        }
        Ok(Some(Resolved {
            capability,
            hash,
            location,
            current_id,
        }))
    }

    pub(crate) fn payment_gate(
        &mut self,
        id: Hex<32>,
        budget: &mut ReadBudget,
    ) -> Result<(), Error> {
        if let Some(found) = self.resolve_payment(id, budget)? {
            if found.current_id != id {
                return Err(Error::SupersededPayment {
                    current: found.current_id,
                });
            }
            if found.location == Location::Archived {
                return Err(Error::ArchivedPayment);
            }
        }
        Ok(())
    }

    pub(crate) fn journal_reserved(
        &mut self,
        point: Outpoint,
        next: u32,
        except: Option<Hex<32>>,
        budget: &mut ReadBudget,
    ) -> Result<bool, Error> {
        self.ready()?;
        let result = self.journal_reserved_inner(point, next, except, budget);
        if matches!(result, Err(Error::JournalCorrupt)) {
            self.poison();
        }
        result
    }
    fn journal_reserved_inner(
        &mut self,
        point: Outpoint,
        next: u32,
        except: Option<Hex<32>>,
        budget: &mut ReadBudget,
    ) -> Result<bool, Error> {
        let root = self.state.journal.clone().ok_or(Error::JournalCorrupt)?;
        let manifest = self.state.manifest.clone();
        let change_next = self.state.payments.change_next;
        let mut journal =
            Journal::resume(self, root.descriptor.journal_id, root.descriptor.limits())?;
        let (entries, _) = journal.page(
            &root.descriptor.snapshot(Kind::Reservations),
            Some(&Key::reservation(point, u32::MAX, Hex([0; 32]))),
            None,
            2,
            budget,
        )?;
        let mut previous = None;
        let mut reserved = false;
        for entry in entries {
            let (found, expiry, lineage) = entry.key.reservation_parts()?;
            if found != point {
                break;
            }
            if previous == Some(lineage) || entry.value != Value::Reservation {
                return Err(Error::JournalCorrupt);
            }
            previous = Some(lineage);
            let Some(Value::Lineage {
                capability,
                proposal_id,
                revision,
                ..
            }) = journal.get(
                &root.descriptor.snapshot(Kind::Lineages),
                &Key::id(lineage),
                budget,
            )?
            else {
                return Err(Error::JournalCorrupt);
            };
            let cap = journal.capability(capability, &manifest, change_next)?;
            if cap.lineage_id != lineage
                || cap.revision != revision
                || cap.proposal.id()? != proposal_id
                || cap.proposal.expiry()? != expiry
                || !cap.proposal.points()?.contains(&point)
            {
                return Err(Error::JournalCorrupt);
            }
            reserved |= Some(lineage) != except && expiry >= next;
        }
        Ok(reserved)
    }
}

fn validate_active(
    journal: &mut Journal<'_>,
    batch: Option<&Batch>,
    descriptor: &Descriptor,
    active: &Active,
    cap: &Capability,
    budget: &mut ReadBudget,
) -> Result<(), Error> {
    if cap.lineage_id != active.lineage_id {
        return Err(Error::JournalCorrupt);
    }
    let id = cap.proposal.id()?;
    let mut required = vec![
        (
            Kind::Aliases,
            Key::id(id),
            Value::Alias {
                capability: active.capability,
                lineage_id: cap.lineage_id,
                revision: cap.revision,
            },
        ),
        (
            Kind::Lineages,
            Key::id(cap.lineage_id),
            Value::Lineage {
                capability: active.capability,
                location: Location::Active,
                proposal_id: id,
                revision: cap.revision,
            },
        ),
    ];
    for point in cap.proposal.points()? {
        required.push((
            Kind::Reservations,
            Key::reservation(point, cap.proposal.expiry()?, cap.lineage_id),
            Value::Reservation,
        ));
    }
    for (kind, key, expected) in required {
        let snapshot = descriptor.snapshot(kind);
        let actual = if let Some(batch) = batch {
            journal.staged_get(batch, &snapshot, &key, budget)?
        } else {
            journal.get(&snapshot, &key, budget)?
        };
        if actual != Some(expected) {
            return Err(Error::JournalCorrupt);
        }
    }
    Ok(())
}

pub(crate) fn inactive(state: PaymentState) -> bool {
    matches!(
        state,
        PaymentState::Confirmed | PaymentState::Conflicted | PaymentState::Expired
    )
}
pub(super) fn decode(bytes: &[u8]) -> Result<State, Error> {
    #[derive(Deserialize)]
    struct Format {
        format: String,
    }
    let format: Format = serde_json::from_slice(bytes).map_err(|_| Error::Encoding)?;
    match format.format.as_str() {
        "ZcashTransparentPQ/watch-state/v1" => {
            canonical::decode::<LegacyState>(bytes, MAX_STATE)?.migrate()
        }
        "ZcashTransparentPQ/watch-state/v2" => canonical::decode(bytes, MAX_STATE),
        FORMAT => {
            let disk: DiskState = canonical::decode(bytes, MAX_V3)?;
            canonical::encode(&disk.payments, 16 * 1024)?;
            Ok(State {
                format: "ZcashTransparentPQ/watch-state/v2".into(),
                manifest: disk.manifest,
                mode: disk.mode,
                payments: crate::payment::Book {
                    change_next: disk.payments.change_next,
                    records: vec![],
                },
                receive_next: disk.receive_next,
                scan: disk.scan,
                journal: Some(Root {
                    active: disk.payments.active,
                    descriptor: disk.payments.journal,
                    archives: vec![],
                }),
            })
        }
        _ => Err(Error::UnsupportedFormat),
    }
}
pub(super) fn encode(state: &State) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let Some(root) = &state.journal else {
        return canonical::encode(state, MAX_STATE);
    };
    let payments = Payments {
        active: root.active.clone(),
        change_next: state.payments.change_next,
        journal: root.descriptor.clone(),
    };
    canonical::encode(&payments, 16 * 1024)?;
    canonical::encode(
        &DiskState {
            format: FORMAT.into(),
            manifest: state.manifest.clone(),
            mode: state.mode,
            payments,
            receive_next: state.receive_next,
            scan: state.scan.clone(),
        },
        MAX_V3,
    )
}
