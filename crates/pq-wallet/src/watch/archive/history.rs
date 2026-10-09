//! Bounded read-only access to saved authorizations and dated archive events.
use super::*;
use crate::payment::{Intent, Partial, Proposal};
use sha2::{Digest, Sha256};

const CURSOR_FORMAT: &str = "ZcashTransparentPQ/payment-history-cursor/v1";
const CURSOR_BYTES: usize = 512;

/// Current placement of a lineage, independent of any past observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentLocation {
    /// Present in the bounded mutable active book.
    Active,
    /// Retained in immutable history; authority and reservations remain.
    Archived,
}

/// A cached observation. An absent checkpoint means it is undated, not current.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PaymentObservation {
    /// Trusted checkpoint dating the cached observation; it does not establish current status.
    pub checkpoint: Option<Checkpoint>,
    /// Cached payment observation; it does not revoke an authorization or reservation.
    pub state: PaymentState,
}

/// An owned saved authorization. Old aliases keep their original envelopes;
/// `current_proposal_id` identifies the latest version of the same lineage.
/// Archived/old versions have no implied current chain observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PaymentDetails {
    /// Content hash of the immutable saved capability, absent in legacy inline state.
    pub capability: Option<Hex<32>>,
    /// Most recent approved proposal ID in this lineage.
    pub current_proposal_id: Hex<32>,
    /// Locally retained independent payment approval.
    pub intent: Intent,
    /// Stable ID of the initial proposal in this lineage.
    pub lineage_id: Option<Hex<32>>,
    /// Current active or archived storage placement.
    pub location: PaymentLocation,
    /// Dated cached chain observation, when available.
    pub observation: Option<PaymentObservation>,
    /// Exact saved local partials; at most one per input.
    pub partials: Vec<Partial>,
    /// Complete canonical proposal with retained effects.
    pub proposal: Proposal,
    /// Monotonic capability revision in this lineage.
    pub revision: Option<u64>,
    /// Exact saved authorization bytes for retry, never silently regenerated.
    pub signed_transaction_hex: Option<String>,
}

/// One archival event. Its state is dated by `checkpoint` and can be reversed
/// by a reorg; it never proves an input is available for another authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PaymentHistoryEntry {
    /// Recipient amount in zatoshis.
    pub amount: u64,
    /// Content hash of the immutable saved capability, absent in legacy inline state.
    pub capability: Hex<32>,
    /// Trusted checkpoint dating the cached observation; it does not establish current status.
    pub checkpoint: Checkpoint,
    /// Stable ID of the initial proposal in this lineage.
    pub lineage_id: Hex<32>,
    /// Digest of the complete canonical proposal.
    pub proposal_id: Hex<32>,
    /// Canonical experimental Regtest receiver.
    pub receiver: String,
    /// Monotonic journal archival event number.
    pub sequence: u64,
    /// Cached payment observation; it does not revoke an authorization or reservation.
    pub state: PaymentState,
}

/// A bounded page of events from one immutable journal snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PaymentHistoryPage {
    /// At most sixteen historical events from the pinned snapshot.
    pub entries: Vec<PaymentHistoryEntry>,
    /// Opaque continuation bound to this exact snapshot, or none at the end.
    pub next_cursor: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCursor {
    format: String,
    next_sequence: u64,
    snapshot: Hex<32>,
}
impl HistoryCursor {
    fn decode(text: &str) -> Result<Self, Error> {
        if text.len() > CURSOR_BYTES * 2 {
            return Err(Error::Limits);
        }
        if !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Encoding);
        }
        let bytes = hex::decode(text).map_err(|_| Error::Encoding)?;
        let value: Self = canonical::decode(&bytes, CURSOR_BYTES)?;
        if value.format != CURSOR_FORMAT {
            return Err(Error::Encoding);
        }
        Ok(value)
    }
    fn encode(next_sequence: u64, snapshot: Hex<32>) -> Result<String, Error> {
        Ok(hex::encode(&*canonical::encode(
            &Self {
                format: CURSOR_FORMAT.into(),
                next_sequence,
                snapshot,
            },
            CURSOR_BYTES,
        )?))
    }
}

impl Descriptor {
    fn fingerprint(&self) -> Result<Hex<32>, Error> {
        let mut hash = Sha256::new();
        hash.update(b"ZcashTransparentPQ/payment-journal-snapshot/v1\0");
        hash.update(&*canonical::encode(self, 4096)?);
        Ok(Hex(hash.finalize().into()))
    }
}

impl WatchStore {
    /// Read one exact saved proposal ID without synchronization, migration,
    /// signing or changing active placement. Unknown IDs return `None`.
    pub fn payment_record(&mut self, id: Hex<32>) -> Result<Option<PaymentDetails>, Error> {
        self.ready()?;
        if self.state.journal.is_none() {
            for record in &self.state.payments.records {
                if record.proposal.id()? == id {
                    return Ok(Some(PaymentDetails {
                        capability: None,
                        current_proposal_id: id,
                        intent: record.intent.clone(),
                        lineage_id: None,
                        location: PaymentLocation::Active,
                        observation: Some(PaymentObservation {
                            checkpoint: None,
                            state: record.state,
                        }),
                        partials: record.partials.clone(),
                        proposal: record.proposal.clone(),
                        revision: None,
                        signed_transaction_hex: record.signed_transaction_hex.clone(),
                    }));
                }
            }
            return Ok(None);
        }
        let Some(found) = self.resolve_payment(id, &mut ReadBudget::new(4096)?)? else {
            return Ok(None);
        };
        let observation = self.state.journal.as_ref().and_then(|root| {
            root.active
                .iter()
                .find(|a| a.capability == found.hash)
                .map(|a| PaymentObservation {
                    checkpoint: a.checkpoint,
                    state: a.state,
                })
        });
        let cap = found.capability;
        Ok(Some(PaymentDetails {
            capability: Some(found.hash),
            current_proposal_id: found.current_id,
            intent: cap.intent,
            lineage_id: Some(cap.lineage_id),
            location: match found.location {
                Location::Active => PaymentLocation::Active,
                Location::Archived => PaymentLocation::Archived,
            },
            observation,
            partials: cap.partials,
            proposal: cap.proposal,
            revision: Some(cap.revision),
            signed_transaction_hex: cap.signed_transaction_hex,
        }))
    }

    /// Return 1..=16 dated archive events per request. The opaque continuation
    /// is valid only for this exact journal root/generation. It is a paging
    /// position, not an integrity certificate or chain authority.
    pub fn payment_history(
        &mut self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<PaymentHistoryPage, Error> {
        self.ready()?;
        let result = self.payment_history_inner(limit, cursor);
        if matches!(result, Err(Error::JournalCorrupt)) {
            self.poison();
        }
        result
    }
    fn payment_history_inner(
        &mut self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<PaymentHistoryPage, Error> {
        if !(1..=16).contains(&limit) {
            return Err(Error::Limits);
        }
        let cursor = cursor.map(HistoryCursor::decode).transpose()?;
        let Some(root) = self.state.journal.clone() else {
            if cursor.is_some() {
                return Err(Error::StaleJournalCursor);
            }
            return Ok(PaymentHistoryPage {
                entries: vec![],
                next_cursor: None,
            });
        };
        let fingerprint = root.descriptor.fingerprint()?;
        if cursor.as_ref().is_some_and(|c| c.snapshot != fingerprint) {
            return Err(Error::StaleJournalCursor);
        }
        let first = cursor.map_or(0, |c| c.next_sequence);
        if first > root.descriptor.next_event {
            return Err(Error::Encoding);
        }
        let count = (root.descriptor.next_event - first).min(limit as u64) as usize;
        if count == 0 {
            return Ok(PaymentHistoryPage {
                entries: vec![],
                next_cursor: None,
            });
        }
        let manifest = self.state.manifest.clone();
        let change_next = self.state.payments.change_next;
        let mut journal =
            Journal::resume(self, root.descriptor.journal_id, root.descriptor.limits())?;
        let mut budget = ReadBudget::new(4096)?;
        let (entries, _) = journal.page(
            &root.descriptor.snapshot(Kind::History),
            Some(&Key::sequence(first)),
            None,
            count,
            &mut budget,
        )?;
        if entries.len() != count {
            return Err(Error::JournalCorrupt);
        }
        let mut rows = Vec::with_capacity(count);
        for (offset, entry) in entries.into_iter().enumerate() {
            let sequence = first + offset as u64;
            let Value::History {
                capability,
                checkpoint,
                lineage_id,
                proposal_id,
                state,
            } = entry.value
            else {
                return Err(Error::JournalCorrupt);
            };
            let cap = journal.capability(capability, &manifest, change_next)?;
            if entry.key != Key::sequence(sequence)
                || cap.lineage_id != lineage_id
                || cap.proposal.id()? != proposal_id
            {
                return Err(Error::JournalCorrupt);
            }
            // Check indexed identities/revisions without claiming to audit an
            // arbitrarily long predecessor chain in one bounded history page.
            let Some(Value::Alias {
                capability: alias_hash,
                lineage_id: alias_lineage,
                revision: alias_revision,
            }) = journal.get(
                &root.descriptor.snapshot(Kind::Aliases),
                &Key::id(proposal_id),
                &mut budget,
            )?
            else {
                return Err(Error::JournalCorrupt);
            };
            let Some(Value::Lineage {
                capability: latest_hash,
                location,
                proposal_id: current_id,
                revision,
            }) = journal.get(
                &root.descriptor.snapshot(Kind::Lineages),
                &Key::id(lineage_id),
                &mut budget,
            )?
            else {
                return Err(Error::JournalCorrupt);
            };
            if alias_lineage != lineage_id
                || alias_revision < cap.revision
                || revision < alias_revision
                || (alias_revision == cap.revision && alias_hash != capability)
                || (revision == alias_revision
                    && (latest_hash != alias_hash || current_id != proposal_id))
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
                &mut budget,
            )? != Some(Value::Alias {
                capability: latest_hash,
                lineage_id,
                revision,
            }) {
                return Err(Error::JournalCorrupt);
            }
            rows.push(PaymentHistoryEntry {
                amount: cap.intent.amount,
                capability,
                checkpoint,
                lineage_id,
                proposal_id,
                receiver: cap.intent.receiver,
                sequence,
                state,
            });
        }
        let next = first + count as u64;
        Ok(PaymentHistoryPage {
            entries: rows,
            next_cursor: (next < root.descriptor.next_event)
                .then(|| HistoryCursor::encode(next, fingerprint))
                .transpose()?,
        })
    }

    /// Export a single saved authorization to a NEW private directory. The
    /// parent/ancestors must be trusted, stable and outside the watch store.
    /// Partial output errors may
    /// leave files behind, but never change or poison the payment journal.
    pub fn export_payment_history(&mut self, id: Hex<32>, directory: &Path) -> Result<(), Error> {
        self.export_payment_with_hook(id, directory, |_| Ok(()))
    }
    #[cfg(unix)]
    pub(crate) fn export_payment_with_hook(
        &mut self,
        id: Hex<32>,
        directory: &Path,
        mut hook: impl FnMut(&Path) -> Result<(), Error>,
    ) -> Result<(), Error> {
        use std::os::unix::fs::DirBuilderExt;
        let record = self.payment_record(id)?.ok_or(Error::ProposalMismatch)?;
        let metadata = canonical::encode(&record, crate::manifest::MAX_PLAINTEXT)?;
        let proposal = record.proposal.to_json()?;
        if directory.file_name().is_none() {
            return Err(Error::Encoding);
        }
        let parent = directory
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // An export must not add directories/files to the source journal's
        // object inventory. Resolve trusted stable ancestors to catch aliases.
        if parent
            .canonicalize()
            .map_err(Error::Storage)?
            .starts_with(self.path.canonicalize().map_err(Error::Storage)?)
        {
            return Err(Error::Encoding);
        }
        let parent_handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(parent)
            .map_err(Error::Storage)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .map_err(Error::Storage)?;
        let mut write = |name: &str, bytes: &[u8]| {
            let path = directory.join(name);
            hook(&path)?;
            write_transfer(&path, bytes)
        };
        write("payment.json", &metadata)?;
        write("proposal.json", &proposal)?;
        for partial in &record.partials {
            write(
                &format!(
                    "input-{:04}-signer-{:02}.json",
                    partial.input_index, partial.signer_index
                ),
                &partial.to_json()?,
            )?;
        }
        if let Some(signed) = &record.signed_transaction_hex {
            write("signed-transaction.hex", signed.as_bytes())?;
        }
        // A completion marker is published last, after all data files have
        // been synced. It contains metadata, not permission to submit/sign.
        write(
            "complete.json",
            b"{\"format\":\"ZcashTransparentPQ/payment-export/v1\"}",
        )?;
        parent_handle.sync_all().map_err(Error::Storage)
    }
    #[cfg(not(unix))]
    pub(crate) fn export_payment_with_hook(
        &mut self,
        _id: Hex<32>,
        _directory: &Path,
        _hook: impl FnMut(&Path) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Err(Error::UnsupportedContext)
    }
}
