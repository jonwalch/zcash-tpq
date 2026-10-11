use super::*;
use crate::{
    canonical,
    manifest::bounded,
    payment::{Book, Intent, Partial, PaymentRecord, PaymentState, Proposal, MAX_INPUTS},
    Checkpoint, Manifest, Outpoint,
};
use serde::{Deserialize, Deserializer, Serialize};

const PAGE_FORMAT: &str = "ZcashTransparentPQ/journal-page/v1";
const CAPABILITY_FORMAT: &str = "ZcashTransparentPQ/journal-capability/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Lineages,
    Aliases,
    Reservations,
    History,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Key(pub String);
impl Key {
    pub fn id(id: Hex<32>) -> Self {
        Self(hex::encode(id.0))
    }
    pub fn sequence(sequence: u64) -> Self {
        Self(hex::encode(sequence.to_be_bytes()))
    }
    pub fn reservation(point: Outpoint, expiry: u32, lineage: Hex<32>) -> Self {
        let mut bytes = [0; 72];
        bytes[..32].copy_from_slice(&point.txid.0);
        bytes[32..36].copy_from_slice(&point.index.to_be_bytes());
        bytes[36..40].copy_from_slice(&(u32::MAX - expiry).to_be_bytes());
        bytes[40..].copy_from_slice(&lineage.0);
        Self(hex::encode(bytes))
    }
    pub fn reservation_parts(&self) -> Result<(Outpoint, u32, Hex<32>)> {
        self.validate(Kind::Reservations)?;
        let bytes = hex::decode(&self.0).map_err(|_| Error::Corrupt)?;
        Ok((
            Outpoint {
                txid: Hex(bytes[..32].try_into().map_err(|_| Error::Corrupt)?),
                index: u32::from_be_bytes(bytes[32..36].try_into().map_err(|_| Error::Corrupt)?),
            },
            u32::MAX - u32::from_be_bytes(bytes[36..40].try_into().map_err(|_| Error::Corrupt)?),
            Hex(bytes[40..].try_into().map_err(|_| Error::Corrupt)?),
        ))
    }
    pub(super) fn validate(&self, kind: Kind) -> Result<()> {
        let len = match kind {
            Kind::Lineages | Kind::Aliases => 64,
            Kind::Reservations => 144,
            Kind::History => 16,
        };
        if self.0.len() != len
            || !self
                .0
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Location {
    Active,
    Archived,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Value {
    Alias {
        capability: Hash,
        lineage_id: Hex<32>,
        revision: u64,
    },
    History {
        capability: Hash,
        checkpoint: Checkpoint,
        lineage_id: Hex<32>,
        proposal_id: Hex<32>,
        state: PaymentState,
    },
    Lineage {
        capability: Hash,
        location: Location,
        proposal_id: Hex<32>,
        revision: u64,
    },
    Reservation,
}
impl Value {
    fn kind(&self) -> Kind {
        match self {
            Self::Alias { .. } => Kind::Aliases,
            Self::History { .. } => Kind::History,
            Self::Lineage { .. } => Kind::Lineages,
            Self::Reservation => Kind::Reservations,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    pub key: Key,
    pub value: Value,
}
impl Entry {
    pub fn validate(&self, kind: Kind) -> Result<()> {
        self.key.validate(kind)?;
        if self.value.kind() != kind {
            return Err(Error::Corrupt);
        }
        if let Value::History { state, .. } = self.value {
            if !matches!(
                state,
                PaymentState::Confirmed | PaymentState::Conflicted | PaymentState::Expired
            ) {
                return Err(Error::Corrupt);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reference {
    pub count: u64,
    pub hash: Hash,
    pub level: u8,
    pub max: Key,
    pub min: Key,
}
impl Reference {
    pub fn validate(&self, kind: Kind) -> Result<()> {
        self.min.validate(kind)?;
        self.max.validate(kind)?;
        if self.count == 0 || self.level >= MAX_DEPTH || self.min > self.max {
            return Err(Error::Corrupt);
        }
        if self.count > (FANOUT as u64).pow(u32::from(self.level) + 1) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Page {
    #[serde(deserialize_with = "children")]
    pub children: Vec<Reference>,
    pub format: String,
    pub journal_id: Hex<16>,
    pub kind: Kind,
    pub level: u8,
    #[serde(deserialize_with = "entries")]
    pub records: Vec<Entry>,
}
fn children<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<Reference>, D::Error> {
    bounded::<D, Reference, FANOUT>(d)
}
fn entries<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<Entry>, D::Error> {
    bounded::<D, Entry, FANOUT>(d)
}
impl Page {
    pub fn leaf(journal_id: Hex<16>, kind: Kind, records: Vec<Entry>) -> Self {
        Self {
            children: vec![],
            format: PAGE_FORMAT.into(),
            journal_id,
            kind,
            level: 0,
            records,
        }
    }
    pub fn branch(journal_id: Hex<16>, kind: Kind, level: u8, children: Vec<Reference>) -> Self {
        Self {
            children,
            format: PAGE_FORMAT.into(),
            journal_id,
            kind,
            level,
            records: vec![],
        }
    }
    pub fn validate(&self, root: bool) -> Result<()> {
        if self.format != PAGE_FORMAT || self.level >= MAX_DEPTH {
            return Err(Error::Corrupt);
        }
        let n = if self.level == 0 {
            if !self.children.is_empty() {
                return Err(Error::Corrupt);
            }
            for entry in &self.records {
                entry.validate(self.kind)?;
            }
            if self.records.windows(2).any(|v| v[0].key >= v[1].key) {
                return Err(Error::Corrupt);
            }
            self.records.len()
        } else {
            if !self.records.is_empty() || self.children.len() < 2 {
                return Err(Error::Corrupt);
            }
            for child in &self.children {
                child.validate(self.kind)?;
                if child.level + 1 != self.level {
                    return Err(Error::Corrupt);
                }
            }
            if self.children.windows(2).any(|v| v[0].max >= v[1].min) {
                return Err(Error::Corrupt);
            }
            self.count()?;
            self.children.len()
        };
        if n == 0 || n > FANOUT || (!root && n < MIN_OCCUPANCY) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn count(&self) -> Result<u64> {
        if self.level == 0 {
            return Ok(self.records.len() as u64);
        }
        self.children.iter().try_fold(0u64, |n, child| {
            n.checked_add(child.count).ok_or(Error::Corrupt)
        })
    }
    pub fn reference(&self) -> Result<Reference> {
        let encoded = self.encode()?;
        let (min, max) = if self.level == 0 {
            (
                self.records.first().ok_or(Error::Corrupt)?.key.clone(),
                self.records.last().ok_or(Error::Corrupt)?.key.clone(),
            )
        } else {
            (
                self.children.first().ok_or(Error::Corrupt)?.min.clone(),
                self.children.last().ok_or(Error::Corrupt)?.max.clone(),
            )
        };
        Ok(Reference {
            count: self.count()?,
            hash: encoded.hash,
            level: self.level,
            max,
            min,
        })
    }
    pub(super) fn encode(&self) -> Result<Encoded> {
        self.validate(true)?;
        let bytes = canonical::encode(self, PAGE_BYTES).map_err(|_| Error::Limit)?;
        Ok(Encoded::new(&bytes))
    }
    pub fn decode(bytes: &[u8], journal_id: Hex<16>, kind: Kind) -> Result<Self> {
        let page: Self = canonical::decode(bytes, PAGE_BYTES).map_err(|_| Error::Corrupt)?;
        page.validate(true)?;
        if page.journal_id != journal_id || page.kind != kind {
            return Err(Error::Corrupt);
        }
        Ok(page)
    }
}

/// Structural validation preserves the existing book rules. This never supplies
/// trusted UTXOs or grants permission to sign/export a new authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Capability {
    pub format: String,
    pub intent: Intent,
    pub journal_id: Hex<16>,
    pub lineage_id: Hex<32>,
    #[serde(deserialize_with = "partials")]
    pub partials: Vec<Partial>,
    pub previous: Option<Hash>,
    pub proposal: Proposal,
    pub revision: u64,
    pub signed_transaction_hex: Option<String>,
}
fn partials<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<Partial>, D::Error> {
    bounded::<D, Partial, MAX_INPUTS>(d)
}
impl Capability {
    pub fn initial(journal_id: Hex<16>, record: &PaymentRecord) -> Result<Self> {
        Ok(Self {
            format: CAPABILITY_FORMAT.into(),
            intent: record.intent.clone(),
            journal_id,
            lineage_id: record.proposal.id().map_err(|_| Error::Corrupt)?,
            partials: record.partials.clone(),
            previous: None,
            proposal: record.proposal.clone(),
            revision: 0,
            signed_transaction_hex: record.signed_transaction_hex.clone(),
        })
    }
    pub fn record(&self, state: PaymentState) -> PaymentRecord {
        PaymentRecord {
            intent: self.intent.clone(),
            partials: self.partials.clone(),
            proposal: self.proposal.clone(),
            signed_transaction_hex: self.signed_transaction_hex.clone(),
            state,
        }
    }

    /// Only approved tip metadata and added authorization may change. Existing
    /// signatures and effects survive every successor, including a tip rollback.
    pub fn successor(&self, hash: Hash, record: &PaymentRecord) -> Result<Self> {
        let mut expected = self.proposal.clone();
        expected.tip = record.proposal.tip;
        let mut partials = self.partials.clone();
        let id = record.proposal.id().map_err(|_| Error::Corrupt)?;
        for partial in &mut partials {
            partial.proposal_id = id;
        }
        if expected != record.proposal
            || self.intent != record.intent
            || (!partials.is_empty() && partials != record.partials)
            || self
                .signed_transaction_hex
                .as_ref()
                .is_some_and(|raw| Some(raw) != record.signed_transaction_hex.as_ref())
        {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            partials: record.partials.clone(),
            proposal: record.proposal.clone(),
            signed_transaction_hex: record.signed_transaction_hex.clone(),
            previous: Some(hash),
            revision: self.revision.checked_add(1).ok_or(Error::Limit)?,
            ..self.clone()
        })
    }

    fn validate(&self, manifest: &Manifest, change_next: u64) -> Result<()> {
        if self.format != CAPABILITY_FORMAT
            || (self.revision == 0) != self.previous.is_none()
            || (self.revision == 0
                && self.lineage_id != self.proposal.id().map_err(|_| Error::Corrupt)?)
        {
            return Err(Error::Corrupt);
        }
        Book {
            change_next,
            records: vec![PaymentRecord {
                intent: self.intent.clone(),
                partials: self.partials.clone(),
                proposal: self.proposal.clone(),
                signed_transaction_hex: self.signed_transaction_hex.clone(),
                state: PaymentState::Prepared,
            }],
        }
        .validate(manifest)
        .map_err(|_| Error::Corrupt)
    }
    pub fn decode(
        bytes: &[u8],
        journal_id: Hex<16>,
        manifest: &Manifest,
        change_next: u64,
    ) -> Result<Self> {
        let capability: Self =
            canonical::decode(bytes, CAPABILITY_BYTES).map_err(|_| Error::Corrupt)?;
        if capability.journal_id != journal_id {
            return Err(Error::Corrupt);
        }
        capability.validate(manifest, change_next)?;
        Ok(capability)
    }
}

impl Batch {
    pub fn capability(
        &mut self,
        capability: &Capability,
        manifest: &Manifest,
        change_next: u64,
        limits: Limits,
    ) -> Result<Hash> {
        let result = (|| {
            if capability.journal_id != self.journal_id {
                return Err(Error::Corrupt);
            }
            capability.validate(manifest, change_next)?;
            let bytes =
                canonical::encode(capability, CAPABILITY_BYTES).map_err(|_| Error::Limit)?;
            self.add(Encoded::new(&bytes), limits)
        })();
        if result.is_err() {
            self.invalid = true;
        }
        result
    }
    pub(super) fn page(&mut self, page: &Page, limits: Limits) -> Result<Reference> {
        if page.journal_id != self.journal_id {
            return Err(Error::Corrupt);
        }
        let reference = page.reference()?;
        self.add(page.encode()?, limits)?;
        Ok(reference)
    }
}
