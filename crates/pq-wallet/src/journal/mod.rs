//! Bounded immutable journal primitives, used by watch-state v3.
//! The caller must validate payment/index deltas before publishing a root.
mod object;
mod store;
mod tree;

pub(crate) use object::{Capability, Entry, Key, Kind, Location, Page, Reference, Value};
pub(crate) use store::Journal;
pub(crate) use store::Stage;
pub(crate) use tree::Snapshot;

use crate::Hex;
use std::{collections::BTreeMap, sync::Arc};

const PAGE_BYTES: usize = 8 * 1024;
const CAPABILITY_BYTES: usize = 1024 * 1024;
const FANOUT: usize = 16;
const MIN_OCCUPANCY: usize = 8;
const MAX_DEPTH: u8 = 8;
const CACHE_PAGES: usize = 128;
const MAX_COMMIT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMMIT_OBJECTS: usize = 4096;
const MAX_OBJECTS: u64 = 131_072;
const MAX_QUOTA: u64 = 8 * 1024 * 1024 * 1024;
const OBJECT_DOMAIN: &[u8] = b"ZcashTransparentPQ/wallet-journal-object/v1\0";
type Hash = Hex<32>;
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("journal object or reference is corrupt")]
    Corrupt,
    #[error("journal storage failed")]
    Storage(#[from] std::io::Error),
    #[error("journal requires reopening")]
    ReopenRequired,
    #[error("journal disk quota exceeded")]
    Quota,
    #[error("journal object count exceeded")]
    ObjectLimit,
    #[error("journal operation limit exceeded")]
    Limit,
    #[error("journal lookup budget exhausted")]
    LookupLimit,
    #[error("journal cursor belongs to a different snapshot")]
    StaleCursor,
    #[error("journal write batch cannot be published")]
    InvalidBatch,
    #[cfg(not(unix))]
    #[error("journal storage requires Unix private-file semantics")]
    Unsupported,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub bytes: u64,
    pub objects: u64,
    pub commit_bytes: u64,
    pub commit_objects: usize,
    pub depth: u8,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 1024 * 1024 * 1024,
            objects: MAX_OBJECTS,
            commit_bytes: MAX_COMMIT_BYTES,
            commit_objects: MAX_COMMIT_OBJECTS,
            depth: MAX_DEPTH,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<()> {
        if self.bytes == 0
            || self.bytes > MAX_QUOTA
            || self.objects == 0
            || self.objects > MAX_OBJECTS
            || self.commit_bytes == 0
            || self.commit_bytes > MAX_COMMIT_BYTES
            || self.commit_objects == 0
            || self.commit_objects > MAX_COMMIT_OBJECTS
            || self.depth == 0
            || self.depth > MAX_DEPTH
        {
            return Err(Error::Limit);
        }
        Ok(())
    }
}

/// Shared across all lookups in one wallet operation; errors also consume I/O.
pub(crate) struct ReadBudget {
    remaining: u32,
    pub reads: u32,
}
impl ReadBudget {
    pub fn new(reads: u32) -> Result<Self> {
        if reads > 4096 {
            return Err(Error::Limit);
        }
        Ok(Self {
            remaining: reads,
            reads: 0,
        })
    }
    fn charge(&mut self) -> Result<()> {
        self.remaining = self.remaining.checked_sub(1).ok_or(Error::LookupLimit)?;
        self.reads += 1;
        Ok(())
    }
}

#[derive(Clone)]
struct Encoded {
    bytes: Arc<[u8]>,
    hash: Hash,
}
impl Encoded {
    fn new(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(OBJECT_DOMAIN);
        hash.update(bytes);
        Self {
            bytes: bytes.into(),
            hash: Hex(hash.finalize().into()),
        }
    }
}

/// All new objects for one prospective root. A failed edit invalidates the batch.
/// Publication makes objects durable, never selects or changes a watch root.
pub(crate) struct Batch {
    journal_id: Hex<16>,
    objects: BTreeMap<Hash, Encoded>,
    bytes: u64,
    invalid: bool,
}
impl Batch {
    pub fn new(journal_id: Hex<16>) -> Self {
        Self {
            journal_id,
            objects: BTreeMap::new(),
            bytes: 0,
            invalid: false,
        }
    }
    fn add(&mut self, object: Encoded, limits: Limits) -> Result<Hash> {
        if let Err(error) = limits.validate() {
            self.invalid = true;
            return Err(error);
        }
        if self.invalid {
            return Err(Error::InvalidBatch);
        }
        if let Some(previous) = self.objects.get(&object.hash) {
            if previous.bytes != object.bytes {
                self.invalid = true;
                return Err(Error::Corrupt);
            }
            return Ok(object.hash);
        }
        let bytes = self
            .bytes
            .checked_add(object.bytes.len() as u64)
            .ok_or(Error::Limit)?;
        if bytes > limits.commit_bytes || self.objects.len() >= limits.commit_objects {
            self.invalid = true;
            return Err(Error::Limit);
        }
        self.bytes = bytes;
        let hash = object.hash;
        self.objects.insert(hash, object);
        Ok(hash)
    }
}

#[cfg(all(test, unix))]
mod tests;

impl From<Error> for crate::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Storage(e) => Self::Storage(e),
            Error::ReopenRequired => Self::ReopenRequired,
            Error::Quota => Self::JournalQuota,
            Error::LookupLimit => Self::JournalLookupLimit,
            Error::ObjectLimit | Error::Limit => Self::JournalLimit,
            #[cfg(not(unix))]
            Error::Unsupported => Self::UnsupportedContext,
            Error::Corrupt | Error::InvalidBatch | Error::StaleCursor => Self::JournalCorrupt,
        }
    }
}
