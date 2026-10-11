//! Bounded, confirmed-input Regtest payments. A proposal never supplies trusted
//! UTXOs or proves that another signer approved its metadata.
mod approval;
mod change;
mod proposal;
mod review;
mod store;

pub use change::{ChangeAdvancement, ChangeReview};
pub use proposal::{InputRecord, OutputRecord, Partial, Proposal};
pub use review::{Intent, Remainder, Review};
pub(crate) use store::Book;
pub use store::{PaymentRecord, PaymentState};

use crate::{ChainSource, Checkpoint, Error, Hex, Outpoint};
use zakura_chain::transparent::Output;

/// Wallet-local limits, independent of node consensus/resource limits.
pub const MAX_TRANSACTION: usize = 262_144;
/// Maximum canonical proposal bytes.
pub const MAX_PROPOSAL: usize = 256 * 1024;
/// Maximum canonical single-partial transfer bytes.
pub const MAX_PARTIAL: usize = 16 * 1024;
/// Maximum transparent inputs per payment.
pub const MAX_INPUTS: usize = 15;
/// Maximum simultaneously active payment records.
pub const MAX_PAYMENTS: usize = 32;
/// Maximum expiry distance from the signer's trusted tip at approval.
/// Coordinated payments also use this distance when first prepared.
pub const EXPIRY_BLOCKS: u32 = 20;
/// Pinned SLH relay floor: 3 * floor(100 * (44 + 7966) / 1000).
pub const DUST: u64 = 2_403;

/// Trusted node resolution at one explicitly identified tip. The amount and
/// script must come from canonical chain data, never proposal hints.
#[derive(Clone, Debug)]
pub struct ResolvedInput {
    /// Output resolved from authenticated canonical chain data.
    pub output: Output,
    /// Block height creating the output.
    pub height: u32,
    /// Whether the output was created by a coinbase transaction.
    pub coinbase: bool,
    /// Trusted checkpoint to which this observation or approval is bound.
    pub tip: Checkpoint,
}

/// A transaction currently known to the trusted node. None means mempool;
/// confirmed transactions identify their current active-chain block.
#[derive(Clone, Debug)]
pub struct LocatedTransaction {
    /// Exact serialized transaction bytes.
    pub bytes: Vec<u8>,
    /// Active-chain confirmation checkpoint, or none for a mempool observation.
    pub block: Option<Checkpoint>,
}

/// The operator authenticates this full node and its PQ rule profile. A network
/// or history failure is an error, never a missing/unspent transaction.
pub trait PaymentSource: ChainSource {
    /// Include mempool spends, but return only confirmed output creations.
    fn resolve(&mut self, outpoint: Outpoint) -> Result<Option<ResolvedInput>, Error>;
    /// Resolve exact saved transaction bytes and current chain placement.
    fn transaction(&mut self, txid: Hex<32>) -> Result<Option<LocatedTransaction>, Error>;
    /// Submit exact previously persisted bytes; an error may leave the outcome unknown.
    fn submit(&mut self, transaction: &[u8]) -> Result<Hex<32>, Error>;
}

#[cfg(all(test, unix))]
mod tests;
