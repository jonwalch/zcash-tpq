/// A transaction cannot supply the reviewed transparent authorization digest.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The transaction version and upgrade are not a reviewed signing pair.
    #[error("unsupported transaction version or network upgrade")]
    TransactionVersion,
    /// The backend cannot represent the reviewed consensus branch consistently.
    #[error("the reviewed consensus branch is unavailable or inconsistent in this backend")]
    BackendUnavailable,
    /// The embedded branch does not match the caller's expected upgrade.
    #[error("transaction consensus branch does not match the expected network upgrade")]
    ConsensusBranch,
    /// Every input needs a corresponding UTXO, and none may be coinbase.
    #[error("expected an in-range non-coinbase input and one previous output per input")]
    InputContext,
    /// The backend could not construct the transaction signature digest.
    #[error("could not compute transaction signature digest: {0}")]
    Sighash(#[source] zakura_chain::Error),
}
