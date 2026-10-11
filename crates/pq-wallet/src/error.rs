/// Wallet failures deliberately omit passwords, plaintext and parser details.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// malformed or noncanonical wallet encoding.
    #[error("malformed or noncanonical wallet encoding")]
    Encoding,
    /// unsupported wallet format.
    #[error("unsupported wallet format")]
    UnsupportedFormat,
    /// unsupported or mismatched wallet context.
    #[error("unsupported or mismatched wallet context")]
    UnsupportedContext,
    /// recipient suite activation is missing, mismatched or not yet active.
    #[error("recipient suite activation is missing, mismatched or not yet active")]
    ReceiverActivation,
    /// wallet size or resource limit exceeded.
    #[error("wallet size or resource limit exceeded")]
    Limits,
    /// wallet revision or derivation range exhausted.
    #[error("wallet revision or derivation range exhausted")]
    Exhausted,
    /// backup authentication failed.
    #[error("backup authentication failed")]
    Authentication,
    /// password must contain 1 to 1024 UTF-8 bytes.
    #[error("password must contain 1 to 1024 UTF-8 bytes")]
    Password,
    /// inventory history or allocator requires reconciliation.
    #[error("inventory history or allocator requires reconciliation")]
    RecoveryIncomplete,
    /// invalid policy or local key origin.
    #[error("invalid policy or local key origin")]
    Policy,
    /// policy requires the required PQ checks; approved limits are the transaction allowance per transaction and the block allowance per block.
    #[error("policy requires {required} PQ checks; approved limits are {transaction} per transaction and {block} per block")]
    PolicyLimit {
        /// Required signature checks.
        required: u32,
        /// Approved transaction limit.
        transaction: u32,
        /// Approved block limit.
        block: u32,
    },
    /// could not obtain secure randomness.
    #[error("could not obtain secure randomness")]
    Entropy,
    /// wallet storage operation failed.
    #[error("wallet storage operation failed")]
    Storage(#[source] std::io::Error),
    /// watch store is already in use.
    #[error("watch store is already in use")]
    Locked,
    /// watch store requires reopening after a storage failure.
    #[error("watch store requires reopening after a storage failure")]
    ReopenRequired,
    /// inventory fingerprint does not match the independently approved fingerprint.
    #[error("inventory fingerprint does not match the independently approved fingerprint")]
    Pairing,
    /// this watcher does not own the receiver allocator.
    #[error("this watcher does not own the receiver allocator")]
    MonitorOnly,
    /// trusted node or required chain history is unavailable; scan is incomplete.
    #[error("trusted node or required chain history is unavailable; scan is incomplete")]
    HistoryUnavailable,
    /// chain changed or returned inconsistent block data; retry synchronization.
    #[error("chain changed or returned inconsistent block data; retry synchronization")]
    ChainChanged,
    /// input is unavailable, immature or differs from trusted node data.
    #[error("input is unavailable, immature or differs from trusted node data")]
    InputContext,
    /// proposal, approved intent or partial authorization does not match.
    #[error("proposal, approved intent or partial authorization does not match")]
    ProposalMismatch,
    /// payment fee, dust or remainder policy is not satisfied.
    #[error("payment fee, dust or remainder policy is not satisfied")]
    Fee,
    /// insufficient eligible funds within the payment limits.
    #[error("insufficient eligible funds within the payment limits")]
    Funds,
    /// input or change is already reserved by another payment.
    #[error("input or change is already reserved by another payment")]
    Reserved,
    /// change would skip unused inventory; review and approve its local advancement ID.
    #[error("change would skip unused inventory; review and approve its local advancement ID")]
    ChangeApprovalRequired,
    /// payment has expired for the candidate block.
    #[error("payment has expired for the candidate block")]
    Expired,
    /// payment expiry exceeds the wallet approval horizon.
    #[error("payment expiry exceeds the wallet approval horizon")]
    ExpiryTooFar,
    /// submission outcome is uncertain; reconcile or retry the saved transaction.
    #[error("submission outcome is uncertain; reconcile or retry the saved transaction")]
    SubmissionUnknown,
    /// payment journal is corrupt or incomplete.
    #[error("payment journal is corrupt or incomplete")]
    JournalCorrupt,
    /// payment journal disk quota exceeded.
    #[error("payment journal disk quota exceeded")]
    JournalQuota,
    /// payment journal storage or commit limit exceeded.
    #[error("payment journal storage or commit limit exceeded")]
    JournalLimit,
    /// payment journal lookup budget exhausted.
    #[error("payment journal lookup budget exhausted")]
    JournalLookupLimit,
    /// payment journal changed; restart pagination from the first page.
    #[error("payment journal changed; restart pagination from the first page")]
    StaleJournalCursor,
    /// all 32 active payment slots are occupied.
    #[error("all 32 active payment slots are occupied")]
    ActivePaymentLimit,
    /// payment is archived; explicitly resume it before mutation.
    #[error("payment is archived; explicitly resume it before mutation")]
    ArchivedPayment,
    /// payment was superseded; current proposal ID is the successor.
    #[error("payment was superseded; current proposal ID is {}", hex::encode(current.0))]
    SupersededPayment {
        /// Current proposal identifier.
        current: crate::Hex<32>,
    },
    /// payment is still active at the trusted checkpoint.
    #[error("payment is still active at the trusted checkpoint")]
    PaymentActive,
    /// experimental SLH authorization failed.
    #[error("experimental SLH authorization failed")]
    Authorization(#[source] zakura_pq_slh_dsa_b_exp::Rejection),
    /// experimental SLH local signature verification failed.
    #[error("experimental SLH local signature verification failed")]
    Signing(#[source] zakura_pq_slh_dsa_b_sign::SignError),
}

impl From<zakura_pq_slh_dsa_b_exp::Rejection> for Error {
    fn from(rejection: zakura_pq_slh_dsa_b_exp::Rejection) -> Self {
        Self::Authorization(rejection)
    }
}

impl From<zakura_pq_slh_dsa_b_sign::SignError> for Error {
    fn from(error: zakura_pq_slh_dsa_b_sign::SignError) -> Self {
        match error {
            zakura_pq_slh_dsa_b_sign::SignError::Entropy => Self::Entropy,
            error => Self::Signing(error),
        }
    }
}
