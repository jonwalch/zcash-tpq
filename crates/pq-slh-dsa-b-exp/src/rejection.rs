//! Stable typed rejection categories for the native authorization contract.

/// A typed rejection. Precedence among simultaneous failures is not a wire rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejection {
    /// Unreviewed transaction version/upgrade pair.
    TransactionVersion,
    /// The backend cannot represent the branch consistently.
    BackendUnavailable,
    /// Embedded branch differs from the trusted upgrade.
    ConsensusBranch,
    /// Input index or ordered spent-output context is invalid.
    InputContext,
    /// The backend transaction hasher failed.
    Sighash,
    /// The spent output is not the exact 35-byte v1 template.
    OutputTemplate,
    /// The scriptSig exceeds its parser cap.
    AuthorizationSize,
    /// Non-minimal, truncated, oversized or trailing authorization data.
    Encoding,
    /// Unknown descriptor version or suite.
    UnsupportedPolicy,
    /// Invalid threshold or participant count.
    Threshold,
    /// Commitments are not strictly increasing.
    KeyOrder,
    /// The revealed policy does not match the spent output.
    OutputCommitment,
    /// The number of signer records differs from the threshold.
    SignatureCount,
    /// Duplicate, unordered or out-of-range signer index.
    SignerIndex,
    /// A revealed key does not match its indexed commitment.
    KeyCommitment,
    /// The caller's reservation of the input's checks failed.
    VerificationBudget,
    /// An SLH-DSA-B-128s signature does not verify for the derived message.
    Signature,
}

impl Rejection {
    /// Stable snake_case name for records and error messages.
    pub fn name(self) -> &'static str {
        match self {
            Self::TransactionVersion => "transaction_version",
            Self::BackendUnavailable => "backend_unavailable",
            Self::ConsensusBranch => "consensus_branch",
            Self::InputContext => "input_context",
            Self::Sighash => "sighash",
            Self::OutputTemplate => "output_template",
            Self::AuthorizationSize => "authorization_size",
            Self::Encoding => "encoding",
            Self::UnsupportedPolicy => "unsupported_policy",
            Self::Threshold => "threshold",
            Self::KeyOrder => "key_order",
            Self::OutputCommitment => "output_commitment",
            Self::SignatureCount => "signature_count",
            Self::SignerIndex => "signer_index",
            Self::KeyCommitment => "key_commitment",
            Self::VerificationBudget => "verification_budget",
            Self::Signature => "signature",
        }
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for Rejection {}

impl From<zakura_pq_tx_context::Error> for Rejection {
    fn from(error: zakura_pq_tx_context::Error) -> Self {
        use zakura_pq_tx_context::Error as E;
        match error {
            E::TransactionVersion => Self::TransactionVersion,
            E::BackendUnavailable => Self::BackendUnavailable,
            E::ConsensusBranch => Self::ConsensusBranch,
            E::InputContext => Self::InputContext,
            E::Sighash(_) => Self::Sighash,
        }
    }
}
