use super::{
    proposal::{decode_output, point},
    ChangeReview, PaymentSource, Proposal, DUST, EXPIRY_BLOCKS, MAX_TRANSACTION,
};
use crate::{canonical, Entry, Error, Hex, Manifest, NodeContext, Receiver};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zakura_chain::{
    block::Height,
    parameters::NetworkUpgrade,
    serialization::ZcashSerialize,
    transaction::{zip317, LockTime, Transaction},
    transparent::{Input, Output, Script, MIN_TRANSPARENT_COINBASE_MATURITY},
};

/// The user's explicit handling of change below its estimated future spend fee.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Remainder {
    /// Require a new explicit choice before retaining uneconomic change.
    Reject,
    /// Keep change even when below its future spending fee.
    Keep,
    /// Explicitly add the remainder to the approved fee.
    Fee,
}

/// Independently supplied recipient intent, reused by each signer. It is not
/// accepted from the proposal itself. Omitting version selects v6.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// Recipient amount in zatoshis.
    pub amount: u64,
    /// Independently approved maximum fee in zatoshis.
    pub max_fee: u64,
    /// Canonical experimental Regtest receiver.
    pub receiver: String,
    /// Operator-approved activation of the receiver's suite on this chain.
    /// Required when paying a different suite; never inferred from a proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_activation_height: Option<u32>,
    /// Explicit handling of economically small change.
    pub remainder: Remainder,
    /// Transaction version, restricted to v5 or v6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
}
impl Intent {
    /// Decode strictly bounded canonical JSON without normalization.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let intent: Self = canonical::decode(bytes, 4096)?;
        intent.validate()?;
        Ok(intent)
    }
    /// Validate and encode exact canonical JSON within the transport cap.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(canonical::encode(self, 4096)?.to_vec())
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        Receiver::parse(&self.receiver)?;
        if !matches!(self.version.unwrap_or(6), 5 | 6) {
            return Err(Error::UnsupportedContext);
        }
        if self.amount < DUST || self.max_fee == 0 {
            return Err(Error::Fee);
        }
        for value in [self.amount, self.max_fee] {
            zakura_chain::amount::Amount::<zakura_chain::amount::NonNegative>::try_from(value)
                .map_err(|_| Error::Funds)?;
        }
        Ok(())
    }

    fn check_receiver_activation(&self, manifest: &Manifest, next: u32) -> Result<(), Error> {
        let same_suite = Receiver::parse(&self.receiver)?.suite().byte() == manifest.suite;
        let height = match (same_suite, self.receiver_activation_height) {
            (true, None) => manifest.profile.pq_activation_height,
            (true, Some(height)) if height == manifest.profile.pq_activation_height => height,
            (false, Some(height)) => height,
            _ => return Err(Error::ReceiverActivation),
        };
        if height < manifest.profile.nu7_activation_height || next < height {
            return Err(Error::ReceiverActivation);
        }
        Ok(())
    }
}

/// Recomputed transaction effects presented for independent signer approval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Review {
    /// Canonical change receiver when change is present.
    pub change_receiver: Option<String>,
    /// Change amount in zatoshis.
    pub change_value: u64,
    /// Number of SLH primitive signature checks required by all inputs.
    pub checks: u32,
    /// Current actual-size ZIP-317 fee in zatoshis.
    pub conventional_fee: u64,
    /// Last block height at which this transaction is valid.
    pub expiry_height: u32,
    /// Approved fee in zatoshis, preserving any explicitly retained historical approval.
    pub fee: u64,
    /// Exact serialized byte length including complete authorizations.
    pub final_bytes: usize,
    /// Estimated actual-size fee to spend the change output.
    pub future_change_spend_fee: u64,
    /// Total authenticated input value in zatoshis.
    pub input_value: u64,
    /// Locally recomputed change allocation and any advancement requiring approval.
    pub local_change: Option<ChangeReview>,
    /// Absolute transaction lock height; this wallet requires zero.
    pub lock_height: u32,
    /// Independently approved recipient receiver.
    pub payment_receiver: String,
    /// Independently approved recipient value in zatoshis.
    pub payment_value: u64,
    /// Digest of the complete canonical proposal.
    pub proposal_id: Hex<32>,
    /// Trusted checkpoint to which this observation or approval is bound.
    pub tip: crate::Checkpoint,
    /// Transaction version, restricted to v5 or v6.
    pub version: u32,
}

pub(crate) struct Checked {
    pub tx: Transaction,
    pub previous: Vec<Output>,
    pub review: Review,
    pub context: NodeContext,
}

pub(crate) fn active(
    source: &mut impl PaymentSource,
    manifest: &Manifest,
    intent: &Intent,
) -> Result<NodeContext, Error> {
    let context = source.context()?;
    context.validate(manifest)?;
    let next = context
        .tip
        .height
        .checked_add(1)
        .ok_or(Error::UnsupportedContext)?;
    if source.block_hash(0)? != manifest.profile.genesis_hash
        || next < manifest.profile.pq_activation_height
        || context.next_branch_id != Hex([0x77, 0x19, 0x0a, 0xd9])
    {
        return Err(Error::UnsupportedContext);
    }
    intent.check_receiver_activation(manifest, next)?;
    stable(source, &context)?;
    Ok(context)
}
pub(crate) fn stable(source: &mut impl PaymentSource, context: &NodeContext) -> Result<(), Error> {
    if source.context()? != *context || source.block_hash(context.tip.height)? != context.tip.hash {
        return Err(Error::ChainChanged);
    }
    Ok(())
}

pub(crate) fn group(entry: &Entry) -> Result<(u8, BTreeSet<Hex<16>>), Error> {
    Ok((
        entry.suite_policy()?.threshold(),
        entry.origins.iter().map(|o| o.wallet_id).collect(),
    ))
}
pub(crate) fn enrolled(manifest: &Manifest, entry: &Entry) -> Result<(), Error> {
    if !manifest.entries.contains(entry) {
        return Err(Error::Policy);
    }
    entry.local(manifest.wallet_id)?;
    Ok(())
}

pub(crate) fn check(
    manifest: &Manifest,
    source: &mut impl PaymentSource,
    proposal: &Proposal,
    intent: &Intent,
    previously_approved: bool,
) -> Result<Checked, Error> {
    intent.validate()?;
    let tx = proposal.transaction()?;
    if proposal.profile != manifest.profile
        || tx.version() != u32::from(intent.version.unwrap_or(6))
    {
        return Err(Error::UnsupportedContext);
    }
    let context = active(source, manifest, intent)?;
    if proposal.tip.height > context.tip.height
        || source.block_hash(proposal.tip.height)? != proposal.tip.hash
    {
        return Err(Error::ChainChanged);
    }
    let proposal_next = proposal
        .tip
        .height
        .checked_add(1)
        .ok_or(Error::UnsupportedContext)?;
    if proposal_next < manifest.profile.pq_activation_height {
        return Err(Error::UnsupportedContext);
    }
    intent.check_receiver_activation(manifest, proposal_next)?;
    let next = context
        .tip
        .height
        .checked_add(1)
        .ok_or(Error::UnsupportedContext)?;
    let expiry = proposal.expiry()?;
    if expiry > Height::MAX_EXPIRY_HEIGHT.0 {
        return Err(Error::UnsupportedContext);
    }
    if next > expiry {
        return Err(Error::Expired);
    }
    // Approval uses the signer's trusted tip, not the coordinator's metadata.
    // Keep this out of journal decoding: a reorg can put an already released
    // capability beyond the horizon without revoking its input reservations.
    let latest_expiry = context
        .tip
        .height
        .checked_add(EXPIRY_BLOCKS)
        .ok_or(Error::UnsupportedContext)?;
    if expiry > latest_expiry {
        return Err(Error::ExpiryTooFar);
    }
    let mut previous = Vec::new();
    let mut total = 0u64;
    let mut checks = 0u32;
    let ownership = group(&proposal.inputs[0].entry)?;
    for (input, record) in tx.inputs().iter().zip(&proposal.inputs) {
        enrolled(manifest, &record.entry)?;
        if group(&record.entry)? != ownership {
            return Err(Error::Policy);
        }
        let Input::PrevOut { outpoint, .. } = input else {
            return Err(Error::InputContext);
        };
        let resolved = source
            .resolve(point(*outpoint))?
            .ok_or(Error::InputContext)?;
        if resolved.tip != context.tip {
            return Err(Error::ChainChanged);
        }
        if resolved.height > context.tip.height
            || (resolved.coinbase
                && next
                    .checked_sub(resolved.height)
                    .is_none_or(|n| n < MIN_TRANSPARENT_COINBASE_MATURITY))
            || resolved.output != decode_output(&record.spent_output_hex)?
        {
            return Err(Error::InputContext);
        }
        manifest
            .profile
            .check_policy(&record.entry.suite_policy()?)?;
        total = total
            .checked_add(u64::from(resolved.output.value))
            .ok_or(Error::Funds)?;
        checks = checks
            .checked_add(u32::from(record.entry.suite_policy()?.threshold()))
            .ok_or(Error::Limits)?;
        previous.push(resolved.output);
    }
    zakura_chain::amount::Amount::<zakura_chain::amount::NonNegative>::try_from(total)
        .map_err(|_| Error::Funds)?;
    if checks > manifest.profile.max_tx_pq_checks || checks > manifest.profile.max_block_pq_checks {
        return Err(Error::Limits);
    }
    let payment_value = u64::from(tx.outputs()[0].value);
    if proposal.outputs[0].receiver != intent.receiver || payment_value != intent.amount {
        return Err(Error::ProposalMismatch);
    }
    let change_value = tx.outputs().get(1).map_or(0, |o| u64::from(o.value));
    let change = proposal.outputs.get(1);
    if let Some(record) = change {
        let entry = record.entry.as_ref().ok_or(Error::Policy)?;
        enrolled(manifest, entry)?;
        manifest.profile.check_policy(&entry.suite_policy()?)?;
        if group(entry)? != ownership
            || proposal
                .inputs
                .iter()
                .any(|r| r.entry.policy_hex == entry.policy_hex)
        {
            return Err(Error::Policy);
        }
    }
    if tx.outputs().iter().any(|o| u64::from(o.value) < DUST) {
        return Err(Error::Fee);
    }
    let fee = total
        .checked_sub(payment_value)
        .and_then(|v| v.checked_sub(change_value))
        .ok_or(Error::Funds)?;
    let entries = proposal.inputs.iter().map(|i| &i.entry).collect::<Vec<_>>();
    let (final_bytes, conventional_fee) = estimate(&tx, &entries)?;
    // Before the 400-zatoshi update, durable approvals used 5,000 per action.
    // Preserve exactly that fee only for the same locally approved effects and
    // intent. New proposals still require the current fee/remainder policy.
    // Report the current conventional fee even when retaining an older fee.
    let approved_legacy_fee = previously_approved
        && fee > conventional_fee
        && fee == estimate_at_rate(&tx, &entries, 5_000)?.1;
    let future = future_spend_fee(&proposal.inputs[0].entry, intent.version.unwrap_or(6))?;
    if fee < conventional_fee
        || fee > intent.max_fee
        || (fee > conventional_fee && intent.remainder != Remainder::Fee && !approved_legacy_fee)
        || (change_value > 0 && change_value < future && intent.remainder != Remainder::Keep)
    {
        return Err(Error::Fee);
    }
    stable(source, &context)?;
    let tip = context.tip;
    Ok(Checked {
        tx,
        previous,
        context,
        review: Review {
            change_receiver: change.map(|r| r.receiver.clone()),
            change_value,
            checks,
            conventional_fee,
            expiry_height: expiry,
            fee,
            final_bytes,
            future_change_spend_fee: future,
            input_value: total,
            local_change: None,
            lock_height: 0,
            payment_receiver: intent.receiver.clone(),
            payment_value,
            proposal_id: proposal.id()?,
            tip,
            version: u32::from(intent.version.unwrap_or(6)),
        },
    })
}

pub(crate) fn transaction(
    version: u8,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    expiry: u32,
) -> Result<Transaction, Error> {
    if expiry == 0 || expiry > Height::MAX_EXPIRY_HEIGHT.0 {
        return Err(Error::UnsupportedContext);
    }
    Ok(match version {
        5 => Transaction::V5 {
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(expiry),
            inputs,
            outputs,
            sapling_shielded_data: None,
            orchard_shielded_data: None,
        },
        6 => Transaction::V6 {
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(expiry),
            inputs,
            outputs,
            sapling_shielded_data: None,
            orchard_shielded_data: None,
            ironwood_shielded_data: None,
        },
        _ => return Err(Error::UnsupportedContext),
    })
}
pub(crate) fn inputs_mut(tx: &mut Transaction) -> Result<&mut Vec<Input>, Error> {
    match tx {
        Transaction::V5 { inputs, .. } | Transaction::V6 { inputs, .. } => Ok(inputs),
        _ => Err(Error::UnsupportedContext),
    }
}
pub(crate) fn estimate(tx: &Transaction, entries: &[&Entry]) -> Result<(usize, u64), Error> {
    estimate_at_rate(tx, entries, zip317::MARGINAL_FEE)
}
fn estimate_at_rate(
    tx: &Transaction,
    entries: &[&Entry],
    marginal_fee: u64,
) -> Result<(usize, u64), Error> {
    let mut sized = tx.clone();
    if sized.inputs().len() != entries.len() {
        return Err(Error::InputContext);
    }
    for (input, entry) in inputs_mut(&mut sized)?.iter_mut().zip(entries) {
        // Fixed-length index/key/signature pushes plus the exact descriptor push.
        let size = entry.suite_policy()?.authorization_size();
        let Input::PrevOut { unlock_script, .. } = input else {
            return Err(Error::InputContext);
        };
        // These bytes are used for size/ZIP-317 counting only, never for signing.
        *unlock_script = Script::new(&vec![0; size]);
    }
    let size = sized.zcash_serialized_size();
    if size > MAX_TRANSACTION {
        return Err(Error::Limits);
    }
    let fee = marginal_fee
        .checked_mul(u64::from(zip317::conventional_actions(&sized)))
        .ok_or(Error::Fee)?;
    Ok((size, fee))
}
pub(crate) fn future_spend_fee(entry: &Entry, version: u8) -> Result<u64, Error> {
    let tx = transaction(
        version,
        vec![Input::PrevOut {
            outpoint: zakura_chain::transparent::OutPoint {
                hash: zakura_chain::transaction::Hash([0; 32]),
                index: 0,
            },
            unlock_script: Script::new(&[]),
            sequence: u32::MAX,
        }],
        vec![Output {
            value: 1u64.try_into().map_err(|_| Error::Funds)?,
            lock_script: entry.suite_policy()?.lock_script(),
        }],
        1,
    )?;
    Ok(estimate(&tx, &[entry])?.1)
}
