use super::{
    proposal::{decode_transaction, decode_variable},
    review::{self, Checked},
    InputRecord, Intent, OutputRecord, Partial, PaymentSource, Proposal, Remainder, Review, DUST,
    EXPIRY_BLOCKS, MAX_INPUTS, MAX_PAYMENTS, MAX_TRANSACTION,
};
use crate::{
    journal::{Location, ReadBudget},
    manifest::bounded,
    suite::{self, InputSigner},
    Error, Hex, KeyPath, Manifest, NodeContext, Outpoint, Role, Wallet, WatchMode, WatchStore,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use zakura_chain::{
    serialization::{BytesInDisplayOrder, ZcashSerialize},
    transaction::{Hash, Transaction},
    transparent::{Input, OutPoint, Output, Script},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentState {
    Prepared,
    PartiallySigned,
    Signed,
    SubmissionUnknown,
    Pending,
    Confirmed,
    Conflicted,
    Expired,
}

/// Cached observation; current chain state must be checked again before action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentRecord {
    pub intent: Intent,
    #[serde(deserialize_with = "partials")]
    pub partials: Vec<Partial>,
    pub proposal: Proposal,
    pub signed_transaction_hex: Option<String>,
    pub state: PaymentState,
}
fn partials<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Partial>, D::Error> {
    bounded::<D, Partial, MAX_INPUTS>(d)
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Book {
    pub change_next: u64,
    #[serde(deserialize_with = "records")]
    pub records: Vec<PaymentRecord>,
}
fn records<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PaymentRecord>, D::Error> {
    bounded::<D, PaymentRecord, MAX_PAYMENTS>(d)
}
impl Book {
    pub fn validate(&self, manifest: &Manifest) -> Result<(), Error> {
        if self.change_next < manifest.retired_change_end
            || self.change_next > manifest.change_end
            || self.records.len() > MAX_PAYMENTS
        {
            return Err(Error::Limits);
        }
        let mut ids = BTreeSet::new();
        for record in &self.records {
            record.intent.validate()?;
            let id = record.proposal.id()?;
            if !ids.insert(id)
                || record.proposal.profile != manifest.profile
                || record.partials.len() > MAX_INPUTS
            {
                return Err(Error::Encoding);
            }
            for input in &record.proposal.inputs {
                review::enrolled(manifest, &input.entry)?;
            }
            let mut indexes = BTreeSet::new();
            for partial in &record.partials {
                partial.authorization()?;
                if partial.proposal_id != id
                    || partial.input_index as usize >= record.proposal.inputs.len()
                    || !indexes.insert(partial.input_index)
                {
                    return Err(Error::ProposalMismatch);
                }
            }
            if let Some(change) = record
                .proposal
                .outputs
                .get(1)
                .and_then(|o| o.entry.as_ref())
            {
                review::enrolled(manifest, change)?;
                if u64::from(change.local(manifest.wallet_id)?.1.index) >= self.change_next {
                    return Err(Error::RecoveryIncomplete);
                }
            }
            if let Some(raw) = &record.signed_transaction_hex {
                let tx = decode_transaction(&decode_variable(raw, MAX_TRANSACTION)?)?;
                same_effects(&record.proposal, &tx)?;
            }
        }
        Ok(())
    }
    fn index(&self, id: Hex<32>) -> Result<Option<usize>, Error> {
        for (i, record) in self.records.iter().enumerate() {
            if record.proposal.id()? == id {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }
    fn reserved(&self, point: Outpoint, next: u32, except: Option<Hex<32>>) -> Result<bool, Error> {
        for record in &self.records {
            // Recomputed at every tip; expiry is reversible after a reorg.
            if Some(record.proposal.id()?) != except
                && record.proposal.expiry()? >= next
                && record.proposal.points()?.contains(&point)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl WatchStore {
    /// Bounded active payments only; archived capabilities remain in the journal.
    pub fn payments(&self) -> Result<&[PaymentRecord], Error> {
        self.ready()?;
        Ok(&self.state.payments.records)
    }
    fn payment_wallet(&self, wallet: &Wallet) -> Result<(), Error> {
        self.ready()?;
        if self.state.mode != WatchMode::Allocator {
            return Err(Error::MonitorOnly);
        }
        if wallet.manifest() != self.manifest() {
            return Err(Error::RecoveryIncomplete);
        }
        Ok(())
    }
    fn payment_sync(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
    ) -> Result<(), Error> {
        self.payment_wallet(wallet)?;
        if !self.sync(source, 10_000)?.complete_at_checkpoint {
            return Err(Error::HistoryUnavailable);
        }
        Ok(())
    }

    fn scanned_context(&self, context: &NodeContext) -> Result<(), Error> {
        let scan = self.status()?;
        if !scan.complete_at_checkpoint || scan.checkpoint != Some(context.tip) {
            return Err(Error::ChainChanged);
        }
        Ok(())
    }

    fn check_payment(
        &mut self,
        source: &mut impl PaymentSource,
        proposal: &Proposal,
        intent: &Intent,
        budget: &mut ReadBudget,
    ) -> Result<Checked, Error> {
        let id = proposal.id()?;
        let (retained, previously_approved) = if let Some(index) = self.state.payments.index(id)? {
            let record = &self.state.payments.records[index];
            (
                true,
                record.intent == *intent && record.proposal == *proposal,
            )
        } else if let Some(found) = self.resolve_payment(id, budget)? {
            (
                true,
                found.capability.intent == *intent && found.capability.proposal == *proposal,
            )
        } else {
            (false, false)
        };
        // A mismatched retained intent receives ordinary fee validation before
        // check_reservations rejects it; it cannot inherit the old fee policy.
        let mut checked = review::check(
            self.manifest(),
            source,
            proposal,
            intent,
            previously_approved,
        )?;
        checked.review.local_change = self.change_review(proposal, intent, retained)?;
        // A stable newer tip is insufficient: its blocks may consume change
        // entries. Review and allocation must use the completed scan's tip.
        self.scanned_context(&checked.context)?;
        Ok(checked)
    }
    /// Review actual outputs and node context against independently provided intent.
    /// No partial or transaction is released by this operation.
    pub fn review_payment(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        proposal: &Proposal,
        intent: &Intent,
    ) -> Result<Review, Error> {
        let mut budget = ReadBudget::new(4096)?;
        self.payment_sync(wallet, source)?;
        let checked = self.check_payment(source, proposal, intent, &mut budget)?;
        self.check_reservations(
            proposal,
            intent,
            checked.context.tip.height + 1,
            &mut budget,
        )?;
        Ok(checked.review)
    }

    /// Select and freeze a payment, then reserve inputs/change before export.
    pub fn prepare_payment(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        intent: &Intent,
    ) -> Result<(Proposal, Review), Error> {
        let mut budget = ReadBudget::new(4096)?;
        let (proposal, review) = self.preview_with_budget(wallet, source, intent, &mut budget)?;
        self.reserve(
            source,
            &proposal,
            intent,
            review.tip.height + 1,
            None,
            &mut budget,
        )?;
        Ok((proposal, review))
    }

    /// Select a proposal for local review without reserving inputs or change.
    /// Use this when preparation requires explicit change advancement approval.
    pub fn preview_payment(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        intent: &Intent,
    ) -> Result<(Proposal, Review), Error> {
        self.preview_with_budget(wallet, source, intent, &mut ReadBudget::new(4096)?)
    }
    pub(super) fn preview_with_budget(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        intent: &Intent,
        budget: &mut ReadBudget,
    ) -> Result<(Proposal, Review), Error> {
        intent.validate()?;
        self.payment_sync(wallet, source)?;
        let context = review::active(source, self.manifest(), intent)?;
        self.scanned_context(&context)?;
        let next = context
            .tip
            .height
            .checked_add(1)
            .ok_or(Error::UnsupportedContext)?;
        let expiry = context
            .tip
            .height
            .checked_add(EXPIRY_BLOCKS)
            .ok_or(Error::UnsupportedContext)?;
        let mut groups = BTreeMap::new();
        for coin in self.coins() {
            if !coin.mature_at(next) {
                continue;
            }
            let entry = self
                .manifest()
                .entries
                .iter()
                .find(|e| {
                    e.role == coin.role
                        && e.local(self.manifest().wallet_id)
                            .is_ok_and(|(_, o)| o.index == coin.index)
                })
                .ok_or(Error::Policy)?;
            groups
                .entry(review::group(entry)?)
                .or_insert_with(Vec::new)
                .push((coin.clone(), entry.clone()));
        }
        let mut last = Error::Funds;
        for (group, mut coins) in groups {
            if let Some((_, entry)) = coins.first() {
                if let Err(error) = self.manifest().profile.check_policy(&entry.suite_policy()?) {
                    last = error;
                    continue;
                }
            }
            coins.sort_by(|a, b| {
                b.0.value
                    .cmp(&a.0.value)
                    .then(a.0.outpoint.cmp(&b.0.outpoint))
            });
            let mut selected = Vec::new();
            let mut inputs = Vec::new();
            let mut total = 0u64;
            for (coin, entry) in coins {
                if self.reserved(coin.outpoint, next, None, budget)? {
                    continue;
                }
                let checks = (selected.len() + 1) * usize::from(group.0);
                if selected.len() == MAX_INPUTS
                    || checks as u64 > u64::from(self.manifest().profile.max_tx_pq_checks)
                {
                    break;
                }
                let Some(resolved) = source.resolve(coin.outpoint)? else {
                    continue;
                };
                if resolved.tip != context.tip {
                    return Err(Error::ChainChanged);
                }
                if resolved.height != coin.height
                    || resolved.coinbase != coin.coinbase
                    || u64::from(resolved.output.value) != coin.value
                    || resolved.output.lock_script != entry.suite_policy()?.lock_script()
                {
                    return Err(Error::InputContext);
                }
                total = total.checked_add(coin.value).ok_or(Error::Funds)?;
                let mut hash = coin.outpoint.txid.0;
                hash.reverse();
                inputs.push(Input::PrevOut {
                    outpoint: OutPoint {
                        hash: Hash(hash),
                        index: coin.outpoint.index,
                    },
                    unlock_script: Script::new(&[]),
                    sequence: u32::MAX,
                });
                selected.push(InputRecord {
                    entry,
                    spent_output_hex: hex::encode(
                        resolved
                            .output
                            .zcash_serialize_to_vec()
                            .map_err(|_| Error::Encoding)?,
                    ),
                });
                let payment = Output {
                    value: intent.amount.try_into().map_err(|_| Error::Funds)?,
                    lock_script: Script::new(&crate::Receiver::parse(&intent.receiver)?.script()),
                };
                let mut tx = review::transaction(
                    intent.version.unwrap_or(6),
                    inputs.clone(),
                    vec![payment.clone()],
                    expiry,
                )?;
                let entries: Vec<_> = selected.iter().map(|r| &r.entry).collect();
                let fee = match review::estimate(&tx, &entries) {
                    Ok((_, fee)) => fee,
                    Err(Error::Limits) => break,
                    Err(error) => return Err(error),
                };
                if fee > intent.max_fee {
                    last = Error::Fee;
                    break;
                }
                let Some(remainder) = total
                    .checked_sub(intent.amount)
                    .and_then(|v| v.checked_sub(fee))
                else {
                    continue;
                };
                let future =
                    review::future_spend_fee(&selected[0].entry, intent.version.unwrap_or(6))?;
                let donate =
                    remainder > 0 && remainder < future && intent.remainder == Remainder::Fee;
                if donate && fee.checked_add(remainder).ok_or(Error::Funds)? > intent.max_fee {
                    // Another input can turn this donation into economical
                    // change while keeping the conventional fee below the cap.
                    last = Error::Fee;
                    continue;
                }
                let mut outputs = vec![OutputRecord {
                    entry: None,
                    kind: "payment".into(),
                    receiver: intent.receiver.clone(),
                }];
                if remainder > 0 && !donate {
                    if remainder < DUST
                        || (remainder < future && intent.remainder != Remainder::Keep)
                    {
                        last = Error::Fee;
                        continue;
                    }
                    let change = self.eligible_change(&selected)?;
                    let Some(change) = change else {
                        last = Error::Exhausted;
                        continue;
                    };
                    tx = review::transaction(
                        intent.version.unwrap_or(6),
                        inputs.clone(),
                        vec![
                            payment,
                            Output {
                                value: remainder.try_into().map_err(|_| Error::Funds)?,
                                lock_script: change.suite_policy()?.lock_script(),
                            },
                        ],
                        expiry,
                    )?;
                    outputs.push(OutputRecord {
                        entry: Some(change.clone()),
                        kind: "change".into(),
                        receiver: change.receiver()?.encode(),
                    });
                }
                let proposal = Proposal {
                    format: "ZcashTransparentPQ/proposal/v1".into(),
                    inputs: selected.clone(),
                    outputs,
                    profile: self.manifest().profile.clone(),
                    tip: context.tip,
                    transaction_hex: hex::encode(
                        tx.zcash_serialize_to_vec().map_err(|_| Error::Encoding)?,
                    ),
                };
                let checked = self.check_payment(source, &proposal, intent, budget)?;
                self.check_reservations(&proposal, intent, checked.context.tip.height + 1, budget)?;
                return Ok((proposal, checked.review));
            }
        }
        Err(last)
    }

    /// Preview a tip-only refresh of an existing payment. The original durable
    /// reservation remains in force; no authorization or approval is changed.
    pub fn preview_payment_refresh(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        previous_id: Hex<32>,
    ) -> Result<(Proposal, Review), Error> {
        let mut budget = ReadBudget::new(4096)?;
        self.payment_gate(previous_id, &mut budget)?;
        self.payment_sync(wallet, source)?;
        let index = self
            .state
            .payments
            .index(previous_id)?
            .ok_or(Error::ProposalMismatch)?;
        let record = self.state.payments.records[index].clone();
        let context = review::active(source, self.manifest(), &record.intent)?;
        self.scanned_context(&context)?;
        let mut proposal = record.proposal.clone();
        proposal.tip = context.tip;
        // The clone changes only tip metadata from the exact retained approval.
        let mut checked = review::check(self.manifest(), source, &proposal, &record.intent, true)?;
        checked.review.local_change = self.change_review(&proposal, &record.intent, true)?;
        self.scanned_context(&checked.context)?;
        self.check_reservations(
            &record.proposal,
            &record.intent,
            checked.context.tip.height + 1,
            &mut budget,
        )?;
        Ok((proposal, checked.review))
    }

    /// Independently review another cosigner's tip-only refresh without
    /// changing the locally approved proposal or its existing capabilities.
    pub fn review_payment_refresh(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        previous_id: Hex<32>,
        proposal: &Proposal,
    ) -> Result<Review, Error> {
        let mut budget = ReadBudget::new(4096)?;
        self.payment_sync(wallet, source)?;
        Ok(self
            .check_payment_refresh(source, previous_id, proposal, &mut budget)?
            .1
            .review)
    }

    fn check_payment_refresh(
        &mut self,
        source: &mut impl PaymentSource,
        previous_id: Hex<32>,
        proposal: &Proposal,
        budget: &mut ReadBudget,
    ) -> Result<(usize, Checked), Error> {
        self.payment_gate(previous_id, budget)?;
        let index = self
            .state
            .payments
            .index(previous_id)?
            .ok_or(Error::ProposalMismatch)?;
        let record = self.state.payments.records[index].clone();
        if let Some(found) = self.resolve_payment(proposal.id()?, budget)? {
            let lineage = self
                .state
                .journal
                .as_ref()
                .ok_or(Error::JournalCorrupt)?
                .active[index]
                .lineage_id;
            if found.capability.lineage_id != lineage {
                return Err(Error::ProposalMismatch);
            }
        } else if self
            .state
            .payments
            .index(proposal.id()?)?
            .is_some_and(|other| other != index)
        {
            return Err(Error::ProposalMismatch);
        }
        let mut expected = record.proposal.clone();
        expected.tip = proposal.tip;
        if expected != *proposal {
            return Err(Error::ProposalMismatch);
        }
        // `expected` binds this refresh to the retained effects and intent.
        let mut checked = review::check(self.manifest(), source, proposal, &record.intent, true)?;
        checked.review.local_change = self.change_review(proposal, &record.intent, true)?;
        self.scanned_context(&checked.context)?;
        self.check_reservations(
            &record.proposal,
            &record.intent,
            checked.context.tip.height + 1,
            budget,
        )?;
        Ok((index, checked))
    }

    /// Independently approve new tip metadata for exactly the same proposal
    /// effects, policies, origins and intent. Replace its journal identity
    /// atomically, preserving reservations, expiry and every signature byte.
    pub fn approve_payment_refresh(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        previous_id: Hex<32>,
        proposal: &Proposal,
        approved_id: Hex<32>,
    ) -> Result<Review, Error> {
        let mut budget = ReadBudget::new(4096)?;
        if proposal.id()? != approved_id {
            return Err(Error::ProposalMismatch);
        }
        self.payment_sync(wallet, source)?;
        let (index, checked) =
            self.check_payment_refresh(source, previous_id, proposal, &mut budget)?;
        let record = &self.state.payments.records[index];
        // Reverify cached capabilities before changing their unkeyed routing
        // IDs. A refresh cannot import a different authorization or spend.
        let previous = Arc::new(checked.previous.clone());
        for partial in &record.partials {
            let input_index = partial.input_index as usize;
            let entry = &proposal.inputs[input_index].entry;
            let policy = entry.suite_policy()?;
            if usize::from(partial.signer_index) != entry.local(self.manifest().wallet_id)?.0 {
                return Err(Error::ProposalMismatch);
            }
            let context = InputSigner::new(&checked.tx, previous.clone(), input_index, &policy)?;
            context.verify_partial(&partial.authorization()?)?;
        }
        if let Some(raw) = &record.signed_transaction_hex {
            let signed = decode_transaction(&decode_variable(raw, MAX_TRANSACTION)?)?;
            verify_signed(proposal, &signed, &checked)?;
        }
        review::stable(source, &checked.context)?;
        let mut candidate = self.state.clone();
        let record = &mut candidate.payments.records[index];
        record.proposal = proposal.clone();
        for partial in &mut record.partials {
            partial.proposal_id = approved_id;
        }
        record.state = if record.signed_transaction_hex.is_some() {
            if record.state == PaymentState::Signed {
                PaymentState::Signed
            } else {
                PaymentState::SubmissionUnknown
            }
        } else if record.partials.is_empty() {
            PaymentState::Prepared
        } else {
            PaymentState::PartiallySigned
        };
        self.commit(candidate)?;
        Ok(checked.review)
    }

    fn reserved(
        &mut self,
        point: Outpoint,
        next: u32,
        except: Option<Hex<32>>,
        budget: &mut ReadBudget,
    ) -> Result<bool, Error> {
        if self.state.journal.is_some() {
            self.journal_reserved(point, next, except, budget)
        } else {
            self.state.payments.reserved(point, next, except)
        }
    }
    fn check_reservations(
        &mut self,
        proposal: &Proposal,
        intent: &Intent,
        next: u32,
        budget: &mut ReadBudget,
    ) -> Result<(), Error> {
        let id = proposal.id()?;
        let found = self.resolve_payment(id, budget)?;
        let except = if let Some(found) = &found {
            if found.capability.intent != *intent || found.capability.proposal != *proposal {
                return Err(Error::ProposalMismatch);
            }
            Some(found.capability.lineage_id)
        } else if let Some(index) = self.state.payments.index(id)? {
            if self.state.payments.records[index].intent != *intent {
                return Err(Error::ProposalMismatch);
            }
            Some(id)
        } else {
            if let Some(change) = proposal.outputs.get(1).and_then(|o| o.entry.as_ref()) {
                if u64::from(change.local(self.manifest().wallet_id)?.1.index)
                    < self.state.payments.change_next
                {
                    return Err(Error::Reserved);
                }
            }
            None
        };
        for point in proposal.points()? {
            if self.reserved(point, next, except, budget)? {
                return Err(Error::Reserved);
            }
        }
        Ok(())
    }
    /// Approve exactly the locally reviewed inventory jump and durably reserve
    /// this proposal. No signatures are generated. An ID from another wallet,
    /// intent, proposal or inventory/cursor state cannot authorize the jump.
    pub fn approve_payment_change(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        proposal: &Proposal,
        intent: &Intent,
        approved_change_id: Hex<32>,
    ) -> Result<Review, Error> {
        let mut budget = ReadBudget::new(4096)?;
        self.payment_sync(wallet, source)?;
        let checked = self.check_payment(source, proposal, intent, &mut budget)?;
        self.reserve(
            source,
            proposal,
            intent,
            checked.context.tip.height + 1,
            Some(approved_change_id),
            &mut budget,
        )?;
        Ok(checked.review)
    }

    fn reserve(
        &mut self,
        source: &mut impl PaymentSource,
        proposal: &Proposal,
        intent: &Intent,
        next: u32,
        approved_change_id: Option<Hex<32>>,
        budget: &mut ReadBudget,
    ) -> Result<usize, Error> {
        self.payment_gate(proposal.id()?, budget)?;
        self.check_reservations(proposal, intent, next, budget)?;
        if let Some(index) = self.state.payments.index(proposal.id()?)? {
            if approved_change_id.is_some() {
                return Err(Error::ProposalMismatch);
            }
            return Ok(index);
        }
        let expected = self
            .change_review(proposal, intent, false)?
            .and_then(|change| change.advancement)
            .map(|advancement| advancement.approval_id);
        if approved_change_id.is_some() && approved_change_id != expected {
            return Err(Error::ProposalMismatch);
        }
        if expected.is_some() && approved_change_id.is_none() {
            return Err(Error::ChangeApprovalRequired);
        }
        let context = review::active(source, self.manifest(), intent)?;
        self.scanned_context(&context)?;
        if context.tip.height.checked_add(1) != Some(next) {
            return Err(Error::ChainChanged);
        }
        let mut candidate = self.capacity_candidate(source)?;
        if let Some(change) = proposal.outputs.get(1).and_then(|o| o.entry.as_ref()) {
            candidate.payments.change_next =
                u64::from(change.local(self.manifest().wallet_id)?.1.index) + 1;
        }
        let index = candidate.payments.records.len();
        candidate.payments.records.push(PaymentRecord {
            intent: intent.clone(),
            partials: vec![],
            proposal: proposal.clone(),
            signed_transaction_hex: None,
            state: PaymentState::Prepared,
        });
        self.commit_observed(source, &context, candidate)?;
        Ok(index)
    }

    /// Each invocation uses only this wallet's root. The explicit ID binds the
    /// caller's approval to the complete reviewed proposal, including metadata.
    pub fn sign_payment(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        proposal: &Proposal,
        intent: &Intent,
        approved_id: Hex<32>,
    ) -> Result<Vec<Partial>, Error> {
        self.sign_payment_inner(wallet, source, proposal, intent, approved_id, &mut || Ok(()))
    }
    // Test-only durable-failure checkpoint. Supplied bytes are discarded and
    // never reach SLH signing, whose entropy remains exclusively operational OS
    // randomness. This preserves the existing failure-ordering regressions.
    #[cfg(test)]
    pub(crate) fn sign_payment_with_rng(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        proposal: &Proposal,
        intent: &Intent,
        approved_id: Hex<32>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Vec<Partial>, Error> {
        self.sign_payment_inner(wallet, source, proposal, intent, approved_id, &mut || {
            let mut discarded = zeroize::Zeroizing::new([0; 16]);
            rng.try_fill_bytes(discarded.as_mut()).map_err(|_| Error::Entropy)
        })
    }

    fn sign_payment_inner(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        proposal: &Proposal,
        intent: &Intent,
        approved_id: Hex<32>,
        before_sign: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<Vec<Partial>, Error> {
        let mut budget = ReadBudget::new(4096)?;
        super::approval::release(
            &proposal.id()?.0,
            &approved_id.0,
            Error::ProposalMismatch,
            &mut || {
                self.payment_gate(proposal.id()?, &mut budget)?;
                self.payment_sync(wallet, source)?;
                let checked = self.check_payment(source, proposal, intent, &mut budget)?;
                let index = self.reserve(
                    source,
                    proposal,
                    intent,
                    checked.context.tip.height + 1,
                    None,
                    &mut budget,
                )?;
                let previous = Arc::new(checked.previous);
                let saved = &self.state.payments.records[index].partials;
                let mut partials = Vec::new();
                for (input_index, record) in proposal.inputs.iter().enumerate() {
                    let policy = record.entry.suite_policy()?;
                    let context =
                        InputSigner::new(&checked.tx, previous.clone(), input_index, &policy)?;
                    let (slot, origin) = record.entry.local(wallet.manifest().wallet_id)?;
                    if !saved.is_empty() {
                        let partial = saved
                            .iter()
                            .find(|p| p.input_index as usize == input_index)
                            .ok_or(Error::ProposalMismatch)?;
                        if partial.signer_index as usize != slot {
                            return Err(Error::ProposalMismatch);
                        }
                        context.verify_partial(&partial.authorization()?)?;
                        partials.push(partial.clone());
                    } else {
                        before_sign()?;
                        let signer = wallet.sign_input(
                            &context,
                            KeyPath {
                                role: if record.entry.role == 0 {
                                    Role::Receive
                                } else {
                                    Role::Change
                                },
                                index: origin.index,
                            },
                        )?;
                        partials.push(Partial::new(
                            approved_id,
                            u32::try_from(input_index).map_err(|_| Error::Limits)?,
                            signer,
                        ));
                    }
                }
                review::stable(source, &checked.context)?;
                if saved.is_empty() {
                    let mut candidate = self.state.clone();
                    let record = &mut candidate.payments.records[index];
                    record.partials = partials.clone();
                    if record.signed_transaction_hex.is_none() {
                        record.state = PaymentState::PartiallySigned;
                    }
                    self.commit(candidate)?;
                }
                Ok(partials)
            },
        )
    }

    pub fn assemble_payment(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        proposal: &Proposal,
        intent: &Intent,
        partials: &[Partial],
    ) -> Result<Vec<u8>, Error> {
        let mut budget = ReadBudget::new(4096)?;
        self.payment_gate(proposal.id()?, &mut budget)?;
        self.payment_sync(wallet, source)?;
        let checked = self.check_payment(source, proposal, intent, &mut budget)?;
        let index = self.reserve(
            source,
            proposal,
            intent,
            checked.context.tip.height + 1,
            None,
            &mut budget,
        )?;
        let previous = Arc::new(checked.previous.clone());
        if partials.len() != checked.review.checks as usize {
            return Err(Error::ProposalMismatch);
        }
        let mut by_input = vec![Vec::new(); proposal.inputs.len()];
        for partial in partials {
            if partial.proposal_id != checked.review.proposal_id {
                return Err(Error::ProposalMismatch);
            }
            by_input
                .get_mut(partial.input_index as usize)
                .ok_or(Error::ProposalMismatch)?
                .push(partial.authorization()?);
        }
        let mut signed = checked.tx.clone();
        for (input_index, (record, signatures)) in proposal.inputs.iter().zip(by_input).enumerate()
        {
            let policy = record.entry.suite_policy()?;
            let context = InputSigner::new(&checked.tx, previous.clone(), input_index, &policy)?;
            let auth = context.assemble(signatures)?;
            let Input::PrevOut { unlock_script, .. } =
                &mut review::inputs_mut(&mut signed)?[input_index]
            else {
                return Err(Error::InputContext);
            };
            *unlock_script = auth;
        }
        verify_signed(proposal, &signed, &checked)?;
        let bytes = signed
            .zcash_serialize_to_vec()
            .map_err(|_| Error::Encoding)?;
        review::stable(source, &checked.context)?;
        let mut candidate = self.state.clone();
        let record = &mut candidate.payments.records[index];
        if record
            .signed_transaction_hex
            .as_ref()
            .is_some_and(|raw| *raw != hex::encode(&bytes))
        {
            // An existing signed retry must keep its exact authorization bytes.
            return Err(Error::ProposalMismatch);
        }
        record.signed_transaction_hex = Some(hex::encode(&bytes));
        record.state = PaymentState::Signed;
        self.commit(candidate)?;
        Ok(bytes)
    }

    /// Refresh observations without releasing still-valid signed capabilities.
    /// Expired reservations become active again if the chain rolls back.
    pub fn reconcile_payments(
        &mut self,
        source: &mut impl PaymentSource,
    ) -> Result<Vec<PaymentState>, Error> {
        let (candidate, _) = self.observe_payments(source)?;
        let states = candidate.payments.records.iter().map(|r| r.state).collect();
        self.commit(candidate)?;
        Ok(states)
    }

    pub(super) fn observe_payments(
        &self,
        source: &mut impl PaymentSource,
    ) -> Result<(crate::watch::State, NodeContext), Error> {
        self.observe_candidate(source, self.state.clone())
    }
    fn observe_candidate(
        &self,
        source: &mut impl PaymentSource,
        mut candidate: crate::watch::State,
    ) -> Result<(crate::watch::State, NodeContext), Error> {
        self.ready()?;
        let context = source.context()?;
        context.validate(self.manifest())?;
        if source.block_hash(0)? != self.manifest().profile.genesis_hash {
            return Err(Error::UnsupportedContext);
        }
        let next = context
            .tip
            .height
            .checked_add(1)
            .ok_or(Error::UnsupportedContext)?;
        for record in &mut candidate.payments.records {
            let unsigned = record.proposal.transaction()?;
            let id = Hex(unsigned.hash().bytes_in_display_order());
            let state = if let Some(found) = source.transaction(id)? {
                let tx = decode_transaction(&found.bytes)?;
                same_effects(&record.proposal, &tx)?;
                if let Some(block) = found.block {
                    if block.height > context.tip.height
                        || source.block_hash(block.height)? != block.hash
                    {
                        return Err(Error::ChainChanged);
                    }
                    PaymentState::Confirmed
                } else {
                    PaymentState::Pending
                }
            } else if next > record.proposal.expiry()? {
                PaymentState::Expired
            } else {
                let mut spent = false;
                for point in record.proposal.points()? {
                    match source.resolve(point)? {
                        Some(resolved) if resolved.tip == context.tip => (),
                        Some(_) => return Err(Error::ChainChanged),
                        None => spent = true,
                    }
                }
                if spent {
                    PaymentState::Conflicted
                } else if matches!(
                    record.state,
                    PaymentState::Pending
                        | PaymentState::Confirmed
                        | PaymentState::Conflicted
                        | PaymentState::Expired
                ) {
                    if record.signed_transaction_hex.is_some() {
                        PaymentState::SubmissionUnknown
                    } else if record.partials.is_empty() {
                        PaymentState::Prepared
                    } else {
                        PaymentState::PartiallySigned
                    }
                } else {
                    record.state
                }
            };
            record.state = state;
        }
        if let Some(root) = &mut candidate.journal {
            for (active, record) in root.active.iter_mut().zip(&candidate.payments.records) {
                active.state = record.state;
                active.checkpoint = Some(context.tip);
            }
        }
        review::stable(source, &context)?;
        Ok((candidate, context))
    }

    /// Move a freshly reconciled inactive payment into durable history. Its
    /// authorizations, change retirement and outpoint reservations are retained.
    pub fn archive_payment(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        id: Hex<32>,
    ) -> Result<(), Error> {
        let mut budget = ReadBudget::new(4096)?;
        self.payment_wallet(wallet)?;
        self.payment_gate(id, &mut budget)?;
        let index = self
            .state
            .payments
            .index(id)?
            .ok_or(Error::ProposalMismatch)?;
        let (observed, context) = self.observe_payments(source)?;
        if !crate::watch::archive::inactive(observed.payments.records[index].state) {
            return Err(Error::PaymentActive);
        }
        self.migrate_payment_journal()?;
        let mut candidate = self.attach_observations(observed, context.tip)?;
        Self::archive_candidate(&mut candidate, index)?;
        self.commit_observed(source, &context, candidate)
    }

    /// Explicitly return the latest archived capability to the active book.
    /// Fresh observation is required; no signing, submission or reservation is
    /// implied. Normal action-specific trusted-node checks still run afterward.
    pub fn resume_payment(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        id: Hex<32>,
    ) -> Result<(), Error> {
        self.payment_wallet(wallet)?;
        let found = self
            .resolve_payment(id, &mut ReadBudget::new(4096)?)?
            .ok_or(Error::ProposalMismatch)?;
        if found.current_id != id {
            return Err(Error::SupersededPayment {
                current: found.current_id,
            });
        }
        if found.location == Location::Active {
            return Ok(());
        }
        let mut candidate = self.capacity_candidate(source)?;
        let unobserved = if found.capability.signed_transaction_hex.is_some() {
            PaymentState::SubmissionUnknown
        } else if found.capability.partials.is_empty() {
            PaymentState::Prepared
        } else {
            PaymentState::PartiallySigned
        };
        candidate
            .payments
            .records
            .push(found.capability.record(unobserved));
        candidate
            .journal
            .as_mut()
            .ok_or(Error::JournalCorrupt)?
            .active
            .push(crate::watch::archive::Active {
                capability: found.hash,
                checkpoint: None,
                lineage_id: found.capability.lineage_id,
                state: unobserved,
            });
        // Reconcile the resumed record in the prospective book without making
        // that book authoritative before the one final root publication.
        let (candidate, context) = self.observe_candidate(source, candidate)?;
        self.commit_observed(source, &context, candidate)
    }

    fn commit_observed(
        &mut self,
        source: &mut impl PaymentSource,
        context: &NodeContext,
        candidate: crate::watch::State,
    ) -> Result<(), Error> {
        if candidate.journal.as_ref().is_some_and(|root| {
            root.archives
                .iter()
                .any(|archived| archived.checkpoint != Some(context.tip))
        }) {
            return Err(Error::ChainChanged);
        }
        review::stable(source, context)?;
        self.commit(candidate)
    }

    fn attach_observations(
        &self,
        mut candidate: crate::watch::State,
        tip: crate::Checkpoint,
    ) -> Result<crate::watch::State, Error> {
        candidate.journal = self.state.journal.clone();
        let root = candidate.journal.as_mut().ok_or(Error::JournalCorrupt)?;
        for (active, record) in root.active.iter_mut().zip(&candidate.payments.records) {
            active.state = record.state;
            active.checkpoint = Some(tip);
        }
        Ok(candidate)
    }
    pub(super) fn archive_candidate(
        candidate: &mut crate::watch::State,
        index: usize,
    ) -> Result<(), Error> {
        let root = candidate.journal.as_mut().ok_or(Error::JournalCorrupt)?;
        let archived = root.active.remove(index);
        if !crate::watch::archive::inactive(archived.state) || archived.checkpoint.is_none() {
            return Err(Error::PaymentActive);
        }
        root.archives.push(archived);
        candidate.payments.records.remove(index);
        Ok(())
    }
    fn capacity_candidate(
        &mut self,
        source: &mut impl PaymentSource,
    ) -> Result<crate::watch::State, Error> {
        if self.state.payments.records.len() < MAX_PAYMENTS {
            return Ok(self.state.clone());
        }
        let (observed, context) = self.observe_payments(source)?;
        let mut eligible = None;
        for (index, record) in observed.payments.records.iter().enumerate() {
            if !crate::watch::archive::inactive(record.state) {
                continue;
            }
            let lineage = if let Some(root) = &observed.journal {
                root.active[index].lineage_id
            } else {
                // Migration uses each retained proposal ID as its first lineage.
                record.proposal.id()?
            };
            if eligible.is_none_or(|(first, _)| lineage < first) {
                eligible = Some((lineage, index));
            }
        }
        let (_, index) = eligible.ok_or(Error::ActivePaymentLimit)?;
        self.migrate_payment_journal()?;
        let mut candidate = self.attach_observations(observed, context.tip)?;
        Self::archive_candidate(&mut candidate, index)?;
        review::stable(source, &context)?;
        Ok(candidate)
    }

    /// Persist uncertainty before the RPC. Every failure leaves signed bytes
    /// and reservations available for an identical retry or reconciliation.
    pub fn submit_payment(
        &mut self,
        wallet: &Wallet,
        source: &mut impl PaymentSource,
        id: Hex<32>,
    ) -> Result<Hex<32>, Error> {
        let mut budget = ReadBudget::new(4096)?;
        self.payment_wallet(wallet)?;
        self.payment_gate(id, &mut budget)?;
        self.reconcile_payments(source)?;
        let index = self
            .state
            .payments
            .index(id)?
            .ok_or(Error::ProposalMismatch)?;
        let record = self.state.payments.records[index].clone();
        let bytes = decode_variable(
            record
                .signed_transaction_hex
                .as_deref()
                .ok_or(Error::ProposalMismatch)?,
            MAX_TRANSACTION,
        )?;
        let signed = decode_transaction(&bytes)?;
        let txid = Hex(signed.hash().bytes_in_display_order());
        if matches!(
            record.state,
            PaymentState::Pending | PaymentState::Confirmed
        ) {
            return Ok(txid);
        }
        self.payment_sync(wallet, source)?;
        let checked = self.check_payment(source, &record.proposal, &record.intent, &mut budget)?;
        self.check_reservations(
            &record.proposal,
            &record.intent,
            checked.context.tip.height + 1,
            &mut budget,
        )?;
        verify_signed(&record.proposal, &signed, &checked)?;
        let mut candidate = self.state.clone();
        candidate.payments.records[index].state = PaymentState::SubmissionUnknown;
        self.commit(candidate)?;
        if source.submit(&bytes).ok() != Some(txid) {
            return Err(Error::SubmissionUnknown);
        }
        let mut candidate = self.state.clone();
        candidate.payments.records[index].state = PaymentState::Pending;
        self.commit(candidate)?;
        Ok(txid)
    }
}

fn same_effects(proposal: &Proposal, tx: &Transaction) -> Result<(), Error> {
    let mut unsigned = tx.clone();
    for input in review::inputs_mut(&mut unsigned)? {
        let Input::PrevOut { unlock_script, .. } = input else {
            return Err(Error::InputContext);
        };
        *unlock_script = Script::new(&[]);
    }
    if unsigned != proposal.transaction()? {
        return Err(Error::ProposalMismatch);
    }
    Ok(())
}
fn verify_signed(proposal: &Proposal, tx: &Transaction, checked: &Checked) -> Result<(), Error> {
    same_effects(proposal, tx)?;
    if tx.zcash_serialized_size() != checked.review.final_bytes
        || u64::from(zakura_chain::transaction::zip317::conventional_fee(tx))
            != checked.review.conventional_fee
    {
        return Err(Error::Fee);
    }
    let suites = proposal
        .inputs
        .iter()
        .map(|input| Ok(input.entry.suite_policy()?.suite()))
        .collect::<Result<Vec<_>, Error>>()?;
    suite::verify_inputs(tx, Arc::new(checked.previous.clone()), &suites)
}
