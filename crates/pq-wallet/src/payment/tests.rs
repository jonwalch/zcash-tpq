//! Synthetic trusted-node histories exercise wallet decisions and persistence.
//! The live CLI test separately checks actual node acceptance.
mod approval;
mod archive;
mod capacity;
mod change;
mod counterexamples;
mod expiry;
#[cfg(unix)]
mod faults;
mod fee_upgrade;
mod formats;
mod history;
mod hostile;
mod incoming;
mod profile_limits;
mod sequences;
mod slh_capacity;
mod snapshot;

use super::*;
use crate::{
    watch::tests::{create, output, profile, transaction, Chain},
    ChainSource, Entry, KeyPath, NodeContext, Origin, Role, Wallet, WatchMode, WatchStore,
};
use rand_core::{CryptoRng, RngCore};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};
use zakura_chain::{
    serialization::{BytesInDisplayOrder, ZcashSerialize},
    transaction::Transaction,
    transparent::{Input, OutPoint},
};
use zakura_pq_slh_dsa_b_exp::Policy;

fn wallets(n: usize, receive: u32, change: u32) -> Vec<Wallet> {
    wallets_with_rng(n, receive, change, &mut rand_core::OsRng)
}
fn wallets_with_rng(
    n: usize,
    receive: u32,
    change: u32,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<Wallet> {
    let mut wallets: Vec<_> = (0..n)
        .map(|_| Wallet::create_with_rng(profile(), 0, rng).unwrap())
        .collect();
    let mut entries = Vec::new();
    for (role, end) in [(Role::Receive, receive), (Role::Change, change)] {
        for index in 0..end {
            let mut keys: Vec<_> = wallets
                .iter()
                .map(|w| {
                    (
                        w.key_commitment(KeyPath { role, index }).unwrap(),
                        Origin {
                            account: 0,
                            index,
                            wallet_id: w.manifest().wallet_id,
                        },
                    )
                })
                .collect();
            keys.sort_by_key(|(commitment, _)| *commitment);
            entries.push(Entry {
                origins: keys.iter().map(|(_, origin)| origin.clone()).collect(),
                policy_hex: hex::encode(
                    Policy::new(
                        if n == 1 { 1 } else { 2 },
                        keys.iter().map(|(c, _)| *c).collect(),
                    )
                    .unwrap()
                    .descriptor(),
                ),
                role: role as u8,
            });
        }
    }
    for wallet in &mut wallets {
        // Test-only setup avoids encrypting the same synthetic enrollment in
        // every case. Real backup/enrollment is exercised by the CLI test.
        wallet.manifest.entries = entries.clone();
        wallet.manifest.receive_end = receive.into();
        wallet.manifest.change_end = change.into();
        wallet.manifest.validate().unwrap();
    }
    wallets
}
fn intent(version: u8) -> Intent {
    Intent {
        amount: 500_000,
        max_fee: 1_000_000,
        receiver: wallets(1, 1, 0)[0].manifest.entries[0]
            .receiver()
            .unwrap()
            .encode(),
        receiver_activation_height: None,
        remainder: Remainder::Reject,
        version: Some(version),
    }
}
fn txid(tx: &Transaction) -> Hex<32> {
    Hex(tx.hash().bytes_in_display_order())
}
struct Source {
    chain: Chain,
    pool: BTreeMap<Hex<32>, Arc<Transaction>>,
    sent: Vec<Vec<u8>>,
    fail_submit: bool,
    accept_before_failure: bool,
    journal: Option<PathBuf>,
    corrupt_value: bool,
    unavailable: bool,
}
impl Source {
    fn funded(wallet: &Wallet, values: &[u64]) -> Self {
        let mut chain = Chain::new();
        chain.push(vec![], None);
        chain.push(vec![], None);
        chain.push(
            vec![transaction(
                6,
                0,
                vec![],
                values
                    .iter()
                    .map(|v| output(&wallet.manifest.entries[0], *v))
                    .collect(),
            )],
            None,
        );
        Self {
            chain,
            pool: BTreeMap::new(),
            sent: vec![],
            fail_submit: false,
            accept_before_failure: false,
            journal: None,
            corrupt_value: false,
            unavailable: false,
        }
    }
    fn mine(&mut self) {
        self.chain
            .push(std::mem::take(&mut self.pool).into_values().collect(), None);
    }
}
impl ChainSource for Source {
    fn context(&mut self) -> Result<NodeContext, Error> {
        if self.unavailable {
            return Err(Error::HistoryUnavailable);
        }
        self.chain.context()
    }
    fn block_hash(&mut self, h: u32) -> Result<Hex<32>, Error> {
        self.chain.block_hash(h)
    }
    fn block_bytes(&mut self, h: Hex<32>) -> Result<Vec<u8>, Error> {
        self.chain.block_bytes(h)
    }
}
// Invalid synthetic fixture data must panic, not simulate a trusted-node refusal.
#[allow(clippy::unwrap_in_result)]
impl PaymentSource for Source {
    fn resolve(&mut self, point: Outpoint) -> Result<Option<ResolvedInput>, Error> {
        let context = self.context()?;
        let mut found = None;
        for (height, block) in self.chain.blocks.iter().enumerate() {
            for tx in &block.transactions {
                if txid(tx) == point.txid {
                    found = tx
                        .outputs()
                        .get(point.index as usize)
                        .map(|o| ResolvedInput {
                            output: o.clone(),
                            height: height as u32,
                            coinbase: tx.is_coinbase(),
                            tip: context.tip,
                        });
                }
                if tx.inputs().iter().any(|i| matches!(i, Input::PrevOut { outpoint, .. } if proposal::point(*outpoint) == point)) {
                    found = None;
                }
            }
        }
        if self.pool.values().any(|t| t.inputs().iter().any(|i| matches!(i, Input::PrevOut { outpoint, .. } if proposal::point(*outpoint) == point))) { return Ok(None); }
        if self.corrupt_value {
            if let Some(input) = &mut found {
                input.output.value = (u64::from(input.output.value) + 1)
                    .try_into()
                    .expect("synthetic amounts leave room for the corruption offset");
            }
        }
        Ok(found)
    }
    fn transaction(&mut self, id: Hex<32>) -> Result<Option<LocatedTransaction>, Error> {
        self.context()?;
        for (height, block) in self.chain.blocks.iter().enumerate() {
            if let Some(tx) = block.transactions.iter().find(|t| txid(t) == id) {
                return Ok(Some(LocatedTransaction {
                    bytes: tx
                        .zcash_serialize_to_vec()
                        .expect("synthetic transactions have serializable fields"),
                    block: Some(crate::Checkpoint {
                        height: height as u32,
                        hash: Hex(block.hash().bytes_in_display_order()),
                    }),
                }));
            }
        }
        Ok(self.pool.get(&id).map(|tx| LocatedTransaction {
            bytes: tx
                .zcash_serialize_to_vec()
                .expect("synthetic transactions have serializable fields"),
            block: None,
        }))
    }
    fn submit(&mut self, bytes: &[u8]) -> Result<Hex<32>, Error> {
        if let Some(path) = &self.journal {
            let persisted = archive::durable_records(path);
            let records: Vec<_> = persisted
                .iter()
                .filter(|r| r["signed_transaction_hex"] == hex::encode(bytes))
                .collect();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["state"], "submission_unknown");
        }
        let tx = Arc::new(proposal::decode_transaction(bytes)?);
        let id = txid(&tx);
        self.sent.push(bytes.to_vec());
        if !self.fail_submit || self.accept_before_failure {
            self.pool.insert(id, tx);
        }
        if self.fail_submit {
            Err(Error::HistoryUnavailable)
        } else {
            Ok(id)
        }
    }
}

#[test]
fn published_proposals_and_partials_remain_canonical() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    for row in corpus["proposals"].as_array().unwrap() {
        let bytes = row["proposal_json"].as_str().unwrap().as_bytes();
        let proposal = Proposal::from_json(bytes).unwrap();
        assert_eq!(proposal.to_json().unwrap(), bytes);
        assert_eq!(hex::encode(proposal.id().unwrap().0), row["proposal_id"]);
        assert!(Proposal::from_json(&[bytes, b"\n"].concat()).is_err());
        let mut duplicate = proposal.clone();
        duplicate.inputs.push(duplicate.inputs[0].clone());
        let mut tx = proposal.transaction().unwrap();
        let input = tx.inputs()[0].clone();
        review::inputs_mut(&mut tx).unwrap().push(input);
        duplicate.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
        assert!(matches!(duplicate.transaction(), Err(Error::InputContext)));
        let mut huge = proposal.clone();
        huge.transaction_hex = "00".repeat(MAX_TRANSACTION + 1);
        assert!(matches!(huge.transaction(), Err(Error::Limits)));
    }
    let bytes = corpus["partial_json"].as_str().unwrap().as_bytes();
    assert_eq!(Partial::from_json(bytes).unwrap().to_json().unwrap(), bytes);
    assert!(Partial::from_json(&vec![b' '; MAX_PARTIAL + 1]).is_err());
}

#[test]
fn single_signer_versions_have_exact_fees_native_change_and_durable_submission() {
    for version in [5, 6] {
        let wallets = wallets(1, 1, 3);
        let wallet = &wallets[0];
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store");
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[800_000, 2_000_000]);
        source.journal = Some(path.join("state.json"));
        let intent = intent(version);
        let (proposal, review) = store.prepare_payment(wallet, &mut source, &intent).unwrap();
        assert_eq!(review.input_value, 2_000_000); // deterministic largest first
        assert_eq!(review.fee, 21_600);
        assert_eq!(review.change_value, 1_478_400);
        assert_eq!(proposal.outputs[1].entry.as_ref().unwrap().role, 1);
        let partials = store
            .sign_payment(wallet, &mut source, &proposal, &intent, review.proposal_id)
            .unwrap();
        let bytes = store
            .assemble_payment(wallet, &mut source, &proposal, &intent, &partials)
            .unwrap();
        assert_eq!(bytes.len(), review.final_bytes);
        assert_eq!(
            store
                .sign_payment(wallet, &mut source, &proposal, &intent, review.proposal_id)
                .unwrap(),
            partials
        );
        drop(store);
        let mut store = WatchStore::open(&path, &profile()).unwrap();
        let id = store
            .submit_payment(wallet, &mut source, review.proposal_id)
            .unwrap();
        assert_eq!(source.sent, [bytes]);
        assert_eq!(
            store
                .submit_payment(wallet, &mut source, review.proposal_id)
                .unwrap(),
            id
        );
        assert_eq!(source.sent.len(), 1);
        source.mine();
        assert_eq!(
            store.reconcile_payments(&mut source).unwrap(),
            [PaymentState::Confirmed]
        );
        assert_eq!(
            store.sync(&mut source, 10).unwrap().confirmed_zatoshis,
            Some(2_278_400)
        );
        let (_, second) = store.prepare_payment(wallet, &mut source, &intent).unwrap();
        assert_ne!(review.change_receiver, second.change_receiver);
        assert_eq!(store.state.payments.change_next, 2);
    }
}

#[test]
fn separate_two_of_three_signers_reject_foreign_duplicate_and_invalid_partials() {
    for version in [5, 6] {
        let wallets = wallets(3, 1, 2);
        let temp = tempfile::tempdir().unwrap();
        let mut stores: Vec<_> = wallets
            .iter()
            .enumerate()
            .map(|(i, w)| {
                create(
                    &temp.path().join(i.to_string()),
                    w.manifest(),
                    WatchMode::Allocator,
                )
            })
            .collect();
        let mut source = Source::funded(&wallets[0], &[2_000_000]);
        let intent = intent(version);
        let (proposal, review) = stores[0]
            .prepare_payment(&wallets[0], &mut source, &intent)
            .unwrap();
        assert_eq!(review.fee, 42_800);
        assert_eq!(review.checks, 2);
        let mut partials = Vec::new();
        for i in [0, 2] {
            assert_eq!(
                stores[i]
                    .review_payment(&wallets[i], &mut source, &proposal, &intent)
                    .unwrap(),
                review
            );
            partials.extend(
                stores[i]
                    .sign_payment(
                        &wallets[i],
                        &mut source,
                        &proposal,
                        &intent,
                        review.proposal_id,
                    )
                    .unwrap(),
            );
        }
        let valid = partials.clone();
        for mutation in 0..6 {
            let mut bad = valid.clone();
            match mutation {
                0 => bad[1] = bad[0].clone(),
                1 => bad[0].proposal_id.0[0] ^= 1,
                2 => bad[0].input_index = 1,
                3 => {
                    let replacement = if bad[0].signature_hex.starts_with("00") {
                        "01"
                    } else {
                        "00"
                    };
                    bad[0].signature_hex.replace_range(..2, replacement);
                }
                4 => bad[0].public_key_hex = valid[1].public_key_hex.clone(),
                _ => {
                    bad.pop();
                }
            }
            assert!(stores[0]
                .assemble_payment(&wallets[0], &mut source, &proposal, &intent, &bad)
                .is_err());
        }
        partials.reverse();
        let signed = stores[0]
            .assemble_payment(&wallets[0], &mut source, &proposal, &intent, &partials)
            .unwrap();
        assert_eq!(signed.len(), review.final_bytes);
        assert_eq!(
            stores[0]
                .assemble_payment(&wallets[0], &mut source, &proposal, &intent, &valid)
                .unwrap(),
            signed
        );
        assert!(stores[1].payments().unwrap().is_empty());
        // A third participant can assemble the other quorum's signatures.
        // Adding its own local partial later must not downgrade the durable
        // fully signed record or replace the saved retry bytes.
        assert_eq!(
            stores[1]
                .assemble_payment(&wallets[1], &mut source, &proposal, &intent, &valid)
                .unwrap(),
            signed
        );
        stores[1]
            .sign_payment(
                &wallets[1],
                &mut source,
                &proposal,
                &intent,
                review.proposal_id,
            )
            .unwrap();
        let record = &stores[1].payments().unwrap()[0];
        assert_eq!(record.state, PaymentState::Signed);
        assert_eq!(
            record.signed_transaction_hex.as_deref(),
            Some(hex::encode(&signed).as_str())
        );
    }
}

#[test]
fn review_rechecks_intent_trusted_inputs_policy_and_current_ancestry() {
    let wallets = wallets(1, 1, 2);
    let wallet = &wallets[0];
    let temp = tempfile::tempdir().unwrap();
    let mut store = create(
        &temp.path().join("store"),
        wallet.manifest(),
        WatchMode::Allocator,
    );
    let mut source = Source::funded(wallet, &[2_000_000]);
    let intent = intent(6);
    let (proposal, _) = store.prepare_payment(wallet, &mut source, &intent).unwrap();
    source.corrupt_value = true;
    assert!(matches!(
        store.review_payment(wallet, &mut source, &proposal, &intent),
        Err(Error::InputContext)
    ));
    source.corrupt_value = false;
    let mut wrong = intent.clone();
    wrong.amount += 1;
    assert!(matches!(
        store.review_payment(wallet, &mut source, &proposal, &wrong),
        Err(Error::ProposalMismatch)
    ));
    wrong = intent.clone();
    wrong.max_fee = 21_599;
    assert!(matches!(
        store.review_payment(wallet, &mut source, &proposal, &wrong),
        Err(Error::Fee)
    ));
    wrong = intent.clone();
    wrong.version = Some(5);
    assert!(matches!(
        store.review_payment(wallet, &mut source, &proposal, &wrong),
        Err(Error::UnsupportedContext)
    ));
    let mut changed = proposal.clone();
    changed.tip.hash.0[0] ^= 1;
    assert!(matches!(
        store.review_payment(wallet, &mut source, &changed, &intent),
        Err(Error::ChainChanged)
    ));
    changed = proposal.clone();
    changed.inputs[0].entry.origins[0].wallet_id.0[0] ^= 1;
    assert!(matches!(
        store.review_payment(wallet, &mut source, &changed, &intent),
        Err(Error::Policy)
    ));
    source.mine(); // Ancestor proposal remains valid across an ordinary new block.
    store
        .review_payment(wallet, &mut source, &proposal, &intent)
        .unwrap();
    assert!(matches!(
        store.sign_payment(wallet, &mut source, &proposal, &intent, Hex([0; 32])),
        Err(Error::ProposalMismatch)
    ));
    source.unavailable = true;
    assert!(matches!(
        store.sign_payment(
            wallet,
            &mut source,
            &proposal,
            &intent,
            proposal.id().unwrap()
        ),
        Err(Error::HistoryUnavailable)
    ));
    assert!(store.payments().unwrap()[0].partials.is_empty());
}

#[test]
fn remainder_requires_explicit_choice_and_respects_dust_and_fee_ceiling() {
    let wallets = wallets(1, 1, 1);
    let wallet = &wallets[0];
    for remainder in [0, DUST - 1, DUST, 21_599, 21_600] {
        for choice in [Remainder::Reject, Remainder::Keep, Remainder::Fee] {
            let temp = tempfile::tempdir().unwrap();
            let mut store = create(
                &temp.path().join("store"),
                wallet.manifest(),
                WatchMode::Allocator,
            );
            let mut source = Source::funded(wallet, &[521_600 + remainder]);
            let mut intent = intent(6);
            intent.remainder = choice;
            let result = store.prepare_payment(wallet, &mut source, &intent);
            let allowed = remainder == 0
                || remainder >= 21_600
                || choice == Remainder::Fee
                || (remainder >= DUST && choice == Remainder::Keep);
            assert_eq!(result.is_ok(), allowed, "{remainder} {choice:?}");
            if let Ok((proposal, review)) = result {
                let donated = remainder > 0 && remainder < 21_600 && choice == Remainder::Fee;
                assert_eq!(review.fee, 21_600 + if donated { remainder } else { 0 });
                assert_eq!(
                    proposal.outputs.len(),
                    if remainder == 0 || donated { 1 } else { 2 }
                );
                if donated {
                    intent.max_fee = review.fee - 1;
                    assert!(matches!(
                        store.review_payment(wallet, &mut source, &proposal, &intent),
                        Err(Error::Fee)
                    ));
                }
            }
        }
    }
}

struct FailingRng;
impl CryptoRng for FailingRng {}
impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        panic!("fallible RNG required")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("fallible RNG required")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("fallible RNG required")
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        bytes.fill(0x77);
        Err(rand_core::Error::from(
            std::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
        ))
    }
}

#[test]
fn failed_signing_and_submission_keep_reservations_and_retry_exact_bytes() {
    let wallets = wallets(1, 1, 2);
    let wallet = &wallets[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("store");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    let mut source = Source::funded(wallet, &[2_000_000]);
    source.journal = Some(path.join("state.json"));
    let intent = intent(6);
    let (proposal, review) = store.prepare_payment(wallet, &mut source, &intent).unwrap();
    assert!(matches!(
        store.sign_payment_with_rng(
            wallet,
            &mut source,
            &proposal,
            &intent,
            review.proposal_id,
            &mut FailingRng
        ),
        Err(Error::Entropy)
    ));
    drop(store);
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    assert!(store.payments().unwrap()[0].partials.is_empty());
    assert!(matches!(
        store.prepare_payment(wallet, &mut source, &intent),
        Err(Error::Funds)
    ));
    let partials = store
        .sign_payment(wallet, &mut source, &proposal, &intent, review.proposal_id)
        .unwrap();
    let signed = store
        .assemble_payment(wallet, &mut source, &proposal, &intent, &partials)
        .unwrap();
    source.fail_submit = true;
    assert!(matches!(
        store.submit_payment(wallet, &mut source, review.proposal_id),
        Err(Error::SubmissionUnknown)
    ));
    assert_eq!(
        store.reconcile_payments(&mut source).unwrap(),
        [PaymentState::SubmissionUnknown]
    );
    assert!(matches!(
        store.prepare_payment(wallet, &mut source, &intent),
        Err(Error::Funds)
    ));
    drop(store);
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    source.accept_before_failure = true;
    assert!(matches!(
        store.submit_payment(wallet, &mut source, review.proposal_id),
        Err(Error::SubmissionUnknown)
    ));
    assert_eq!(source.sent, [signed.clone(), signed]);
    assert_eq!(
        store.reconcile_payments(&mut source).unwrap(),
        [PaymentState::Pending]
    );
    store
        .submit_payment(wallet, &mut source, review.proposal_id)
        .unwrap();
    assert_eq!(source.sent.len(), 2);
    source.mine();
    assert_eq!(
        store.reconcile_payments(&mut source).unwrap(),
        [PaymentState::Confirmed]
    );
    source.chain.blocks.pop();
    assert_eq!(
        store.reconcile_payments(&mut source).unwrap(),
        [PaymentState::SubmissionUnknown]
    );
    assert!(matches!(
        store.prepare_payment(wallet, &mut source, &intent),
        Err(Error::Funds)
    ));
    let point = proposal.points().unwrap()[0];
    let mut hash = point.txid.0;
    hash.reverse();
    source.chain.push(
        vec![transaction(
            6,
            5,
            vec![OutPoint {
                hash: zakura_chain::transaction::Hash(hash),
                index: point.index,
            }],
            vec![],
        )],
        None,
    );
    assert_eq!(
        store.reconcile_payments(&mut source).unwrap(),
        [PaymentState::Conflicted]
    );
    source.chain.blocks.pop();
    while source.chain.blocks.len() <= review.expiry_height as usize {
        source.mine();
    }
    assert_eq!(
        store.reconcile_payments(&mut source).unwrap(),
        [PaymentState::Expired]
    );
    assert!(matches!(
        store.submit_payment(wallet, &mut source, review.proposal_id),
        Err(Error::Expired)
    ));
    store.prepare_payment(wallet, &mut source, &intent).unwrap();
    source.chain.blocks.truncate(4);
    // Both capabilities reserve the same input again after rollback. Neither
    // can be signed until the overlap is resolved by chain expiry.
    assert!(matches!(
        store.review_payment(wallet, &mut source, &proposal, &intent),
        Err(Error::Reserved)
    ));
    assert!(matches!(
        store.preview_payment_refresh(wallet, &mut source, review.proposal_id),
        Err(Error::Reserved)
    ));
}

#[test]
fn observed_change_and_v1_migration_never_reuse_active_history_addresses() {
    let wallets = wallets(1, 2, 4);
    let wallet = &wallets[0];
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("store");
    let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
    store.receive().unwrap();
    let mut source = Source::funded(wallet, &[2_000_000]);
    let change = transaction(
        6,
        8,
        vec![],
        vec![output(&wallet.manifest.entries[3], 1_000_000)],
    );
    let spent = transaction(
        6,
        9,
        vec![OutPoint {
            hash: change.hash(),
            index: 0,
        }],
        vec![],
    );
    source.chain.push(vec![change, spent], None);
    store.sync(&mut source, 10).unwrap();
    assert_eq!(store.state.payments.change_next, 2);
    drop(store);
    let state_path = path.join("state.json");
    let mut old: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    old["format"] = "ZcashTransparentPQ/watch-state/v1".into();
    old.as_object_mut().unwrap().remove("payments");
    fs::write(&state_path, serde_json::to_vec(&old).unwrap()).unwrap();
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    assert!(!store.status().unwrap().complete_at_checkpoint);
    assert_eq!(
        store.receive().unwrap(),
        wallet.manifest.entries[1].receiver().unwrap()
    );
    store.sync(&mut source, 10).unwrap();
    assert_eq!(store.state.payments.change_next, 2);
    source.chain.blocks.pop();
    store.sync(&mut source, 10).unwrap();
    assert_eq!(store.state.payments.change_next, 2);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &intent(6))
        .unwrap();
    assert_eq!(
        proposal.outputs[1]
            .entry
            .as_ref()
            .unwrap()
            .local(wallet.manifest.wallet_id)
            .unwrap()
            .1
            .index,
        2
    );
}

#[test]
fn payment_state_publication_failure_poisoning_is_recoverable() {
    use crate::watch::StateStage;
    for fail_at in [
        StateStage::FileSync,
        StateStage::Publish,
        StateStage::DirectorySync,
    ] {
        let wallets = wallets(1, 1, 2);
        let wallet = &wallets[0];
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store");
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[2_000_000]);
        let intent = intent(6);
        let (proposal, review) = store.prepare_payment(wallet, &mut source, &intent).unwrap();
        let prepared = store.state.clone();
        let partials = store
            .sign_payment(wallet, &mut source, &proposal, &intent, review.proposal_id)
            .unwrap();
        let candidate = store.state.clone();
        // Replay the final signing publication through each durable-write
        // boundary, starting with the already committed reservation.
        store.commit(prepared).unwrap();
        assert!(store
            .commit_with_hook(candidate, |stage| {
                if stage == fail_at {
                    Err(Error::Storage(std::io::Error::other("injected")))
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
        drop(store);
        let mut store = WatchStore::open(&path, &profile()).unwrap();
        assert_eq!(store.state.payments.change_next, 1);
        assert!(matches!(
            store.prepare_payment(wallet, &mut source, &intent),
            Err(Error::Funds)
        ));
        if fail_at == StateStage::DirectorySync {
            assert_eq!(store.payments().unwrap()[0].partials, partials);
        } else {
            assert!(store.payments().unwrap()[0].partials.is_empty());
        }
        // Complete through the public API after reopening. A directory-sync
        // error can leave the new state installed; reuse its cached signature.
        let recovered = if fail_at == StateStage::DirectorySync {
            store
                .sign_payment_with_rng(
                    wallet,
                    &mut source,
                    &proposal,
                    &intent,
                    review.proposal_id,
                    &mut FailingRng,
                )
                .unwrap()
        } else {
            store
                .sign_payment(wallet, &mut source, &proposal, &intent, review.proposal_id)
                .unwrap()
        };
        store
            .assemble_payment(wallet, &mut source, &proposal, &intent, &recovered)
            .unwrap();
        source.journal = Some(path.join("state.json"));
        store
            .submit_payment(wallet, &mut source, review.proposal_id)
            .unwrap();
        source.mine();
        assert_eq!(
            store.reconcile_payments(&mut source).unwrap(),
            [PaymentState::Confirmed]
        );
    }
}

#[test]
fn maturity_activation_monitor_and_check_limits_fail_closed() {
    let mut wallets = wallets(3, 1, 1);
    let wallet = &mut wallets[0];
    wallet.manifest.profile.max_tx_pq_checks = 1;
    let temp = tempfile::tempdir().unwrap();
    let mut store = create(
        &temp.path().join("budget"),
        wallet.manifest(),
        WatchMode::Allocator,
    );
    let mut source = Source::funded(wallet, &[2_000_000]);
    assert!(store
        .prepare_payment(wallet, &mut source, &intent(6))
        .is_err());
    let mut monitor = create(
        &temp.path().join("monitor"),
        wallet.manifest(),
        WatchMode::Monitor,
    );
    assert!(matches!(
        monitor.prepare_payment(wallet, &mut source, &intent(6)),
        Err(Error::MonitorOnly)
    ));
    wallet.manifest.profile.max_tx_pq_checks = 15;
    let mut store = create(
        &temp.path().join("active"),
        wallet.manifest(),
        WatchMode::Allocator,
    );
    source.chain.blocks.truncate(3);
    assert!(matches!(
        store.prepare_payment(wallet, &mut source, &intent(6)),
        Err(Error::UnsupportedContext)
    ));
    source
        .chain
        .push(vec![], Some(output(&wallet.manifest.entries[0], 2_000_000)));
    assert!(matches!(
        store.prepare_payment(wallet, &mut source, &intent(6)),
        Err(Error::Funds)
    ));
    while source.chain.blocks.len() < 103 {
        source.mine();
    }
    store
        .prepare_payment(wallet, &mut source, &intent(6))
        .unwrap();
}

#[test]
fn input_check_and_final_size_boundaries_are_independent() {
    for (n, limit, values, amount, expected_inputs) in [
        (1, 15, vec![200_000; 15], 2_600_000, Some(15)),
        (1, 15, vec![200_000; 16], 2_810_000, None),
        (3, 14, vec![400_000; 8], 2_840_000, None),
        (3, 16, vec![400_000; 8], 2_840_000, Some(8)),
        (3, 16, vec![400_000; 9], 3_200_000, None),
    ] {
        let mut wallets = wallets(n, 1, 1);
        let wallet = &mut wallets[0];
        wallet.manifest.profile.max_tx_pq_checks = limit;
        let temp = tempfile::tempdir().unwrap();
        let mut store = create(
            &temp.path().join("store"),
            wallet.manifest(),
            WatchMode::Allocator,
        );
        let mut source = Source::funded(wallet, &values);
        let mut intent = intent(6);
        intent.amount = amount;
        intent.max_fee = 3_000_000;
        intent.remainder = Remainder::Keep;
        let result = store.prepare_payment(wallet, &mut source, &intent);
        if let Some(count) = expected_inputs {
            let (proposal, review) = result.unwrap();
            assert_eq!(proposal.inputs.len(), count);
            assert!(review.final_bytes <= MAX_TRANSACTION);
            // The limit and estimator also hold after real full assembly.
            let mut partials = store
                .sign_payment(wallet, &mut source, &proposal, &intent, review.proposal_id)
                .unwrap();
            if n == 3 {
                wallets[1].manifest.profile.max_tx_pq_checks = limit;
                let mut cosigner = create(
                    &temp.path().join("cosigner"),
                    wallets[1].manifest(),
                    WatchMode::Allocator,
                );
                partials.extend(
                    cosigner
                        .sign_payment(
                            &wallets[1],
                            &mut source,
                            &proposal,
                            &intent,
                            review.proposal_id,
                        )
                        .unwrap(),
                );
            }
            assert_eq!(
                store
                    .assemble_payment(&wallets[0], &mut source, &proposal, &intent, &partials)
                    .unwrap()
                    .len(),
                review.final_bytes
            );
        } else {
            assert!(result.is_err());
            assert!(store.payments().unwrap().is_empty());
        }
    }
}

#[test]
fn coordinator_cannot_redirect_recipient_or_downgrade_enrolled_change() {
    let mut wallets = wallets(3, 1, 2);
    let wallet = &mut wallets[0];
    // Even a separately enrolled 1-of-1 change policy cannot replace the
    // spending policy's 2-of-3 threshold/participants in a normal payment.
    let key = wallet.key(KeyPath {
        role: Role::Change,
        index: 1,
    });
    wallet.manifest.entries[2] = Entry {
        origins: vec![Origin {
            account: 0,
            index: 1,
            wallet_id: wallet.manifest.wallet_id,
        }],
        policy_hex: hex::encode(
            Policy::new(
                1,
                vec![zakura_pq_slh_dsa_b_exp::codec::key_commitment(
                    key.public_key(),
                )],
            )
            .unwrap()
            .descriptor(),
        ),
        role: 1,
    };
    let temp = tempfile::tempdir().unwrap();
    let mut store = create(
        &temp.path().join("store"),
        wallet.manifest(),
        WatchMode::Allocator,
    );
    let mut source = Source::funded(wallet, &[2_000_000]);
    let intent = intent(6);
    let (proposal, _) = store.prepare_payment(wallet, &mut source, &intent).unwrap();
    let mut changed = proposal.clone();
    let entry = &wallet.manifest.entries[2];
    changed.outputs[1].entry = Some(entry.clone());
    changed.outputs[1].receiver = entry.receiver().unwrap().encode();
    let mut tx = changed.transaction().unwrap_err();
    // Structural mismatch fails before any signing. Then make both the script
    // and its metadata agree: ownership-group review must still reject it.
    assert!(matches!(tx, Error::ProposalMismatch));
    let mut transaction = proposal.transaction().unwrap();
    if let Transaction::V6 { outputs, .. } = &mut transaction {
        outputs[1].lock_script = entry.policy().unwrap().lock_script();
    }
    changed.transaction_hex = hex::encode(transaction.zcash_serialize_to_vec().unwrap());
    tx = store
        .review_payment(wallet, &mut source, &changed, &intent)
        .unwrap_err();
    assert!(matches!(tx, Error::Policy));
    changed = proposal.clone();
    changed.outputs[0].receiver = entry.receiver().unwrap().encode();
    transaction = proposal.transaction().unwrap();
    if let Transaction::V6 { outputs, .. } = &mut transaction {
        outputs[0].lock_script = entry.policy().unwrap().lock_script();
    }
    changed.transaction_hex = hex::encode(transaction.zcash_serialize_to_vec().unwrap());
    assert!(matches!(
        store.review_payment(wallet, &mut source, &changed, &intent),
        Err(Error::ProposalMismatch)
    ));
    assert!(store.payments().unwrap()[0].partials.is_empty());
}

#[test]
fn donation_over_fee_ceiling_continues_selection() {
    for version in [5, 6] {
        for ceiling in [20_399, 20_500, 20_799] {
            let wallets = wallets(1, 1, 2);
            let wallet = &wallets[0];
            let temp = tempfile::tempdir().unwrap();
            let mut store = create(
                &temp.path().join("store"),
                wallet.manifest(),
                WatchMode::Allocator,
            );
            let mut source = Source::funded(wallet, &[520_799, 512_000]);
            let mut approved = intent(version);
            approved.max_fee = ceiling;
            approved.remainder = Remainder::Fee;
            let result = store.prepare_payment(wallet, &mut source, &approved);
            if ceiling == 20_399 {
                assert!(matches!(result, Err(Error::Fee)));
                assert!(store.payments().unwrap().is_empty());
            } else {
                let (proposal, review) = result.unwrap();
                if ceiling == 20_500 {
                    assert_eq!(proposal.inputs.len(), 2);
                    assert_eq!(review.fee, 42_800);
                    assert_eq!(review.change_value, 512_399);
                } else {
                    assert_eq!(proposal.inputs.len(), 1);
                    assert_eq!(review.fee, 20_799);
                    assert_eq!(review.change_value, 0);
                }
            }
        }
    }
}

struct AdvanceAfterScan {
    source: Source,
    contexts: usize,
    advance_at: usize,
    advance: Vec<Arc<Transaction>>,
}
impl ChainSource for AdvanceAfterScan {
    fn context(&mut self) -> Result<NodeContext, Error> {
        self.contexts += 1;
        // sync sees a consistent old tip; the independent review sees an
        // ordinary new block that has already used the proposed change entry.
        if self.contexts == self.advance_at {
            self.source
                .chain
                .push(std::mem::take(&mut self.advance), None);
        }
        self.source.context()
    }
    fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error> {
        self.source.block_hash(height)
    }
    fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
        self.source.block_bytes(hash)
    }
}
impl PaymentSource for AdvanceAfterScan {
    fn resolve(&mut self, point: Outpoint) -> Result<Option<ResolvedInput>, Error> {
        self.source.resolve(point)
    }
    fn transaction(&mut self, id: Hex<32>) -> Result<Option<LocatedTransaction>, Error> {
        self.source.transaction(id)
    }
    fn submit(&mut self, raw: &[u8]) -> Result<Hex<32>, Error> {
        self.source.submit(raw)
    }
}

#[test]
fn all_payment_paths_require_the_reviewed_tip_to_be_scanned() {
    for action in [
        "prepare",
        "prepare_late",
        "review",
        "sign",
        "assemble",
        "submit",
        "preview_refresh",
        "review_refresh",
        "approve_refresh",
    ] {
        let wallets = wallets(3, 1, 2);
        let temp = tempfile::tempdir().unwrap();
        let mut proposer = create(
            &temp.path().join("proposer"),
            wallets[0].manifest(),
            WatchMode::Allocator,
        );
        let mut signer = create(
            &temp.path().join("signer"),
            wallets[1].manifest(),
            WatchMode::Allocator,
        );
        let mut third = create(
            &temp.path().join("third"),
            wallets[2].manifest(),
            WatchMode::Allocator,
        );
        let mut source = Source::funded(&wallets[0], &[2_000_000]);
        let approved = intent(6);
        let (proposal, review) = proposer
            .prepare_payment(&wallets[0], &mut source, &approved)
            .unwrap();
        let mut partials = proposer
            .sign_payment(
                &wallets[0],
                &mut source,
                &proposal,
                &approved,
                review.proposal_id,
            )
            .unwrap();
        partials.extend(
            third
                .sign_payment(
                    &wallets[2],
                    &mut source,
                    &proposal,
                    &approved,
                    review.proposal_id,
                )
                .unwrap(),
        );
        proposer
            .assemble_payment(&wallets[0], &mut source, &proposal, &approved, &partials)
            .unwrap();
        let change = proposal.outputs[1].entry.as_ref().unwrap();
        let used = transaction(6, 50, vec![], vec![output(change, 2_000_000)]);
        let mut advancing = AdvanceAfterScan {
            source,
            contexts: 0,
            advance: vec![used],
            advance_at: if matches!(action, "submit" | "prepare_late") {
                5
            } else {
                3
            },
        };
        let original = proposer.payments().unwrap()[0]
            .signed_transaction_hex
            .clone();
        let result = match action {
            "prepare" | "prepare_late" => signer
                .prepare_payment(&wallets[1], &mut advancing, &approved)
                .map(|_| ()),
            "review" => signer
                .review_payment(&wallets[1], &mut advancing, &proposal, &approved)
                .map(|_| ()),
            "sign" => signer
                .sign_payment_with_rng(
                    &wallets[1],
                    &mut advancing,
                    &proposal,
                    &approved,
                    review.proposal_id,
                    &mut FailingRng,
                )
                .map(|_| ()),
            "assemble" => signer
                .assemble_payment(&wallets[1], &mut advancing, &proposal, &approved, &partials)
                .map(|_| ()),
            "submit" => proposer
                .submit_payment(&wallets[0], &mut advancing, review.proposal_id)
                .map(|_| ()),
            "preview_refresh" => proposer
                .preview_payment_refresh(&wallets[0], &mut advancing, review.proposal_id)
                .map(|_| ()),
            "review_refresh" => proposer
                .review_payment_refresh(&wallets[0], &mut advancing, review.proposal_id, &proposal)
                .map(|_| ()),
            "approve_refresh" => proposer
                .approve_payment_refresh(
                    &wallets[0],
                    &mut advancing,
                    review.proposal_id,
                    &proposal,
                    review.proposal_id,
                )
                .map(|_| ()),
            _ => unreachable!(),
        };
        assert!(
            matches!(result, Err(Error::ChainChanged)),
            "{action}: {result:?}"
        );
        assert!(signer.payments().unwrap().is_empty());
        assert!(advancing.source.sent.is_empty());
        assert_eq!(
            proposer.payments().unwrap()[0].proposal.id().unwrap(),
            review.proposal_id
        );
        assert_eq!(
            proposer.payments().unwrap()[0].signed_transaction_hex,
            original
        );
        if action == "sign" {
            // Once scanned, the already used change entry is rejected instead
            // of signing it as a fresh allocation.
            assert!(matches!(
                signer.sign_payment_with_rng(
                    &wallets[1],
                    &mut advancing,
                    &proposal,
                    &approved,
                    review.proposal_id,
                    &mut FailingRng
                ),
                Err(Error::Reserved)
            ));
        }
    }
}

fn replace_tip(source: &mut Source) {
    source.chain.blocks.pop();
    source
        .chain
        .push(vec![transaction(6, 99, vec![], vec![])], None);
}

#[test]
fn approved_tip_refresh_preserves_reservations_and_identical_retry_bytes() {
    for version in [5, 6] {
        let wallets = wallets(1, 1, 2);
        let wallet = &wallets[0];
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("store");
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        let mut source = Source::funded(wallet, &[2_000_000]);
        source.mine(); // The replaced proposal tip does not contain the funding.
        let approved = intent(version);
        let (proposal, review) = store
            .prepare_payment(wallet, &mut source, &approved)
            .unwrap();
        let partials = store
            .sign_payment(
                wallet,
                &mut source,
                &proposal,
                &approved,
                review.proposal_id,
            )
            .unwrap();
        let signed = store
            .assemble_payment(wallet, &mut source, &proposal, &approved, &partials)
            .unwrap();
        source.fail_submit = true;
        assert!(matches!(
            store.submit_payment(wallet, &mut source, review.proposal_id),
            Err(Error::SubmissionUnknown)
        ));
        replace_tip(&mut source);
        assert!(matches!(
            store.submit_payment(wallet, &mut source, review.proposal_id),
            Err(Error::ChainChanged)
        ));
        let (refreshed, new_review) = store
            .preview_payment_refresh(wallet, &mut source, review.proposal_id)
            .unwrap();
        assert_ne!(new_review.proposal_id, review.proposal_id);
        assert_eq!(refreshed.transaction_hex, proposal.transaction_hex);
        assert_eq!(new_review.expiry_height, review.expiry_height);
        assert_eq!(store.payments().unwrap()[0].proposal, proposal);
        assert!(matches!(
            store.prepare_payment(wallet, &mut source, &approved),
            Err(Error::Funds)
        ));
        assert!(matches!(
            store.approve_payment_refresh(
                wallet,
                &mut source,
                review.proposal_id,
                &refreshed,
                review.proposal_id
            ),
            Err(Error::ProposalMismatch)
        ));
        // Renewing metadata cannot smuggle changed effects, origins or expiry.
        for mutation in 0..3 {
            let mut changed = refreshed.clone();
            if mutation == 0 {
                changed.inputs[0].entry.origins[0].wallet_id.0[0] ^= 1;
            } else {
                let mut tx = changed.transaction().unwrap();
                let (expiry, outputs) = match &mut tx {
                    Transaction::V5 {
                        expiry_height,
                        outputs,
                        ..
                    }
                    | Transaction::V6 {
                        expiry_height,
                        outputs,
                        ..
                    } => (expiry_height, outputs),
                    _ => unreachable!(),
                };
                if mutation == 1 {
                    expiry.0 += 1;
                } else {
                    outputs[0].value = (u64::from(outputs[0].value) + 1).try_into().unwrap();
                }
                changed.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
            }
            assert!(matches!(
                store.approve_payment_refresh(
                    wallet,
                    &mut source,
                    review.proposal_id,
                    &changed,
                    changed.id().unwrap()
                ),
                Err(Error::ProposalMismatch)
            ));
            assert_eq!(store.payments().unwrap()[0].proposal, proposal);
        }
        store
            .approve_payment_refresh(
                wallet,
                &mut source,
                review.proposal_id,
                &refreshed,
                new_review.proposal_id,
            )
            .unwrap();
        assert_eq!(store.payments().unwrap().len(), 1);
        assert_eq!(store.state.payments.change_next, 1);
        assert_eq!(
            store.payments().unwrap()[0].state,
            PaymentState::SubmissionUnknown
        );
        assert_eq!(
            store.payments().unwrap()[0]
                .signed_transaction_hex
                .as_deref(),
            Some(hex::encode(&signed).as_str())
        );
        let updated = store
            .sign_payment_with_rng(
                wallet,
                &mut source,
                &refreshed,
                &approved,
                new_review.proposal_id,
                &mut FailingRng,
            )
            .unwrap();
        assert_eq!(updated[0].proposal_id, new_review.proposal_id);
        assert_eq!(updated[0].public_key_hex, partials[0].public_key_hex);
        assert_eq!(updated[0].signature_hex, partials[0].signature_hex);
        assert!(matches!(
            store.assemble_payment(wallet, &mut source, &refreshed, &approved, &partials),
            Err(Error::ProposalMismatch)
        ));
        assert_eq!(
            store
                .assemble_payment(wallet, &mut source, &refreshed, &approved, &updated)
                .unwrap(),
            signed
        );
        drop(store);
        let mut store = WatchStore::open(&path, &profile()).unwrap();
        assert!(matches!(
            store.prepare_payment(wallet, &mut source, &approved),
            Err(Error::Funds)
        ));
        source.fail_submit = false;
        assert!(matches!(
            store.submit_payment(wallet, &mut source, review.proposal_id),
            Err(Error::ProposalMismatch)
        ));
        store
            .submit_payment(wallet, &mut source, new_review.proposal_id)
            .unwrap();
        assert_eq!(source.sent, [signed.clone(), signed]);
        source.mine();
        assert_eq!(
            store.reconcile_payments(&mut source).unwrap(),
            [PaymentState::Confirmed]
        );
    }
}

#[test]
fn separate_cosigners_refresh_cached_partials_without_new_signatures() {
    for version in [5, 6] {
        let wallets = wallets(3, 1, 2);
        let temp = tempfile::tempdir().unwrap();
        let mut stores: Vec<_> = wallets
            .iter()
            .enumerate()
            .map(|(i, w)| {
                create(
                    &temp.path().join(i.to_string()),
                    w.manifest(),
                    WatchMode::Allocator,
                )
            })
            .collect();
        let mut source = Source::funded(&wallets[0], &[2_000_000]);
        source.mine();
        let approved = intent(version);
        let (proposal, review) = stores[0]
            .prepare_payment(&wallets[0], &mut source, &approved)
            .unwrap();
        let mut partials = Vec::new();
        for i in [0, 2] {
            partials.extend(
                stores[i]
                    .sign_payment(
                        &wallets[i],
                        &mut source,
                        &proposal,
                        &approved,
                        review.proposal_id,
                    )
                    .unwrap(),
            );
        }
        let signed = stores[0]
            .assemble_payment(&wallets[0], &mut source, &proposal, &approved, &partials)
            .unwrap();
        replace_tip(&mut source);
        let (refreshed, new_review) = stores[0]
            .preview_payment_refresh(&wallets[0], &mut source, review.proposal_id)
            .unwrap();
        let mut updated = Vec::new();
        for i in [0, 2] {
            let independent = stores[i]
                .review_payment_refresh(&wallets[i], &mut source, review.proposal_id, &refreshed)
                .unwrap();
            assert_eq!(independent, new_review);
            assert_eq!(stores[i].payments().unwrap()[0].proposal, proposal);
            stores[i]
                .approve_payment_refresh(
                    &wallets[i],
                    &mut source,
                    review.proposal_id,
                    &refreshed,
                    new_review.proposal_id,
                )
                .unwrap();
            updated.extend(
                stores[i]
                    .sign_payment_with_rng(
                        &wallets[i],
                        &mut source,
                        &refreshed,
                        &approved,
                        new_review.proposal_id,
                        &mut FailingRng,
                    )
                    .unwrap(),
            );
            assert_eq!(stores[i].state.payments.change_next, 1);
        }
        // A cosigner may review the same refreshed proposal at a later scanned
        // descendant, without inventing another proposal identity.
        source.mine();
        let later = stores[2]
            .review_payment_refresh(&wallets[2], &mut source, new_review.proposal_id, &refreshed)
            .unwrap();
        assert_eq!(later.proposal_id, new_review.proposal_id);
        assert_ne!(later.tip, new_review.tip);
        for (old, new) in partials.iter().zip(&updated) {
            assert_eq!(old.signature_hex, new.signature_hex);
            assert_eq!(old.signer_index, new.signer_index);
        }
        assert_eq!(
            stores[0]
                .assemble_payment(&wallets[0], &mut source, &refreshed, &approved, &updated)
                .unwrap(),
            signed
        );
        assert!(stores[1].payments().unwrap().is_empty());
    }
}

#[test]
fn refresh_cannot_revive_expiry_or_accept_corrupt_cached_authorization() {
    let wallets = wallets(1, 1, 2);
    let wallet = &wallets[0];
    let temp = tempfile::tempdir().unwrap();
    let mut store = create(
        &temp.path().join("store"),
        wallet.manifest(),
        WatchMode::Allocator,
    );
    let mut source = Source::funded(wallet, &[2_000_000]);
    let approved = intent(6);
    let (proposal, review) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    store
        .sign_payment(
            wallet,
            &mut source,
            &proposal,
            &approved,
            review.proposal_id,
        )
        .unwrap();
    source.mine();
    let (refreshed, new_review) = store
        .preview_payment_refresh(wallet, &mut source, review.proposal_id)
        .unwrap();
    let mut candidate = store.state.clone();
    let signature = &mut candidate.payments.records[0].partials[0].signature_hex;
    let replacement = if signature.starts_with("00") {
        "01"
    } else {
        "00"
    };
    signature.replace_range(..2, replacement);
    store.commit(candidate).unwrap();
    assert!(matches!(
        store.approve_payment_refresh(
            wallet,
            &mut source,
            review.proposal_id,
            &refreshed,
            new_review.proposal_id
        ),
        Err(Error::Authorization(_))
    ));
    assert_eq!(store.payments().unwrap()[0].proposal, proposal);
    while source.chain.blocks.len() <= review.expiry_height as usize {
        source.mine();
    }
    assert!(matches!(
        store.preview_payment_refresh(wallet, &mut source, review.proposal_id),
        Err(Error::Expired)
    ));
    assert!(matches!(
        store.approve_payment_refresh(
            wallet,
            &mut source,
            review.proposal_id,
            &refreshed,
            new_review.proposal_id
        ),
        Err(Error::Expired)
    ));
    source.chain.blocks.truncate(3);
    assert!(matches!(
        store.preview_payment_refresh(wallet, &mut source, review.proposal_id),
        Err(Error::UnsupportedContext)
    ));
    assert_eq!(store.payments().unwrap()[0].proposal, proposal);
}
