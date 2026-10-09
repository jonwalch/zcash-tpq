//! Coordinator-shaped proposals reach independent review without preparation filters.
use super::*;
use crate::Receiver;
use sha2::{Digest, Sha256};
use zakura_chain::{
    block::Height,
    serialization::ZcashDeserialize,
    transaction::LockTime,
    transparent::{Output, Script},
};

fn outputs_mut(tx: &mut Transaction) -> &mut Vec<Output> {
    match tx {
        Transaction::V5 { outputs, .. } | Transaction::V6 { outputs, .. } => outputs,
        _ => unreachable!(),
    }
}

fn encoded(mut proposal: Proposal, tx: Transaction) -> Proposal {
    proposal.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
    proposal
}

// Independently frame the canonical envelope, including structurally hostile
// proposals which the production id()/to_json() helpers deliberately reject.
fn approval(proposal: &Proposal) -> Hex<32> {
    let mut hash = Sha256::new();
    hash.update(b"ZcashTransparentPQ/wallet-proposal/v1\0");
    hash.update(serde_json::to_vec(proposal).unwrap());
    Hex(hash.finalize().into())
}

fn fixture(
    wallet: &Wallet,
    version: u8,
    entries: &[usize],
    change: usize,
    value: u64,
) -> (Source, Proposal, Intent) {
    let mut source = Source::funded(wallet, &[]);
    source.chain.blocks.pop();
    let funding = transaction(
        6,
        0,
        vec![],
        entries
            .iter()
            .map(|i| output(&wallet.manifest.entries[*i], value))
            .collect(),
    );
    source.chain.push(vec![funding.clone()], None);
    let tip = source.context().unwrap().tip;
    let approved = intent(version);
    let inputs: Vec<_> = entries
        .iter()
        .enumerate()
        .map(|(i, _)| Input::PrevOut {
            outpoint: OutPoint {
                hash: funding.hash(),
                index: i as u32,
            },
            unlock_script: Script::new(&[]),
            sequence: u32::MAX,
        })
        .collect();
    let entry = &wallet.manifest.entries[change];
    let mut tx = review::transaction(
        version,
        inputs,
        vec![
            Output {
                value: approved.amount.try_into().unwrap(),
                lock_script: Script::new(&Receiver::parse(&approved.receiver).unwrap().script()),
            },
            output(entry, value * entries.len() as u64 - approved.amount),
        ],
        tip.height + EXPIRY_BLOCKS,
    )
    .unwrap();
    let fee = review::estimate(
        &tx,
        &entries
            .iter()
            .map(|i| &wallet.manifest.entries[*i])
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .1;
    let change_value = u64::from(tx.outputs()[1].value) - fee;
    outputs_mut(&mut tx)[1].value = change_value.try_into().unwrap();
    let proposal = Proposal {
        format: "ZcashTransparentPQ/proposal/v1".into(),
        inputs: entries
            .iter()
            .enumerate()
            .map(|(i, index)| InputRecord {
                entry: wallet.manifest.entries[*index].clone(),
                spent_output_hex: hex::encode(
                    funding.outputs()[i].zcash_serialize_to_vec().unwrap(),
                ),
            })
            .collect(),
        outputs: vec![
            OutputRecord {
                entry: None,
                kind: "payment".into(),
                receiver: approved.receiver.clone(),
            },
            OutputRecord {
                entry: Some(entry.clone()),
                kind: "change".into(),
                receiver: entry.receiver().unwrap().encode(),
            },
        ],
        profile: wallet.manifest.profile.clone(),
        tip,
        transaction_hex: hex::encode(tx.zcash_serialize_to_vec().unwrap()),
    };
    assert_eq!(proposal.id().unwrap(), approval(&proposal));
    (source, proposal, approved)
}

struct Signer<'a> {
    wallet: &'a Wallet,
    path: PathBuf,
    store: WatchStore,
}
impl<'a> Signer<'a> {
    fn new(wallet: &'a Wallet, path: PathBuf, source: &mut impl PaymentSource) -> Self {
        let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
        assert!(store.sync(source, 1000).unwrap().complete_at_checkpoint);
        Self {
            wallet,
            path,
            store,
        }
    }
    fn reject(
        mut self,
        source: &mut impl PaymentSource,
        proposal: &Proposal,
        intent: &Intent,
        expected: Error,
        name: &str,
    ) -> Self {
        let state = serde_json::to_vec(&self.store.state).unwrap();
        let disk = fs::read(self.path.join("state.json")).unwrap();
        for error in [
            self.store
                .review_payment(self.wallet, source, proposal, intent)
                .expect_err("PQ hostile guard: review unexpectedly accepted"),
            self.store
                .sign_payment_with_rng(
                    self.wallet,
                    source,
                    proposal,
                    intent,
                    approval(proposal),
                    &mut FailingRng,
                )
                .expect_err("PQ hostile guard: signing unexpectedly accepted"),
        ] {
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected),
                "PQ hostile guard {name}: {error:?}"
            );
        }
        assert_eq!(
            serde_json::to_vec(&self.store.state).unwrap(),
            state,
            "{name} changed memory"
        );
        assert_eq!(
            fs::read(self.path.join("state.json")).unwrap(),
            disk,
            "{name} changed disk"
        );
        drop(self.store);
        self.store = WatchStore::open(&self.path, &self.wallet.manifest.profile).unwrap();
        assert_eq!(serde_json::to_vec(&self.store.state).unwrap(), state);
        self
    }
}

fn complete(
    owners: &[Wallet],
    signer: &mut Signer<'_>,
    source: &mut Source,
    proposal: &Proposal,
    approved: &Intent,
) {
    signer
        .store
        .review_payment(signer.wallet, source, proposal, approved)
        .unwrap();
    let id = proposal.id().unwrap();
    let mut partials = signer
        .store
        .sign_payment(signer.wallet, source, proposal, approved, id)
        .unwrap();
    if owners.len() > 1 {
        let path = signer.path.with_extension("cosigner");
        let mut other = create(&path, owners[1].manifest(), WatchMode::Allocator);
        partials.extend(
            other
                .sign_payment(&owners[1], source, proposal, approved, id)
                .unwrap(),
        );
    }
    let bytes = signer
        .store
        .assemble_payment(signer.wallet, source, proposal, approved, &partials)
        .unwrap();
    signer
        .store
        .submit_payment(signer.wallet, source, id)
        .unwrap();
    assert_eq!(source.sent, [bytes]);
    source.mine();
    assert_eq!(
        signer.store.reconcile_payments(source).unwrap(),
        [PaymentState::Confirmed]
    );
}

#[test]
fn hostile_transaction_shapes_fail_before_signer_state_changes() {
    for version in [5, 6] {
        for n in [1, 3] {
            let owners = wallets(n, 2, 3);
            let wallet = &owners[0];
            let (mut source, proposal, intent) = fixture(wallet, version, &[0], 2, 2_000_000);
            let temp = tempfile::tempdir().unwrap();
            let mut signer = Signer::new(wallet, temp.path().join("signer"), &mut source);
            for case in ["lock time", "sequence", "scriptSig", "v4", "shielded"] {
                let mut tx = proposal.transaction().unwrap();
                let expected = match case {
                    "lock time" => {
                        match &mut tx {
                            Transaction::V5 { lock_time, .. }
                            | Transaction::V6 { lock_time, .. } => {
                                *lock_time = LockTime::Height(Height(1))
                            }
                            _ => unreachable!(),
                        }
                        Error::UnsupportedContext
                    }
                    "sequence" | "scriptSig" => {
                        let Input::PrevOut {
                            sequence,
                            unlock_script,
                            ..
                        } = &mut review::inputs_mut(&mut tx).unwrap()[0]
                        else {
                            unreachable!()
                        };
                        if case == "sequence" {
                            *sequence -= 1;
                        } else {
                            *unlock_script = Script::new(&[0]);
                        }
                        Error::InputContext
                    }
                    "v4" => {
                        tx = Transaction::V4 {
                            inputs: tx.inputs().to_vec(),
                            outputs: tx.outputs().to_vec(),
                            lock_time: LockTime::unlocked(),
                            expiry_height: Height(23),
                            joinsplit_data: None,
                            sapling_shielded_data: None,
                        };
                        Error::UnsupportedContext
                    }
                    _ => {
                        // Attributed historical bytes; only parse the bundle, never generate proofs.
                        let mut bytes = hex::decode(
                            include_str!("../../../../../tests/slh-dsa-b128s/shielded/data/sapling-source.hex")
                                .split_whitespace()
                                .collect::<String>(),
                        )
                        .unwrap();
                        bytes[4..8].copy_from_slice(
                            &zakura_chain::parameters::TX_V6_VERSION_GROUP_ID.to_le_bytes(),
                        );
                        bytes[8..12].copy_from_slice(&0x7719_0ad9u32.to_le_bytes());
                        let Transaction::V6 {
                            sapling_shielded_data: bundle,
                            ..
                        } = Transaction::zcash_deserialize(bytes.as_slice()).unwrap()
                        else {
                            unreachable!()
                        };
                        assert!(bundle.is_some());
                        match &mut tx {
                            Transaction::V5 {
                                sapling_shielded_data,
                                ..
                            }
                            | Transaction::V6 {
                                sapling_shielded_data,
                                ..
                            } => *sapling_shielded_data = bundle,
                            _ => unreachable!(),
                        }
                        Error::UnsupportedContext
                    }
                };
                let bad = encoded(proposal.clone(), tx);
                let error = Proposal::from_json(&serde_json::to_vec(&bad).unwrap())
                    .expect_err("PQ hostile guard: structural proposal unexpectedly accepted");
                assert_eq!(
                    std::mem::discriminant(&error),
                    std::mem::discriminant(&expected),
                    "PQ hostile guard {case}"
                );
                signer = signer.reject(&mut source, &bad, &intent, expected, case);
            }
            complete(&owners, &mut signer, &mut source, &proposal, &intent);
        }
    }
}

struct Resolution<'a> {
    source: &'a mut Source,
    wrong_tip: bool,
    age: Option<u32>,
}
impl ChainSource for Resolution<'_> {
    fn context(&mut self) -> Result<NodeContext, Error> {
        self.source.context()
    }
    fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error> {
        self.source.block_hash(height)
    }
    fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
        self.source.block_bytes(hash)
    }
}
impl PaymentSource for Resolution<'_> {
    fn resolve(&mut self, point: Outpoint) -> Result<Option<ResolvedInput>, Error> {
        let mut resolved = self.source.resolve(point)?.unwrap();
        if self.wrong_tip {
            resolved.tip.hash.0[0] ^= 1;
        }
        if let Some(age) = self.age {
            resolved.coinbase = true;
            resolved.height = resolved.tip.height + 1 - age;
        }
        Ok(Some(resolved))
    }
    fn transaction(&mut self, id: Hex<32>) -> Result<Option<LocatedTransaction>, Error> {
        self.source.transaction(id)
    }
    fn submit(&mut self, raw: &[u8]) -> Result<Hex<32>, Error> {
        self.source.submit(raw)
    }
}

#[test]
fn hostile_resolution_tip_and_maturity_are_independent_signer_checks() {
    let owners = wallets(1, 2, 3);
    let wallet = &owners[0];
    let (mut source, mut proposal, intent) = fixture(wallet, 6, &[0], 2, 2_000_000);
    while source.chain.blocks.len() < 102 {
        source.mine();
    }
    proposal.tip = source.context().unwrap().tip;
    let tx = proposal.transaction().unwrap();
    let tx = review::transaction(
        6,
        tx.inputs().to_vec(),
        tx.outputs().to_vec(),
        proposal.tip.height + EXPIRY_BLOCKS,
    )
    .unwrap();
    proposal = encoded(proposal, tx);
    let temp = tempfile::tempdir().unwrap();
    let signer = Signer::new(wallet, temp.path().join("signer"), &mut source);
    let signer = signer.reject(
        &mut Resolution {
            source: &mut source,
            wrong_tip: true,
            age: None,
        },
        &proposal,
        &intent,
        Error::ChainChanged,
        "resolved tip",
    );
    let mut signer = signer.reject(
        &mut Resolution {
            source: &mut source,
            wrong_tip: false,
            age: Some(99),
        },
        &proposal,
        &intent,
        Error::InputContext,
        "coinbase maturity",
    );
    signer
        .store
        .review_payment(
            wallet,
            &mut Resolution {
                source: &mut source,
                wrong_tip: false,
                age: Some(100),
            },
            &proposal,
            &intent,
        )
        .unwrap();
    complete(&owners, &mut signer, &mut source, &proposal, &intent);
}

#[test]
fn hostile_check_budget_rejects_funded_coherent_proposals() {
    for n in [1, 3] {
        let mut owners = wallets(n, 2, 3);
        for owner in &mut owners {
            owner.manifest.profile.max_tx_pq_checks = if n == 1 { 1 } else { 3 };
        }
        let wallet = &owners[0];
        let (mut source, proposal, intent) = fixture(wallet, 6, &[0, 0], 2, 2_000_000);
        let temp = tempfile::tempdir().unwrap();
        let signer = Signer::new(wallet, temp.path().join("bad"), &mut source);
        signer.reject(
            &mut source,
            &proposal,
            &intent,
            Error::Limits,
            "check budget",
        );
        let (mut source, proposal, intent) = fixture(wallet, 6, &[0], 2, 2_000_000);
        let mut signer = Signer::new(wallet, temp.path().join("good"), &mut source);
        complete(&owners, &mut signer, &mut source, &proposal, &intent);
    }
}

#[test]
fn hostile_mixed_enrolled_input_groups_are_rejected() {
    let mut owners = wallets(3, 2, 3);
    let wallet = &mut owners[0];
    let key = wallet.key(KeyPath {
        role: Role::Receive,
        index: 1,
    });
    wallet.manifest.entries[1] = Entry {
        origins: vec![Origin {
            account: 0,
            index: 1,
            wallet_id: wallet.manifest.wallet_id,
        }],
        role: 0,
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
    };
    wallet.manifest.validate().unwrap();
    let (mut source, proposal, intent) = fixture(wallet, 6, &[0, 1], 2, 2_000_000);
    let temp = tempfile::tempdir().unwrap();
    let signer = Signer::new(wallet, temp.path().join("mixed"), &mut source);
    signer.reject(
        &mut source,
        &proposal,
        &intent,
        Error::Policy,
        "ownership group",
    );
    let (mut source, proposal, intent) = fixture(&owners[0], 6, &[0, 0], 2, 2_000_000);
    let mut signer = Signer::new(&owners[0], temp.path().join("same"), &mut source);
    complete(&owners, &mut signer, &mut source, &proposal, &intent);
}

#[test]
fn change_role_coins_sign_assemble_and_confirm_without_reusing_input_policy() {
    for version in [5, 6] {
        for n in [1, 3] {
            let owners = wallets(n, 2, 3);
            let wallet = &owners[0];
            let (mut source, proposal, intent) = fixture(wallet, version, &[2], 3, 2_000_000);
            assert_eq!(proposal.inputs[0].entry.role, 1);
            let mut bad = proposal.clone();
            let entry = &wallet.manifest.entries[2];
            bad.outputs[1].entry = Some(entry.clone());
            bad.outputs[1].receiver = entry.receiver().unwrap().encode();
            let mut tx = proposal.transaction().unwrap();
            outputs_mut(&mut tx)[1].lock_script = entry.policy().unwrap().lock_script();
            bad = encoded(bad, tx);
            bad.transaction().unwrap();
            let temp = tempfile::tempdir().unwrap();
            let signer = Signer::new(wallet, temp.path().join("signer"), &mut source);
            let mut signer = signer.reject(
                &mut source,
                &bad,
                &intent,
                Error::Policy,
                "reused input change",
            );
            complete(&owners, &mut signer, &mut source, &proposal, &intent);
            drop(signer.store);
            assert_eq!(
                WatchStore::open(&signer.path, &wallet.manifest.profile)
                    .unwrap()
                    .payments()
                    .unwrap()[0]
                    .state,
                PaymentState::Confirmed
            );
        }
    }
}

#[test]
fn hostile_fees_and_lookalike_change_preserve_signer_state() {
    for version in [5, 6] {
        for n in [1, 3] {
            let owners = wallets(n, 2, 3);
            let wallet = &owners[0];
            let (mut source, proposal, intent) = fixture(wallet, version, &[0], 2, 2_000_000);
            let temp = tempfile::tempdir().unwrap();
            let mut signer = Signer::new(wallet, temp.path().join("signer"), &mut source);
            for delta in [1i64, -1] {
                let mut tx = proposal.transaction().unwrap();
                outputs_mut(&mut tx)[1].value = (u64::from(tx.outputs()[1].value) as i64 + delta)
                    .try_into()
                    .unwrap();
                let bad = encoded(proposal.clone(), tx);
                let name = if delta == 1 {
                    "conventional fee"
                } else {
                    "silent donation"
                };
                signer = signer.reject(&mut source, &bad, &intent, Error::Fee, name);
                if delta == -1 {
                    let mut consenting = intent.clone();
                    consenting.remainder = Remainder::Fee;
                    signer
                        .store
                        .review_payment(wallet, &mut source, &bad, &consenting)
                        .unwrap();
                    let mut keep = intent.clone();
                    keep.remainder = Remainder::Keep;
                    signer = signer.reject(&mut source, &bad, &keep, Error::Fee, name);
                }
            }
            let mut entry = wallet.manifest.entries[2].clone();
            let strangers = wallets(n, 2, 3);
            entry.policy_hex = strangers[0].manifest.entries[2].policy_hex.clone();
            let mut bad = proposal.clone();
            bad.outputs[1].entry = Some(entry.clone());
            bad.outputs[1].receiver = entry.receiver().unwrap().encode();
            let mut tx = proposal.transaction().unwrap();
            outputs_mut(&mut tx)[1].lock_script = entry.policy().unwrap().lock_script();
            bad = encoded(bad, tx);
            bad.transaction().unwrap();
            signer = signer.reject(
                &mut source,
                &bad,
                &intent,
                Error::Policy,
                "lookalike change",
            );
            complete(&owners, &mut signer, &mut source, &proposal, &intent);
        }
    }
}

#[test]
fn hostile_dust_change_is_not_masked_by_fee_or_remainder() {
    for (n, fee) in [(1, 21_600), (3, 42_800)] {
        let owners = wallets(n, 2, 3);
        let wallet = &owners[0];
        let temp = tempfile::tempdir().unwrap();
        for dust in [DUST - 1, DUST] {
            let (mut source, proposal, mut intent) =
                fixture(wallet, 6, &[0], 2, 500_000 + fee + dust);
            intent.remainder = Remainder::Keep;
            assert_eq!(
                u64::from(proposal.transaction().unwrap().outputs()[1].value),
                dust
            );
            let mut signer = Signer::new(wallet, temp.path().join(dust.to_string()), &mut source);
            if dust < DUST {
                signer.reject(&mut source, &proposal, &intent, Error::Fee, "dust floor");
            } else {
                complete(&owners, &mut signer, &mut source, &proposal, &intent);
            }
        }
    }
}

#[test]
fn intent_json_amounts_and_fees_have_exact_encoding_and_value_boundaries() {
    let original = intent(6);
    let raw = original.to_json().unwrap();
    assert_eq!(Intent::from_json(&raw).unwrap(), original);
    for field in ["amount", "max_fee"] {
        for representation in ["-1", "1.0", "1e6", "\"1000000\"", "18446744073709551616"] {
            let value = if field == "amount" {
                original.amount
            } else {
                original.max_fee
            };
            let changed = String::from_utf8(raw.clone()).unwrap().replace(
                &format!("\"{field}\":{value}"),
                &format!("\"{field}\":{representation}"),
            );
            assert!(
                matches!(Intent::from_json(changed.as_bytes()), Err(Error::Encoding)),
                "{field}: {representation}"
            );
        }
        for value in [0, (zakura_chain::amount::MAX_MONEY as u64) + 1] {
            let mut changed = serde_json::to_value(&original).unwrap();
            changed[field] = value.into();
            let error = Intent::from_json(&serde_json::to_vec(&changed).unwrap()).unwrap_err();
            let expected = if value == 0 { Error::Fee } else { Error::Funds };
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
        }
        let mut boundary = original.clone();
        if field == "amount" {
            boundary.amount = zakura_chain::amount::MAX_MONEY as u64;
        } else {
            boundary.max_fee = zakura_chain::amount::MAX_MONEY as u64;
        }
        assert_eq!(
            Intent::from_json(&boundary.to_json().unwrap()).unwrap(),
            boundary
        );
    }
    for amount in [DUST - 1, DUST] {
        let mut boundary = serde_json::to_value(&original).unwrap();
        boundary["amount"] = amount.into();
        let result = Intent::from_json(&serde_json::to_vec(&boundary).unwrap());
        if amount < DUST {
            assert!(matches!(result, Err(Error::Fee)));
        } else {
            assert_eq!(result.unwrap().amount, DUST);
        }
    }
}

#[test]
fn input_and_final_size_limits_are_not_hidden_by_fund_selection() {
    let owners = wallets(1, 2, 3);
    let (_, mut proposal, _) = fixture(&owners[0], 6, &[0; MAX_INPUTS], 2, 2_000_000);
    let mut tx = proposal.transaction().unwrap();
    assert_eq!(tx.inputs().len(), MAX_INPUTS);
    let mut extra = tx.inputs()[0].clone();
    let Input::PrevOut { outpoint, .. } = &mut extra else {
        unreachable!()
    };
    outpoint.index = MAX_INPUTS as u32;
    review::inputs_mut(&mut tx).unwrap().push(extra);
    proposal.inputs.push(proposal.inputs[0].clone());
    proposal = encoded(proposal, tx);
    assert!(matches!(proposal.transaction(), Err(Error::Limits)));

    let owners = wallets(3, 2, 3);
    let (_, proposal, _) = fixture(&owners[0], 6, &[0; 8], 2, 2_000_000);
    let mut tx = proposal.transaction().unwrap();
    let entry = &proposal.inputs[0].entry;
    assert!(review::estimate(&tx, &[entry; 8]).unwrap().0 <= MAX_TRANSACTION);
    let input = tx.inputs()[0].clone();
    review::inputs_mut(&mut tx).unwrap().push(input);
    assert!(matches!(
        review::estimate(&tx, &[entry; 9]),
        Err(Error::Limits)
    ));
}
