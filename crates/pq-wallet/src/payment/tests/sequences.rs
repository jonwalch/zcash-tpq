//! Bounded wallet sequences, not a consensus simulator or a randomized CI load.
//! Public test entropy makes keys, proposals and operation choices repeatable.
//! Signing uses OS entropy; retries must preserve the saved signature bytes.
use super::*;
use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};

const VALUES: [u64; 2] = [2_000_000, 1_800_000];

// Deliberately predictable test material. Never use this RNG for a real wallet.
struct TraceRng(u64);
impl CryptoRng for TraceRng {}
impl RngCore for TraceRng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}

struct Approved {
    intent: Intent,
    proposal: Proposal,
    // Expected selection comes from the fixture/trace, never the payment journal.
    coins: Vec<usize>,
    change: usize,
    exported: Vec<Vec<Partial>>,
    assembled: Option<Vec<u8>>,
}
struct Trace {
    seed: u64,
    steps: Vec<String>,
    rng: TraceRng,
    temp: tempfile::TempDir,
    owners: Vec<Wallet>,
    stores: Vec<WatchStore>,
    source: Source,
    intent: Intent,
    approved: Vec<Approved>,
    // Explicit test-side records of requests that reserve funds. There is no
    // model of PaymentState transitions and no call to Book::reserved here.
    reservations: Vec<Vec<usize>>,
    cursors: Vec<u64>,
    submissions: Vec<Vec<u8>>,
}
impl Trace {
    fn new(seed: u64, version: u8, participants: usize) -> Self {
        assert_ne!(seed, 0);
        let mut rng = TraceRng(seed);
        let mut owners = wallets_with_rng(participants, 1, 4, &mut rng);
        owners.truncate(2);
        let recipient = wallets_with_rng(1, 1, 0, &mut rng);
        let intent = Intent {
            amount: 500_000,
            max_fee: 600_000,
            receiver: recipient[0].manifest.entries[0]
                .receiver()
                .unwrap()
                .encode(),
            receiver_activation_height: None,
            remainder: Remainder::Reject,
            version: Some(version),
        };
        let temp = tempfile::tempdir().unwrap();
        let stores = owners
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
        let mut source = Source::funded(&owners[0], &VALUES);
        source.mine(); // A replaceable tip above the funding block.
        source.journal = Some(temp.path().join("0/state.json"));
        Self {
            seed,
            steps: vec![],
            rng,
            temp,
            stores,
            source,
            intent,
            reservations: vec![vec![]; owners.len()],
            cursors: vec![0; owners.len()],
            owners,
            approved: vec![],
            submissions: vec![],
        }
    }
    // Retain reproducible failure diagnostics from the pinned test harness.
    #[allow(clippy::print_stderr)]
    fn step(&mut self, name: impl Into<String>, action: impl FnOnce(&mut Self)) {
        self.steps.push(name.into());
        let result = catch_unwind(AssertUnwindSafe(|| {
            assert!(self.steps.len() <= 12);
            action(self);
            self.audit();
        }));
        if let Err(error) = result {
            eprintln!(
                "wallet sequence seed={:#x}, operations={:#?}",
                self.seed, self.steps
            );
            std::panic::resume_unwind(error);
        }
    }
    fn path(&self, owner: usize) -> PathBuf {
        self.temp.path().join(owner.to_string())
    }
    fn reopen(&mut self) {
        for i in 0..self.stores.len() {
            let before = fs::read(self.path(i).join("state.json")).unwrap();
            drop(self.stores.remove(i));
            self.stores
                .insert(i, WatchStore::open(&self.path(i), &profile()).unwrap());
            assert_eq!(fs::read(self.path(i).join("state.json")).unwrap(), before);
        }
    }
    fn remember_reservation(&mut self, owner: usize, payment: usize) {
        if !self.reservations[owner].contains(&payment) {
            self.reservations[owner].push(payment);
            self.cursors[owner] = self.cursors[owner].max(self.approved[payment].change as u64 + 1);
        }
    }
    fn prepare(&mut self, coins: &[usize], amount: u64) {
        assert!(self.approved.len() < 3);
        let mut intent = self.intent.clone();
        intent.amount = amount;
        let (proposal, review) = self.stores[0]
            .prepare_payment(&self.owners[0], &mut self.source, &intent)
            .unwrap();
        assert_eq!(review.proposal_id, proposal.id().unwrap());
        let payment = self.approved.len();
        self.approved.push(Approved {
            intent,
            proposal,
            coins: coins.to_vec(),
            change: payment,
            exported: vec![vec![]; self.owners.len()],
            assembled: None,
        });
        self.remember_reservation(0, payment);
    }
    fn sign(&mut self, payment: usize, owner: usize) {
        let p = &mut self.approved[payment];
        let partials = self.stores[owner]
            .sign_payment_with_rng(
                &self.owners[owner],
                &mut self.source,
                &p.proposal,
                &p.intent,
                p.proposal.id().unwrap(),
                &mut self.rng,
            )
            .unwrap();
        assert_eq!(partials.len(), p.coins.len());
        if !p.exported[owner].is_empty() {
            assert_eq!(partials, p.exported[owner]);
        }
        p.exported[owner] = partials;
        self.remember_reservation(owner, payment);
    }
    fn randomness_failure(&mut self, payment: usize) {
        let p = &self.approved[payment];
        assert!(p.exported[0].is_empty());
        assert!(matches!(
            self.stores[0].sign_payment_with_rng(
                &self.owners[0],
                &mut self.source,
                &p.proposal,
                &p.intent,
                p.proposal.id().unwrap(),
                &mut FailingRng,
            ),
            Err(Error::Entropy)
        ));
    }
    fn partials(&self, payment: usize) -> Vec<Partial> {
        self.approved[payment]
            .exported
            .iter()
            .flatten()
            .cloned()
            .collect()
    }
    fn reject(&mut self, payment: usize, partials: &[Partial], crypto: bool) {
        let p = &self.approved[payment];
        let before = serde_json::to_value(&self.stores[0].state.payments).unwrap();
        let error = self.stores[0]
            .assemble_payment(
                &self.owners[0],
                &mut self.source,
                &p.proposal,
                &p.intent,
                partials,
            )
            .unwrap_err();
        if crypto {
            assert!(matches!(error, Error::Authorization(_)), "{error:?}");
        } else {
            assert!(matches!(error, Error::ProposalMismatch), "{error:?}");
        }
        assert_eq!(
            serde_json::to_value(&self.stores[0].state.payments).unwrap(),
            before
        );
    }
    fn assemble(&mut self, payment: usize) {
        let mut partials = self.partials(payment);
        partials.reverse(); // Delivery order is independent of signer/input order.
        let p = &mut self.approved[payment];
        let bytes = self.stores[0]
            .assemble_payment(
                &self.owners[0],
                &mut self.source,
                &p.proposal,
                &p.intent,
                &partials,
            )
            .unwrap();
        if let Some(previous) = &p.assembled {
            assert_eq!(&bytes, previous);
        }
        p.assembled = Some(bytes);
    }
    fn submit(&mut self, payment: usize) {
        let p = &self.approved[payment];
        self.stores[0]
            .submit_payment(&self.owners[0], &mut self.source, p.proposal.id().unwrap())
            .unwrap();
        self.submissions.push(p.assembled.clone().unwrap());
    }
    fn audit(&self) {
        let funding = &self.source.chain.blocks[3].transactions[1];
        for p in &self.approved {
            let points: Vec<_> = p
                .coins
                .iter()
                .map(|i| {
                    proposal::point(OutPoint {
                        hash: funding.hash(),
                        index: *i as u32,
                    })
                })
                .collect();
            assert_eq!(p.proposal.points().unwrap(), points);
            for (input, coin) in p.proposal.inputs.iter().zip(&p.coins) {
                let entry = &self.owners[0].manifest.entries[0];
                assert_eq!(&input.entry, entry);
                assert_eq!(
                    input.spent_output_hex,
                    hex::encode(
                        output(entry, VALUES[*coin])
                            .zcash_serialize_to_vec()
                            .unwrap()
                    )
                );
            }
            let tx = p.proposal.transaction().unwrap();
            assert_eq!(tx.version(), u32::from(p.intent.version.unwrap()));
            assert_eq!(tx.outputs().len(), 2);
            assert_eq!(u64::from(tx.outputs()[0].value), p.intent.amount);
            assert_eq!(
                tx.outputs()[0].lock_script.as_raw_bytes(),
                crate::Receiver::parse(&p.intent.receiver).unwrap().script()
            );
            let change = &self.owners[0].manifest.entries[1 + p.change];
            assert_eq!(p.proposal.outputs[1].entry.as_ref(), Some(change));
            assert_eq!(
                tx.outputs()[1].lock_script,
                change.policy().unwrap().lock_script()
            );
            let total: u64 = p.coins.iter().map(|i| VALUES[*i]).sum();
            let fee = total
                .checked_sub(tx.outputs().iter().map(|o| u64::from(o.value)).sum())
                .unwrap();
            assert!(fee > 0 && fee <= p.intent.max_fee);
        }
        for (owner, store) in self.stores.iter().enumerate() {
            let durable: Value =
                serde_json::from_slice(&fs::read(self.path(owner).join("state.json")).unwrap())
                    .unwrap();
            assert_eq!(durable, serde_json::to_value(&store.state).unwrap());
            assert_eq!(store.state.payments.change_next, self.cursors[owner]);
            let records = store.payments().unwrap();
            assert_eq!(records.len(), self.reservations[owner].len());
            for (record, payment) in records.iter().zip(&self.reservations[owner]) {
                let p = &self.approved[*payment];
                assert_eq!(record.proposal, p.proposal);
                assert_eq!(record.intent, p.intent);
                assert_eq!(record.partials, p.exported[owner]);
                assert_eq!(
                    record.signed_transaction_hex,
                    if owner == 0 {
                        p.assembled.as_ref().map(hex::encode)
                    } else {
                        None
                    }
                );
            }
        }
        assert_eq!(self.source.sent, self.submissions);
    }
}

#[test]
fn seeded_competing_proposals_keep_approvals_and_authorization_separate() {
    // Fixed before CI: eight samples, twelve operations, two coins/proposals.
    // Seeds choose early signing order and one isolated routing/crypto attack.
    for sample in 0..8 {
        let seed = 0x5041_5953_4551_0001 + sample;
        let version = 5 + (sample % 2) as u8;
        let participants = if sample % 4 < 2 { 1 } else { 3 };
        let mut t = Trace::new(seed, version, participants);
        let mut choices = TraceRng(seed);
        let first = (choices.next_u64() % 2) as usize;
        let attack = choices.next_u64() % 4;
        t.step("prepare A", |t| t.prepare(&[0], 500_000));
        t.step("prepare B", |t| t.prepare(&[1], 500_000));
        t.step(format!("randomness fails for {first}"), |t| {
            t.randomness_failure(first)
        });
        t.step("reopen both journals", Trace::reopen);
        t.step(format!("first signer signs {first}"), |t| t.sign(first, 0));
        t.step(format!("first signer signs {}", 1 - first), |t| {
            t.sign(1 - first, 0)
        });
        let second = t.owners.len() - 1;
        t.step("second signer A / cached single signature", |t| {
            t.sign(0, second)
        });
        t.step("second signer B / cached single signature", |t| {
            t.sign(1, second)
        });
        t.step(format!("reject partial attack {attack}"), |t| {
            let mut partials = t.partials(0);
            match attack {
                0 | 1 => {
                    partials[0] = t.partials(1)[0].clone();
                    if attack == 1 {
                        // Even a coordinator that repairs routing metadata
                        // cannot transplant a signature for the other coin.
                        partials[0].proposal_id = t.approved[0].proposal.id().unwrap();
                    }
                }
                2 => partials[0].input_index = 1,
                3 => partials[0].signer_index = (partials[0].signer_index + 1) % participants as u8,
                _ => unreachable!(),
            }
            if attack == 3 && participants == 1 {
                partials[0].signer_index = 1;
            }
            t.reject(0, &partials, attack == 1 || attack == 3);
        });
        t.step("assemble B from reversed delivery", |t| t.assemble(1));
        t.step("assemble A from reversed delivery", |t| t.assemble(0));
        t.step("submit A", |t| t.submit(0));
        t.reopen();
        t.audit();
    }
}

#[test]
fn two_input_multisig_rejects_reassigned_and_duplicate_signers_after_reopen() {
    let mut t = Trace::new(0x494e_5055_5453, 6, 3);
    t.step("prepare two-input payment", |t| {
        t.prepare(&[0, 1], 2_700_000)
    });
    t.step("first cosigner", |t| t.sign(0, 0));
    t.step("reopen", Trace::reopen);
    t.step("one signer cannot satisfy quorum", |t| {
        t.reject(0, &t.partials(0), false)
    });
    t.step("second cosigner", |t| t.sign(0, 1));
    t.step("duplicate first signer cannot satisfy quorum", |t| {
        let first = &t.approved[0].exported[0];
        t.reject(0, &[first.clone(), first.clone()].concat(), true);
    });
    t.step("swap valid input indexes of one cosigner", |t| {
        let mut partials = t.partials(0);
        for partial in &mut partials[..2] {
            partial.input_index ^= 1;
        }
        // Each input still has two distinct signer positions and well-formed
        // signatures. Only the signed input binding has changed.
        t.reject(0, &partials, true);
    });
    t.step("complete honest quorum", |t| t.assemble(0));
    t.step("submit", |t| t.submit(0));
    t.step("confirm", |t| {
        t.source.mine();
        assert_eq!(
            t.stores[0].reconcile_payments(&mut t.source).unwrap(),
            [PaymentState::Confirmed]
        );
    });
    t.step("reopen confirmed journal", Trace::reopen);
}

#[test]
fn rollback_reactivates_old_capability_without_freeing_competing_reservations() {
    let mut t = Trace::new(0x4558_5049_5259, 5, 1);
    t.step("prepare A", |t| t.prepare(&[0], 500_000));
    t.step("prepare B", |t| t.prepare(&[1], 500_000));
    t.step("sign A", |t| t.sign(0, 0));
    t.step("assemble A", |t| t.assemble(0));
    t.step("expire A and B", |t| {
        while t.source.chain.blocks.len() <= t.approved[0].proposal.expiry().unwrap() as usize {
            t.source.mine();
        }
        assert_eq!(
            t.stores[0].reconcile_payments(&mut t.source).unwrap(),
            [PaymentState::Expired; 2]
        );
    });
    t.step("prepare replacement C on A's coin", |t| {
        t.prepare(&[0], 500_000)
    });
    t.step("rollback before A's expiry and reopen", |t| {
        t.source.chain.blocks.truncate(5);
        t.reopen();
        // Deliberately keep the stale Expired observations. Signing/refresh
        // must recompute reservations even without an explicit reconciliation.
        assert_eq!(
            t.stores[0]
                .payments()
                .unwrap()
                .iter()
                .map(|r| r.state)
                .collect::<Vec<_>>(),
            [
                PaymentState::Expired,
                PaymentState::Expired,
                PaymentState::Prepared
            ]
        );
    });
    t.step("both overlapping capabilities reject refresh", |t| {
        for i in [0, 2] {
            // C also falls outside the approval horizon after rollback. Its
            // retained reservation must still prevent A from being approved.
            let error = t.stores[0]
                .preview_payment_refresh(
                    &t.owners[0],
                    &mut t.source,
                    t.approved[i].proposal.id().unwrap(),
                )
                .unwrap_err();
            assert!(matches!(
                (i, error),
                (0, Error::Reserved) | (2, Error::ExpiryTooFar)
            ));
        }
        assert!(matches!(
            t.stores[0].prepare_payment(&t.owners[0], &mut t.source, &t.intent),
            Err(Error::Funds)
        ));
        let old = &t.approved[0];
        assert!(matches!(
            t.stores[0].sign_payment_with_rng(
                &t.owners[0],
                &mut t.source,
                &old.proposal,
                &old.intent,
                old.proposal.id().unwrap(),
                &mut FailingRng,
            ),
            Err(Error::Reserved)
        ));
        assert!(matches!(
            t.stores[0].submit_payment(&t.owners[0], &mut t.source, old.proposal.id().unwrap(),),
            Err(Error::Reserved)
        ));
    });
    t.step("expire only the older capabilities again", |t| {
        while t.source.chain.blocks.len() <= t.approved[0].proposal.expiry().unwrap() as usize {
            t.source.mine();
        }
        assert_eq!(
            t.stores[0].reconcile_payments(&mut t.source).unwrap(),
            [
                PaymentState::Expired,
                PaymentState::Expired,
                PaymentState::Prepared
            ]
        );
    });
    t.step("sign replacement", |t| t.sign(2, 0));
    t.step("assemble replacement", |t| t.assemble(2));
    t.step("submit replacement", |t| t.submit(2));
    t.reopen();
    t.audit();
}

#[test]
fn restored_inventory_import_preserves_journal_and_requires_fresh_payment_approval() {
    let mut t = Trace::new(0x0052_4553_544f_5245, 6, 1);
    t.step("prepare before restore", |t| t.prepare(&[0], 500_000));
    t.step("sign before restore", |t| t.sign(0, 0));
    t.step("assemble before restore", |t| t.assemble(0));
    t.step("submit before restore", |t| t.submit(0));
    t.step("confirm before allocator replacement", |t| {
        t.source.mine();
        assert_eq!(
            t.stores[0].reconcile_payments(&mut t.source).unwrap(),
            [PaymentState::Confirmed]
        );
    });
    // Unit restoration begins with authenticated plaintext. Encryption/KDF
    // controls are reused; this is not evidence of recovering a lost journal.
    let mut restored =
        Wallet::from_plaintext(&t.owners[0].plaintext().unwrap(), &profile()).unwrap();
    restored.retire_for_restore_with_rng(&mut t.rng).unwrap();
    let manifest = restored.manifest();
    let bytes = manifest.to_json().unwrap();
    let fingerprint = manifest.fingerprint().unwrap();
    let path = t.path(0);
    let before = fs::read(path.join("state.json")).unwrap();
    let old_approval = t.owners[0].manifest().fingerprint().unwrap();
    assert_ne!(old_approval, fingerprint);
    assert!(matches!(
        t.stores[0].import(&bytes, old_approval),
        Err(Error::Pairing)
    ));
    assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
    t.reopen();
    t.audit();

    let records = serde_json::to_value(t.stores[0].payments().unwrap()).unwrap();
    t.stores[0].import(&bytes, fingerprint).unwrap();
    t.reopen();
    assert_eq!(
        serde_json::to_value(t.stores[0].payments().unwrap()).unwrap(),
        records
    );
    assert_eq!(t.stores[0].receive_next(), 1);
    assert_eq!(t.stores[0].state.payments.change_next, 4);
    assert_eq!(t.stores[0].manifest(), manifest);
    let before = fs::read(path.join("state.json")).unwrap();
    let old = &t.approved[0];
    assert!(matches!(
        t.stores[0].sign_payment_with_rng(
            &restored,
            &mut t.source,
            &old.proposal,
            &old.intent,
            old.proposal.id().unwrap(),
            &mut FailingRng,
        ),
        Err(Error::MonitorOnly)
    ));
    assert!(matches!(
        t.stores[0].submit_payment(&restored, &mut t.source, old.proposal.id().unwrap()),
        Err(Error::MonitorOnly)
    ));
    assert!(matches!(t.stores[0].receive(), Err(Error::MonitorOnly)));
    assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
    assert_eq!(t.source.sent, t.submissions);

    // The old payment is confirmed and its journal is retained as a monitor.
    // The replacement allocator spends the other original coin, with an exact
    // independently approved amount because every old change slot is retired.
    let path = t.temp.path().join("restored");
    let mut store = create(&path, manifest, WatchMode::Allocator);
    store.sync(&mut t.source, 10).unwrap();
    let before = fs::read(path.join("state.json")).unwrap();
    assert!(matches!(
        store.prepare_payment(&restored, &mut t.source, &t.intent),
        Err(Error::Exhausted)
    ));
    assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
    let mut exact = t.intent.clone();
    exact.amount = VALUES[1] - 21_600;
    let (proposal, review) = store
        .prepare_payment(&restored, &mut t.source, &exact)
        .unwrap();
    assert_eq!(proposal.outputs.len(), 1);
    assert_eq!((review.fee, review.change_value), (21_600, 0));
    assert_eq!(
        proposal.points().unwrap(),
        [proposal::point(OutPoint {
            hash: t.source.chain.blocks[3].transactions[1].hash(),
            index: 1,
        })]
    );
    let before = fs::read(path.join("state.json")).unwrap();
    assert!(matches!(
        store.sign_payment_with_rng(
            &restored,
            &mut t.source,
            &proposal,
            &exact,
            old.proposal.id().unwrap(),
            &mut FailingRng,
        ),
        Err(Error::ProposalMismatch)
    ));
    assert_eq!(fs::read(path.join("state.json")).unwrap(), before);
    drop(store);
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    let partials = store
        .sign_payment_with_rng(
            &restored,
            &mut t.source,
            &proposal,
            &exact,
            review.proposal_id,
            &mut t.rng,
        )
        .unwrap();
    let signed = store
        .assemble_payment(&restored, &mut t.source, &proposal, &exact, &partials)
        .unwrap();
    t.source.journal = Some(path.join("state.json"));
    store
        .submit_payment(&restored, &mut t.source, review.proposal_id)
        .unwrap();
    assert_eq!(t.source.sent.last().unwrap(), &signed);
    t.source.mine();
    assert_eq!(
        store.reconcile_payments(&mut t.source).unwrap(),
        [PaymentState::Confirmed]
    );
    assert_eq!(store.state.payments.change_next, 4);
    drop(store);
    assert_eq!(
        WatchStore::open(&path, &profile())
            .unwrap()
            .state
            .payments
            .change_next,
        4
    );
}

#[test]
fn signing_returns_no_partial_when_final_publication_fails_then_retries_after_reopen() {
    // Move the journal directory at the test-only pre-sign checkpoint, after
    // scanning and reservation have published. The actual signer still uses
    // OS entropy. The real final commit now fails opening its old path; the
    // old journal survives, and no production fault hook is exposed.
    struct RelocatingRng {
        rng: TraceRng,
        from: PathBuf,
        to: PathBuf,
        calls: usize,
    }
    impl CryptoRng for RelocatingRng {}
    // Fixture relocation failure must fail the test rather than imitate entropy failure.
    #[allow(clippy::unwrap_in_result)]
    impl RngCore for RelocatingRng {
        fn next_u32(&mut self) -> u32 {
            panic!("must use fallible randomness")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("must use fallible randomness")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("must use fallible randomness")
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
            assert_eq!(self.calls, 0);
            fs::rename(&self.from, &self.to)
                .expect("the test owns an existing private watcher at the original path");
            self.calls += 1;
            self.rng.try_fill_bytes(bytes)
        }
    }
    let mut t = Trace::new(0x0050_5542_4c49_5348, 6, 1);
    t.step("prepare", |t| t.prepare(&[0], 500_000));
    let p = &t.approved[0];
    let before = fs::read(t.path(0).join("state.json")).unwrap();
    let mut rng = RelocatingRng {
        rng: TraceRng(0x4641_494c),
        from: t.path(0),
        to: t.temp.path().join("relocated"),
        calls: 0,
    };
    let error = t.stores[0]
        .sign_payment_with_rng(
            &t.owners[0],
            &mut t.source,
            &p.proposal,
            &p.intent,
            p.proposal.id().unwrap(),
            &mut rng,
        )
        .unwrap_err();
    assert!(matches!(error, Error::Storage(_)), "{error:?}");
    assert_eq!(rng.calls, 1);
    assert!(matches!(t.stores[0].payments(), Err(Error::ReopenRequired)));
    assert_eq!(fs::read(rng.to.join("state.json")).unwrap(), before);
    assert!(t.source.sent.is_empty());
    drop(t.stores.remove(0));
    let mut store = WatchStore::open(&rng.to, &profile()).unwrap();
    assert!(store.payments().unwrap()[0].partials.is_empty());
    assert_eq!(store.state.payments.change_next, 1);
    let partials = store
        .sign_payment_with_rng(
            &t.owners[0],
            &mut t.source,
            &p.proposal,
            &p.intent,
            p.proposal.id().unwrap(),
            &mut t.rng,
        )
        .unwrap();
    let signed = store
        .assemble_payment(
            &t.owners[0],
            &mut t.source,
            &p.proposal,
            &p.intent,
            &partials,
        )
        .unwrap();
    t.source.journal = Some(rng.to.join("state.json"));
    store
        .submit_payment(&t.owners[0], &mut t.source, p.proposal.id().unwrap())
        .unwrap();
    assert_eq!(t.source.sent, [signed]);
    t.source.mine();
    assert_eq!(
        store.reconcile_payments(&mut t.source).unwrap(),
        [PaymentState::Confirmed]
    );
}
