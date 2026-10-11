//! Expiry is an independent signer policy, not coordinator-supplied authority.
use super::*;
use zakura_chain::block::Height;

pub(super) fn with_expiry(proposal: &Proposal, expiry: u32) -> Proposal {
    let mut proposal = proposal.clone();
    let mut tx = proposal.transaction().unwrap();
    match &mut tx {
        Transaction::V5 { expiry_height, .. } | Transaction::V6 { expiry_height, .. } => {
            *expiry_height = Height(expiry);
        }
        _ => unreachable!(),
    }
    proposal.transaction_hex = hex::encode(tx.zcash_serialize_to_vec().unwrap());
    Proposal::from_json(&proposal.to_json().unwrap()).unwrap()
}

#[test]
fn expiry_approval_rejects_an_overflowing_trusted_height_before_input_resolution() {
    struct OverflowingTip(Source);
    impl ChainSource for OverflowingTip {
        fn context(&mut self) -> Result<NodeContext, Error> {
            let mut context = self.0.context()?;
            context.tip.height = u32::MAX;
            Ok(context)
        }
        fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error> {
            self.0.block_hash(height)
        }
        fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
            self.0.block_bytes(hash)
        }
    }
    impl PaymentSource for OverflowingTip {
        fn resolve(&mut self, _: Outpoint) -> Result<Option<ResolvedInput>, Error> {
            panic!("invalid height must fail before resolving inputs")
        }
        fn transaction(&mut self, _: Hex<32>) -> Result<Option<LocatedTransaction>, Error> {
            panic!("review does not locate transactions")
        }
        fn submit(&mut self, _: &[u8]) -> Result<Hex<32>, Error> {
            panic!("review does not submit transactions")
        }
    }
    let owners = wallets(1, 1, 1);
    let wallet = &owners[0];
    let temp = tempfile::tempdir().unwrap();
    let mut store = create(
        &temp.path().join("store"),
        wallet.manifest(),
        WatchMode::Allocator,
    );
    let mut source = Source::funded(wallet, &[2_000_000]);
    let intent = intent(6);
    let (proposal, _) = store.prepare_payment(wallet, &mut source, &intent).unwrap();
    assert!(matches!(
        review::check(
            wallet.manifest(),
            &mut OverflowingTip(source),
            &proposal,
            &intent,
            false,
        ),
        Err(Error::UnsupportedContext)
    ));
}

#[test]
fn distant_expiry_is_rejected_before_any_payment_reservation_or_signature() {
    for version in [5, 6] {
        for participants in [1, 3] {
            let owners = wallets(participants, 1, 1);
            let wallet = &owners[0];
            let temp = tempfile::tempdir().unwrap();
            let mut coordinator = create(
                &temp.path().join("coordinator"),
                wallet.manifest(),
                WatchMode::Allocator,
            );
            let path = temp.path().join("signer");
            let mut signer = create(&path, wallet.manifest(), WatchMode::Allocator);
            let mut source = Source::funded(wallet, &[2_000_000]);
            let intent = intent(version);
            let (proposal, _) = coordinator
                .prepare_payment(wallet, &mut source, &intent)
                .unwrap();
            let tip = source.context().unwrap().tip.height;
            signer.sync(&mut source, 100).unwrap();
            let before = serde_json::to_value(&signer.state).unwrap();
            let durable = fs::read(path.join("state.json")).unwrap();

            for expiry in [tip + 21, Height::MAX_EXPIRY_HEIGHT.0] {
                let changed = with_expiry(&proposal, expiry);
                assert!(matches!(
                    signer.review_payment(wallet, &mut source, &changed, &intent),
                    Err(Error::ExpiryTooFar)
                ));
                assert!(matches!(
                    signer.sign_payment_with_rng(
                        wallet,
                        &mut source,
                        &changed,
                        &intent,
                        changed.id().unwrap(),
                        &mut FailingRng,
                    ),
                    Err(Error::ExpiryTooFar)
                ));
                assert!(matches!(
                    signer.assemble_payment(wallet, &mut source, &changed, &intent, &[]),
                    Err(Error::ExpiryTooFar)
                ));
                assert_eq!(serde_json::to_value(&signer.state).unwrap(), before);
                assert_eq!(fs::read(path.join("state.json")).unwrap(), durable);
                drop(signer);
                signer = WatchStore::open(&path, &profile()).unwrap();
                assert!(signer.payments().unwrap().is_empty());
                assert_eq!(signer.state.payments.change_next, 0);
            }
        }
    }
}

#[test]
fn expiry_boundaries_use_the_current_trusted_tip_not_proposal_metadata() {
    for version in [5, 6] {
        for participants in [1, 3] {
            let owners = wallets(participants, 1, 1);
            let wallet = &owners[0];
            let temp = tempfile::tempdir().unwrap();
            let mut coordinator = create(
                &temp.path().join("coordinator"),
                wallet.manifest(),
                WatchMode::Allocator,
            );
            let mut source = Source::funded(wallet, &[2_000_000]);
            let intent = intent(version);
            let (proposal, _) = coordinator
                .prepare_payment(wallet, &mut source, &intent)
                .unwrap();
            source.mine();
            let tip = source.context().unwrap().tip;
            assert!(proposal.tip.height < tip.height);
            for remaining in [1, 20] {
                let mut signer = create(
                    &temp.path().join(format!("signer-{remaining}")),
                    wallet.manifest(),
                    WatchMode::Allocator,
                );
                let changed = with_expiry(&proposal, tip.height + remaining);
                let reviewed = signer
                    .review_payment(wallet, &mut source, &changed, &intent)
                    .unwrap();
                assert_eq!(reviewed.tip, tip);
                assert_eq!(reviewed.expiry_height, tip.height + remaining);
                let partials = signer
                    .sign_payment(
                        wallet,
                        &mut source,
                        &changed,
                        &intent,
                        changed.id().unwrap(),
                    )
                    .unwrap();
                assert_eq!(partials.len(), changed.inputs.len());
            }
            let expired = with_expiry(&proposal, tip.height);
            assert!(matches!(
                review::check(wallet.manifest(), &mut source, &expired, &intent, false),
                Err(Error::Expired)
            ));
            let mut future_tip = with_expiry(&proposal, tip.height + 21);
            future_tip.tip.height = tip.height + 1;
            assert!(matches!(
                review::check(wallet.manifest(), &mut source, &future_tip, &intent, false),
                Err(Error::ChainChanged)
            ));
        }
    }
}

#[test]
fn expiry_horizon_after_rollback_preserves_signed_capabilities_and_exact_retries() {
    for version in [5, 6] {
        for participants in [1, 3] {
            let owners = wallets(participants, 1, 1);
            let wallet = &owners[0];
            let temp = tempfile::tempdir().unwrap();
            let mut coordinator = create(
                &temp.path().join("coordinator"),
                wallet.manifest(),
                WatchMode::Allocator,
            );
            let mut source = Source::funded(wallet, &[2_000_000]);
            let ancestor = source.context().unwrap().tip;
            source.mine();
            let intent = intent(version);
            let (mut proposal, _) = coordinator
                .prepare_payment(wallet, &mut source, &intent)
                .unwrap();
            // An older, still-connected metadata tip is permitted. It must not
            // determine the expiry horizon or bypass the post-rollback check.
            proposal.tip = ancestor;
            let id = proposal.id().unwrap();
            let count = if participants == 1 { 1 } else { 2 };
            let mut stores: Vec<_> = owners
                .iter()
                .take(count)
                .enumerate()
                .map(|(i, w)| {
                    create(
                        &temp.path().join(format!("signer-{i}")),
                        w.manifest(),
                        WatchMode::Allocator,
                    )
                })
                .collect();
            let mut partials = Vec::new();
            for (store, owner) in stores.iter_mut().zip(&owners) {
                partials.extend(
                    store
                        .sign_payment(owner, &mut source, &proposal, &intent, id)
                        .unwrap(),
                );
            }
            let signed = stores[0]
                .assemble_payment(wallet, &mut source, &proposal, &intent, &partials)
                .unwrap();
            let saved_partials = stores[0].payments().unwrap()[0].partials.clone();
            drop(stores);
            source.chain.blocks.pop();
            let path = temp.path().join("signer-0");
            let mut signer = WatchStore::open(&path, &profile()).unwrap();
            signer.sync(&mut source, 100).unwrap();
            assert_eq!(source.context().unwrap().tip, ancestor);
            let before = serde_json::to_value(&signer.state).unwrap();
            let durable = fs::read(path.join("state.json")).unwrap();

            assert!(matches!(
                signer.review_payment(wallet, &mut source, &proposal, &intent),
                Err(Error::ExpiryTooFar)
            ));
            assert!(matches!(
                signer.sign_payment_with_rng(
                    wallet,
                    &mut source,
                    &proposal,
                    &intent,
                    id,
                    &mut FailingRng,
                ),
                Err(Error::ExpiryTooFar)
            ));
            assert!(matches!(
                signer.assemble_payment(wallet, &mut source, &proposal, &intent, &partials),
                Err(Error::ExpiryTooFar)
            ));
            assert!(matches!(
                signer.preview_payment_refresh(wallet, &mut source, id),
                Err(Error::ExpiryTooFar)
            ));
            assert!(matches!(
                signer.review_payment_refresh(wallet, &mut source, id, &proposal),
                Err(Error::ExpiryTooFar)
            ));
            assert!(matches!(
                signer.approve_payment_refresh(wallet, &mut source, id, &proposal, id),
                Err(Error::ExpiryTooFar)
            ));
            assert!(matches!(
                signer.prepare_payment(wallet, &mut source, &intent),
                Err(Error::Funds)
            ));
            assert_eq!(serde_json::to_value(&signer.state).unwrap(), before);
            assert_eq!(fs::read(path.join("state.json")).unwrap(), durable);
            assert!(matches!(
                signer.submit_payment(wallet, &mut source, id),
                Err(Error::ExpiryTooFar)
            ));
            assert!(source.sent.is_empty());
            assert_eq!(signer.payments().unwrap()[0].partials, saved_partials);
            assert_eq!(
                signer.payments().unwrap()[0].signed_transaction_hex,
                Some(hex::encode(&signed))
            );

            // Returning within the horizon restores ordinary retry behavior,
            // including reuse of the original hedged signatures without RNG.
            source.mine();
            drop(signer);
            let mut signer = WatchStore::open(&path, &profile()).unwrap();
            assert_eq!(
                signer
                    .sign_payment_with_rng(
                        wallet,
                        &mut source,
                        &proposal,
                        &intent,
                        id,
                        &mut FailingRng,
                    )
                    .unwrap(),
                saved_partials
            );
            assert_eq!(
                signer
                    .assemble_payment(wallet, &mut source, &proposal, &intent, &partials)
                    .unwrap(),
                signed
            );
            signer.submit_payment(wallet, &mut source, id).unwrap();
            assert_eq!(source.sent, [signed]);
        }
    }
}
