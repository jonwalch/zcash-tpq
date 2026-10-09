//! Bounded hostile receipts, using synthetic trusted-node history and real PQ signing.
//! Restoration starts at authenticated plaintext; encrypted/live recovery has separate tests.
use super::*;
use crate::Outpoint;
use std::path::Path;

const USABLE: u64 = 2_000_000;
const OTHER_USABLE: u64 = 800_000;

fn participants(n: usize, restored: bool) -> Vec<Wallet> {
    let mut owners = wallets(n, 2, 2);
    // The third cosigner is unavailable. Never weaken its enrolled 2-of-3 policy.
    owners.truncate(2);
    owners
        .into_iter()
        .map(|wallet| {
            if !restored {
                return wallet;
            }
            let mut recovered =
                Wallet::from_plaintext(&wallet.plaintext().unwrap(), &profile()).unwrap();
            recovered.retire_for_restore().unwrap();
            assert_eq!(recovered.manifest.entries, wallet.manifest.entries);
            assert_eq!(recovered.manifest.retired_receive_end, 2);
            assert_eq!(recovered.manifest.retired_change_end, 2);
            recovered
        })
        .collect()
}

fn receipts(wallet: &Wallet, version: u8, usable: bool) -> Source {
    // More tiny outputs than a payment can consume, ordered before usable coins.
    // Include receipts below and above the relay floor, all below spend cost.
    let mut values: Vec<_> = [1, DUST - 1, DUST, 4_000].repeat(4);
    assert!(values.len() > MAX_INPUTS);
    if usable {
        values.extend([OTHER_USABLE, USABLE]);
    }
    let mut source = Source::funded(wallet, &values);
    // A later receipt to another covered receiver must also be discovered after
    // restoration has retired the old issuance ranges.
    source.chain.push(
        vec![transaction(
            version,
            1,
            vec![],
            vec![output(&wallet.manifest.entries[1], DUST)],
        )],
        None,
    );
    source
}

fn snapshot(store: &WatchStore, path: &Path) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(path.join("state.json")).unwrap(),
        serde_json::to_vec(&store.state).unwrap(),
    )
}

fn reopen_unchanged(store: WatchStore, path: &Path, before: &(Vec<u8>, Vec<u8>)) -> WatchStore {
    assert_eq!(&snapshot(&store, path), before);
    drop(store);
    let reopened = WatchStore::open(path, &profile()).unwrap();
    assert_eq!(&snapshot(&reopened, path), before);
    reopened
}

fn complete(
    owners: &[Wallet],
    stores: &mut [WatchStore],
    source: &mut Source,
    proposal: &Proposal,
    approved: &Intent,
    summary: &Review,
) -> Vec<u8> {
    let mut partials = Vec::new();
    for (owner, store) in owners.iter().zip(stores.iter_mut()) {
        assert_eq!(
            store
                .review_payment(owner, source, proposal, approved)
                .unwrap(),
            *summary
        );
        partials.extend(
            store
                .sign_payment(owner, source, proposal, approved, summary.proposal_id)
                .unwrap(),
        );
    }
    assert_eq!(partials.len(), summary.checks as usize);
    // Assembly checks real authorization, transaction size and the pinned fee helper.
    let bytes = stores[0]
        .assemble_payment(&owners[0], source, proposal, approved, &partials)
        .unwrap();
    assert_eq!(bytes.len(), summary.final_bytes);
    bytes
}

#[test]
fn hostile_receipts_leave_normal_and_recovered_funds_spendable() {
    for version in [5, 6] {
        for n in [1, 3] {
            for restored in [false, true] {
                let owners = participants(n, restored);
                let wallet = &owners[0];
                let temp = tempfile::tempdir().unwrap();
                let paths: Vec<_> = (0..owners.len())
                    .map(|i| temp.path().join(i.to_string()))
                    .collect();
                let mut source = receipts(wallet, version, true);
                let mut stores: Vec<_> = owners
                    .iter()
                    .zip(&paths)
                    .map(|(w, path)| {
                        let mut store = create(path, w.manifest(), WatchMode::Allocator);
                        assert!(store.sync(&mut source, 10).unwrap().complete_at_checkpoint);
                        store
                    })
                    .collect();
                assert_eq!(stores[0].coins().len(), 19);
                let tiny: Vec<_> = stores[0]
                    .coins()
                    .iter()
                    .filter(|c| c.value < OTHER_USABLE)
                    .cloned()
                    .collect();
                assert_eq!(tiny.len(), 17);
                assert!(tiny.iter().any(|c| c.index == 1));
                let usable = stores[0]
                    .coins()
                    .iter()
                    .find(|c| c.value == USABLE)
                    .unwrap()
                    .outpoint;
                assert_eq!(stores[0].coins().last().unwrap().outpoint, usable);
                let fee = if n == 1 { 21_600 } else { 42_800 };
                let mut approved = intent(version);
                approved.max_fee = fee;
                if restored {
                    // Old change coordinates cannot be reissued after restoration.
                    approved.amount = USABLE - fee;
                }
                let mut unapproved = approved.clone();
                unapproved.max_fee -= 1;
                let before = snapshot(&stores[0], &paths[0]);
                assert!(matches!(
                    stores[0].prepare_payment(wallet, &mut source, &unapproved),
                    Err(Error::Fee)
                ));
                let store = stores.remove(0);
                stores.insert(0, reopen_unchanged(store, &paths[0], &before));

                let (proposal, summary) = stores[0]
                    .prepare_payment(wallet, &mut source, &approved)
                    .unwrap();
                assert_eq!(proposal.points().unwrap(), [usable]);
                assert_eq!(summary.input_value, USABLE);
                assert_eq!((summary.fee, summary.conventional_fee), (fee, fee));
                assert_eq!(summary.checks, if n == 1 { 1 } else { 2 });
                assert_eq!(summary.change_value, USABLE - approved.amount - fee);
                assert_eq!(proposal.outputs.len(), if restored { 1 } else { 2 });

                // Every signer independently enforces the ceiling even with the
                // correct proposal ID. Failure precedes entropy/signature release.
                for i in 0..owners.len() {
                    let before = snapshot(&stores[i], &paths[i]);
                    assert!(matches!(
                        stores[i].sign_payment_with_rng(
                            &owners[i],
                            &mut source,
                            &proposal,
                            &unapproved,
                            summary.proposal_id,
                            &mut FailingRng,
                        ),
                        Err(Error::Fee)
                    ));
                    let store = stores.remove(i);
                    stores.insert(i, reopen_unchanged(store, &paths[i], &before));
                }
                let signed = complete(
                    &owners,
                    &mut stores,
                    &mut source,
                    &proposal,
                    &approved,
                    &summary,
                );
                stores[0]
                    .submit_payment(wallet, &mut source, summary.proposal_id)
                    .unwrap();
                assert_eq!(source.sent, [signed]);
                source.mine();
                assert_eq!(
                    stores[0].reconcile_payments(&mut source).unwrap(),
                    [PaymentState::Confirmed]
                );
                let status = stores[0].sync(&mut source, 10).unwrap();
                assert_eq!(
                    status.confirmed_zatoshis,
                    Some(
                        tiny.iter().map(|c| c.value).sum::<u64>()
                            + OTHER_USABLE
                            + summary.change_value
                    )
                );
                for coin in &tiny {
                    assert!(stores[0].coins().contains(coin));
                }
                assert!(stores[0].coins().iter().any(|c| c.value == OTHER_USABLE));
                assert!(!stores[0].coins().iter().any(|c| c.outpoint == usable));
            }
        }
    }
}

#[test]
fn hostile_receipts_alone_cannot_fund_or_erase_a_reserved_payment() {
    for version in [5, 6] {
        for n in [1, 3] {
            let owners = participants(n, true);
            let wallet = &owners[0];
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("store");
            let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
            let mut source = receipts(wallet, version, false);
            let status = store.sync(&mut source, 10).unwrap();
            let mut approved = intent(version);
            approved.amount = 10_000;
            approved.max_fee = 3_000_000; // Above every permitted candidate's fee.
            let balance = status.confirmed_zatoshis.unwrap();
            assert!(balance > approved.amount);
            // Every receipt costs more to spend than its own value.
            assert!(store.coins().iter().all(|coin| coin.value < 21_600));
            let before = snapshot(&store, &path);
            let error = store
                .prepare_payment(wallet, &mut source, &approved)
                .unwrap_err();
            assert!(matches!(error, Error::Funds));
            assert_eq!(
                error.to_string(),
                "insufficient eligible funds within the payment limits"
            );
            store = reopen_unchanged(store, &path, &before);
            assert_eq!(store.status().unwrap(), status);
            assert!(source.sent.is_empty());

            // The same wallet succeeds once a usable receipt arrives at a retired
            // receiver; no new inventory or change range is required for an exact payment.
            let fee = if n == 1 { 21_600 } else { 42_800 };
            let funding = transaction(
                version,
                2,
                vec![],
                vec![output(&wallet.manifest.entries[1], approved.amount + fee)],
            );
            let point = Outpoint {
                txid: txid(&funding),
                index: 0,
            };
            source.chain.push(vec![funding], None);
            let (proposal, summary) = store
                .prepare_payment(wallet, &mut source, &approved)
                .unwrap();
            assert_eq!(proposal.points().unwrap(), [point]);
            assert_eq!(summary.fee, fee);
            assert_eq!(summary.change_value, 0);
            let before = snapshot(&store, &path);
            assert!(matches!(
                store.prepare_payment(wallet, &mut source, &approved),
                Err(Error::Funds)
            ));
            store = reopen_unchanged(store, &path, &before);
            assert_eq!(store.payments().unwrap().len(), 1);
            assert_eq!(
                store.payments().unwrap()[0].proposal.id().unwrap(),
                summary.proposal_id
            );
            let mut stores = vec![store];
            for (i, owner) in owners.iter().enumerate().skip(1) {
                stores.push(create(
                    &temp.path().join(i.to_string()),
                    owner.manifest(),
                    WatchMode::Allocator,
                ));
            }
            complete(
                &owners,
                &mut stores,
                &mut source,
                &proposal,
                &approved,
                &summary,
            );
        }
    }
}
