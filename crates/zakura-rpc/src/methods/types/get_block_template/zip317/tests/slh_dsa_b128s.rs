//! Template accounting fixtures stand for completed verifier results; they do
//! not claim valid signatures or proofs. Consensus tests cover real workers.

use std::sync::Arc;

use super::super::{BlockTemplateLimits, SelectedMempoolTx};
use super::*;
use zakura_chain::{
    parameters::{
        testnet::{ConfiguredActivationHeights, ExperimentalSlhDsaB128sLimits, RegtestParameters},
        NetworkUpgrade,
    },
    transaction::{
        arbitrary::{fake_v5_with_sapling_outputs, fake_v6_with_orchard_and_ironwood_actions},
        Transaction, UnminedTx, VerifiedUnminedTx,
    },
    transparent::Input,
};

const SLH_HEIGHT: Height = Height(110);

fn network(block: u32) -> Network {
    profile_network(block.min(16), block)
}

fn profile_network(transaction: u32, block: u32) -> Network {
    Network::new_regtest(RegtestParameters {
        activation_heights: ConfiguredActivationHeights {
            nu6_3: Some(1),
            nu7: Some(105),
            ..Default::default()
        },
        experimental_slh_dsa_b128s_activation_height: Some(SLH_HEIGHT),
        experimental_slh_dsa_b128s_limits: Some(
            ExperimentalSlhDsaB128sLimits::new(transaction, block).unwrap(),
        ),
        ..Default::default()
    })
}

/// The retained signatures are mutated only to construct selection identities.
/// These are trusted-result accounting fixtures, not new signature acceptance
/// claims. Consensus tests separately exercise their original complete bytes.
fn public_fixture(version: u8, case: &str) -> (Transaction, Vec<Output>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/slh-dsa-b128s/fixtures/data")
        .join(format!("v{version}-{case}.json"));
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let bytes = hex::decode(json["transaction_hex"].as_str().unwrap()).unwrap();
    let tx = bytes.as_slice().zcash_deserialize_into().unwrap();
    let previous = json["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let spent = &input["spent_output"];
            Output::new(
                spent["value_zat"].as_u64().unwrap().try_into().unwrap(),
                Script::new(&hex::decode(spent["script_hex"].as_str().unwrap()).unwrap()),
            )
        })
        .collect();
    (tx, previous)
}

fn classical_output() -> Output {
    let mut bytes = vec![0x76, 0xa9, 0x14];
    bytes.extend([3; 20]);
    bytes.extend([0x88, 0xac]);
    Output::new(100_000.try_into().unwrap(), Script::new(&bytes))
}

fn record(network: &Network, tx: Transaction, checks: u32) -> VerifiedUnminedTx {
    let output = if checks == 0 {
        classical_output()
    } else {
        public_fixture(6, "1of1").1[0].clone()
    };
    let spent = Arc::new(vec![output; tx.inputs().len()]);
    let tx = UnminedTx::from(tx);
    let fee = tx.conventional_fee();
    VerifiedUnminedTx::new(tx, fee, 0, 0, spent)
        .unwrap()
        .with_verified_slh_dsa_b128s(network, SLH_HEIGHT, checks)
        .unwrap()
}

fn verified(network: &Network, version: u8, index: u32, checks: u32) -> VerifiedUnminedTx {
    let (mut tx, _) = public_fixture(version, "1of1");
    let input = tx.inputs()[0].clone();
    *tx.inputs_mut() = (0..checks.max(1))
        .map(|offset| {
            let mut input = input.clone();
            let Input::PrevOut {
                outpoint,
                unlock_script,
                ..
            } = &mut input
            else {
                unreachable!()
            };
            outpoint.hash = transaction::Hash([31; 32]);
            outpoint.index = index.checked_mul(32).unwrap() + offset;
            if checks == 0 {
                *unlock_script = Script::new(&[0x00, 0x00]);
            }
            input
        })
        .collect();
    tx.outputs_mut()[0].value = (10_000 + u64::from(index)).try_into().unwrap();
    // A classical output permits a separate classical child after SLH exhaustion.
    tx.outputs_mut().push(classical_output());
    record(network, tx, checks)
}

fn child(
    network: &Network,
    index: u32,
    checks: u32,
    parents: &[&VerifiedUnminedTx],
    deps: &mut TransactionDependencies,
) -> VerifiedUnminedTx {
    assert!(checks == 0 || usize::try_from(checks).unwrap() == parents.len());
    let mut tx = verified(network, 6, index, checks)
        .transaction
        .transaction()
        .as_ref()
        .clone();
    let input = tx.inputs()[0].clone();
    let outpoints: Vec<_> = parents
        .iter()
        .map(|p| {
            OutPoint::from_usize(
                p.transaction.id().mined_id(),
                if checks == 0 { 2 } else { 0 },
            )
        })
        .collect();
    *tx.inputs_mut() = outpoints
        .iter()
        .map(|outpoint| {
            let mut input = input.clone();
            let Input::PrevOut {
                outpoint: point, ..
            } = &mut input
            else {
                unreachable!()
            };
            *point = *outpoint;
            input
        })
        .collect();
    let mut tx = record(network, tx, checks);
    tx.spent_outputs = Arc::new(
        parents
            .iter()
            .map(|p| p.transaction.transaction().outputs()[if checks == 0 { 2 } else { 0 }].clone())
            .collect(),
    );
    let tx = tx
        .with_verified_slh_dsa_b128s(network, SLH_HEIGHT, checks)
        .unwrap();
    deps.add(tx.transaction.id().mined_id(), outpoints);
    tx
}

#[test]
fn slh_templates_enforce_16_per_transaction_and_64_per_block() {
    let net = profile_network(16, 64);
    let mut txs: Vec<_> = (0..4).map(|i| verified(&net, 5, i, 16)).collect();
    txs.push(verified(&net, 6, 4, 1));
    let zero = verified(&net, 6, 5, 0);
    txs.push(zero.clone());
    let mut limits = limits(&net);
    for tx in &txs[..4] {
        assert!(limits.try_add(tx));
    }
    assert_eq!(limits.remaining_slh_dsa_b128s_checks, 0);
    let exhausted = limits.clone();
    assert!(!limits.try_add(&txs[4]));
    assert_eq!(limits, exhausted);
    assert!(limits.try_add(&zero));

    // Counts at 16 and 17 are structurally distinct from successful metadata.
    let mut seventeen = verified(&net, 6, 9, 16);
    let mut tx = seventeen.transaction.transaction().as_ref().clone();
    let input = tx.inputs()[0].clone();
    tx.inputs_mut().push(input);
    seventeen.transaction = tx.into();
    let output = seventeen.spent_outputs[0].clone();
    Arc::make_mut(&mut seventeen.spent_outputs).push(output);
    assert!(seventeen
        .clone()
        .with_verified_slh_dsa_b128s(&net, SLH_HEIGHT, 17)
        .is_err());
    // Even a deliberately forged trusted count of 16 cannot hide 17 structures.
    seventeen = seventeen
        .with_verified_slh_dsa_b128s(&net, SLH_HEIGHT, 16)
        .unwrap();
    assert!(!self::limits(&net).try_add(&seventeen));

    let selected = select(&net, txs, TransactionDependencies::default());
    assert!(selected
        .iter()
        .any(|(_, tx)| tx.transaction.id() == zero.transaction.id()));
    assert!(
        selected
            .iter()
            .map(|(_, tx)| tx.verified_slh_dsa_b128s_checks(&net, SLH_HEIGHT).unwrap())
            .sum::<u32>()
            <= 64
    );
    let (tx, previous) = public_fixture(6, "15of15");
    let Input::PrevOut { unlock_script, .. } = &tx.inputs()[0] else {
        unreachable!()
    };
    assert!(unlock_script.as_raw_bytes().len() > 65_536);
    let tx = UnminedTx::from(tx);
    let fee = tx.conventional_fee();
    let large = VerifiedUnminedTx::new(tx, fee, 0, 0, Arc::new(previous))
        .unwrap()
        .with_verified_slh_dsa_b128s(&net, SLH_HEIGHT, 15)
        .unwrap();
    assert!(self::limits(&net).try_add(&large));
}

fn miner() -> MinerParams {
    MinerParams::from(Address::from(TransparentAddress::PublicKeyHash([0x7e; 20])))
}

fn limits(network: &Network) -> BlockTemplateLimits {
    let coinbase = TransactionTemplate::coinbase_resource_usage(
        network,
        SLH_HEIGHT,
        &miner(),
        Some(Amount::zero()),
    )
    .unwrap();
    BlockTemplateLimits::initial(network, SLH_HEIGHT, coinbase)
}

fn select_at(
    network: &Network,
    height: Height,
    transactions: Vec<VerifiedUnminedTx>,
    deps: TransactionDependencies,
) -> Vec<SelectedMempoolTx> {
    select_mempool_transactions(
        network,
        height,
        &miner(),
        Some(Amount::zero()),
        transactions,
        deps,
    )
    .unwrap()
}

fn select(
    network: &Network,
    txs: Vec<VerifiedUnminedTx>,
    deps: TransactionDependencies,
) -> Vec<SelectedMempoolTx> {
    select_at(network, SLH_HEIGHT, txs, deps)
}

#[test]
fn slh_templates_enforce_configured_limit_and_keep_zero_cost_candidates() {
    for cap in [3, 42] {
        let net = network(cap);
        let mut txs: Vec<_> = (0..=cap)
            .map(|i| verified(&net, if i % 2 == 0 { 5 } else { 6 }, i, 1))
            .collect();
        let zero = verified(&net, 6, cap + 1, 0);
        txs.push(zero.clone());
        let selected = select(&net, txs.clone(), TransactionDependencies::default());
        assert_eq!(selected.len(), usize::try_from(cap + 1).unwrap());
        assert!(selected
            .iter()
            .any(|(_, t)| t.transaction.id() == zero.transaction.id()));
        assert_eq!(
            selected
                .iter()
                .map(|(_, t)| t.verified_slh_dsa_b128s_checks(&net, SLH_HEIGHT).unwrap())
                .sum::<u32>(),
            cap
        );

        // The selector receives a snapshot, leaving the original entries intact.
        // A fresh template can select the payment omitted by the previous cap.
        let skipped: Vec<_> = txs
            .into_iter()
            .filter(|t| {
                !selected
                    .iter()
                    .any(|(_, s)| s.transaction.id() == t.transaction.id())
            })
            .collect();
        assert_eq!(skipped.len(), 1);
        assert_eq!(
            select_at(
                &net,
                Height(111),
                skipped,
                TransactionDependencies::default()
            )
            .len(),
            1
        );
    }

    let net = network(42);
    let mut limits = limits(&net);
    for (i, count) in [15, 15, 12].into_iter().enumerate() {
        assert!(limits.try_add(&verified(&net, 6, u32::try_from(i).unwrap(), count)));
    }
    assert_eq!(limits.remaining_slh_dsa_b128s_checks, 0);
    let before = limits.clone();
    assert!(!limits.try_add(&verified(&net, 5, 3, 1)));
    assert_eq!(limits, before);
    assert!(limits.try_add(&verified(&net, 5, 4, 0)));
}

#[test]
fn slh_rejection_and_other_limits_leave_every_allowance_unchanged() {
    let net = network(3);
    let mut limits = limits(&net);
    assert!(limits.try_add(&verified(&net, 5, 0, 2)));
    let before = limits.clone();

    let excessive_slh = verified(&net, 6, 1, 2);
    let mut missing = verified(&net, 6, 2, 1);
    missing.slh_dsa_b128s_verification = None;
    let oversized = with_serialized_size(verified(&net, 6, 3, 1), limits.remaining_bytes + 1)
        .with_verified_slh_dsa_b128s(&net, SLH_HEIGHT, 1)
        .unwrap();
    let mut sigops = verified(&net, 6, 4, 1);
    sigops.legacy_sigop_count = limits.remaining_sigops - 1;
    sigops.p2sh_sigop_count = 2;
    let mut unpaid = verified(&net, 6, 5, 1);
    unpaid.unpaid_actions = limits.remaining_unpaid_actions + 1;
    for tx in [excessive_slh, missing, oversized, sigops, unpaid] {
        assert!(!limits.try_add(&tx));
        assert_eq!(
            limits, before,
            "a skipped candidate must not consume any allowance"
        );
    }
    assert!(limits.try_add(&verified(&net, 6, 6, 1)));
    assert_eq!(limits.remaining_slh_dsa_b128s_checks, 0);
}

#[test]
fn slh_accounting_preserves_shielded_limits_and_atomic_rejection() {
    let net = network(3);
    let mut mixed = fake_v6_with_orchard_and_ironwood_actions(NetworkUpgrade::Nu7, 1, 1)
        .as_ref()
        .clone();
    *mixed.inputs_mut() = verified(&net, 6, 0, 1)
        .transaction
        .transaction()
        .inputs()
        .to_vec();
    let Transaction::V5 {
        sapling_shielded_data,
        ..
    } = fake_v5_with_sapling_outputs(1).as_ref().clone()
    else {
        unreachable!()
    };
    let Transaction::V6 {
        sapling_shielded_data: sapling,
        ..
    } = &mut mixed
    else {
        unreachable!()
    };
    *sapling = sapling_shielded_data;
    let mixed = record(&net, mixed, 1);
    let counts = mixed.transaction.transaction().shielded_action_counts();
    assert_eq!(
        (
            counts.orchard_actions,
            counts.ironwood_actions,
            counts.sapling_ios
        ),
        (1, 1, 1)
    );
    for exhausted in ["orchard", "ironwood", "sapling", "global"] {
        let mut limits = limits(&net);
        match exhausted {
            "orchard" => limits.remaining_orchard_actions = 0,
            "ironwood" => limits.remaining_ironwood_actions = 0,
            "sapling" => limits.remaining_sapling_ios = 0,
            _ => limits.remaining_shielded_cost = counts.cost() - 1,
        }
        let before = limits.clone();
        assert!(!limits.try_add(&mixed));
        assert_eq!(
            limits, before,
            "shielded rejection cannot consume SLH or other capacity"
        );
    }
    let mut limits = limits(&net);
    let before = limits.clone();
    assert!(limits.try_add(&mixed));
    assert_eq!(
        limits.remaining_slh_dsa_b128s_checks,
        before.remaining_slh_dsa_b128s_checks - 1
    );
    assert_eq!(
        limits.remaining_orchard_actions,
        before.remaining_orchard_actions - 1
    );
    assert_eq!(
        limits.remaining_ironwood_actions,
        before.remaining_ironwood_actions - 1
    );
    assert_eq!(
        limits.remaining_sapling_ios,
        before.remaining_sapling_ios - 1
    );
    assert_eq!(
        limits.remaining_shielded_cost,
        before.remaining_shielded_cost - counts.cost()
    );
}

#[test]
fn slh_templates_require_current_rules_and_exact_verification_payloads() {
    let net = network(3);
    for version in [5, 6] {
        let valid = verified(&net, version, 0, 1);
        let mut missing = valid.clone();
        missing.slh_dsa_b128s_verification = None;
        let mut different_auth = valid.clone();
        let mut tx = valid.transaction.transaction().as_ref().clone();
        let Input::PrevOut { unlock_script, .. } = &mut tx.inputs_mut()[0] else {
            unreachable!()
        };
        *unlock_script = Script::new(&[0x51]);
        different_auth.transaction = tx.into();
        assert_eq!(
            different_auth.transaction.id().mined_id(),
            valid.transaction.id().mined_id()
        );
        assert_ne!(different_auth.transaction.id(), valid.transaction.id());
        let mut different_utxo = valid.clone();
        Arc::make_mut(&mut different_utxo.spent_outputs)[0].value = 1.try_into().unwrap();
        for bad in [
            missing,
            different_auth,
            different_utxo,
            verified(&network(4), version, 0, 1),
        ] {
            let mut limits = limits(&net);
            let before = limits.clone();
            assert!(!limits.try_add(&bad));
            assert_eq!(limits, before);
            assert!(select(&net, vec![bad], TransactionDependencies::default()).is_empty());
        }
        assert_eq!(
            select_at(
                &net,
                Height(111),
                vec![valid.clone()],
                TransactionDependencies::default()
            )
            .len(),
            1
        );
        assert!(select_at(
            &net,
            Height(109),
            vec![valid],
            TransactionDependencies::default()
        )
        .is_empty());

        let mut legacy = verified(&net, version, 1, 0);
        legacy.slh_dsa_b128s_verification = None;
        assert_eq!(
            select_at(
                &net,
                Height(109),
                vec![legacy.clone()],
                TransactionDependencies::default()
            )
            .len(),
            1
        );
        assert!(select(&net, vec![legacy], TransactionDependencies::default()).is_empty());
    }
    // Public networks keep accepting their existing unannotated legacy entries.
    let mainnet = Network::Mainnet;
    let legacy = mainnet.unmined_transactions_in_blocks(..).next().unwrap();
    assert_eq!(
        select_at(
            &mainnet,
            Height(1_000_000),
            vec![legacy],
            TransactionDependencies::default()
        )
        .len(),
        1
    );
}

#[test]
fn slh_budget_applies_to_descendants_and_requires_selected_parents() {
    let net = network(3);
    let parent = verified(&net, 5, 0, 1);
    let mut deps = TransactionDependencies::default();
    let child = child(&net, 1, 1, &[&parent], &mut deps);
    let grandchild = self::child(&net, 2, 1, &[&child], &mut deps);
    let txs = vec![grandchild.clone(), child.clone(), parent.clone()];
    let selected = select(&net, txs, deps.clone());
    assert_eq!(
        selected
            .iter()
            .map(|(depth, tx)| (*depth, tx.transaction.id()))
            .collect::<Vec<_>>(),
        vec![
            (0, parent.transaction.id()),
            (1, child.transaction.id()),
            (2, grandchild.transaction.id())
        ]
    );

    let mut bad_parent = parent.clone();
    bad_parent.slh_dsa_b128s_verification = None;
    assert!(select(&net, vec![bad_parent, child.clone(), grandchild], deps).is_empty());

    // An omitted child must also withhold its zero-cost grandchild.
    let mut deps = TransactionDependencies::default();
    let limited_net = network(1);
    let parent = verified(&limited_net, 5, 3, 1);
    let excessive_child = self::child(&limited_net, 4, 1, &[&parent], &mut deps);
    let zero_grandchild = self::child(&limited_net, 5, 0, &[&excessive_child], &mut deps);
    let selected = select(
        &limited_net,
        vec![zero_grandchild, excessive_child, parent.clone()],
        deps,
    );
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].1.transaction.id(), parent.transaction.id());

    // Funding/legacy descendants remain selectable after the SLH budget is full.
    let parent = verified(&net, 5, 5, 3);
    let mut deps = TransactionDependencies::default();
    let zero_child = self::child(&net, 6, 0, &[&parent], &mut deps);
    assert_eq!(select(&net, vec![zero_child, parent], deps).len(), 2);
}

#[test]
fn slh_child_waits_for_every_parent() {
    let mut deps = TransactionDependencies::default();
    let net = network(4);
    let first = verified(&net, 5, 0, 1);
    let second = verified(&net, 6, 1, 1);
    let child = child(&net, 2, 2, &[&first, &second], &mut deps);
    let selected = select(
        &net,
        vec![child.clone(), second.clone(), first.clone()],
        deps.clone(),
    );
    assert_eq!(selected.len(), 3);
    assert_eq!(selected[2].1.transaction.id(), child.transaction.id());
    // Exclude a stale second parent without also invalidating the first.
    let mut stale = second;
    stale.slh_dsa_b128s_verification = None;
    let selected = select(&net, vec![child, stale, first.clone()], deps);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].1.transaction.id(), first.transaction.id());
}
