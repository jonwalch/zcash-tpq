use std::{iter, sync::Arc};

use chrono::Utc;
use futures::FutureExt;

use zakura_chain::{
    block,
    chain_tip::{ChainTip, NoChainTip},
    parameters::Network::*,
};

use super::super::{ChainTipBlock, ChainTipSender};

fn tip(height: u32, hash_byte: u8, parent_byte: u8) -> ChainTipBlock {
    ChainTipBlock {
        hash: block::Hash([hash_byte; 32]),
        height: block::Height(height),
        time: Utc::now(),
        transactions: Vec::new(),
        transaction_hashes: Arc::from([]),
        previous_block_hash: block::Hash([parent_byte; 32]),
    }
}

#[test]
fn current_best_tip_is_initially_empty() {
    let (_chain_tip_sender, latest_chain_tip, _chain_tip_change) =
        ChainTipSender::new(None, &Mainnet);

    assert_eq!(latest_chain_tip.best_tip_height(), None);
    assert_eq!(latest_chain_tip.best_tip_hash(), None);
    assert_eq!(
        latest_chain_tip.best_tip_mined_transaction_ids(),
        iter::empty().collect()
    );
}

#[test]
fn empty_latest_chain_tip_is_empty() {
    let latest_chain_tip = NoChainTip;

    assert_eq!(latest_chain_tip.best_tip_height(), None);
    assert_eq!(latest_chain_tip.best_tip_hash(), None);
    assert_eq!(
        latest_chain_tip.best_tip_mined_transaction_ids(),
        iter::empty().collect()
    );
}

#[test]
fn chain_tip_change_is_initially_not_ready() {
    let (_chain_tip_sender, _latest_chain_tip, mut chain_tip_change) =
        ChainTipSender::new(None, &Mainnet);

    // TODO: use `tokio::task::unconstrained` to avoid spurious waits from tokio's cooperative multitasking
    //       (needs a recent tokio version)
    // See:
    // https://github.com/ZcashFoundation/zebra/pull/2777#discussion_r712488817
    // https://docs.rs/tokio/1.11.0/tokio/task/index.html#cooperative-scheduling
    // https://tokio.rs/blog/2020-04-preemption

    let first = chain_tip_change
        .wait_for_tip_change()
        .now_or_never()
        .transpose()
        .expect("watch sender is not dropped");

    assert_eq!(first, None);

    assert_eq!(chain_tip_change.last_tip_change(), None);

    // try again, just to be sure
    let first = chain_tip_change
        .wait_for_tip_change()
        .now_or_never()
        .transpose()
        .expect("watch sender is not dropped");

    assert_eq!(first, None);

    assert_eq!(chain_tip_change.last_tip_change(), None);

    // also test our manual `Clone` impl
    #[allow(clippy::redundant_clone)]
    let first_clone = chain_tip_change
        .clone()
        .wait_for_tip_change()
        .now_or_never()
        .transpose()
        .expect("watch sender is not dropped");

    assert_eq!(first_clone, None);

    assert_eq!(chain_tip_change.last_tip_change(), None);
}

#[test]
fn empty_non_finalized_state_returns_tip_publication_to_finalized() {
    let initial = tip(10, 10, 9);
    let non_finalized = tip(12, 12, 11);
    let finalized = tip(11, 11, 10);
    let (mut sender, latest, _) = ChainTipSender::new(initial, &Mainnet);

    sender.set_best_non_finalized_tip(non_finalized.clone());
    sender.set_finalized_tip(finalized.clone());
    assert_eq!(latest.best_tip_hash(), Some(non_finalized.hash));

    sender.clear_best_non_finalized_tip(finalized.clone());
    assert_eq!(latest.best_tip_height(), Some(finalized.height));
    assert_eq!(latest.best_tip_hash(), Some(finalized.hash));
}

#[test]
fn late_broadcast_completion_does_not_rewind_the_tip_cursor() {
    let (mut sender, _, mut changes) = ChainTipSender::new(None, &Mainnet);
    sender.set_best_non_finalized_tip(Some(tip(2, 2, 1)));
    changes.mark_last_change_hash(block::Hash([2; 32]));
    changes.mark_last_change_hash(block::Hash([1; 32]));
    assert_eq!(changes.last_tip_change(), None);
    sender.set_best_non_finalized_tip(Some(tip(3, 3, 2)));
    assert_eq!(
        changes
            .last_tip_change()
            .unwrap()
            .best_tip_hash_and_height(),
        (block::Hash([3; 32]), block::Height(3))
    );
}

#[test]
fn experimental_slh_dsa_b128s_resets_at_its_own_next_block_activation() {
    use super::super::TipAction;
    use zakura_chain::parameters::{
        testnet::{
            ConfiguredActivationHeights, ExperimentalSlhDsaB128sLimits, Parameters,
            RegtestParameters,
        },
        Magic, Network,
    };
    // SLH activation resets at candidate height 12, including after rollback.
    let activation_heights = ConfiguredActivationHeights {
        nu6_3: Some(1),
        nu7: Some(5),
        ..Default::default()
    };
    let limits = ExperimentalSlhDsaB128sLimits::new(2, 4).unwrap();
    let regtest = Network::new_regtest(RegtestParameters {
        activation_heights,
        experimental_slh_dsa_b128s_activation_height: Some(block::Height(12)),
        experimental_slh_dsa_b128s_limits: Some(limits),
        ..Default::default()
    });
    let custom_testnet = Parameters::build()
        .with_network_name("SlhTipResetDevnet")
        .unwrap()
        .with_network_magic(Magic([0x53, 0x4c, 0x48, 0x31]))
        .unwrap()
        .with_genesis_hash(block::Hash([42; 32]))
        .unwrap()
        .with_activation_heights(activation_heights)
        .unwrap()
        .clear_funding_streams()
        .with_lockbox_disbursements(vec![])
        .clear_checkpoints()
        .unwrap()
        .with_experimental_slh_dsa_b128s(block::Height(12), limits)
        .unwrap()
        .to_network()
        .unwrap();
    assert!(!custom_testnet.is_regtest());

    for network in [regtest, custom_testnet] {
        let (mut sender, _, mut changes) = ChainTipSender::new(None, &network);
        for (height, hash, parent, reset) in [
            (8, 8, 7, true),  // initial observation
            (9, 9, 8, false), // no configured activation at candidate height 10
            (10, 10, 9, false),
            (11, 11, 10, true), // candidate height 12 activates SLH-DSA-B-128s
            (12, 12, 11, false),
            (10, 20, 9, true),  // rollback below SLH-DSA-B-128s activation
            (11, 21, 20, true), // reactivate candidate height 12
            (12, 22, 21, false),
            (12, 23, 21, true), // same-height fork invalidates bound verification results
            (13, 24, 23, false),
            (3, 30, 2, true),  // rollback below both SLH and NU7
            (4, 31, 30, true), // candidate height 5 reactivates NU7
            (5, 32, 31, false),
            (6, 33, 32, false),
            (7, 34, 33, false),
            (8, 35, 34, false),
            (9, 36, 35, false),
            (10, 37, 36, false),
            (11, 38, 37, true), // SLH activation remains independent of the branch upgrade
        ] {
            sender.set_best_non_finalized_tip(Some(tip(height, hash, parent)));
            assert_eq!(
                matches!(changes.last_tip_change().unwrap(), TipAction::Reset { .. }),
                reset,
                "network {network}, height {height}, hash {hash}"
            );
        }

        // Multiple notifications can be coalesced by the watch channel. Missing
        // the exact activation block still resets before any result is consumed.
        sender.set_best_non_finalized_tip(Some(tip(10, 40, 9)));
        assert!(
            matches!(changes.last_tip_change(), Some(TipAction::Reset { .. })),
            "network {network}: rollback resets before coalesced notifications"
        );
        sender.set_best_non_finalized_tip(Some(tip(11, 41, 40)));
        sender.set_best_non_finalized_tip(Some(tip(12, 42, 41)));
        assert!(
            matches!(changes.last_tip_change(), Some(TipAction::Reset { .. })),
            "network {network}: coalesced activation notifications reset"
        );
    }
}
