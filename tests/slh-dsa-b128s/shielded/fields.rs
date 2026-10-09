//! Field and collection mutations reused from the existing shielded controls.

use super::sources::{
    actions_mut as orchard_mut, change_byte, resize_proof, sapling_mut, IRONWOOD, ORCHARD,
};
use super::{assert_effect, assert_messages, source, transaction};
use zakura_chain::{
    orchard, sapling,
    serialization::{ZcashDeserialize, ZcashSerialize},
    transaction::Transaction,
};

#[test]
fn every_sapling_effecting_field_and_ciphertext_region_is_committed() {
    for version in [5, 6] {
        let (tx, outputs) = transaction(version, 1);
        // Negating a compressed point preserves its valid encoding. Other
        // offsets change one byte of a field/ciphertext region at a time.
        for (field, offset, mask) in [
            ("spend_cv", 31, 0x80),
            ("spend_rk", 95, 0x80),
            ("output_cv", 31, 0x80),
            ("cmu", 32, 1),
            ("ephemeral_key", 95, 0x80),
            ("ciphertext_prefix", 96, 1),
            ("memo", 148, 1),
            ("authentication_tag", 660, 1),
            ("outgoing_ciphertext", 676, 1),
        ] {
            let mut changed = tx.clone();
            let sapling::TransferData::SpendsAndMaybeOutputs {
                spends,
                maybe_outputs,
                ..
            } = &mut sapling_mut(&mut changed).transfers
            else {
                unreachable!()
            };
            if field.starts_with("spend_") {
                let spend = spends.iter_mut().next().unwrap();
                let (prefix, proof, signature) = spend.clone().into_v5_parts();
                *spend = sapling::Spend::from_v5_parts(
                    change_byte(&prefix, offset, mask),
                    proof,
                    signature,
                );
            } else {
                maybe_outputs[0] =
                    change_byte(&maybe_outputs[0].clone().into_v4(), offset, mask).into_output();
            }
            assert_ne!(tx, changed, "{field}");
            assert_effect(&tx, &changed, outputs.clone(), true);
        }
    }
}

#[test]
fn every_orchard_and_ironwood_effecting_field_is_committed() {
    for (version, pool) in [(5, ORCHARD), (6, ORCHARD), (6, IRONWOOD)] {
        let (tx, outputs) = transaction(version, pool);
        for (field, offset, mask) in [
            ("cv", 31, 0x80),
            ("rk", 95, 0x80),
            ("cmx", 96, 1),
            ("ephemeral_key", 159, 0x80),
            ("ciphertext_prefix", 160, 1),
            ("memo", 212, 1),
            ("authentication_tag", 724, 1),
            ("outgoing_ciphertext", 740, 1),
        ] {
            let mut changed = tx.clone();
            let action = &mut orchard_mut(&mut changed, pool)
                .actions
                .iter_mut()
                .next()
                .unwrap()
                .action;
            *action = change_byte(action, offset, mask);
            assert_ne!(tx, changed, "{field}");
            assert_effect(&tx, &changed, outputs.clone(), true);
        }
    }
}

#[test]
fn sapling_collection_counts_order_and_empty_sides_are_committed() {
    for version in [5, 6] {
        let (mut tx, outputs) = transaction(version, 1);
        let sapling::TransferData::SpendsAndMaybeOutputs {
            spends,
            maybe_outputs,
            ..
        } = &mut sapling_mut(&mut tx).transfers
        else {
            unreachable!()
        };
        let mut spend_list: Vec<_> = spends.iter().cloned().collect();
        let mut second = spend_list[0].clone();
        second.nullifier = [42; 32].into();
        assert_ne!(second, spend_list[0]);
        spend_list.push(second);
        *spends = spend_list.try_into().unwrap();
        let second = change_byte(&maybe_outputs[0].clone().into_v4(), 148, 1).into_output();
        maybe_outputs.push(second);
        assert_messages(&tx, outputs.clone());
        for field in [
            "spend_add",
            "spend_remove",
            "spend_reorder",
            "output_add",
            "output_remove",
            "output_reorder",
            "outputs_only",
            "spends_only",
        ] {
            let mut changed = tx.clone();
            let bundle = sapling_mut(&mut changed);
            let sapling::TransferData::SpendsAndMaybeOutputs {
                spends,
                maybe_outputs,
                ..
            } = &mut bundle.transfers
            else {
                unreachable!()
            };
            let mut spend_list: Vec<_> = spends.iter().cloned().collect();
            match field {
                "spend_add" => spend_list.push(spend_list[0].clone()),
                "spend_remove" => {
                    spend_list.pop();
                }
                "spend_reorder" => spend_list.reverse(),
                "output_add" => maybe_outputs.push(maybe_outputs[0].clone()),
                "output_remove" => {
                    maybe_outputs.pop();
                }
                "output_reorder" => maybe_outputs.reverse(),
                "spends_only" => maybe_outputs.clear(),
                _ => {}
            }
            *spends = spend_list.try_into().unwrap();
            if field == "outputs_only" {
                bundle.transfers = sapling::TransferData::JustOutputs {
                    outputs: maybe_outputs.clone().try_into().unwrap(),
                };
            }
            assert_ne!(tx, changed, "{field}");
            assert_effect(&tx, &changed, outputs.clone(), true);
            if matches!(field, "outputs_only" | "spends_only") {
                assert_messages(&changed, outputs.clone());
            }
        }
    }
}

#[test]
fn orchard_and_ironwood_collection_counts_order_and_pool_identity_are_committed() {
    for (version, pool) in [(5, ORCHARD), (6, ORCHARD), (6, IRONWOOD)] {
        let (mut tx, outputs) = transaction(version, pool);
        let bundle = orchard_mut(&mut tx, pool);
        // Use flags valid in both pools so the swap reaches hashing instead of
        // failing because Orchard reserves Ironwood's cross-address flag.
        bundle.flags.remove(orchard::Flags::ENABLE_CROSS_ADDRESS);
        let mut actions: Vec<_> = bundle.actions.iter().cloned().collect();
        let mut second = actions[0].clone();
        second.action.nullifier = [42; 32].try_into().unwrap();
        assert_ne!(second, actions[0]);
        actions.push(second);
        bundle.actions = actions.try_into().unwrap();
        resize_proof(bundle);
        assert_messages(&tx, outputs.clone());
        for change in ["add", "remove", "reorder", "remove_pool", "swap_pool"] {
            if change == "swap_pool" && version == 5 {
                continue;
            }
            let mut changed = tx.clone();
            let bundle = orchard_mut(&mut changed, pool);
            let mut actions: Vec<_> = bundle.actions.iter().cloned().collect();
            match change {
                "add" => actions.push(actions[0].clone()),
                "remove" => {
                    actions.pop();
                }
                "reorder" => actions.reverse(),
                _ => {}
            }
            bundle.actions = actions.try_into().unwrap();
            resize_proof(bundle);
            if matches!(change, "remove_pool" | "swap_pool") {
                match &mut changed {
                    Transaction::V5 {
                        orchard_shielded_data,
                        ..
                    } => *orchard_shielded_data = None,
                    Transaction::V6 {
                        orchard_shielded_data,
                        ironwood_shielded_data,
                        ..
                    } => {
                        if change == "swap_pool" {
                            std::mem::swap(orchard_shielded_data, ironwood_shielded_data);
                        } else if pool == 2 {
                            *orchard_shielded_data = None;
                        } else {
                            *ironwood_shielded_data = None;
                        }
                    }
                    _ => unreachable!(),
                }
            }
            assert_ne!(tx, changed, "{change}");
            assert_effect(&tx, &changed, outputs.clone(), true);
        }
    }
}

#[test]
fn pq_spends_can_have_only_shielded_destinations() {
    for (version, pool) in [(5, 1), (5, 2), (6, 1), (6, 2), (6, 4)] {
        let (mut tx, outputs) = transaction(version, pool);
        zakura_pq_test_support::outputs_mut(&mut tx).clear();
        if pool == 1 {
            let Transaction::V6 {
                sapling_shielded_data: Some(bundle),
                ..
            } = source("sapling_output")
            else {
                unreachable!()
            };
            *sapling_mut(&mut tx) = bundle;
            assert!(matches!(
                sapling_mut(&mut tx).transfers,
                sapling::TransferData::JustOutputs { .. }
            ));
        }
        assert_messages(&tx, outputs.clone());
        let raw = tx.zcash_serialize_to_vec().unwrap();
        let parsed = Transaction::zcash_deserialize(raw.as_slice()).unwrap();
        assert_messages(&parsed, outputs);
    }
}
