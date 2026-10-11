use zakura_chain::{
    block::Height,
    parameters::NetworkUpgrade,
    serialization::ZcashSerialize,
    transaction::{Hash, LockTime},
    transparent::{Input, OutPoint, Output, Script},
};
use zakura_pq_test_support::{
    inputs_mut, install, outputs_mut, set_upgrade, Spend, TransactionRecipe,
};

fn spend(hash: u8, index: u32, sequence: u32, value: u64, script: &[u8]) -> Spend {
    Spend {
        outpoint: OutPoint {
            hash: Hash([hash; 32]),
            index,
        },
        sequence,
        previous_output: Output {
            value: value.try_into().unwrap(),
            lock_script: Script::new(script),
        },
    }
}

#[test]
fn explicit_fields_and_unsorted_context_keep_exact_bytes() {
    for version in [5, 6] {
        let (tx, previous) = TransactionRecipe {
            version,
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::Height(Height(23)),
            expiry_height: Height(456),
            spends: vec![
                spend(0x22, 3, 7, 50, &[0xff]),
                spend(0x11, 8, u32::MAX - 1, 60, &[0x4c]),
            ],
            outputs: vec![Output {
                value: 42.try_into().unwrap(),
                lock_script: Script::new(&[0x00, 0x6a]),
            }],
        }
        .build();

        // Explicit wire expectation, independent of the recipe and its field
        // accessors: nonfinal sequences, unsorted outpoints and arbitrary scripts.
        let mut wire = if version == 5 {
            vec![5, 0, 0, 0x80, 0x0a, 0x27, 0xa7, 0x26]
        } else {
            vec![6, 0, 0, 0x80, 0x98, 0xb6, 0x84, 0xd8]
        };
        wire.extend([0xd9, 0x0a, 0x19, 0x77, 23, 0, 0, 0, 0xc8, 1, 0, 0, 2]);
        wire.extend([0x22; 32]);
        wire.extend([3, 0, 0, 0, 0, 7, 0, 0, 0]);
        wire.extend([0x11; 32]);
        wire.extend([8, 0, 0, 0, 0, 0xfe, 0xff, 0xff, 0xff]);
        wire.extend([1, 42, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x6a, 0, 0, 0]);
        if version == 6 {
            wire.push(0);
        }
        assert_eq!(tx.zcash_serialize_to_vec().unwrap(), wire);
        let context: Vec<_> = previous
            .iter()
            .flat_map(|output| output.zcash_serialize_to_vec().unwrap())
            .collect();
        assert_eq!(
            context,
            [50, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 60, 0, 0, 0, 0, 0, 0, 0, 1, 0x4c]
        );
    }
}

#[test]
fn negative_recipes_are_not_repaired_or_validated() {
    for version in [5, 6] {
        // Duplicate outpoints with different claimed outputs are intentional.
        let (mut tx, previous) = TransactionRecipe {
            version,
            network_upgrade: NetworkUpgrade::Nu5,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(0),
            spends: vec![spend(1, 0, 0, 1, &[]), spend(1, 0, 0, 2, &[0x4c])],
            outputs: vec![],
        }
        .build();
        assert_eq!(tx.inputs()[0].outpoint(), tx.inputs()[1].outpoint());
        // Both claimed outputs stay paired with their inputs, in recipe order.
        assert_eq!(
            previous
                .iter()
                .map(|output| (u64::from(output.value), output.lock_script.as_raw_bytes()))
                .collect::<Vec<_>>(),
            [(1, [].as_slice()), (2, [0x4c].as_slice())]
        );
        assert!(tx.outputs().is_empty());
        assert_eq!(tx.network_upgrade(), Some(NetworkUpgrade::Nu5));
        install(&mut tx, 0, Script::new(&[0xff]));
        let Input::PrevOut { unlock_script, .. } = &tx.inputs()[0] else {
            panic!("recipe inputs are previous-output inputs");
        };
        assert_eq!(unlock_script.as_raw_bytes(), &[0xff]);
        set_upgrade(&mut tx, NetworkUpgrade::Nu7);
        assert_eq!(tx.network_upgrade(), Some(NetworkUpgrade::Nu7));
        outputs_mut(&mut tx).push(previous[1].clone());
        inputs_mut(&mut tx).clear();
        assert!(tx.inputs().is_empty());
        assert_eq!(tx.outputs(), &[previous[1].clone()]);

        let (empty, previous) = TransactionRecipe {
            version,
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(0),
            spends: vec![],
            outputs: vec![],
        }
        .build();
        assert!(empty.inputs().is_empty() && empty.outputs().is_empty() && previous.is_empty());
    }
}
