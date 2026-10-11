//! Bounded trusted-node history reconstruction, adapted from pinned research
//! pq_ironwood_spend/history.rs. This is not a block/consensus verifier.
use super::*;
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use std::collections::{HashMap, HashSet};
use zakura_chain::{block::Block, parameters::Network, transaction::Hash};

const MAX_HEIGHT: usize = 512;
const MAX_HISTORY_BYTES: usize = 6 * 1024 * 1024;
const MAX_COMMITMENTS: usize = 4096;

pub(super) struct History {
    pub blocks: Vec<Block>,
    pub transactions: HashMap<Hash, (usize, Arc<Transaction>)>,
    pub spent: HashSet<OutPoint>,
    pub tip_height: u32,
    pub tip_hash: String,
    pub sha256: String,
}
pub(super) struct ActionNote {
    pub note: orchard::Note,
    pub path: MerklePath,
    pub anchor: orchard::Anchor,
}
pub(super) struct SaplingNote {
    pub note: sapling_crypto::Note,
    pub path: sapling_crypto::MerklePath,
    pub anchor: sapling_crypto::Anchor,
}
pub(super) enum Note {
    Sapling(Box<SaplingNote>),
    Action(Box<ActionNote>),
}
pub(super) struct Funding {
    pub pool: String,
    pub note: Note,
    pub metadata: Value,
}

pub(super) fn parse(request: &ShieldedHistory) -> Result<History> {
    require(
        (111..=MAX_HEIGHT + 1).contains(&request.blocks.len()),
        "history",
        "height_bound",
    )?;
    let total = request
        .blocks
        .iter()
        .try_fold(0usize, |sum, raw| sum.checked_add(raw.len()));
    require(
        total.is_some_and(|n| n <= 2 * MAX_HISTORY_BYTES),
        "history",
        "byte_bound",
    )?;
    let mut blocks = Vec::new();
    let mut transactions = HashMap::new();
    let mut spent = HashSet::new();
    for (height, raw) in request.blocks.iter().enumerate() {
        let bytes = bounded_hex(raw, 512 * 1024)?;
        let block = converted(Block::zcash_deserialize(bytes.as_slice()))?;
        require(
            converted(block.zcash_serialize_to_vec())? == bytes,
            "history",
            "canonical_block",
        )?;
        require(
            block.coinbase_height() == Some(Height(u32::try_from(height).expect("bounded height"))),
            "history",
            "block_height",
        )?;
        if height == 0 {
            require(
                block.hash() == Network::new_regtest(Default::default()).genesis_hash(),
                "history",
                "regtest_genesis",
            )?;
        } else {
            let previous: &Block = &blocks[height - 1];
            require(
                block.header.previous_block_hash == previous.hash(),
                "history",
                "disconnected",
            )?;
        }
        for tx in &block.transactions {
            require(
                transactions
                    .insert(tx.hash(), (height, tx.clone()))
                    .is_none(),
                "history",
                "duplicate_transaction",
            )?;
            require(transactions.len() <= 8192, "history", "transaction_bound")?;
            for outpoint in tx.inputs().iter().filter_map(|input| input.outpoint()) {
                require(spent.insert(outpoint), "history", "duplicate_prevout")?;
            }
        }
        blocks.push(block);
    }
    let tip_height = u32::try_from(blocks.len() - 1).expect("bounded height");
    let tip_hash = needed(blocks.last())?.hash().to_string();
    require(
        request.treestate["height"].as_u64() == Some(u64::from(tip_height))
            && request.treestate["hash"].as_str() == Some(tip_hash.as_str()),
        "history",
        "stale_treestate",
    )?;
    Ok(History {
        blocks,
        transactions,
        spent,
        tip_height,
        tip_hash,
        sha256: strict::hash(&strict::canonical(&encode(request))),
    })
}
impl History {
    pub fn previous(&self, tx: &Transaction, height: usize) -> Result<Arc<Vec<ChainOutput>>> {
        tx.inputs()
            .iter()
            .map(|input| {
                let point = needed(input.outpoint())?;
                let (parent_height, parent) = needed(self.transactions.get(&point.hash))?;
                require(*parent_height < height, "history", "funding_prevout_height")?;
                needed(
                    parent
                        .outputs()
                        .get(usize::try_from(point.index).expect("u32 fits usize")),
                )
                .cloned()
            })
            .collect::<Result<Vec<_>>>()
            .map(Arc::new)
    }
    pub fn parent(&self, raw: &str, index: u32) -> Result<ChainOutput> {
        let tx = decode_transaction(&bounded_hex(raw, MAX_TX)?)?;
        let (height, actual) = needed(self.transactions.get(&tx.hash()))?;
        require(actual.as_ref() == &tx, "history", "parent_bytes")?;
        require(
            !self.spent.contains(&OutPoint {
                hash: tx.hash(),
                index,
            }),
            "history",
            "parent_spent",
        )?;
        require(
            !tx.is_coinbase()
                || usize::try_from(self.tip_height).expect("bounded") + 1 >= height + 100,
            "history",
            "parent_maturity",
        )?;
        needed(
            tx.outputs()
                .get(usize::try_from(index).expect("u32 fits usize")),
        )
        .cloned()
    }
}

/// Select the leaf by position, then include every later commitment in its path.
pub(super) fn action_witness(
    leaves: &[[u8; 32]],
    position: usize,
) -> Result<(MerklePath, orchard::Anchor)> {
    require(
        leaves.len() <= MAX_COMMITMENTS,
        "history",
        "commitment_bound",
    )?;
    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut witness: Option<IncrementalWitness<MerkleHashOrchard, 32>> = None;
    for (index, bytes) in leaves.iter().enumerate() {
        let leaf = needed(Option::<MerkleHashOrchard>::from(
            MerkleHashOrchard::from_bytes(bytes),
        ))?;
        converted(tree.append(leaf))?;
        if let Some(witness) = &mut witness {
            converted(witness.append(leaf))?;
        } else if index == position {
            witness = IncrementalWitness::from_tree(tree.clone());
        }
    }
    let witness = needed(witness)?;
    require(witness.root() == tree.root(), "history", "witness_tip")?;
    Ok((needed(witness.path())?.into(), tree.root().into()))
}
pub(super) fn sapling_witness(
    leaves: &[[u8; 32]],
    position: usize,
) -> Result<(sapling_crypto::MerklePath, sapling_crypto::Anchor)> {
    require(
        leaves.len() <= MAX_COMMITMENTS,
        "history",
        "commitment_bound",
    )?;
    let mut tree = sapling_crypto::CommitmentTree::empty();
    let mut witness: Option<sapling_crypto::IncrementalWitness> = None;
    for (index, bytes) in leaves.iter().enumerate() {
        let leaf = needed(Option::<sapling_crypto::Node>::from(
            sapling_crypto::Node::from_bytes(*bytes),
        ))?;
        converted(tree.append(leaf))?;
        if let Some(witness) = &mut witness {
            converted(witness.append(leaf))?;
        } else if index == position {
            witness = sapling_crypto::IncrementalWitness::from_tree(tree.clone());
        }
    }
    let witness = needed(witness)?;
    require(witness.root() == tree.root(), "history", "witness_tip")?;
    Ok((needed(witness.path())?, tree.root().into()))
}

pub(super) fn recover(history: &History, request: &ShieldedSpendRecipe) -> Result<Vec<Funding>> {
    require(
        request.pools.len() == request.funding_txids.len()
            && request
                .pools
                .iter()
                .zip(&request.funding_txids)
                .all(|(p, f)| p == &f.pool),
        "history",
        "funding_pools",
    )?;
    let mut result = Vec::new();
    for source in &request.funding_txids {
        let hash: Hash = converted(source.txid.parse())?;
        require(hash.to_string() == source.txid, "history", "funding_txid")?;
        let (height, tx) = needed(history.transactions.get(&hash))?;
        let pool = source.pool.as_str();
        let upgrade = if pool == "orchard" {
            NetworkUpgrade::Nu6_2
        } else {
            NetworkUpgrade::Nu7
        };
        require(
            tx.network_upgrade() == Some(upgrade)
                && if pool == "orchard" {
                    (102..104).contains(height) && tx.version() == 5
                } else {
                    *height >= 110
                },
            "history",
            "funding_profile",
        )?;
        let hasher = converted(tx.sighasher(upgrade, history.previous(tx, *height)?))?;
        let root = fixed_hex::<32>(needed(
            request.history.treestate[pool]["commitments"]["finalRoot"].as_str(),
        )?)?;
        let (funding_index, commitment, note) = if pool == "sapling" {
            let bundle = needed(hasher.sapling_bundle())?;
            require(
                bundle.shielded_spends().is_empty()
                    && i64::from(*bundle.value_balance()) == -50_000,
                "history",
                "funding_deposit",
            )?;
            let key = sapling_key();
            let fvk = key.to_diversifiable_full_viewing_key();
            let ivk = sapling_crypto::keys::PreparedIncomingViewingKey::new(&fvk.fvk().vk.ivk());
            let notes: Vec<_> = bundle
                .shielded_outputs()
                .iter()
                .enumerate()
                .filter_map(|(i, o)| {
                    sapling_crypto::note_encryption::try_sapling_note_decryption(
                        &ivk,
                        o,
                        sapling_crypto::note_encryption::Zip212Enforcement::On,
                    )
                    .filter(|(n, _, _)| n.value().inner() != 0)
                    .map(|(n, _, _)| (i, n))
                })
                .collect();
            require(
                notes.len() == 1 && notes[0].1.value().inner() == NOTE_VALUE,
                "history",
                "public_note",
            )?;
            let (i, note) = notes.into_iter().next().expect("one note checked");
            (i, note.cmu().to_bytes(), EitherNote::Sapling(note))
        } else {
            let bundle = needed(if pool == "orchard" {
                hasher.orchard_bundle()
            } else {
                hasher.ironwood_bundle()
            })?;
            require(
                !bundle.flags().spends_enabled()
                    && bundle.flags().outputs_enabled()
                    && i64::from(*bundle.value_balance()) == -50_000,
                "history",
                "funding_deposit",
            )?;
            let fvk = FullViewingKey::from(&action_key());
            let notes: Vec<_> = bundle
                .decrypt_outputs_with_keys(&[fvk.to_ivk(Scope::External)])
                .into_iter()
                .filter(|(_, _, n, _, _)| n.value().inner() != 0)
                .collect();
            require(
                notes.len() == 1 && notes[0].2.value().inner() == NOTE_VALUE,
                "history",
                "public_note",
            )?;
            let (i, _, note, _, _) = notes.into_iter().next().expect("one note checked");
            (
                i,
                orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                EitherNote::Action(note),
            )
        };
        let mut leaves = Vec::new();
        let mut position = None;
        let mut sapling_tree = zakura_chain::sapling::tree::NoteCommitmentTree::default();
        let mut action_tree = zakura_chain::orchard::tree::NoteCommitmentTree::default();
        for block in &history.blocks {
            for transaction in &block.transactions {
                let commitments: Vec<[u8; 32]> = if pool == "sapling" {
                    transaction
                        .sapling_note_commitments()
                        .map(|c| {
                            converted(sapling_tree.append(*c))?;
                            Ok(c.to_bytes())
                        })
                        .collect::<Result<_>>()?
                } else if pool == "orchard" {
                    transaction
                        .orchard_note_commitments()
                        .map(|c| {
                            converted(action_tree.append(*c))?;
                            Ok(<[u8; 32]>::from(*c))
                        })
                        .collect::<Result<_>>()?
                } else {
                    transaction
                        .ironwood_note_commitments()
                        .map(|c| {
                            converted(action_tree.append(*c))?;
                            Ok(<[u8; 32]>::from(*c))
                        })
                        .collect::<Result<_>>()?
                };
                for (i, c) in commitments.into_iter().enumerate() {
                    if transaction.hash() == hash && i == funding_index {
                        position = Some(leaves.len());
                    }
                    leaves.push(c);
                    require(
                        leaves.len() <= MAX_COMMITMENTS,
                        "history",
                        "commitment_bound",
                    )?;
                }
            }
        }
        let position = needed(position)?;
        require(leaves[position] == commitment, "history", "witnessed_note")?;
        let (note, nullifier) = match note {
            EitherNote::Sapling(note) => {
                let (path, anchor) = sapling_witness(&leaves, position)?;
                // Sapling RPC roots reverse the canonical witness anchor bytes.
                require(
                    anchor.to_bytes() == <[u8; 32]>::from(sapling_tree.root())
                        && sapling_tree.root().bytes_in_display_order() == root
                        && sapling_crypto::Anchor::from(
                            path.root(sapling_crypto::Node::from_cmu(&note.cmu())),
                        ) == anchor,
                    "history",
                    "root_mismatch",
                )?;
                let nf = note
                    .nf(
                        &sapling_key()
                            .to_diversifiable_full_viewing_key()
                            .fvk()
                            .vk
                            .nk,
                        u64::try_from(position).expect("bounded position"),
                    )
                    .0;
                (
                    Note::Sapling(Box::new(SaplingNote { note, path, anchor })),
                    nf,
                )
            }
            EitherNote::Action(note) => {
                let (path, anchor) = action_witness(&leaves, position)?;
                require(
                    anchor.to_bytes() == root
                        && <[u8; 32]>::from(action_tree.root()) == root
                        && path.root(orchard::note::ExtractedNoteCommitment::from(
                            note.commitment(),
                        )) == anchor,
                    "history",
                    "root_mismatch",
                )?;
                let nf = note
                    .nullifier(&FullViewingKey::from(&action_key()))
                    .to_bytes();
                (
                    Note::Action(Box::new(ActionNote { note, path, anchor })),
                    nf,
                )
            }
        };
        for block in &history.blocks {
            for tx in &block.transactions {
                let spent = match pool {
                    "sapling" => tx
                        .sapling_nullifiers()
                        .any(|nf| <[u8; 32]>::from(*nf) == nullifier),
                    "orchard" => tx
                        .orchard_nullifiers()
                        .any(|nf| <[u8; 32]>::from(*nf) == nullifier),
                    _ => tx
                        .ironwood_nullifiers()
                        .any(|nf| <[u8; 32]>::from(*nf) == nullifier),
                };
                require(!spent, "history", "note_spent")?;
            }
        }
        result.push(Funding { pool: source.pool.clone(), note, metadata: json!({
            "pool":pool,"funding_txid":source.txid,"funding_height":height,"funding_output_index":funding_index,
            "position":position,"value_zat":NOTE_VALUE,"anchor":hex::encode(root),"nullifier":hex::encode(nullifier),
            "commitment":hex::encode(commitment),"commitment_count":leaves.len()
        }) });
    }
    Ok(result)
}
enum EitherNote {
    Sapling(sapling_crypto::Note),
    Action(orchard::Note),
}

#[cfg(test)]
mod tests {
    use super::*;
    // Canonical serialization/history tests only: these synthetic successor blocks
    // are deliberately not claimed to have valid PoW or consensus state.
    fn exported() -> ShieldedHistory {
        let genesis = zakura_chain::block::genesis::regtest_genesis_block();
        let mut blocks = vec![genesis.as_ref().clone()];
        for height in 1..=110 {
            let mut block = genesis.as_ref().clone();
            let tx = Arc::make_mut(&mut block.transactions[0]);
            let Transaction::V1 { inputs, .. } = tx else {
                unreachable!("Regtest genesis is v1")
            };
            let ChainInput::Coinbase { height: h, .. } = &mut inputs[0] else {
                unreachable!()
            };
            *h = Height(height);
            let previous = blocks.last().unwrap().hash();
            Arc::make_mut(&mut block.header).previous_block_hash = previous;
            Arc::make_mut(&mut block.header).merkle_root = block.transactions.iter().collect();
            blocks.push(block);
        }
        ShieldedHistory {
            treestate: json!({"height":110,"hash":blocks.last().unwrap().hash().to_string()}),
            blocks: blocks
                .iter()
                .map(|b| hex::encode(b.zcash_serialize_to_vec().unwrap()))
                .collect(),
        }
    }
    #[test]
    fn history_rejects_stale_disconnected_duplicate_and_noncanonical_exports() {
        let mut request = exported();
        let valid = parse(&request).unwrap();
        assert_eq!(valid.tip_height, 110);
        let original = request.treestate.clone();
        request.treestate["height"] = json!(109);
        assert_eq!(parse(&request).err().unwrap().reason, "stale_treestate");
        request.treestate = original.clone();
        request.treestate["hash"] = json!("00".repeat(32));
        assert_eq!(parse(&request).err().unwrap().reason, "stale_treestate");
        request.treestate = original;
        let original = request.blocks[109].clone();
        let mut block = valid.blocks[109].clone();
        Arc::make_mut(&mut block.header).previous_block_hash = valid.blocks[107].hash();
        request.blocks[109] = hex::encode(block.zcash_serialize_to_vec().unwrap());
        assert_eq!(parse(&request).err().unwrap().reason, "disconnected");
        request.blocks[109] = original.clone() + "00";
        assert_eq!(parse(&request).err().unwrap().reason, "canonical_block");
        let mut block = valid.blocks[109].clone();
        block
            .transactions
            .push(valid.blocks[108].transactions[0].clone());
        request.blocks[109] = hex::encode(block.zcash_serialize_to_vec().unwrap());
        assert_eq!(
            parse(&request).err().unwrap().reason,
            "duplicate_transaction"
        );
        request.blocks[109] = original;
        request.blocks[0] = request.blocks[1].clone();
        assert_eq!(parse(&request).err().unwrap().reason, "block_height");
        // A canonical height-0 block with another header is not Regtest genesis.
        let mut genesis = valid.blocks[0].clone();
        Arc::make_mut(&mut genesis.header).time += std::time::Duration::from_secs(1);
        request.blocks[0] = hex::encode(genesis.zcash_serialize_to_vec().unwrap());
        assert_eq!(parse(&request).err().unwrap().reason, "regtest_genesis");
    }
    #[test]
    fn history_parent_resolution_uses_actual_ordered_outputs_and_unspent_state() {
        let request = exported();
        let mut history = parse(&request).unwrap();
        let parent = history.blocks[1].transactions[0].clone();
        let raw = hex::encode(parent.zcash_serialize_to_vec().unwrap());
        assert_eq!(history.parent(&raw, 0).unwrap(), parent.outputs()[0]);
        assert!(history.parent(&raw, 1).is_err());
        let immature = history.blocks[109].transactions[0].clone();
        assert_eq!(
            history
                .parent(&hex::encode(immature.zcash_serialize_to_vec().unwrap()), 0)
                .unwrap_err()
                .reason,
            "parent_maturity"
        );
        let point = OutPoint {
            hash: parent.hash(),
            index: 0,
        };
        history.spent.insert(point);
        assert_eq!(history.parent(&raw, 0).unwrap_err().reason, "parent_spent");
        let other = history.blocks[2].transactions[0].clone();
        let (tx, _) = TransactionRecipe {
            version: 5,
            network_upgrade: NetworkUpgrade::Nu7,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(210),
            spends: vec![
                Spend {
                    outpoint: OutPoint {
                        hash: other.hash(),
                        index: 0,
                    },
                    sequence: 0,
                    previous_output: chain_output(1, vec![]).unwrap(),
                },
                Spend {
                    outpoint: point,
                    sequence: 0,
                    previous_output: chain_output(2, vec![]).unwrap(),
                },
            ],
            outputs: vec![],
        }
        .build();
        let previous = history.previous(&tx, 110).unwrap();
        assert_eq!(
            previous.as_ref(),
            &vec![other.outputs()[0].clone(), parent.outputs()[0].clone()]
        );
        assert_eq!(
            history.previous(&tx, 2).unwrap_err().reason,
            "funding_prevout_height"
        );
        history.transactions.remove(&other.hash());
        assert!(history.previous(&tx, 110).is_err());
    }
    #[test]
    fn encrypted_public_notes_recover_and_finalize_rpc_roots_without_proofs() {
        // Builders only create ciphertext/effecting data here. Zero authorization
        // and proof bytes are explicit placeholders, never passed to a verifier.
        let mut request = exported();
        let mut blocks = parse(&request).unwrap().blocks;
        let Transaction::V1 { outputs, .. } = Arc::make_mut(&mut blocks[4].transactions[0]) else {
            unreachable!("synthetic coinbase is v1")
        };
        outputs[0].lock_script = classical::scripts("single").unwrap().0;
        outputs[0].value = 3_000_000u64.try_into().unwrap();
        let mut sources = Vec::new();
        let mut rng = rand_10::rng();
        for (index, pool) in ["sapling", "orchard", "ironwood"].into_iter().enumerate() {
            let upgrade = if pool == "orchard" {
                NetworkUpgrade::Nu6_2
            } else {
                NetworkUpgrade::Nu7
            };
            let parent = &blocks[index + 1].transactions[0];
            let (mut tx, _) = TransactionRecipe {
                version: if pool == "orchard" { 5 } else { 6 },
                network_upgrade: upgrade,
                lock_time: LockTime::unlocked(),
                expiry_height: Height(200),
                spends: vec![Spend {
                    outpoint: OutPoint {
                        hash: parent.hash(),
                        index: 0,
                    },
                    sequence: u32::MAX,
                    previous_output: parent.outputs()[0].clone(),
                }],
                outputs: vec![],
            }
            .build();
            if pool == "sapling" {
                let mut builder = sapling_crypto::builder::Builder::new(
                    sapling_crypto::note_encryption::Zip212Enforcement::On,
                    sapling_crypto::builder::BundleType::DEFAULT,
                    sapling_crypto::Anchor::empty_tree(),
                );
                builder
                    .add_output(
                        None,
                        sapling_key().default_address().1,
                        sapling_crypto::value::NoteValue::from_raw(NOTE_VALUE),
                        [0; 512],
                    )
                    .unwrap();
                let unsigned = builder
                    .build::<LocalTxProver, LocalTxProver, _, ZatBalance>(&[], &mut rng)
                    .unwrap()
                    .unwrap()
                    .0;
                let fake = unsigned.map_authorization(
                    (),
                    |_, _| [0; 192],
                    |_, _| [0; 192],
                    |_, _| [0; 64].into(),
                    |_, _| sapling_crypto::bundle::Authorized {
                        binding_sig: [0; 64].into(),
                    },
                );
                *sapling_slot(&mut tx) = Some(chain_sapling(&fake).unwrap());
            } else {
                let version = if pool == "orchard" {
                    BundleVersion::orchard_v2()
                } else {
                    BundleVersion::ironwood_v3()
                };
                let mut builder = Builder::new(
                    BundleType::DEFAULT,
                    version,
                    Flags::SPENDS_DISABLED,
                    orchard::Anchor::empty_tree(),
                )
                .unwrap();
                builder
                    .add_output(
                        None,
                        FullViewingKey::from(&action_key()).address_at(0u32, Scope::External),
                        NoteValue::from_raw(NOTE_VALUE),
                        [0; 512],
                    )
                    .unwrap();
                let unsigned = builder.build::<ZatBalance>(&mut rng).unwrap().unwrap().0;
                let fake = unsigned.map_authorization(
                    &mut (),
                    |_, _, _| [0; 64].into(),
                    |_, _| {
                        orchard::bundle::Authorized::from_parts(
                            orchard::Proof::new(vec![0; orchard::Proof::expected_proof_size(2)]),
                            [0; 64].into(),
                        )
                    },
                );
                *action_slot(&mut tx, pool) = Some(chain_action(&fake).unwrap());
            }
            sources.push(ShieldedFundingId {
                pool: pool.into(),
                txid: tx.hash().to_string(),
            });
            blocks[if pool == "orchard" { 102 } else { 110 }]
                .transactions
                .push(Arc::new(tx));
        }
        for height in 1..blocks.len() {
            let previous = blocks[height - 1].hash();
            Arc::make_mut(&mut blocks[height].header).previous_block_hash = previous;
            Arc::make_mut(&mut blocks[height].header).merkle_root =
                blocks[height].transactions.iter().collect();
        }
        request.blocks = blocks
            .iter()
            .map(|b| hex::encode(b.zcash_serialize_to_vec().unwrap()))
            .collect();
        request.treestate["hash"] = json!(blocks.last().unwrap().hash().to_string());
        let mut sapling = zakura_chain::sapling::tree::NoteCommitmentTree::default();
        let mut orchard = zakura_chain::orchard::tree::NoteCommitmentTree::default();
        let mut ironwood = zakura_chain::ironwood::tree::NoteCommitmentTree::default();
        for block in &blocks {
            for tx in &block.transactions {
                for cm in tx.sapling_note_commitments() {
                    sapling.append(*cm).unwrap();
                }
                for cm in tx.orchard_note_commitments() {
                    orchard.append(*cm).unwrap();
                }
                for cm in tx.ironwood_note_commitments() {
                    ironwood.append(*cm).unwrap();
                }
            }
        }
        for (pool, root) in [
            ("sapling", sapling.root().bytes_in_display_order()),
            ("orchard", orchard.root().bytes_in_display_order()),
            ("ironwood", ironwood.root().bytes_in_display_order()),
        ] {
            request.treestate[pool] = json!({"commitments":{"finalRoot":hex::encode(root)}});
        }
        let mut recipe = ShieldedSpendRecipe {
            human_run: true,
            transaction_version: 6,
            pools: vec!["sapling".into(), "orchard".into(), "ironwood".into()],
            parent_hex: hex::encode(blocks[4].transactions[0].zcash_serialize_to_vec().unwrap()),
            output_index: 0,
            expiry_height: 210,
            authorization: "single".into(),
            public_key_hex: None,
            // Finalization must not load parameters or create proofs.
            sapling_parameters: Some(SaplingParameters {
                spend_path: "/unused/spend.params".into(),
                spend_sha256: "11".repeat(32),
                output_path: "/unused/output.params".into(),
                output_sha256: "22".repeat(32),
            }),
            history: request,
            funding_txids: sources,
        };
        let history = parse(&recipe.history).unwrap();
        let notes = recover(&history, &recipe).unwrap();
        assert_eq!(notes.len(), 3);
        let mut spend_tx = context(&recipe).unwrap().tx;
        for note in &notes {
            assert_eq!(note.metadata["value_zat"], NOTE_VALUE);
            assert_eq!(note.metadata["commitment_count"], 2);
            assert_eq!(
                note.metadata["anchor"],
                recipe.history.treestate[&note.pool]["commitments"]["finalRoot"]
            );
            match &note.note {
                Note::Sapling(funding) => {
                    let mut builder = sapling_crypto::builder::Builder::new(
                        sapling_crypto::note_encryption::Zip212Enforcement::On,
                        sapling_crypto::builder::BundleType::DEFAULT,
                        funding.anchor,
                    );
                    builder
                        .add_spend(
                            sapling_key()
                                .to_diversifiable_full_viewing_key()
                                .fvk()
                                .clone(),
                            funding.note.clone(),
                            funding.path.clone(),
                        )
                        .unwrap();
                    let (unsigned, metadata) = builder
                        .build::<LocalTxProver, LocalTxProver, _, ZatBalance>(
                            &[sapling_key()],
                            &mut rng,
                        )
                        .unwrap()
                        .unwrap();
                    assert_eq!(metadata.spend_index(0), Some(0));
                    assert_eq!(
                        hex::encode(unsigned.shielded_spends()[0].nullifier().0),
                        note.metadata["nullifier"]
                    );
                    let fake = unsigned.map_authorization(
                        (),
                        |_, _| [0; 192],
                        |_, _| [0; 192],
                        |_, _| [0; 64].into(),
                        |_, _| sapling_crypto::bundle::Authorized {
                            binding_sig: [0; 64].into(),
                        },
                    );
                    assert_eq!(chain_sapling(&fake).unwrap().spends().count(), 1);
                    *sapling_slot(&mut spend_tx) = Some(chain_sapling(&fake).unwrap());
                }
                Note::Action(funding) => {
                    let version = if note.pool == "orchard" {
                        BundleVersion::orchard_v3()
                    } else {
                        BundleVersion::ironwood_v3()
                    };
                    let flags =
                        Flags::from_byte(if note.pool == "orchard" { 1 } else { 5 }, version)
                            .unwrap();
                    let mut builder =
                        Builder::new(BundleType::DEFAULT, version, flags, funding.anchor).unwrap();
                    builder
                        .add_spend(
                            FullViewingKey::from(&action_key()),
                            funding.note,
                            funding.path.clone(),
                        )
                        .unwrap();
                    let (unsigned, metadata) =
                        builder.build::<ZatBalance>(&mut rng).unwrap().unwrap();
                    let real = metadata.spend_action_index(0).unwrap();
                    assert_eq!(
                        hex::encode(unsigned.actions()[real].nullifier().to_bytes()),
                        note.metadata["nullifier"]
                    );
                    let fake = unsigned.map_authorization(
                        &mut (),
                        |_, _, _| [0; 64].into(),
                        |_, _| {
                            orchard::bundle::Authorized::from_parts(
                                orchard::Proof::new(vec![
                                    0;
                                    orchard::Proof::expected_proof_size(2)
                                ]),
                                [0; 64].into(),
                            )
                        },
                    );
                    *action_slot(&mut spend_tx, &note.pool) = Some(chain_action(&fake).unwrap());
                }
            }
        }
        for version in [5, 6] {
            let final_recipe = ShieldedSpendRecipe {
                human_run: true,
                transaction_version: version,
                pools: recipe
                    .pools
                    .iter()
                    .filter(|pool| version == 6 || *pool != "ironwood")
                    .cloned()
                    .collect(),
                parent_hex: recipe.parent_hex.clone(),
                output_index: 0,
                expiry_height: 210,
                authorization: "single".into(),
                public_key_hex: None,
                sapling_parameters: recipe.sapling_parameters.clone(),
                history: ShieldedHistory {
                    blocks: recipe.history.blocks.clone(),
                    treestate: recipe.history.treestate.clone(),
                },
                funding_txids: recipe
                    .funding_txids
                    .iter()
                    .filter(|source| version == 6 || source.pool != "ironwood")
                    .map(|source| ShieldedFundingId {
                        pool: source.pool.clone(),
                        txid: source.txid.clone(),
                    })
                    .collect(),
            };
            let mut tx = context(&final_recipe).unwrap().tx;
            *sapling_slot(&mut tx) = sapling_slot(&mut spend_tx).clone();
            for pool in final_recipe.pools.iter().filter(|pool| *pool != "sapling") {
                *action_slot(&mut tx, pool) = action_slot(&mut spend_tx, pool).clone();
            }
            let raw = hex::encode(tx.zcash_serialize_to_vec().unwrap());
            // This only checks finalization correspondence and classical signing;
            // the deliberate zero shielded proofs/signatures remain invalid.
            let finalized = finalize(&final_recipe, &raw, None).unwrap();
            assert_eq!(finalized["ecdsa_checks"], 1);
            let TransferData::SpendsAndMaybeOutputs { shared_anchor, .. } =
                &mut sapling_slot(&mut tx).as_mut().unwrap().transfers
            else {
                unreachable!("one Sapling spend")
            };
            assert_ne!(
                hex::encode(<[u8; 32]>::from(*shared_anchor)),
                notes[0].metadata["anchor"]
            );
            assert_eq!(
                hex::encode(shared_anchor.bytes_in_display_order()),
                notes[0].metadata["anchor"]
            );
            *shared_anchor = sapling_crypto::Anchor::empty_tree()
                .to_bytes()
                .try_into()
                .unwrap();
            let changed = hex::encode(tx.zcash_serialize_to_vec().unwrap());
            assert_eq!(
                finalize(&final_recipe, &changed, None).unwrap_err().reason,
                "sapling_spend"
            );
        }
        // The RPC convention is exact: accepting both byte orders would weaken
        // the exported-root guard and conceal this adapter error.
        recipe.history.treestate["sapling"]["commitments"]["finalRoot"] =
            json!(hex::encode(<[u8; 32]>::from(sapling.root())));
        assert_eq!(
            recover(&history, &recipe).err().unwrap().reason,
            "root_mismatch"
        );
        recipe.history.treestate["sapling"]["commitments"]["finalRoot"] = json!("00".repeat(32));
        assert_eq!(
            recover(&history, &recipe).err().unwrap().reason,
            "root_mismatch"
        );
        recipe.history.treestate["sapling"]["commitments"]["finalRoot"] =
            notes[0].metadata["anchor"].clone();
        recipe.funding_txids.swap(0, 1);
        assert_eq!(
            recover(&history, &recipe).err().unwrap().reason,
            "funding_pools"
        );
        recipe.funding_txids.swap(0, 1);
        let mut history = history;
        let hash: Hash = recipe.funding_txids[2].txid.parse().unwrap();
        let mut spent = history.transactions[&hash].1.as_ref().clone();
        let nf = fixed_hex::<32>(notes[2].metadata["nullifier"].as_str().unwrap()).unwrap();
        action_slot(&mut spent, "ironwood")
            .as_mut()
            .unwrap()
            .actions
            .iter_mut()
            .next()
            .unwrap()
            .action
            .nullifier = nf.try_into().unwrap();
        history
            .blocks
            .last_mut()
            .unwrap()
            .transactions
            .push(Arc::new(spent));
        let mut tree = zakura_chain::ironwood::tree::NoteCommitmentTree::default();
        for block in &history.blocks {
            for tx in &block.transactions {
                for cm in tx.ironwood_note_commitments() {
                    tree.append(*cm).unwrap();
                }
            }
        }
        recipe.history.treestate["ironwood"]["commitments"]["finalRoot"] =
            json!(hex::encode(<[u8; 32]>::from(tree.root())));
        assert_eq!(
            recover(&history, &recipe).err().unwrap().reason,
            "note_spent"
        );
    }
    #[test]
    fn real_position_paths_include_later_and_duplicate_leaves() {
        let leaves: Vec<_> = [1u8, 2, 1, 3, 4]
            .into_iter()
            .map(|v| {
                let mut b = [0; 32];
                b[0] = v;
                b
            })
            .collect();
        for (i, leaf) in leaves.iter().enumerate() {
            let (path, root) = action_witness(&leaves, i).unwrap();
            let cm =
                Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(leaf)).unwrap();
            assert_eq!(path.position(), u32::try_from(i).unwrap());
            assert_eq!(path.root(cm), root);
            let (path, root) = sapling_witness(&leaves, i).unwrap();
            let cm = Option::from(sapling_crypto::Node::from_bytes(*leaf)).unwrap();
            assert_eq!(u64::from(path.position()), u64::try_from(i).unwrap());
            assert_eq!(sapling_crypto::Anchor::from(path.root(cm)), root);
        }
        assert_ne!(
            action_witness(&leaves[..1], 0).unwrap().1,
            action_witness(&leaves, 0).unwrap().1
        );
        assert_ne!(
            sapling_witness(&leaves[..1], 0).unwrap().1,
            sapling_witness(&leaves, 0).unwrap().1
        );
    }
    #[test]
    fn paths_reject_missing_and_noncanonical_or_unbounded_inputs() {
        for leaves in [vec![], vec![[255; 32]], vec![[0; 32]; MAX_COMMITMENTS + 1]] {
            assert!(action_witness(&leaves, 0).is_err());
            assert!(sapling_witness(&leaves, 0).is_err());
        }
        assert!(action_witness(&[[0; 32]], 1).is_err());
        assert!(sapling_witness(&[[0; 32]], 1).is_err());
    }
}
