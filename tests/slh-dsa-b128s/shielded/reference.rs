//! Separately parsed librustzcash-family digest path; no production digest or framing.

use zakura_chain::{serialization::ZcashSerialize, transaction::Transaction, transparent::Output};
use zakura_pq_tx_context::NetworkDomain;
use zcash_primitives::transaction as reference;
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_transparent::{
    address::Script,
    bundle,
    sighash::{SighashType, SignableInput, TransparentAuthorizingContext},
};

#[derive(Clone, Debug)]
struct PreviousOutputs(Vec<bundle::TxOut>);

impl bundle::Authorization for PreviousOutputs {
    type ScriptSig = Script;
}

impl TransparentAuthorizingContext for PreviousOutputs {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.0.iter().map(|output| output.value()).collect()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.0
            .iter()
            .map(|output| output.script_pubkey().clone())
            .collect()
    }
}

impl bundle::MapAuth<bundle::Authorized, PreviousOutputs> for PreviousOutputs {
    fn map_script_sig(&self, script: Script) -> Script {
        script
    }
    fn map_authorization(&self, _: bundle::Authorized) -> PreviousOutputs {
        self.clone()
    }
}

struct ReferenceAuthorization;
impl reference::Authorization for ReferenceAuthorization {
    type TransparentAuth = PreviousOutputs;
    type SaplingAuth = <reference::Authorized as reference::Authorization>::SaplingAuth;
    type OrchardAuth = <reference::Authorized as reference::Authorization>::OrchardAuth;
}

// Uses the separately implemented librustzcash digest path and wire parser;
// never calls Zakura's SigHasher or trusts a digest from the fixture.
pub fn digest(
    tx: &Transaction,
    outputs: &[Output],
    branch: BranchId,
    mode: SighashType,
    index: Option<usize>,
) -> [u8; 32] {
    assert_eq!(outputs.len(), tx.inputs().len());
    let raw = tx.zcash_serialize_to_vec().unwrap();
    let tx = reference::Transaction::read(raw.as_slice(), branch)
        .unwrap()
        .into_data();
    // V5/v6 parsers read the embedded branch and ignore read()'s branch argument.
    // Check it explicitly so the reference cannot silently hash another context.
    assert_eq!(tx.consensus_branch_id(), branch);
    assert!(tx.version().valid_in_branch(branch));
    let parts = tx.digest(reference::txid::TxIdDigester);
    let previous = PreviousOutputs(
        outputs
            .iter()
            .map(|output| {
                bundle::TxOut::read(&mut output.zcash_serialize_to_vec().unwrap().as_slice())
                    .unwrap()
            })
            .collect(),
    );
    let data = tx.map_authorization::<ReferenceAuthorization>(previous, (), ());
    let input = match index {
        Some(index) => {
            let bundle = data.transparent_bundle().unwrap();
            let output = &bundle.authorization.0[index];
            reference::sighash::SignableInput::Transparent(
                SignableInput::from_parts(
                    bundle,
                    mode,
                    index,
                    output.script_pubkey(),
                    output.script_pubkey(),
                    output.value(),
                )
                .unwrap(),
            )
        }
        None => {
            assert_eq!(mode, SighashType::ALL);
            reference::sighash::SignableInput::Shielded
        }
    };
    *reference::sighash::signature_hash(&data, &input, &parts).as_ref()
}

// The SLH message contract is written here without production framing constants.
// The independently parsed transaction supplies version and branch assertions.
pub fn message(
    tx: &Transaction,
    outputs: &[Output],
    index: usize,
    network: NetworkDomain,
) -> [u8; 101] {
    let version = match tx {
        Transaction::V5 { .. } => 5,
        Transaction::V6 { .. } => 6,
        _ => panic!("shielded SLH controls define only v5/v6"),
    };
    let mut message =
        Vec::from(b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/message/v1\0".as_slice());
    message.extend([
        0xf7,
        match network {
            NetworkDomain::Mainnet => 0,
            NetworkDomain::Testnet => 1,
            NetworkDomain::Regtest => 2,
        },
        version,
    ]);
    message.extend(0x7719_0ad9_u32.to_le_bytes());
    message.extend(u32::try_from(index).unwrap().to_le_bytes());
    message.extend(digest(
        tx,
        outputs,
        BranchId::Nu7,
        SighashType::ALL,
        Some(index),
    ));
    message.try_into().unwrap()
}
