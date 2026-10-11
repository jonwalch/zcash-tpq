use super::*;
use crate::payment::approval as gate;

#[test]
fn approval_gate_checks_every_byte_and_preserves_continuation_outcomes() {
    let id = std::array::from_fn(|i| i as u8);
    for index in 0..32 {
        let mut wrong = id;
        wrong[index] ^= 0x80;
        let mut calls = 0;
        let result = gate::release(&id, &wrong, "mismatch", &mut || {
            calls += 1;
            Ok(17)
        });
        assert_eq!(result, Err("mismatch"), "complete approval ID: {index}");
        assert_eq!(calls, 0, "approval continuation calls before rejection");
    }
    for expected in [Ok(17), Err("continuation failed")] {
        let mut calls = 0;
        let result = gate::release(&id, &id, "mismatch", &mut || {
            calls += 1;
            expected
        });
        assert_eq!(result, expected, "approval continuation outcome");
        assert_eq!(calls, 1, "approval continuation calls after acceptance");
    }
}

#[test]
fn proposal_encoding_failure_does_not_hash() {
    let mut encoded = 0;
    let mut hashed = 0;
    let result = gate::proposal_id(
        || {
            encoded += 1;
            Err("encoding failed")
        },
        |_, _| {
            hashed += 1;
            [0; 32]
        },
    );
    assert_eq!(result, Err("encoding failed"), "proposal encoding error");
    assert_eq!(encoded, 1);
    assert_eq!(hashed, 0, "proposal hash before successful encoding");
}

#[test]
fn proposal_id_preserves_complete_canonical_bytes() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
    ))
    .unwrap();
    let rows = corpus["proposals"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let original = row["proposal_json"].as_str().unwrap();
        // Load the independent fixture directly so an omitted Serialize field
        // reaches the exact assertion rather than failing a decoder control.
        let proposal: Proposal = serde_json::from_str(original).unwrap();
        assert_eq!(
            proposal.to_json().unwrap(),
            original.as_bytes(),
            "complete proposal JSON"
        );
        assert_eq!(
            hex::encode(proposal.id().unwrap().0),
            row["proposal_id"],
            "complete proposal ID"
        );
        let id: [u8; 32] = gate::proposal_id(
            || proposal.to_json(),
            |domain, canonical| {
                assert_eq!(domain, b"ZcashTransparentPQ/wallet-proposal/v1\0");
                assert_eq!(canonical, original.as_bytes());
                [73; 32]
            },
        )
        .unwrap();
        assert_eq!(id, [73; 32]);
    }
}

struct ObservedSource {
    source: Source,
    calls: usize,
}
impl ChainSource for ObservedSource {
    fn context(&mut self) -> Result<NodeContext, Error> {
        self.calls += 1;
        self.source.context()
    }
    fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error> {
        self.calls += 1;
        self.source.block_hash(height)
    }
    fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
        self.calls += 1;
        self.source.block_bytes(hash)
    }
}
impl PaymentSource for ObservedSource {
    fn resolve(&mut self, point: Outpoint) -> Result<Option<ResolvedInput>, Error> {
        self.calls += 1;
        self.source.resolve(point)
    }
    fn transaction(&mut self, id: Hex<32>) -> Result<Option<LocatedTransaction>, Error> {
        self.calls += 1;
        self.source.transaction(id)
    }
    fn submit(&mut self, bytes: &[u8]) -> Result<Hex<32>, Error> {
        self.calls += 1;
        self.source.submit(bytes)
    }
}

#[derive(Default)]
struct ObservedRng(usize);
impl RngCore for ObservedRng {
    fn next_u32(&mut self) -> u32 {
        self.0 += 1;
        7
    }
    fn next_u64(&mut self) -> u64 {
        self.0 += 1;
        7
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0 += 1;
        bytes.fill(7);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl CryptoRng for ObservedRng {}

#[test]
fn public_signing_requires_approval_before_fresh_and_cached_release() {
    for version in [5, 6] {
        for count in [1, 3] {
            let wallets = wallets(count, 1, 3);
            let wallet = &wallets[count - 1];
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("store");
            let mut store = create(&path, wallet.manifest(), WatchMode::Allocator);
            let mut source = ObservedSource {
                source: Source::funded(wallet, &[2_000_000]),
                calls: 0,
            };
            let intent = intent(version);
            let (proposal, review) = store.prepare_payment(wallet, &mut source, &intent).unwrap();
            let mut fresh = None;
            for cached in [false, true] {
                for index in 0..32 {
                    let mut wrong = review.proposal_id;
                    wrong.0[index] ^= 0x80;
                    source.calls = 0;
                    let mut rng = ObservedRng::default();
                    let state = serde_json::to_vec(&store.state).unwrap();
                    let disk = fs::read(path.join("state.json")).unwrap();
                    let result = store.sign_payment_with_rng(
                        wallet,
                        &mut source,
                        &proposal,
                        &intent,
                        wrong,
                        &mut rng,
                    );
                    assert!(
                        matches!(result, Err(Error::ProposalMismatch)),
                        "approval before release: cached={cached}, byte={index}: {result:?}"
                    );
                    assert_eq!(source.calls, 0, "approval before node calls");
                    assert_eq!(rng.0, 0, "approval before the test-only signing checkpoint");
                    assert_eq!(serde_json::to_vec(&store.state).unwrap(), state);
                    assert_eq!(fs::read(path.join("state.json")).unwrap(), disk);
                }
                source.calls = 0;
                let mut rng = ObservedRng::default();
                let partials = store
                    .sign_payment_with_rng(
                        wallet,
                        &mut source,
                        &proposal,
                        &intent,
                        review.proposal_id,
                        &mut rng,
                    )
                    .unwrap();
                assert!(!partials.is_empty());
                assert!(source.calls > 0);
                if cached {
                    assert_eq!(rng.0, 0);
                    assert_eq!(Some(partials), fresh);
                } else {
                    assert!(rng.0 > 0);
                    fresh = Some(partials);
                }
            }
        }
    }
}
