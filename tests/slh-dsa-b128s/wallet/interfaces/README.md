# Independent public enrollment and snapshot comparisons

This bounded suite closes two gaps left by the existing wallet format tests:
the CLI's public `enroll-prepare` file/command boundary and operational snapshot
receipt identities/companion bytes. All roots, passwords, keys, encrypted bytes
and identities used here are **public test material**, unsuitable for funds.

`reference.py` imports the existing independent [format oracle](../formats/README.md)
for canonical JSON, policy/key domains, origin mapping, profile validation and
cumulative inventory rules. It checks that source and the unchanged H1/L1
corpora by SHA-256 before use. Expected values use Python's standard library;
there is no production Rust call, subprocess, network request, new signing or
backup KDF in the oracle. The existing format oracle's Python dependencies are
still required to import it. [sources.json](sources.json) records source pins,
schema inputs and adaptations; [NOTICE](NOTICE) preserves attribution.

The new, separate `vectors.json` contains:

- Three cumulative enrollments: 2-of-3 receive, 1-of-1 change and 3-of-3 receive
  at the next local index. Key exchanges, fingerprints, sorted descriptors,
  exact origin mappings, inventories and inventory fingerprints are independent
  answers. Inputs arrive in reverse participant order and external origins use
  large u32 indices. H1 public keys are reused with synthetic public participant
  IDs; this is not evidence of independent funded cosigner ownership.
- A deterministic v2 allocator state after one receiver is issued, the exact
  existing L1 encrypted backup, one retained orphan object, and their complete
  receipt. State SHA-256, backup SHA-256, inventory identity and domain-separated
  journal-root/receipt identities are independently computed from exact bytes.
- Twelve valid receipt identity mutations and nine invalid schema/byte controls.
  The maximum-generation v3 metadata example checks receipt syntax only; it is
  deliberately not a valid journal store or a recoverable authority fixture.

The Rust CLI integration test launches only nonterminal `enroll-prepare` with
public files and closed stdin. It compares the output file and stdout object to
retained answers, verifies that retries cannot replace a candidate, and rejects
eleven transport/pairing/origin mutations without publishing output. The wallet
integration test consumes independently supplied receipt bytes and captures one
bounded snapshot through the public library API, comparing all four companions.
This invokes the existing backup decryption/key check once; it does not run a
live payment, terminal backup or recovery driver.

```sh
python3 -m pip install -r tests/slh-dsa-b128s/wallet/formats/requirements.txt
python3 tests/slh-dsa-b128s/wallet/interfaces/reference.py
python3 -m unittest discover -s tests/slh-dsa-b128s/wallet/interfaces -p 'test_*.py' -v
cargo test --locked -p zakura-pq-cli -p zakura-pq-wallet --features experimental-slh-dsa-b128s --test public_enrollment --test snapshot_conformance
```

The ordinary reference command independently recomputes and compares the entire
retained file. `--write` only creates a new file and refuses replacement. Product
comparisons must never update the reference answers. Both Rust integration files
require Unix and the explicit feature; the default package tests separately
check refusal. No runtime module, crypto implementation, fee rule, schema, pin,
proof-covered approval source or preexisting vector changes for these tests.

## Coverage retained from earlier tests

The gap audit used the following existing consumers, which remain the first
reference. This suite does not repeat their full matrices.

| Existing area | Existing test source |
| --- | --- |
| HKDF, public keys and signatures | [`keys/tests.rs`](../../../../crates/pq-wallet/src/keys/tests.rs), [`suite/tests.rs`](../../../../crates/pq-wallet/src/suite/tests.rs) |
| All 120 policy shapes, receiver/inventory formats and origin mappings | [`watch/tests.rs`](../../../../crates/pq-wallet/src/watch/tests.rs), [`wallet_tests.rs`](../../../../crates/pq-wallet/src/wallet_tests.rs), [`enrollment.rs](../../../../crates/pq-cli/src/enrollment.rs), [`test_formats.py`](../formats/test_formats.py) |
| Proposal/partial identities and independent size/check ceilings | [`payment/tests.rs`](../../../../crates/pq-wallet/src/payment/tests.rs), [`payment/tests/slh_capacity.rs`](../../../../crates/pq-wallet/src/payment/tests/slh_capacity.rs) |
| Exact encrypted backup and authenticated invalid schema controls | [`backup_tests.rs`](../../../../crates/pq-wallet/src/backup_tests.rs) |
| Raw RPC block/hash/Merkle checks, exact amounts, unspent context and transport bounds | [`rpc/tests/payment.rs`](../../../../crates/pq-wallet/src/rpc/tests/payment.rs), [`rpc/tests/discovery.rs`](../../../../crates/pq-wallet/src/rpc/tests/discovery.rs) |
| Snapshot corruption, saved authority, trust restrictions and atomic publication | [`recovery/tests.rs`](../../../../crates/pq-wallet/src/recovery/tests.rs), [`payment/tests/snapshot.rs`](../../../../crates/pq-wallet/src/payment/tests/snapshot.rs) |

Receipt identity proves byte binding, not completeness, freshness, wallet
ownership, a valid chain or retirement of another allocator. Funded independent
quorums, actual trusted RPC/node acceptance and real terminal flows remain
[human validation](../../../../docs/slh-dsa-b128s/acceptance.md) requirements.
