# Independent transparent transaction conformance

This checker independently reconstructs the complete transparent v5/v6 wire
transaction, ZIP 244/229 SIGHASH_ALL, SLH descriptors/commitments/authorizations,
and the 101-byte `slh-dsa-b-128s-exp-v1` message. It verifies all 146 signatures
in the 18 prescribed public artifacts using the separately pinned
[Python/portable-C reference](../reference/README.md). Expected digests and
cryptographic verdicts never call the production implementation. The fixture
host is only an optional comparison target after the independent computation.

It also runs 60 negative controls with explicit expected interface stages or
native rejection codes, plus independent old-domain and double-Pure-framing
controls. Mutation cases reconstruct redundant hashes/digests/messages when
exercising native rejection. Separate mismatch cases test those correspondence
checks. Structural errors are checked before any signature work. The 17-check
case is natively valid and fails only the explicit 16-check test profile.
Context rejection still checks every raw-decodable authorization against its
metadata. Unknown or version-ineligible branch IDs and all-zero outpoint hashes
fail wire decoding before native evaluation.
The interface, initial recipes and bounds are defined in
[transaction fixtures](../../../docs/slh-dsa-b128s/transaction-fixtures.md).

From the product repository root, after preparing the reference and corpus:

```bash
python3 -m unittest discover -s tests/slh-dsa-b128s/transactions -p 'test_*.py'
python3 tests/slh-dsa-b128s/transactions/check.py .context/slh-reference \
  --corpus tests/slh-dsa-b128s/fixtures/data \
  --host target/debug/slh-dsa-b128s-fixture-host \
  --signer tests/slh-dsa-b128s/fixture-signer/target/debug/slh-dsa-b128s-public-fixture \
  --output .context/slh-g2-receipt.json
```

Use the actual binary paths for the selected `CARGO_TARGET_DIR`. Both binaries
are hash-checked against every artifact's producer claims; this checker invokes
only the host's `check` operation. `--candidate-source-tree` selects the committed
source tree used for those binaries. Inventories use tracked regular files and
reject dirty covered inputs. They identify source bytes; their hashes alone do
not prove a compiler's history. Retain the associated build and generation
record. Receipts require a fresh output path and include exact raw corpus-file
hashes, source inventory lists, binary/lock/checker/reference hashes and outcomes.

Omit both binary arguments to verify saved artifacts with the independent
reference alone. Such a receipt has no producer-source verification or native
comparison and is not a substitute for the complete G2 gate. Later source
changes make old producer hashes differ intentionally; verify the recorded
committed source checkpoint when reproducing the original gate.

The thirteen cheap unit tests use explicitly synthetic zero signatures to exercise
schemas, all 120 policy shapes, bounds, correspondence and failure precedence.
Their callbacks do not establish primitive validity. Only the separate full
checker runs real independent verification. Neither workflow runs key generation,
signing, tree generation, live nodes or a performance study.

Coverage is transparent-only. Shielded digest effects/exclusions, consensus,
relay/mining, operational wallet/CLI/backup/recovery and human live acceptance
remain separate pending gates. Public fixtures contain only public test material
and synthetic previous outputs; they do not authenticate real UTXOs.

The [initial G2 receipt](receipts/g2-initial.json) records independent agreement
for all 18 artifacts, 146 signatures, 55 typed mutations, two message controls
and 105 official portable-C BLAKE3 controls. The accompanying
[production receipt](receipts/production.json) records deterministic generation,
source inventories and raw artifact hashes; the
[build record](receipts/producer-build.json) identifies the compiler,
configuration, locks and exact invoked binaries. All three bind producer source
checkpoint `324a9311ec499f981d06addcb203678ffff2a1ae`. This is bounded native
conformance evidence, with the pending coverage above unchanged.
