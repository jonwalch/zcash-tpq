# Independent transparent transaction conformance

This checker independently reconstructs transparent v5/v6 transactions and their ZIP 244/229 SIGHASH_ALL digests.
It also reconstructs SLH policies, authorizations, and the 101-byte contract message. It verifies all 146 signatures
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

From a fresh product checkout, compare a new host build with the retained corpus.
First prepare the [independent reference](../reference/README.md).
Choose a new host artifact directory under an existing private parent:

```sh
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind host \
  --artifacts /absolute/private/new-host-build
python3 -m unittest discover -s tests/slh-dsa-b128s/transactions -p 'test_*.py'
python3 tests/slh-dsa-b128s/transactions/check.py /absolute/reference-inputs \
  --comparison-host /absolute/private/new-host-build/slh-dsa-b128s-fixture-host \
  --comparison-build /absolute/private/new-host-build/build.json \
  --output /absolute/private/new-comparison.json
```

The comparison mode needs no signer binary or research checkout.
It does not generate keys or signatures.
It checks the host build receipt against the current committed source and binary.
It preserves the original corpus and producer identities from the pinned
[adapter review receipt](receipts/g2-review-2026-10-09.json).
The new receipt records the current comparison target separately.
Changed corpus, source, binary, build receipt, checker, or reference inputs cause failure.
Keep the local build and comparison receipts together; build commands can contain local paths.
These hashes bind recorded inputs but do not prove a compiler's execution history.

For a newly generated corpus, use its original host and signer as producers:

```bash
python3 -m unittest discover -s tests/slh-dsa-b128s/transactions -p 'test_*.py'
python3 tests/slh-dsa-b128s/transactions/check.py .context/slh-reference \
  --corpus tests/slh-dsa-b128s/fixtures/data \
  --host target/debug/slh-dsa-b128s-fixture-host \
  --signer tests/slh-dsa-b128s/fixture-signer/target/debug/slh-dsa-b128s-public-fixture \
  --output .context/slh-g2-receipt.json
```

Use the actual binary paths for the selected `CARGO_TARGET_DIR` and pass that
corpus directory with `--corpus`. Both binaries
are hash-checked against every artifact's producer claims; this checker invokes
only the host's `check` operation. `--candidate-source-tree` selects the committed
source tree used for those binaries. Inventories use tracked regular files and
reject dirty covered inputs. They identify source bytes; their hashes alone do
not prove a compiler's history. Retain the associated build and generation
record. Receipts require a new output path.
They include raw corpus hashes, source inventories, binary/lock/checker/reference hashes, and outcomes.

Do not combine producer options with `--comparison-host` or `--comparison-build`.
Producer mode still rejects a new binary that did not produce the saved corpus.
Omit all binary arguments to verify saved artifacts with the independent
reference alone. Such a receipt has no producer-source verification or native
comparison and is not a substitute for the complete G2 gate. Later source
changes make old producer hashes differ intentionally; verify the recorded
committed source checkpoint when reproducing the original gate.

The focused oracle tests use explicitly synthetic zero signatures to exercise
schemas, all 120 policy shapes, bounds, correspondence and failure precedence.
Their callbacks do not establish primitive validity. Only the separate full
checker runs real independent verification. Replay tests also reject stale build
identities, modified retained inputs, mixed command modes, and changes during a run.
These tests use mocks and preserve the original producer-mismatch rejection.
Neither workflow runs key generation,
signing, tree generation, live nodes or a performance study.

Coverage is transparent-only. Shielded digests, consensus, relay/mining, and
wallet behavior have separate checks; see the
[validation guide](../../../docs/slh-dsa-b128s/validation.md). Human live
acceptance remains pending. Public fixtures contain only public test material
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

The [adapter review receipt](receipts/g2-review-2026-10-09.json) compares the
corrected host and oracle at `feee7e6352e6e3251369240cb4114ac23548a7ed` against
the same 18 artifacts, with 60 mutation controls. It records the original
artifact producer separately from the current comparison target. The original
artifact bytes and production/build/initial acceptance receipts remain unchanged;
no signatures were regenerated. This distinguishes verification of existing
fixtures from a claim that the updated host produced them.
