# SLH validation evidence

The [node matrix](../../tests/slh-dsa-b128s/evidence/node-matrix.json) maps all
12 required areas into 63 subcontrols. Each subcontrol links exact source
anchors, prepared human cases or historical receipts, and records missing
preparation separately. **It does not claim functional acceptance.** A test
function's presence, a source hash and a prepared driver are not execution
receipts. Source references are pinned to the recorded checkpoint and hashes;
historical receipts keep their original source, binary and configuration scope.

The index consistency check is offline and runs no referenced Rust test, node,
signer, proof generator or live driver:

```sh
python3 tests/slh-dsa-b128s/evidence/matrix.py --list-gaps
python3 -m unittest discover -s tests/slh-dsa-b128s/evidence -v
```

The first command checks exact fields, all required subcontrol identities,
relative regular-file references, anchors and source hashes. It cannot determine
whether a test semantically proves its requirement. Independent source review
and actual execution evidence remain necessary. Deliberate source changes need
review of the affected mapping and updated reference hashes; do not remove a
subcontrol merely to make the guard pass.

| Area | Existing bounded coverage or preparation | Remaining distinction |
| --- | --- | --- |
| Primitive and domains | Pure answers, context bounds, key/signature regions, wrong hash profiles | Historical primitive receipts remain checkpoint-specific |
| Codec and policy | 120 shapes, high index, maximum wire size, canonical encoding, structural ordering | Library observation is not daemon primitive telemetry |
| Transaction binding | Transparent independent oracle; separate shielded parser/digest comparisons | Supplied previous outputs are not authenticated UTXOs; valid proof/node cases remain separate |
| Dispatch | Exact spent-output recognition, decoys and worker dispatch; prepared enabled/default control | Live execution and daemon entry observations pending |
| Migration | Classical authorization/funding, explicit zero accounting, later SLH threshold | Missing classical quorum and same-input signature-family substitution need dedicated real cases |
| Mixed inputs | Library classification; genuine both-order relay/direct-block driver | Unsupported-template variants and mixed candidates across activation/reorg need preparation |
| Accounting | 16/17, 64/65, concurrent atomic budgets, no refunds; prepared live limits | Prepared live cases remain unexecuted |
| Publication/mining | Bound payload identity, atomic selection, parent ordering, maximum authorization | Generic late failure and synthetic shielded resource counts do not prove real shielded failure suppression |
| Build/gates | Dependency isolation, configuration/gate tests; prepared default/enabled build/startup controls | Dedicated daemon builds and startup cases are human-only |
| Lifecycle | Tip reset, signature/payload identity, prepared-cache bypass; rollback/reorg driver | Deterministic pending/completed/stored queue barriers and same-TXID live mutation are not prepared |
| Persistent history | Namespaces, clean restart, ordinary backups; optional fresh block replay/recovered spend | No crash durability or future-contract-version migration claim; finalized DB internals are not inspected |
| Compatibility | Classical parity and active SLH enabled/default driver; policy separation tests | Explicit nonstandard-but-consensus-valid, unsupported-template and real shielded compatibility variants remain |

Run prepared human cases exactly as described in [acceptance.md](acceptance.md)
and [lifecycle-controls.md](lifecycle-controls.md): both transaction versions and
both classical funding profiles, plus a separate `--finalized-history` run.
The matrix identifies the actual driver function or assertion for each claim.
All node/build/wallet/terminal workloads remain human-only under
[AGENTS.md](../../AGENTS.md). No performance workload is registered here;
resource sampling preparation remains gated on human functional acceptance.

## Independent checking of saved public artifacts

The existing fixed-corpus [transaction checker](../../tests/slh-dsa-b128s/transactions/README.md)
requires its original 18 case names and recipes. The new
[artifact wrapper](../../tests/slh-dsa-b128s/evidence/artifacts.py) accepts arbitrary
case names from the **same exact public signed-transaction schema**, so a saved
human case can be checked without rewriting it into a corpus recipe. It directly
reuses the unchanged independent wire/digest/message oracle and checked
Python/portable-C primitive reference. It never invokes the native host, signer
or node, and its receipt is explicitly independent-only.

Prepare the pinned reference inputs using the existing
[reference instructions](../../tests/slh-dsa-b128s/reference/README.md), then run:

```sh
python3 tests/slh-dsa-b128s/evidence/artifacts.py /absolute/reference-inputs \
  --artifact /absolute/public-node-artifacts/budget-0.json \
  --artifact /absolute/public-node-artifacts/budget-1.json \
  --output /absolute/existing-directory/new-independent-receipt.json
```

The output must be new and its parent must exist. A batch is limited to 18
artifacts, 2 MiB per file, 8 MiB total and 146 signature callbacks. Every input's
schema, duplicate identity and aggregate work bounds are checked before loading
the reference. Only regular, non-symlink input files with simple distinct
filenames/case identities are accepted. Exact retained input bytes are both
parsed and hashed, so later replacement does not change the receipt's meaning.
Checker sources and the reference build/library identities must remain unchanged
through the run. Reference failures, non-Boolean verdicts and expectation
mismatches produce no successful receipt. The unchanged oracle computes its
observed result before comparing the artifact's supplied expectation.

Supported examples include `budget-0.json`, `post-replay.json`,
`block-transaction-0.json` and `compatibility-slh-spend.json` from the prepared
node/control drivers. Pass only complete signed all-SLH transaction artifacts.
Classical funding objects, mixed-input helper envelopes, blocks, wallet proposals
and execution receipts use different schemas and are rejected. Never rewrite
original artifact bytes or producer receipts to make a comparison pass.

The wrapper verifies transparent bytes, digests, messages and SLH authorization
against **ordered caller-supplied previous outputs**. Its receipt does not
verify producer provenance, authenticate chain UTXOs, establish node acceptance,
observe daemon primitive entries, cover shielded transactions or compare a
production implementation. Bind it to a separately successful human execution
receipt and actual parent/tip evidence before making those separate claims.
The existing fixed-corpus checker remains the path for native comparison and
producer identity verification; neither result upgrades the other by implication.

## Historical evidence and independent scope

The immutable [G1 receipt](../../tests/slh-dsa-b128s/reference/receipts/g1-initial.json),
[G2 receipt](../../tests/slh-dsa-b128s/transactions/receipts/g2-initial.json) and
[later G2 comparison receipt](../../tests/slh-dsa-b128s/transactions/receipts/g2-review-2026-10-09.json)
retain the original primitive/corpus producer and comparison identities. Their
coverage and pending fields describe those checkpoints. The
[consensus library receipt](receipts/consensus-library-2026-10-09.json) is explicitly
for `27af4949d7ee3211987b5a75b7dbdac8c5355ac5`: runtime support was still false,
its SLH selections were 16 observer/4 default tests, and it does not certify later
runtime integration, RPC tests or a daemon build. Do not relabel it with a new
commit or interpret its shared-budget tests as live direct-block acceptance.

The existing [shielded target](../../tests/slh-dsa-b128s/shielded/README.md),
introduced by `88e834a8d` and integrated as `7a8c5a84e`, has 12 offline tests:
114 shielded mutations, four transparent authorization exclusions and 36 context
comparisons. Its source files remain unchanged at the matrix checkpoint. Prior
execution evidence belongs to that earlier checkpoint; this work does not rerun
or upgrade it. The separate pinned parser/digest reference shares low-level
hash, curve and librustzcash-family libraries with the comparison target. It
covers synthetic shielded bundles and effects, not proof validity, genuine SLH
signatures on those shapes, or node acceptance. A narrow attributed adapter for
valid proof/signed-shielded cases and a failed-shielded-authorization case is
still required before those human runs can be prepared.

## Reuse and attribution

No existing oracle, vector, producer receipt, acceptance driver or runtime source
is changed by these tools. [Evidence source mappings](../../tests/slh-dsa-b128s/evidence/sources.json)
record exact inputs and adaptation scope. The wrapper reuses G2's bounded file
reader and complete oracle, and the pinned G1 reference loader. Its preflight,
receipt binding and fixed work limits are new glue for arbitrary saved cases.
The source/byte receipt approach was checked against the MIT/Apache-2.0 research
acceptance helper at `e759cb86a06510893f8e7d1eb986b7025401c8c9`;
no broad driver or measurement stack was copied. Independent reference licensing
and attribution remain in the existing reference directory. Unrelated upstream
Zakura issues are outside these completion gates.
