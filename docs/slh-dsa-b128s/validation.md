# Validation evidence

The repository records focused crypto, format, library, and mocked driver checks.
Live node, wallet, terminal, proof-generation, crash, and performance tests remain pending.
Agents must obtain user approval before these runs under [AGENTS.md](../../AGENTS.md).
An implementation or a prepared command does not establish a test result.

The [node matrix](../../tests/slh-dsa-b128s/evidence/node-matrix.json) tracks
12 areas and 63 subcontrols.
It links source locations and historical receipts.
It separates missing test preparation from scenarios ready to run after approval.
A **receipt** records the inputs and outcome of one run.
It applies only to the recorded source, binary, and configuration.

## Check the evidence index

```sh
python3 tests/slh-dsa-b128s/evidence/matrix.py --list-gaps
python3 -m unittest discover -s tests/slh-dsa-b128s/evidence -v
```

These commands check required fields, file paths, source hashes, and referenced text.
They do not execute referenced tests, nodes, signers, or live drivers.
They cannot determine whether a test covers its requirement adequately.
After source edits, review the affected mappings and hashes.
Retain every required subcontrol.

| Area | Available checks or prepared cases | Main limit |
| --- | --- | --- |
| Primitive and domains | Independent Pure signatures, length/context limits, wrong hash profiles | Each receipt applies to its recorded build |
| Codec and policy | All 120 shapes, maximum sizes, ordering, and rejection before crypto | Library observations are separate from daemon logs |
| Transaction binding | Independent transparent oracle and separate shielded digest/parser | Supplied previous outputs do not authenticate chain UTXOs |
| Dispatch and migration | Spent-output classification, classical funding, zero SLH work | Funded node outcomes require live runs |
| Mixed inputs | Both input orders, unsupported templates, activation/reorg cases | Prepared drivers are not live rejection evidence |
| Accounting | 16/17 and 64/65 boundaries, atomic budgets, cancellation, no refunds | Live transaction/block limits are unexecuted |
| Publication and mining | Verified identity, parent order, resource selection, shielded failures | Synthetic checks do not establish live proof rejection |
| Builds and gates | Dependency isolation, configuration, default/enabled scenarios | Dedicated daemon builds and startup remain pending and require user approval for agent execution |
| Lifecycle and history | Reset/cache behavior, restarts, rollback, replay, crash scenarios | No deterministic live queue-state or general database durability claim |
| Compatibility | Default/enabled replay for classical and shielded-output transactions. Separate spend/anchor tests. | Spend lifecycle runs use enabled nodes. They are not a default/enabled comparison |

The [acceptance guide](acceptance.md) supplies build commands and scenarios.
Each version and funding profile needs a separate artifact directory.
[AGENTS.md](../../AGENTS.md) requires agents to obtain user approval before heavy tests.
No performance workload is registered here.
Resource measurements require functional acceptance first.

The [benchmark framework](benchmarking.md) adds isolated primitive measurements,
offline result validation and resource/trace adapters. Synthetic tests check
their reporting and failure boundaries. Wallet/node workloads, propagation
instrumentation and all fresh performance evidence remain pending. A framework
unit-test result does not extend any historical live acceptance receipt.

## Test boundaries

Crypto and wallet tests use real signature verification, public retained vectors,
and temporary storage. Signature rejection tests must first accept the unchanged
input. The native, consensus-worker, and wallet suites corrupt signatures in each
input, including the final signer of a 15-of-15 policy. Native assembly checks
every signer as well.
These tests reuse the saved v5/v6 signatures; they need no new signing or node.

Fixture builder tests use complete valid requests before changing one condition.
The block builder accepts one through five supplied transactions. Its tests check
both accepted limits, empty and six-transaction lists, and a nonempty template.
Building a block does not establish valid spends or node acceptance.

Mocks belong at external boundaries: node replies, process control, and injected
storage failures. Driver unit tests check command flow and failure handling.
They do not establish live behavior. Use the real parser, verifier, wallet, and
fixture builder when those components are the subject of the test.
After a reorg, saved transaction bytes must also have active-chain confirmations.
A lookup can return unchanged bytes from the old branch.

## Observations and failures

[Verifier observations](observations.md) count attempted primitive calls within a process and capture window.
They do not count successful signatures or isolate one RPC request.
The [capture driver](observation-controls.md) uses funded positive controls and complete process logs.
Late entries cannot be omitted from a zero-count claim.
Public RPC cannot expose exact pending or completed queue states.

[History controls](history-controls.md) test unavailable, inconsistent, and pruned history.
[Wallet fault controls](fault-controls.md) test named write stages and process kills.
[Node crash controls](crash-controls.md) test specific nonfinalized checkpoints.
Journal quota tests do not test OS disk exhaustion.
A pre-sign entropy error does not test OS entropy suppression.
SIGKILL does not test power loss.

## Independent checking of saved public artifacts

The [transaction checker](../../tests/slh-dsa-b128s/transactions/README.md) checks
the fixed 18-case corpus. The [artifact wrapper](../../tests/slh-dsa-b128s/evidence/artifacts.py)
checks other case names with the same public signed-transaction schema.
It uses the independent wire, digest, and message oracle with the Python/portable-C verifier.
It does not call the host, signer, or node.

Prepare the [reference inputs](../../tests/slh-dsa-b128s/reference/README.md), then run:

```sh
python3 tests/slh-dsa-b128s/evidence/artifacts.py /absolute/reference-inputs \
  --artifact /absolute/public-node-artifacts/budget-0.json \
  --artifact /absolute/public-node-artifacts/budget-1.json \
  --output /absolute/existing-directory/new-independent-receipt.json
```

Use a new output file.
Each batch permits at most 18 artifacts, 2 MiB per file, 8 MiB total, and 146 signature callbacks.
Inputs must be regular files, without symlinks.
They need distinct simple names and case identities.
The wrapper checks schema and work limits before it loads the reference.
The receipt hashes the exact checked bytes.
Source changes, reference changes, non-Boolean results, and mismatches prevent success.

Only complete transparent all-SLH transaction artifacts are accepted.
Classical funding, mixed inputs, blocks, wallet proposals, and execution receipts use different schemas.
Do not change original artifacts to fit this schema.

This check binds signatures to transactions and **supplied previous outputs in input order**.
It does not authenticate UTXOs, check the producer build, establish node acceptance, or cover shielded transactions.
It also does not compare the native implementation.
The fixed-corpus checker supplies native comparison and producer-identity checks.
Its [comparison mode](../../tests/slh-dsa-b128s/transactions/README.md) accepts a
new host build with its matching build receipt. It keeps the retained artifact
producer identity separate from the current comparison target. This lets a fresh
checkout repeat the bounded comparison without a research checkout, old binaries,
or new signatures.

## Historical evidence and independent scope

The [initial primitive receipt](../../tests/slh-dsa-b128s/reference/receipts/g1-initial.json),
[initial transaction receipt](../../tests/slh-dsa-b128s/transactions/receipts/g2-initial.json),
and [corrected transaction comparison](../../tests/slh-dsa-b128s/transactions/receipts/g2-review-2026-10-09.json)
retain their original source and binary identities. They do not certify later builds.
The [consensus receipt](receipts/consensus-library-2026-10-09.json) covers
`27af4949d7ee3211987b5a75b7dbdac8c5355ac5`, when runtime support was false.
It records 16 observer tests and four default tests.
It includes no daemon build or live block test.

The separate [shielded digest target](../../tests/slh-dsa-b128s/shielded/README.md)
covers 12 tests, 114 shielded mutations, four transparent authorization exclusions,
and 36 context comparisons.
Its separate parser shares lower-level hash and curve libraries with the comparison target.
Synthetic bundles check digest behavior but cannot establish proof validity. The [output](shielded-controls.md) and
[spend/anchor](shielded-spend-controls.md) drivers prepare real proofs using upstream
libraries. They are not independent proof verifiers. Only completed matching live
receipts establish their proof and node outcomes.

## Reuse and attribution

The artifact wrapper reuses the existing oracle, reference loader, vectors, and
producer receipts. [Source mappings](../../tests/slh-dsa-b128s/evidence/sources.json)
record the input hashes and adaptations. Reference licenses stay with the test
code. Current source maps can be updated after review. Historical run receipts
must keep their original content and scope.
