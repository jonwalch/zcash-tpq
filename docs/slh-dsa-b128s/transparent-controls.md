# Transparent authorization and lifecycle controls

The [acceptance adapter](../../tests/slh-dsa-b128s/acceptance/transparent_controls.py)
prepares additional disposable Regtest cases for the SLH-only runtime. Actual
execution and signing remain **human-only** under [AGENTS.md](../../AGENTS.md).
The offline mock suite and fixture-host tests do not establish live acceptance.
Use the clean-source, binary and build receipts from the
[acceptance runbook](acceptance.md); every run requires a new artifact directory.

```sh
python3 tests/slh-dsa-b128s/acceptance/transparent_controls.py --human-run \
  --node "$SLH_ACCEPTANCE_ROOT/node-slh/zakurad" \
  --node-build "$SLH_ACCEPTANCE_ROOT/node-slh/build.json" \
  --host "$SLH_ACCEPTANCE_ROOT/host/slh-dsa-b128s-fixture-host" \
  --host-build "$SLH_ACCEPTANCE_ROOT/host/build.json" \
  --signer "$SLH_ACCEPTANCE_ROOT/signer/slh-dsa-b128s-public-fixture" \
  --signer-build "$SLH_ACCEPTANCE_ROOT/signer/build.json" \
  --version 5 --artifacts "$SLH_ACCEPTANCE_ROOT/transparent-v5"
```

Repeat with `--version 6` and a distinct `transparent-v6` directory. The classical
control is the existing fixed public-key 2-of-3 P2SH CHECKMULTISIG policy. Its
public secret scalars and all SLH fixture keys are unsuitable for real funds.
The driver authenticates the same mature coinbase and subsequent unspent outputs
through both connected nodes. NU7 activates at 105; SLH activates at 110.

| Prepared case | Required observations |
| --- | --- |
| Missing classical quorum | Remove one of two genuine ECDSA signatures while retaining the multisig dummy and exact 2-of-3 redeem script. Relay and direct-block rejection preserve the parents and tip. |
| SLH signature substituted into the same classical input | Retain one ECDSA signature; replace the second signature with a genuine SLH signature. Relay rejects the oversized scriptSig and block validation rejects the classical script. This attempted hybrid quorum cannot authorize the classical input. |
| Classical signature substituted into the same SLH input | Replace a signature push with the genuine DER ECDSA signature plus SIGHASH byte. The TXID and outputs stay fixed; canonical SLH encoding and relay admission reject it. |
| Changed SLH authorization | Flip one signature byte using the native codec. Encoding and effects stay fixed; direct validation must report the signature failure. |
| Mixed transparent input families | A genuinely signed SLH input plus classical 2-of-3, exact unsupported `0x51`, or exact unsupported `0x52` funding, in both input orders. Active relay/block validation must report mixed inputs. The unsupported inputs have empty authorization and no backend. |
| Separate classical and SLH transactions | Both valid transactions are proposed and then accepted in one block. Verify ordered TXIDs, full transaction/block bytes, spent parents and resulting UTXOs. |
| Relay policy versus consensus | Correct classical funding to SLH outputs before activation, and a 2,402-zatoshi SLH output after activation, reject for the specific policy reason but are accepted in direct blocks. |
| Reorg, rollback and reactivation | Recheck the authorization variants and all mixed forms after a real block invalidation/restart, retain the original funding while rolling below SLH, and check the candidate-height activation boundary. Reconcile and remine the exact saved valid transaction bytes. |

Funding is placed in a direct block at height 108, after NU7 and before SLH.
This preserves real unspent parents when the driver invalidates height 109 and
returns to tip 108. At that tip, candidate 109 uses legacy script rules and the
mixed controls must fail for script standardness/verification. After mining one
block, candidate 110 is active and must reject the same funded mixed candidates
for the SLH mixed-input rule. Missing parents, expiry or unrelated RPC errors
cannot stand in for these expected failures.

The earlier reorg removes the block containing the separate classical and SLH
payments. After a disposable restart, all authorization controls run again
against the restored parents, then the existing saved-byte reconciliation helper
resubmits/mines the valid transactions. Their TXIDs match the rejected variants;
their authorization digests differ. The same saved valid bytes are replayed after
reactivation. Restarts preserve existing Zakura retry behavior; this driver does
not create a queue barrier or change reset semantics.

Receipts retain full public transaction/block artifacts, hashes, exact rejection
diagnostics, source/build/binary/config identities and node shutdown results.
`execution.json` starts incomplete and only becomes complete after all checks and
source/binary rechecks. A failed run retains its artifacts. These are functional
RPC/block observations: the driver does not enable primitive-entry logging,
claim zero primitive calls, establish isolated request counts, measure resources,
or cover shielded transactions and durable wallet faults.

The explicit fixture operations are `control-funding` and
`control-authorization`. The first reuses `classical-spend` and permits only the
two additional exact unsupported templates. Ordinary funding retains its original
allowlist. The second accepts only transparent NU7 v5/v6 public transactions,
checks the expected source authorization shape, modifies one input, and requires
unchanged TXID, changed authorization digest and complete byte decoding. Donor
transactions are mandatory only for the two signature-family substitutions.
`mixed-prepare`/`mixed-assemble` retain ordinary classical modes and add the two
unsupported template modes. The existing `control-block` now accepts NU7 heights
105–109 as well as later heights, with the same branch, commitment and miner-fee
rules; it rejects pre-NU7 heights and nontransparent shapes.

The implementation reuses the pinned research relay dust/preactivation controls,
same-TXID authorization mutation, history UTXO checks and saved-byte lifecycle
flows. It reuses the product native codec, public classical signer, block builder,
node lifecycle, single-input SLH fixture generation and retry reconciliation.
Exact source mappings and adaptations are recorded in
[sources.json](../../tests/slh-dsa-b128s/acceptance/sources.json), with host details
in [ATTRIBUTION.md](../../tests/slh-dsa-b128s/fixtures/host/ATTRIBUTION.md).

Permitted focused checks, which launch no live workload:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_transparent_controls.py' -v
cargo test --locked -p slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --all-targets -- -D warnings
```

The mocked flow exercises the real driver through both rollbacks, strict negative
diagnostics, present UTXOs, block ordering, complete saved bytes and valid replay.
Host tests check both transaction versions, fixed transaction effects, actual
native signature failure, unsupported-template bounds, and NU7 block construction.
Historical fixture artifacts are checked without regeneration or relabeling.
