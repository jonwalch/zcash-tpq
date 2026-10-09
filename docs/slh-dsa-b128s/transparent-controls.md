# Transparent authorization tests

The [driver](../../tests/slh-dsa-b128s/acceptance/transparent_controls.py) prepares
additional Regtest cases for SLH authorization.
Live execution and signing are human-only under [AGENTS.md](../../AGENTS.md).
Offline mocks and host tests do not establish live acceptance.

## Human command

Create matching builds with the [acceptance workflow](acceptance.md).
Use a new artifact directory.
Run the driver:

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

Repeat with `--version 6` and a new `transparent-v6` directory.
The classical control uses public-key 2-of-3 P2SH CHECKMULTISIG.
All classical and SLH fixture keys are public and unsuitable for real funds.
Both connected nodes authenticate the mature coinbase and subsequent unspent outputs.
NU7 activates at 105. SLH activates at 110.

## Cases

| Case | Required result |
| --- | --- |
| Missing classical quorum | Keep the dummy and 2-of-3 redeem script, but remove one ECDSA signature. Relay and blocks reject without state changes. |
| SLH signature in a classical input | Replace one of two ECDSA signatures with a genuine SLH signature. Relay rejects scriptSig size. Blocks reject the classical script. |
| Classical signature in an SLH input | Insert a genuine DER ECDSA signature with its SIGHASH byte. The TXID stays fixed. Canonical encoding and relay checks reject it. |
| Changed SLH authorization | Flip one signature byte through the native codec. Effects and encoding stay fixed. Direct validation reports signature failure. |
| Mixed input families | Test a genuine SLH input with classical 2-of-3, exact `0x51`, or exact `0x52`, in both orders. Active relay and blocks report mixed inputs. |
| Separate classical and SLH transactions | Propose and accept both valid transactions in one block. Check order, exact bytes, spent parents, and resulting UTXOs. |
| Policy versus consensus | Test SLH funding before activation and a 2,402-zatoshi SLH output after activation. Relay rejects the policy violation. Direct blocks accept them. |
| Reorg and reactivation | Repeat authorization and mixed-input checks after invalidation and restart. Preserve funding below activation. Remine the exact valid bytes. |

Unsupported inputs have empty authorization and no verifier backend.
Funding enters a direct block at height 108, after NU7 but before SLH.
Invalidation of height 109 returns to tip 108 with the funding unspent.
Candidate 109 uses legacy rules, so mixed controls must fail Script standardness or verification.
After one block, candidate 110 must reject the same controls under the SLH mixed-input rule.
Missing parents, expiry, and unrelated RPC errors cannot satisfy these checks.

An earlier reorg removes the separate classical and SLH payments.
After restart, authorization controls run against restored parents.
The saved-byte helper then submits and mines the valid transactions again.
Rejected variants share their TXIDs but have different authorization digests.
Reactivation replays the same valid bytes.
The driver preserves Zakura retry and reset behavior. It adds no queue barrier.

## Fixture operations

`control-funding` reuses `classical-spend` and permits the two exact unsupported templates.
Ordinary funding keeps its existing allowlist.
`control-authorization` accepts only transparent NU7 v5/v6 public transactions.
It checks the source shape and changes one input.
It requires a fixed TXID, a changed authorization digest, and complete decoding.
The two signature-family substitutions require donor transactions.

`mixed-prepare` and `mixed-assemble` add the unsupported template modes.
They retain ordinary classical modes.
`control-block` accepts NU7 heights 105–109 and later heights with the existing commitment and fee rules.
It rejects earlier heights and nontransparent shapes.

## Evidence and limits

Receipts retain artifacts, hashes, rejection diagnostics, build identities, configuration identities, and shutdown results.
`execution.json` remains incomplete until all checks and final source/binary checks succeed.
Failures retain artifacts.
These are functional RPC and block tests.
They do not count primitive calls, measure resources, test shielded transactions, or test wallet write faults.

The implementation reuses the research dust, activation, authorization-change, UTXO, and saved-byte test patterns.
It shares product codecs, signers, block builders, node helpers, and retry logic.
The [source map](../../tests/slh-dsa-b128s/acceptance/sources.json)
and [host attribution](../../tests/slh-dsa-b128s/fixtures/host/ATTRIBUTION.md) record adaptations.

## Focused tests

Run these checks without a live workload:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_transparent_controls.py' -v
cargo test --locked -p slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --all-targets -- -D warnings
```

Mocks exercise both rollbacks, exact failures, UTXOs, block order, saved bytes, and valid replay.
Host tests cover both versions, unchanged effects, native signature failure,
template bounds, and NU7 block construction.
Historical artifacts retain their original bytes and identities.
