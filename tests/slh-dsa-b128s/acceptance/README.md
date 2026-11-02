# Human acceptance drivers

The [acceptance guide](../../../docs/slh-dsa-b128s/acceptance.md) gives build commands and live scenarios.
Agents must obtain **user approval** before builds and actual node, wallet, signing,
recovery, and terminal runs under [AGENTS.md](../../../AGENTS.md).
Prepare the commands and scope, ask for approval, and wait for the answer.
Importing these modules starts no workload.
Execution receipts start incomplete and retain failed attempts.
Historical results keep their original identities.

Node startup waits for a nonnegative integer `getblockcount` result. Alongside
transport readiness retries, it retries only the pinned Zakura empty-state error
(`-1`, `No blocks in state`), which can precede the genesis commit. Other RPC
errors and malformed heights fail immediately. The existing 60-second bound and
process-exit checks still apply. This reuses the research drivers' startup retry
flow with a narrower error check; it changes no node behavior.

## Offline tests

Install the pinned [wallet-format requirements](../wallet/formats/requirements.txt).
Run the focused suite:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_*.py' -v
```

It uses mocked CLI, RPC, process, signal, and proof interfaces.
It also reuses independent wallet-format calculations.
It starts no node, terminal, signer, build, container, prover, or profiler.
`fake_cli.py` is test-only and is never imported by a live driver.
[Source mappings](sources.json) record hashes and adaptations.
[NOTICE](NOTICE) preserves attribution.

## Additional scenarios

| Area | Guide |
| --- | --- |
| Transparent signatures, mixed inputs, and activation | [Transparent controls](../../../docs/slh-dsa-b128s/transparent-controls.md) |
| Missing or inconsistent wallet history | [History controls](../../../docs/slh-dsa-b128s/history-controls.md) |
| Primitive calls and funded capture windows | [Observations](../../../docs/slh-dsa-b128s/observations.md), [capture controls](../../../docs/slh-dsa-b128s/observation-controls.md) |
| Real shielded proofs, notes, and anchors | [Output controls](../../../docs/slh-dsa-b128s/shielded-controls.md), [spend controls](../../../docs/slh-dsa-b128s/shielded-spend-controls.md) |
| Interrupted writes and processes | [Wallet faults](../../../docs/slh-dsa-b128s/fault-controls.md), [node crashes](../../../docs/slh-dsa-b128s/crash-controls.md) |

Each guide states its required controls and evidence limits.
Offline success does not establish live acceptance, power-loss recovery, or general database durability.

## TPQ on a ZDN-managed devnet

[`zdn_flow.py`](zdn_flow.py) coordinates one bounded full journey through explicit
phases and reviewed evidence references. Only ZDN owns lifecycle writes. The
driver has no arbitrary command hooks, wallet signer, payment journal or direct
cloud writes. It leaves managed `zdn connect` and controlling-terminal wallet
operations at explicit human gates. It does not change the Regtest drivers.
See the [interface and runbook](../../../docs/slh-dsa-b128s/zdn.md#reusable-full-journey-qualification)
for plan/gate schemas, command shapes, uncertain-operation resume and cleanup.

Run only its focused offline tests with:

```sh
PYTHONPATH=tests/slh-dsa-b128s/acceptance python3 -m unittest zdn_test -v
```

This separate test name is intentional: new lane-owned files use the `zdn_`
prefix. The ordinary `test_*.py` discovery command above does not include it.
Tests supply a fake process runner and synthetic public evidence. They do not
start a node, RPC, wallet, PTY, signer, build, Docker or cloud operation.

The config pin protects raw file bytes. The request's `configSha256` is a
separate semantic identity: ZDN hashes its validated parsed Rust `Config`,
serialized as compact JSON. The coordinator checks this digest's shape, not its
equality to the raw pin. It does not parse YAML or reproduce Rust defaults.
ZDN's authoritative `require_config` check still runs during launch with the
pinned config and request. Offline tests accept separately pinned YAML,
commented YAML and pretty JSON. They reject changes behind a frozen raw pin,
malformed semantic digests and bad request schemas. Their semantic fingerprint
is independently specified synthetic data, not output from real ZDN staging.

[`zdn_cases.json`](zdn_cases.json) records selected `SRC-03`, `DEP-02`,
`NET-01/03/04`, `PAY-01/02/03`, `REC-03` and `CLN-01` subcases from ZDN beta
plan v1.0 (2026-10-23), with its document hash. It also defines eight negative
controls. The required journey includes a **new confirmed payment after trusted
restore**, not only restored balances. Every live subcase remains pending.
Offline orchestration checks do not grant beta qualification credit.
