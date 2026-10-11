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
