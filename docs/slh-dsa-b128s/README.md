# Experimental SLH node and wallet

This is a focused SLH-only extension of upstream Zakura commit
`9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`. The fixed experimental contract is
`slh-dsa-b-128s-exp-v1`, suite `f7`, using the pinned BLAKE3-based algorithm.
It is not the FIPS 205 SHAKE/SHA2 profile. See the [protocol](protocol.md) for
the exact encoding, algorithm pin, activation rules and supported context.

The node verifier, wallet signer and independent references remain separate.
Normal node builds do not contain wallet/signing code. The
`experimental-slh-dsa-b128s` feature is off by default and only supports an
explicitly configured Regtest network after NU7. Classical and shielded rules
retain upstream behavior except the documented SLH integration boundaries.

## Entry points

| Task | Maintained guide |
| --- | --- |
| Enable a disposable Regtest node and inspect runtime identity | [Runtime and configuration](runtime.md) |
| Understand activation, budgets and wire format | [Protocol](protocol.md), [relay and mining](relay-mining.md) |
| Create an encrypted root, enroll independent cosigners and approve payments | [CLI commands](cli.md), [wallet contract](wallet.md) |
| Maintain public finite receive inventory and monitor balances | [Inventory and watch-only behavior](wallet.md#recovery-and-watch-only-behavior) |
| Preserve and restore payment authority | [Recovery artifacts and trust](recovery.md) |
| Run the prepared node/wallet/terminal scenarios | [Human acceptance runbook](acceptance.md), [lifecycle controls](lifecycle-controls.md) |
| Exercise transparent refusal and uncertain wallet history | [Transparent controls](transparent-controls.md), [history controls](history-controls.md) |
| Capture opt-in Regtest primitive attempts | [Observation and bounded receipts](observations.md) |
| Check new public artifacts and inspect validation coverage | [Independent evidence and coverage](validation.md) |
| Compare public enrollment and snapshot identities | [Independent wallet interfaces](../../tests/slh-dsa-b128s/wallet/interfaces/README.md) |
| Audit source, dependencies and archives | [Packaging](packaging.md), [dependency guard](../../tests/slh-dsa-b128s/dependencies/README.md) |

Use the committed Rust toolchain, Git, Python 3.11 or later, and the exact Python
requirements beside each reference suite. A full source checkout is required
for history/content checks. Build receipts and exact feature commands are in
the acceptance runbook. Dedicated node builds and live node/wallet/terminal
validation are human-only under [AGENTS.md](../../AGENTS.md); the content guard
and its focused Python tests perform no such work.

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/release-content -p 'test_*.py' -v
python3 tests/slh-dsa-b128s/release-content/check.py
```

## Recovery and limits

Keep encrypted backups and independent inventory/snapshot receipt fingerprints
outside disposable working state. An operational snapshot contains `backup.tpq`,
`receipt.json`, `watch/state.json` and the existing immutable `watch/journal/`
when present. Retain every required participant's backup for the intended quorum.
Inventory-only or unknown-authority restore remains monitor-only. A trusted
snapshot cannot recover later lost signatures or prove an old allocator stopped;
the [recovery guide](recovery.md) describes the required trust and retirement.

The 16-check transaction/64-check block profile is a functional test setting,
not a production budget. Library/reference/mock evidence is distinct from live
funded acceptance. The runbook records unexecuted human cases, prepared hostile
history and observation tools, and remaining shielded-fixture, durable-fault and
scenario-specific capture preparation.
No production readiness, live recovery, performance or proof-validation result
is implied by packaging success.

Upstream and imported MIT/Apache-2.0 licenses, per-module notices and public
vector provenance are retained. The [import ledger](imports.json) maps every
post-upstream file change to its disposition and attribution. Public research
URLs identify sources; the research checkout, notes, experiment tree and Git
history are not dependencies or product contents. Publication to a new remote
and release destinations remains a separate action.
