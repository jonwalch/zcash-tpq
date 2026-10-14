# SLH node and wallet guide

This extension lets a Zakura test network hold and spend transparent funds
with SLH-DSA-B-128s. It includes a node verifier, wallet, command-line interface
(CLI), multisig, backups, recovery, and public address inventories.
SLH is the only added post-quantum (PQ) signature scheme.
Node builds do not include the wallet signer.

Support requires the `experimental-slh-dsa-b128s` feature.
Regtest and isolated custom testnets must set SLH activation after NU7.
The [devnet guide](devnets.md) describes the node APIs for launchers.
The wallet CLI and its operational guides still use Regtest.
The BLAKE3 construction is experimental. It is not a FIPS 205 profile.
The [protocol](protocol.md) specifies the source revisions and the
`slh-dsa-b-128s-exp-v1` contract.

## Use the node and wallet

| Task | Guide |
| --- | --- |
| Configure a test node and identify its verifier | [Runtime](runtime.md) |
| Integrate a public or private devnet launcher | [Custom devnets](devnets.md) |
| Create a wallet, enroll cosigners, and make payments | [CLI commands](cli.md) |
| Back up keys and payment history, then restore them | [Recovery](recovery.md) |
| Understand finite address inventories and watch-only roles | [Wallet behavior](wallet.md#recovery-and-watch-only-behavior) |
| Build matching binaries and run end-to-end scenarios | [Acceptance runbook](acceptance.md) |
| Register measurements and report saved observations | [Benchmark framework](benchmarking.md) |

The build requires Rust 1.97 or later, Git, and Python 3.11 or later.
Each reference suite lists its Python dependencies.
`rust-toolchain.toml` selects the `stable` channel, which changes over time.
Build receipts record the exact compiler version.
The acceptance guide gives the build commands.
[AGENTS.md](../../AGENTS.md) requires agents to obtain user approval before dedicated node builds and live tests.

## Reference and validation

| Area | Guide |
| --- | --- |
| Encodings, signing messages, activation, and limits | [Protocol](protocol.md), [wallet specification](wallet.md) |
| Verification, mempool admission, and mining | [Consensus](consensus.md), [relay and mining](relay-mining.md) |
| Ecosystem decisions for public SLH adoption | [Open questions](open-questions.md) |
| Current fees and fee policy choices | [Fee policy discussion](relay-mining.md#fee-policy-discussion) |
| What has been checked and what remains | [Validation evidence](validation.md) |
| Funding, rejection, restart, and reorg scenarios | [Lifecycle](lifecycle-controls.md), [transparent controls](transparent-controls.md) |
| Missing or inconsistent node history | [Wallet history controls](history-controls.md) |
| Verifier-call logs and their interpretation | [Observations](observations.md), [capture scenarios](observation-controls.md) |
| Shielded outputs, note spends, and anchors | [Output controls](shielded-controls.md), [spend controls](shielded-spend-controls.md) |
| Interrupted wallet writes and node processes | [Wallet faults](fault-controls.md), [node crashes](crash-controls.md) |
| Public test data and independent comparisons | [Fixtures](fixtures.md), [transaction schema](transaction-fixtures.md), [wallet interfaces](../../tests/slh-dsa-b128s/wallet/interfaces/README.md) |
| Source, dependencies, and release contents | [Packaging](packaging.md), [dependency checks](../../tests/slh-dsa-b128s/dependencies/README.md) |
| Changes included in the initial product import | [Initial import notes](initial-import/README.md) |

## Current limits

The implementation includes focused tests and drivers for live scenarios.
The live tests still need successful runs with recorded source and binary hashes.
This includes payment, recovery, terminal, proof-generation, and crash tests.
No performance result establishes readiness for production.
The limits of 16 checks per transaction and 64 checks per block are test settings.

A key backup cannot recover payment history or signatures made after the backup.
A restore with incomplete or untrusted history stays monitor-only.
The [recovery guide](recovery.md) describes the required files and trust decisions.

The repository includes source mappings and licenses.
It excludes internal research notes and history.
The [writing guide](writing.md) defines the documentation style and technical terms.
