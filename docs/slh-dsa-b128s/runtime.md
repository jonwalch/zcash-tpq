# Experimental SLH runtime wiring

The daemon feature `experimental-slh-dsa-b128s` selects the existing consensus
verifier and RPC mining accounting together. It is off by default and adds no
signer or fixture dependency. Configured activation also requires
`zakura_consensus::supports_experimental_slh_dsa_b128s()`: that support signal
remains false until the complete runtime release gate is cleared. Library checks
alone do not establish daemon startup or live acceptance.

## Verifier identity

The exact standalone command `zakurad --slh-dsa-b128s-verifier-identity` prints one
JSON object and exits before node initialization. It does not load configuration,
start services or execute cryptography. Additional arguments take the ordinary
CLI parser path. Both default and feature-enabled builds recognize the query.

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` |
| `contract` | `slh-dsa-b-128s-exp-v1` |
| `suite_id` | `f7` |
| `backend` | `portable-rust` with the verifier compiled, otherwise `disabled` |
| `algorithm_revision` | `b392fe82d2d9770142477a576a758a233888bc0a` |
| `blake3_version` | `1.8.5` |
| `verifier_compiled` | Whether consensus was compiled with the SLH feature |
| `runtime_supported` | Whether the complete runtime startup gate is open |

The algorithm and hash fields identify the experimental contract even when the
verifier is disabled; inspect `verifier_compiled` and `backend` together. Runtime
support is distinct from compiled verifier availability. The external receipt
must bind exact source, dependency features, executable and configuration hashes.
The identity does not assert those hashes or independently establish provenance.

## Configuration and lifecycle

A functional test profile uses the following fields; these limits are test
parameters, not deployment recommendations:

```toml
[network]
network = "Regtest"

[network.testnet_parameters]
activation_heights = { "NU6.3" = 1, NU7 = 105 }
experimental_slh_dsa_b128s_activation_height = 110
experimental_slh_dsa_b128s_max_checks_per_transaction = 16
experimental_slh_dsa_b128s_max_checks_per_block = 64
```

All three SLH fields are required together. The activation height is nonzero,
Regtest-only and strictly after NU7 and all checkpoints. Limits satisfy
`0 < transaction <= block <= u32::MAX`. Public and custom public networks reject
SLH fields. A build without complete runtime support refuses configured startup.

Database and non-finalized backup paths use
`regtest-slh-dsa-b128s-v1-hH-tT-bB`. Changing the SLH gate or either limit selects a
fresh namespace. Existing plain Regtest state and old rule namespaces are never
copied, renamed or opened as the new history. The suffix identifies the v1 contract;
a future incompatible contract must use a distinct namespace.

Mempool admission uses candidate-next-block height. Chain-tip notifications reset
before the first active SLH candidate, on forks and rollbacks, and when several
updates coalesce across activation. The existing upstream reset path drops the
whole prior active state, including pending and completed downloads and stored
results, then queues transactions for verification at the new tip. F's existing
constructor supplies the same network to fresh storage. No parallel mempool
lifecycle is introduced. Both prepared-block cache lookup and insertion bypass
active SLH blocks, as specified by the [consensus boundary](consensus.md).

## Validation boundary

Selected library checks cover parameter and configuration rejection, unchanged
defaults, state/backup namespace isolation, activation/rollback/reactivation,
same-height forks, coalesced tip updates, and JSON identity under both feature
modes. They use mocked tips and temporary directories. No new proof fixture,
live node, daemon build, restart/reorg suite or performance workload is run by
these checks.

```sh
cargo test --locked -p zakura-chain -p zakura-network -p zakura-state --lib slh
cargo test --locked -p zakura-consensus --lib slh
cargo test --locked -p zakura-consensus --lib --features slh-test-observer slh
cargo clippy --locked -p zakura-chain -p zakura-network -p zakura-state -p zakura-consensus --all-targets -- -D warnings
cargo clippy --locked -p zakura-consensus --all-targets --features slh-test-observer -- -D warnings
```

The daemon identity entry point, feature forwarding, startup refusal and mempool
storage/reset consumers are source-reviewed only at this checkpoint. A human must
build and execute the daemon and required live acceptance under the repository's
[agent rules](../../AGENTS.md). Runtime activation remains unavailable here.

## Reused sources

The identity query follows the existing one-argument early-exit command and
backend-identity facade from research revision
`e759cb86a06510893f8e7d1eb986b7025401c8c9`, preserving its MIT/Apache-2.0 source
attribution. The typed JSON facade adds the SLH contract, fixed algorithm/hash
pins and separate compiled/runtime flags; it uses existing Serde dependencies.
No alternate verifier or research runtime dependency is imported.

| Target | Research source at that revision | Adaptation |
| --- | --- | --- |
| `crates/zakurad/src/bin/zakurad/main.rs` | `node/zakura/crates/zakurad/src/bin/zakurad/main.rs` | Same exact-argument early-exit mechanism with the SLH identity facade |
| `crates/zakura-consensus/src/slh_identity.rs` and `lib.rs` | `node/zakura/crates/zakura-consensus/src/transaction/sqisign.rs` | Typed fixed-profile identity, no alternate backend/CPU switch, independent runtime availability |
| `crates/zakurad/Cargo.toml` | `node/zakura/crates/zakurad/Cargo.toml` | Forward only the existing SLH consensus and mining features |
| `crates/zakura-state/src/service/chain_tip/tests/vectors.rs` | `node/zakura/crates/zakura-state/src/service/chain_tip/tests/vectors.rs` | Extend the existing C1 mock-tip test with SLH/NU7 rollback, reactivation, same-height fork and coalescing cases |

The lifecycle implementation itself is reused from the existing C/E/F slices and
pinned upstream `9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`. The upstream mempool
reset/drop/retry mechanism is retained verbatim. No unrelated upstream issues are
fixed or made release gates by this work.
