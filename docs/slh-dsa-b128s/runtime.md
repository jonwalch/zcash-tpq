# Node configuration and verifier identity

The `experimental-slh-dsa-b128s` feature enables consensus verification and RPC mining accounting.
It is off by default. It adds no signer or fixture dependency.
Configured activation also requires `zakura_consensus::supports_experimental_slh_dsa_b128s()`.
This function returns true when the build includes the feature.
Live node acceptance remains open.

## Read the verifier identity

Run this exact command:

```sh
zakurad --slh-dsa-b128s-verifier-identity
```

The command prints one JSON object and exits before node initialization.
It does not load configuration, start services, or execute cryptography.
Both default and feature-enabled builds accept the command.
Additional arguments select the ordinary CLI parser instead.
Identity detection compares operating-system arguments without UTF-8 conversion.
An unrelated non-UTF-8 argument reaches the ordinary parser without an identity-check panic.

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` |
| `contract` | `slh-dsa-b-128s-exp-v1` |
| `suite_id` | `f7` |
| `backend` | `portable-rust` with the verifier compiled, otherwise `disabled` |
| `algorithm_revision` | `b392fe82d2d9770142477a576a758a233888bc0a` |
| `blake3_version` | `1.8.5` |
| `verifier_compiled` | Whether consensus was compiled with the SLH feature |
| `runtime_supported` | Whether integrated experimental runtime support is compiled |

The algorithm and hash fields identify the contract even when the verifier is disabled.
`verifier_compiled` and `backend` identify the compiled mode.
The runtime and verifier flags follow the same feature.
Neither flag proves execution or security acceptance.
A separate receipt must record source, dependency features, binary hashes, and configuration hashes.
The identity object does not establish source provenance.

## Configure Regtest

The following profile uses functional test limits:

```toml
[network]
network = "Regtest"

[network.testnet_parameters]
activation_heights = { "NU6.3" = 1, NU7 = 105 }
experimental_slh_dsa_b128s_activation_height = 110
experimental_slh_dsa_b128s_max_checks_per_transaction = 16
experimental_slh_dsa_b128s_max_checks_per_block = 64
```

All three SLH fields are required together.
Activation must be nonzero and after NU7 and every checkpoint.
Limits must satisfy `0 < transaction <= block <= u32::MAX`.
Public networks, including custom public networks, reject SLH fields.
A build without the feature refuses configured startup.
These limits are not production recommendations.

## State and activation

Database and non-finalized backup paths use `regtest-slh-dsa-b128s-v1-hH-tT-bB`.
A change to activation or either limit selects a new namespace.
The node does not reuse plain Regtest state or state from different rule settings.
An incompatible future contract needs a different namespace.

Mempool admission uses the next candidate block height.
Chain-tip notifications reset the mempool at activation, forks, and rollbacks.
The reset also handles coalesced updates that cross activation.
It discards pending downloads, completed downloads, and stored results.
It then queues transactions for verification under the new tip.
The storage constructor uses the same network configuration after reset.
Active SLH blocks bypass prepared-block cache lookup and insertion.
The [consensus guide](consensus.md) describes these checks.

## Focused tests

Library tests cover configuration rejection, unchanged defaults, namespace isolation,
activation, rollback, reactivation, forks, coalesced updates, and both identity modes.
They use mocked tips and temporary directories.
They do not build a daemon or run live tests.

```sh
cargo test --locked -p zakura-chain -p zakura-network -p zakura-state --lib slh
cargo test --locked -p zakura-consensus --lib slh
cargo test --locked -p zakura-consensus --lib --features slh-test-observer slh
cargo test --locked -p zakura --lib slh_identity_args
cargo test --locked -p zakura --lib --features experimental-slh-dsa-b128s slh_identity_args
cargo clippy --locked -p zakura-chain -p zakura-network -p zakura-state -p zakura-consensus --all-targets -- -D warnings
cargo clippy --locked -p zakura-consensus --all-targets --features slh-test-observer -- -D warnings
```

The library test harness includes the standalone identity argument tests, including non-UTF-8 arguments.
Normal Cargo and nextest discovery includes these tests even though the daemon binary disables its test harness.
The complete daemon entry point, feature forwarding, startup refusal, and reset consumers have source review only at this checkpoint.
A human must build the daemon and run live acceptance under [AGENTS.md](../../AGENTS.md).

## Source attribution

The identity command reuses the early-exit mechanism from research revision
`e759cb86a06510893f8e7d1eb986b7025401c8c9`.
The typed JSON API adds the SLH contract, fixed source versions, and separate support flags.
It uses the existing Serde dependencies and retains MIT/Apache-2.0 attribution.

| Target | Research source at that revision | Adaptation |
| --- | --- | --- |
| `crates/zakurad/src/bin/zakurad/main.rs` and `slh_identity_args.rs` | `node/zakura/crates/zakurad/src/bin/zakurad/main.rs` | Exact-argument early exit with the SLH identity facade; extract the predicate for tests and compare OS arguments to preserve non-UTF-8 handling |
| `crates/zakurad/src/lib.rs` | Existing product argument-test module above | Include the same source under `cfg(test)` so standard library test discovery runs both regressions; runtime code is unchanged |
| `crates/zakura-consensus/src/slh_identity.rs` and `lib.rs` | `node/zakura/crates/zakura-consensus/src/transaction/sqisign.rs` | Typed fixed-profile identity, no alternate backend/CPU switch, independent runtime availability |
| `crates/zakurad/Cargo.toml` | `node/zakura/crates/zakurad/Cargo.toml` | Forward only the existing SLH consensus and mining features |
| `crates/zakura-state/src/service/chain_tip/tests/vectors.rs` | `node/zakura/crates/zakura-state/src/service/chain_tip/tests/vectors.rs` | Extend the existing C1 mock-tip test with SLH/NU7 rollback, reactivation, same-height fork and coalescing cases |

The lifecycle code reuses the existing integration and pinned upstream revision
`9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`.
The upstream mempool reset, discard, and retry mechanism remains unchanged.
