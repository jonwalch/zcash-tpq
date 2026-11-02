# SLH dependency boundary checks

Run from the repository root:

```sh
python3 -B -m unittest discover -s tests/slh-dsa-b128s/dependencies -v
python3 tests/slh-dsa-b128s/dependencies/check.py
```

This invokes locked, offline Cargo metadata/tree inspection only. It does not
compile a node, execute a live suite or dispatch CI. Cargo dependencies must
already be available locally.

The guard checks each dependency graph separately:

- Each node root with default features: normal and build dependencies.
- Each node root with all features: normal, build, and development dependencies.
- Explicit SLH consensus, native verifier, and primitive verifier graphs.
- Default, public-profile-only, and full SLH wallet graphs, plus default and
  enabled CLI graphs.
- Default, `--no-default-features`, and
  `--no-default-features --features adapter` devnet consumer graphs.
- The separate benchmark workspace, including its development dependencies.

Every graph uses `--target all`, including dependencies for other operating systems.
This avoids hidden edges and misleading workspace-wide feature combinations.
A regression test resolves small Windows and non-Windows dependencies without compiling them.
The same fixture checks the mandatory public-profile wallet dependency and the
optional full wallet feature. It also resolves the adapter feature with its
optional SHA-256 and TOML dependencies. It rejects an adapter-only KDF dependency
even when the no-feature graph stays clean. Both non-signing devnet profiles
reject signing enabled by `public-profile`, a transitive chain default, or a
wallet default when the dependency loses its `default-features = false`
protection.
Other tests run the guard on prepared metadata and graphs. They check each
graph's required and forbidden packages, local paths, and product packages.

The guard rejects alternate PQ packages, including optional and test-only packages.
Local dependency paths must stay inside the repository.
The signer is allowed in full SLH wallet/CLI graphs, the default devnet launcher,
and the separate benchmark.
The default wallet feature set stays empty. The standalone `wallet-public-profile`
graph selects only `public-profile` with default features disabled. It must contain
`zakura-pq-wallet`, but must exclude the signer, CLI, native SLH verifier, primitive
SLH verifier, transaction context, and `zakura-chain`. It also excludes `hkdf`,
`argon2`, `chacha20poly1305`, and `rand_core`. The public feature exposes canonical
`Hex`, `Profile`, and `Error` types through `serde`, `serde_json`, `hex`,
`thiserror`, and `zeroize`. `zeroize` is an intentional dependency of the shared
canonical encoder; it does not imply signing support. The full wallet feature
`experimental-slh-dsa-b128s` includes `public-profile` and adds signing support.
The default `zakura-tpq-devnet` graph must contain `zakura-chain`, the wallet,
signer, native transaction context, and both SLH verifier packages. The launcher's
default `wallet` feature enables the wallet's `experimental-slh-dsa-b128s` feature
for full wallet support. Its wallet dependency is mandatory, with
`default-features = false` and `features = ["public-profile"]`. With
`--no-default-features`, its graph must contain `zakura-chain` and
`zakura-pq-wallet`, but exclude `zakura-pq-cli`, `zakura-pq-slh-dsa-b-sign`,
`zakura-pq-tx-context`, `zakura-pq-slh-dsa-b-exp`, and
`zakura-pq-slh-dsa-b-verify`. This profile uses the chain's public rules and the
wallet's public canonical profile types, not full wallet support.
The `tpq-devnet-adapter` case selects `zakura-tpq-devnet` with
`--no-default-features --features adapter`. It must contain `zakura-chain` and
`zakura-pq-wallet`, which supplies the canonical public profile types. It must
exclude the SLH signer, both SLH verifiers, native transaction context, wallet CLI,
and benchmark. It also excludes the wallet-only key derivation and password
packages `hkdf`, `argon2`, and `password-hash`. The adapter feature enables
SHA-256 and TOML support, not the full wallet feature.
Do not apply the standalone public-profile exclusions to the whole adapter
graph: the chain already uses `rand_core` and `chacha20poly1305` for inherited
classical and shielded support. Those shared packages do not establish wallet
key generation or wallet encryption support. `zeroize` also remains allowed.
All three devnet graphs inspect normal and build dependencies across all targets.
None may contain the wallet CLI or benchmark package.
The benchmark package is forbidden in every node, wallet and verifier graph.
Its graph must contain the real signer, verifier, wallet and native transaction
context. Wallet payment cases run in this isolated executable. Its graph excludes
the node, consensus service, state database, network service, CLI and fixture tools.
The default CLI also excludes the wallet library.
BLAKE3 stays pinned to 1.8.5 without its Rayon feature.
Upstream node and chain-library use of Rayon is unchanged.

These checks establish dependency isolation. Runtime support now follows the
explicit SLH feature, and CLI source is integrated. Neither the dependency graph
nor the compiled-support flag establishes live acceptance or signer security.
