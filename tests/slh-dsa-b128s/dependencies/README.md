# SLH dependency boundary checks

Run from the repository root:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/dependencies -v
python3 tests/slh-dsa-b128s/dependencies/check.py
```

This invokes locked, offline Cargo metadata/tree inspection only. It does not
compile a node, execute a live suite or dispatch CI. Cargo dependencies must
already be available locally.

The guard checks each dependency graph separately:

- Each node root with default features: normal and build dependencies.
- Each node root with all features: normal, build, and development dependencies.
- Explicit SLH consensus, native verifier, and primitive verifier graphs.
- Default and enabled wallet and CLI graphs.
- The separate benchmark workspace, including its development dependencies.

Every graph uses `--target all`, including dependencies for other operating systems.
This avoids hidden edges and misleading workspace-wide feature combinations.
A regression test resolves small Windows and non-Windows dependencies without compiling them.
Other tests run the guard on prepared metadata and graphs. They check each
graph's required and forbidden packages, local paths, and product packages.

The guard rejects alternate PQ packages, including optional and test-only packages.
Local dependency paths must stay inside the repository.
The signer is allowed in enabled wallet/CLI graphs and the separate benchmark.
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
