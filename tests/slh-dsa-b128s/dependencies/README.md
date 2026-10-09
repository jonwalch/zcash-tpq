# SLH dependency boundary checks

Run from the repository root:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/dependencies -v
python3 tests/slh-dsa-b128s/dependencies/check.py
```

This invokes locked, offline Cargo metadata/tree inspection only. It does not
compile a node, execute a live suite or dispatch CI. Cargo dependencies must
already be available locally.

The check rejects alternate PQ packages even when optional or test-only, and
rejects local dependencies outside this repository. It inspects each node root
separately: default features use normal/build edges, and all features use
normal/build/dev edges. This avoids workspace-wide feature unification hiding a
signer dependency. Every graph uses
`--target all`, including dependencies behind target conditions that do not
match the machine running the check. A regression resolves tiny local crates
with Windows and non-Windows dependencies without compiling either target.
It also checks normal/build graphs for the explicit consensus SLH feature,
native/primitive verifiers and default/enabled wallet features. The signer is
allowed only in the enabled wallet graph. BLAKE3
remains pinned to 1.8.5 without its Rayon feature. Upstream node Rayon use is
unaffected.

This establishes dependency isolation, not source provenance, absence of secret
handling bugs or runtime acceptance. The implemented wallet and relay/mining
libraries do not establish complete CLI flows or live acceptance; the node's
runtime support signal remains false.
