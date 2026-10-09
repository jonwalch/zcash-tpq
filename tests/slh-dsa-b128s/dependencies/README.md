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
separately in default and all-feature normal/build/dev graphs so workspace-wide
feature unification cannot hide a signer dependency. It also checks the explicit
consensus SLH feature, native/primitive verifier graphs and default/enabled
wallet graphs. The signer is allowed only in the enabled wallet graph. BLAKE3
remains pinned to 1.8.5 without its Rayon feature. Upstream node Rayon use is
unaffected.

This establishes dependency isolation, not source provenance, absence of secret
handling bugs or runtime acceptance. The wallet key foundation and the node's
false runtime support signal do not imply completed payments or relay/mining.
