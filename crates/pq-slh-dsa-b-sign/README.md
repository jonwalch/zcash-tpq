# Experimental SLH-DSA-B-128s signer

This crate implements the fixed BLAKE3 profile in the
[protocol](../../docs/slh-dsa-b128s/protocol.md). It is a wallet primitive, not a
transaction approval API. Callers must use the native trusted signing context
and approve transaction effects before signing. It is not a FIPS 205 profile.

`SigningKey::from_seed` owns a `Zeroizing<[u8;48]>` containing
`SK.seed || SK.prf || PK.seed` and computes the full public root.
The key has no `Debug`, `Clone`, or secret serialization.
For each signature, `sign(&[u8;101])`:

1. Requests 16 bytes from fallible `OsRng`.
2. Applies external Pure framing once, with empty context.
3. Verifies the result before returning the boxed 7,856-byte signature.

Failure returns no signature.
Operational callers cannot select randomness, replace verification, or bypass framing.
Prescribed randomness and fault injection are private unit-test code only.

The implementation retains the pinned serial FORS, XMSS, WOTS, and hypertree algorithms without caching.
Fixed widths replace generic RustCrypto types.
Safe streaming replaces unsafe temporary hash buffers and unused parallel paths. The node verifier remains unchanged and does not
depend on this crate. No Rayon, JSON, subprocess, alternate PQ algorithm or
upstream prerelease signing API is a normal dependency.

## Clearing scope

The owned seed, per-signature entropy, PRF secret outputs and evolving secret
WOTS chain states use `Zeroizing`. The previous chain state clears on replacement.
The pending signature uses a fixed-length clearing allocation and moves out only
after verification. BLAKE3 `Hasher` and `OutputReader` are clearing owners under
the pinned 1.8.5 `zeroize` feature, including PRF and secret hashing.

These ownership rules do not prove complete memory erasure.
Moves, compiler spills/registers, return-value temporaries and BLAKE3 compression
internals may retain copies. Published/public-tree nodes and verifier recovery
temporaries are not individually cleared. The caller remains responsible for
its original seed material. The wallet's inherited HKDF/HMAC implementation does
not expose internal-state clearing. There is no mlock, process isolation or
constant-time/fault-resistance certification. Secret-bearing APIs do not derive formatting or serialization.
Errors contain only fixed strings.

## Evidence and attribution

[PROVENANCE.json](PROVENANCE.json) records exact sources, local hashes and
adaptation rationale. [NOTICE.md](NOTICE.md) and both upstream licenses are
retained. Local copies of verifier helpers preserve the reviewed verifier interface and dependency graph.
The provenance file maps them to their exact sources.

The public [wallet vectors](../../tests/slh-dsa-b128s/wallet/README.md) include
six complete independently computed roots and two prescribed-randomness
signatures. Focused tests compare this signer byte-for-byte and cover failed
entropy, failed mandatory verification, fresh operational randomness and Pure
framing. These primitive checks do not establish payment, recovery, or live-node acceptance.

```sh
cargo test --locked -p zakura-pq-slh-dsa-b-sign --profile ci-tests
cargo clippy --locked -p zakura-pq-slh-dsa-b-sign --all-targets -- -D warnings
```
