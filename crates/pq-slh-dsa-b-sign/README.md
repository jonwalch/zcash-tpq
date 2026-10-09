# Experimental SLH-DSA-B-128s signer

This crate implements the fixed BLAKE3 profile in the
[protocol](../../docs/slh-dsa-b128s/protocol.md). It is a wallet primitive, not a
transaction approval API. Callers must use the native trusted signing context
and approve transaction effects before signing. It is not a FIPS 205 profile.

`SigningKey::from_seed` takes ownership of a `Zeroizing<[u8;48]>` containing
`SK.seed || SK.prf || PK.seed` and computes the full public root. The key has no
`Debug`, `Clone` or secret serialization. `sign(&[u8;101])` makes one fallible
16-byte `OsRng` request per signature, applies external Pure with empty context
exactly once and calls the real verifier crate before releasing the
boxed 7,856-byte signature. A failure returns no signature. Operational callers
cannot select randomness, replace verification or access internal framing.
Prescribed randomness and fault injection are private unit-test code only.

The initial implementation retains the pinned upstream serial, recursive
FORS/XMSS and WOTS/hypertree algorithms without caching. Fixed widths replace
generic RustCrypto types; safe streaming replaces unsafe temporary hash buffers
and unused parallel paths. The node verifier remains unchanged and does not
depend on this crate. No Rayon, JSON, subprocess, alternate PQ algorithm or
upstream prerelease signing API is a normal dependency.

## Clearing scope

The owned seed, per-signature entropy, PRF secret outputs and evolving secret
WOTS chain states use `Zeroizing`. The previous chain state clears on replacement.
The pending signature uses a fixed-length clearing allocation and moves out only
after verification. BLAKE3 `Hasher` and `OutputReader` are clearing owners under
the pinned 1.8.5 `zeroize` feature, including PRF and secret hashing.

This is a source-level ownership guarantee, not complete memory-erasure proof.
Moves, compiler spills/registers, return-value temporaries and BLAKE3 compression
internals may retain copies. Published/public-tree nodes and verifier recovery
temporaries are not individually cleared. The caller remains responsible for
its original seed material. The wallet's inherited HKDF/HMAC implementation does
not expose internal-state clearing. There is no mlock, process isolation or
constant-time/fault-resistance certification. No secret-bearing API derives
formatting or serialization; errors contain only fixed strings.

## Evidence and attribution

[PROVENANCE.json](PROVENANCE.json) records exact sources, local hashes and
adaptation rationale. [NOTICE.md](NOTICE.md) and both upstream licenses are
retained. Shared verifier helpers are copied locally in this initial checkpoint
to preserve the verifier's reviewed interface and dependency graph; they are
mapped to their exact source rather than reimplemented with new cryptography.

The public [wallet vectors](../../tests/slh-dsa-b128s/wallet/README.md) include
six complete independently computed roots and two prescribed-randomness
signatures. Focused tests compare this signer byte-for-byte and cover failed
entropy, failed mandatory verification, fresh operational randomness and Pure
framing. These checks do not imply wallet payment/recovery or live-node support.

```sh
cargo test --locked -p zakura-pq-slh-dsa-b-sign --profile ci-tests
cargo clippy --locked -p zakura-pq-slh-dsa-b-sign --all-targets -- -D warnings
```
