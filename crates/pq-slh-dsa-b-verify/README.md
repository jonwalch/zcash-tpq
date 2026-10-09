# Experimental SLH-DSA-B-128s verifier

This crate verifies the fixed `Blake3_128s` construction from PQC Suite B
revision `b392fe82d2d9770142477a576a758a233888bc0a`. This BLAKE3 construction is
not a FIPS 205 profile. It exposes only external Pure verification, with a
32-byte public key, 7,856-byte signature, message at most 65,536 bytes and context
at most 255 bytes. All bounds are checked before hashing. The Pure prefix is
added once inside `verify`; an internal-message interface is not exposed.

The verification loops preserve the upstream FORS, WOTS+, XMSS and hypertree
algorithms. The necessary adaptations specialize the parameters, borrow encoded
signature sections, serialize addresses explicitly, and replace unsafe copying
and parallel hash glue with safe streaming concatenation. No signature-sized
allocation or copy is performed by verification. Intermediate nodes and WOTS/FORS
root arrays have fixed sizes. This is a source-level description, not a measured
stack, timing or throughput claim.

The only direct runtime dependency is BLAKE3 `=1.8.5`, with default features off
and `std` enabled. No Rayon feature is requested. The hash dependency retains its
normal architecture dispatch: supported x86 implementations are selected by the
dependency's CPU detection; AArch64 uses its available NEON implementation; other
targets use the dependency's supported fallback. This crate neither forces a
particular instruction set nor introduces nested parallelism. Feature unification
in a consuming workspace must still be reviewed separately.

The public API is `verify(public_key, signature, message, context)`. The node
contract supplies its 101-byte signing message and empty context. Signing, key
generation, secret storage, RNGs, chain dependencies, dynamic loading and JSON
are absent from the runtime graph.

Run the focused checks from the workspace root:

```sh
cargo fmt -p zakura-pq-slh-dsa-b-verify -- --check
cargo test -p zakura-pq-slh-dsa-b-verify --locked
cargo clippy -p zakura-pq-slh-dsa-b-verify --all-targets --locked -- -D warnings
cargo tree -p zakura-pq-slh-dsa-b-verify --locked -e normal,build,features
```

The retained public KAT projection preserves three independently generated
verification tuples exactly. Tests also mutate every 16-byte signature node,
both public-key halves, message/context/framing, and encoding lengths/bounds.
They do not regenerate expected crypto outputs. A fresh independently executed
comparison against the pinned upstream and portable-C/Python reference remains
a separate integration gate.

The dev-only `compare` example accepts one JSON object on stdin containing four
hex string fields: `public_key`, `signature`, `message`, `context`. It rejects
unknown fields and malformed hex, limits the request to 160,000 bytes, and limits
each decoded field to one byte over the API maximum so boundary errors can be
compared. Output is `{"valid":true,"error":null}` or a false verdict with the
`VerifyError` variant name. Adapter/schema errors have an `Adapter: ` prefix.
Callers should impose a process timeout. There is no profile switch, signer or
framing bypass. JSON dependencies are dev-only.

See [NOTICE.md](NOTICE.md), [PROVENANCE.json](PROVENANCE.json),
[MIT license](LICENSE-MIT) and [Apache license](LICENSE-APACHE) for provenance.
