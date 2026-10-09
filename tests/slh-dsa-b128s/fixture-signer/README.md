# Public fixture signer

This isolated test workspace creates deterministic, explicitly public
SLH-DSA-B-128s fixtures. It is never a wallet signing service and is not a node or
wallet dependency. All key and seed material supplied to it must already be
public test material. It does not implement live disposable-key handling.

The [version 1 interface](../../../docs/slh-dsa-b128s/fixtures.md) requires one
strict JSON object on stdin. Both requests and responses are limited to 32,768
bytes. A request always includes `version: 1`,
`contract: "slh-dsa-b-128s-exp-v1"`, `public_fixture: true`, and `op`.

* `keygen` requires a hex `seed` of exactly 48 bytes. It returns `public_key`
  (32 bytes) and `secret_key` (64 bytes), labeled `material: "public-test-only"`.
* `sign` requires hex `secret_key` (64 bytes), `message` (101 bytes) and
  `randomizer` (16 bytes). It returns `public_key`, `signature` (7,856 bytes),
  and `locally_verified: true` after both upstream and the extracted verifier
  accept. No secret key is included in a signing response. Context is empty.

Unknown or duplicate fields, malformed hex, missing randomness, incorrect
lengths, other contracts and a false public-fixture declaration are rejected
before cryptography. Errors are fixed strings and never contain input bytes.
There is no internal-framing, profile, context, repetition or measurement switch.
Callers must apply a process timeout and check the bounded response. Before
exporting a public transaction artifact, omit all seed, secret-key and randomness
fields; those artifacts use the separate public schema.

The signer dependency is unmodified `PQC-Suite-B/signatures` revision
`b392fe82d2d9770142477a576a758a233888bc0a`; the manifest and lock pin BLAKE3
`=1.8.5`. The signing source has short-message unsafe buffer copies. Their use
here is constrained by checked fixed arrays: the Pure wrapper contributes two
bytes, so PRF input is `16 + 16 + 2 + 101 = 135` bytes and H_msg input is
`16 + 16 + 16 + 2 + 101 = 151` bytes, both below its 384-byte buffer. Keygen and
tree hashes have fixed inputs; F/PRF are 64 bytes, H is 80, and T copies only the
48-byte seed/address prefix into its 64-byte buffer before streaming nodes.
This bounded test use does not establish an unrestricted upstream API's safety.

Upstream directly requests BLAKE3's Rayon feature, so this isolated dependency
graph retains Rayon to avoid patching upstream source or its manifest. Under the
fixed message bounds its parallel message path is never selected. No Rayon
feature is requested by the runtime verifier; feature unification here belongs
only to this isolated fixture workspace. The only version adaptation from the
retained signer lock is BLAKE3 1.8.2 to 1.8.5 and its required dependency changes.
No original fixture or lock was edited.

Run focused checks with this manifest; do not add this package to the node
workspace:

```sh
cargo fmt --manifest-path tests/slh-dsa-b128s/fixture-signer/Cargo.toml -- --check
cargo test --manifest-path tests/slh-dsa-b128s/fixture-signer/Cargo.toml --locked
cargo clippy --manifest-path tests/slh-dsa-b128s/fixture-signer/Cargo.toml --all-targets --locked -- -D warnings
cargo build --manifest-path tests/slh-dsa-b128s/fixture-signer/Cargo.toml --locked
```

The keygen regression preserves one independent expected public tuple, including
its intentionally public signing material. The new 101-byte message is signed
and checked locally; independent verification of generated transaction fixtures
is a separate corpus gate. Source hashes, reuse mappings, source/lock adaptations
and licenses are in [PROVENANCE.json](PROVENANCE.json),
[NOTICE.md](NOTICE.md), [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
