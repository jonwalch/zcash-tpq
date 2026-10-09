# Source and fixture attribution

The signer dependency is the unchanged
[PQC Suite B SLH-DSA implementation](https://github.com/PQC-Suite-B/signatures/tree/b392fe82d2d9770142477a576a758a233888bc0a/slh-dsa),
derived from RustCrypto and licensed MIT OR Apache-2.0. Its two license texts are
retained here unchanged. Algorithm source hashes are recorded in
[PROVENANCE.json](PROVENANCE.json); Cargo's git revision and isolated lock retain
the exact dependency identity.

The wrapper reuses the bounded decoding and upstream keygen/sign/local-verify
sequence of the earlier SLH fixture tooling. Necessary adaptations remove
alternate profiles, internal framing, context selection, timing, repeats and
dynamic loading; enforce the new fixed public-fixture contract; and verify
every exported signature with the extracted runtime verifier as well.

The public keygen fixture was generated before candidate comparison by
[colinxu2020/slhdsa](https://github.com/colinxu2020/slhdsa/tree/588ea1028003bf5608a92bae1d8d76abaa7274a2)
with portable C BLAKE3. Its expected key bytes were not regenerated. The
reference implementation is LGPL-3.0-or-later; its source is not included in or
linked by this workspace. The retained seed and signing-key bytes are explicitly
public test material, not wallet keys.
