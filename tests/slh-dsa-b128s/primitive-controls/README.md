# Valid wrong-profile controls

These two public NIST ACVP external/Pure signatures are valid under
SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-128s. Both have the same 32-byte public-key
and 7,856-byte signature sizes as the experimental BLAKE3 profile, so their
rejection exercises the cryptographic profile rather than a length mismatch.
They do not establish FIPS compliance of the experimental profile.

The source is NIST's [ACVP-Server signature-verification projection](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json),
SHA-256 `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792`.
The selected source identities are group 19/case 266 (SHA2) and group 25/case
343 (SHAKE). The extraction lowercases public hex and retains only public
verification material; it contains no seed or private key. NIST source notice
is preserved in [NIST-NOTICE.txt](NIST-NOTICE.txt). The selection and field
adaptation were made on 2026-10-09.

`extract.py` reuses the existing bounded, hash-checked test-source fetcher.
`check_controls.py` reuses the existing [independent reference](../reference/README.md)
and bounded native adapter without changing either. The checker first checks the 105 official BLAKE3 hash vectors.
Both verifiers must then accept one retained BLAKE3 known answer, so a broken hash or an adapter that always rejects cannot pass.
Next, the checker accepts each signature under its original SHA2 or SHAKE profile.
It then rejects a signature mutation under that profile.
Finally, it rejects the original signature under BLAKE3 and compares the Rust verifier's error.
The independent reference and checker remain test-only LGPL-3.0-or-later;
their license copies remain in [reference/licenses](../reference/licenses).
No alternative algorithm is added to the Rust runtime dependency graph.

From the repository root, after preparing the independent reference and building
the existing `compare` example with the focused verifier package:

```sh
python3 tests/slh-dsa-b128s/primitive-controls/extract.py .context/acvp-sigver.json
python3 tests/slh-dsa-b128s/primitive-controls/check_controls.py \
  --inputs .context/slh-reference \
  --source-cache .context/acvp-sigver.json \
  --binary target/debug/examples/compare \
  --output .context/wrong-profile-receipt.json
cargo test --locked -p zakura-pq-slh-dsa-b-verify --test wrong_profile
```

The focused Rust test consumes the retained public cases and requires
`InvalidSignature`, not a length error. The independent checker supplies the
source-profile positive evidence. Its receipt records source, fixture, binary
and checker hashes. This is bounded primitive conformance, not node, wallet,
signer or operational acceptance.
