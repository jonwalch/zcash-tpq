# Independent SLH wallet format answers

These are public, format-only conformance fixtures for the frozen
[wallet contract](../../../../docs/slh-dsa-b128s/wallet.md). Passwords,
roots, salts and nonces are deliberately public test values. Never use them for
funds. Synthetic policy keys and the maximum partial's signature are byte
patterns, not valid generated keys or signatures. The four-entry inventory
instead uses the unchanged, independently generated [H1 keys](../README.md).

The Python oracle reuses the separately written Transparent PQ reference's
canonical JSON, Bech32m, inventory transitions and encrypted backup algorithm.
[sources.json](sources.json) pins the imported source and contract inputs;
[NOTICE](NOTICE) preserves attribution. The adaptations are the SLH domains and
suite `f7`, all 120 policies, the W0 size ledger, strict parser prechecks and
standalone format fixtures. No production Rust serializer, signer, encryption
implementation, subprocess or node computes expected bytes. SHA-256 and JSON
use Python's standard library. Argon2id and ChaCha20Poly1305 use a separate
pinned Python library, with no changed encryption parameters or container.

```sh
python3 -m pip install -r tests/slh-dsa-b128s/wallet/formats/requirements.txt
python3 tests/slh-dsa-b128s/wallet/formats/reference.py
python3 -m unittest discover -s tests/slh-dsa-b128s/wallet/formats -p 'test_*.py' -v
```

The normal reference command recomputes and compares the complete retained
file byte for byte. `--write` creates only a new file and refuses to overwrite
one. The independent H1 key corpus is checked by SHA-256; this suite does not
repeat expensive signing or silently regenerate its answers. It does compute
the unchanged 64 MiB, three-pass, four-lane Argon2id backup key and complete
ChaCha20Poly1305 ciphertext/tag. The tests are bounded Python/reference checks,
with no live payment, recovery, terminal backup or performance driver.

The 20 test methods cover:

- All 120 descriptors, receiver/checksum/script answers and approved origin
  mappings; all 120 shapes in v5/v6 byte accounting; alternate suite, ordering,
  duplication, unknown fields, type, role, index and participant mutations.
- Canonical ASCII JSON, depth 16, sorted fields, no escapes or normalization;
  pre-decode byte/depth rejection and exact retained-file identity.
- Maximum 16,001-byte partials at indices 14/14, the independent 16,384-byte
  reader cap, and version 1 proposal/profile/inventory fingerprints. The two
  unsigned v5/v6 proposal transactions have independently encoded bytes.
- CompactSize and minimal-push boundaries, 118,882-byte authorization and
  118,927-byte full input, the five W0 transaction cases in both versions, check
  limits independently from transaction size, and a byte-limit rejection even
  when the check limit permits the transaction.
- Independent 4,096-entry and 8 MiB inventory ceilings: a full 1-of-1 inventory
  fits, a full 15-participant inventory exceeds bytes, and 4,097 entries fail
  before entry processing. A maximal entry is 2,206 bytes; 4,096 such entries
  alone occupy 9,039,873 bytes. Historical policies remain schema-readable when
  a smaller approved check limit forbids new issuance.
- Existing inventory revision, coverage, retirement and allocator rotation
  rules; rewritten history, shrinkage, changed profiles and rollback reject.
- The existing 56-byte v1 encrypted backup header, complete known-answer
  ciphertext, exact minimum/maximum length checks before KDF, authentication
  mutations, password bounds and authenticated-but-invalid recovery schemas.
  Recovery retains `format`, `manifest`, `root_hex`; it contains no journal.

The validators establish public syntax and reference expectations. Entry
syntax alone cannot authenticate origin claims; `check_origin_mapping` consumes
an independently approved mapping. `check_proposal_envelope` intentionally does
not verify transaction effects, UTXO provenance, grouping, fee approvals or
signatures. Those comparisons require the payment implementation. The retained
journal/watch caps are ledger expectations only, not implemented journal
readers or a promise that maximal nested objects fit.

Product comparisons against H2/I/J/K remain pending. In particular, root restore
must regenerate every local public key, and operational recovery must compare
actual durable objects and preserve exact authority bytes. No new operational
snapshot schema is defined here. The following acceptance cases remain required
for the existing file/journal design:

| Existing recovery case | Required outcome |
| --- | --- |
| Root/inventory backup alone | Regenerate local keys, retire old issuance ranges and rotate allocator; no complete-history claim; fresh covering backup before issuance |
| Coherent watch/journal copy from a trusted protected snapshot | Bind backup hash, wallet/suite/profile/inventory and generation; preserve saved bytes and reservations; stage then atomically publish in a new private directory |
| Missing/truncated/mismatched reachable object or unsafe path | Reject; leave existing state unchanged |
| Legitimate retained orphan/temp object | Preserve under the existing quota rules; no wholesale journal read into a recovery buffer |
| Self-consistent replacement or unknown newer authority | Keep authority restricted; empty mempool does not establish completeness |
| Cached observations or unavailable/pruned history | Reconcile with trusted node; never turn uncertainty into a zero/current balance |

These cases need product tests and separately evidenced human live/terminal
acceptance. This corpus proves neither durable recovery nor funded spending.
