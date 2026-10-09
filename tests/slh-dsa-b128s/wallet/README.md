# Independent wallet key answers

Every root, derived seed and randomizer in `vectors.json` is deliberately public
test material. Never use these values for a wallet. The corpus is separate from
the historical primitive and transaction fixtures; those artifacts are unchanged.

`reference.py` computes the HKDF extraction and both full expansion blocks with
Python stdlib HMAC-SHA256. It loads the existing hash-checked independent
[SLH reference](../reference/README.md), using its pinned Python algorithms and
portable C BLAKE3. Production Rust crypto and wallet modules are never imported.
The six answers cover receive/change indices 0, 1 and 4,294,967,295, with full
32-byte public keys. Three other suite bytes are HKDF separation controls only;
they add no alternate signing algorithm. Two answers include complete
prescribed-randomness signatures over exact 101-byte messages with Pure empty
context framing once. The max-index case is a primitive message binding test,
not a transaction with billions of inputs.

Each run checks the 105 official BLAKE3 controls, recomputes all six keys and both
signatures and rejects eight signature mutations and two double-framing cases.
`test_reference.py` separately checks RFC 5869's first test case, literal layout
and bounds, seed ordering, entropy request count and Pure framing using mocks.

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/wallet -p 'test_*.py'
python3 tests/slh-dsa-b128s/wallet/reference.py --inputs /path/to/checked-reference-cache
```

Initial creation used `--write`, which refuses to replace an existing vector
file. Normal checks compare complete recomputed answers. Candidate Rust unit
tests independently compare these retained answers; recording a candidate
output cannot update expectations. No benchmarking, real wallet secrets,
shielded-proof generation or live acceptance driver is involved.
