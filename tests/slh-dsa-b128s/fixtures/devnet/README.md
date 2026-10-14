# Public Testnet-domain SLH fixtures

These two fixtures contain new SLH signatures for the Testnet network domain.
They cover transparent v5 and v6 1-of-1 payments under
`slh-dsa-b-128s-exp-v1`. Previous outputs are synthetic test data, not authenticated
UTXOs. Every key is prescribed public test material and is unsuitable for funds.

The [bounded producer](../generate_devnet_transactions.py) keeps the transaction
effects from the corresponding [Regtest fixtures](../data/README.md). It derives
public `seed(0)` once and signs exactly two actual Testnet messages. It uses the
existing [fixture host](../host/README.md) and isolated
[fixture signer](../../fixture-signer/README.md). The original 18-case corpus,
its signatures, and its receipts remain unchanged.

Production used product commit `016a1a7d1c8b9af0d6c53a2d51b820b417d2717a`,
with clean producer source, pinned Zakura
`24a17b3f0e7d88513688d607054f018ab6f15af2`, and signature source
`b392fe82d2d9770142477a576a758a233888bc0a`. Each artifact records the exact host,
signer, lockfile, and source inventory hashes. Build and run receipts remain in
the coordinator's ignored `.context` directory. Hashes identify recorded inputs;
they do not prove a compiler's execution history.

New production uses the current Zakura pin
`e33dc43089acca2fe2c6516927932f2b7618b8bc`. Before it calls the host or signer,
the producer requires that pin to match the
[source ledger](../../../../docs/slh-dsa-b128s/imports.json). Its source inventory
also records the ledger, so a change during production fails the final identity
check. The host and independent schema checker accept this pin and the two
recorded historical pins; unknown pins fail. Mocked tests check the reported pin
and refusal before signing. These changes do not regenerate the fixtures below
or extend their historical receipts to the current source.

| File | SHA-256 |
| --- | --- |
| `v5-testnet-1of1.json` | `fcd06b78da9654cb36acc1a7012d4d10f9029a7fe2717c8e85c5f2dd9f4cdfc6` |
| `v6-testnet-1of1.json` | `86450b127452ee996434ece74bcf438eb63452ba07be553eb43dba057b2c8348` |

On 2026-10-14, the [independent control checker](../check_devnet_transactions.py)
accepted both fixtures and rejected their four derived controls: a Regtest
message domain and a changed signature byte for each version. It reconstructed
the transaction digests and messages with the existing Python oracle, then ran
six signature checks with the separately pinned Python/portable-C reference.
The check also passed 105 official BLAKE3 controls. It made no producer-source,
authenticated-UTXO, node-acceptance, or shielded-coverage claim.

The checker requires each original fixture to expect acceptance with one signature
check. It then requires the independent verifier to match that result. This prevents
rejected originals from counting as positive controls. Regression tests reject
corrupted originals whose expectations were changed to rejection, and check that
a positive expectation still fails when the verifier rejects its signature.

To repeat that bounded check, first prepare the
[independent reference](../../reference/README.md), then select a fresh receipt:

```sh
python3 tests/slh-dsa-b128s/fixtures/check_devnet_transactions.py \
  --fixtures tests/slh-dsa-b128s/fixtures/devnet \
  --reference-inputs .context/slh-reference \
  --output .context/new-devnet-independent.json
```

The [custom network consensus tests](../../../../crates/zakura-consensus/src/transaction/tests/slh_dsa_b128s/devnet.rs)
reuse the retained trusted-service controls with these signatures. They cover
block and mempool dispatch, wrong-domain and corrupt signatures, activation,
compiled-verifier refusal, budgets, bound metadata, and classical funding.
This adaptation is needed because a valid Regtest signature cannot serve as a
positive Testnet fixture. The existing wire contract and trusted-output boundary
are unchanged. Live multi-node acceptance is a separate check.
