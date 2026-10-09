# Public SLH transaction corpus

These 18 deterministic NU7 v5/v6 artifacts cover 1of1, 2of3, 3of5, 8of10,
10of10, 15of15, index14 selection in 1of15, and heterogeneous 16/17-check
transactions. Their 146 signatures use prescribed public test keys and bind
complete transactions with ordered synthetic previous outputs. The 17-check
cases are natively valid and exceed only the explicit 16-check test profile.

Generation follows the maintained
[recipe and artifact specification](../../../../docs/slh-dsa-b128s/transaction-fixtures.md).
The [independent checker](../../transactions/README.md) reconstructs wire
encoding, ZIP244/229 digests, descriptors, commitments, messages and real
signature verdicts before comparing the Rust fixture host. Its
[G2 receipt](../../transactions/receipts/g2-initial.json) records initial
acceptance and exact raw file hashes, alongside separate production/build
receipts. No secrets, seeds or randomizers occur in these files.

This corpus does not authenticate live UTXOs or establish shielded, consensus,
relay/mining, wallet/recovery or performance acceptance. Never derive real
wallet material from these public test recipes.
