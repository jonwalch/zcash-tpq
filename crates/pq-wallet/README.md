# Experimental SLH wallet

This crate implements inventory, enrollment, payments, durable history, and recovery.
The [wallet contract](../../docs/slh-dsa-b128s/wallet.md) specifies its behavior.
Default builds have no normal dependencies and report disabled support.
`experimental-slh-dsa-b128s` enables only suite `f7` on Regtest.

## Keys, approval, and limits

`Wallet::create` requests a 32-byte root and separate 16-byte wallet and allocator IDs from fallible OS entropy.
The initial inventory has no addresses.
SLH key derivation uses the retained HKDF domains, account zero, receive/change coordinates, and 48 output bytes.
`Root` also remains available for keys without enrollment.
Secrets have no `Debug`, `Clone`, serialization, or public fixed-seed import/export API.
The implementation is serial and has no cache.
HKDF/HMAC internal-state clearing remains limited.

`Manifest` retains canonical version 1 JSON, cumulative history, authenticated origin structure, and the approved profile.
The 4,096-entry and 8 MiB limits apply independently.
All 120 policies through 15-of-15 use the native codec.
Other suites and incompatible formats are rejected.

`InputSigner` reconstructs messages from transaction effects and ordered spent outputs.
It cannot accept a supplied digest.
The caller must authenticate those UTXOs and approve effects, activation, fees, and reservations.
Signing requires an enrolled local coordinate, matching policy, and approved check limits.
Every signature uses fresh OS entropy and passes local and native-context verification before release.
There is no operational API for deterministic or injected randomness.

## Storage and recovery

Enrollment saves a covering encrypted backup before it installs new address coordinates.
Payment review checks trusted UTXOs, fees, expiry, participants, and separate change approval.
Signing saves reservations first. Retries preserve exact authorization bytes.
The implementation reuses existing backup, journal, and watch-state formats.

[Recovery](../../docs/slh-dsa-b128s/recovery.md) supports key/inventory restore and operational snapshots.
Snapshots retain state and journal objects under the allocator lock.
Restore checks history and publishes a new directory.
Unknown authority stays monitor-only.
Known authority requires an independently trusted receipt and reconciliation of signatures and old allocators.
A consistent snapshot cannot prove its own completeness.

The [CLI](../../docs/slh-dsa-b128s/cli.md) uses the wallet APIs and trusted loopback RPC adapter.
Live node and terminal acceptance remain open.

## Tests and attribution

The `PROVENANCE.json`, `PAYMENTS_PROVENANCE.json`, `RECOVERY_PROVENANCE.json`,
and `CLI_RPC_PROVENANCE.json` files record source mappings.
Independent key, format, receiver, and backup answers support focused tests.
Synthetic trusted-source tests do not establish real UTXO provenance or funded acceptance.

```sh
cargo test --locked -p zakura-pq-wallet --lib
cargo test --locked -p zakura-pq-wallet --features experimental-slh-dsa-b128s --lib
cargo clippy --locked -p zakura-pq-wallet --all-targets --features experimental-slh-dsa-b128s -- -D warnings
```
