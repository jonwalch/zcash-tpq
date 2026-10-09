# Experimental SLH wallet

This crate implements SLH inventory, enrollment, payments, durable history and
recovery for the [wallet contract](../../docs/slh-dsa-b128s/wallet.md).
The default package has no normal dependencies and explicitly reports disabled
support. Feature `experimental-slh-dsa-b128s` enables only suite `f7`.

`Wallet::create` draws a 32-byte root and separate 16-byte wallet and allocator
identifiers through fallible OS entropy. Its empty inventory issues no receiver.
Public keys and commitments retain the existing wallet HKDF-SHA256 literal
domains, Regtest/account-zero layout and receive/change coordinates, with 48
output bytes for SLH. `Root` remains available for the earlier non-enrolled key
foundation. Secret owners have no Debug, Clone, serialization or public fixed-
seed import/export API. The initial implementation is serial and uncached; the
inherited HKDF/HMAC internal-state clearing limitation remains.

`Manifest` retains version 1 canonical JSON, independent 4,096-entry/8 MiB
ceilings, cumulative history, participant-origin authentication structure and
approved profile. All 120 policies through 15-of-15 use the existing native
codec; other suite bytes and formats reject. The private `SuitePolicy`, `SignerPartial` and `InputSigner` retain the
existing policy, partial verification and assembly boundary for payment code. `InputSigner` reconstructs the message from transaction effects and
ordered spent outputs; it accepts no supplied digest. These boundaries do not authenticate the provenance of caller-supplied UTXOs.

`Wallet::sign_partial` and internal `sign_input` require an enrolled local coordinate,
the exact matching policy and approved check limits. Callers must separately
approve effects, activation, fees and durable reservations before signing. Each
signature obtains fresh OS entropy inside the operational signer, verifies
locally and is checked against the native input context before release. There
is no injectable or deterministic operational signing randomness API.

Enrollment saves a covering encrypted backup before installing new receive or
change coordinates. Payment review reconstructs effects from trusted ordered
UTXOs, checks fees, expiry and participant grouping, and requires separate change
approval. Signing first persists its reservation; retries preserve the exact
saved authorization bytes. The existing canonical encodings, encrypted backup
container, journal objects and watch-state formats are reused.

[Recovery](../../docs/slh-dsa-b128s/recovery.md) supports encrypted root/inventory
restore and coherent operational snapshots. Snapshots retain exact state and
journal objects under the allocator lock, validate reachable history and aliases,
then publish into a new directory. Unknown authority remains monitor-only;
known-authority restore requires an independently trusted receipt and caller
reconciliation of the latest authority and previous allocators. A self-consistent
snapshot cannot establish its own completeness.

[CLI command flows](../../docs/slh-dsa-b128s/cli.md) now use the reused trusted
loopback RPC adapter and the existing wallet APIs. Live-node and real-terminal
acceptance remain pending; source and mocked checks do not establish full wallet
readiness.

`PROVENANCE.json`, `PAYMENTS_PROVENANCE.json`, `RECOVERY_PROVENANCE.json` and
`CLI_RPC_PROVENANCE.json`
record source mappings and adaptations. Independent seed/root, format, receiver
and encrypted-backup answers accompany focused payment and persistence tests.
Synthetic trusted-source tests do not establish real node provenance or funded
payment acceptance.

```sh
cargo test --locked -p zakura-pq-wallet --lib
cargo test --locked -p zakura-pq-wallet --features experimental-slh-dsa-b128s --lib
cargo clippy --locked -p zakura-pq-wallet --all-targets --features experimental-slh-dsa-b128s -- -D warnings
```
