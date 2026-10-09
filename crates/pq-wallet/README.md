# Experimental SLH wallet foundation

This crate implements the suite, public inventory and trusted-context signing
foundation for the [wallet contract](../../docs/slh-dsa-b128s/wallet.md).
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

This checkpoint does not yet expose enrollment or encrypted backup, payment
approval/persistence, watch/recovery or CLI flows. An empty newly created wallet
therefore cannot sign until the subsequent durable enrollment implementation.
It does not establish full wallet readiness or live-node acceptance.

`PROVENANCE.json` records exact source mappings and adaptations. Existing
independent seed/root vectors and retained independently produced v5/v6 partials
exercise the foundation; tests use private synthetic enrollment fixtures without
claiming durable storage or UTXO authentication.

```sh
cargo test --locked -p zakura-pq-wallet --lib
cargo test --locked -p zakura-pq-wallet --features experimental-slh-dsa-b128s --lib
cargo clippy --locked -p zakura-pq-wallet --all-targets --features experimental-slh-dsa-b128s -- -D warnings
```
