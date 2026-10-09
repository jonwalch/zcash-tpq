# Experimental wallet key foundation

This is the H1 key checkpoint for the [wallet contract](../../docs/slh-dsa-b128s/wallet.md).
The default package has no normal dependencies and explicitly reports disabled
support. Feature `experimental-slh-dsa-b128s` enables only the SLH key foundation.

`Root::generate` obtains 32 bytes using fallible OS entropy. `derive_key(KeyPath)`
retains the existing wallet's HKDF-SHA256 literal domains, Regtest/account-zero
layout and receive/change coordinate types, with suite `f7` and 48 output bytes.
It passes the owned clearing seed to the separate in-process signer. Roots have
no Debug, Clone, serialization, public fixed-seed import or export API. The
initial implementation is serial and uncached. The HKDF/HMAC internal-state
clearing limitation is inherited and explicitly retained.

This primitive root is not an enrolled wallet, a durable backup or permission to
spend. It has no wallet/allocator ID and issues no receivers. Later H2 imports
the existing suite, policy, partial and trusted signing-context plumbing; I/J/K
add the preserved payment, storage, recovery/watch and CLI flows. These are
required follow-on work, not completed functionality of this crate.

`PROVENANCE.json` maps the retained source to the existing wallet. The fixed
derivation is checked against independent Python stdlib HKDF and pinned
Python/C SLH roots in the public wallet corpus.

```sh
cargo test --locked -p zakura-pq-wallet
cargo test --locked -p zakura-pq-wallet --features experimental-slh-dsa-b128s --profile ci-tests
cargo clippy --locked -p zakura-pq-wallet --all-targets --features experimental-slh-dsa-b128s -- -D warnings
```
