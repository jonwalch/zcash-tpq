# Source and license attribution

`wire.py` adapts the MIT OR Apache-2.0 independently authored transparent-only
wire checker from `jonwalch/zcash-transparent-pq`, source commit
`0dce78ab42cc4afbd26b5c3474748f7a4a1db3ba`, file
`experiments/hash-four-payments/wire.py`, SHA-256
`f7e356e2dfd1c12930a2d35ac0e52993dce2255178ad5dc42a636de2b8ca8c49`.
The prior checker itself credited the independent Falcon/SQIsign wire checkers.
Only this small neutral file is reused. No alternate signature implementation,
research catalog or dependency on the source checkout is imported.

The ZIP 244/229 BLAKE2b digest input ordering and personalizations are unchanged.
Adaptations enforce this public interface's input/output/script and amount-sum
bounds, reject duplicate/coinbase outpoints, and remove unused fee calculations.
The source is available at
[its pinned revision](https://github.com/jonwalch/zcash-transparent-pq/blob/0dce78ab42cc4afbd26b5c3474748f7a4a1db3ba/experiments/hash-four-payments/wire.py).
The repository's [MIT](../../../LICENSE-MIT) and
[Apache](../../../LICENSE-APACHE) licenses apply.

`oracle.py`, `mutations.py`, `check.py` and their focused tests are new,
MIT OR Apache-2.0 test glue implementing the frozen public fixture specification.
A separate schema/codec oracle is necessary to keep expectations independent of
the Rust library under comparison. Its tests exercise strict JSON, required
nullable fields, all 120 policy shapes, complete wire consumption, digest field
sensitivity/exclusion, coherent negative controls and structural-before-crypto
precedence. It does not copy production Rust codec or digest implementations.

Cryptographic verification reuses the existing checked
[Python/portable-C reference](../reference/NOTICE.md) without modifying its
algorithms, loader, source pins or licenses. That reference remains separate
LGPL test tooling and is not linked into the node or wallet.
