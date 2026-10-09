# SLH consensus source attribution

The SLH accounting and worker integration adapts the selected modules below
from `jonwalch/zcash-transparent-pq` at `48ff42d0196079048f70ba6d74e0ab0463fe900e`. Existing
[MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE) notices apply. The integration
retains pinned upstream Zakura's ordered UTXO resolver, legacy checks and mempool
reset implementation. Only SLH runtime types and dependencies are included.

| Source module under `node/zakura/` | SHA-256 | Adaptation |
| --- | --- | --- |
| `crates/zakura-consensus/src/transaction/pq.rs` | `a25d28a3a6d6e507e82386f7c0211cc86adf6f747c58ba56e54a4c8c0f693984` | Retain generic atomic budget implementation; remove other suites; substitute explicit SLH limits/errors and frozen16/64 functional boundary controls. |
| `crates/zakura-consensus/src/transaction.rs` | `75a337a0e86db4d07d5a5d6014f9c6fb24d8a0fd34cd9df3ffe0df78b51234a8` | Reuse ordered reservation and Rayon find_map_first N1 prefix verification; SLH native facade and boxed signatures. |
| `crates/zakura-chain/src/transaction/unmined/pq.rs` | `eecfbc221dd1305563dca3c4ad61f230cd025452fe68b0cfcb1b1b6b699ceddc` | Reuse private accounting fields, authorization ID, transaction/output Arc identity and network/upgrade rule binding; only SLH and boxed optional metadata. |
| `crates/zakura-chain/src/transaction/unmined/pq/tests.rs` | `5f6084bd0f2c7443f05cca6926115bd536428c0a2f663ad4a0028f628c37082e` | Reuse two suite-independent metadata tests. Omit alternate suites and invalid-for-SLH pre-NU7 activation scenario. |
| `crates/zakura-consensus/src/transaction/tests/pq/accounting.rs` | `1b167b8173830ea580db3841e1e48c5cfa9c51da2118360f468de0e545b9e4f4` | Reuse async success-publication/cancellation and mock trusted-state service patterns; replace runtime test signing with immutable public SLH corpus and add mixed-input prohibition controls. |
| `crates/zakura-consensus/src/block/prepared.rs` | `cc84effdaf4f10c1d10c75217f2006efd97eea27079ad39cd6cd16e2ca2e9013` | Reuse cache lookup+insertion gate and focused inactive/active tests; SLH-only activation parameters. |
| `crates/zakura-script/src/lib.rs` | `abf244e67f07ab2f4a56c27ac371a579a2d0681599fa323d395363b66f18cbf4` | Add shared_previous_outputs accessor only to retain exact trusted allocation; no FFI behavior changes. |
| `crates/zakura-consensus/src/primitives.rs` | `7cb53aa5c9271fe34128f4fedc5b0508f7c0b52e54ba6161692407089a79fe89` | Exact three-line generic success-result type adaptation to existing spawn_fifo_and_convert; preserves queue, channel and boxed-error behavior; existing callers infer unit. |

Tests use the retained public synthetic SLH transaction corpus and the existing
mock trusted-state services. They do not introduce a node signing dependency.
Active SLH rules bypass prepared-candidate caches.
Runtime support follows the explicit feature, which is off by default.
Live acceptance still requires human execution.
