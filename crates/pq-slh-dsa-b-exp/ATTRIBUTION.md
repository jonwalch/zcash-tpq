# Native authorization attribution

Policy encoding, message framing and the reservation facade were adapted from
`crates/pq-sqisign-exp` in `jonwalch/zcash-transparent-pq` at
`85f75af3f70cc292918a013b280ed06426b6fa98`. The accompanying MIT and
Apache-2.0 notices apply. The source mappings below identify the reused modules;
no SQIsign implementation or signing dependency is imported.

| Source module | SHA-256 | Local module |
| --- | --- | --- |
| `codec.rs` | `96624bcf2b5537ba04f1b85b50d7fc32a675dc69960506bd2673e4a074c1a133` | `codec.rs` |
| `contract.rs` | `baf5e8e863ef732e8b62aa590344f513770fdad86dea34d04ee38ca62abb7520` | `contract.rs` |
| `verifier.rs` | `7c6baae217f63a34822ad075e9197fcd251fb5270375c7bacd9d5f216296e637` | `rejection.rs` |
| `verifier.rs` | `7c6baae217f63a34822ad075e9197fcd251fb5270375c7bacd9d5f216296e637` | `verifier.rs` |
| `signer.rs` | `95549d9ce8e28754e891eb01a9d2c3c48011ffae01dafc0a615a31f64eceb699` | `signing_context.rs` |
| `test_observer.rs` | `a83d12e5bc800547a5234306be0c98438668c93808c90ff8c7816dfdc83a8348` | `test_observer.rs` |

Changes are limited to the frozen SLH identifiers and field sizes, fifteen
participants, the 128 KiB preliminary guard, boxed signature ownership, the
real SLH verifier call, and removal of source-suite normalization and signer
dependencies. Policy counts are rejected before sorting; public push encoding
rejects fields that cannot fit PUSHDATA2. Native verification accepts exactly
101 message bytes with empty context. The public signing-context extraction
contains only trusted policy binding, message access and verified assembly.

Canonical codec tests adapt the source module’s regression cases. Context
tests reuse the separately attributed neutral `pq-test-support` recipes.
SHA-256 commitment answers were computed independently with Python `hashlib`
and literal protocol bytes. Independent signed-transaction corpus validation
is an additional required check, not supplied by these structural tests.
