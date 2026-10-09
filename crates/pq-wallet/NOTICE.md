# Source attribution

The account-zero receive/change coordinate types and wallet root HKDF-SHA256
layout are selectively adapted from `crates/pq-wallet/src/lib.rs` in
<https://github.com/jonwalch/zcash-transparent-pq>, source revision
`85f75af3f70cc292918a013b280ed06426b6fa98`, under MIT OR Apache-2.0. Both license
texts are retained as `LICENSE-MIT` and `LICENSE-APACHE`.

`PROVENANCE.json` maps the narrow changes: an off-by-default SLH-only feature,
48-byte seed expansion and a temporary key-foundation facade while the existing
wallet flows are ported. No alternative suite, storage format, approval change
or research history is imported by this checkpoint.
