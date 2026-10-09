# Source attribution

Wallet suite dispatch, canonical JSON, inventory/profile schemas, wallet
creation/signing boundaries, error categories and focused test patterns are
adapted from `crates/pq-wallet/` in
<https://github.com/jonwalch/zcash-transparent-pq>, source revision
`da638d4045074f7957aec3fb3fb018bd66b96d05`, under MIT OR Apache-2.0. Both license
texts are retained as `LICENSE-MIT` and `LICENSE-APACHE`.

The earlier root/key foundation first selected the same derivation layout from
revision `85f75af3f70cc292918a013b280ed06426b6fa98`. Its independent derivation
vectors and algorithm remain unchanged; the complete wallet now calls the same
48-byte derivation helper.

`PROVENANCE.json` maps source files and exact target hashes. Changes restrict
suite dispatch to experimental SLH, use the existing verifier-only context and
operational signer, support policies through fifteen participants and keep all
normal dependencies behind the default-off feature. Canonical JSON is copied
without edits. No alternate signature backend or research Git history is part
of this repository.
