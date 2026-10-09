# Source attribution

The fixed-profile algorithms are adapted from RustCrypto/PQC Suite B SLH-DSA
at <https://github.com/PQC-Suite-B/signatures>, revision
`b392fe82d2d9770142477a576a758a233888bc0a`, under MIT OR Apache-2.0. The source's
license texts are retained without modification as `LICENSE-MIT` and
`LICENSE-APACHE`.

Address, utility and signature-recovery helpers reuse this repository's existing
verifier extraction at `24ff6cfc607a169fbf3ce4c34b596ba22ba02789` with the narrow
changes listed in `PROVENANCE.json`. The safe hash role and clearing changes,
fixed-width ownership API and tests are local adaptations. No source algorithms
from the independent LGPL Python reference are incorporated in this Rust crate.
