# Source and license attribution

The verification algorithms are adapted from the
[PQC Suite B signatures fork](https://github.com/PQC-Suite-B/signatures/tree/b392fe82d2d9770142477a576a758a233888bc0a/slh-dsa),
derived from RustCrypto SLH-DSA, under MIT OR Apache-2.0. The unmodified upstream
license texts are retained in [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). The exact upstream files, hashes, source-to-local
mapping and adaptations are recorded in [PROVENANCE.json](PROVENANCE.json).

The retained Pure verification tuples were generated independently using
[colinxu2020/slhdsa](https://github.com/colinxu2020/slhdsa/tree/588ea1028003bf5608a92bae1d8d76abaa7274a2)
and portable C BLAKE3 before comparison with the original candidate. The three
public key/signature/message/context tuples are copied byte-for-byte; public
seed and signing-key fields are omitted. No LGPL reference implementation is
included or linked by this crate. These BLAKE3 fixtures are not NIST vectors.

The hash test includes the initial 64 bytes of the length-zero unkeyed vector
from the [BLAKE3 team's official test vectors](https://github.com/BLAKE3-team/BLAKE3/blob/f55849f89cd85083c1c9daa2c5de20766f309c00/test_vectors/test_vectors.json).
That source is Apache-2.0 OR CC0-1.0. The runtime hash implementation is the locked
BLAKE3 1.8.5 dependency; its own distribution retains its source and licenses.
