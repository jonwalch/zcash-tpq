# Source and license attribution

The independent [colinxu2020/slhdsa implementation](https://github.com/colinxu2020/slhdsa/tree/588ea1028003bf5608a92bae1d8d76abaa7274a2)
is pinned at `588ea1028003bf5608a92bae1d8d76abaa7274a2` and licensed
LGPL-3.0-or-later. The fetched low-level modules are unchanged, retain their
copyright notices, and are used only by separate Python test tooling. Complete
[GPLv3](licenses/COPYING) and [LGPLv3](licenses/COPYING.LESSER) texts are retained
here and fetched alongside the source. `reference.py` supplies the experimental
BLAKE3 parameter hooks and is distributed under LGPL-3.0-or-later.

The official [portable C BLAKE3 implementation](https://github.com/BLAKE3-team/BLAKE3/tree/f55849f89cd85083c1c9daa2c5de20766f309c00/c)
and hash vectors are pinned at `f55849f89cd85083c1c9daa2c5de20766f309c00`,
under Apache-2.0 OR CC0-1.0. Both [Apache](licenses/BLAKE3-LICENSE_A2) and
[CC0](licenses/BLAKE3-LICENSE_CC0) texts are retained. `hash_shim.c` wraps its
streaming API with portable dispatch. The Rust candidate uses BLAKE3 1.8.5;
the independent C pin is deliberately unchanged.

[sources.json](sources.json) records every fetched file hash. Adaptations to the
checker glue are limited to selecting these two source groups, removing signing,
key-generation and alternate-profile entry points, exposing only external Pure
verification, using portable library filenames, validating source receipts, and
writing bounded comparison receipts. `hash_shim.c` only renames the wrapper
symbol; its hash operations are unchanged. No low-level reference algorithm or
official expected hash output is patched.

The three public SLH verification tuples retain the independent reference's
expected bytes and provenance recorded by the
[verifier crate](../../../crates/pq-slh-dsa-b-verify/PROVENANCE.json). Public test
material carries no real wallet secrets. This BLAKE3 variant is experimental
and is not a FIPS 205 profile.
