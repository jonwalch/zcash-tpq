# Zakura with experimental SLH-DSA-B-128s

This repository adds SLH-DSA-B-128s signatures for transparent funds to
[Zakura](https://github.com/zakura-core/zakura), a Zcash node in Rust.
It includes a command-line wallet, multisig policies through 15-of-15,
encrypted backups, recovery, and watch-only monitoring.

**SLH support is off by default and works only on Regtest**, a local test network.
The node and wallet include the implementation. Live tests and performance tests
still require human execution. The BLAKE3 construction is experimental.
It is not a FIPS 205 profile or a production release.

## Start here

The [SLH guide](docs/slh-dsa-b128s/README.md) contains these instructions:

- [Configure a node](docs/slh-dsa-b128s/runtime.md).
- [Use the wallet](docs/slh-dsa-b128s/cli.md).
- [Save and restore backups](docs/slh-dsa-b128s/recovery.md).
- [Build the software and run acceptance tests](docs/slh-dsa-b128s/acceptance.md).
- [Check test coverage and open work](docs/slh-dsa-b128s/validation.md).

Build from this checkout with the specified features.
Upstream installers, packages, and releases do not contain this extension.
The project has no selected destination for product releases.

## Technical documents

The [protocol](docs/slh-dsa-b128s/protocol.md) specifies signatures, transaction
formats, and activation rules. The [wallet contract](docs/slh-dsa-b128s/wallet.md)
specifies key derivation, payment approval, and storage limits.
The [packaging guide](docs/slh-dsa-b128s/packaging.md) describes source attribution
and checks before publication.
The [writing guide](docs/slh-dsa-b128s/writing.md) describes the plain-English style and technical terms.

The upstream base is Zakura commit `9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`.
Zakura derives from [Zebra](https://github.com/ZcashFoundation/zebra).
The inherited documents remain in this repository.
Their installation instructions and performance results apply to upstream releases.
The [pinned upstream README](https://github.com/zakura-core/zakura/blob/9b175e9d3d46a6aa4cfb5552517c3d828852ecbc/README.md)
contains the upstream project information.

## Security and licenses

Use disposable test funds and keys. The fixture keys are public.
Independent security review and public-network activation remain open work.
The [validation guide](docs/slh-dsa-b128s/validation.md) states the limits of the existing tests.
The inherited [security policy](docs/security.md) applies to upstream Zakura.
The SLH extension has no designated contact for security disclosures.

The repository retains source licenses and notices.
Most Rust code uses [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
Some components have different terms.
The Python reference uses LGPL-3.0-or-later and is for tests only.
Each component includes its license information.
