# Zakura with experimental SLH-DSA-B-128s

This repository adds SLH-DSA-B-128s signatures for transparent funds to
[Zakura](https://github.com/zakura-core/zakura), a Zcash node in Rust.
It includes a command-line wallet, multisig policies through 15-of-15,
encrypted backups, recovery, and watch-only monitoring.

**SLH support is off by default and works only on Regtest**, a local test network.
The node and wallet include the implementation. Live tests and performance tests
remain pending. Agents must obtain user approval before running them under
[AGENTS.md](AGENTS.md). The BLAKE3 construction is experimental.
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
The source repository is [jonwalch/zcash-tpq](https://github.com/jonwalch/zcash-tpq).
Binary and package releases are not configured.

## Technical documents

The [protocol](docs/slh-dsa-b128s/protocol.md) specifies signatures, transaction
formats, and activation rules. The [wallet contract](docs/slh-dsa-b128s/wallet.md)
specifies key derivation, payment approval, and storage limits.
The [packaging guide](docs/slh-dsa-b128s/packaging.md) describes source attribution
and checks before publication.
The [writing guide](docs/slh-dsa-b128s/writing.md) describes the plain-English style and technical terms.

The upstream base is Zakura commit `a29a968575e37223cbeb8ac7a5d57aba135fb93a`.
Zakura derives from [Zebra](https://github.com/ZcashFoundation/zebra).
The inherited documents remain in this repository.
Their installation instructions and performance results apply to upstream releases.
The [pinned upstream README](https://github.com/zakura-core/zakura/blob/a29a968575e37223cbeb8ac7a5d57aba135fb93a/README.md)
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
