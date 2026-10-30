# Standalone TPQ devnet tools

`tpq-devnet` prepares one isolated local cohort, loads its saved seed blocks
through the node verifier, and signs one classical-to-SLH funding payment.
The package is `zakura-tpq-devnet`, with `publish = false`. Nodes do not depend
on this package. It does not change ZDN or require a research checkout at runtime.
Read the [protocol](protocol.md) and [native network guide](devnets.md) first.

This is an opt-in, bounded local recipe, not a public-network launcher or a
general classical wallet. The recipe disables proof of work explicitly. Do not
expose it as a permissionless public chain. Live acceptance remains unqualified.

## Reuse public rules and profiles without signing

The existing library supports `default-features = false`. This keeps `Rules`,
`Rules::network`, `Chain`, `Chain::validate`, `Chain::load`, `Chain::wallet_profile`
and `Chain::validate_wallet_profile` available without wallet keys, the SLH
signer or the transaction-signing context. It reuses the same native rule,
saved-block and canonical profile checks. It does not copy consensus,
fingerprint or profile parsing logic.

`validate_wallet_profile` requires exact canonical profile bytes and compares
every profile field with the validated saved chain. It rejects a profile that
is valid by itself but has another genesis, fingerprint, activation or check
budget. This is consistency checking, not authentication: first bind the input
files to an independently approved public artifact set.

The dependency on `zakura-pq-wallet` selects only its opt-in `public-profile`
feature, with default features disabled. This exposes `Hex`, `Profile` and
`Error`, not keys, signing, backup encryption or payment operations. The full
wallet feature includes it. The public types moved from `manifest.rs` to
`profile.rs`, retaining their public re-exports and validation. The existing
`canonical.rs` is unchanged, including its clearing output buffer, ASCII/depth
checks, duplicate/unknown rejection, exact serialization comparison and the
4,096-byte profile limit. This reuses the implementation at TPQ source baseline
`7d8d9349dbc8914c6423f1a5a3d3ef8f2f6f208d`; no research runtime dependency or
new wire format is introduced.

The default `wallet` feature retains the existing `tpq-devnet` executable,
preparation, bootstrap, RPC and funding APIs. The
executable requires that feature. Existing default commands and file formats
are unchanged. A public-input adapter can select the signing-free library profile
without adding another crate or importing private funding operations.

This library boundary is not an OS sandbox. The optional public adapter below
adds an offline process protocol, not deployment or host lifecycle authorization.
Other consumers in the same Cargo graph can still enable the default feature;
check the exact final consumer graph before packaging a host executable.
The [dependency guard](../../tests/slh-dsa-b128s/dependencies/README.md) checks
both standalone-tool and public-rules profiles across all targets.

## Signing-free public-input adapter

The separate `zdn-tpq-adapter` executable implements
`zdn-public-chain-adapter/v1`. Build only this profile for host distribution:

```sh
cargo build --locked -p zakura-tpq-devnet --no-default-features \
  --features adapter --bin zdn-tpq-adapter
```

The `adapter` feature selects only public validation, SHA-256 and TOML support.
It does not select the `wallet` feature. Normal all-target checks may enable
both; that executable refuses at startup rather than acting as a host adapter.
Never package a combined-feature executable as signing-free. The normal/build
dependency guard checks the dedicated adapter graph across all targets.

Invoke the executable with exactly `--zdn-public-chain-adapter-v1`. It reads one
bounded UTF-8 JSON request from stdin and writes one JSON response. Operations
are `describe`, `compile` and `render`. Protocol, operation, fresh caller UUID,
adapter-selection digest and operation context must match. Envelope and typed
objects reject unknown/duplicate fields, positional arrays, floats and trailing
JSON. Public metadata/schema is `zdn-external-public/v1`; implementation identity
is `zdn-tpq` version `0.1.0`. A digest identifies bytes, not their publisher.

`CompileInput` has exactly `descriptor`, `nativeRulesJson`, `walletProfileJson`
and `seedBundle` (byte count/SHA-256). The descriptor has `schema`, `nativeName`
and `nativeFingerprint`. Native rules and canonical profile are exact public
file bytes in explicit slots, not arbitrary settings or an executable callback.
The raw slot is always the regular file `seed-blocks.bin` in the staged working
directory. Its format is repeated four-byte little-endian length plus exact
block bytes, with no paths. The compiler verifies the bundle digest and actually
decodes every block through `Chain::validate`, then checks the canonical profile
with `Chain::validate_wallet_profile`. It does not trust claimed block hashes.
`import_public` converts only explicit `chain.json` and `wallet-profile.json`
bytes. Do not recursively upload a preparation directory or include `funder.json`.

The exact compact result bytes contain native identity, full effective rules,
collapsed native upgrade/branch schedule, dense seed identities and byte pins,
sorted Cargo features/capabilities and finite transport class. Result hashes do
not include request IDs or envelopes. `render` recompiles the public inputs and
requires the exact compiled-result hash. Runtime paths, role, image digest,
native listener, expected persistent NodeId and private public-peer inventory
are bound in the request's input hash. Rendered configuration includes
`network.zakura.expected_node_id` and keeps identity storage separate from chain
state. ZDN must independently enforce its allowlisted security envelope before
comparing or installing renders.

The rule projection moved from the product's
`zakura-rpc/src/methods/chain_diagnostics.rs` into
`zakura-chain/src/chain_diagnostics.rs`. RPC supplies its actual verifier/runtime
identity; the adapter supplies required true support flags for a future node.
Those flags are expectations, not observations or evidence this executable has
a verifier. The signing-contract constant has one native owner, used by consensus
and both projections. No consensus/fingerprint implementation was copied and
no RPC/service dependency was added to the adapter.

Budgets: 4 MiB request/response, 2 MiB per metadata slot, 128 MiB raw bundle,
256 blocks and the existing 1 MiB native seed-block decoder bound. Core may
accept up to 2,000,000 bytes per saved block, but this adapter retains its stricter
native-tool bound. This is not full 20 MB saved-history import. Core supervision
must enforce deadlines/cancellation and independent output limits. Scrubbing
environment variables does not establish OS, network or filesystem isolation.

**Operational status:** offline contracts only. ZDN host delivery/sandbox,
two-phase persistent peer inventory/UDP provisioning and install/startup/
bootstrap/readiness/producer/update/recovery gates remain required before an
external deployment can be enabled. Inspection/cleanup must not require adapter
execution. A deliberate refusal is not supported deployment integration. No live,
cloud, container, signing or payment qualification is provided by these contracts.

The separate-terminal connection, managed identity, approved funding, uncertain
wallet outcome and recovery workflow is in the [ZDN runbook](zdn.md). Use that
runbook rather than treating this protocol reference as deployment approval.

### Export only the public slots

Build the separate signing-free importer with the same feature selection:

```sh
cargo build --locked -p zakura-tpq-devnet --no-default-features \
  --features adapter --bin zdn-tpq-import
target/debug/zdn-tpq-import ABS_CHAIN_JSON ABS_WALLET_PROFILE_JSON \
  ABS_LINUX_HOST_ADAPTER EXECUTABLE_SHA256 SELECTION_SHA256 SOURCE_REVISION \
  ABS_NEW_PUBLIC_DIR
```

All four paths must be absolute; the output directory must be new. The two
64-character lowercase SHA-256 values pin the selected executable and adapter
selection. The source revision is 40 lowercase hex characters. The importer
validates the native chain, canonical profile and exact executable bytes before
creating the directory. It writes only `descriptor.json`, `native-rules.json`,
`wallet-profile.json`, `seed-blocks.bin`, `host-adapter`, `compiled.json` and
`package.json`. The package pins exact slot bytes and the two original public
source files. It does not execute the host adapter, upload files or read a funder.
The final JSON contains the exact package pin and native fingerprint. The
package's declarations are not an independent core trust decision.

## Prepare once

After the package is included in the workspace, build it separately:

```sh
cargo build --locked -p zakura-tpq-devnet --bin tpq-devnet
target/debug/tpq-devnet prepare /srv/tpq/cohort-public /srv/tpq/cohort-private MyCohort
```

Both directories must be new. Their parents must already exist and be trusted.
The directories must not contain each other. Preparation uses the native
`local_genesis` generator, with one random P2PKH funder and 100 empty maturity
padding blocks. It saves 102 blocks: genesis at 0, the 10 ZEC funding coinbase
at 1, and empty blocks through seed tip 101. NU7 starts at 102; SLH starts at
103. The limits are 16 checks per transaction and 64 per block. These are test
settings, not capacity recommendations.

The new generator entry point is
`generate_local_testnet_with_slh_dsa_b128s_funding`. It explicitly enables
`should_allow_unshielded_coinbase_spends` **before** network construction and
the final native fingerprint. It does not reduce coinbase maturity from 100.
The existing ordinary and SLH generator APIs retain their previous behavior.

Preparation writes these public files:

| File | Content |
| --- | --- |
| `chain.json` | Exact canonical seed bytes, full supported rules, native fingerprint |
| `node-network.toml` | Node network configuration fragment with the exact rules |
| `network.json` | The same network fragment as JSON for callers |
| `wallet-profile.json` | Canonical custom wallet profile accepted by `Profile::from_json`, without keys |

Only the native fingerprint goes to preparation stdout. The public files do
not contain a private key. Authenticate the public artifact and fingerprint
through your deployment channel before use. A hash in an untrusted file does
not authenticate that file.

`cohort-private/funder.json` contains the real classical key. Its schema is
`{"schema":1,"chain_fingerprint":"<hex32>","secret_key_hex":"<hex32>"}`.
The directory has mode 0700, and files have mode 0600. All writes use create-new,
file sync, and directory sync. Read paths check private permissions and reject
direct symlinks. Private input must be a regular file. Other operating systems
fail closed instead of claiming Unix permission protection.

**Private storage limitation:** this file is not encrypted. Use an encrypted
volume and a private backup with the same access controls. This bounded tool
does not add a password/KDF format or reuse the PQ root for classical signing.
It does not promise memory zeroization, protection from the same user or root,
or race-free operation against an attacker who can rename ancestor directories.
Use a trusted single-writer directory tree. Never commit this file or upload it
with public chain artifacts. A partial preparation failure leaves its files in
place for inspection; it does not overwrite or automatically regenerate them.

## Configure each node

Use `node-network.toml` as a fragment in a full node config. Do not change its
consensus fields or extend its checkpoints. Configure separate node-specific
state caches, peer caches, identity directories, listen ports, and RPC ports.
Use the native `zakura` peer stack and your own `NodeId@IP:port` bootstrap
inventory. The emitted empty native bootstrap list is intentional. Clear public
seeds. The existing native peer handshake, fingerprint, and state namespace
rules provide isolation; the tool does not replace them.

Enable the node's experimental SLH runtime feature. Bind authenticated RPC to
loopback. Direct mode uses the node's private cookie file, reopened for each
request (mode 0600 in a mode-0700 directory), not credentials on the command line.
Funding commands can instead replace the cookie positional argument with
`--trusted-local-gateway`. This explicitly trusts a literal-loopback local gateway
and sends no node credentials. Cookie and gateway modes are mutually exclusive;
there is no automatic fallback. Bootstrap remains direct-cookie-only because the
participant gateway cannot submit blocks or call administrator diagnostics.
Both modes preserve approved-chain/profile checks and reject DNS, proxies,
redirects and external endpoints. Keep a ZDN managed connection running in one
terminal and use the wallet in another normal terminal for password prompts.
Never put wallet passwords or dummy cookies in arguments, environment or journals.

Each RPC has a ten-second total network deadline and a three-second connection
timeout. Headers have a 16 KiB bound. Metadata retains the 2 MiB default body
limit; approved block/transaction hex methods use finite 40,100,000-byte bounds
including JSON overhead. This does not qualify maximum-size decoded verbose
block objects, and every gateway/forwarding hop must also support the bound.
Only fixed-length HTTP responses are accepted; chunked responses fail closed.
Saved chain files have a 16 MiB bound, with at most 256 seed blocks and a 1 MiB
bound on each decoded seed block. These are tool limits, not consensus limits.

## Load saved blocks through verification

A custom Testnet does not seed itself. Stop **all** block producers and prevent
peer sync/inbound block production during bootstrap. Keep the target node and
its authenticated RPC running. Run:

```sh
target/debug/tpq-devnet bootstrap /srv/tpq/cohort-public/chain.json \
  127.0.0.1:18232 /srv/tpq/node-private/.cookie --producers-stopped
```

The flag is an operator precondition, not a remote mining-control command.
The tool checks the configured genesis, native fingerprint, and runtime support
in `getblockchaininfo.experimental_slh_dsa_b128s`, even before state has a tip.
It uses `tip_height = null` to identify that empty state; it does not mistake a
configured fallback genesis for a committed block.

The loader decodes canonical blocks and checks genesis, parent links, coinbase
heights, transaction merkle roots, and each exact configured checkpoint. It
observes a stable current best chain, reconciles its saved prefix, and calls
`submitblock` only for missing saved blocks. The node verifier remains the
authority. There are no direct database writes and no additional checkpoints.
After each submission it checks the best hash and exact `getblock` bytes.

A lost reply can follow a successful commit. The loader checks current state
instead of blindly repeating that submission. If it cannot establish the
expected tip, it stops. Re-run the same command with the **same** artifact to
reconcile. It never regenerates blocks. It refuses conflicting chains and tips
beyond the saved seed range; after production starts, use the normal node
restart path, not bootstrap. This recipe does not use `getchainrules` or
`inspectchainblock`; it uses the existing verifier/RPC path.

## Fund an SLH receiver

Use a separate PQ wallet root and the saved custom profile. The profile has:

```text
genesis_hash, max_block_pq_checks=64, max_tx_pq_checks=16, network=1,
nu7_activation_height=102, nu7_branch_id="77190ad9",
pq_activation_height=103, chain_fingerprint=<native hex32>
```

This tool takes a `tpqtest` Bech32m receiver from the wallet. It uses the wallet's
public receiver API to check the native chain fingerprint before it extracts
the 35-byte SLH locking script. Receivers for another chain, Regtest receivers,
and raw script hex are rejected before key access, signing, or RPC calls.
Do not pass a PQ secret or root to this tool.

After bootstrap, use the existing block producer to produce the NU7 block at
102. Then stop it and establish a stable tip before funding. Use the existing
classical mining payout support; this tool does not add a native PQ mining
address or build shielded proofs. The seed output keeps its 100-block maturity.
Funding is permitted only when SLH governs the next block.

```sh
target/debug/tpq-devnet fund-draft /srv/tpq/cohort-public/chain.json \
  127.0.0.1:18232 /srv/tpq/node-private/.cookie \
  /srv/tpq/cohort-private/funder.json /srv/tpq/cohort-private/payment.json \
  "$TPQTEST_RECEIVER" 100000000 10000
```

The bounded first version spends only seed block 1, output 0. It authenticates
that block hash and genesis against the trusted node, checks `gettxout`
ownership, integer amount agreement, coinbase status, confirmations, maturity,
and stable best tip. Saved canonical block bytes provide the integer amount;
RPC coin values must convert exactly to zatoshis without floating-point math.
The transaction is transparent-only v5 at NU7. It has one real P2PKH signature,
one SLH destination, and classical P2PKH change to the same funder. It needs no
SLH signing or PQ signature checks.

Review the saved payment file and stdout. Check chain fingerprint, source,
destination script, amount, fee, change, expiry, txid, and transaction SHA-256.
Amounts use checked integer arithmetic. The destination and change floors are
2,403 zatoshis; the allowed explicit fee range is 10,000 through 1,000,000.
These are conservative tool bounds, not new consensus or fee-estimation rules.
The tool saves and syncs signed bytes **before** any submission.

After review, explicitly approve the saved transaction SHA-256:

```sh
target/debug/tpq-devnet fund-submit /srv/tpq/cohort-public/chain.json \
  127.0.0.1:18232 /srv/tpq/node-private/.cookie \
  /srv/tpq/cohort-private/payment.json "$APPROVED_TRANSACTION_SHA256"
```

Submission rechecks saved canonical bytes, signature, payment arithmetic,
fingerprint, source state, and expiry. It first reconciles exact known bytes
through `getrawtransaction`. A successful command means node-known, not mined
or final. After an ambiguous reply, retain the payment file. Re-run only this
exact submit command to reconcile or retry the exact saved bytes. Never create
a new payment to resolve an unknown result. A spent source or expired unknown
payment stops the tool and needs operator investigation. Resume the existing
producer separately and monitor confirmation through the trusted node.

There is no automatic key deletion, change spending, UTXO selection, generic
legacy wallet, shielded funding, background retry worker, or multiple-funder
allocation. Keep one review file per seed funding operation. Do not make
competing drafts for the same outpoint.

## Source mapping and validation scope

The implementation starts from product commit
`cc724c0d3092bde7a2efc4ad9d2199d228842be0`:

- `local_genesis`: reuse its random keys, block construction, seed timestamps,
  checkpoints, and upgrade scheduling. The new opt-in function changes only
  the unshielded coinbase funding flag before final network construction.
- `zakura-network/src/config.rs`, `DTestnetParameters::from`: map the supported
  generated consensus fields to the public network fragment. Replay them through
  the native builder and require the same native fingerprint, not a new hash.
- `tests/slh-dsa-b128s/fixtures/host/src/classical.rs`: reuse NU7 SIGHASH_ALL,
  DER signature and sighash suffix construction. Replace public fixed P2SH
  fixtures with the generator's real random P2PKH key and trusted-node source
  resolution. The underlying research signing flow is also present in
  `tests/common/feasibility.rs`; no research runtime dependency is introduced.
- `crates/pq-test-support/src/lib.rs`: preserve explicit transparent-only v5
  field construction directly, rather than depending on a test-only crate.

New orchestration code is necessary because a custom Testnet does not self-seed,
and fixture-only funding does not own real keys or authenticate live UTXOs.
The package adds bounded file/HTTP storage and transport, not chain consensus.
It serializes the wallet's public `Profile` type in compact field order and uses
`Receiver::{parse,check_profile,script}` rather than a second receiver decoder.
The wallet dependency belongs only to this standalone utility; nodes must not
depend on it or acquire its signing features.

Focused tests cover random real-key signature verification and output mutation,
wrong ownership, maturity, checked fee/change arithmetic, saved-byte retries,
lost block replies, prefix restarts, wrong genesis/fingerprint, bootstrap
conflicts, create-new separation, and authenticated bounded loopback HTTP.
Regression tests also parse the emitted profile through the wallet public API,
parse both config fragments through `zakura_network::Config`, and reject funding
receivers from another custom chain or Regtest.
Integrated checks with Rust 1.97.1 passed all seven standalone-tool tests and
all fourteen focused genesis-generator tests. These are local library and
authenticated HTTP-double tests, not live-node qualification. Repeat them with:

```sh
cargo test --locked -p zakura-tpq-devnet
cargo test --locked -p zakura-chain local_genesis
cargo clippy --locked -p zakura-tpq-devnet --all-targets -- -D warnings
cargo clippy --locked -p zakura-chain --all-targets -- -D warnings
```

Live node/bootstrap/funding acceptance and any dedicated node build remain
pending explicit approval under [AGENTS.md](../../AGENTS.md). No proof generation,
node/container run, profiling, or ZDN integration is claimed here.
