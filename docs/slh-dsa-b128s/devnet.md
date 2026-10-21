# Standalone TPQ devnet tools

`tpq-devnet` prepares one isolated local cohort, loads its saved seed blocks
through the node verifier, and signs one classical-to-SLH funding payment.
The package is `zakura-tpq-devnet`, with `publish = false`. Nodes do not depend
on this package. It does not change ZDN or require a research checkout at runtime.
Read the [protocol](protocol.md) and [native network guide](devnets.md) first.

This is an opt-in, bounded local recipe, not a public-network launcher or a
general classical wallet. The recipe disables proof of work explicitly. Do not
expose it as a permissionless public chain. Live acceptance remains unqualified.

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
| `wallet-profile.json` | Custom wallet profile input, without keys |

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
loopback. Use the node's cookie file, with mode 0600 in a mode-0700 directory.
The tool takes a numeric socket and cookie path, not credentials on the command
line. It uses Basic authentication over literal-loopback HTTP only. It does
not use DNS, proxy environment settings, redirects, or an external RPC URL.

Each RPC has a ten-second total network deadline and a three-second connection
timeout. Headers have a 16 KiB bound; requests and responses have a 2 MiB bound.
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

This tool currently takes the wallet's exact 35-byte native SLH locking script:
`53 20 <commitment:32> c0`. It does not interpret a receiver as an address from
another chain. Receiver decoding is left to the wallet integration. A future
`tpqtest` Bech32m receiver must bind the fingerprint before extracting its script.
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
  "$SLH_SCRIPT_HEX" 100000000 10000
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

Focused tests cover random real-key signature verification and output mutation,
wrong ownership, maturity, checked fee/change arithmetic, saved-byte retries,
lost block replies, prefix restarts, wrong genesis/fingerprint, bootstrap
conflicts, create-new separation, and authenticated bounded loopback HTTP.
At lane handoff these tests are **written but not executed**: Rust compilation
is reserved for the coordinator's serialized integrated checks. Formatting and
offline source/document checks do not establish target execution. Run after
workspace and lockfile integration:

```sh
cargo test --locked -p zakura-tpq-devnet
cargo test --locked -p zakura-chain local_genesis
cargo clippy --locked -p zakura-tpq-devnet --all-targets -- -D warnings
cargo clippy --locked -p zakura-chain --all-targets -- -D warnings
```

Live node/bootstrap/funding acceptance and any dedicated node build remain
pending explicit approval under [AGENTS.md](../../AGENTS.md). No proof generation,
node/container run, profiling, or ZDN integration is claimed here.
