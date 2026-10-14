# SLH-DSA-B-128s protocol

This document specifies `slh-dsa-b-128s-exp-v1`.
Support is off by default and works only on Regtest.
SLH-DSA-B-128s uses BLAKE3. It is not a FIPS 205 profile.
The node includes consensus, relay, mining, and state support behind the feature.
Live acceptance and independent security review remain open.

## Source and signature primitive

| Item | Pinned value |
| --- | --- |
| Zakura commit | `24a17b3f0e7d88513688d607054f018ab6f15af2` |
| Zakura tree | `d31e58e9f200123dd39434d42ad2643eda7a8a23` |
| `PQC-Suite-B/signatures` commit | `b392fe82d2d9770142477a576a758a233888bc0a` |
| Algorithm | `Blake3_128s` |
| Verifier and wallet signer hash dependency | BLAKE3 `=1.8.5`, without Rayon |
| Parameters | n=16, h=63, d=7, h'=9, a=12, k=14, w=16 |
| WOTS chains / message digest | 35 / 30 bytes |
| Public key / signature | 32 / 7,856 bytes |

The implementation preserves the source's unkeyed BLAKE3 input order,
addresses, masks, and output lengths.
The verifier exports this API:

```rust,ignore
pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 7856;
pub const MAX_MESSAGE_BYTES: usize = 65536;
pub const MAX_CONTEXT_BYTES: usize = 255;
pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8],
              context: &[u8]) -> Result<(), VerifyError>;
```

`VerifyError` distinguishes `PublicKeyLength`, `SignatureLength`,
`MessageTooLong`, `ContextTooLong`, and `InvalidSignature`.
The verifier checks lengths before it hashes data.
It applies Pure framing once: `[0, context.len()] || context || message`.
No public API bypasses this framing.
The node supplies the 101-byte message below and an empty context.

The verifier borrows signature sections.
Its runtime dependencies exclude signing, random-number generation, JSON,
chain code, dynamic loaders, and subprocesses.

## Byte contract

Strings use ASCII. `\0` denotes one final zero byte.
Hashes use raw bytes. Transaction digests retain their byte order.

```text
key_domain     = "ZcashTransparentPQ/experimental/slh-dsa-b-128s/key/v1\0"
policy_domain  = "ZcashTransparentPQ/experimental/slh-dsa-b-128s/policy/v1\0"
message_domain = "ZcashTransparentPQ/experimental/slh-dsa-b-128s/message/v1\0"

H[i] = SHA256(key_domain || f7 || public_key[i])
D    = 01 || f7 || m:u8 || n:u8 || H[0] || ... || H[n-1]
C    = SHA256(policy_domain || D)
scriptPubKey = 53 20 <C:32> c0
scriptSig    = (<index> <public_key> <signature>)[m] <D>
M_i = message_domain || f7 || network || tx_version
      || LE32(branch_id) || LE32(input_index) || SIGHASH_ALL_digest[32]
context = empty
```

The message domain has 58 bytes. `M_i` has 101 bytes.
Network bytes 00, 01, and 02 denote Mainnet, Testnet, and Regtest for domain checks.
Only Regtest permits activation.
Transaction versions are 05 and 06. The NU7 branch ID is `0x77190ad9`.
The message includes the input index. The primitive adds `00 00` once.

All 120 policy shapes satisfy `1 <= m <= n <= 15`.
The descriptor has exactly `4 + 32*n` bytes.
Commitments must be distinct and in increasing order.
Exactly m records must have distinct indices in increasing order and within the policy.
The encodings are:

- Indices 0..14: 00 or 51..5e.
- Public keys: `20 <32 bytes>`.
- Signatures: `4d b0 1e <7856 bytes>`.
- Descriptor: its minimal direct, PUSHDATA1, or PUSHDATA2 push.

The decoder rejects trailing bytes, sighash suffixes, signature chunks, extra records,
and nonminimal pushes. Each key must match its indexed commitment.

The decoder first checks the 131,072-byte authorization guard.
It rejects more than fifteen participants before it allocates commitments.
It rejects a sixteenth record before it reads the key or signature.
The canonical maximum is 118,882 bytes.
A 15-of-15 input uses five bytes for the CompactSize script length.

| Quantity | Bytes |
| --- | ---: |
| Signer record | 7,893 |
| 1-of-1 authorization / full input | 7,930 / 7,973 |
| 2-of-3 authorization | 15,888 |
| 8-of-10 / 9-of-10 authorization | 63,471 / 71,364 |
| 10-of-10 authorization | 79,257 |
| 15-of-15 descriptor / pushed descriptor | 484 / 487 |
| 15-of-15 authorization / full input | 118,882 / 118,927 |
| v5/v6 1-of-1 payment with recipient and change | 8,086 / 8,087 |
| v5/v6 15-of-15 payment with recipient and change | 119,040 / 119,041 |

These are calculated encoding sizes. They do not establish live acceptance.
A change to domains, framing, templates, or policy limits requires a contract revision.
It also requires new vectors and a review of state namespaces.

## Authorization API and ownership

`Policy` owns its bounded commitments.
`Record` owns its public key and one `Box<[u8; 7856]>`.
`Authorization::decode` makes one bounded heap copy per signature.
`TransactionContext<'tx>` borrows one immutable transaction and retains `Arc<Vec<Output>>`.
It prepares digests once.
The caller must authenticate outpoints and supply previous outputs in input order.
Shape checks do not establish that trust.

The API includes `TransactionContext::{new,message,reserve_input,verify_input}`
and `ReservedInput::{input_index,checks,verify}`.
`reserve_input(index, reserve)` binds the keys and policy.
Before cryptography, it calls one `FnOnce(usize) -> Result<(), Rejection>`.
It moves signature boxes into private `SignatureCheck` fields.
`SignatureCheck::verify` calls the real primitive.
The worker cannot clone checks or accept a supplied digest or replacement verifier.

`InputSigningContext` supplies verifier-only access to the trusted context,
partial verification, and authorization assembly.
The wallet signer uses this context outside the node dependency graph.
The native crate does not depend on a signer.

## Network and state rules

This fork sets the block limit to 20 MB (20,000,000 bytes) on every network for
devnet use. Transaction decoding uses the same byte limit. Block headers and the
transaction count also consume block space. This change does not activate SLH
on public networks or change SLH signature-check budgets.
The upstream block limit is 2 MB. Nodes with that limit reject larger blocks.
Use this binary only on the devnet. Its rules are not compatible with public
Mainnet or Testnet, even when those network names are selected in the config.
The state database format is 30.0.0 because transaction indexes now use four
bytes. The cache uses `state-tpq/v30` to avoid sharing an upstream database with
the same version number. Existing caches under `state` require a fresh sync.
Startup rejects a database marked with a version below 30 in the v30 directory.
It also rejects an unversioned cache that contains records, whose index layout
cannot be identified. The version file must include the major version (`30.0.0`, for
example); legacy minor/patch-only markers cannot identify the layout either.
These checks apply to read-only and skip-upgrade opens. An absent
or empty directory can start a fresh database. If the first start stops after
RocksDB creates its files but before it stores any records or a version marker,
a writable restart can finish initialization. This check reads raw column
families without decoding indexes. A read-only open reports that initialization
is incomplete and asks for a writable start first. An unreadable or unidentified
cache is rejected with its cause and guidance to use a fresh cache.
All version queries require a full marker for format 30 or later.
Moving an old cache does not migrate it.

Automatic cleanup stays within `state-tpq`. Old `state` caches remain on disk;
another upstream node may still use them. Remove an old cache only after
confirming that it is no longer needed. The inherited public-network snapshot
bake, source-build benchmark, and NU7 seed tools reject this fork's layout.
They cannot convert upstream transaction indexes by moving directories.
`deploy/runner/feed_run.sh` requires an explicit `BENCH_DB_REL` that matches its
binary and snapshot, such as `state-tpq/v30/<network>` for this fork.

The classical block signature-operation limit deliberately remains 20,000,
including legacy and P2SH operations. A transparent-payment workload can reach
that limit before it fills 20 MB. The byte-limit change does not promise ten
times the classical payment throughput. SLH checks use their separate configured
budgets, and shielded transactions retain their existing resource limits.

The default RPC response budget is 641,048,576 bytes to allow verbose transaction
JSON, which repeats data as raw hex, script hex, disassembled scripts, and fields.
An explicit `rpc.max_response_body_size` setting still takes precedence. Existing
configs that set the former 50 MiB limit must raise it to receive larger responses.
The limit applies to each response, not to total RPC memory. Concurrent verbose
requests can use much more memory than a single response.

The block-sync speculative look-ahead budget defaults to 1.5 GiB. Config loading
raises positive values below one full block to 20 MB. The active checkpoint
window bypasses this budget so it can finish when speculative memory is full.
This separate window can retain 401 full blocks: 8.02 GB of serialized data and
about 32.08 GB of estimated decoded copies. The 1.5 GiB setting is not a cap on
total node memory and does not ensure that every workload fits a 4–8 GB machine.
Requests without a body-size hint reserve 20 MB each, so a fixed request budget
permits fewer concurrent requests. Legacy block and transaction messages can
carry up to 20 MiB each. The decoder does not reserve a full body from its header;
the transport buffer grows as bytes arrive. Other legacy commands, including unknown commands,
retain the old 2 MiB ceiling; oversized headers are rejected before reserving
the body buffer. The 1 KiB pre-handshake ceiling still applies.
Concurrent peers that send full bodies can still consume substantial memory.
These limits have not been measured in a live devnet run.

The configuration uses these fields:

- `experimental_slh_dsa_b128s_activation_height`
- `experimental_slh_dsa_b128s_max_checks_per_transaction`
- `experimental_slh_dsa_b128s_max_checks_per_block`

The configuration requires all three fields or none.
It rejects public networks, invalid limits, and integer overflow.
Activation must follow NU7 and every checkpoint.
`ExperimentalSlhDsaB128sLimits::{new,transaction,block}` supplies typed limits.
`Network::{experimental_slh_dsa_b128s_activation_height,experimental_slh_dsa_b128s_limits,is_experimental_slh_dsa_b128s_active}`
supplies the network rules. There are no implicit limits.

The test profile uses NU7=105, SLH=110, 16 checks per transaction, and 64 checks per block.
These are functional test settings, not production recommendations.
History checks use the containing block height.
Mempool admission uses the next candidate block height.
Database and backup paths use `regtest-slh-dsa-b128s-v1-hH-tT-bB`.
Activation, rollback, and reactivation reset pending, completed, and stored work.

Startup checks `zakura_consensus::supports_experimental_slh_dsa_b128s()`.
This function reports whether the build includes experimental support.
It does not establish live acceptance.

Classical inputs can fund SLH outputs with classical authorization and zero SLH checks.
If one transparent input spends an active SLH output, all transparent inputs must do so.
The node classifies trusted spent outputs before it reserves checks or verifies signatures.
Different SLH policies can share a transaction.
There is no alternate PQ backend or classical/PQ fallback.

The node reserves signature budgets atomically, with deterministic failure order and no refunds.
It publishes verified counts only after the complete transaction succeeds.
Classical funding under active rules receives a bound zero count.
Active SLH rules bypass prepared-candidate caches.
Relay and mining require agreement with verified metadata.
They check every resource before deduction and preserve parent ordering.
Classical funding can still enter a template when the SLH budget is exhausted.

The existing fee policy uses actual encoded sizes.
The SLH dust floor is 2,403 zatoshis at the pinned policy.
This floor is a relay rule.
Existing classical and shielded checks still apply.

## Wallet and validation

Independent checks use separate signature and digest implementations.
The [validation guide](validation.md) describes their source pins, vectors, and limits.
The wallet includes signing, the CLI, finite public inventories, encrypted backups, and operational recovery.
The [wallet contract](wallet.md) specifies formats and limits.
The [CLI guide](cli.md) lists commands.
A key backup cannot reconstruct unknown signatures or payment history.
Live node and wallet acceptance remain pending.
Agents must obtain user approval before these runs under [AGENTS.md](../../AGENTS.md).
