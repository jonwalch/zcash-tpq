# Experimental SLH-DSA-B-128s transparent authorization

This specification freezes `slh-dsa-b-128s-exp-v1` for an off-by-default,
Regtest-only implementation. SLH-DSA-B-128s uses BLAKE3 and is not a FIPS 205
profile. Public-network activation, construction security review and operational
acceptance are separate requirements. Consensus, relay, mining and state lifecycle
source are integrated behind the explicit feature. Default builds refuse configured
activation; daemon and live acceptance remain pending human execution.

## Source and primitive

The Zakura baseline is upstream `zakura-core/zakura` commit
`9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`, tree
`ac1ad49b6262001d4c07b7458f9638859cc75c36`.
The algorithm source is `PQC-Suite-B/signatures` commit
`b392fe82d2d9770142477a576a758a233888bc0a`, fixed `Blake3_128s`.
The new verifier and wallet signer pin BLAKE3 `=1.8.5` with no Rayon feature.
Parameter values are n=16, h=63, d=7, h'=9, a=12, k=14, w=16,
35 WOTS chains and a 30-byte message digest. The public key is 32 bytes and
the signature is 7,856 bytes. Preserve unkeyed BLAKE3 hash input ordering,
addresses, masks and output lengths from that source.

The verifier crate exports:

```rust,ignore
pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 7856;
pub const MAX_MESSAGE_BYTES: usize = 65536;
pub const MAX_CONTEXT_BYTES: usize = 255;
pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8],
              context: &[u8]) -> Result<(), VerifyError>;
```

`VerifyError` distinguishes `PublicKeyLength`, `SignatureLength`,
`MessageTooLong`, `ContextTooLong` and `InvalidSignature`. Check all lengths
before hashing. Apply external Pure framing `[0, context.len()] || context ||
message` exactly once; no internal-framing bypass is public. The node always
passes the 101-byte message below and an empty context. Verification borrows
signature sections. There is no signing, RNG, JSON, chain, dynamic loader or
subprocess dependency in this crate's runtime graph.

## Byte contract

Strings are ASCII and `\0` is one terminal zero byte. Hashes are raw bytes;
transaction digests are not reversed.

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

The message domain occupies 58 bytes and `M_i` occupies 101. Network bytes
00/01/02 denote Mainnet/Testnet/Regtest for domain checks; activation is Regtest
only. Versions are 05/06 with reviewed NU7 branch `0x77190ad9`. Input index is
bound explicitly. The primitive adds `00 00` to this message once.

All 120 policy shapes `1 <= m <= n <= 15` are supported. Commitments are
strictly increasing and distinct, and descriptor length is exactly `4 + 32*n`.
Exactly m records use increasing distinct indices in range. Indices 0..14 use
00 or 51..5e, keys use `20 <32 bytes>`, and signatures use
`4d b0 1e <7856 bytes>`. The descriptor uses its minimal direct/PUSHDATA1/
PUSHDATA2 push. Reject trailing bytes, sighash suffixes, chunking, extra records,
nonminimal pushes and keys that do not match indexed commitments.

Check the 131,072-byte authorization guard first. Reject more than fifteen
participants before allocating commitments and a sixteenth record before
reading its key or signature. The canonical maximum is 118,882 bytes, not the
guard. A 15-of-15 input uses a five-byte CompactSize script length.

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

These sizes are encoding calculations; they do not establish signed-vector or
live-node acceptance. Changing domains, framing, template or policy limits
requires a contract revision, new vectors and state-namespace review.

## Authorization API and ownership

The native crate reuses the reviewed canonical-policy and prepared-transaction
facade. `Policy` owns its bounded commitments. `Record` owns its public key and
one `Box<[u8; 7856]>`; `Authorization::decode` makes one bounded heap copy per
signature. `TransactionContext<'tx>` retains one immutable borrowed transaction
and `Arc<Vec<Output>>`, and prepares digests once. The caller authenticates the
outpoints and ordered previous outputs; shape checks do not establish trust.

`TransactionContext::{new,message,reserve_input,verify_input}` and
`ReservedInput::{input_index,checks,verify}` preserve the existing facade.
`reserve_input(index, reserve)` binds keys/policy and invokes one
`FnOnce(usize) -> Result<(), Rejection>` before crypto. It moves signature boxes
into private `SignatureCheck` fields. `SignatureCheck::verify` calls the real
primitive; checks are not clonable through the worker path. No supplied digest
or caller-selected verifier is accepted. Incomplete structural checkpoints may
omit verification methods; they must never provide an accepting placeholder.

Verifier-only `InputSigningContext` provides construction from trusted context,
network/upgrade/input/policy/message accessors, partial verification and
authorization assembly. The wallet signer consumes this context outside the
node graph. The native crate never depends on a signing implementation.

## Network rules and state

The configuration fields are
`experimental_slh_dsa_b128s_activation_height`,
`experimental_slh_dsa_b128s_max_checks_per_transaction`, and
`experimental_slh_dsa_b128s_max_checks_per_block`.
Require all three or none; reject public-network settings, invalid/overflowing
limits, activation at or before NU7, and activation at or before any checkpoint.
`ExperimentalSlhDsaB128sLimits::{new,transaction,block}` and
`Network::{experimental_slh_dsa_b128s_activation_height,
experimental_slh_dsa_b128s_limits,is_experimental_slh_dsa_b128s_active}` supply
the typed contract. No implicit limits are installed.

The initial functional test profile is NU7=105, SLH=110, 16 checks/transaction,
64/block. These values are not performance or production recommendations.
Use containing-block height for history and candidate-next-block height for
mempool admission. Namespace database and backup paths as
`regtest-slh-dsa-b128s-v1-hH-tT-bB`; reset pending/completed/stored work on
activation, rollback and reactivation. Startup consults
`zakura_consensus::supports_experimental_slh_dsa_b128s()`, which reports whether
the integrated experimental feature is compiled. It does not attest live acceptance.

Classical inputs may fund SLH outputs with ordinary classical authorization and
zero SLH checks. If any transparent input spends an active SLH output, every
transparent input must do so. Classify trusted spent outputs and reject mixtures
before reservation or verification. Different SLH policies may share a node
transaction. There is no alternate PQ backend or classical/PQ fallback.

Reserve signature budgets atomically with deterministic input/check failure
ordering and no refunds. Publish verified accounting only after full transaction
success, including bound zero counts for classical funding under active rules.
Bypass prepared-candidate caches whenever SLH is active. Relay/mining must agree
with verified metadata, admit zero-cost funding when check budgets are exhausted,
check all resources before deduction, and respect parent ordering.

Apply the existing fee policy to actual encoded sizes. The SLH dust floor at
the pinned policy is 2,403 zatoshis; it is a relay rule. Other ordinary classical
and shielded behavior stays unchanged.

## Verification and wallet scope

Independent primitive/native conformance precedes runtime wiring. Expected
crypto outputs and transaction digests must not call production implementations.
Retain source hashes, licensing, small public KATs and negative mutations.
No new verification-result cache or performance optimization is included.

The full deliverable also includes an in-process wallet signer, normal CLI,
finite public watch inventories, encrypted key/inventory backup and coherent
recovery of existing journal/watch state. Freeze wallet derivation, capacities
and recovery contracts before coding wallet consumers. Reuse existing formats
and durable approval behavior wherever their meaning is unchanged. A key backup
alone cannot reconstruct unknown outstanding signatures or authorization history.
Wallet completion and human acceptance remain pending.
