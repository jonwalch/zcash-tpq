# Experimental SLH wallet contract

Status: design frozen for implementation, 2026-10-09. This document specifies
the planned SLH wallet; it does not claim that payment, CLI or recovery support
is implemented. The [protocol](protocol.md) owns consensus bytes and the
`slh-dsa-b-128s-exp-v1` identity. This wallet is Regtest-only and off by default
behind `experimental-slh-dsa-b128s`.

The implementation reuses the existing Transparent PQ wallet's canonical JSON,
HKDF layout, enrollment, approval, encryption, durable reservation and journal
contracts. Changes are restricted to SLH identity, lengths, policy capacity and
operational recovery orchestration. Only suite `f7` is accepted. Other-suite
backups, saved proposals and partials are rejected, never converted implicitly.
An unavailable feature is an explicit unsupported-operation error.

## Root and derivation

A wallet owns a uniformly generated 32-byte root. Root, wallet ID and allocator
ID use separate fallible OS entropy requests; the latter two identifiers have
16 bytes each. A failure issues no receiver. Account is always zero; receive
role is `00`, change role is `01`, and index is an unsigned 32-bit integer.
Exhaustion never wraps. There is no public child derivation or xpub.

The existing derivation version and domains remain unchanged. ASCII literals
below include the single written terminal zero byte:

```text
salt = ASCII("ZcashTransparentPQ/wallet-root/v1\0")
PRK  = HMAC-SHA256(key=salt, data=root)
info = ASCII("ZcashTransparentPQ/wallet-key/v1\0")
       || 01 || 02 || f7 || LE32(0) || role || LE32(index)
T1   = HMAC-SHA256(key=PRK, data=info || 01)
T2   = HMAC-SHA256(key=PRK, data=T1 || info || 02)
seed = T1 || T2[0..16]
SK.seed = seed[0..16]; SK.prf = seed[16..32]; PK.seed = seed[32..48]
```

This is HKDF-SHA256 with 48 output bytes, not padding or repeating a 32-byte
child seed. Restore reconstructs every local public root and key commitment
and checks it against its enrolled sorted position. Independent conformance
must pin both expansion blocks, full public keys and receive/change/index
boundaries before the signer checkpoint is accepted.

The signer is a separate, safe fixed-profile crate. It accepts owned clearing
seed material, has no secret `Debug`, `Clone` or serialization, and signs the
exact 101-byte external message using Pure with empty context exactly once.
Each operational signature obtains 16 fresh bytes through fallible entropy and
passes local primitive verification before release. Entropy or verification
failure returns no partial; there is no deterministic operational fallback.
Explicit randomness belongs only to isolated conformance builds. The initial
implementation is serial and uncached. Document temporary/backend clearing
limits, including the inherited HKDF/HMAC internal-state limitation.

The wallet reconstructs trusted transaction context and approves effects before
calling the signer. The native crate supplies verifier-only
`InputSigningContext`, partial verification and canonical assembly. Neither
native nor node code depends on signing. Feature-enabled wallet dependencies
may include the signer; default wallet and every node graph must exclude it.

## Receiver, transport and policies

Retain Bech32m HRP `tpqreg`, 69 lowercase characters and the existing 35-byte
payload layout: `01 || 02 || f7 || policy_commitment`. The resulting script is
exactly `53 || 20 || policy_commitment || c0`. Reject alternate HRPs/checksums,
case, length, suites and noncanonical encodings. The prefix is experimental;
it is not an assigned Unified Address receiver.

Retain canonical JSON: printable ASCII without escapes, sorted object fields,
no whitespace/newline, duplicate or unknown fields; unsigned shortest decimal
integers, explicit permitted nulls and depth at most 16. Readers bound bytes and
collections before expensive work and reject rather than normalize.

Retain inventory/recovery/proposal version 1 envelope fields and their meanings.
The inventory's suite byte selects the 48-byte derivation, so it does not
reinterpret a saved other-suite object. A partial uses the distinct format
`ZcashTransparentPQ/experimental/slh-dsa-b-128s/partial/v1` and exactly these
fields in this order:

| Field | Encoding |
| --- | --- |
| `format` | Exact format string above |
| `input_index` | Unsigned integer 0–14, validated against approved inputs |
| `proposal_id` | 64 lowercase hex characters |
| `public_key_hex` | 64 lowercase hex characters |
| `signature_hex` | 15,712 lowercase hex characters |
| `signer_index` | Unsigned integer 0–14, validated against the enrolled policy |

Policies support all 120 shapes `1 <= m <= n <= 15`. Origins correspond
one-for-one to sorted distinct commitments; each has account zero, u32 index
and distinct participant wallet ID. Every cosigner approves the full threshold,
participant set and origin mapping. New enrollment, issuance, change selection
and signing preflight actual encoded sizes and both approved check limits.
Existing incompatible history remains readable/scannable for recovery.

Preserve the payment grouping rule: all inputs and change have the same
threshold and participant wallet-ID set, with suite-homogeneous policies. The
node's heterogeneous-policy budget fixtures do not change this approval rule.
Payments retain transparent-only v5/v6 on NU7, final sequences, zero lock time,
one recipient and optional change, and the existing 20-block expiry horizon.
Profile/recipient activation are independently approved; RPC metadata is not
permission to enable a gate. Funding tools may use classical inputs with zero
SLH checks; this does not add a classical-key wallet here.

## Capacity and rejection ledger

Bounds are independent ceilings, not a promise every combination fits. Count
canonical bytes before allocating/publishing; retain schema versions where only
the SLH size allowance changes. Errors preserve the existing distinction
between encoding/size limits, context, policy limits and approval mismatch.

| Item | Frozen allowance and required enforcement |
| --- | --- |
| Per-input authorization | Canonical maximum 118,882 bytes; native guard 131,072; validate push/index/policy encoding before crypto |
| Partial | 16,001 bytes at indices 14/14, including JSON; cap 16,384 for encode/decode, CLI files and saved local partials |
| Final transaction | Cap 262,144 bytes; apply to serialization, RPC hex bounds, review, final assembly, history/retry and snapshot reads |
| Proposal | Retain 262,144 bytes and 15 inputs; unsigned transaction has empty authorizations. At most two outputs; origins bounded at 15 before allocation |
| Assembly input files | At most the sum of approved thresholds, never over 225; reject excess and duplicate slots before verification |
| Saved local partials | At most 15, one local signature per input; do not reinterpret this as every cosigner's signatures |
| Inventory/recovery/transfer | Retain 4,096 entries and 8,388,608 bytes independently; preflight exact canonical envelope size before enrollment/export |
| Encrypted root backup | Existing 56-byte header plus bounded plaintext plus 16-byte authentication tag; no journal in this envelope |
| Journal capability | Retain 1,048,576 bytes, count the complete object including proposal, local partials, final hex transaction and metadata |
| Watch state | Retain v2 33,554,432-byte limit; v3 retains its 16,384-byte metadata allowance |
| Journal commit/quota | Retain 67,108,864-byte commit cap, object/count limits and configured quota; retained generations consume quota separately |

An entry with 15 origins at maximum u32 indices is 2,206 canonical bytes. An
array of 4,096 such entries is 9,039,873 bytes before the outer envelope, so the
entry count alone cannot promise capacity. Do not raise the 8 MiB cap: exact
preflight determines the smaller capacity. The independent envelope and object
caps similarly constrain active payment slots and retained history; do not
load the entire journal into a single recovery buffer.

Transaction sizes below include a 35-byte-script recipient and change and no
shielded data. They use exact CompactSize widths, including five bytes for a
15-of-15 authorization. Check count and byte limits are tested independently:

| Inputs/policy | Checks | v5 bytes | v6 bytes | Initial 16-check profile |
| --- | ---: | ---: | ---: | --- |
| One 1-of-1 | 1 | 8,086 | 8,087 | Fits |
| One 15-of-15 | 15 | 119,040 | 119,041 | Fits |
| Eight 2-of-3 | 16 | 127,561 | 127,562 | Exact check boundary |
| Nine 2-of-3 | 18 | 143,492 | 143,493 | Reject check limit, not byte limit |
| Two 15-of-15 | 30 | 237,967 | 237,968 | Reject check limit, not byte limit |

Use current Zakura actual-size ZIP-317 accounting and marginal fee 400, not an
old helper's 5,000. Recipient/change SLH dust is 2,403 zatoshis; test
2,402/2,403/2,404. Do not rewrite stored fee approvals. The 16-transaction /
64-block check profile is a test configuration, not a production recommendation.

## Recovery and watch-only behavior

Retain encrypted root/inventory backup algorithms and bounded parameters,
private durable file publication, exact saved authorization bytes, monotonic
retirement/cursors and one allocator. A monitor holds public inventory only;
it cannot sign or allocate. A paired allocator issues only generated entries
covered by a durable backup. Exhaustion requires explicit generation,
enrollment, backup and public inventory import.

Key/inventory restore regenerates commitments, reconciles the latest available
backup, retires old issuance ranges while preserving scan coverage and rotates
the allocator. Fresh issuance requires a new covering backup. This mode cannot
claim complete payment history or outstanding-authority recovery.

Operational restore uses the exact encrypted backup plus a coherent private
copy of the existing watch-state file and immutable journal, captured under the
allocator lock or after clean close. Receipt metadata binds backup hash,
wallet/suite/profile/inventory identity and generation. Completeness requires
a protected trusted backup source or independently retained trusted state/root
receipt; a self-consistent replacement cannot prove no authority was omitted.
Unknown outstanding authority remains restricted, including with an empty
mempool. A snapshot cannot recover later lost signatures or prove an old
allocator has stopped elsewhere.

Copy objects with bounded streaming, preserve legitimate retained orphan/temp
files under existing quota rules and validate reachable objects with the
existing readers. Reject missing/truncated/mismatched reachable objects and
unsafe paths. Stage then atomically publish into a new private directory,
leaving existing state intact on failure. Preserve reservations and exact saved
bytes. Imported observations remain cached until trusted-node reconciliation;
incomplete/pruned/unavailable history cannot become a zero/current balance.
Historical reads and any migration are explicit and recoverable. No new
encrypted journal container is required by this contract.

Implementation gates include independently checked derivation/signing, bounded
format/size tests, all policy shapes, durable approval and backup failure tests,
corruption/stale-snapshot/unknown-authority controls and default/feature graphs.
Live payments, funded recovery and terminal backup validation require human
execution and remain pending until separately evidenced.
