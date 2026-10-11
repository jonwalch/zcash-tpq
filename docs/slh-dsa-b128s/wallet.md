# Wallet contract

This document specifies the wallet contract dated 2026-10-09.
The wallet, payment, recovery, and CLI code implement this contract.
Live node and terminal tests remain open.
The [protocol](protocol.md) specifies consensus bytes and `slh-dsa-b-128s-exp-v1`.
The wallet requires Regtest and `experimental-slh-dsa-b128s`, which is off by default.

The implementation reuses canonical JSON, HKDF derivation, enrollment,
approval, encryption, reservations, and journals from the Transparent PQ wallet.
The adaptations cover SLH identity, lengths, policy capacity, and operational recovery.
Only suite `f7` is accepted.
Other-suite backups, proposals, and partials produce errors. The wallet does not convert them.
An unavailable feature produces an unsupported-operation error.

## Root and key derivation

The wallet uses a uniformly generated 32-byte root.
The root, wallet ID, and allocator ID each require a separate fallible OS entropy request.
The two IDs have 16 bytes each.
An entropy failure issues no receiver.
Account is always zero. Receive role is `00`. Change role is `01`.
The index is an unsigned 32-bit integer. Exhaustion never wraps the index.
There is no public child derivation or xpub.

The derivation version and domains remain unchanged.
Each ASCII literal below includes one final zero byte:

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

HKDF-SHA256 produces 48 bytes through two expansion blocks.
It does not pad or repeat a 32-byte seed.
Restore reconstructs each local public root and key commitment.
It checks each commitment against its sorted position in the inventory.
Independent [wallet vectors](../../tests/slh-dsa-b128s/wallet/README.md)
cover both blocks, full public keys, roles, and index boundaries.

## Signer and approval

The separate signer crate uses safe Rust and a fixed profile.
It accepts owned seed material with memory clearing.
Secrets have no `Debug`, `Clone`, or serialization implementation.
The signer applies Pure framing once to the 101-byte message with empty context.
Each operational signature requires 16 fresh bytes from fallible entropy.
Local primitive verification must succeed before the signer returns a partial.
An entropy or verification failure returns no partial.
There is no deterministic fallback for operational signatures.

Prescribed randomness and fault injection are private unit-test code only.
The initial signer is serial and has no cache.
The [signer README](../../crates/pq-slh-dsa-b-sign/README.md#clearing-scope)
states memory-clearing limits, including HKDF/HMAC internal state.

Before signing, the wallet reconstructs trusted transaction context and approves the effects.
The native crate supplies verifier-only `InputSigningContext`, partial verification, and canonical assembly.
Neither the native crate nor the node depends on a signer.
Only feature-enabled wallet builds can include the signer.

## Receivers and transport

The receiver uses Bech32m, HRP `tpqreg`, and 69 lowercase characters.
Its 35-byte payload is `01 || 02 || f7 || policy_commitment`.
The output script is `53 || 20 || policy_commitment || c0`.
The decoder rejects other HRPs, checksums, case, lengths, suites, and noncanonical encodings.
This experimental prefix is not an assigned Unified Address receiver.

Canonical JSON has these requirements:

- Printable ASCII, without escapes, whitespace, or a final newline.
- Sorted object fields, without duplicate or unknown fields.
- Unsigned integers in the shortest decimal form.
- Null only where the schema permits it.
- A maximum depth of 16.

Readers check byte and collection limits before expensive work.
They reject invalid encodings instead of normalizing them.
Inventory, recovery, and proposal envelopes retain version 1 and the existing field meanings.
The suite byte selects the 48-byte derivation.
It cannot reinterpret an object from another suite.

A partial uses `ZcashTransparentPQ/experimental/slh-dsa-b-128s/partial/v1`.
Its fields occur in this order:

| Field | Encoding |
| --- | --- |
| `format` | Exact format string above |
| `input_index` | Unsigned integer 0–14, validated against approved inputs |
| `proposal_id` | 64 lowercase hex characters |
| `public_key_hex` | 64 lowercase hex characters |
| `signature_hex` | 15,712 lowercase hex characters |
| `signer_index` | Unsigned integer 0–14, validated against the enrolled policy |

## Policies and payments

The wallet supports all 120 policies with `1 <= m <= n <= 15`.
Each sorted commitment has one origin, with account zero, a u32 index, and a distinct participant wallet ID.
Each cosigner approves the threshold, participants, and origin mapping.
Enrollment, address issuance, change selection, and signing check actual sizes and both approved check limits.
Incompatible old history remains readable for recovery and scans.

All payment inputs and change must share a threshold and participant wallet-ID set.
Their policies must use the same suite.
The node's fixtures with different policies do not change this wallet rule.
Payments use transparent-only v5/v6 transactions on NU7, final sequences, and zero lock time.
They have one recipient, optional change, and a 20-block expiry horizon.
Profile and recipient activation require independent approval.
RPC metadata cannot authorize activation.
Classical funding tools do not add a classical-key wallet to this extension.

## Capacity limits

Each limit applies independently. Some combinations cannot fit all limits.
The wallet counts canonical bytes before allocation or publication.
A change in the SLH size allowance alone does not change schema versions.
Errors distinguish encoding, size, context, policy, and approval failures.

| Item | Frozen allowance and required enforcement |
| --- | --- |
| Per-input authorization | Canonical maximum 118,882 bytes. Native guard 131,072. Validate push/index/policy encoding before crypto |
| Partial | 16,001 bytes at indices 14/14, including JSON. Cap 16,384 for encode/decode, CLI files and saved local partials |
| Final transaction | Cap 262,144 bytes. Apply to serialization, RPC hex bounds, review, final assembly, history/retry and snapshot reads |
| Proposal | 262,144 bytes and 15 inputs. Unsigned transaction has empty authorizations. At most two outputs. Origins bounded at 15 before allocation |
| Assembly input files | At most the sum of approved thresholds, never over 225. Reject excess and duplicate slots before verification |
| Saved local partials | At most 15, one local signature per input. Do not reinterpret this as every cosigner's signatures |
| Inventory/recovery/transfer | 4,096 entries and 8,388,608 bytes independently. Preflight exact canonical envelope size before enrollment/export |
| Encrypted root backup | Existing 56-byte header plus bounded plaintext plus 16-byte authentication tag. No journal in this envelope |
| Journal capability | 1,048,576 bytes, count the complete object including proposal, local partials, final hex transaction and metadata |
| Watch state | Version 2 has a 33,554,432-byte limit. Version 3 retains a 16,384-byte metadata allowance. |
| Journal commit/quota | 67,108,864-byte commit cap, object/count limits and configured quota. Retained generations consume quota separately |

An entry with 15 origins at maximum u32 indices has 2,206 canonical bytes.
An array of 4,096 such entries has 9,039,873 bytes before the envelope.
Thus, the entry count does not guarantee capacity within 8 MiB.
Exact byte counts determine the smaller capacity.
Journal objects and retained history also consume independent limits.
Recovery must not load the full journal into one buffer.

The following sizes include a recipient and change, each with a 35-byte script.
They exclude shielded data and use exact CompactSize widths.
A 15-of-15 authorization needs a five-byte CompactSize length.

| Inputs/policy | Checks | v5 bytes | v6 bytes | Initial 16-check profile |
| --- | ---: | ---: | ---: | --- |
| One 1-of-1 | 1 | 8,086 | 8,087 | Fits |
| One 15-of-15 | 15 | 119,040 | 119,041 | Fits |
| Eight 2-of-3 | 16 | 127,561 | 127,562 | Exact check boundary |
| Nine 2-of-3 | 18 | 143,492 | 143,493 | Reject check limit, not byte limit |
| Two 15-of-15 | 30 | 237,967 | 237,968 | Reject check limit, not byte limit |

Wallet fees use actual sizes and Zakura's marginal fee of 400 zatoshis per action.
The [fee policy discussion](relay-mining.md#fee-policy-discussion) compares this
rate with the ZIPs and lists open choices for deployment beyond Regtest.
The SLH recipient and change dust floor is 2,403 zatoshis.
Boundary tests use 2,402, 2,403, and 2,404.
Stored fee approvals remain unchanged.
The 16-check transaction and 64-check block limits are test settings.

## Recovery and watch-only behavior

The wallet retains encrypted backups, private durable publication, exact saved authorizations,
monotonic retirement and cursors, and one allocator.
A monitor holds public inventory. It cannot sign or allocate addresses.
A paired allocator issues only generated entries covered by a durable backup.
Inventory exhaustion requires more generation, enrollment, backup, and public inventory import.

Key/inventory restore reconstructs commitments and checks the latest available backup.
It retires old address ranges but retains their scan coverage.
It replaces the allocator identity and restores a monitor.
A key backup cannot establish complete payment history or all outstanding signatures.

An operational snapshot includes the matching encrypted backup, watch state, and immutable journal.
Capture requires the allocator lock or a clean close.
The receipt binds the backup hash, wallet, suite, profile, inventory, and generation.
The [recovery guide](recovery.md) specifies files, trusted receipt requirements, and restore modes.
A consistent set of files alone cannot prove that no signatures are missing.
An empty mempool does not resolve unknown outstanding signatures.
A snapshot cannot recover later signatures or prove that another allocator stopped.

Restore copies objects with bounded buffers and retains valid orphan and temporary journal files.
Existing quota rules still apply.
The existing readers check all reachable objects.
Missing, truncated, mismatched, or unsafe paths cause rejection.
Restore stages the files and atomically publishes a new private directory.
It preserves reservations and exact saved bytes.
A final directory-sync failure can report an error after publication.

Imported observations remain cached until synchronization with a trusted node.
Incomplete, pruned, or unavailable history cannot become a current zero balance.
Historical reads and migrations remain explicit and recoverable.
The snapshot does not introduce a new encrypted journal container.

Focused tests cover derivation, signatures, formats, policy shapes, approvals, backups,
corruption, stale snapshots, unknown authority, and dependency graphs.
Live payments, funded recovery, and terminal tests remain pending.
Agents must obtain user approval before these runs under [AGENTS.md](../../AGENTS.md).
