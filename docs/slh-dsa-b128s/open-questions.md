# Open questions

This page tracks unresolved ecosystem decisions for public adoption of SLH-protected transparent funds.
Existing Zcash rules are the baseline. Each entry identifies a choice added by SLH.
Keep prototype operation and wallet implementation details in the component guides.
The [validation guide](validation.md) tracks evidence and tests that still need execution.
Sources and ZIP status were checked on 2026-10-10.

## F1: SLH fee policy

Status: Open.

[ZIP 317](https://zips.z.cash/zip-0317) already charges transparent inputs and outputs by serialized size.
Larger SLH authorizations therefore incur more actions under the existing formula.
The [fee comparison](relay-mining.md#fee-policy-discussion) records this effect and the public fee proposals.

Do measured SLH costs justify a change to this transparent fee accounting?
If so, which SLH-specific rule should wallets, relay nodes, and miners adopt?

Compare verification, bandwidth, and storage costs with fees under the existing rule.
Assess small payments and multisig spending under both the baseline and any proposed change.
Any change needs evidence that it preserves resistance to denial-of-service attacks.
The prototype's rate and dust floor are implementation settings, not proposed ecosystem defaults.

## S1: Security target and key use

Status: Open.

The [proposed construction](protocol.md#source-and-signature-primitive) uses BLAKE3 signatures
and SHA-256 key and policy commitments.
It retains the BLAKE2b-256 transaction digests defined for v5 by [ZIP 244](https://zips.z.cash/zip-0244).
The BLAKE3 signature construction is experimental and is not a FIPS 205 profile.

What quantum security target and protection period must this complete authorization meet?
What per-key signing limits and key-rotation assumptions can the ecosystem rely on?
Does the combined signature, digest, and commitment construction meet that target?

Include use across outputs and devices, replacement signatures, and released partials.
Review risks across many keys and the guarantees required when a cosigner acts maliciously.
Public adoption needs independent construction and implementation review.
Agreement between implementations does not establish these security claims.

## S2: Public SLH signing modes

Status: Open for public adoption.

[ZIP 244](https://zips.z.cash/zip-0244) already defines `SIGHASH_ALL`, `SIGHASH_NONE`,
and `SIGHASH_SINGLE`, each with or without `ANYONECANPAY`, for transparent v5 inputs.
Their signed fields and exclusions are specified behavior.
The [prototype contract](protocol.md#byte-contract) permits only `SIGHASH_ALL` without `ANYONECANPAY`.

Should public SLH preserve the existing transparent signing modes or deliberately restrict them?
What SLH-specific security benefit would justify a restriction, and which existing uses would it prevent?

Resolve this compatibility choice before standardizing the public SLH authorization format.
Use the existing digest semantics for retained modes.

## D1: Public SLH resource limits

Status: Open.

Zcash already has transaction, block, and signature-operation limits in its
[protocol specification](https://zips.z.cash/protocol/protocol.pdf).
[ZIP 200](https://zips.z.cash/zip-0200) defines network-upgrade activation and replay protection.

Which additional consensus limits should apply to SLH verification per transaction and block?
Which limits permit useful multisig payments while keeping full-node operation practical?

Evaluate mixed SLH, classical, and shielded work under the existing block rules.
Use adversarial whole-node measurements across implementations and representative hardware.
Include the added bandwidth, historical storage, and synchronization costs of SLH authorizations.
Select public limits through the existing network-upgrade process.
The prototype's 16-check and 64-check settings do not select those limits.

## I1: SLH receiver standard

Status: Open.

[ZIP 316](https://zips.z.cash/zip-0316) supplies Unified Addresses and receiver-selection rules.
[ZIP 321](https://zips.z.cash/zip-0321) supplies payment-request URIs that can contain Unified Addresses.
These are the interoperability baseline; ZIP 316 revision 2 remains a draft.

Which SLH receiver encoding, type code, and selection priority should the ecosystem standardize?
How should a recipient require SLH protection when an address also offers other receiver types?

Resolve SLH selection together with the existing privacy and unsupported-receiver rules.
A request for SLH protection must not silently become a payment using another authorization scheme.
The [experimental receiver](wallet.md#receivers-and-transport) is not a public allocation.

## M1: Migration, retirement, and legacy recovery

Status: Open.

Ordinary migration can use existing ECDSA authorization while it remains secure.
The [current coinbase rule](https://zips.z.cash/protocol/protocol.pdf#txnconsensus)
requires transactions that spend transparent coinbase outputs to have no transparent outputs.
Such funds therefore need a shielded step before another transparent payment under existing rules.

What cutoff and notice period should apply to ordinary ECDSA spending?
Should creation of new classical outputs stop? If so, when?
Which ownership evidence and PQ-safe recovery construction should admit preserved funds?
Should the PQ transition retain the shielded route for coinbase funds or specify a different route?
How should a later replacement of SLH preserve ownership and historical validation?

This project's proposed direction is ordinary migration, then an announced ECDSA cutoff,
with remaining UTXOs preserved for a separately specified recovery path.
Public adoption, eligibility, and activation remain open.
Preservation does not guarantee recovery; funds without sufficient evidence remain frozen.
[ZIP 2007](https://zips.z.cash/zip-2007) remains Reserved and does not specify an adopted recovery protocol.

Evaluate the coinbase route against the agreed quantum security target, including shielded-pool assumptions.
The open decision is whether the PQ transition needs to change that route.
The existing restriction and the prototype wallet's payment scope are already specified behavior.

## Record a decision

For each new entry, state the existing Zcash baseline and the unresolved SLH change.
Keep a question here only if existing rules cannot settle that change.
When a question is resolved, record the ecosystem decision and its reason.
Update the affected guide and mark the question as resolved here.
