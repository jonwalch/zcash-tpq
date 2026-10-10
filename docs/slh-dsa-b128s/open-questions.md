# Open questions

This page tracks unresolved choices for the SLH extension.
These choices concern deployment beyond the current Regtest scope.
The [protocol](protocol.md) and component guides describe the implemented rules.
The [validation guide](validation.md) tracks evidence and tests that still need execution.

## F1: Fees beyond Regtest

Status: Open.

Which fee rate should apply beyond Regtest?
Should SLH have a separate fee adjustment for its resource costs?

The implementation uses Zakura's 400-zatoshi rate and ZIP-317 action counts.
It applies no SLH fee discount or surcharge.
The [fee policy discussion](relay-mining.md#fee-policy-discussion) compares the ZIPs,
shows the effect of SLH signature sizes, and lists the required decisions.
Those decisions need cost evidence and a review of wallet and node compatibility.
The current Regtest fees do not establish a production fee policy.

## S1: Security target and key use

Status: Open.

What security target and protection period must the exact BLAKE3 construction meet?
What limits on signatures per key and what key-rotation rules are required?
Include use across outputs and devices, replacement signatures, and released partials.

The [construction and parameters](protocol.md#source-and-signature-primitive) are fixed for this experiment.
Independent implementation checks do not establish the construction's security.
Select the required independent review of quantum assumptions and signer behavior.
That review must cover each supported platform, including side channels and secret handling.
The [signer guide](../../crates/pq-slh-dsa-b-sign/README.md#clearing-scope) records current limits.

## S2: Signing modes and message format

Status: Current Regtest contract fixed. Future extensions open.

The current [v5/v6 contract](protocol.md#byte-contract) permits only `SIGHASH_ALL`,
with `ANYONECANPAY` disabled.
It commits to all inputs and outputs, including trusted input amounts and scripts.
The signing message also binds the signature suite, network, transaction version,
upgrade branch, and input index.

The authorization carries no selectable signing mode or sighash suffix.

Before extending this contract, resolve these questions:

- Should future versions remain `SIGHASH_ALL` only?
- Which use case would justify `SIGHASH_SINGLE`, `SIGHASH_NONE`, or `ANYONECANPAY`?
- What must each signer approve when some inputs or outputs can change?
- How would new modes or message formats be versioned and activated?

Specify the exact signed fields and intentional exclusions for each transaction version.
`SIGHASH_ALL` does not mean every serialized byte is signed.

## D1: Public activation and resource limits

Status: Open.

What evidence and deployment process are required before public activation?
Which transaction and block limits should apply?
Which hardware, queue, memory, and verification-concurrency limits must nodes support?

The [runtime](runtime.md#configure-regtest) rejects SLH settings on public networks.
The 16-check transaction and 64-check block settings are functional test values.
Choose deployment limits from whole-node measurements, including hostile and cancelled work.
Review the activation height, upgrade context, checkpoints, and state compatibility together.
The [validation guide](validation.md) remains the record of evidence and pending tests.

## I1: Receiver and payment interoperability

Status: Open.

Which public address and payment-request formats should carry SLH receivers?
How should other wallets identify support and authenticate the requested recipient?

The current [receiver](wallet.md#receivers-and-transport) uses the experimental `tpqreg` prefix.
It is not an assigned Unified Address receiver.
A checksum checks the encoding; it does not authenticate the recipient.
Specify identifiers, sender behavior for unsupported receivers, and payment-request authentication.
The existing [independent payment review](cli.md#approve-and-exchange-a-payment) remains required.

## M1: Migration, retirement, and legacy recovery

Status: Open.

What cutoff height and notice period should apply to ordinary ECDSA spending?
When should creation of new classical outputs stop?
Which ownership evidence and PQ-safe recovery construction should admit preserved funds?
How should a later signature-suite change preserve ownership and historical validation?

The agreed direction is ordinary migration, followed by an announced ECDSA cutoff.
Preserve remaining UTXOs for a separately specified recovery path.
Preservation does not guarantee recovery; funds without sufficient evidence remain frozen.
Cutoff details and the recovery construction still need a separate specification and activation.

The current [migration path](protocol.md#network-and-state-rules) uses classical authorization to fund SLH outputs.
Later SLH spends require SLH authorization.
The Regtest implementation has no public ECDSA cutoff or legacy-recovery protocol.
It rejects mixed classical and SLH transparent inputs.
Classical and SLH outputs retain separate authorization rules.

## H1: History availability and recovery support

Status: Open.

What history must remain available to a wallet that returns after a long absence?
Who provides that history if a node prunes transaction bodies?
What backup retention and rescan support should users be able to rely on?

Distinguish the UTXO set, historical transactions, and private wallet journals.
The [recovery formats](recovery.md#backup-types) preserve different parts of wallet state.
A key backup cannot reconstruct unknown signatures or complete payment history.
The [wallet](wallet.md#recovery-and-watch-only-behavior) keeps observations cached until trusted synchronization.
Unknown signing authority keeps a restore in monitor-only mode.
Define a supported history and backup policy before promising long-term recovery.

## Record a decision

When a question is resolved, record the decision and its reason.
Update the affected guide and mark the question as resolved here.
