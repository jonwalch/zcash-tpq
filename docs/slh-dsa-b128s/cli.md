# Wallet commands

`pq-wallet` manages SLH wallets on Regtest and approved isolated custom Testnets.
Package `zakura-pq-cli` requires `experimental-slh-dsa-b128s` for wallet operations.
Without that feature, only help is available.
The [acceptance guide](acceptance.md#build-receipts) gives build commands.
Live node and terminal tests remain open.

## Prepare the wallet

Run `pq-wallet --help` for exact arguments.

Passwords come from the controlling terminal with echo disabled.
Arguments, environment variables, and stdin cannot supply passwords.
Creation and rekeying require confirmation of the new password.

Each operation uses an independently approved canonical `profile.json`.
The profile fixes the chain genesis, activation heights, and signature limits.
Check these values against the intended node configuration.
RPC responses cannot approve or enable wallet rules.

Custom Testnet requires `network:1` and `chain_fingerprint`, the 32-byte TPQ node
fingerprint as lowercase hex. It is not a ZDN manifest hash. Regtest requires
`network:2` and no fingerprint field. For example, this is canonical custom
profile JSON (example hashes only; replace them with independently approved values):

```json
{"chain_fingerprint":"3131313131313131313131313131313131313131313131313131313131313131","genesis_hash":"4242424242424242424242424242424242424242424242424242424242424242","max_block_pq_checks":64,"max_tx_pq_checks":16,"network":1,"nu7_activation_height":100,"nu7_branch_id":"77190ad9","pq_activation_height":101}
```

Do not include the code block's final newline in a profile file.
The node's effective fingerprint, genesis, NU7, SLH activation and budgets must
match. Custom Testnet cannot fall back to missing diagnostics or Regtest addresses.

Wallet JSON requires sorted fields and excludes extra fields, whitespace, and a final newline.
The [wallet contract](wallet.md) specifies formats and limits.
A fingerprint identifies exact public data.
Before import, authenticate its fingerprint through a separate trusted channel.

RPC endpoints use numeric loopback addresses, such as `127.0.0.1:18232` or `[::1]:18232`.
They exclude `http://`.
Authenticate the local node and its configuration.
For a remote node, use an authenticated local tunnel.
The adapter checks block hashes, transaction inclusion, amounts, and unspent outputs.
Its bounded HTTP transport rejects unsupported framing and server failures.

Select cookie authentication explicitly with a global option before the command:

```text
pq-wallet --json --rpc-cookie /trusted/private/node/.cookie sync profile.json watch-directory 127.0.0.1:18232 100
pq-wallet --json receive profile.json watch-directory
pq-wallet --json --rpc-cookie /trusted/private/node/.cookie submit profile.json backup.tpq watch-directory 127.0.0.1:18232 APPROVED_PROPOSAL_ID
```

The cookie option names a file, not a credential. Never pass a cookie or password
in argv. The adapter reopens the cookie for each request, so atomic node cookie
rotation works. It requires a regular owner-only file owned by the current user.
It rejects final symlinks, directories, oversized files and control characters.
Parent directories must be trusted and stable. Authentication failures do not
retry without credentials. Cookie transport is supported on Unix only.
The CLI requires a cookie for custom Testnet RPC. Trusted local legacy Regtest
can still use unauthenticated RPC when the option is absent.

Use `--json` before the command for machine output. Existing structured command
results remain structured; scalar receivers, transaction IDs and publication
messages become JSON objects. `inspect` emits only its canonical inventory,
without the human explanation. Errors are JSON objects on stderr with nonzero
exit status. Passwords still require `/dev/tty`, with echo disabled, including
in machine mode. Neither stdin nor environment variables supply passwords.
Help remains human-readable. A successful command does not replace journal
reconciliation or independently authenticated approvals.

## Commands

| Task | Commands |
| --- | --- |
| Keys and encrypted backup | `create-slh-exp`, `inspect`, `pubkey`, `rekey` |
| Address inventory | `extend`, `key-export`, `enroll-prepare`, `enroll`, `export` |
| Watch-only discovery | `watch-create`, `watch-import`, `receive`, `sync`, `status` |
| Payment approval | `propose`, `propose-preview`, `review`, `change-approve`, `sign` |
| Signature exchange and broadcast | `assemble`, `submit`, `payments`, `payment-export` |
| Saved payment history | `payment-archive`, `payment-resume`, `payment-history`, `payment-history-export` |
| Refresh chain-tip metadata | `refresh-propose`, `refresh-review`, `refresh-approve` |
| Recovery | `restore`, `snapshot-save`, `snapshot-restore` |

Creation saves an encrypted backup without addresses.
For a single-key wallet, `extend` generates receive/change entries and saves a covering backup.
`export` writes the public inventory.
Before `watch-create`, keep an external backup and authenticate the inventory fingerprint.

A `monitor` observes public inventory. It cannot issue addresses, sign, or submit payments.
An `allocator` issues addresses and manages payments.
Only one store can act as allocator.
It can issue only generated entries covered by a backup.
After exhaustion, generate and enroll more entries.
Then save a backup, export the inventory, and import it into the watch store.

`status` reports cached confirmed history and identifies incomplete history.
It does not guarantee current spendability.

## Enroll a multisig policy

Each participant needs a wallet and its exported public inventory.
For each new policy, export each participant's own key and origin:

```text
pq-wallet key-export profile.json alice.tpq receive 0 alice-key.json
pq-wallet key-export profile.json bob.tpq receive 0 bob-key.json
pq-wallet key-export profile.json carol.tpq receive 0 carol-key.json
```

Authenticate each key fingerprint separately.
For each cosigner, prepare a cumulative inventory with all participant files and trusted fingerprints:

```text
pq-wallet enroll-prepare profile.json alice-inventory.json receive 2 alice-candidate.json alice-key.json ALICE_KEY_FP bob-key.json BOB_KEY_FP carol-key.json CAROL_KEY_FP
pq-wallet enroll profile.json alice.tpq alice-candidate.json ALICE_CANDIDATE_FP alice-enrolled.tpq
pq-wallet export profile.json alice-enrolled.tpq alice-inventory-next.json
```

Repeat the procedure for Bob and Carol with their own files.
Before enrollment, check suite `247` (`f7`), threshold, participants, origins, and profile.

The wallet sorts commitments with their origins.
It regenerates its local key to check the position.
Participant inventories have different fingerprints, but the shared policy must produce the same receive address.
Enrollment saves the covering backup first. It cannot overwrite an issued policy.

A policy permits one through fifteen participants and any threshold up to that count.
Each enrollment adds one policy.
Use each participant's next cumulative index. These indices need not match.
Repeat with `change` for matching change policies.
Payment inputs and change must share the threshold and participant set.
Inventory preparation does not approve a payment.

## Approve and exchange a payment

Each cosigner uses its own backup, watch store, and authenticated node.
`review` shows the recipient, amount, fee, expiry, policy, origins, profile, and any change-index advance.
Supply the complete approval ID to `sign`.
If requested, use `change-approve` separately.
`propose-preview` can export a proposal before change approval without input reservations.

`sign` saves input/change reservations before signing.
It writes at most fifteen local partials.
For `assemble`, collect exactly the threshold of distinct signer slots for each input.
Remove extra files explicitly.
The file count cannot exceed the threshold sum or 225.
Each partial has a 16 KiB limit.
Duplicates, wrong proposal IDs, and insufficient signatures fail before cryptographic verification.
Proposals and final transactions each have a separate 256 KiB limit.

New fees use actual sizes and a 400-zatoshi marginal fee.
SLH receive and change outputs have a 2,403-zatoshi dust floor.
Existing fee approvals remain unchanged.
Assembly saves the verified transaction before submission.
`submit` and retries use those exact bytes.

Archive operations do not revoke signatures or release reservations.
History exports retain proposals, partials, and signed transactions.
Tip refresh requires renewed approval.
It preserves transaction effects, expiry, and signed bytes.

## Recovery commands

```text
pq-wallet restore profile.json backup.tpq APPROVED_INVENTORY_FP new-directory
pq-wallet snapshot-save profile.json backup.tpq watch-directory new-snapshot
pq-wallet snapshot-restore profile.json new-snapshot new-directory unknown
pq-wallet snapshot-restore profile.json new-snapshot new-directory known TRUSTED_RECEIPT_FP --retired-old-allocators
```

`restore` recovers keys and inventory into a monitor.
`snapshot-save` also retains known payment state and journal history.
Protect the receipt fingerprint through an independent channel.

An `unknown` snapshot restore stays monitor-only.
A `known` restore requires the trusted latest receipt and retirement of all old allocators.
A source monitor always restores a monitor.
Payments still require synchronization with a trusted node.

Each restore needs a new private destination.
It retains the original backup and writes `backup-restored.tpq`.
It retires old address ranges but retains their scan coverage.
To change the password after restore, use `rekey`.
The [recovery guide](recovery.md) specifies all files, trust requirements, and failure behavior.

Focused tests cover parsers, enrollment, and mocked RPC.
[CLI/RPC provenance](../../crates/pq-wallet/CLI_RPC_PROVENANCE.json) records source mappings.
The [acceptance guide](acceptance.md) lists live and terminal tests.
