# Experimental SLH wallet commands

`pq-wallet` is off by default. Enable `experimental-slh-dsa-b128s` on
`zakura-pq-cli` to expose the SLH-only Regtest commands below. The default build
accepts help and explicitly refuses wallet operations before reading files or
credentials. The feature does not authorize node activation. Human node and
terminal acceptance are separate gates described in [acceptance](acceptance.md).
The [wallet contract](wallet.md) owns formats, approvals, capacities and recovery.

The CLI reuses the pinned Transparent PQ command, password and RPC modules.
Passwords come only from the controlling terminal with echo disabled; they are
never arguments, environment variables, standard input, public JSON or logs.
Creation and rekey confirm the new password. Other commands prompt once for the
existing backup password. Source mappings and necessary adapters are recorded in
[CLI/RPC provenance](../../crates/pq-wallet/CLI_RPC_PROVENANCE.json).

Run `pq-wallet --help` for exact positional arguments. Every operation starts
with a separately approved canonical profile file. The profile fixes the genesis,
NU7/SLH activation and per-transaction/per-block check allowances; RPC metadata
never approves or enables those gates. Endpoints are numeric loopback socket
addresses such as `127.0.0.1:18232` or `[::1]:18232`, without an HTTP URL. The
operator authenticates the local node and its configuration; remote nodes require
an authenticated local tunnel. Transport uses bounded HTTP/1.0 close framing,
rejects unsupported framing/server failures and obtains exact UTXO amounts from
confirmed block bytes checked against block hashes and transaction Merkle roots.

| Family | Implemented commands |
| --- | --- |
| Keys and encrypted backup | `create-slh-exp`, `inspect`, `pubkey`, `rekey` |
| Backed-up inventory | `extend`, `key-export`, `enroll-prepare`, `enroll`, `export` |
| Watch-only discovery | `watch-create`, `watch-import`, `receive`, `sync`, `status` |
| Independent payment approval | `propose`, `propose-preview`, `review`, `change-approve`, `sign` |
| Exchange and broadcast | `assemble`, `submit`, `payments`, `payment-export` |
| Durable history | `payment-archive`, `payment-resume`, `payment-history`, `payment-history-export` |
| Tip metadata refresh | `refresh-propose`, `refresh-review`, `refresh-approve` |
| Recovery | `restore`, `snapshot-save`, `snapshot-restore` |

Creation writes a verified encrypted backup with empty inventory. `extend`
generates receive/change 1-of-1 entries, then makes the covering backup durable.
`export` emits public inventory. Pair its fingerprint over an authenticated
channel before `watch-create`; choose `monitor` for observation or `allocator`
for the single authorized issuer. A monitor holds no secrets and cannot issue or
sign. A paired allocator can issue only finite generated entries covered by the
backup. Exhaustion requires explicit extend/enrollment, backup, export and import.
Retain an external backup before issuing receivers. `status` is cached confirmed
history, not a claim of current spendability; incomplete history remains explicit.

## Public multisig enrollment

No hand-authored descriptor is required. Every participant first creates its own
wallet and exports its empty/current public inventory. For each next receive or
change policy, participants export their own public key and origin:

```text
pq-wallet key-export profile.json alice.tpq receive 0 alice-key.json
pq-wallet key-export profile.json bob.tpq receive 0 bob-key.json
pq-wallet key-export profile.json carol.tpq receive 0 carol-key.json
```

Each output gives the public exchange and its fingerprint. Authenticate these
fingerprints through a separate channel; a fingerprint copied beside an untrusted
key file does not authenticate its sender. Each cosigner prepares its own
cumulative candidate, naming every key file and authenticated fingerprint:

```text
pq-wallet enroll-prepare profile.json alice-inventory.json receive 2 alice-candidate.json alice-key.json ALICE_KEY_FP bob-key.json BOB_KEY_FP carol-key.json CAROL_KEY_FP
pq-wallet enroll profile.json alice.tpq alice-candidate.json ALICE_CANDIDATE_FP alice-enrolled.tpq
pq-wallet export profile.json alice-enrolled.tpq alice-inventory-next.json
```

Repeat for Bob and Carol against their own inventories and backups. Review the
candidate's suite `247` (`f7`), threshold, complete ordered origin mapping,
participant wallet IDs and approved profile before `enroll`. Policy commitments
are sorted by the existing native policy constructor; the matching origins move
with their commitments. Every enrolled wallet independently regenerates its local
key from its root and verifies its exact sorted slot. Their inventory fingerprints
differ because local wallet/allocator identities differ; matching policy receivers
must agree. Enrollment writes a new covering encrypted backup before making the
candidate usable. An already issued policy is never overwritten.

The same commands accept one through fifteen authenticated participants and any
threshold from one through the participant count, including 15-of-15. Append one
policy per enrollment/backup generation. Use each participant's actual next
cumulative index; indices need not agree across participants. Repeat with `change`
to enroll matching change policies. Payment inputs and change retain the same
threshold and participant set. Every participant approves the full cumulative
inventory; `enroll-prepare` is public construction, not signing approval.

## Payment exchange and retries

The existing command help documents positional intent/proposal/approval-ID paths.
Each cosigner uses its own backup, watch store and authenticated node. `review`
displays full recipient, amount, fee, expiry, suite/policy/origins, approved profile
and local change advancement. Supply its exact approval ID to `sign`; when change
advancement is needed, separately approve the displayed local change ID first.
`propose-preview` exports without reserving when preparing requires that jump.

`sign` durably reserves before signing and writes at most fifteen local partials.
Copy the selected public partials into one collection directory. `assemble`
accepts exactly each input's threshold of distinct signer slots: up to the sum of
approved thresholds, never over 225 files. Every file is at most 16,384 bytes;
indices and proposal IDs are checked and duplicates/subquorums rejected before
primitive verification. A 15-of-15 input requires all fifteen partials. Extra
cosigner files must be removed from the collection explicitly. Proposal and final
transaction bounds remain independent at 262,144 bytes. Receiver/change dust is
2,403 zatoshis; new fees use actual size and marginal fee 400.

Assembly preserves verified signed bytes before submission. `submit` sends only
those exact saved bytes; a transport failure leaves authority intact for retry.
Archiving is bookkeeping and does not revoke partials or free reservations.
`payment-history` pages archived events; `payment-history-export` writes exact
saved proposals, partials and signed transaction hex into a new directory.
Refresh changes tip metadata after renewed approval without changing effects,
expiry or saved authorization bytes. Existing fee approvals are not rewritten.

## Recovery commands

```text
pq-wallet restore profile.json backup.tpq APPROVED_INVENTORY_FP new-directory
pq-wallet snapshot-save profile.json backup.tpq watch-directory new-snapshot
pq-wallet snapshot-restore profile.json new-snapshot new-directory unknown
pq-wallet snapshot-restore profile.json new-snapshot new-directory known TRUSTED_RECEIPT_FP --retired-old-allocators
```

`restore` requires an independently reconciled inventory fingerprint. It restores
keys/inventory, retires covered issuance ranges, rotates allocation, writes
`backup-restored.tpq`, and creates `watch/` in monitor mode. It cannot recover
missing payment authority/history or infer safety from an empty mempool.

`snapshot-save` captures the exact encrypted backup plus coherent watch/journal
under the allocator lock. It outputs the receipt and its fingerprint; retain that
fingerprint through a protected independent channel. The complete artifact set is
`backup.tpq`, `receipt.json` and the complete `watch/` subtree. Journal objects,
including legitimate retained orphans, must remain together.

`snapshot-restore ... unknown` stays monitor-only even after reconciliation or
restart. `known` requires a separately trusted latest receipt fingerprint and an
explicit assertion that every old allocator has stopped. A self-consistent
snapshot does not authenticate completeness or prove no later signature exists.
Known restoration still requires trusted-node reconciliation before payment use;
a source monitor is never promoted. Both modes preserve exact existing authority,
rotate allocation, retire old issuance and publish into a new private directory.
They retain original backup artifacts, write `backup-restored.tpq` using the entered
password, and preserve source files. Use `rekey` afterward for a new password.
Never reuse an existing destination. Snapshot history does not recover signatures
created after capture; receipt authentication and freshness remain human duties.

Focused parser, public enrollment, bounded file collection and scripted loopback
RPC tests run without live nodes or password terminals. They do not establish
terminal behavior, live funded payments, full recovery/discovery or node
acceptance. Those commands are prepared for separate human execution.
