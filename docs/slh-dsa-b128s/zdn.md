# TPQ tools with a ZDN-managed connection

This guide separates local wallet authority from node administration. It describes
the optional TPQ integration, not built-in TPQ support in ordinary ZDN installs.
The adapter, gateway and managed-identity changes are local development work.
The published ZDN Preview 4 does not provide a complete TPQ deployment path.
Offline checks do not qualify live deployment, payments or recovery.

Do not run a live journey merely to follow this guide. Use a separately approved,
bounded test scope. Never bypass a ZDN refusal with direct cloud writes or edit
its saved packages to make an unsupported deployment appear compatible.

## Keep tools and authority separate

| Process | Inputs and authority |
| --- | --- |
| ZDN controller | Cloud lifecycle, immutable package and image pins, operation journals, managed connections and cleanup |
| `zdn-tpq-adapter` | Pinned public chain/profile/block inputs; pure `describe`, `compile` and `render`; no RPC or signing |
| Node | Own durable native key, state, private cookie and consensus verifier |
| `tpq-devnet` on the operator's machine | Native preparation and explicitly reviewed one-time classical seed funding |
| `pq-wallet` on each participant's machine | Encrypted roots, one allocator, approvals, saved signed bytes and wallet journals |

Build the public-input adapter separately from the default wallet-enabled tool:

```sh
cargo build --release --locked -p zakura-tpq-devnet --no-default-features \
  --features adapter --bin zdn-tpq-adapter --bin zdn-tpq-import
```

Do not package a host adapter with its `wallet` feature. That combination refuses
protocol operations; only the no-default `adapter` graph excludes signing.
Use the release artifact, not an unstripped debug executable, which can exceed
the 128 MiB host-artifact bound. Any stripping or other post-processing changes
the bytes and must precede executable hashing and package creation.
Record the source revision, compiler, executable SHA-256, byte count,
platform and supported protocol. A digest identifies bytes, not their publisher.
Host and controller artifacts can have different platform-specific pins; their
compiled public results must agree exactly. Do not ship local signing tools to
the host as the public-input adapter.

Use the existing [preparation and funding guide](devnet.md). Preserve the exact
native network name and fingerprint. Keep `funder.json` outside every public
artifact directory. Convert only explicitly named public files; never upload a
preparation directory recursively. Authenticate the canonical wallet profile
through an independent approved channel.

The public importer accepts absolute paths to those two public files and the
separately reviewed Linux host executable. Supply its approved SHA-256, the
operator-approved selection SHA-256, and the exact source commit. The output
directory must not exist:

```sh
target/release/zdn-tpq-import "$CHAIN" "$PROFILE" "$HOST_ADAPTER" \
  "$HOST_ADAPTER_SHA256" "$ADAPTER_SELECTION_SHA256" "$SOURCE_REVISION" \
  "$NEW_PUBLIC_PACKAGE_DIR"
```

This exports only fixed public slots and prints the resulting package pin.
It does not install or run the supplied host artifact, authenticate its publisher,
grant ZDN execution trust, or launch a deployment. Source identity fields are
declarations; retain independent source/build receipts and review both executable
and package pins before selecting them. Do not label a dirty development tree
with its base commit as if that commit contained the new source.

## Native identity and RPC boundary

The managed native key belongs in a private persistent directory outside chain
snapshots. Before final peer rendering, the node identity command ensures the
key and returns public metadata only:

```sh
zakurad --config node.toml native-identity --identity-dir /srv/tpq/identity
```

The parent directory must already be trusted and stable. The output schema is
`zakura-native-identity/v1`, with `nodeId` and `chainFingerprint`. Pin the public
ID as `network.zakura.expected_node_id` in the final node configuration. With
that pin, missing, corrupt, unsafe or mismatched private key storage refuses;
startup does not silently create a replacement. Provisioning is not a live
native-peer or restart qualification. Ordinary unpinned nodes retain their
existing behavior. Never collect the private key into a peer inventory.

Native peers use private cohort-scoped UDP and explicit `NodeId@IP:port`
endpoints. Legacy TCP access alone does not enable QUIC. RPC stays authenticated
on host loopback. Participants use the restricted gateway, not the administrator
cookie. Readiness must check fresh full effective rules and history, not just
an open socket or matching genesis.

## Connect in one terminal, use the wallet in another

Keep the supported ZDN connection running in terminal A. For an invited
participant, use your own local AWS login and a reviewed credential-free endpoint
file:

```sh
zdn connect --endpoints endpoints.json --aws-profile participant
```

In terminal B, set the numeric loopback socket from the printed RPC URL. The
wallet accepts `127.0.0.1:PORT` or `[::1]:PORT`, not the URL, DNS or a remote
address. Check the endpoint and approved profile before selecting gateway mode:

```sh
pq-wallet --trusted-local-gateway sync "$PROFILE" "$STORE" "$RPC_SOCKET" 256
pq-wallet status "$PROFILE" "$STORE"
```

`--trusted-local-gateway` and `--rpc-cookie FILE` are mutually exclusive global
options before the command. Gateway mode sends no node credentials. It trusts
the explicitly established local service, not every process on loopback. It
does not disable the wallet's approved profile and effective-rule checks.
Authentication failure never selects gateway mode automatically. Direct private
cookie mode remains available to authorized local operators.

Use a normal controlling terminal for passwords. Do not put passwords in argv,
environment, JSON, scripts or ZDN journals. Do not put interactive wallet commands
under `zdn exec`: its child has closed stdin and a separate session, while wallet
passwords use `/dev/tty`. Ctrl-C in terminal A closes the managed connection,
not the deployment. Reconnect explicitly, then reconcile the original wallet
records; reconnecting is not permission to repeat a payment blindly.

## Bootstrap and fund once

Use the ZDN administrative lifecycle for saved-history installation and production.
Participant gateways must not gain `submitblock`, `getchainrules`,
`inspectchainblock` or mining authority to make bootstrap convenient.
The standalone `tpq-devnet bootstrap` command remains direct-cookie-only.

The seed recipe ends at 101; NU7 is at 102 and SLH at 103. Produce the required
transition through the supported operator path, stop production and establish a
stable tip before funding. Retain the native 100-block coinbase maturity.
Review the destination, amount, fee, change, expiry, txid and transaction hash.
The seed funder can use the restricted gateway because it needs only participant
methods:

```sh
tpq-devnet fund-draft "$CHAIN" "$RPC_SOCKET" --trusted-local-gateway \
  "$FUNDER" "$REVIEW" "$RECEIVER" 100000000 10000
tpq-devnet fund-submit "$CHAIN" "$RPC_SOCKET" --trusted-local-gateway \
  "$REVIEW" "$APPROVED_TRANSACTION_SHA256"
```

The second command requires independent explicit review of the first command's
saved transaction. Never approve a value by blindly piping draft output back
into submission. Retain the saved bytes after an uncertain reply; reconcile
them through the same review file. This tool spends one known seed outpoint,
not arbitrary classical change. Fund a local PQ treasury once, then use normal
PQ wallet payments. There is no cloud faucet, cloud wallet or PQ mining payout.

## Payments, uncertainty and recovery

Use the wallet's existing `propose` → `review` → explicit approval → `sign` →
`assemble` → `submit` flow. The canonical independent intent selects version 5
or 6, amount, receiver, maximum fee and remainder handling. Pass the same global
gateway option to every command that uses RPC. Never substitute a second
companion payment journal for the wallet's authoritative records.

After a lost reply, reconcile the original proposal and exact signed bytes.
Do not create a replacement intent to resolve an unknown submission. Verify both
sender and recipient against authenticated blocks and actual spent outpoints;
a returned transaction ID alone is not a completed payment oracle.

Follow [wallet recovery](recovery.md). Keep the latest snapshot receipt through
an independent trusted channel and retire old allocators before known-authority
restore. Unknown-authority and inventory-only restores remain monitor-only.
After restoring, reconcile history and original payments before signing again.
A live recovery qualification must include a **new** successful payment from
the restored state, not only a readable balance. None of those live steps is
credited by offline transport or adapter tests.

Raw block and transaction hex have a finite 40,100,000-byte transport class for
exact nonverbose operations. Metadata and verbose client responses retain 2 MiB
limits; headers, timeouts and wallet transaction limits remain finite. This is
not unlimited RPC or a promise of maximum-size verbose block JSON support.

## Reusable full-journey qualification

The optional [qualification coordinator](../../tests/slh-dsa-b128s/acceptance/zdn_flow.py)
implements an explicit ordered journey. It is not a wallet, shell task runner or
cloud control plane. It dispatches only pinned ZDN `devnet up`, `health`,
`update` and `destroy` commands. All wallet operations and fault injections stop
at human-review gates. No live journey has run with this coordinator.

The [case manifest](../../tests/slh-dsa-b128s/acceptance/zdn_cases.json) names each
TPQ subcase and negative control. Its reference is **ZDN beta plan v1.0,
2026-10-23**, document SHA-256
`20bc7e52be2df2d78706d5e4c453bfa91e42feefcad83d550c5a1abc31a499d2`.
These are selected subcases, not complete beta-case passes:

| TPQ scenario | Beta reference | Required observation; all live results pending |
| --- | --- | --- |
| `TPQ-SOURCE` | `SRC-03` | Prepared/imported public artifacts, exact source/build/features and platform tool pins |
| `TPQ-DEPLOY` | `DEP-02` | ZDN external lifecycle, seed bootstrap, transitions and strict readiness |
| `TPQ-NATIVE` | `NET-01/03/04` | Native UDP, empty/lagging peer sync, relay, retained node/key and rotated cookie |
| `TPQ-PAY` | `PAY-01/02/03` | One funding, v5 Alice→Bob, v6 Bob→Alice spending the actual received outpoint |
| `TPQ-RECOVER` | `REC-03`, `PAY-03` | Original uncertain payment, exact-byte retry, trusted restore, then a new confirmed payment |
| `TPQ-CLEAN` | `CLN-01` | Revocation, managed destroy without installed local TPQ tools, residual/secret audit |

This does not extend the beta plan's clean-TPQ exclusion or qualify Ironwood,
shielded-proof formats, a named-wallet scanner, performance or native macOS.
Offline tests cover only orchestration refusal and bookkeeping logic.

### Prepare the reviewed plan

Store the plan, run directory and sanitized evidence outside source control.
Use a trusted private directory. Evidence files must be regular files, not links.
The run stores hashes and references, not private snapshots, keys, cookies,
terminal output or copies of product journals. Do not put secrets in file names.
Retain all referenced public evidence for the life of the report.

The plan schema is `tpq-zdn-qualification/v1`. All fields are required; unknown
fields refuse. `validate_plan()` is the importable schema validator. Set:

| Field | Exact contents |
| --- | --- |
| `schema`, `beta_sha256` | The schema above and the beta document hash above |
| `binding` | `deployment_id` (canonical UUID from the reviewed ZDN render), `request_sha256`, `native_fingerprint` |
| `pins` | Each role below has exactly `path` (absolute), `bytes` (positive integer), `sha256` (lowercase hex) |
| `directory` | Absolute fixed-slot directory produced by `zdn external stage` |
| `state_dir`, `profile_alias` | Explicit ZDN state directory and saved local ZDN profile, not AWS profile |
| `launch` | Exactly `ami_id`, `availability_zone`, `reward_address`, `native_port` |
| `payments` | Exactly `fund`, `pay5`, `pay6`, `pay-restored`; each has `version`, integer-zatoshi `amount` and `fee`, hex `receiver_script`, `sender`, `recipient` |

The pin roles are `zdn`, `wallet`, `devnet`, `config`, `request`, `chain`,
`profile`, `prepare_receipt`, `import_receipt`, `build_receipt`, `update_record`,
`update_manifest` and `update_config`. Tool receipts must identify source commit,
source inventory, compiler/platform, version, protocol and executable hashes.
The build receipt must bind the image's source, recipe, features and capabilities.
Pin the actual development inventory; do not claim a base commit contains local
edits. Review receipt contents independently: hashing a receipt does not prove it.

`request` uses ZDN's `zdn-external-artifact-set/v1` schema. The coordinator checks
its schema and semantic digest shape, profile, native fingerprint, SLH feature
and all eleven fixed-slot file pins. Raw config integrity and semantic config
identity are separate checks. The plan's `config` pin identifies exact file
bytes, including comments and formatting. The request's `configSha256` is ZDN's
`Config::fingerprint`: SHA-256 of the validated parsed Rust `Config` serialized
as compact JSON. It is not the raw file hash. The coordinator requires a
64-character lowercase hexadecimal semantic digest. It does not parse YAML,
apply Rust defaults or compare that digest to the raw pin. Even a comment edit
behind an existing frozen raw pin still refuses.

Launch still passes the pinned config and request through the fixed ZDN argv.
ZDN's authoritative `require_config` check decides their semantic compatibility.
ZDN also owns strict package/image validation, fresh compilation, host rendering
and runtime readiness. Offline Python tests use synthetic requests and an
independently specified semantic fingerprint; they are not real Rust CLI staging
evidence. Cross-repository offline validation with actual ZDN staging remains
pending. Before `prepare` can pass,
review the result of this real product command, using independently approved pins:

```sh
zdn external verify --request "$REQUEST" --sha256 "$REQUEST_SHA256" \
  --directory "$EXTERNAL_DIRECTORY"
```

The three binding fields are different identities. `request_sha256` identifies
the external ZDN deployment manifest bytes, not the native fingerprint or a
classical ZDN `ConsensusManifest`. Never manufacture an ordinary consensus
manifest for this path. Check the rendered UUID against saved ZDN ownership.

Use directions seed→Alice, Alice→Bob, Bob→Alice, Alice→Bob in that order. The
versions are 5, 5, 6 and 6. Plan fees from the independently reviewed transaction
shape, not the historical 21,600-zat example. The last payment has its own amount,
approval and balances. No other payment may change these balances during the run.

### Execute one phase at a time

The following commands are interfaces, **not approval to run live workloads**.
`init`, `next`, `gate` and `accept` do file validation only. `dispatch` starts the
live ZDN command and needs separate user approval for its exact scope. Review the
displayed argv and plan digest independently; do not pipe a produced digest into
approval. Passing `--approve-plan` acknowledges the chosen operation, including
the update storage/mixed-version attestation or destructive data removal.

```sh
python3 tests/slh-dsa-b128s/acceptance/zdn_flow.py init "$PLAN" "$NEW_RUN"
python3 tests/slh-dsa-b128s/acceptance/zdn_flow.py next "$RUN"
python3 tests/slh-dsa-b128s/acceptance/zdn_flow.py gate "$RUN" "$NEW_GATE"
# Independently review evidence; complete the pending gate in a trusted editor.
python3 tests/slh-dsa-b128s/acceptance/zdn_flow.py accept "$RUN" "$REVIEWED_GATE"
# Only at an automated phase, after separate workload approval:
python3 tests/slh-dsa-b128s/acceptance/zdn_flow.py dispatch "$RUN" \
  --approve-plan "$INDEPENDENTLY_REVIEWED_PLAN_SHA256"
```

The order is `prepare`, `network`, `observe`, `wallets`, `fund-review`, `fund`,
`pay5-review`, `pay5`, `pay6-review`, `pay6`, `update`, `reobserve`, `recovery`,
`uncertain`, `restore`, `pay-restored-review`, `pay-restored`, `negatives`,
`disconnect`, `cleanup`, `audit`. The fixed update targets only `node-2` using
the pinned image triple. This bounded scenario does not select all nodes or
build an image. Setup, IAM, preparation, import and builds remain separately
approved prerequisites through their existing product commands.

Keep `zdn connect` running in terminal A and use normal controlling-terminal
wallet commands in terminal B as described above. The coordinator never starts
a connection in a detached subprocess, invokes a wallet, or supplies passwords.
`terminal.py` retains PTY/password handling for the existing acceptance drivers;
`wallet_live.py` retains their coherent wallet/payment/recovery operations.
This driver does not call their Regtest network recipe or automated approval
flow. The October 21 thread supplied historical scenario guidance only. Its
archived `run.py` was not available for direct script reuse.

### Gate data and independent evidence

`gate` creates a pending form with all checks false and no approvals. Each form
has exactly `schema`, `phase`, `plan_sha256`, `binding`, `reviewer`, `checks`,
`references` and `data`. `references` must contain at least two distinct pinned
public files. Use independent observations, not two copies of wallet output.
`checks` must contain exactly the phase's named booleans shown by `next`.
False, missing or unknown checks refuse. A reviewer label is an attestation,
not authenticated proof of the reviewer's identity or of independence.

| Phase | Exact `data` fields |
| --- | --- |
| Each `*-review` | `intent` equal to that independently prepared plan payment; `approved_digest` from an independent funding transaction review or wallet proposal review |
| Each payment | `proposal_id` (null for seed funding), `transaction_sha256`, `transaction` (pin of public serialized binary bytes, not the hex text file), `txid`, `version`, `amount`, `fee`, `change`, `receiver_script`, `inputs`, `output_index`, `peers`, `before`, `after` |
| `network`, `observe`, `update`, `reobserve`, `cleanup` | `operation_reference` to original saved ZDN records/fresh health report; `ready: true` attests the reviewed result, not merely exit zero |
| `recovery` | `native_ids_before`, `native_ids_after` (same ordered pair of distinct public IDs), `cookie_rotation_receipt` (sanitized public report pin) |
| `uncertain` | `original_phase` (`pay5` or `pay6`), original `proposal_id`, `txid`, `original_bytes_sha256`, `retry_transaction` (binary file pin), `retried_bytes_sha256` |
| `restore` | `snapshot_receipt_sha256` (one of the public references), distinct `old_allocator` and `new_allocator` |
| `negatives` | `controls`: all `TPQ-N01` through `TPQ-N08`, each with manifest `reason_class`, `effect` and public `evidence` pin |
| `audit` | `kms_deletion`: `not-applicable`, `scheduled-pending` or `deleted`; a schedule is not a completed deletion |
| Other phases | Empty object |

Payment `inputs` are `{txid,index,value}` records with authenticated integer
values. Each of two `peers` has `node_id`, `block_hash`, positive `height`, `txid`,
`transaction_sha256`, `spent_outpoints_authenticated: true` and
`receiver_output_authenticated: true`. The block height/hash must agree between
distinct peers. `before` and `after` each contain integer `alice` and `bob`
balances. The validator checks input value = amount + fee + change, continuity,
exact approved digest/bytes, the v6 received outpoint and a new post-restore
proposal/txid. An independent reviewer must decode and authenticate full blocks,
transactions, scripts, change and prevouts with read-only node observations;
the coordinator is not a transaction decoder or RPC authenticity oracle.

Inject the lost reply on the original pay5 or pay6 submission, then retain its
wallet record and bytes. The later `uncertain` phase reviews reconciliation of
that original payment; it does not send another payment. Pin the actual retried
serialized bytes. Keep trusted snapshot files private and supply only their
public receipt through an independent trusted channel. Retire old allocators
before restore. Do not sign the new payment until the restore gate passes.

The negative manifest requires both unknown-authority and inventory-only monitor
refusals, changed funding and wallet approvals, a reachable wrong-rule peer,
conflicting spends, and interrupted bootstrap/update/connect reconciliation.
Diagnostic class labels alone are not proof: each report must retain actual
subcase diagnostics and side-effect observations. Missing subcases stay pending.
Never replace ZDN lifecycle operations with AWS mutations or direct node starts.

### Failure, resume and cleanup

The run directory serializes writes and creates each dispatch fence before
starting ZDN. It retains the argv and exit outcome, but no subprocess output.
Exit zero does not advance a phase. A timeout, crash or nonzero result never
automatically retries. Keep the original ZDN journals. Inspect with
`zdn devnet status "$NETWORK" --state-dir "$STATE" --profile "$ZDN_PROFILE"`.
Reconcile the original operation through ZDN, then accept the independently
reviewed gate. Do not delete a dispatch fence or create a second run to retry
uncertain effects. For example, an interrupted image update uses:

```sh
zdn devnet update "$NETWORK" --state-dir "$STATE" --profile "$ZDN_PROFILE" \
  --resume "$SAVED_UPDATE_UUID" --reconcile \
  --acknowledge-storage-compatibility --yes
```

Cleanup can run after a failed gate without pretending the journey passed:

```sh
python3 tests/slh-dsa-b128s/acceptance/zdn_flow.py dispatch "$RUN" --cleanup \
  --approve-plan "$INDEPENDENTLY_REVIEWED_PLAN_SHA256"
```

This uses only pinned ZDN and saved ownership, not installed local TPQ tools or
the local adapter artifact. Once cleanup starts, later non-cleanup dispatches
refuse. Early cleanup leaves the remaining journey phases incomplete; retain
its audit separately. If evidence is damaged, use the reviewed direct ZDN
`devnet destroy "$NETWORK" --state-dir "$STATE" --profile "$ZDN_PROFILE"
--delete-data --yes` path rather than weaken the qualification checks.
Use ZDN staged team removal only when that separately approved scope requires it.
Record protected shared resources and delayed KMS deletion honestly.

All live gates remain **pending, not run**. The offline suite uses fake process
results and synthetic public observations only. It does not run a wallet, signer,
PTY, RPC, node, Docker, build or cloud operation. A future report must pin actual
sources/binaries/configuration, commands and evidence per manifest subcase.

## Source launch and controller handoff

The matching local ZDN checkout now implements both completed-image launch and
initial source-to-image launch. Use its `docs/external-controller.md` for the
external configuration and artifact contracts. These paths are not in published
Preview 4. The coordinator above uses the completed-image request path; it does
not turn a source-build review into proof that a build or deployment ran.

With an explicit external config selecting the TPQ source and its build recipe,
render the first-source inputs without making cloud calls:

```sh
zdn devnet render --config "$EXTERNAL_CONFIG" \
  --external-public-directory "$PUBLIC_PACKAGE" --external-trust "$TRUST" \
  --external-build-helper "$LINUX_ZDN" --host-helper "$LINUX_ZDN" \
  --reward-address "$REWARD_ADDRESS" --ami-id "$AMI" --availability-zone "$ZONE"
```

This captures immutable source and public inputs. It does not build a node.
Only a separately approved `devnet up` with the same inputs and `--yes` may
submit the native CodeBuild job and deploy. Resume with `devnet up --saved
NETWORK --reconcile --yes`; do not recapture a changed source checkout to recover.

ZDN also owns portable external handoff export/import through its normal
`devnet handoff` commands. Keep the independently conveyed archive digest and
quiesce the original controller. The separate external schema retains public
artifacts, source/build journals, native inventory and revision evidence, never
wallet secrets or node keys. Import does not clear unknown operations or grant
permission to restart a build. An unfinished first deployment must be reconciled
on its original controller before handoff. Read the matching ZDN checkout's
`docs/handoff.md`; these are local implementation contracts, not live recovery
qualification.
