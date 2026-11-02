# Linux x86-64 TPQ experimental preview with ZDN

Use ZDN for cloud lifecycle and connections. Use local `tpq-devnet` for fresh
preparation and reviewed seed funding. Use local `pq-wallet` for wallet authority.
This opt-in preview is not ordinary ZDN Preview 4, Mainnet, public Testnet or a
full beta release. Ordinary Preview 4 and Mac instructions remain separate.
No Python, research checkout, private test directory or development harness is
required. No prebuilt node image is required: ZDN builds the pinned node source.

**Status:** R8 (2026-11-01) completed the two-private-node AWS journey in
55.85 minutes: one seed funding, v5 and v6 payments, a new restored-wallet v6
payment, one retained node-only restart per node and original gateway continuity.
Staged/final cleanup audits made 229/228 observations, preserving 57 protected
keys and the baseline across 17 regions. KMS deletion remained scheduled, not
physical deletion. This is selected analog PAY-01, happy-path PAY-02, WAL-08,
JRN-06 and CLN-01/03 coverage under ZDN beta plan **v1.0 / 2026-10-23**
(SHA-256 `20bc7e52be2df2d78706d5e4c453bfa91e42feefcad83d550c5a1abc31a499d2`).
It is not release-binary or clean-user qualification. R8 did not inject a lost
reply, update an image, reboot a host or run the separate qualification
coordinator. Fault/retry, handoff, full beta and the clean-download release
rehearsal remain pending. The instructions below have not had that live rehearsal.

## 1. Verify the distribution and choose a private workspace

Select only the `tpq-linux-x86_64` profile from the authenticated distribution
index. No version/tag or download filename is implied here. Independently obtain
and compare the profile checksum-list/index digest through your trusted release
channel, then verify **every** listed asset. Co-downloaded checksums alone do not
authenticate a publisher. An unsigned preview needs an explicit operator trust
decision; a digest is not a signature. Never use `--ignore-missing`.

```sh
set -eu
umask 077
DOWNLOADS=/REPLACE/absolute/verified-downloads
PROFILE_SUMS="$DOWNLOADS/SHA256SUMS.tpq-linux-x86_64"
cd "$DOWNLOADS"
sha256sum "$PROFILE_SUMS"   # compare with independently trusted value first
sha256sum -c "$PROFILE_SUMS"
```

Retain controller/source provenance, complete TPQ node source/map, product source,
notices, build manifest, instructions and starter archive. The profile also
supplies `zdn-tpq-adapter`, `zdn-tpq-import`, `tpq-devnet` and `pq-wallet`.
It does **not** select an ordinary chain-manifest/bundle or Ironwood wallet.
Inspect archive member paths before extracting into new trusted directories.
Set the following absolute paths from the reviewed index and extraction layout;
replace every `REPLACE` value. Filenames can change between candidates.

```sh
ZDN="$DOWNLOADS/REPLACE_CONTROLLER_FILENAME"
HOST_HELPER="$ZDN"
HOST_ADAPTER="$DOWNLOADS/REPLACE_ADAPTER_FILENAME"
IMPORT="$DOWNLOADS/REPLACE_IMPORT_FILENAME"
DEVNET="$DOWNLOADS/REPLACE_DEVNET_FILENAME"
WALLET="$DOWNLOADS/REPLACE_WALLET_FILENAME"
NODE_SOURCE=/REPLACE/absolute/extracted-node-source
STARTER=/REPLACE/absolute/docs/slh-dsa-b128s/zdn-preview
NODE_REV=REPLACE_REVIEWED_DISTRIBUTED_SOURCE_GIT_COMMIT
TPQ_REV=REPLACE_REVIEWED_ORIGINAL_TPQ_SOURCE_COMMIT
ADAPTER_SELECTION_SHA256=REPLACE_INDEPENDENTLY_APPROVED_SELECTION_SHA256
WORK=/REPLACE/absolute/new-private-tpq-work
mkdir -m 700 "$WORK"
STATE="$WORK/state"
CONFIG_DIR="$WORK/config"
CONFIG="$CONFIG_DIR/external.yaml"
mkdir -m 700 "$STATE" "$CONFIG_DIR"
chmod 700 "$ZDN" "$HOST_ADAPTER" "$IMPORT" "$DEVNET" "$WALLET"
git -C "$NODE_SOURCE" fsck --full --no-reflogs
test "$(git -C "$NODE_SOURCE" rev-parse HEAD)" = "$NODE_REV"
test -z "$(git -C "$NODE_SOURCE" status --porcelain)"
test -z "$(git -C "$NODE_SOURCE" remote)"
STATE=$(cd "$STATE" && pwd -P)
CONFIG_DIR=$(cd "$CONFIG_DIR" && pwd -P)
CONFIG="$CONFIG_DIR/external.yaml"
SOURCE_WORKTREE=$(git -C "$NODE_SOURCE" rev-parse --show-toplevel)
case "$STATE/" in
  "$CONFIG_DIR/"*|"$SOURCE_WORKTREE/"*)
    echo 'State must be outside the configuration directory and source Git worktree' >&2
    exit 1 ;;
esac
"$ZDN" --version
"$ZDN" reference > "$WORK/command-reference.txt"
"$ZDN" reference --schema > "$WORK/command-schema.json"
"$WALLET" --help
```

Keep config and state in separate directories. Do not put state below the config
directory or inside the source Git worktree. The local check above resolves
directory links and rejects either layout before AWS setup. It does not verify
cloud access or authorize deployment. Keep private funder and wallet files out
of the config directory and node source.

Use Linux x86-64. The distribution build manifest must record each executable's
actual compiler, target, features, byte count, SHA-256 and tested ABI. The Linux
ZDN helper targets the AL2023 host ABI (GLIBC through 2.34); do not infer that
the companion wallet tools support every Linux distribution. Stop on an ABI
failure. Install Git, `jq`, `curl`, AWS CLI v2 >=2.37.4 and the native AWS Session
Manager plugin (newer than 1.2.497.0) from trusted channels. ZDN installs its
managed tools with `deps install`; local Docker is not needed for this
source-to-image path.

The host adapter and importer must be separate signing-free builds of package
`zakura-tpq-devnet`, with `--no-default-features --features adapter`. Never combine
that build with wallet-enabled tools through Cargo feature unification. The
adapter refuses that combination. Hash only the final bytes after stripping or
other post-processing. Nodes and hosts receive no wallet keys or signing tools.
Local adapter execution is explicit same-user trust, not a local OS sandbox.
Host sandbox admission is an additional boundary; do not disable it to proceed.

The local `tpq-devnet` selects its `wallet` feature; `pq-wallet` requires
`experimental-slh-dsa-b128s`. Their authority must not enter the host adapter
build. The protocol is `slh-dsa-b-128s-exp-v1` (BLAKE3, not a FIPS 205 profile).
The node extension stays off by default and rejects activation on built-in
Mainnet/public Testnet. This fork's 20 MB block limit is not an RPC capacity
guarantee: exact nonverbose block/transaction hex has a finite 40,100,000-byte
transport class; metadata/verbose responses remain bounded at 2 MiB.

### Source and image identity

The current TPQ `docker/Dockerfile` uses `ARG RUST_VERSION=1.97.1`, base
`rust:${RUST_VERSION}-trixie`, context `.`, release build of package `zakura`
and runtime target `runtime` (`debian:trixie-slim`). It sets
`RUSTFLAGS=-C link-arg=-Wl,--compress-debug-sections=zlib`. ZDN supplies the exact
features `default-release-binaries,experimental-slh-dsa-b128s` through the Docker
`FEATURES` argument. Required capabilities are `native-managed-identity-v1` and
`slh-dsa-b128s-v2`. Review the same-candidate recipe, lockfile and build receipt;
moving base tags are not reproducible image pins. The resulting image manifest
and config have their own authenticated identities. No compiler override or
local substitute is implied. Do not use an ordinary node recipe or drop SLH.

The pinned upstream Zakura baseline is
`436a6af46d04637bba793efce5b16be94ec1f7f0`; see [protocol](protocol.md).
R8 used TPQ `a8968159f39bd98403e6f3c67eeb16fd2ca55cbc`, containing public main
`362b062a324bb6c8cede30ce82c791d9114d4f85`. R8's ZDN was base
`47ebd4055b151340dba20cda38b77f4103d02594` plus pinned local changes, not that
clean commit alone. These historical IDs do not select a future download.
Use its authenticated source map/build manifest for `NODE_REV` and `TPQ_REV`.
A projected Git revision can differ from the original source revision. A dirty
tree requires its full inventory and patch identity; never attribute its binary
to a base commit as if that commit contained the edits.

## 2. Prepare a new seed and import public inputs

Choose one new cohort name. Preparation is local and creates random **private**
classical funding authority. Never distribute a maintainer's seed funder or
copy test authority from R8.

```sh
COHORT=REPLACE_NEW_COHORT_NAME
PUBLIC="$WORK/cohort-public"
PRIVATE="$WORK/cohort-private"
"$DEVNET" prepare "$PUBLIC" "$PRIVATE" "$COHORT" > "$WORK/native-fingerprint.txt"
CHAIN="$PUBLIC/chain.json"
PROFILE="$PUBLIC/wallet-profile.json"
FUNDER="$PRIVATE/funder.json"
PACKAGE="$WORK/public-package"
TRUST="$WORK/core-trust.json"
HOST_ADAPTER_SHA256=$(sha256sum "$HOST_ADAPTER" | cut -d ' ' -f 1)
HOST_ADAPTER_BYTES=$(wc -c < "$HOST_ADAPTER" | tr -d '[:space:]')
```

Review the adapter byte count/hash against the **authenticated distribution**
and source/build manifest before import. Merely measuring an arbitrary local
file does not approve its execution. Independently approve the selection digest;
it identifies the chosen adapter implementation, not the native chain or package.

Preparation creates public `chain.json`, `network.json`, `node-network.toml`
and canonical `wallet-profile.json`. The seed has heights **0..101**: genesis,
the height-1 funding coinbase and 100 padding blocks. NU7 starts at 102; SLH at
103, with 16 checks/transaction and 64/block. Native coinbase maturity stays 100.
The private `funder.json` is unencrypted: use encrypted storage and a private
backup. Both output directories must be new, disjoint and under trusted parents.

```sh
"$IMPORT" "$CHAIN" "$PROFILE" "$HOST_ADAPTER" "$HOST_ADAPTER_SHA256" \
  "$ADAPTER_SELECTION_SHA256" "$TPQ_REV" "$PACKAGE" > "$WORK/import-receipt.json"
PACKAGE_SHA256=$(sha256sum "$PACKAGE/package.json" | cut -d ' ' -f 1)
PACKAGE_BYTES=$(wc -c < "$PACKAGE/package.json" | tr -d '[:space:]')
```

Review the import receipt, native fingerprint, original public inputs and seven
slots: `package.json`, `descriptor.json`, `native-rules.json`,
`wallet-profile.json`, `seed-blocks.bin`, `host-adapter`, `compiled.json`.
Check that `host-adapter` is byte-identical to the approved executable. The
importer's own declarations do not authenticate source or grant execution trust.
Only after review, create the explicit core-owned trust object:

```sh
jq --arg p "$PACKAGE_SHA256" --arg e "$HOST_ADAPTER_SHA256" \
  --arg s "$ADAPTER_SELECTION_SHA256" --argjson pb "$PACKAGE_BYTES" \
  --argjson eb "$HOST_ADAPTER_BYTES" \
  '.package={bytes:$pb,sha256:$p} | .executable={bytes:$eb,sha256:$e} |
   .adapterSelectionSha256=$s' "$STARTER/core-trust.json.in" > "$TRUST"
```

Keep only explicitly selected public inputs in the package. Do not recursively
upload `$WORK`, `$PRIVATE`, a wallet directory or a preparation directory.
Source launch needs these seven slots, not the completed-image eleven-slot set.
Authenticate the profile and native fingerprint independently before any wallet
uses them. A public profile supplied by an untrusted RPC is not approval.

## 3. Select AWS scope and render locally

AWS builds, NAT, hosts, disks and storage cost money. Use a dedicated development
account, never root or a shared production tenant. A deadline is not a spending
cap. Use one authenticated administrator-capable source login through cleanup.
Deployment credentials can read/cancel other SSM commands in the region unless
external policy denies that access. Set your own values:

```sh
AWS_PROFILE=REPLACE_AUTHENTICATED_AWS_PROFILE
ACCOUNT_ID=REPLACE_OWN_TWELVE_DIGIT_ACCOUNT_ID
TRUST_PRINCIPAL=REPLACE_EXACT_IAM_USER_OR_ROLE_ARN
REGION=REPLACE_AWS_REGION
TEAM=REPLACE_NEW_DISPOSABLE_TEAM
BUCKET=REPLACE_NEW_GLOBALLY_UNIQUE_BUCKET
ZDN_PROFILE=default
"$ZDN" deps install --noninteractive
"$ZDN" doctor
AMI_ID=$(aws ssm get-parameter --profile "$AWS_PROFILE" --region "$REGION" \
  --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text)
aws ec2 describe-images --profile "$AWS_PROFILE" --region "$REGION" \
  --owners amazon --image-ids "$AMI_ID" \
  --query 'Images[].{Id:ImageId,Name:Name,Architecture:Architecture,State:State}'
aws ec2 describe-availability-zones --profile "$AWS_PROFILE" --region "$REGION" \
  --query 'AvailabilityZones[?State==`available`].ZoneName' --output text
ZONE=REPLACE_SELECTED_ZONE
```

Those AWS lookups are read-only. Require one available Amazon Linux 2023 x86-64
image and an available zone in that region. Retain the concrete AMI and zone;
do not resolve the moving parameter again to resume an interrupted deployment.
Before creating resources, independently record your account's protected baseline
and chosen cleanup scope with read-only inventory. Keep it private for comparison
after teardown; do not infer resource ownership from names or tags alone.
Prepare and check the config locally before creating IAM/backend resources:

```sh
cp "$STARTER/external.yaml" "$CONFIG"
```

In a trusted editor, replace all `REPLACE` values in `$CONFIG`: local profile,
reviewed `$PACKAGE_SHA256`, selection digest, absolute `$NODE_SOURCE` and its
`$NODE_REV`. The template uses two private `small` nodes, no cloud wallet,
faucet or lightwalletd, explicit height 121 and two-hour first-activation ceilings.
Its native rules come from the compiled package, not ordinary activation defaults.
The outer config still requires `network.activationHeights.NU6.3: 1` for schema
validation. That field does not set TPQ's NU7/SLH schedule or native fingerprint.
The 3600-second scheduled cadence allows deliberate bounded controls; stop it
before funding. A scheduled block can still race you. Do not renew the lifetime
or weaken a refusal to finish a test. These are test settings, not production
resource or timing recommendations.

Set a supported classical Testnet mining reward address whose key you control;
do not use an SLH receiver. Mining rewards are separate from the prepared seed
funder. No PQ mining payout or shielded proof generation is provided here.

```sh
REWARD_ADDRESS=REPLACE_OWN_CLASSICAL_TESTNET_ADDRESS
if grep -n REPLACE "$CONFIG"; then echo 'Edit all marked values first' >&2; exit 1; fi
"$ZDN" check --config "$CONFIG"
"$ZDN" plan --config "$CONFIG"
```

After reviewing costs and permissions, `setup bootstrap` below **creates
IAM/backend resources**. It is not local preparation. The following render is
local and must use the same config and state paths checked above:

```sh
"$ZDN" setup bootstrap --aws-profile "$AWS_PROFILE" \
  --trust-principal "$TRUST_PRINCIPAL" --team-id "$TEAM" \
  --account-id "$ACCOUNT_ID" --region "$REGION" --bucket "$BUCKET" \
  --state-dir "$STATE" --profile "$ZDN_PROFILE" --export "$WORK/team.yaml" --yes
"$ZDN" devnet render --config "$CONFIG" --state-dir "$STATE" \
  --external-public-directory "$PACKAGE" --external-trust "$TRUST" \
  --external-build-helper "$HOST_HELPER" --host-helper "$HOST_HELPER" \
  --reward-address "$REWARD_ADDRESS" --ami-id "$AMI_ID" --availability-zone "$ZONE"
NETWORK=REPLACE_EXACT_NETWORK_UUID_RETURNED_BY_RENDER
```

Render captures immutable source/public inputs and saves a network UUID. It
makes no cloud calls and builds no image. Keep the original saved state and
source receipts. Do not run ordinary `chain verify`, `identity bind`, `wallet`,
`fund` or `send` commands to manufacture a parallel ordinary-chain identity.

## 4. Launch and use saved bounded controls

This command **submits/reuses a billed native CodeBuild image and deploys nodes**:

```sh
"$ZDN" devnet up --saved "$NETWORK" --state-dir "$STATE" \
  --profile "$ZDN_PROFILE" --reconcile --yes
"$ZDN" devnet status "$NETWORK" --state-dir "$STATE" --profile "$ZDN_PROFILE"
"$ZDN" devnet health "$NETWORK" --state-dir "$STATE" --profile "$ZDN_PROFILE" \
  --wait --timeout-seconds 120
```

Require fresh strict readiness on both nodes: full effective rules, native
inventory, saved seed history and current image/producer/gateway bindings.
An open socket or matching genesis is insufficient. Unknown build dispatch must
be inspected/reconciled through this original saved UUID, never a fresh render.

For **each** control, save a new preparation result to a new filename, review it,
then execute only its saved ID. This example first stops node-1's scheduled
producer. Preparation is local; execution crosses the AWS lease/SSM boundary:

```sh
"$ZDN" --format json devnet control "$NETWORK" --state-dir "$STATE" \
  --profile "$ZDN_PROFILE" --node node-1 --action "$STARTER/stop-producer.json" \
  --prepare-only > "$WORK/stop-prepared.json"
jq -e '.outcome == "succeeded" and .data.dispatched == false' "$WORK/stop-prepared.json"
CONTROL_ID=$(jq -er '.data.controlId' "$WORK/stop-prepared.json")
# Review nodeId, intent.request.action, request and runtime pins before execution.
"$ZDN" --format json devnet control "$NETWORK" --state-dir "$STATE" \
  --profile "$ZDN_PROFILE" --resume "$CONTROL_ID" --reconcile --yes \
  > "$WORK/stop-completed.json"
```

ZDN validates the returned response against request pin, effective runtime,
deployment, node and native inventory. Retain both files. Inspect
`data.observation.result`, not merely exit zero or `controlId`. Do not interpret
`launchReady:false` or `paymentQualification:pending` in a control wrapper as
a payment result. A completed old read is not fresh evidence. Unknown mutations
remain fenced: resume the original ID and investigate, never delete its records
or create a new mutation to resolve uncertainty. Do not execute generated scripts.

Repeat this prepare/review/resume pattern with `tip.json` separately on node-1
and node-2. Require the same stable tip/hash. If it is 101, use
`produce-102.json` on node-1, then fresh tip reads on both nodes. Require stable
height 102 and identical hash before funding: SLH must govern the **next** block.
The funding coinbase is mature under the unchanged 100-block rule. If scheduled
production already passed 102, do not rewind or blindly run that action: inspect
both tips and use the stable SLH-active state. Do not bootstrap a running chain.

For later confirmation, create a new typed action at a new path with `jq -n
--argjson h HEIGHT '{kind:"produce",blocks:1,height:$h,seconds:120}'`, replacing
`HEIGHT` with the independently observed stable tip plus one (103 after initial
funding at 102). Prepare/review/execute it with the same saved-ID pattern.
Each invocation stops scheduled production. Limits are 1..20 blocks, a positive
absolute height and 1..600 seconds, intersected with immutable launch ceilings.
An in-flight RPC/reconciliation can outlast the budget; this is not a kill switch.

## 5. Connect in terminal A; create wallets in terminal B

In terminal A, retain the original `STATE`, `ZDN_PROFILE`, `NETWORK` and `ZDN`:

```sh
"$ZDN" connect "$NETWORK" --state-dir "$STATE" --profile "$ZDN_PROFILE"
```

Leave it running. In terminal B, set the same verified `WALLET`, `DEVNET`,
`PROFILE`, `CHAIN`, `FUNDER`, `WORK` and `STARTER` absolute paths from above.
Use `set -eu` and `umask 077` in that shell too.
Set `RPC_SOCKET` to the numeric loopback socket in the printed RPC URL, **without
`http://`**. Do not guess a port or use DNS/a remote address. An invited participant
instead uses their own login and a reviewed credential-free endpoint file with
`zdn connect --endpoints FILE --aws-profile OWN_PROFILE`. This preview journey
uses node-1's gateway for both wallets; node-2 supplies independent controls,
not an invented second gateway route.

```sh
RPC_SOCKET=127.0.0.1:REPLACE_PRINTED_LOCAL_PORT
mkdir -m 700 "$WORK/alice" "$WORK/bob" "$WORK/recovery-copies"
"$WALLET" create-slh-exp "$PROFILE" "$WORK/alice/root.tpq" 0
"$WALLET" extend "$PROFILE" "$WORK/alice/root.tpq" "$WORK/alice/enrolled.tpq" 8 8
"$WALLET" export "$PROFILE" "$WORK/alice/enrolled.tpq" "$WORK/alice/inventory.json"
"$WALLET" inspect "$PROFILE" "$WORK/alice/enrolled.tpq"
```

This single-key extension enrolls receive/change entries and saves a covering
encrypted backup. Copy it to protected recovery storage before creating an
allocator or issuing receivers. Check the inventory fingerprint independently;
do not accept a replacement inventory just because it has its own hash.

```sh
cp "$WORK/alice/enrolled.tpq" "$WORK/recovery-copies/alice-enrolled.tpq"
ALICE_INVENTORY_FP=REPLACE_REVIEWED_ALICE_INVENTORY_FINGERPRINT
"$WALLET" watch-create "$PROFILE" "$WORK/alice/inventory.json" \
  "$ALICE_INVENTORY_FP" "$WORK/alice/watch" allocator
"$WALLET" receive "$PROFILE" "$WORK/alice/watch"
```

Repeat those creation, extension, export, independent fingerprint check, backup
and watch-create commands for `bob` with its own root and fingerprint. Keep only
one allocator per inventory; never clone one. Record their returned receivers:

```sh
ALICE_RECEIVER=REPLACE_AUTHENTICATED_ALICE_TPQTEST_RECEIVER
BOB_RECEIVER=REPLACE_AUTHENTICATED_BOB_TPQTEST_RECEIVER
BACKUP="$WORK/alice/enrolled.tpq"
STORE="$WORK/alice/watch"
"$WALLET" --trusted-local-gateway sync "$PROFILE" "$STORE" "$RPC_SOCKET" 256
"$WALLET" status "$PROFILE" "$STORE"
```

Passwords use the normal controlling terminal (`/dev/tty`), with echo disabled.
Never put them in argv, environment, JSON or scripts. Do not run wallet commands
under `zdn exec` (closed stdin/separate session). Wallet gateway mode is a global
option **before** the command, mutually exclusive with `--rpc-cookie FILE`.
It sends no node credentials and explicitly trusts the selected local service.
There is no cookie/authentication fallback. Ctrl-C in terminal A ends the
connection, not the deployment. Reconnect explicitly and reconcile saved records.

## 6. Review one funding, then make v5 and v6 payments

At the stopped stable SLH-ready tip, fund Alice once (3,000,000 zat example).
The funding tool's gateway argument is positional **after the socket**, unlike
the wallet's global option:

```sh
REVIEW="$WORK/seed-funding.json"
"$DEVNET" fund-draft "$CHAIN" "$RPC_SOCKET" --trusted-local-gateway \
  "$FUNDER" "$REVIEW" "$ALICE_RECEIVER" 3000000 10000
APPROVED_TRANSACTION_SHA256=REPLACE_INDEPENDENTLY_REVIEWED_TRANSACTION_SHA256
"$DEVNET" fund-submit "$CHAIN" "$RPC_SOCKET" --trusted-local-gateway \
  "$REVIEW" "$APPROVED_TRANSACTION_SHA256"
```

Check fingerprint, mature seed outpoint, recipient script, amount, fee, change,
expiry, txid and exact transaction digest before approving. Do not pipe draft
output into approval. This tool spends only the one prepared seed outpoint; it
does not spend arbitrary classical change. Keep the private funder and review
file. After an uncertain reply, use this **same** review file and approved digest
to reconcile exact saved bytes, not a new draft. Node-known does not mean mined.
Produce the next block through a new saved bounded control in terminal C/the
administrative shell, then check transaction/output observations on both nodes.
Sync Alice to the actual tip before interpreting funds.

Fees depend on the selected inputs/policies and outputs. The wallet sizes each
full authorization and applies 400 zat times ZIP-317 conventional actions. For
transparent-only payments this counts the greater of total input bytes/150
rounded up, total output bytes/34 rounded up, and the two-action grace floor.
A one-input 1-of-1 SLH input has 7,973 bytes: 54 input actions. With two 44-byte
SLH outputs, output actions are 3, so the fee is 21,600 zat. The complete v5/v6
transaction has 8,086/8,087 bytes. More inputs or another policy can change the
fee; 21,600 is **not** universal. The seed funding uses a different classical
shape and explicit tool fee. The 2,403-zat SLH dust floor is not a fee estimate.

Create an independent intent. The template's 50,000-zat maximum is an editable
ceiling, not the amount the wallet must charge. Review and change it for your
shape. `remainder:reject` asks for a new decision for uneconomic change.

```sh
INTENT="$WORK/pay5-intent.json"
PROPOSAL="$WORK/pay5-proposal.json"
PARTIALS="$WORK/pay5-partials"
jq -S -c -j --arg r "$BOB_RECEIVER" \
  '.receiver=$r | .amount=1000000 | .max_fee=50000 | .version=5' \
  "$STARTER/payment-intent.json.in" > "$INTENT"
"$WALLET" --trusted-local-gateway sync "$PROFILE" "$STORE" "$RPC_SOCKET" 256
"$WALLET" --trusted-local-gateway propose "$PROFILE" "$BACKUP" "$STORE" \
  "$RPC_SOCKET" "$INTENT" "$PROPOSAL"
"$WALLET" --trusted-local-gateway review "$PROFILE" "$BACKUP" "$STORE" \
  "$RPC_SOCKET" "$INTENT" "$PROPOSAL"
APPROVED_ID=REPLACE_INDEPENDENTLY_REVIEWED_FULL_PROPOSAL_ID
"$WALLET" --trusted-local-gateway sign "$PROFILE" "$BACKUP" "$STORE" \
  "$RPC_SOCKET" "$INTENT" "$PROPOSAL" "$APPROVED_ID" "$PARTIALS"
"$WALLET" --trusted-local-gateway assemble "$PROFILE" "$BACKUP" "$STORE" \
  "$RPC_SOCKET" "$INTENT" "$PROPOSAL" "$PARTIALS"
"$WALLET" --trusted-local-gateway submit "$PROFILE" "$BACKUP" "$STORE" \
  "$RPC_SOCKET" "$APPROVED_ID"
```

Review recipient, version, amount, inputs, policy, fee, change, expiry and local
change-range advancement. If review requires it, separately use
`change-approve PROFILE BACKUP STORE RPC INTENT PROPOSAL APPROVED_CHANGE_ID`
with the wallet's gateway global option; inspect that signer's displayed
`local_change.approval_id`. Do not silently approve skipped ranges. A proposal
needing a change jump can be exported with `propose-preview` before approval.
For this 1-of-1 example, the generated partial directory is the collection;
multisig requires exactly the threshold per input, not all available files.

Confirm with a new saved one-block control. On both nodes prepare fresh typed
`read` queries for `transaction` with the returned `txid`, and `output` with
`txid`/unsigned `index`. Check matching canonical block hashes/heights, raw-byte
digest/size where available, spent inputs, receiver and change outputs. A null
output alone is not proof of a confirmed spend. The participant gateway supplies
raw nonverbose block/transaction bytes for independent decoding. Verify input
value = recipient amount + fee + change and sync both wallets. Do not infer
confirmation from a returned txid or cached `status` alone.

For the v6 return payment, set `BACKUP`/`STORE` to Bob's enrolled backup/watch,
`INTENT`, `PROPOSAL`, `PARTIALS` to **new** pay6 paths, and generate a new canonical
intent with receiver `$ALICE_RECEIVER`, amount 400000 and version 6. Repeat the
complete propose/review/approval/sign/assemble/submit flow and bounded confirmation.
Require it to spend Bob's actual received outpoint before proceeding.

## 7. Reconcile, back up, restore and restart without replacing authority

After uncertainty inspect `payments PROFILE STORE RPC` (with the gateway global
option) and retain the original proposal ID, intent, partials and saved bytes.
`payment-export PROFILE STORE ID NEW_FILE` preserves the authoritative proposal.
Re-run `submit` only with that original ID to reconcile/retry saved bytes. Do
not create a replacement payment, clear reservations, force-unlock or refresh
an approval to resolve an unknown outcome. Tip refresh is a separate reviewed
operation, not permission to change transaction effects or expiry.

Quiesce wallet writers before capture. Save each complete operational snapshot
and matching encrypted backup, including watch state and all retained journal
objects. Protect the receipt fingerprint through a separate trusted channel.
For Alice (repeat capture independently for Bob):

```sh
BACKUP="$WORK/alice/enrolled.tpq"
STORE="$WORK/alice/watch"
"$WALLET" snapshot-save "$PROFILE" "$BACKUP" "$STORE" "$WORK/alice-snapshot"
TRUSTED_RECEIPT_FP=REPLACE_INDEPENDENTLY_RETAINED_LATEST_RECEIPT_FINGERPRINT
"$WALLET" snapshot-restore "$PROFILE" "$WORK/alice-snapshot" "$WORK/alice-monitor" unknown
```

Unknown-authority and key/inventory-only restores stay monitor-only, even after
sync. They cannot issue receivers, sign or submit. A source monitor always remains
a monitor. For known-authority restore, reconcile outstanding signatures and
**retire every old allocator first**: stop its writers, remove its use from all
machines and keep its old data offline. Then, and only then:

```sh
"$WALLET" snapshot-restore "$PROFILE" "$WORK/alice-snapshot" "$WORK/alice-restored" \
  known "$TRUSTED_RECEIPT_FP" --retired-old-allocators
BACKUP="$WORK/alice-restored/backup-restored.tpq"
STORE="$WORK/alice-restored/watch"
"$WALLET" --trusted-local-gateway sync "$PROFILE" "$STORE" "$RPC_SOCKET" 256
"$WALLET" extend "$PROFILE" "$BACKUP" "$WORK/alice-restored/extended.tpq" 8 8
BACKUP="$WORK/alice-restored/extended.tpq"
"$WALLET" export "$PROFILE" "$BACKUP" "$WORK/alice-restored/inventory.json"
```

Save an external protected copy of the extended backup, independently check its
new inventory fingerprint, then `watch-import PROFILE STORE INVENTORY FINGERPRINT`.
Restoration rotates allocator authority and retires old ranges. Rescan until
complete, reconcile original payments and verify old exports. It cannot prove
that no newer state/signatures were lost. See [recovery](recovery.md).
Make a **new**, separately approved restored-Alice v6 payment to Bob (100000 zat
example), with new intent/proposal/partials paths and new ID. Confirm it through
bounded production and both nodes; a readable balance is not restored spending.

Before restart, collect fresh tip controls on both nodes and
`gateway-identity.json` on node-1. Use the saved-control pattern with
`restart-node.json` first on node-1, then node-2, checking fresh readiness and
matching native IDs/history after each. It is a retained same-revision node-only
restart, not a host reboot, update or bootstrap. Production stays stopped.
The gateway can remain alive and report unavailable during the outage, then
reread rotated credentials. Make a real wallet sync through the still-running
connection and collect a new gateway-identity control; compare PID, start ticks,
boot ID and executable pin to the original observation. Do not claim continuity
from unit text or isolated observations. Confirm final coin sets on both nodes.

## 8. Destroy, retain/delete data and remove only your disposable team

Stop local connections (Ctrl-C in terminal A), wallet writers and other controllers.
Keep private backups and original state/journals. Cleanup does not need local
adapter execution, wallet software, original source checkout or a working image.
Unknown builds/mutations still require original-operation investigation.

```sh
"$ZDN" devnet list --state-dir "$STATE" --profile "$ZDN_PROFILE"
"$ZDN" devnet destroy "$NETWORK" --state-dir "$STATE" --profile "$ZDN_PROFILE" --yes
```

The first destroy retains chain data and its costs. Independently inspect the
original scoped volume IDs: require the expected encrypted disks available and
unattached **before** the next destructive command. Do not adopt similarly named
resources. Only after review and backup, delete retained data:

```sh
"$ZDN" devnet destroy "$NETWORK" --state-dir "$STATE" --profile "$ZDN_PROFILE" \
  --delete-data --yes
"$ZDN" setup remove-team --state-dir "$STATE" --profile "$ZDN_PROFILE" \
  --aws-profile "$AWS_PROFILE"
# Optional intermediate removal: retain backend state, not complete cleanup.
"$ZDN" setup remove-team --state-dir "$STATE" --profile "$ZDN_PROFILE" \
  --aws-profile "$AWS_PROFILE" --keep-backend --delete-data --yes --writers-stopped
# Final removal after all networks/data/participant grants are closed:
"$ZDN" setup remove-team --state-dir "$STATE" --profile "$ZDN_PROFILE" \
  --aws-profile "$AWS_PROFILE" --delete-data --yes --writers-stopped
```

The proposal is local, not live ownership proof. Skip the optional intermediate
command when not wanted. Its `--delete-data` flag consents to deleting owned
build data; `--keep-backend` preserves backend state and its enabled KMS key.
Use only the original creator profile/admin login and team receipts; imported
scope is not team deletion authority. On interruption,
rerun the **same** removal/destroy command with `--reconcile` and the same consent,
not wildcard AWS deletes. Resolve active/unknown builds through product recovery.
Team removal schedules owned KMS deletion for 30 days; PendingDeletion is not
physical deletion, credential invalidation or billing closure.

Independently audit the exact original compute, disks, VPC/network, build/image,
cache/log, access, backend and SSM session/lock scope against the pre-run inventory.
Use read-only AWS observations for that audit, not substitute lifecycle writes.
Preserve unrelated/shared resources and record exclusions or pending deletion.
A successful product command is not an account-wide absence or cost assertion.
Never publish funders, passwords, encrypted wallet stores/snapshots, node keys,
cookies, credentials, private receipts or raw evidence bundles.

## Advanced contracts and qualification

The matching ZDN `docs/external-controller.md` describes completed-image launch,
source update and saved controls; `docs/handoff.md` describes portable handoff.
Quiesce the original controller and independently convey the handoff digest.
Import does not clear unknown work or restart builds. An unfinished first launch
must reconcile on its original controller. These are not R8 handoff/update passes.

The optional source-only [qualification coordinator](../../tests/slh-dsa-b128s/acceptance/zdn_flow.py)
and [case manifest](../../tests/slh-dsa-b128s/acceptance/zdn_cases.json) remain
developer tools, not installation/runtime prerequisites. That coordinator's live
gates remain unrun. Its completed-image path and fault gates must not be confused
with R8's actual source-launch happy path. The release rehearsal must consume the
actual candidate downloads and these instructions, with exact source/binary/config
pins and selected REL-01/02/03/05 subcase evidence. Nothing in this guide grants
approval to start builds, live workloads, AWS mutations or publication.
