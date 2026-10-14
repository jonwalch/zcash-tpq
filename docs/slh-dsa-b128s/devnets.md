# SLH nodes for devnet launchers

An explicitly configured custom testnet can activate experimental SLH-DSA-B-128s.
The same node can run in a public or private devnet. Each node must use the same
chain definition and include the `experimental-slh-dsa-b128s` feature.
Built-in Mainnet and public Testnet cannot activate SLH.

This support is for transparent SLH outputs. It preserves the
[experimental v1 contract](protocol.md), NU7 signing context, classical checks,
and shielded checks. It changes no block-size or fee policy.
The wallet CLI remains Regtest-only. Live devnet acceptance remains pending.

## Generate one chain definition

The launcher can call this function in `zakura_chain::local_genesis`:

```rust,ignore
generate_local_testnet_with_slh_dsa_b128s(miner_names, options, limits)
```

`options` is the existing `LocalTestnetGenesisOptions` type.
Set `latest_network_upgrade` to `NetworkUpgrade::Nu7` explicitly.
The ordinary generator still defaults to NU6.3. The SLH generator rejects that default.
Construct limits with `ExperimentalSlhDsaB128sLimits::new(transaction, block)`.
The values 16 and 64 remain a functional test profile, not a capacity recommendation.

The result is `GeneratedLocalTestnet`: network parameters, seed blocks, classical
funded keys, and checkpoints. If the seed tip is S, NU7 activates at S+1 and SLH
at S+2. The generator checks height arithmetic before it generates keys or blocks.
It does not generate SLH keys or signatures.

Generate these values once. Save the network and seed blocks, and reuse them
for every node and restart. Keep generated keys in the launcher's private storage.
Do not regenerate the chain separately for each node.

Choose `disable_pow` explicitly. Its existing default is true for local testing.
An open devnet that requires proof of work must set it to false and use a build
with the existing internal-miner support when generating solved seed blocks.
Public/private peer exposure is separate from the consensus PoW choice.

The ordinary custom-network builder also provides:

```rust,ignore
parameters_builder.with_experimental_slh_dsa_b128s(activation_height, limits)?
```

Final construction validates the complete settings. Activation must follow NU7
and every configured or mandatory checkpoint. Changing another builder setting
after the SLH setter cannot bypass these checks.

## Configure nodes

Custom testnets use the existing explicit `network = { ... }` form in the
node's `[network]` configuration. Put these fields inside that object:

- `experimental_slh_dsa_b128s_activation_height`
- `experimental_slh_dsa_b128s_max_checks_per_transaction`
- `experimental_slh_dsa_b128s_max_checks_per_block`

All three fields are required together. The limits must satisfy
`0 < transaction <= block`. Set the full generated network parameters, including
genesis, upgrades, difficulty, funding rules, and checkpoints. A genesis hash
without its matching seed chain is insufficient for bootstrap.

The separate `[network.testnet_parameters]` section is for Regtest.
It does not configure a custom testnet. A custom SLH testnet needs a nonreserved
name and magic and a genesis different from the built-in networks. A renamed
public Testnet does not qualify.

Set the launcher's own legacy and Zakura bootstrap peers. Clear unused peer lists.
Configuration loading and startup reject built-in bootstrap peers for SLH devnets. Use separate listening
ports, peer identities, cache paths, and data roots for nodes and devnets.
Serialize through the node network configuration type so the complete custom
parameters are retained; `NetworkKind::Testnet` alone is not a chain definition.
This covers the settings returned by the generator. Existing custom builder
options for unshielded coinbase spends and disabling the temporary Orchard fork
do not round-trip through the upstream configuration format.

For an embedded launcher, assign the generated network to `ZakuradConfig` and
enable the SLH feature on its `zakura` dependency. Reuse `node::run_with_services_ready`
and its shutdown token. The existing API requires the embedding application to
initialize tracing, metrics, and Rayon. It reports that services have started;
it does not report synchronization or mempool readiness.

For a launcher that starts `zakurad`, check the
[verifier identity](runtime.md#read-the-verifier-identity) before startup.
Both entry points refuse a configured SLH network when the build lacks its verifier.
The node graph continues to exclude PQ signing, PQ key generation, and fixture tools.

## Keep state with the correct chain

`Network::experimental_slh_dsa_b128s_chain_fingerprint()` returns a 32-byte
fingerprint for a configured SLH custom testnet. It returns none on Regtest and
unconfigured networks. Encode it as lowercase hexadecimal for storage and comparison.

Version 1 hashes a fixed binary encoding of the normalized network parameters
with SHA-256. It includes the name, magic, genesis, upgrade schedule, SLH contract,
activation, limits, PoW and timing rules, subsidy/funding/lockbox settings,
checkpoints, and monetary-state settings. Map and unordered-payment ordering is
normalized. The derived NSM cache is excluded; its inputs are included.
The exact encoding and reference vector are in
[`slh_identity.rs`](../../crates/zakura-chain/src/parameters/network/testnet/slh_identity.rs).

The database and nonfinalized backup namespace is
`<name>-slh-dsa-b128s-v1-<fingerprint>`. Two devnets with the same name and different
genesis or rules use different state. Regtest retains its existing namespace.
Keep the saved chain definition with backups. Changing consensus settings starts
a different devnet; it does not update an existing chain in place.

The fingerprint identifies settings. It does not authenticate a remote node or
prove its execution. It also does not change signatures: custom testnets use the
existing Testnet byte 01. Cloned histories do not gain separate signature domains
from different network magic or fingerprints.

## Check effective rules

On configured SLH networks, `getblockchaininfo` adds this optional object:

| Field | Meaning |
| --- | --- |
| `experimental_slh_dsa_b128s.schema_version` | Diagnostic schema version 1 |
| `contract` | `slh-dsa-b-128s-exp-v1` |
| `verifier_compiled`, `runtime_supported` | Compiled node capabilities |
| `genesis_hash` | Configured genesis in RPC display order |
| `chain_fingerprint` | Custom-testnet identity, or null on Regtest |
| `activation_height` | First SLH block height |
| `max_checks_per_transaction`, `max_checks_per_block` | Effective allowances |
| `tip_height` | Observed tip, or null when state cannot supply it |
| `next_block_height` | Candidate height, or null without a usable tip |
| `active_for_next_block` | SLH rule status at the candidate height, or null |

All rows after the first are fields within `experimental_slh_dsa_b128s`.
Unconfigured networks omit the object. The corresponding Rust type is
`zakura_rpc::client::ExperimentalSlhDsaB128sInfo`.

Compare the response with the launcher's saved network parameters. Then check
the expected seed tip, peer synchronization, mempool, and mining readiness.
Rule activation alone does not establish those conditions.

## Bootstrap and funding boundaries

Regtest automatically seeds its built-in genesis and enables its mempool early.
Custom testnets do not receive these shortcuts. The launcher must supply or serve
the generated seed chain through existing validation/bootstrap interfaces.
Later nodes must be able to download it through the selected peer stack.
No database-write bypass or new bootstrap service is added by SLH support.

Keep checkpoints before SLH activation so SLH-era blocks receive semantic
validation. The existing activation, rollback, and reactivation reset paths
apply to the custom testnet. Blocks use their containing height; admission and
mining use the next candidate height.

Generated premine outputs are classical coinbase outputs. The generator does
not waive the existing coinbase spending restriction. A funding flow must use
the route required by its chain rules, including a shielded step where required.
The SLH wallet and faucet integration are separate from node verification.

## Launcher integration and validation

The `zdn` launcher was inspected at revision
`7129776986bddbc074642c660b61929d73ddf356`. Its `src/chain.rs` describes a draft
chain request, and `src/main.rs` has no implemented node launch operation.
Its upgrade configuration stops at NU6.3. These node APIs provide the integration
boundary; this change does not implement `zdn` deployment.
Its request fingerprint is not this node's normalized consensus fingerprint.
Do not mark a deployment ready merely because those draft files were generated.

Focused tests cover custom configuration, rule identity, state isolation, local
chain generation, startup refusal, and the RPC response. Source presence does
not establish a successful live run. The [validation guide](validation.md)
separates recorded checks from live acceptance.

The [public Testnet fixtures](../../tests/slh-dsa-b128s/fixtures/devnet/README.md)
contain separately signed v5/v6 transactions. Consensus tests use them for block
and mempool dispatch, wrong-domain rejection, corrupt signatures, fresh budgets,
and metadata tied to custom rules. Independent controls check both valid
signatures and four mutations. Their supplied previous outputs are synthetic;
these checks do not establish funded node acceptance.

Before agent execution, [AGENTS.md](../../AGENTS.md) requires approval for dedicated
node builds and live tests. Prepare a bounded miner/relay/joining-node run with
matching source, binary, configuration, funding, and timeout details. It must test
payment relay, block inclusion, fresh sync, restart, and activation reorgs on the
actual custom testnet. The existing Regtest drivers alone cannot establish that result.

## Source mapping

The parameter and state changes extend the retained mechanisms in
[`node-reuse.json`](node-reuse.json), pinned to research revision
`85f75af3f70cc292918a013b280ed06426b6fa98`.
The genesis helper and embedded lifecycle reuse pinned upstream Zakura
`24a17b3f0e7d88513688d607054f018ab6f15af2`.
The fingerprint and optional rule diagnostics are product adaptations needed to
identify separately configured SLH chains. They add no research runtime dependency.
