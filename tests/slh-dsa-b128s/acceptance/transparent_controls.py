#!/usr/bin/env python3
"""HUMAN ONLY: genuine transparent quorum, substitution and lifecycle controls.

Reuse product lifecycle/native fixture helpers and pinned research relay/history
controls. Importing this file starts no process and performs no signing.
"""
import argparse
import hashlib
from pathlib import Path
import re

from common import (ROOT, CONTRACT, AcceptanceError, canonical, common_tip, read_json,
                    require, sha256, source_state, validate_build, wait_for, write_json, zat)
from generate_transactions import host_call, producer_identity, randomizer, seed, signer_call
from lifecycle_controls import rejection_unchanged, single_artifact, utxos
from node_live import authenticated_outputs, policy, reconcile_saved, restart_with_backups
from nodes import Network, SLH_HEIGHT, authenticate_coinbase

CLASSICAL_SCRIPT = (("could not verify a transparent script",),
                    ("non-standard transparent inputs",))
STANDARD_SIZE = (("scriptsig", "standardness limit"),)
ACTIVE_MIXED = (("active slh transparent inputs cannot be mixed",),)
AUTHORIZATION_RELAY = {
    "missing-classical-quorum": CLASSICAL_SCRIPT,
    "slh-on-classical": STANDARD_SIZE,
    "classical-on-slh": (("non-standard transparent inputs",),),
    "corrupt-slh": (("experimental slh-dsa-b-128s authorization failed", ": signature"),),
}


def relay_match(message, pattern):
    # Native rejection names are snake_case: ": signature" is not ": signature_count".
    return all(re.search(re.escape(part) + r"(?![_a-z])", message) for part in pattern)


def reject_relay(node, raw, patterns):
    reply = node.response("sendrawtransaction", raw)
    error = reply.get("error")
    require(type(error) is dict and type(error.get("code")) is int
            and error["code"] in (-1, -25) and type(error.get("message")) is str,
            "transparent_relay_error_schema")
    # The pin maps verifier results to Verify=-25; immediate queue failures use
    # Misc=-1. A code alone or an unrelated RPC failure never proves rejection.
    message = error["message"].lower()
    require(any(relay_match(message, pattern) for pattern in patterns),
            "transparent_wrong_relay_rejection")
    return {"code": error["code"], "error_sha256": hashlib.sha256(canonical(error)).hexdigest(),
            "matched_reason": next(list(p) for p in patterns if relay_match(message, p))}


def proposal_rejection(value, reason):
    require(type(value) is str, "transparent_missing_proposal_rejection")
    if reason == "mixed":
        matched = "experimentalslhdsab128smixedinputs" in value
    elif reason == "script":
        matched = re.search(r"(?:^|-)script(?:-|$)", value) is not None
    else:
        require(reason in ("encoding", "signature"), "transparent_unknown_rejection")
        # Proposal names are kebab-cased: SignatureCount is "signature-count".
        matched = ("experimentalslhdsab128s" in value and re.search(
            r"(?:^|-)reason-" + reason + r"(?!-count)(?:-|$)", value) is not None)
    require(matched, "transparent_wrong_proposal_rejection")


def fee(transaction, parent_values):
    values = [output["value_zat"] for output in transaction["outputs"]]
    require(all(type(value) is int and value >= 0 for value in [*values, *parent_values]),
            "transparent_value_schema")
    result = sum(parent_values) - sum(values)
    require(result > 0, "transparent_fee")
    return result


def authorization_variants(args, artifacts, classical, slh):
    variants = []
    for name, original, donor in (
            ("missing-classical-quorum", classical, None),
            ("slh-on-classical", classical, slh),
            ("classical-on-slh", slh, classical),
            ("corrupt-slh", slh, None)):
        variant = host_call(args.host, "control-authorization", recipe={
            "transaction_hex": original["transaction_hex"], "input_index": 0, "variant": name,
            "donor_transaction_hex": donor["transaction_hex"] if donor else None})
        require(variant["variant"] == name and variant["outputs"] == original["outputs"]
                and variant["transaction_hex"] != original["transaction_hex"]
                and variant["positive_transaction_sha256"] == original["transaction_sha256"]
                and variant["positive_auth_digest"] != variant["auth_digest"],
                "transparent_authorization_correspondence")
        if "txid" in original:
            require(variant["txid"] == original["txid"], "transparent_variant_changed_txid")
        if "auth_digest" in original:
            require(variant["positive_auth_digest"] == original["auth_digest"],
                    "transparent_positive_identity_changed")
        original["txid"] = variant["txid"]
        original["auth_digest"] = variant["positive_auth_digest"]
        write_json(artifacts / (name + ".json"), variant)
        variants.append(variant)
    require(variants[0]["txid"] == variants[1]["txid"]
            and variants[2]["txid"] == variants[3]["txid"], "transparent_same_txid_pairs")
    return variants


def mixed_artifacts(args, artifacts, funding, keys, expiry):
    public = next(iter(keys))
    parent = {"parent_hex": funding["transaction_hex"]}
    results = []
    for kind, other_index in (("multisig", 2), ("unsupported51", 4), ("unsupported52", 5)):
        for first in (True, False):
            name = f"mixed-{kind}-{int(first)}"
            recipe = {"kind": kind, "transaction_version": args.version, "expiry_height": expiry,
                "classical_first": first, "classical": {**parent, "output_index": other_index},
                "slh": {**parent, "output_index": 3}, "public_key_hex": public, "fee_zat": 100_000}
            prepared = host_call(args.host, "mixed-prepare", recipe=recipe)
            require(prepared["slh_input_index"] == int(first) and prepared["public_key_hex"] == public,
                    "transparent_mixed_signing_context")
            signed = signer_call(args.signer, "sign", secret_key=keys[public],
                message=prepared["message_hex"], randomizer=randomizer(name, int(first), 0))
            require(signed["public_key"] == public, "transparent_mixed_signer")
            tx = host_call(args.host, "mixed-assemble", recipe=recipe, record={"signer_index": 0,
                "public_key_hex": public, "signature_hex": signed["signature"]})
            require(tx["message_hex"] == prepared["message_hex"] and tx["slh_checks"] == 1
                    and tx["ecdsa_checks"] == (2 if kind == "multisig" else 0)
                    and fee(tx, [3_000_000, 3_000_000]) == 100_000,
                    "transparent_mixed_assembly")
            write_json(artifacts / (name + ".json"), tx)
            results.append({"name": name, "kind": kind, "classical_first": first,
                            "indexes": [other_index, 3], "transaction": tx})
    return results


class Controls:
    """One disposable run, using the existing native block and node helpers."""
    def __init__(self, args, artifacts, network):
        self.args, self.artifacts, self.network = args, artifacts, network
        self.nonce = 1000

    def block(self, label, transactions, fees):
        require(len(transactions) == len(fees), "transparent_block_fees")
        template = self.network.a.rpc("getblocktemplate")
        require(template["transactions"] == [], "transparent_empty_template_required")
        self.nonce += 1
        candidate = host_call(self.args.host, "control-block", recipe={"template": template,
            "kind": "multisig", "nonce": self.nonce,
            "transactions": [{"transaction_hex": tx["transaction_hex"], "fee_zat": value}
                             for tx, value in zip(transactions, fees)]})
        require(candidate["txids"] == [tx["txid"] for tx in transactions]
                and candidate["aggregate_fee_zat"] == sum(fees), "transparent_block_correspondence")
        write_json(self.artifacts / (label + "-block.json"), candidate)
        return candidate

    def reject(self, label, tx, value, parent, indexes, relay_patterns, consensus_reason):
        before = common_tip(self.network.nodes)
        snapshot = utxos(self.network.nodes, parent, indexes)
        require(all(row is not None for row in snapshot), "transparent_control_parent_missing")
        relay = rejection_unchanged(self.network,
            lambda: [reject_relay(node, tx["transaction_hex"], relay_patterns) for node in self.network.nodes],
            before, parent, indexes, snapshot)
        require(all(tx["txid"] not in node.rpc("getrawmempool") for node in self.network.nodes),
                "transparent_invalid_mempool_entry")
        candidate = self.block(label, [tx], [value])
        def reject_blocks():
            rows = []
            for node in self.network.nodes:
                proposal = node.rpc("getblocktemplate", {"mode": "proposal", "data": candidate["block_hex"]})
                proposal_rejection(proposal, consensus_reason)
                submitted = node.rpc("submitblock", candidate["block_hex"])
                require(submitted == "rejected", "transparent_invalid_block_accepted")
                rows.append({"proposal": proposal, "submitblock": submitted})
            return rows
        rejected = rejection_unchanged(self.network, reject_blocks, before, parent, indexes, snapshot)
        return {"label": label, "txid": tx["txid"], "tip": before, "relay": relay,
                "blocks": rejected, "parents_present": True, "tip_and_utxos_unchanged": True}

    def accept(self, label, transactions, fees, *, publish=True):
        before = common_tip(self.network.nodes)
        candidate = self.block(label, transactions, fees)
        for node in self.network.nodes:
            require(node.rpc("getblocktemplate", {"mode": "proposal", "data": candidate["block_hex"]}) is None,
                    "transparent_positive_proposal_rejected")
        require(common_tip(self.network.nodes) == before, "transparent_proposal_changed_tip")
        if publish:
            require(self.network.a.rpc("submitblock", candidate["block_hex"]) is None,
                    "transparent_positive_block_rejected")
            wait_for(lambda: all(node.tip() == (candidate["height"], candidate["block_hash"])
                                 for node in self.network.nodes), "transparent_positive_peer_tip")
            for node in self.network.nodes:
                require(node.rpc("getblock", candidate["block_hash"], 0) == candidate["block_hex"]
                        and node.rpc("getblock", candidate["block_hash"], 1)["tx"][1:]
                            == [tx["txid"] for tx in transactions], "transparent_positive_block_bytes")
                for tx in transactions:
                    saved = node.rpc("getrawtransaction", tx["txid"], 1)
                    require(saved["hex"] == tx["transaction_hex"] and saved["confirmations"] > 0,
                            "transparent_positive_transaction_bytes")
            for tx in transactions:
                authenticated_outputs(self.network.nodes, tx["txid"], tx["outputs"])
        return {"block_hash": candidate["block_hash"], "height": candidate["height"],
                "txids": candidate["txids"], "published": publish, "exact_bytes": True}

    def mixed(self, label, mixed, funding, *, active):
        return [self.reject(label + "-" + case["name"], case["transaction"], 100_000,
                funding["txid"], case["indexes"], ACTIVE_MIXED if active else STANDARD_SIZE,
                "mixed" if active else "script") for case in mixed]

    def authorization(self, label, variants, funding):
        return [self.reject(label + "-" + case["variant"], case,
                20_000 if index < 2 else 1_000_000, funding["txid"], [0 if index < 2 else 1],
                AUTHORIZATION_RELAY[case["variant"]], case["expected_consensus_reason"])
                for index, case in enumerate(variants)]


def mine_to(network, height):
    require(network.a.tip()[0] <= height, "transparent_mining_target")
    while network.a.tip()[0] < height:
        network.mine(min(25, height - network.a.tip()[0]))


def rollback(network, block_hash, height):
    removed = [network.a.rpc("getblockhash", index)
               for index in range(height + 1, common_tip(network.nodes)["height"] + 1)]
    require(removed and removed[0] == block_hash, "transparent_rollback_block")
    for node in network.nodes:
        node.rpc("invalidateblock", block_hash)
    wait_for(lambda: all(node.tip()[0] == height for node in network.nodes), "transparent_rollback_tip")
    # Existing disposable restart clears local relay retries for a new negative
    # window; it does not change upstream reset/retry behavior or assert barriers.
    return restart_with_backups(network, excluded=removed)


def execute(args, artifacts, receipt):
    info = host_call(args.host, "classical-info", kind="multisig")
    require(info["ecdsa_checks"] == 2, "transparent_real_classical_quorum")
    producer, _ = producer_identity(args.root, args.host, args.signer)
    generated = signer_call(args.signer, "keygen", seed=seed(0))
    keys = {generated["public_key"]: generated["secret_key"]}
    try:
        _, script = policy(list(keys), 1)
        with Network(args.node, artifacts, info["address"]) as network:
            control = Controls(args, artifacts, network)
            mine_to(network, SLH_HEIGHT - 3)
            parent = authenticate_coinbase(network.nodes, 1, info["script_hex"])
            funding = host_call(args.host, "control-funding", recipe={"kind": "multisig",
                "transaction_version": args.version, "lock_time": 0, "expiry_height": 210,
                "parent_hex": parent["parent_hex"], "output_index": parent["output_index"],
                "outputs": [{"value_zat": 3_000_000, "script_hex": raw} for raw in
                    (info["script_hex"], script, info["script_hex"], script, "51" + script[2:], "52" + script[2:])],
                "fee_zat": 20_000})
            write_json(artifacts / "funding.json", funding)
            before = common_tip(network.nodes)
            snapshot = utxos(network.nodes, parent["txid"], [parent["output_index"]])
            require(snapshot[0] is not None
                    and fee(funding, [zat(snapshot[0]["value"])]) == 20_000,
                    "transparent_funding_fee")
            receipt["preactivation_funding_relay"] = rejection_unchanged(network,
                lambda: [reject_relay(node, funding["transaction_hex"], (("uses slh before activation",),))
                         for node in network.nodes], before, parent["txid"], [parent["output_index"]], snapshot)
            receipt["preactivation_funding_block"] = control.accept("preactivation-funding", [funding], [20_000])
            require(network.a.tip()[0] == 108, "transparent_pre_activation_funding_height")
            mine_to(network, SLH_HEIGHT)
            classical = host_call(args.host, "classical-spend", recipe={"kind": "multisig",
                "transaction_version": args.version, "lock_time": 0, "expiry_height": 210,
                "parent_hex": funding["transaction_hex"], "output_index": 0,
                "outputs": [{"value_zat": 1_000_000, "script_hex": info["script_hex"]}], "fee_zat": 20_000})
            slh_artifact = single_artifact(args, keys, producer, funding["txid"], 1, 210, "transparent-slh-positive")
            write_json(artifacts / "slh-positive.json", slh_artifact)
            slh = {name: slh_artifact[name] for name in ("transaction_hex", "transaction_sha256", "outputs")}
            variants = authorization_variants(args, artifacts, classical, slh)
            write_json(artifacts / "classical-positive.json", classical)
            require(fee(classical, [3_000_000]) == 20_000 and fee(slh, [3_000_000]) == 1_000_000,
                    "transparent_positive_fees")
            mixed = mixed_artifacts(args, artifacts, funding, keys, 210)
            receipt["producer"] = producer
            receipt["positive_preflight"] = control.accept("positive-preflight", [classical, slh],
                                                           [20_000, 1_000_000], publish=False)
            receipt["authorization"] = control.authorization("active", variants, funding)
            receipt["mixed_active"] = control.mixed("active", mixed, funding, active=True)

            dust_parent = authenticate_coinbase(network.nodes, 2, info["script_hex"])
            dust = host_call(args.host, "classical-spend", recipe={"kind": "multisig",
                "transaction_version": args.version, "lock_time": 0, "expiry_height": 210,
                "parent_hex": dust_parent["parent_hex"], "output_index": dust_parent["output_index"],
                "outputs": [{"value_zat": 2402, "script_hex": script}], "fee_zat": 20_000})
            write_json(artifacts / "dust.json", dust)
            before = common_tip(network.nodes)
            snapshot = utxos(network.nodes, dust_parent["txid"], [dust_parent["output_index"]])
            require(snapshot[0] is not None
                    and fee(dust, [zat(snapshot[0]["value"])]) == 20_000,
                    "transparent_dust_fee")
            receipt["dust_relay"] = rejection_unchanged(network,
                lambda: [reject_relay(node, dust["transaction_hex"], (("below the slh dust threshold",),))
                         for node in network.nodes], before, dust_parent["txid"], [dust_parent["output_index"]], snapshot)
            receipt["dust_block"] = control.accept("dust", [dust], [20_000])
            together = control.accept("classical-and-slh", [classical, slh], [20_000, 1_000_000])
            receipt["separate_transactions_same_block"] = together
            require(utxos(network.nodes, funding["txid"], [0, 1]) == [None, None],
                    "transparent_positive_parents_not_spent")
            # Variant consistency cannot catch a uniformly wrong host identity; bind it to both nodes.
            require(all(node.rpc("getrawtransaction", tx["txid"], 1).get("authdigest") == tx["auth_digest"]
                        for node in network.nodes for tx in (classical, slh)),
                    "transparent_positive_auth_digest")

            receipt["reorg_restart"] = rollback(network, together["block_hash"], together["height"] - 1)
            authenticated_outputs(network.nodes, funding["txid"], funding["outputs"])
            receipt["authorization_after_reorg"] = control.authorization("reorg", variants, funding)
            receipt["mixed_after_reorg"] = control.mixed("reorg", mixed, funding, active=True)
            saved = [{"txid": tx["txid"], "raw": tx["transaction_hex"]} for tx in (classical, slh)]
            receipt["same_txid_reentry"] = reconcile_saved(network, saved, 1)

            boundary = network.a.rpc("getblockhash", SLH_HEIGHT - 1)
            receipt["activation_rollback_restart"] = rollback(network, boundary, SLH_HEIGHT - 2)
            authenticated_outputs(network.nodes, funding["txid"], funding["outputs"])
            receipt["mixed_before_activation"] = control.mixed("inactive", mixed, funding, active=False)
            network.mine()  # Tip109: candidate110 is active, with original funding still present.
            receipt["mixed_reactivation"] = control.mixed("reactivated", mixed, funding, active=True)
            receipt["authorization_reactivation"] = control.authorization("reactivated", variants, funding)
            receipt["reactivated_saved_bytes"] = reconcile_saved(network, saved, 1)
            receipt["final_tip"] = common_tip(network.nodes)
            receipt["positive_identities"] = [{"txid": tx["txid"], "auth_digest": tx["auth_digest"]}
                                               for tx in (classical, slh)]
        receipt["nodes"] = network.metadata()
    finally:
        keys.clear()  # All fixture keys are public; this is not an erasure claim.


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    for role in ("node", "host", "signer"):
        result.add_argument("--" + role, type=Path, required=True)
        result.add_argument("--" + role + "-build", type=Path, required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    result.add_argument("--version", type=int, choices=(5, 6), required=True)
    return result


def main(args):
    args.root = ROOT
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {"schema_version": 1, "contract": CONTRACT, "complete": False,
               "version": args.version, "classical": "multisig",
               "scope": "functional RPC controls; no daemon primitive-entry or queue-barrier claims"}
    write_json(artifacts / "execution.json", receipt)
    try:
        receipt["builds"] = {role: validate_build(read_json(getattr(args, role + "_build")),
            getattr(args, role), "node-slh" if role == "node" else role, runtime_required=role == "node")
            for role in ("node", "host", "signer")}
        before = source_state()
        execute(args, artifacts, receipt)
        require(source_state() == before, "source_changed_during_controls")
        for role, build in receipt["builds"].items():
            require(sha256(getattr(args, role)) == build["binary_sha256"], "binary_changed_during_controls")
        receipt["complete"] = True
    except BaseException as error:
        receipt["failure"] = str(error) if isinstance(error, AcceptanceError) else type(error).__name__
        raise
    finally:
        receipt["artifacts"] = [{"path": str(path.relative_to(artifacts)), "sha256": sha256(path)}
            for path in sorted(artifacts.rglob("*")) if path.is_file() and not path.is_symlink()
            and path != artifacts / "execution.json" and "state" not in path.relative_to(artifacts).parts]
        write_json(artifacts / "execution.json", receipt, fresh=False)


if __name__ == "__main__":
    main(parser().parse_args())
