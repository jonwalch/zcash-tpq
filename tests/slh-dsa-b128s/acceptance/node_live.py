#!/usr/bin/env python3
"""HUMAN ONLY: actual SLH transaction budgets, template budgets and lifecycle.

Public deterministic conformance keys only; signing/transport reuse the existing
isolated fixture tool. The RPC driver independently resolves the actual parents.
No corpus byte or expected answer is changed. No timing/resource claims.
"""
import argparse
import hashlib
from pathlib import Path

from common import (CONTRACT, AcceptanceError, common_tip, read_json, require, sha256,
                    source_state, validate_build, wait_for, write_json, zat)
from generate_transactions import (host_call, producer_identity, randomizer, seed, signer_call)
from nodes import Network, ManagedNode, NU7_HEIGHT, SLH_HEIGHT, TX_LIMIT, BLOCK_LIMIT, authenticate_coinbase, port
from wallet_live import key_commitment


def policy(public, threshold):
    commitments = sorted(key_commitment(bytes.fromhex(key)) for key in public)
    descriptor = bytes([1, 247, threshold, len(public)]) + b"".join(commitments)
    script = "5320" + hashlib.sha256(
        b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/policy/v1\0" + descriptor).hexdigest() + "c0"
    return descriptor.hex(), script


def signed_artifact(args, keys, producer, txid, indexes, values, shapes, version, expiry, case):
    public = list(keys)
    recipe = {"case_id": case, "network": "Regtest", "transaction_version": version,
        "lock_time": 0, "expiry_height": expiry,
        "inputs": [{"outpoint": {"txid_display_hex": parent, "index": index},
            "sequence": 0xfffffffe, "value_zat": value, "threshold": threshold,
            "public_keys_hex": public[:participants], "signer_indices": list(range(threshold))}
            for parent, index, value, (threshold, participants) in
            zip(txid if isinstance(txid, list) else [txid] * len(indexes), indexes, values, shapes)],
        "outputs": [{"value_zat": sum(values) - 1_000_000, "input_policy_index": 1}]}
    prepared = host_call(args.host, "prepare", recipe=recipe)
    records = []
    for index, previous in enumerate(prepared["inputs"]):
        shares = []
        for entry in previous["signers"]:
            public_key, slot = entry["public_key_hex"], entry["signer_index"]
            signed = signer_call(args.signer, "sign", secret_key=keys[public_key],
                message=previous["message_hex"], randomizer=randomizer(case, index, slot))
            require(signed["public_key"] == public_key, "fixture_signing_key")
            shares.append({"signer_index": slot, "public_key_hex": public_key,
                           "signature_hex": signed["signature"]})
        records.append(shares)
    artifact = host_call(args.host, "assemble", recipe=recipe, records=records, producer=producer)
    require(artifact["expected"]["signature_checks"] == sum(threshold for threshold, _ in shapes)
            and artifact["expected"]["native_authorization"] == "accept", "fixture_native_authorization")
    return artifact


def authenticated_outputs(nodes, txid, outputs):
    common_tip(nodes)
    for index, expected in enumerate(outputs):
        observed = [node.rpc("gettxout", txid, index, False) for node in nodes]
        require(all(output is not None and not output["coinbase"] and output["confirmations"] >= 1
                    and output["scriptPubKey"]["hex"] == expected["script_hex"]
                    and zat(output["value"]) == expected["value_zat"] for output in observed),
                "authenticated_funding_output")


def transaction_state(node, transaction):
    """Bind saved bytes before interpreting best-chain or mempool presence."""
    reply = node.response("getrawtransaction", transaction["txid"], 1)
    error = reply.get("error")
    if error is not None:
        require(type(error) is dict and error.get("code") == -5 and
                "not found" in error.get("message", "").lower(), "saved_transaction_lookup")
        return "absent"
    value = reply.get("result")
    require(type(value) is dict and value.get("hex") == transaction["raw"], "saved_transaction_bytes")
    if value.get("confirmations", 0) > 0:
        return "confirmed"
    # Side-chain transactions are also returned by getrawtransaction. Their
    # bytes alone do not establish active-chain acceptance or mempool presence.
    return "mempool" if transaction["txid"] in node.rpc("getrawmempool") else "absent"


def reconcile_saved(network, transactions, max_blocks):
    """Respect upstream rejected-transaction retries across activation changes."""
    common_tip(network.nodes)
    initial = {}
    for transaction in transactions:
        state = transaction_state(network.a, transaction)
        initial[transaction["txid"]] = state
        if state == "absent":
            reply = network.a.response("sendrawtransaction", transaction["raw"])
            # A retry can enter the mempool between lookup and explicit submit.
            # Only authenticated presence of these exact bytes excuses refusal.
            require(reply.get("error") is None and reply.get("result") == transaction["txid"]
                    or transaction_state(network.a, transaction) != "absent", "saved_transaction_submission")
    wait_for(lambda: all(transaction_state(node, tx) != "absent"
                        for node in network.nodes for tx in transactions), "saved_transaction_relay")
    mined = []
    for _ in range(max_blocks):
        if all(transaction_state(node, tx) == "confirmed" for node in network.nodes for tx in transactions):
            break
        mined.extend(network.mine())
    require(all(transaction_state(node, tx) == "confirmed" for node in network.nodes for tx in transactions),
            "saved_transaction_confirmation")
    return {"initial_states": initial, "mined_blocks": mined}


def restart_with_backups(network, *, excluded=()):
    """Observe ordinary backup completion/removal before an exact-tip reopen."""
    # These existing lifecycle helpers reuse this module's public fixtures, so
    # import after initialization rather than introducing an import cycle.
    from shielded_spend_controls import backup_ready
    backup = backup_ready(network, excluded=excluded)
    return {**network.restart(), "backup": backup}


def restart_replayed(node, expected):
    """Use the research history tip-backup check for the longer replay case."""
    from lifecycle_controls import backup_tip, namespace
    target = (expected["height"], expected["hash"])
    require(node.tip() == target, "replay_backup_tip_changed")
    backup = backup_tip(node, node.directory / "state", namespace((SLH_HEIGHT, TX_LIMIT, BLOCK_LIMIT)))
    node.stop()
    node.start()
    require(node.tip() == target, "replay_restart")
    return backup


def execute(args, artifacts, receipt):
    info = host_call(args.host, "classical-info", kind=args.classical)
    producer, inventories = producer_identity(args.root, args.host, args.signer)
    receipt["producer"] = producer
    keys = {}
    try:
        for index in range(15):
            generated = signer_call(args.signer, "keygen", seed=seed(index))
            keys[generated["public_key"]] = generated["secret_key"]
        require(len(keys) == 15, "fixture_public_keys")
        public = list(keys)
        _, maximum = policy(public, 15)
        _, single = policy(public[:1], 1)
        _, pair = policy(public[:3], 2)
        with Network(args.node, artifacts, info["address"]) as network:
            receipt["bootstrap_tip"] = network.bootstrap()
            parent = authenticate_coinbase(network.nodes, 1, info["script_hex"])
            scripts = [script for _ in range(5) for script in (maximum, single)] + [maximum, pair]
            funding = host_call(args.host, "classical-spend", recipe={"kind": args.classical,
                "transaction_version": args.version, "lock_time": 0,
                "expiry_height": network.a.tip()[0] + 20, "parent_hex": parent["parent_hex"],
                "output_index": parent["output_index"],
                "outputs": [{"value_zat": 3_000_000, "script_hex": script} for script in scripts],
                "fee_zat": 20_000})
            require(network.a.rpc("sendrawtransaction", funding["transaction_hex"]) == funding["txid"],
                    "classical_funding_submission")
            wait_for(lambda: funding["txid"] in network.b.rpc("getrawmempool"), "classical_relay")
            network.mine()
            authenticated_outputs(network.nodes, funding["txid"], funding["outputs"][:-1])
            write_json(artifacts / "funding.json", funding)
            before = common_tip(network.nodes)
            transactions = []
            for index in range(6):
                shapes = [(15, 15), (1, 1)] if index < 5 else [(15, 15), (2, 3)]
                artifact = signed_artifact(args, keys, producer, funding["txid"], [2 * index, 2 * index + 1],
                    [3_000_000, 3_000_000], shapes, args.version, before["height"] + 20, f"budget-{index}")
                write_json(artifacts / f"budget-{index}.json", artifact)
                if index == 5:
                    receipt["transaction_excess"] = network.a.reject("sendrawtransaction", "limit of 16",
                                                                      artifact["transaction_hex"])
                    require(network.a.tip() == (before["height"], before["hash"]), "rejection_changed_tip")
                else:
                    txid = network.a.rpc("sendrawtransaction", artifact["transaction_hex"])
                    transactions.append({"txid": txid, "raw": artifact["transaction_hex"],
                                         "checks": 16, "artifact": artifact})
            wait_for(lambda: all(tx["txid"] in network.b.rpc("getrawmempool") for tx in transactions),
                     "budget_peer_relay", 60)
            template = network.a.rpc("getblocktemplate")
            selected = [tx for tx in transactions if tx["txid"] in {row["hash"] for row in template["transactions"]}]
            require(len(selected) == 4 and sum(tx["checks"] for tx in selected) == BLOCK_LIMIT,
                    "template_exact_slh_block_budget")
            require(all(any(row["hash"] == tx["txid"] and row["data"] == tx["raw"]
                            for row in template["transactions"]) for tx in selected), "template_saved_bytes")
            first_block = network.mine()[0]
            mined = set(network.a.rpc("getblock", first_block, 1)["tx"])
            require(len(mined.intersection(tx["txid"] for tx in transactions)) == 4,
                    "mined_exact_block_budget")
            receipt["block_budget"] = {"limit": BLOCK_LIMIT, "included": [tx["txid"] for tx in selected],
                "block_hash": first_block, "selected_checks": 64,
                "mined": sorted(mined.intersection(tx["txid"] for tx in transactions)),
                "consensus_excess_block_tested": False}
            second_block = network.mine()[0]
            require(all(network.a.rpc("getrawtransaction", tx["txid"], 1)["confirmations"] >= 1
                        for tx in transactions), "remaining_budget_transaction")
            # Reuse History's actual invalidation/re-entry mechanism. Both nodes
            # explicitly invalidate the same accepted payment branch.
            for node in network.nodes:
                node.rpc("invalidateblock", first_block)
            wait_for(lambda: all(node.tip() == (before["height"], before["hash"]) for node in network.nodes),
                     "reorg_payment_tip")
            authenticated_outputs(network.nodes, funding["txid"], funding["outputs"][:-1])
            for tx in transactions:
                if tx["txid"] not in network.a.rpc("getrawmempool"):
                    require(network.a.rpc("sendrawtransaction", tx["raw"]) == tx["txid"], "reorg_resubmission")
            replacement = network.mine(2)
            require(first_block not in replacement and second_block not in replacement, "replacement_branch")
            for tx in transactions:
                for node in network.nodes:
                    require(transaction_state(node, tx) == "confirmed", "reorg_confirmation")
            receipt["reorg"] = {"fork": before, "old_blocks": [first_block, second_block],
                                "replacement_blocks": replacement}
            receipt["restart"] = restart_with_backups(network, excluded=(first_block, second_block))
            # Candidate-height rules use tip+1. Tip103 is below the NU7
            # candidate gate; tip104 is the boundary for candidate105.
            rollback = network.a.rpc("getblockhash", NU7_HEIGHT - 1)
            removed = [network.a.rpc("getblockhash", height)
                       for height in range(NU7_HEIGHT - 1, network.a.tip()[0] + 1)]
            for node in network.nodes:
                node.rpc("invalidateblock", rollback)
            wait_for(lambda: all(node.tip()[0] == NU7_HEIGHT - 2 for node in network.nodes),
                     "rollback_below_nu7")
            require(all(tx["txid"] not in node.rpc("getrawmempool")
                        for node in network.nodes for tx in transactions), "stale_slh_mempool_metadata")
            # Clear pre-rollback relay retries by restarting our disposable nodes;
            # the subsequent negative controls deliberately retain retry behavior.
            receipt["below_nu7_restart"] = restart_with_backups(network, excluded=removed)
            nu7_parent = authenticate_coinbase(network.nodes, 2, info["script_hex"])
            require((nu7_parent["txid"], nu7_parent["output_index"]) !=
                    (parent["txid"], parent["output_index"]), "nu7_control_distinct_parent")
            nu7_control = host_call(args.host, "classical-spend", recipe={"kind": args.classical,
                "transaction_version": args.version, "lock_time": 0, "expiry_height": before["height"] + 20,
                "parent_hex": nu7_parent["parent_hex"], "output_index": nu7_parent["output_index"],
                "outputs": [{"value_zat": 1_000_000, "script_hex": info["script_hex"]}], "fee_zat": 20_000})
            receipt["nu7_rollback"] = network.a.reject("sendrawtransaction", "incorrect consensus branch id",
                                                      nu7_control["transaction_hex"])
            network.mine()
            receipt["nu7_candidate_boundary"] = common_tip(network.nodes)
            network.mine(SLH_HEIGHT - 2 - network.a.tip()[0])
            receipt["gate_rollback"] = network.a.reject("sendrawtransaction", "before activation",
                                                        funding["transaction_hex"])
            network.mine(2)
            receipt["reactivated_funding"] = reconcile_saved(network,
                [{"txid": funding["txid"], "raw": funding["transaction_hex"]}], 1)
            authenticated_outputs(network.nodes, funding["txid"], funding["outputs"][:-1])
            receipt["reactivated_slh"] = reconcile_saved(network, transactions, 2)
            if args.finalized_history:
                # The pin fixes MAX_BLOCK_REORG_HEIGHT=1000. This is a human
                # workload; never run it as part of mocked/offline verification.
                target = network.a.tip()[0] + 1001
                while network.a.tip()[0] < target:
                    network.mine(min(25, target - network.a.tip()[0]))
                original_tip = common_tip(network.nodes)
                replay = ManagedNode(args.node, artifacts, "node-replay", info["address"], port())
                digest = hashlib.sha256()
                try:
                    replay.start()
                    require(replay.tip()[0] == 0, "fresh_replay_database")
                    for height in range(1, original_tip["height"] + 1):
                        block_hash = network.a.rpc("getblockhash", height)
                        raw = network.a.rpc("getblock", block_hash, 0)
                        require(replay.rpc("submitblock", raw) is None, "replay_block_rejection")
                        wait_for(lambda: replay.tip() == (height, block_hash), "replay_tip")
                        require(replay.rpc("getblock", block_hash, 0) == raw, "replay_block_bytes")
                        digest.update(bytes.fromhex(block_hash))
                    for tx in transactions:
                        original = network.a.rpc("gettxout", tx["txid"], 0, False)
                        require(original == replay.rpc("gettxout", tx["txid"], 0, False), "replay_utxo")
                    # Reuse the research history driver's ordinary tip-backup
                    # observation, without widening the short crash-case bound.
                    receipt["history_restart_backup"] = restart_replayed(replay, original_tip)
                    recovered = signed_artifact(args, keys, producer,
                        [tx["txid"] for tx in transactions[:2]], [0, 0], [5_000_000, 5_000_000],
                        [(1, 1), (1, 1)], args.version, original_tip["height"] + 20, "post-replay")
                    write_json(artifacts / "post-replay.json", recovered)
                    restored_txid = replay.rpc("sendrawtransaction", recovered["transaction_hex"])
                    require(network.a.rpc("sendrawtransaction", recovered["transaction_hex"]) == restored_txid,
                            "post_replay_submission")
                    recovered_block = replay.rpc("generate", 1)[0]
                    block_bytes = replay.rpc("getblock", recovered_block, 0)
                    require(network.a.rpc("submitblock", block_bytes) is None, "post_replay_block")
                    wait_for(lambda: network.a.tip() == network.b.tip() == replay.tip(), "post_replay_peer_tip")
                    for node in [*network.nodes, replay]:
                        require(transaction_state(node, {"txid": restored_txid,
                                    "raw": recovered["transaction_hex"]}) == "confirmed",
                                "post_replay_spend_confirmation")
                    receipt["history"] = {"tip": original_tip, "reorg_window": 1000,
                        "ordered_block_hashes_sha256": digest.hexdigest(), "exact_block_bytes": True,
                        "utxo_equality": True, "post_replay_spend": restored_txid,
                        "finalized_database_layout_asserted": False}
                finally:
                    replay.close()
            receipt["final_tip"] = common_tip(network.nodes)
        receipt["nodes"] = network.metadata()
    finally:
        keys.clear()  # Public fixture material, not an erasure claim.


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    for role in ("node", "host", "signer"):
        result.add_argument("--" + role, type=Path, required=True)
        result.add_argument("--" + role + "-build", type=Path, required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    result.add_argument("--version", type=int, choices=(5, 6), required=True)
    result.add_argument("--classical", choices=("single", "multisig"), default="single")
    result.add_argument("--finalized-history", action="store_true")
    return result


def main(args):
    from common import ROOT
    args.root = ROOT
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {"schema_version": 1, "contract": CONTRACT, "complete": False,
               "version": args.version, "classical": args.classical,
               "finalized_history_requested": args.finalized_history}
    write_json(artifacts / "execution.json", receipt)
    try:
        receipt["builds"] = {role: validate_build(read_json(getattr(args, role + "_build")),
            getattr(args, role), kind, runtime_required=role == "node")
            for role, kind in (("node", "node-slh"), ("host", "host"), ("signer", "signer"))}
        before = source_state()
        execute(args, artifacts, receipt)
        require(source_state() == before, "source_changed_during_acceptance")
        for role in ("node", "host", "signer"):
            require(sha256(getattr(args, role)) == receipt["builds"][role]["binary_sha256"], "binary_changed_during_acceptance")
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
