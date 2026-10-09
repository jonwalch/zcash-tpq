#!/usr/bin/env python3
"""Explicit live operation: real shielded spends, saved bytes and causal anchors.

Selective reuse of pinned pq_ironwood_spend_fixture/live and the product's
shielded/transparent adapters. Importing this module performs no live work.
"""
import argparse
import hashlib
from pathlib import Path
import re

from common import (CONTRACT, AcceptanceError, canonical, common_tip, read_json,
                    require, sha256, source_state, validate_build, wait_for, write_json, zat)
from generate_transactions import MAX_HOST, hex_field, host_call, invoke, randomizer, seed, signer_call
from lifecycle_controls import namespace, utxos
from crash_controls import backup_observed, export_chain
from node_live import authenticated_outputs, policy, reconcile_saved, transaction_state
from nodes import BLOCK_LIMIT, SLH_HEIGHT, TX_LIMIT, Network, authenticate_coinbase
import shielded_controls as outputs
from transparent_controls import Controls, mine_to, reject_relay

POOLS = outputs.POOLS
MAX_HEIGHT = 512
MAX_BLOCK_BYTES = 2 * 1024 * 1024
MAX_HISTORY_BYTES = 12 * 1024 * 1024
GENESIS = "029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"
EXPIRY = 210
PREPARED = outputs.PREPARED | {"withdrawal_zat", "notes", "history_sha256", "anchor_height", "anchor_block_hash", "positive_components"}
FINAL = outputs.FINAL | {"withdrawal_zat"}
NOTE = {"pool", "funding_txid", "funding_height", "funding_output_index", "position", "value_zat",
        "anchor", "nullifier", "commitment", "commitment_count", "real_spend_index"}


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def root_fields(tree, tip, *, inactive_ironwood=False):
    require(type(tree) is dict and type(tree.get("height")) is int
            and (tree["height"], tree.get("hash")) == (tip["height"], tip["hash"]),
            "spend_treestate_context")
    roots = {}
    for pool in POOLS:
        if pool == "ironwood" and inactive_ironwood:
            require(tip["height"] < 104 and tree.get(pool) == {"commitments": {}}, "spend_inactive_ironwood")
            roots[pool] = None
            continue
        root = tree.get(pool, {}).get("commitments", {}).get("finalRoot")
        hex_field(root, 32)
        roots[pool] = root
    return roots


def parent_state(nodes, parent, *, available=True):
    rows = utxos(nodes, parent["txid"], [parent["output_index"]])
    require(len(rows) == 1, "spend_parent_observation")
    row = rows[0]
    if not available:
        require(row is None, "spend_parent_not_consumed")
        return None
    require(type(row) is dict and row.get("confirmations", 0) >= 1
            and zat(row["value"]) == parent["value_zat"]
            and row["scriptPubKey"]["hex"] == parent["script_hex"], "spend_parent_unavailable")
    require(not row.get("coinbase") or row["confirmations"] >= 100, "spend_parent_immature")
    return {"txid": parent["txid"], "index": parent["output_index"],
            "value_zat": zat(row["value"]), "script_hex": row["scriptPubKey"]["hex"]}


def collect_history(nodes, parents, funding):
    """Trusted-node history, not a second consensus or cryptographic verifier."""
    tip = common_tip(nodes)
    require(type(tip["height"]) is int and 0 <= tip["height"] <= MAX_HEIGHT,
            "spend_history_height")
    infos = [node.rpc("getblockchaininfo") for node in nodes]
    require(all(info["chain"] == "test" and (info["blocks"], info["bestblockhash"]) ==
                (tip["height"], tip["hash"]) for info in infos), "spend_history_network")
    trees = [node.rpc("z_gettreestate", str(tip["height"])) for node in nodes]
    require(trees[0] == trees[1], "spend_history_tree_disagreement")
    root_fields(trees[0], tip)
    blocks, hashes, total = [], [], 0
    for height in range(tip["height"] + 1):
        names = [node.rpc("getblockhash", height) for node in nodes]
        require(names[0] == names[1] and names[0] not in hashes, "spend_history_hash_disagreement")
        hex_field(names[0], 32)
        require(height != 0 or names[0] == GENESIS, "spend_history_genesis")
        require(height != tip["height"] or names[0] == tip["hash"], "spend_history_tip")
        raws = [node.rpc("getblock", names[0], 0) for node in nodes]
        require(raws[0] == raws[1] and type(raws[0]) is str
                and 0 < len(raws[0]) <= MAX_BLOCK_BYTES * 2 and len(raws[0]) % 2 == 0,
                "spend_history_block_bytes")
        hex_field(raws[0], len(raws[0]) // 2)
        total += len(raws[0])
        require(total <= MAX_HISTORY_BYTES, "spend_history_size")
        headers = [node.rpc("getblock", names[0], 1) for node in nodes]
        require(headers[0] == headers[1] and headers[0]["hash"] == names[0]
                and headers[0]["height"] == height
                and (height == 0 or headers[0]["previousblockhash"] == hashes[-1]),
                "spend_history_linkage")
        hashes.append(names[0]); blocks.append(raws[0])
    for parent in parents:
        parent_state(nodes, parent)
    for tx in funding:
        for node in nodes:
            saved = node.rpc("getrawtransaction", tx["txid"], 1)
            require(saved["hex"] == tx["transaction_hex"] and saved.get("confirmations", 0) > 0
                    and saved["blockhash"] in hashes
                    and tx["txid"] in node.rpc("getblock", saved["blockhash"], 1)["tx"],
                    "spend_note_funding_history")
    require(common_tip(nodes) == tip, "spend_history_changed")
    for node in nodes:
        require(node.rpc("z_gettreestate", str(tip["height"])) == trees[0], "spend_history_tree_changed")
    history = {"blocks": blocks, "treestate": trees[0]}
    require(len(canonical(history)) <= MAX_HISTORY_BYTES, "spend_history_size")
    return history


def proof_call(host, op, recipe):
    require(op in ("shielded-spend-funding", "shielded-spend-prepare"), "spend_proof_operation")
    request = dict(schema_version=1, contract=CONTRACT, public_fixture=True, op=op, recipe=recipe)
    reply = invoke(host, request, MAX_HOST, timeout=1800)
    require(type(reply) is dict and set(reply) == {
        "schema_version", "contract", "public_fixture", "op", "ok", "result"}
        and type(reply["schema_version"]) is int and reply["schema_version"] == 1
        and reply["contract"] == CONTRACT and reply["public_fixture"] is True
        and reply["op"] == op and reply["ok"] is True, "spend_host_reply")
    return reply["result"]


def validate_prepared(result, recipe, parent):
    require(type(result) is dict and set(result) == PREPARED, "spend_prepared_schema")
    pools, history = recipe["pools"], recipe["history"]
    tip = {"height": history["treestate"]["height"], "hash": history["treestate"]["hash"]}
    roots = root_fields(history["treestate"], tip)
    expected = dict(material="public-test-only", version=recipe["transaction_version"], pools=pools,
        parent_txid=parent["txid"], parent_index=parent["output_index"], parent_value_zat=parent["value_zat"],
        parent_script_hex=parent["script_hex"],
        parent_transaction_sha256=hashlib.sha256(bytes.fromhex(recipe["parent_hex"])).hexdigest(),
        fee_zat=100000, deposit_zat=0, withdrawal_zat=50000*len(pools),
        orchard_value_zat=50000*int("orchard" in pools), proof_profile="real-spend-post-nu6.3",
        parameters=recipe["sapling_parameters"], history_sha256=digest(history),
        anchor_height=tip["height"], anchor_block_hash=tip["hash"])
    for name, value in expected.items():
        require(result[name] == value and type(result[name]) is type(value), "spend_prepared_identity")
    require(result["positive_pool_valid"] == dict.fromkeys(pools, True)
            and all(value is True for value in result["positive_pool_valid"].values()),
            "spend_positive_verification")
    require(type(result["notes"]) is list and len(result["notes"]) == len(pools), "spend_notes_schema")
    for note, source in zip(result["notes"], recipe["funding_txids"]):
        require(type(note) is dict and set(note) == NOTE and note["pool"] == source["pool"]
                and note["funding_txid"] == source["txid"] and note["value_zat"] == 50000
                and type(note["value_zat"]) is int, "spend_note_identity")
        for field in ("funding_height", "funding_output_index", "position", "commitment_count", "real_spend_index"):
            require(type(note[field]) is int and note[field] >= 0, "spend_note_index")
        require(0 < note["funding_height"] <= tip["height"] and note["position"] < note["commitment_count"]
                and note["real_spend_index"] < 2 and note["funding_output_index"] < 2
                and note["anchor"] == roots[note["pool"]], "spend_note_context")
        for field in ("anchor", "nullifier", "commitment", "funding_txid"):
            hex_field(note[field], 32)
    expected_components = {p: {"spend_auth": [True] * (1 if p == "sapling" else 2),
        "binding": True, "proof": None if p == "sapling" else True} for p in pools}
    require(canonical(result["positive_components"]) == canonical(expected_components), "spend_positive_components")
    positive = result["positive"]
    outputs.wire_check(positive)
    require(positive["outputs"] == [{"output_index": 0, "script_hex": parent["script_hex"],
        "value_zat": parent["value_zat"] + expected["withdrawal_zat"] - expected["fee_zat"]}],
        "spend_value_accounting")
    for pool, field in zip(POOLS, ("sapling_outputs", "orchard_actions", "ironwood_actions")):
        require(positive[field] == (2 if pool in pools else 0), "spend_pool_shape")
    cases = [(p, m) for p in pools for m in ("spend_auth", "binding", "proof")]
    require(type(result["variants"]) is list and len(result["variants"]) == len(cases), "spend_variant_count")
    seen = {positive["auth_digest"]}
    for row, (pool, mutation) in zip(result["variants"], cases):
        outputs.wire_check(row, outputs.WIRE | {"pool", "mutation", "pool_valid", "components"})
        require(row["pool"] == pool and row["mutation"] == mutation
                and row["pool_valid"] == {p: p != pool for p in pools}
                and all(type(v) is bool for v in row["pool_valid"].values()), "spend_variant_verification")
        require(all(row[f] == positive[f] for f in outputs.WIRE - {
            "transaction_hex", "transaction_sha256", "auth_digest"})
            and row["transaction_hex"] != positive["transaction_hex"] and row["auth_digest"] not in seen,
            "spend_variant_effects")
        expected_components = {p: {"spend_auth": [True] * (1 if p == "sapling" else 2),
            "binding": True, "proof": None if p == "sapling" else True} for p in pools}
        if mutation == "spend_auth":
            index = next(note["real_spend_index"] for note in result["notes"] if note["pool"] == pool)
            require(index < len(expected_components[pool]["spend_auth"]), "spend_real_spend_index")
            expected_components[pool]["spend_auth"][index] = False
        elif mutation == "binding":
            expected_components[pool]["binding"] = False
        elif pool != "sapling":
            expected_components[pool]["proof"] = False
        require(canonical(row["components"]) == canonical(expected_components), "spend_variant_components")
        seen.add(row["auth_digest"])
    return result


def finalize(args, recipe, prepared, key, label):
    record = None
    if recipe["authorization"] == "slh":
        signed = signer_call(args.signer, "sign", secret_key=key["secret_key"],
            message=prepared["positive"]["message_hex"], randomizer=randomizer(label, 0, 0))
        require(signed["public_key"] == recipe["public_key_hex"], "spend_signer_identity")
        record = {"signer_index": 0, "public_key_hex": signed["public_key"], "signature_hex": signed["signature"]}
    rows = []
    for unsigned in [prepared["positive"], *prepared["variants"]]:
        row = host_call(args.host, "shielded-spend-finalize", recipe=recipe,
                        transaction_hex=unsigned["transaction_hex"], record=record)
        outputs.wire_check(row, FINAL)
        require(all(row[f] == unsigned[f] for f in outputs.WIRE - {
                    "transaction_hex", "transaction_sha256", "auth_digest"})
                and row["transaction_hex"] != unsigned["transaction_hex"]
                and type(row["slh_checks"]) is int and row["slh_checks"] == int(record is not None)
                and type(row["ecdsa_checks"]) is int and row["ecdsa_checks"] == (0 if record else 2 if recipe["authorization"] == "multisig" else 1)
                and all(type(row[f]) is int and row[f] == prepared[f] for f in ("fee_zat", "withdrawal_zat", "deposit_zat")),
                "spend_finalized_correspondence")
        if "pool" in unsigned:
            row.update(pool=unsigned["pool"], mutation=unsigned["mutation"])
        rows.append(row)
    require(len({row["auth_digest"] for row in rows}) == len(rows), "spend_final_auth_identity")
    return rows[0], rows[1:]


def observe(nodes, parents, spent=()):
    tip = common_tip(nodes)
    roots, values = [], []
    for node in nodes:
        info = node.rpc("getblockchaininfo")
        require((info["blocks"], info["bestblockhash"]) == (tip["height"], tip["hash"]), "spend_observation_tip")
        root = root_fields(node.rpc("z_gettreestate", str(tip["height"])), tip, inactive_ironwood=tip["height"] < 104)
        selected = [p for p in info["valuePools"] if p["id"] in POOLS]
        require(len(selected) == len(POOLS), "spend_value_pools")
        value = {p["id"]: p["chainValueZat"] for p in selected}
        require(set(value) == set(POOLS) and all(type(v) is int and v >= 0 for v in value.values()), "spend_pool_value")
        roots.append(root); values.append(value)
    require(roots[0] == roots[1] and values[0] == values[1], "spend_pool_disagreement")
    coins = [parent_state(nodes, parent, available=index not in spent) for index, parent in enumerate(parents)]
    require(common_tip(nodes) == tip, "spend_observation_changed")
    return {"tip": tip, "roots": roots[0], "values": values[0], "parents": coins}


def same_effect_state(left, right):
    require(all(left[f] == right[f] for f in ("roots", "values", "parents")), "spend_restored_effect_state")


class SpendControls(Controls):
    """Keep existing block construction and exact-byte discipline; narrow new op."""
    def block(self, label, transactions, fees):
        require(len(transactions) == len(fees) and transactions, "spend_block_fees")
        template = self.network.a.rpc("getblocktemplate")
        require(template["transactions"] == [], "spend_empty_template")
        self.nonce += 1
        candidate = host_call(self.args.host, "shielded-spend-block", recipe={"template": template,
            "kind": self.args.classical, "nonce": self.nonce, "transactions": [
                {"transaction_hex": tx["transaction_hex"], "fee_zat": fee} for tx, fee in zip(transactions, fees)]})
        require(candidate["txids"] == [tx["txid"] for tx in transactions]
                and candidate["aggregate_fee_zat"] == sum(fees)
                and candidate["height"] == common_tip(self.network.nodes)["height"] + 1
                and hashlib.sha256(bytes.fromhex(candidate["block_hex"])).hexdigest() == candidate["block_sha256"],
                "spend_candidate_correspondence")
        write_json(self.artifacts / (label + "-block.json"), candidate)
        return candidate


def preflight(control, label, tx, parents, spent=()):
    before = observe(control.network.nodes, parents, spent)
    require(before["tip"]["height"] + 1 <= EXPIRY, "spend_expired")
    block = control.block(label, [tx], [tx["fee_zat"]])
    for node in control.network.nodes:
        require(node.rpc("getblocktemplate", {"mode": "proposal", "data": block["block_hex"]}) is None,
                "spend_positive_proposal")
    require(observe(control.network.nodes, parents, spent) == before, "spend_proposal_changed_state")
    return {"transaction_sha256": tx["transaction_sha256"], "block_sha256": block["block_sha256"],
            "positive_proposals": 2}


def reject(control, label, tx, parents, *, pool=None, state_reason=None, spent=()):
    before = observe(control.network.nodes, parents, spent)
    require(before["tip"]["height"] + 1 <= EXPIRY, "spend_expired")
    require((pool is None) != (state_reason is None), "spend_rejection_kind")
    pools = control.args.pools
    if state_reason:
        require(state_reason in ("anchor", "nullifier"), "spend_state_reason")
        patterns = tuple((f"unknown {p} anchor",) if state_reason == "anchor" else
                         (f"{p} double-spend", "duplicate nullifier") for p in pools)
        proposal_patterns = [f"unknown{p}anchor" if state_reason == "anchor" else f"duplicate{p}nullifier" for p in pools]
    else:
        patterns = (("sapling proof or signature verification failed",),) if pool == "sapling" else (("orchard or ironwood halo2 proof verification failed",),)
        proposal_patterns = ["saplingverificationfailed" if pool == "sapling" else "halo2verificationfailed"]
    relay = [reject_relay(node, tx["transaction_hex"], patterns) for node in control.network.nodes]
    require(observe(control.network.nodes, parents, spent) == before, "spend_relay_changed_state")
    require(all(tx["txid"] not in node.rpc("getrawmempool") for node in control.network.nodes), "spend_rejected_mempool")
    block = control.block(label, [tx], [tx["fee_zat"]])
    proposals = []
    for node in control.network.nodes:
        value = node.rpc("getblocktemplate", {"mode": "proposal", "data": block["block_hex"]})
        require(type(value) is str and any(re.search(r"(?:^|-)" + p + r"(?:-|$)", value.lower())
                for p in proposal_patterns), "spend_wrong_proposal_rejection")
        require(node.rpc("submitblock", block["block_hex"]) == "rejected", "spend_invalid_block_accepted")
        proposals.append(value)
    require(observe(control.network.nodes, parents, spent) == before, "spend_rejection_changed_state")
    require(all(tx["txid"] not in node.rpc("getrawmempool") for node in control.network.nodes), "spend_rejected_mempool")
    return {"label": label, "transaction_sha256": tx["transaction_sha256"], "txid": tx["txid"],
            "auth_digest": tx["auth_digest"], "relay": relay, "proposal": proposals, "unchanged": before}


def authorization_round(control, positive, variants, parents, label):
    rows = [preflight(control, label + "-valid-before", positive, parents)]
    for tx in variants:
        require(tx["txid"] == positive["txid"] and tx["message_hex"] == positive["message_hex"]
                and tx["auth_digest"] != positive["auth_digest"], "spend_negative_identity")
        rows.append(reject(control, label + "-" + tx["pool"] + "-" + tx["mutation"], tx, parents, pool=tx["pool"]))
    rows.append(preflight(control, label + "-valid-after", positive, parents))
    return rows


def publish(network, tx, artifacts, label):
    saved = {"txid": tx["txid"], "raw": tx["transaction_hex"]}
    for node in network.nodes:
        reply = node.response("sendrawtransaction", saved["raw"])
        require(reply.get("error") is None and reply.get("result") == saved["txid"]
                or transaction_state(node, saved) == "mempool", "spend_positive_relay")
        wait_for(lambda: transaction_state(node, saved) == "mempool", "spend_positive_mempool")
        template = node.rpc("getblocktemplate")
        require(any(row["hash"] == saved["txid"] and row["data"] == saved["raw"]
                    for row in template["transactions"]), "spend_positive_template")
    hashes = network.mine()
    require(len(hashes) == 1, "spend_mining_count")
    for node in network.nodes:
        require(transaction_state(node, saved) == "confirmed"
                and saved["txid"] in node.rpc("getblock", hashes[0], 1)["tx"], "spend_mined_membership")
    raws = [node.rpc("getblock", hashes[0], 0) for node in network.nodes]
    require(raws[0] == raws[1], "spend_mined_block_bytes")
    authenticated_outputs(network.nodes, saved["txid"], tx["outputs"])
    block = {"block_hash": hashes[0], "block_hex": raws[0], "block_sha256": hashlib.sha256(bytes.fromhex(raws[0])).hexdigest(),
             "height": common_tip(network.nodes)["height"], "transaction_sha256": tx["transaction_sha256"]}
    write_json(artifacts / (label + "-accepted-block.json"), block)
    return block


def backup_ready(network, *, excluded=()):
    """Observe complete canonical backups and removal; never force a writer flush."""
    tip = common_tip(network.nodes)
    rows = []
    for node in network.nodes:
        rows.append(backup_observed(node, export_chain(node, tip["height"])))
        directory = node.directory / "state" / "non_finalized_state" / namespace((SLH_HEIGHT, TX_LIMIT, BLOCK_LIMIT))
        for block_hash in excluded:
            hex_field(block_hash, 32)
            wait_for(lambda: not (directory / block_hash).exists(), "spend_invalidated_backup_present", 30)
    require(common_tip(network.nodes) == tip, "spend_backup_tip_changed")
    return {"canonical": rows, "excluded_block_hashes": list(excluded)}


def rollback(network, block, expected, *, restart=True):
    for node in network.nodes:
        node.rpc("invalidateblock", block["block_hash"])
    wait_for(lambda: common_tip(network.nodes) == expected, "spend_rollback_tip")
    if restart:
        # Inherited invalidated-block records are memory-only. This path does
        # not reconsider them; wait for ordinary backup removal before reopen.
        backup = backup_ready(network, excluded=(block["block_hash"],))
        network.restart()
        require(common_tip(network.nodes) == expected, "spend_rollback_restart")
        return backup
    return None


def lifecycle(control, positive, duplicate, variants, parents, baseline, anchor_block, anchored, receipt):
    network, nodes = control.network, control.network.nodes
    require(positive["txid"] != duplicate["txid"] and positive["message_hex"] != duplicate["message_hex"],
            "spend_duplicate_parent_identity")
    require(anchor_block["height"] == baseline["tip"]["height"] + 1
            and anchored["tip"] == {"height": anchor_block["height"], "hash": anchor_block["block_hash"]}
            and all(anchored["roots"][p] != baseline["roots"][p] for p in control.args.pools),
            "spend_anchor_not_new")
    receipt["anchor_positive_before"] = preflight(control, "anchor-positive-before", positive, parents)
    receipt["duplicate_positive_before"] = preflight(control, "duplicate-positive-before", duplicate, parents)
    rollback(network, anchor_block, baseline["tip"], restart=False)
    require(observe(nodes, parents) == baseline, "spend_anchor_rollback_state")
    receipt["removed_anchor"] = reject(control, "removed-anchor", positive, parents, state_reason="anchor")
    for node in nodes:
        node.rpc("reconsiderblock", anchor_block["block_hash"])
    wait_for(lambda: common_tip(nodes) == anchored["tip"], "spend_anchor_reconsider_tip")
    receipt["reconsider_backup"] = backup_ready(network)
    network.restart()
    require(observe(nodes, parents) == anchored, "spend_anchor_reconsider_state")
    for node in nodes:
        require(node.rpc("getblock", anchor_block["block_hash"], 0) == anchor_block["block_hex"], "spend_reconsider_bytes")
    receipt["authorization"] = authorization_round(control, positive, variants, parents, "restored-anchor")
    mined = publish(network, positive, control.artifacts, "spend")
    after = observe(nodes, parents, (0,))
    require(all(after["values"][p] == anchored["values"][p] - (50000 if p in control.args.pools else 0)
                and (after["roots"][p] != anchored["roots"][p]) == (p in control.args.pools) for p in POOLS),
            "spend_pool_transition")
    receipt["duplicate_spend"] = reject(control, "duplicate-note", duplicate, parents, state_reason="nullifier", spent=(0,))
    receipt["mined"] = {"block": mined, "state": after}
    receipt["rollback_backup"] = rollback(network, mined, anchored["tip"])
    require(observe(nodes, parents) == anchored, "spend_rollback_effects")
    # Mine replacement blocks above the retained funding and anchor. This is a
    # fork selected after explicit invalidation, not a competing-peer race.
    replacement = network.mine(2)
    require(len(replacement) == 2 and common_tip(nodes)["height"] == anchored["tip"]["height"] + 2
            and all(node.rpc("getblockhash", mined["height"]) != mined["block_hash"] for node in nodes),
            "spend_replacement_branch")
    restored = observe(nodes, parents)
    same_effect_state(restored, anchored)
    receipt["reorg_authorization"] = authorization_round(control, positive, variants, parents, "replacement")
    saved = [{"txid": positive["txid"], "raw": positive["transaction_hex"]}]
    receipt["saved_reentry"] = reconcile_saved(network, saved, 1)
    require(common_tip(nodes)["height"] == restored["tip"]["height"] + 1, "spend_reentry_mining")
    remined = observe(nodes, parents, (0,))
    same_effect_state(remined, after)
    authenticated_outputs(nodes, positive["txid"], positive["outputs"])
    for node in nodes:
        require(transaction_state(node, saved[0]) == "confirmed", "spend_reentry_saved_bytes")
    receipt["replacement_blocks"] = replacement
    receipt["remined"] = remined


def coinbase(nodes, height, script):
    parent = authenticate_coinbase(nodes, height, script)
    observed = utxos(nodes, parent["txid"], [parent["output_index"]])[0]
    require(observed is not None, "spend_coinbase_missing")
    parent.update(value_zat=zat(observed["value"]), script_hex=observed["scriptPubKey"]["hex"])
    parent_state(nodes, parent)
    return parent


def output_deposit(args, network, artifacts, parent, pools, label):
    recipe = {"human_run": True, "transaction_version": args.version, "pools": pools,
        "parent_hex": parent["parent_hex"], "output_index": parent["output_index"], "expiry_height": EXPIRY,
        "authorization": args.classical, "public_key_hex": None,
        "sapling_parameters": args.parameters if "sapling" in pools else None}
    write_json(artifacts / (label + "-request.json"), recipe)
    before = observe(network.nodes, [parent])
    prepared = outputs.validate_prepared(outputs.proof_call(args.host, recipe), recipe, parent)
    write_json(artifacts / (label + "-proof.json"), prepared)
    tx, _ = outputs.finalize(args, recipe, prepared, None)
    write_json(artifacts / (label + "-signed.json"), tx)
    require(observe(network.nodes, [parent]) == before, "spend_deposit_preparation_changed_state")
    block = publish(network, tx, artifacts, label)
    after = observe(network.nodes, [parent], (0,))
    require(all(after["values"][p] == before["values"][p] + (50000 if p in pools and p != "orchard" else 0)
                and (after["roots"][p] != before["roots"][p]) == (p in pools) for p in POOLS),
            "spend_deposit_pool_transition")
    return tx, block


def orchard_deposit(args, network, artifacts, parent):
    require(common_tip(network.nodes)["height"] == 101, "spend_orchard_funding_height")
    recipe = {"human_run": True, "parent_hex": parent["parent_hex"], "output_index": parent["output_index"],
              "expiry_height": 103, "kind": args.classical}
    write_json(artifacts / "orchard-funding-request.json", recipe)
    before = observe(network.nodes, [parent])
    tx = proof_call(args.host, "shielded-spend-funding", recipe)
    required = (outputs.WIRE - {"message_hex"}) | {"material", "version", "parent_txid", "parent_index",
        "parent_value_zat", "parent_script_hex", "parent_transaction_sha256", "fee_zat", "deposit_zat",
        "orchard_value_zat", "proof_profile", "pool_valid", "ecdsa_checks", "slh_checks"}
    require(type(tx) is dict and set(tx) == required, "spend_orchard_funding_schema")
    # The pre-NU6.3 transaction is fully classical-signed and has no SLH message.
    wire = {name: tx[name] for name in outputs.WIRE - {"message_hex"}}
    outputs.wire_check(dict(wire, message_hex="00" * 101))
    expected = dict(material="public-test-only", version=5, parent_txid=parent["txid"],
        parent_index=parent["output_index"], parent_value_zat=parent["value_zat"], parent_script_hex=parent["script_hex"],
        parent_transaction_sha256=hashlib.sha256(bytes.fromhex(parent["parent_hex"])).hexdigest(),
        fee_zat=100000, deposit_zat=50000, orchard_value_zat=50000, proof_profile="orchard-pre-nu6.3",
        pool_valid={"orchard": True}, ecdsa_checks=2 if args.classical == "multisig" else 1,
        slh_checks=0, sapling_outputs=0, orchard_actions=2, ironwood_actions=0,
        outputs=[{"output_index": 0, "script_hex": parent["script_hex"], "value_zat": parent["value_zat"] - 150000}])
    for name, value in expected.items():
        require(tx[name] == value and type(tx[name]) is type(value), "spend_orchard_funding_identity")
    require(tx["pool_valid"]["orchard"] is True, "spend_orchard_funding_verification")
    write_json(artifacts / "orchard-funding.json", tx)
    require(observe(network.nodes, [parent]) == before, "spend_orchard_preparation_changed_state")
    block = publish(network, tx, artifacts, "orchard-funding")
    after = observe(network.nodes, [parent], (0,))
    require(block["height"] == 102 and all(after["values"][p] == before["values"][p] + (50000 if p == "orchard" else 0)
        and (after["roots"][p] != before["roots"][p]) == (p == "orchard") for p in POOLS),
        "spend_orchard_funding_transition")
    return tx


def execute(args, artifacts, receipt):
    info = host_call(args.host, "classical-info", kind=args.classical)
    key = signer_call(args.signer, "keygen", seed=seed(0)) if args.authorization == "slh" else None
    script = policy([key["public_key"]], 1)[1] if key else info["script_hex"]
    with Network(args.node, artifacts, info["address"], activation_heights={"NU6.2": 1, "NU6.3": 104, "NU7": 105}) as network:
        require(common_tip(network.nodes)["height"] == 0, "spend_fresh_chain")
        control = SpendControls(args, artifacts, network)
        mine_to(network, 101)
        funding, funding_ids = [], []
        if "orchard" in args.pools:
            tx = orchard_deposit(args, network, artifacts, coinbase(network.nodes, 1, info["script_hex"]))
            funding.append(tx)
            funding_ids.append({"pool": "orchard", "txid": tx["txid"]})
        mine_to(network, 110)
        new_pools = [p for p in args.pools if p != "orchard"]
        if new_pools:
            tx, _ = output_deposit(args, network, artifacts, coinbase(network.nodes, 3, info["script_hex"]), new_pools, "note-funding")
            funding.append(tx)
            funding_ids.extend({"pool": p, "txid": tx["txid"]} for p in new_pools)
        bank_parent = coinbase(network.nodes, 2, info["script_hex"])
        bank = host_call(args.host, "classical-spend", recipe={"kind": args.classical,
            "transaction_version": args.version, "lock_time": 0, "expiry_height": EXPIRY,
            "parent_hex": bank_parent["parent_hex"], "output_index": bank_parent["output_index"],
            "outputs": [{"value_zat": 3_000_000, "script_hex": script}] * 2, "fee_zat": 20000})
        bank["fee_zat"] = 20000
        write_json(artifacts / "transparent-funding.json", bank)
        publish(network, bank, artifacts, "transparent-funding")
        parents = [{"txid": bank["txid"], "parent_hex": bank["transaction_hex"], "output_index": i,
                    "value_zat": 3_000_000, "script_hex": script} for i in range(2)]
        baseline = observe(network.nodes, parents)
        _, anchor_block = output_deposit(args, network, artifacts,
            coinbase(network.nodes, 4, info["script_hex"]), args.pools, "anchor-funding")
        anchored = observe(network.nodes, parents)
        history = collect_history(network.nodes, parents, funding)
        write_json(artifacts / "history.json", history)
        history_hash = digest(history)
        funding_ids.sort(key=lambda row: POOLS.index(row["pool"]))
        prepared_rows, signed_rows, signed_hashes = [], [], []
        for index, parent in enumerate(parents):
            label = "primary" if index == 0 else "duplicate"
            recipe = {"human_run": True, "transaction_version": args.version, "pools": args.pools,
                "parent_hex": parent["parent_hex"], "output_index": parent["output_index"], "expiry_height": EXPIRY,
                "authorization": args.authorization, "public_key_hex": key["public_key"] if key else None,
                "sapling_parameters": args.parameters, "history": history, "funding_txids": funding_ids}
            write_json(artifacts / (label + "-request.json"), recipe)
            prepared = validate_prepared(proof_call(args.host, "shielded-spend-prepare", recipe), recipe, parent)
            require(digest(history) == history_hash and digest(read_json(artifacts / "history.json")) == history_hash,
                    "spend_saved_history_changed")
            require(observe(network.nodes, parents) == anchored, "spend_preparation_changed_state")
            write_json(artifacts / (label + "-proof.json"), prepared)
            positive, variants = finalize(args, recipe, prepared, key, label)
            write_json(artifacts / (label + "-signed.json"), {"positive": positive, "variants": variants})
            prepared_rows.append(prepared); signed_rows.append((positive, variants))
            signed_hashes.append(sha256(artifacts / (label + "-signed.json")))
        note_identity = lambda notes: [{k: v for k, v in note.items() if k != "real_spend_index"} for note in notes]
        require(note_identity(prepared_rows[0]["notes"]) == note_identity(prepared_rows[1]["notes"]),
                "spend_duplicate_note_identity")
        for label, expected_hash in zip(("primary", "duplicate"), signed_hashes):
            require(sha256(artifacts / (label + "-signed.json")) == expected_hash, "spend_saved_authorization_changed")
        receipt["saved_authorization_sha256"] = dict(zip(("primary", "duplicate"), signed_hashes))
        receipt["history_sha256"] = history_hash
        receipt["notes"] = prepared_rows[0]["notes"]
        receipt["parents"] = [{k: p[k] for k in ("txid", "output_index", "value_zat", "script_hex")} for p in parents]
        lifecycle(control, signed_rows[0][0], signed_rows[1][0], signed_rows[0][1], parents,
                  baseline, anchor_block, anchored, receipt)
        for label, expected_hash in zip(("primary", "duplicate"), signed_hashes):
            require(sha256(artifacts / (label + "-signed.json")) == expected_hash, "spend_saved_authorization_changed")
        receipt["configs"] = [sha256(node.config) for node in network.nodes]
    receipt["shutdown"] = network.metadata()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    for role in ("node", "host", "signer"):
        result.add_argument("--" + role, type=Path, required=True)
        result.add_argument("--" + role + "-build", type=Path, required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    result.add_argument("--version", type=int, choices=(5, 6), required=True)
    result.add_argument("--pools", type=outputs.pools_arg, required=True)
    result.add_argument("--authorization", choices=("slh", "single", "multisig"), default="slh")
    result.add_argument("--classical", choices=("single", "multisig"), default="single")
    result.add_argument("--sapling-spend-parameters", type=Path)
    result.add_argument("--sapling-output-parameters", type=Path)
    return result


def main(args):
    require(args.version == 6 or "ironwood" not in args.pools, "spend_version_pool")
    require(args.authorization == "slh" or args.authorization == args.classical, "spend_classical_profile")
    args.parameters = None
    paths = (args.sapling_spend_parameters, args.sapling_output_parameters)
    if "sapling" in args.pools:
        require(all(path is not None and path.is_absolute() and path.is_file() and not path.is_symlink()
                    and 0 < path.stat().st_size <= 64*1024*1024 for path in paths), "spend_parameter_files")
        args.parameters = {"spend_path": str(paths[0]), "spend_sha256": sha256(paths[0]),
                           "output_path": str(paths[1]), "output_sha256": sha256(paths[1])}
    else:
        require(paths == (None, None), "spend_unneeded_parameters")
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {"schema_version": 1, "contract": CONTRACT, "complete": False, "version": args.version,
        "pools": args.pools, "authorization": args.authorization, "parameters": args.parameters,
        "scope": "RPC-observed real-note spend/anchor/duplicate refusal; no internal nullifier membership or queue/cache claim"}
    write_json(artifacts / "execution.json", receipt)
    try:
        before = source_state()
        receipt["builds"] = {role: validate_build(read_json(getattr(args, role + "_build")), getattr(args, role),
            kind, runtime_required=role == "node") for role, kind in
            (("node", "node-slh"), ("host", "host-shielded"), ("signer", "signer"))}
        execute(args, artifacts, receipt)
        require(source_state() == before, "spend_source_changed")
        for role, build in receipt["builds"].items():
            require(sha256(getattr(args, role)) == build["binary_sha256"], "spend_binary_changed")
        if args.parameters:
            require(sha256(paths[0]) == args.parameters["spend_sha256"]
                    and sha256(paths[1]) == args.parameters["output_sha256"], "spend_parameters_changed")
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
