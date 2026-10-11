#!/usr/bin/env python3
"""HUMAN ONLY: bounded real-proof shielded output shapes with exact SLH binding.

Selective research proof/control flow; see the public shielded guide and mappings.
Importing this module performs no key generation, signing, proving or node work.
"""
import argparse
import contextlib
import hashlib
from pathlib import Path
import re

from common import (ROOT, CONTRACT, AcceptanceError, canonical, common_tip, read_json,
                    require, sha256, source_state, validate_build, wait_for, write_json, zat)
from generate_transactions import (MAX_HOST, hex_field, host_call, invoke, randomizer,
                                   seed, signer_call)
from lifecycle_controls import configured, copy_blocks, utxos
from node_live import authenticated_outputs, policy
from nodes import ManagedNode, SLH_HEIGHT, authenticate_coinbase, port
from transparent_controls import reject_relay

POOLS = ("sapling", "orchard", "ironwood")
WIRE = {"transaction_hex", "transaction_sha256", "txid", "auth_digest", "message_hex",
        "outputs", "sapling_outputs", "orchard_actions", "ironwood_actions"}
PREPARED = {"material", "version", "pools", "parent_txid", "parent_index", "parent_value_zat",
            "parent_script_hex", "parent_transaction_sha256", "fee_zat", "deposit_zat",
            "orchard_value_zat", "proof_profile", "parameters", "positive",
            "positive_pool_valid", "variants"}
FINAL = WIRE | {"slh_checks", "ecdsa_checks", "fee_zat", "deposit_zat"}


def pools_arg(value):
    pools = value.split(",")
    require(pools == [p for p in POOLS if p in pools] and pools, "shielded_pool_selection")
    return pools


def proof_call(host, recipe):
    # Same strict nonblocking transport as public fixtures; a finite larger
    # deadline only for the explicitly requested human proof operation.
    request = dict(schema_version=1, contract=CONTRACT, public_fixture=True,
                   op="shielded-prepare", recipe=recipe)
    reply = invoke(host, request, MAX_HOST, timeout=1800)
    require(type(reply) is dict and set(reply) == {
        "schema_version", "contract", "public_fixture", "op", "ok", "result"}
        and type(reply["schema_version"]) is int and reply["schema_version"] == 1
        and reply["contract"] == CONTRACT and reply["public_fixture"] is True
        and reply["op"] == "shielded-prepare" and reply["ok"] is True,
        "shielded_host_reply")
    return reply["result"]


def wire_check(value, fields=WIRE):
    require(type(value) is dict and set(value) == fields, "shielded_wire_schema")
    raw = value["transaction_hex"]
    require(type(raw) is str and 1 <= len(raw) <= 524288 and len(raw) % 2 == 0,
            "shielded_wire_size")
    hex_field(raw, len(raw) // 2)
    for name in ("transaction_sha256", "txid", "auth_digest"):
        hex_field(value[name], 32)
    hex_field(value["message_hex"], 101)
    require(hashlib.sha256(bytes.fromhex(raw)).hexdigest() == value["transaction_sha256"],
            "shielded_wire_hash")
    require(type(value["outputs"]) is list and len(value["outputs"]) == 1,
            "shielded_output_schema")
    output = value["outputs"][0]
    require(type(output) is dict and set(output) == {"output_index", "script_hex", "value_zat"}
            and type(output["output_index"]) is int and output["output_index"] == 0
            and type(output["value_zat"]) is int and 2403 <= output["value_zat"] <= 2_100_000_000_000_000
            and type(output["script_hex"]) is str and len(output["script_hex"]) in (46, 70),
            "shielded_output_schema")
    hex_field(output["script_hex"], len(output["script_hex"]) // 2)
    for field in ("sapling_outputs", "orchard_actions", "ironwood_actions"):
        require(type(value[field]) is int and value[field] in (0, 2), "shielded_pool_count")


def validate_prepared(result, recipe, parent):
    require(type(result) is dict and set(result) == PREPARED, "shielded_prepared_schema")
    pools = recipe["pools"]
    require(result["material"] == "public-test-only" and result["version"] == recipe["transaction_version"]
            and type(result["version"]) is int and result["pools"] == pools
            and result["proof_profile"] == "output-only-post-nu6.3"
            and result["parameters"] == recipe["sapling_parameters"], "shielded_prepared_identity")
    expected = dict(parent_txid=parent["txid"], parent_index=parent["output_index"],
        parent_value_zat=parent["value_zat"], parent_script_hex=parent["script_hex"],
        parent_transaction_sha256=hashlib.sha256(bytes.fromhex(recipe["parent_hex"])).hexdigest(),
        fee_zat=100000, deposit_zat=50000 * len([p for p in pools if p != "orchard"]),
        orchard_value_zat=0)
    for key, value in expected.items():
        require(result[key] == value and type(result[key]) is type(value), "shielded_parent_or_value")
    require(result["positive_pool_valid"] == dict.fromkeys(pools, True)
            and all(value is True for value in result["positive_pool_valid"].values()),
            "shielded_positive_verification")
    positive = result["positive"]
    wire_check(positive)
    require(positive["outputs"] == [{"output_index": 0, "script_hex": parent["script_hex"],
            "value_zat": parent["value_zat"] - expected["fee_zat"] - expected["deposit_zat"]}],
            "shielded_fee_or_change")
    for pool, field in zip(POOLS, ("sapling_outputs", "orchard_actions", "ironwood_actions")):
        require(positive[field] == (2 if pool in pools else 0), "shielded_expected_pool_count")
    variants = result["variants"]
    require(type(variants) is list and len(variants) == 2 * len(pools), "shielded_variant_count")
    expected_cases = [(p, m) for p in pools for m in ("binding", "proof")]
    seen_auth = {positive["auth_digest"]}
    for row, (pool, mutation) in zip(variants, expected_cases):
        wire_check(row, WIRE | {"pool", "mutation", "pool_valid"})
        require(row["pool"] == pool and row["mutation"] == mutation
                and row["pool_valid"] == {p: p != pool for p in pools}
                and all(type(value) is bool for value in row["pool_valid"].values()),
                "shielded_mutation_verification")
        require(row["txid"] == positive["txid"] and row["message_hex"] == positive["message_hex"]
                and row["outputs"] == positive["outputs"]
                and all(row[f] == positive[f] for f in ("sapling_outputs", "orchard_actions", "ironwood_actions"))
                and row["transaction_hex"] != positive["transaction_hex"]
                and row["auth_digest"] not in seen_auth,
                "shielded_authorization_identity")
        seen_auth.add(row["auth_digest"])
    return result


def finalize(args, recipe, prepared, key):
    entry = None
    if recipe["authorization"] == "slh":
        signed = signer_call(args.signer, "sign", secret_key=key["secret_key"],
            message=prepared["positive"]["message_hex"], randomizer=randomizer("shielded-" + "-".join(recipe["pools"]), 0, 0))
        require(signed["public_key"] == recipe["public_key_hex"], "shielded_signer_identity")
        entry = {"signer_index": 0, "public_key_hex": signed["public_key"], "signature_hex": signed["signature"]}
    rows = []
    for unsigned in [prepared["positive"], *prepared["variants"]]:
        tx = host_call(args.host, "shielded-finalize", recipe=recipe,
                       transaction_hex=unsigned["transaction_hex"], record=entry)
        wire_check(tx, FINAL)
        require(all(tx[field] == unsigned[field] for field in WIRE - {
                    "transaction_hex", "transaction_sha256", "auth_digest"})
                and tx["transaction_hex"] != unsigned["transaction_hex"]
                and type(tx["slh_checks"]) is int and tx["slh_checks"] == int(entry is not None)
                and type(tx["ecdsa_checks"]) is int and tx["ecdsa_checks"] == (0 if entry else 2 if recipe["authorization"] == "multisig" else 1)
                and tx["fee_zat"] == prepared["fee_zat"] and tx["deposit_zat"] == prepared["deposit_zat"],
                "shielded_finalized_correspondence")
        if "pool" in unsigned:
            tx["pool"], tx["mutation"] = unsigned["pool"], unsigned["mutation"]
        rows.append(tx)
    require(len({tx["auth_digest"] for tx in rows}) == len(rows), "shielded_final_authorization_identity")
    return rows[0], rows[1:]


def candidate(args, nodes, tx, nonce, *, shielded=True):
    template = nodes[0].rpc("getblocktemplate")
    require(template["transactions"] == [], "shielded_control_mempool_not_empty")
    block = host_call(args.host, "shielded-block" if shielded else "control-block", recipe={
        "kind": args.classical, "template": template, "nonce": nonce,
        "transactions": [{"transaction_hex": tx["transaction_hex"], "fee_zat": tx["fee_zat"]}]})
    require(block["txids"] == [tx["txid"]] and block["height"] == common_tip(nodes)["height"] + 1
            and block["aggregate_fee_zat"] == tx["fee_zat"], "shielded_block_correspondence")
    return block


def tree_roots(nodes):
    tip = common_tip(nodes)
    states = [node.rpc("z_gettreestate", str(tip["height"])) for node in nodes]
    require(states[0] == states[1] and states[0]["height"] == tip["height"]
            and states[0]["hash"] == tip["hash"], "shielded_tree_context")
    roots = {pool: states[0][pool]["commitments"]["finalRoot"] for pool in POOLS}
    for root in roots.values():
        hex_field(root, 32)
    return roots


def snapshot(nodes, parent):
    state = utxos(nodes, parent["txid"], [parent["output_index"]])
    require(all(row is not None and zat(row["value"]) == parent["value_zat"]
                and row["scriptPubKey"]["hex"] == parent["script_hex"] for row in state),
            "shielded_parent_unavailable")
    return common_tip(nodes), state, tree_roots(nodes)


def unchanged(nodes, parent, before):
    require(snapshot(nodes, parent) == before, "shielded_rejection_changed_state")


def preflight(args, nodes, positive, parent, artifacts):
    before = snapshot(nodes, parent)
    block = candidate(args, nodes, positive, 100)
    write_json(artifacts / "positive-preflight.json", block)
    for node in nodes:
        require(node.rpc("getblocktemplate", {"mode": "proposal", "data": block["block_hex"]}) is None,
                "shielded_positive_preflight_rejected")
    unchanged(nodes, parent, before)
    return {"block_sha256": block["block_sha256"], "txid": positive["txid"],
            "auth_digest": positive["auth_digest"], "both_positive_proposals_accepted": True}


def negative_controls(args, nodes, positive, variants, parent, artifacts):
    receipts = []
    for number, tx in enumerate(variants):
        require(tx["txid"] == positive["txid"] and tx["message_hex"] == positive["message_hex"]
                and tx["auth_digest"] != positive["auth_digest"], "shielded_negative_identity")
        before = snapshot(nodes, parent)
        sapling = tx["pool"] == "sapling"
        relay_text = "sapling proof or signature verification failed" if sapling else "orchard or ironwood halo2 proof verification failed"
        relay = [reject_relay(node, tx["transaction_hex"], ((relay_text,),)) for node in nodes]
        unchanged(nodes, parent, before)
        require(all(tx["txid"] not in node.rpc("getrawmempool") for node in nodes),
                "shielded_failed_checks_published")
        block = candidate(args, nodes, tx, 101 + number)
        write_json(artifacts / f'{tx["pool"]}-{tx["mutation"]}-block.json', block)
        proposals = []
        for node in nodes:
            proposal = node.rpc("getblocktemplate", {"mode": "proposal", "data": block["block_hex"]})
            reason = "saplingverificationfailed" if sapling else "halo2verificationfailed"
            require(type(proposal) is str and re.search(r"(?:^|-)" + reason + r"(?:-|$)", proposal),
                    "shielded_wrong_proposal_rejection")
            require(node.rpc("submitblock", block["block_hex"]) == "rejected", "shielded_bad_block_accepted")
            proposals.append(proposal)
        unchanged(nodes, parent, before)
        require(all(tx["txid"] not in node.rpc("getrawmempool") for node in nodes),
                "shielded_failed_checks_published")
        receipts.append({"pool": tx["pool"], "mutation": tx["mutation"], "txid": tx["txid"],
            "auth_digest": tx["auth_digest"], "transaction_sha256": tx["transaction_sha256"],
            "relay": relay, "proposal": proposals, "parent_and_tip_unchanged": True,
            "mempool_absent": True})
    return receipts


def publish(args, nodes, tx, parent, artifacts):
    before = snapshot(nodes, parent)
    for node in nodes:
        require(node.rpc("sendrawtransaction", tx["transaction_hex"]) == tx["txid"], "shielded_positive_relay")
        wait_for(lambda: tx["txid"] in node.rpc("getrawmempool"), "shielded_positive_mempool")
        template = node.rpc("getblocktemplate")
        require(any(row["hash"] == tx["txid"] and row["data"] == tx["transaction_hex"]
                    for row in template["transactions"]), "shielded_positive_template")
    require(common_tip(nodes) == before[0], "shielded_relay_changed_tip")
    hashes = nodes[0].rpc("generate", 1)
    require(len(hashes) == 1, "shielded_positive_mining")
    copy_blocks(nodes[0], nodes[1], hashes)
    raw = nodes[0].rpc("getblock", hashes[0], 0)
    write_json(artifacts / "accepted-block.json", {"block_hex": raw,
        "block_sha256": hashlib.sha256(bytes.fromhex(raw)).hexdigest(), "block_hash": hashes[0]})
    for node in nodes:
        saved = node.rpc("getrawtransaction", tx["txid"], 1)
        require(saved["hex"] == tx["transaction_hex"] and saved["confirmations"] > 0,
                "shielded_positive_saved_bytes")
        require(tx["txid"] in node.rpc("getblock", hashes[0], 1)["tx"], "shielded_positive_block_membership")
    require(utxos(nodes, parent["txid"], [parent["output_index"]]) == [None], "shielded_parent_unspent")
    authenticated_outputs(nodes, tx["txid"], tx["outputs"])
    after_roots = tree_roots(nodes)
    require(all((after_roots[p] != before[2][p]) == (p in args.pools) for p in POOLS),
            "shielded_commitment_tree_transition")
    return {"tip": common_tip(nodes), "txid": tx["txid"], "auth_digest": tx["auth_digest"],
            "exact_transaction_and_block_bytes": True, "parent_spent": True, "change_authenticated": True,
            "roots_before": before[2], "roots_after": after_roots}


@contextlib.contextmanager
def pair(args, artifacts, info):
    nodes = []
    try:
        for index, (binary, label) in enumerate(((args.node_default if args.authorization != "slh" else args.node_slh,
                                                 "first"), (args.node_slh, "enabled"))):
            address = port()
            node = ManagedNode(binary, artifacts, label, info["address"], address)
            nodes.append(node)
            if index == 0 and args.authorization != "slh":
                configured(node, address, info["address"], node.directory / "state", None)
            node.start()
            require(node.rpc("getpeerinfo") == [], "shielded_unexpected_peers")
        require(common_tip(nodes)["height"] == 0, "shielded_fresh_nodes")
        while nodes[0].tip()[0] < SLH_HEIGHT:
            copy_blocks(nodes[0], nodes[1], nodes[0].rpc("generate", min(25, SLH_HEIGHT - nodes[0].tip()[0])))
        yield nodes
    finally:
        failures = []
        for node in reversed(nodes):
            try:
                node.close()
            except Exception as error:
                failures.append(error)
        if failures:
            raise failures[0]


def execute(args, artifacts, receipt):
    info = host_call(args.host, "classical-info", kind=args.classical)
    key = None
    if args.authorization == "slh":
        key = signer_call(args.signer, "keygen", seed=seed(0))
    with pair(args, artifacts, info) as nodes:
        parent = authenticate_coinbase(nodes, 1, info["script_hex"])
        if key:
            _, script = policy([key["public_key"]], 1)
            funding = host_call(args.host, "classical-spend", recipe={"kind":args.classical,
                "transaction_version":args.version,"lock_time":0,"expiry_height":210,
                "parent_hex":parent["parent_hex"],"output_index":parent["output_index"],
                "outputs":[{"value_zat":3_000_000,"script_hex":script}],"fee_zat":20_000})
            funding["fee_zat"] = 20000
            block = candidate(args, nodes, funding, 99, shielded=False)
            write_json(artifacts / "funding.json", funding)
            write_json(artifacts / "funding-block.json", block)
            for node in nodes:
                require(node.rpc("getblocktemplate", {"mode":"proposal","data":block["block_hex"]}) is None,
                        "shielded_funding_preflight")
                require(node.rpc("submitblock", block["block_hex"]) is None, "shielded_funding_block")
                wait_for(lambda: node.tip() == (block["height"], block["block_hash"]), "shielded_funding_tip")
            authenticated_outputs(nodes, funding["txid"], funding["outputs"])
            parent = {"txid":funding["txid"],"parent_hex":funding["transaction_hex"],"output_index":0}
        observed = utxos(nodes, parent["txid"], [parent["output_index"]])
        require(observed[0] is not None, "shielded_parent_disagreement")
        parent.update(value_zat=zat(observed[0]["value"]), script_hex=observed[0]["scriptPubKey"]["hex"])
        recipe = {"human_run":True,"transaction_version":args.version,"pools":args.pools,
            "parent_hex":parent["parent_hex"],"output_index":parent["output_index"],"expiry_height":210,
            "authorization":args.authorization,"public_key_hex":key["public_key"] if key else None,
            "sapling_parameters":args.parameters}
        write_json(artifacts / "proof-request.json", recipe)
        before = snapshot(nodes, parent)
        prepared = validate_prepared(proof_call(args.host, recipe), recipe, parent)
        write_json(artifacts / "proof-artifacts.json", prepared)
        unchanged(nodes, parent, before)
        positive, variants = finalize(args, recipe, prepared, key)
        write_json(artifacts / "signed-artifacts.json", {"positive":positive,"variants":variants})
        receipt["positive_preflight"] = preflight(args, nodes, positive, parent, artifacts)
        receipt["negative_controls"] = negative_controls(args, nodes, positive, variants, parent, artifacts)
        receipt["accepted"] = publish(args, nodes, positive, parent, artifacts)
        receipt["parent"] = {name: parent[name] for name in ("txid","output_index","value_zat","script_hex")}
        receipt["configs"] = [sha256(node.config) for node in nodes]
    receipt["shutdown_exit_codes"] = [node.stops for node in nodes]


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    for role in ("node-default", "node-slh", "host", "signer"):
        result.add_argument("--" + role, type=Path, required=True)
        result.add_argument("--" + role + "-build", type=Path, required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    result.add_argument("--version", type=int, choices=(5,6), required=True)
    result.add_argument("--pools", type=pools_arg, required=True)
    result.add_argument("--authorization", choices=("slh","single","multisig"), required=True)
    result.add_argument("--classical", choices=("single","multisig"), default="single")
    result.add_argument("--sapling-spend-parameters", type=Path)
    result.add_argument("--sapling-output-parameters", type=Path)
    return result


def main(args):
    require(args.version == 6 or "ironwood" not in args.pools, "shielded_version_pool")
    require(args.authorization == "slh" or args.authorization == args.classical, "shielded_classical_profile")
    args.parameters = None
    paths = (args.sapling_spend_parameters, args.sapling_output_parameters)
    if "sapling" in args.pools:
        require(all(path is not None and path.is_absolute() and path.is_file()
                    and 0 < path.stat().st_size <= 64 * 1024 * 1024 for path in paths), "shielded_parameter_files")
        args.parameters = {"spend_path":str(paths[0]),"spend_sha256":sha256(paths[0]),
                           "output_path":str(paths[1]),"output_sha256":sha256(paths[1])}
    else:
        require(paths == (None,None), "shielded_unneeded_parameters")
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {"schema_version":1,"contract":CONTRACT,"complete":False,"version":args.version,
        "pools":args.pools,"authorization":args.authorization,"parameters":args.parameters,
        "scope":"output-only real proofs; zero-valued Orchard; no spend/anchor, primitive count or queue-barrier claim"}
    write_json(artifacts / "execution.json", receipt)
    try:
        before = source_state()
        receipt["builds"] = {role: validate_build(read_json(getattr(args, role + "_build")),
            getattr(args,role), kind, runtime_required=role=="node_slh") for role,kind in (
                ("node_default","node-default"),("node_slh","node-slh"),("host","host-shielded"),("signer","signer"))}
        execute(args, artifacts, receipt)
        require(source_state() == before, "shielded_source_changed")
        for role, build in receipt["builds"].items():
            require(sha256(getattr(args,role)) == build["binary_sha256"], "shielded_binary_changed")
        if args.parameters:
            require(sha256(paths[0]) == args.parameters["spend_sha256"]
                    and sha256(paths[1]) == args.parameters["output_sha256"], "shielded_parameters_changed")
        receipt["complete"] = True
    except BaseException as error:
        receipt["failure"] = str(error) if isinstance(error,AcceptanceError) else type(error).__name__
        raise
    finally:
        receipt["artifacts"] = [{"path":str(path.relative_to(artifacts)),"sha256":sha256(path)}
            for path in sorted(artifacts.rglob("*")) if path.is_file() and not path.is_symlink()
            and path != artifacts / "execution.json" and "state" not in path.relative_to(artifacts).parts]
        write_json(artifacts / "execution.json",receipt,fresh=False)


if __name__ == "__main__":
    main(parser().parse_args())
