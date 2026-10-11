#!/usr/bin/env python3
"""HUMAN ONLY: compatibility, mixed inputs, exact block budgets and disk isolation.

Reuses the pinned research compatibility/history/restart assertions and current
acceptance lifecycle/fixture adapters. Importing this module starts no process.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

from common import (ROOT, CONTRACT, AcceptanceError, common_tip, read_json, require,
                    sha256, source_state, validate_build, wait_for, write_json, zat)
from generate_transactions import host_call, producer_identity, randomizer, seed, signer_call
from node_live import authenticated_outputs, policy, signed_artifact
from nodes import (ManagedNode, Network, SLH_HEIGHT, authenticate_coinbase,
                   configuration, port)


def configured(node, p2p, miner, state, rules):
    """Use the shared complete config; vary only the three SLH consensus fields."""
    text = configuration(node.address, p2p, None, state, miner, enabled=rules is not None)
    if rules is not None:
        for field, old, new in zip(("activation_height", "max_checks_per_transaction",
                                   "max_checks_per_block"), (110, 16, 64), rules):
            before = f"experimental_slh_dsa_b128s_{field} = {old}"
            require(text.count(before) == 1, "configuration_adapter_changed")
            text = text.replace(before, f"experimental_slh_dsa_b128s_{field} = {new}")
    node.config.write_text(text)


def startup_refusal(args, artifacts, miner):
    node = ManagedNode(args.node_default, artifacts, "default-refusal", miner, port())
    log = node.directory / "refusal.log"
    try:
        with log.open("xb") as stream:
            result = subprocess.run([str(node.binary), "--config", str(node.config), "start"],
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=20)
        require(result.returncode != 0, "default_build_accepted_slh_configuration")
        require(log.stat().st_size <= 1024 * 1024, "refusal_log_size")
        require(b"requires complete SLH-DSA-B-128s" in log.read_bytes(), "wrong_startup_refusal")
        require(not (node.directory / "state").exists(), "refusal_opened_state")
        return {"exit_code": result.returncode, "config_sha256": sha256(node.config),
                "log_sha256": sha256(log), "before_state_initialization": True}
    finally:
        node.close()


def copy_blocks(source, target, hashes):
    """Submit exact source blocks as in the research compatibility/replay drivers."""
    for block_hash in hashes:
        raw = source.rpc("getblock", block_hash, 0)
        require(target.rpc("submitblock", raw) is None, "classical_compatibility_block")
        wait_for(lambda: target.tip()[1] == block_hash, "classical_compatibility_tip")
        require(target.rpc("getblock", block_hash, 0) == raw, "compatibility_block_bytes")


def classical_compatibility(args, artifacts, info):
    p2p = [port(), port()]
    nodes = [ManagedNode(binary, artifacts, label, info["address"], address)
             for binary, label, address in zip((args.node_default, args.node_slh),
                                               ("classical-default", "classical-enabled"), p2p)]
    configured(nodes[0], p2p[0], info["address"], nodes[0].directory / "state", None)
    try:
        for node in nodes:
            node.start()
            require(node.rpc("getpeerinfo") == [], "compatibility_peers")
        require(common_tip(nodes)["height"] == 0, "compatibility_fresh_history")
        while nodes[0].tip()[0] < SLH_HEIGHT:
            copy_blocks(nodes[0], nodes[1], nodes[0].rpc("generate", min(25, SLH_HEIGHT - nodes[0].tip()[0])))
        parent = authenticate_coinbase(nodes, 1, info["script_hex"])
        spend = host_call(args.host, "classical-spend", recipe={"kind": args.classical,
            "transaction_version": args.version, "lock_time": 0, "expiry_height": SLH_HEIGHT + 20,
            "parent_hex": parent["parent_hex"], "output_index": parent["output_index"],
            "outputs": [{"value_zat": 3_000_000, "script_hex": info["script_hex"]}], "fee_zat": 20_000})
        write_json(artifacts / "classical-compatibility.json", spend)
        for node in nodes:
            require(node.rpc("sendrawtransaction", spend["transaction_hex"]) == spend["txid"],
                    "classical_compatibility_relay")
            template = node.rpc("getblocktemplate")
            require(any(row["hash"] == spend["txid"] and row["data"] == spend["transaction_hex"]
                        for row in template["transactions"]), "classical_compatibility_template")
        copy_blocks(nodes[0], nodes[1], nodes[0].rpc("generate", 1))
        authenticated_outputs(nodes, spend["txid"], spend["outputs"])
        for node in nodes:
            raw = node.rpc("getrawtransaction", spend["txid"], 1)
            require(raw["hex"] == spend["transaction_hex"] and raw["confirmations"] >= 1,
                    "classical_compatibility_saved_bytes")
        result = {"tip": common_tip(nodes), "txid": spend["txid"], "slh_checks": 0,
                  "same_block_bytes": True, "same_utxos": True,
                  "config_sha256": [sha256(node.config) for node in nodes]}
        result["slh_enabled_disabled"] = slh_compatibility(args, artifacts, info, nodes)
        return result
    finally:
        failures = []
        for node in reversed(nodes):
            try:
                node.close()
            except Exception as error:
                failures.append(error)
        if failures:
            raise failures[0]


def single_artifact(args, keys, producer, txid, index, expiry, case):
    """Single-input form of the existing node_live prepare/sign/assemble flow."""
    public = next(iter(keys))
    recipe = {"case_id": case, "network": "Regtest", "transaction_version": args.version,
        "lock_time": 0, "expiry_height": expiry,
        "inputs": [{"outpoint": {"txid_display_hex": txid, "index": index},
            "sequence": 0xfffffffe, "value_zat": 3_000_000, "threshold": 1,
            "public_keys_hex": [public], "signer_indices": [0]}],
        "outputs": [{"value_zat": 2_000_000, "input_policy_index": 0}]}
    prepared = host_call(args.host, "prepare", recipe=recipe)
    signed = signer_call(args.signer, "sign", secret_key=keys[public],
        message=prepared["inputs"][0]["message_hex"], randomizer=randomizer(case, 0, 0))
    require(signed["public_key"] == public, "single_control_signer_key")
    artifact = host_call(args.host, "assemble", recipe=recipe,
        records=[[{"signer_index": 0, "public_key_hex": public, "signature_hex": signed["signature"]}]],
        producer=producer)
    require(artifact["expected"]["native_authorization"] == "accept"
            and artifact["expected"]["signature_checks"] == 1, "single_control_authorization")
    return artifact


def slh_compatibility(args, artifacts, info, nodes):
    """Same legally funded state/bytes, native acceptance versus legacy-script refusal."""
    default, enabled = nodes
    producer, _ = producer_identity(args.root, args.host, args.signer)
    generated = signer_call(args.signer, "keygen", seed=seed(0))
    keys = {generated["public_key"]: generated["secret_key"]}
    try:
        _, script = policy(list(keys), 1)
        parent = authenticate_coinbase(nodes, 2, info["script_hex"])
        funding = host_call(args.host, "classical-spend", recipe={"kind": args.classical,
            "transaction_version": args.version, "lock_time": 0, "expiry_height": enabled.tip()[0] + 20,
            "parent_hex": parent["parent_hex"], "output_index": parent["output_index"],
            "outputs": [{"value_zat": 3_000_000, "script_hex": script}], "fee_zat": 20_000})
        candidate = host_call(args.host, "control-block", recipe={"template": enabled.rpc("getblocktemplate"),
            "kind": args.classical, "nonce": 700,
            "transactions": [{"transaction_hex": funding["transaction_hex"], "fee_zat": 20_000}]})
        write_json(artifacts / "compatibility-slh-funding.json", funding)
        write_json(artifacts / "compatibility-funding-block.json", candidate)
        for node in nodes:
            require(node.rpc("getblocktemplate", {"mode": "proposal", "data": candidate["block_hex"]}) is None,
                    "compatibility_classical_funding_proposal")
        require(enabled.rpc("submitblock", candidate["block_hex"]) is None,
                "compatibility_classical_funding_block")
        wait_for(lambda: enabled.tip()[1] == candidate["block_hash"], "compatibility_funding_tip")
        copy_blocks(enabled, default, [candidate["block_hash"]])
        authenticated_outputs(nodes, funding["txid"], funding["outputs"])
        before = common_tip(nodes)
        original = utxos(nodes, funding["txid"], [0])
        spend = single_artifact(args, keys, producer, funding["txid"], 0,
                                before["height"] + 20, "compatibility-slh-spend")
        candidate = host_call(args.host, "control-block", recipe={"template": enabled.rpc("getblocktemplate"),
            "kind": args.classical, "nonce": 701,
            "transactions": [{"transaction_hex": spend["transaction_hex"], "fee_zat": 1_000_000}]})
        write_json(artifacts / "compatibility-slh-spend.json", spend)
        write_json(artifacts / "compatibility-slh-block.json", candidate)
        require(enabled.rpc("getblocktemplate", {"mode": "proposal", "data": candidate["block_hex"]}) is None,
                "enabled_slh_proposal_rejected")
        refused = default.rpc("getblocktemplate", {"mode": "proposal", "data": candidate["block_hex"]})
        require(isinstance(refused, str) and "script" in refused, "disabled_slh_wrong_rejection")
        require(default.rpc("submitblock", candidate["block_hex"]) == "rejected", "disabled_slh_block_accepted")
        require(default.tip() == (before["height"], before["hash"])
                and default.rpc("gettxout", funding["txid"], 0, False) == original[0],
                "disabled_slh_rejection_changed_state")
        require(enabled.rpc("submitblock", candidate["block_hex"]) is None, "enabled_slh_block_rejected")
        wait_for(lambda: enabled.tip()[1] == candidate["block_hash"], "enabled_slh_block_tip")
        require(enabled.rpc("getblock", candidate["block_hash"], 0) == candidate["block_hex"]
                and enabled.rpc("gettxout", funding["txid"], 0, False) is None,
                "enabled_slh_block_state")
        return {"common_parent": before, "funding_txid": funding["txid"],
                "candidate_block": candidate["block_hash"], "default_rejection": refused,
                "default_tip_unchanged": True, "enabled_tip": enabled.tip(), "producer": producer}
    finally:
        keys.clear()


def utxos(nodes, txid, indexes):
    rows = [[node.rpc("gettxout", txid, index, False) for index in indexes] for node in nodes]
    require(rows[0] == rows[1], "control_utxo_disagreement")
    return rows[0]


def rejection_unchanged(network, operation, before, txid, indexes, snapshot):
    observations = operation()
    require(common_tip(network.nodes) == before, "rejected_control_changed_tip")
    require(utxos(network.nodes, txid, indexes) == snapshot, "rejected_control_changed_utxos")
    return observations


def mixed_controls(args, artifacts, network, funding, keys):
    parent = {"parent_hex": funding["transaction_hex"]}
    public = next(iter(keys))
    before = common_tip(network.nodes)
    snapshot = utxos(network.nodes, funding["txid"], [0, 1])
    require(all(value is not None for value in snapshot), "mixed_funding_missing")
    results = []
    for classical_first in (True, False):
        recipe = {"kind": args.classical, "transaction_version": args.version,
            "expiry_height": before["height"] + 20, "classical_first": classical_first,
            "classical": {**parent, "output_index": 0}, "slh": {**parent, "output_index": 1},
            "public_key_hex": public, "fee_zat": 100_000}
        prepared = host_call(args.host, "mixed-prepare", recipe=recipe)
        require(prepared["slh_input_index"] == int(classical_first)
                and prepared["public_key_hex"] == public, "mixed_signing_context")
        signed = signer_call(args.signer, "sign", secret_key=keys[public],
            message=prepared["message_hex"], randomizer=randomizer("mixed-control", int(classical_first), 0))
        require(signed["public_key"] == public, "mixed_signer_key")
        mixed = host_call(args.host, "mixed-assemble", recipe=recipe,
            record={"signer_index": 0, "public_key_hex": public, "signature_hex": signed["signature"]})
        require(mixed["message_hex"] == prepared["message_hex"] and mixed["slh_checks"] == 1,
                "mixed_assembly_context")
        write_json(artifacts / f"mixed-{int(classical_first)}.json", mixed)
        observed = rejection_unchanged(network, lambda: [node.reject("sendrawtransaction",
            "cannot be mixed", mixed["transaction_hex"]) for node in network.nodes],
            before, funding["txid"], [0, 1], snapshot)
        require(all(mixed["txid"] not in node.rpc("getrawmempool") for node in network.nodes),
                "mixed_transaction_in_mempool")
        template = network.a.rpc("getblocktemplate")
        require(template["transactions"] == [], "mixed_template_must_be_empty")
        candidate = host_call(args.host, "control-block", recipe={"template": template,
            "kind": args.classical, "nonce": 500 + int(classical_first),
            "transactions": [{"transaction_hex": mixed["transaction_hex"], "fee_zat": 100_000}]})
        write_json(artifacts / f"mixed-block-{int(classical_first)}.json", candidate)
        def reject_block():
            rows = []
            for node in network.nodes:
                proposal = node.rpc("getblocktemplate", {"mode": "proposal", "data": candidate["block_hex"]})
                require(isinstance(proposal, str) and
                        ("experimentalslhdsab128smixedinputs" in proposal or "cannot-be-mixed" in proposal),
                        "wrong_mixed_block_proposal_rejection")
                submitted = node.rpc("submitblock", candidate["block_hex"])
                require(submitted == "rejected", "mixed_block_not_rejected")
                rows.append({"proposal": proposal, "submitblock": submitted})
            return rows
        block_rejections = rejection_unchanged(network, reject_block, before,
            funding["txid"], [0, 1], snapshot)
        results.append({"classical_first": classical_first, "txid": mixed["txid"],
                        "rejections": observed, "block_rejections": block_rejections,
                        "tip_and_utxos_unchanged": True})
    return results


def block_controls(args, artifacts, network, funding, keys, producer):
    before = common_tip(network.nodes)
    # Funding indexes 2..9 are four independent 16-check transactions; 10 is
    # one additional genuine 1-check transaction. None enters the mempool.
    indexes = list(range(2, 11))
    snapshot = utxos(network.nodes, funding["txid"], indexes)
    require(all(value is not None for value in snapshot), "block_control_funding_missing")
    transactions = []
    for index in range(5):
        slots = [2 + index * 2, 3 + index * 2] if index < 4 else [10]
        shapes = [(15, 15), (1, 1)] if index < 4 else [(1, 1)]
        # The existing multi-input helper writes to policy index 1; retain its
        # flow with the single-input adapter when only index 0 exists.
        if index < 4:
            artifact = signed_artifact(args, keys, producer, funding["txid"], slots,
                [3_000_000] * len(slots), shapes, args.version, before["height"] + 20,
                f"block-control-{index}")
        else:
            artifact = single_artifact(args, keys, producer, funding["txid"], 10,
                before["height"] + 20, "block-control-excess")
        require(artifact["expected"]["native_authorization"] == "accept"
                and artifact["expected"]["signature_checks"] == (16 if index < 4 else 1),
                "block_control_authorization")
        write_json(artifacts / f"block-transaction-{index}.json", artifact)
        transactions.append({"transaction_hex": artifact["transaction_hex"], "fee_zat": 1_000_000})
    template = network.a.rpc("getblocktemplate")
    require(template["transactions"] == [], "control_template_must_be_empty")
    candidates = {}
    for checks, entries in ((64, transactions[:4]), (65, transactions)):
        candidates[checks] = host_call(args.host, "control-block", recipe={"template": template,
            "kind": args.classical, "nonce": checks, "transactions": entries})
        write_json(artifacts / f"block-{checks}.json", candidates[checks])
    def reject_excess():
        rows = []
        for node in network.nodes:
            # Both entry points return a rejection result, not a JSON-RPC error.
            proposal = node.rpc("getblocktemplate", {"mode": "proposal", "data": candidates[65]["block_hex"]})
            submitted = node.rpc("submitblock", candidates[65]["block_hex"])
            require(isinstance(proposal, str) and
                    (("toomanyexperimentalslhdsab128schecks" in proposal and "limit-64" in proposal)
                     or "exceeds-64-slh-checks" in proposal),
                    "wrong_excess_block_proposal_rejection")
            require(submitted == "rejected",
                    "wrong_excess_block_submit_rejection")
            rows.append({"proposal": proposal, "submitblock": submitted})
        return rows
    rejected = rejection_unchanged(network, reject_excess, before, funding["txid"], indexes, snapshot)
    for node in network.nodes:
        require(node.rpc("getblocktemplate", {"mode": "proposal", "data": candidates[64]["block_hex"]}) is None,
                "exact_block_proposal_rejected")
    require(network.a.rpc("submitblock", candidates[64]["block_hex"]) is None, "exact_block_submit_rejected")
    wait_for(lambda: all(node.tip() == (candidates[64]["height"], candidates[64]["block_hash"])
                        for node in network.nodes), "exact_block_peer_tip")
    for node in network.nodes:
        require(node.rpc("getblock", candidates[64]["block_hash"], 0) == candidates[64]["block_hex"],
                "exact_block_saved_bytes")
    after = utxos(network.nodes, funding["txid"], indexes)
    require(all(value is None for value in after[:8]) and after[8] is not None,
            "exact_block_wrong_spends")
    return {"accepted_checks": 64, "rejected_checks": 65, "rejections": rejected,
            "accepted_block": candidates[64]["block_hash"], "exact_bytes": True}


def mixed_and_blocks(args, artifacts, info):
    producer, _ = producer_identity(args.root, args.host, args.signer)
    keys = {}
    try:
        for index in range(15):
            generated = signer_call(args.signer, "keygen", seed=seed(index))
            keys[generated["public_key"]] = generated["secret_key"]
        require(len(keys) == 15, "control_fixture_keys")
        public = list(keys)
        _, maximum = policy(public, 15)
        _, single = policy(public[:1], 1)
        with Network(args.node_slh, artifacts, info["address"]) as network:
            network.bootstrap()
            parent = authenticate_coinbase(network.nodes, 1, info["script_hex"])
            scripts = [info["script_hex"], single] + [script for _ in range(4) for script in (maximum, single)] + [single]
            funding = host_call(args.host, "classical-spend", recipe={"kind": args.classical,
                "transaction_version": args.version, "lock_time": 0,
                "expiry_height": network.a.tip()[0] + 20, "parent_hex": parent["parent_hex"],
                "output_index": parent["output_index"],
                "outputs": [{"value_zat": 3_000_000, "script_hex": script} for script in scripts], "fee_zat": 20_000})
            require(network.a.rpc("sendrawtransaction", funding["transaction_hex"]) == funding["txid"],
                    "control_funding_submission")
            wait_for(lambda: funding["txid"] in network.b.rpc("getrawmempool"), "control_funding_relay")
            network.mine()
            authenticated_outputs(network.nodes, funding["txid"], funding["outputs"])
            write_json(artifacts / "control-funding.json", funding)
            mixed = mixed_controls(args, artifacts, network, funding, keys)
            blocks = block_controls(args, artifacts, network, funding, keys, producer)
        return {"producer": producer, "mixed_inputs": mixed, "block_budget": blocks,
                "nodes": network.metadata()}
    finally:
        keys.clear()  # Public fixture material only; not an erasure guarantee.


def namespace(rules):
    return "regtest" if rules is None else "regtest-slh-dsa-b128s-v1-h%d-t%d-b%d" % rules


def state_files(cache, name):
    """Hash only stopped namespaces; no links or nonregular files are accepted."""
    databases = list((cache / "state").glob(f"v*/{name}"))
    require(len(databases) == 1 and (databases[0] / "CURRENT").is_file(), "namespace_database")
    backup = cache / "non_finalized_state" / name
    require(backup.is_dir(), "namespace_backup")
    files = {}
    for directory in [databases[0], backup]:
        for ancestor in [cache, directory.parent, directory.parent.parent, directory]:
            require(not ancestor.is_symlink(), "namespace_symlink")
        for path in sorted(directory.rglob("*")):
            require(not path.is_symlink(), "namespace_symlink")
            if path.is_dir():
                continue
            require(path.is_file(), "namespace_special_file")
            files[str(path.relative_to(cache))] = sha256(path)
    require(any(str(path).startswith(str(backup.relative_to(cache)) + "/") for path in files),
            "namespace_backup_empty")
    return files


def backup_tip(node, cache, name):
    height, block_hash = node.tip()
    require(re.fullmatch("[0-9a-f]{64}", block_hash) is not None, "backup_tip_hash")
    expected = bytes.fromhex(node.rpc("getblock", block_hash, 0))
    target = cache / "non_finalized_state" / name / block_hash
    def saved():
        if not target.exists():
            return False
        require(not target.is_symlink() and target.is_file(), "backup_tip_file")
        # Retain the research history driver's exact eight-byte deferred-pool prefix.
        with target.open("rb") as stream:
            actual = stream.read(len(expected) + 9)
        return len(actual) == len(expected) + 8 and actual[8:] == expected
    wait_for(saved, "ordinary_backup_did_not_preserve_tip", 30)
    return {"height": height, "hash": block_hash, "raw_block_sha256": hashlib.sha256(expected).hexdigest()}


def namespace_controls(args, artifacts, info):
    cache = artifacts / "namespace-cache"
    p2p = port()
    node = ManagedNode(args.node_slh, artifacts, "namespace-node", info["address"], p2p)
    retained, rows = {}, []
    base = (110, 16, 64)
    try:
        for rules in (None, base, (111, 16, 64), (110, 15, 64), (110, 16, 65)):
            name = namespace(rules)
            configured(node, p2p, info["address"], cache, rules)
            node.start()
            require(node.tip()[0] == 0 and node.rpc("getpeerinfo") == [], "namespace_reused_old_history")
            node.rpc("generate", 3)
            saved = backup_tip(node, cache, name)
            node.stop()
            for old_name, hashes in retained.items():
                require(state_files(cache, old_name) == hashes, "unopened_namespace_changed")
            retained[name] = state_files(cache, name)
            node.start()
            require(node.tip() == (saved["height"], saved["hash"])
                    and node.rpc("getpeerinfo") == [], "namespace_restart_lost_tip")
            require(backup_tip(node, cache, name) == saved, "namespace_restart_backup")
            node.stop()
            retained[name] = state_files(cache, name)
            rows.append({"namespace": name, "tip": saved, "config_sha256": sha256(node.config),
                         "stopped_files": retained[name], "restart_without_peers": True})
        # Restore the first SLH configuration after all three rule changes.
        configured(node, p2p, info["address"], cache, base)
        node.start()
        saved = rows[1]["tip"]
        require(node.tip() == (saved["height"], saved["hash"]), "restored_rules_lost_history")
        node.stop()
        for name, hashes in retained.items():
            if name != namespace(base):
                require(state_files(cache, name) == hashes, "other_namespace_changed_on_restore")
        return rows
    finally:
        node.close()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    for role in ("node-default", "node-slh", "host", "signer"):
        result.add_argument("--" + role, type=Path, required=True)
        result.add_argument("--" + role + "-build", type=Path, required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    result.add_argument("--version", type=int, choices=(5, 6), required=True)
    result.add_argument("--classical", choices=("single", "multisig"), default="single")
    return result


def main(args):
    args.root = ROOT
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {"schema_version": 1, "contract": CONTRACT, "complete": False,
               "version": args.version, "classical": args.classical}
    write_json(artifacts / "execution.json", receipt)
    try:
        receipt["builds"] = {role: validate_build(read_json(getattr(args, role + "_build")),
            getattr(args, role), role.replace("_", "-"), runtime_required=role == "node_slh")
            for role in ("node_default", "node_slh", "host", "signer")}
        before = source_state()
        info = host_call(args.host, "classical-info", kind=args.classical)
        receipt["startup_refusal"] = startup_refusal(args, artifacts, info["address"])
        receipt["classical_compatibility"] = classical_compatibility(args, artifacts, info)
        receipt["consensus_controls"] = mixed_and_blocks(args, artifacts, info)
        receipt["namespace_restarts"] = namespace_controls(args, artifacts, info)
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
            and path != artifacts / "execution.json"
            and not {"state", "namespace-cache"}.intersection(path.relative_to(artifacts).parts)]
        write_json(artifacts / "execution.json", receipt, fresh=False)


if __name__ == "__main__":
    main(parser().parse_args())
