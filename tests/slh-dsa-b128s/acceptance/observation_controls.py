#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""HUMAN ONLY: funded functional brackets and saved-byte SLH lifecycle capture.

Reuses the pinned research proposal/closed-process observation and history/relay
mechanisms through the current product adapters. Importing launches nothing.
"""
import argparse
from pathlib import Path

import observations
from common import (ROOT, CONTRACT, AcceptanceError, common_tip, read_json, require,
                    sha256, source_state, validate_build, write_json, zat)
from generate_transactions import host_call, producer_identity, seed, signer_call
from lifecycle_controls import single_artifact, utxos
from node_live import authenticated_outputs, policy, reconcile_saved, transaction_state
from nodes import Network, SLH_HEIGHT, authenticate_coinbase
from transparent_controls import (ACTIVE_MIXED, AUTHORIZATION_RELAY, STANDARD_SIZE,
    Controls, authorization_variants, fee, mine_to, mixed_artifacts,
    proposal_rejection, reject_relay, rollback)


MIXED_NAMES = [f"mixed-{kind}-{int(first)}"
               for kind in ("multisig", "unsupported51", "unsupported52") for first in (True, False)]
REJECTION_METHODS = ["sendrawtransaction", "proposal", "submitblock"]


class Attempts:
    """Retain intended operations before dispatch, including failed attempts."""
    def __init__(self, path):
        self.path, self.rows = path, []

    def call(self, label, node, method, tx, action, candidate=None):
        require(len(self.rows) < 512, "capture_attempt_bound")
        row = {"ordinal": len(self.rows), "label": label, "node": node, "method": method,
               "identity": transaction_identity(tx), "transaction_sha256": tx["transaction_sha256"],
               "complete": False}
        if candidate is not None:
            row["block_hash"] = candidate["block_hash"]
            row["block_sha256"] = observations.digest(bytes.fromhex(candidate["block_hex"]))
        self.rows.append(row)
        write_json(self.path, self.rows, fresh=len(self.rows) == 1)
        try:
            result = action()
            row.update(complete=True, result=result)
            return result
        except BaseException as error:
            row["failure"] = str(error) if isinstance(error, AcceptanceError) else type(error).__name__
            raise
        finally:
            write_json(self.path, self.rows, fresh=False)


def transaction_identity(tx):
    result = {name: tx[name] for name in ("txid", "auth_digest")}
    observations.identity(result)
    return result


def identify(nodes, tx):
    """Bind exact public bytes to both nodes' ordinary decoded identities."""
    raw = tx["transaction_hex"]
    require(type(raw) is str and 0 < len(raw) <= 524288 and len(raw) % 2 == 0
            and all(char in "0123456789abcdef" for char in raw), "capture_transaction_bytes")
    require(observations.digest(bytes.fromhex(raw)) == tx["transaction_sha256"],
            "capture_transaction_hash")
    decoded = [node.rpc("decoderawtransaction", raw) for node in nodes]
    ids = [{"txid": row["txid"], "auth_digest": row["authdigest"]} for row in decoded]
    require(ids[0] == ids[1], "capture_decoded_disagreement")
    observations.identity(ids[0])
    for name, value in ids[0].items():
        require(name not in tx or tx[name] == value, "capture_fixture_identity")
    tx.update(ids[0])
    return ids[0]


def parents(network, funding, classical_parent):
    """Public UTXO projection; never serialize Decimal RPC values into receipts."""
    result = []
    for txid, indexes in ((funding["txid"], list(range(10))),
                          (classical_parent["txid"], [classical_parent["output_index"]])):
        rows = utxos(network.nodes, txid, indexes)
        require(all(row is not None for row in rows), "capture_parent_missing")
        result.extend({"txid": txid, "index": index, "value_zat": zat(row["value"]),
            "script_hex": row["scriptPubKey"]["hex"], "coinbase": row["coinbase"],
            "confirmations": row["confirmations"]} for index, row in zip(indexes, rows))
    return result


class CaptureControls:
    def __init__(self, args, artifacts, network, attempts, funding, classical_parent):
        self.base = Controls(args, artifacts, network)
        self.network, self.attempts = network, attempts
        self.funding, self.classical_parent = funding, classical_parent

    def state(self):
        return {"tip": common_tip(self.network.nodes),
                "parents": parents(self.network, self.funding, self.classical_parent),
                "mempools": [node.rpc("getrawmempool") for node in self.network.nodes]}

    def unchanged(self, before):
        require(self.state() == before, "capture_control_changed_state")

    def proposal(self, label, tx, value, *, candidate=None):
        before = self.state()
        require(before["mempools"] == [[], []], "capture_empty_mempools")
        if candidate is None:
            candidate = self.base.block(label, [tx], [value])
        results = []
        for index, node in enumerate(self.network.nodes):
            result = self.attempts.call(label, index, "proposal", tx,
                lambda: node.rpc("getblocktemplate", {"mode": "proposal", "data": candidate["block_hex"]}),
                candidate)
            require(result is None, "capture_positive_proposal_rejected")
            results.append({"node": index, "accepted": True})
        self.unchanged(before)
        return {"identity": transaction_identity(tx), "block_hash": candidate["block_hash"],
                "block_sha256": observations.digest(bytes.fromhex(candidate["block_hex"])),
                "results": results, "state": before, "state_unchanged": True}

    def reject(self, label, tx, value, patterns, reason):
        before = self.state()
        require(before["mempools"] == [[], []], "capture_empty_mempools")
        candidate = self.base.block(label, [tx], [value])
        rows = []
        for index, node in enumerate(self.network.nodes):
            relay = self.attempts.call(label, index, "sendrawtransaction", tx,
                lambda: reject_relay(node, tx["transaction_hex"], patterns))
            proposal = self.attempts.call(label, index, "proposal", tx,
                lambda: node.rpc("getblocktemplate", {"mode": "proposal", "data": candidate["block_hex"]}),
                candidate)
            proposal_rejection(proposal, reason)
            submitted = self.attempts.call(label, index, "submitblock", tx,
                lambda: node.rpc("submitblock", candidate["block_hex"]), candidate)
            require(submitted == "rejected", "capture_invalid_block_accepted")
            rows.append({"node": index, "relay": relay, "proposal": proposal, "submitblock": submitted})
        self.unchanged(before)
        return {"identity": transaction_identity(tx), "results": rows, "state": before,
                "state_unchanged": True}


def check_attempts(attempts, start, expected):
    actual = [(row["label"], row["node"], row["method"]) for row in attempts.rows[start:]]
    require(actual == expected and all(row["complete"] for row in attempts.rows[start:]),
            "capture_subject_not_attempted")


def expected_calls(label, methods):
    return [(label, index, method) for index in range(2) for method in methods]


def active_windows(control, stage, txs, mixed):
    """Two brackets per process; all four positive identities are distinct."""
    require(control.network.a.tip()[0] + 1 >= SLH_HEIGHT, "capture_inactive_window")
    require([case["name"] for case in mixed] == MIXED_NAMES, "capture_mixed_subject_manifest")
    plan = [("zero-before", ["proposal"]), ("structural", REJECTION_METHODS),
            ("classical-funding", ["proposal"]),
            *((name, REJECTION_METHODS) for name in MIXED_NAMES),
            *((name, ["proposal"]) for name in ("zero-after", "cache-before", "saved-first", "saved-repeat")),
            ("changed-authorization", REJECTION_METHODS),
            ("saved-after-refusal", ["proposal"]), ("cache-after", ["proposal"])]
    start = len(control.attempts.rows)
    expected = [row for label, methods in plan for row in expected_calls(stage + "-" + label, methods)]
    results = {}
    def positive(label, tx, value=1_000_000, candidate=None):
        label = stage + "-" + label
        results[label] = control.proposal(label, tx, value, candidate=candidate)
    def negative(label, tx, value, patterns, reason):
        label = stage + "-" + label
        results[label] = control.reject(label, tx, value, patterns, reason)
    positive("zero-before", txs["zero-before"])
    negative("structural", txs["structural"], 1_000_000,
             AUTHORIZATION_RELAY["classical-on-slh"], "encoding")
    positive("classical-funding", txs["classical-funding"], 20_000)
    for case in mixed:
        negative(case["name"], case["transaction"], 100_000, ACTIVE_MIXED, "mixed")
    positive("zero-after", txs["zero-after"])
    positive("cache-before", txs["cache-before"])
    # Reuse this exact block, not a newly built look-alike, for repeated proposals.
    candidate = control.base.block(stage + "-saved-candidate", [txs["saved"]], [1_000_000])
    positive("saved-first", txs["saved"], candidate=candidate)
    positive("saved-repeat", txs["saved"], candidate=candidate)
    negative("changed-authorization", txs["changed-authorization"], 1_000_000,
             AUTHORIZATION_RELAY["corrupt-slh"], "signature")
    positive("saved-after-refusal", txs["saved"], candidate=candidate)
    positive("cache-after", txs["cache-after"])
    check_attempts(control.attempts, start, expected)
    require(all(type(row) is dict and row.get("state_unchanged") is True for row in results.values()),
            "capture_functional_outcome_missing")
    return {"stage": stage, "attempts": [start, len(control.attempts.rows)], "functional": results,
        "windows": [
            {"name": "zero", "before": transaction_identity(txs["zero-before"]),
             "after": transaction_identity(txs["zero-after"]),
             "subjects": [transaction_identity(txs[name]) for name in ("structural", "classical-funding")]
                         + [transaction_identity(case["transaction"]) for case in mixed]},
            {"name": "revalidation", "before": transaction_identity(txs["cache-before"]),
             "after": transaction_identity(txs["cache-after"]),
             "subjects": [transaction_identity(txs[name]) for name in ("saved", "changed-authorization")]}]}


def replay(network, txs, funding, classical_parent):
    saved = [{"txid": txs[name]["txid"], "raw": txs[name]["transaction_hex"]}
             for name in ("saved", "classical-funding")]
    before = common_tip(network.nodes)
    require(all(transaction_state(node, tx) == "absent" for node in network.nodes for tx in saved),
            "capture_replay_already_present")
    result = reconcile_saved(network, saved, 1)
    after = common_tip(network.nodes)
    require(after["height"] == before["height"] + 1 and after["hash"] != before["hash"]
            and result["mined_blocks"] == [after["hash"]], "capture_replay_no_new_block")
    for node in network.nodes:
        block = node.rpc("getblock", after["hash"], 1)
        require(set(block["tx"][1:]) == {tx["txid"] for tx in saved}
                and len(block["tx"]) == 3, "capture_replay_wrong_transactions")
        for tx in saved:
            observed = node.rpc("getrawtransaction", tx["txid"], 1)
            require(observed["hex"] == tx["raw"] and observed["confirmations"] > 0,
                    "capture_replay_wrong_bytes")
    require(utxos(network.nodes, funding["txid"], [1]) == [None]
            and utxos(network.nodes, classical_parent["txid"], [classical_parent["output_index"]]) == [None],
            "capture_replay_parents_unspent")
    return {**result, "before": before, "after": after, "saved": saved, "exact_bytes": True}


def sealed_reports(args, network, stages, artifacts, build):
    require([stage["stage"] for stage in stages] == ["active", "reorg", "reactivated"],
            "capture_stage_manifest")
    reports = []
    for node_index, node in enumerate(network.nodes):
        require(node.process is None and node.stops == [0] * len(stages)
                and len(node.observation_captures) == len(stages), "capture_missing_closed_process")
        require([row["file"] for row in node.observation_captures]
                == [f"observation-{index}.json" for index in range(3)], "capture_process_manifest")
        end = 0
        for stage, capture_ref in zip(stages, node.observation_captures):
            capture_path = node.directory / capture_ref["file"]
            require(sha256(capture_path) == capture_ref["sha256"], "capture_receipt_hash")
            capture = read_json(capture_path)
            require(capture["start_offset"] == end, "capture_process_gap")
            end = capture["end_offset"]
            for window in stage["windows"]:
                result = observations.analyze(capture, node.directory / "node.log", args.node,
                    node.config, build, window["before"], window["after"], window["subjects"])
                path = write_json(artifacts / f'{stage["stage"]}-node-{node_index}-{window["name"]}.json', result)
                reports.append({"stage": stage["stage"], "node": node_index, "window": window["name"],
                                "path": path.name, "sha256": sha256(path)})
                subjects = result["window"]["subjects"]
                if window["name"] == "zero":
                    require(result["window"]["window_entries"] == 0
                            and all(row["process_observed_entries"] == row["window_observed_entries"] == 0
                                    for row in subjects), "capture_zero_work_failed")
                else:
                    require(subjects[0]["window_observed_entries"] >= 3
                            and subjects[1]["window_observed_entries"] > 0, "capture_revalidation_not_observed")
        require(end == (node.directory / "node.log").stat().st_size, "capture_uncounted_log_tail")
    return reports


def execute(args, artifacts, receipt):
    info = host_call(args.host, "classical-info", kind="multisig")
    require(info["ecdsa_checks"] == 2, "capture_classical_quorum")
    producer, _ = producer_identity(args.root, args.host, args.signer)
    generated = signer_call(args.signer, "keygen", seed=seed(0))
    keys = {generated["public_key"]: generated["secret_key"]}
    attempts = Attempts(artifacts / "attempts.json")
    receipt["stages"] = stages = []
    try:
        _, script = policy(list(keys), 1)
        with Network(args.node, artifacts, info["address"], observation_token=args.token) as network:
            base = Controls(args, artifacts, network)
            mine_to(network, 107)
            parent = authenticate_coinbase(network.nodes, 1, info["script_hex"])
            scripts = [info["script_hex"], script, info["script_hex"], script,
                       "51" + script[2:], "52" + script[2:]] + [script] * 4
            funding = host_call(args.host, "control-funding", recipe={"kind": "multisig",
                "transaction_version": args.version, "lock_time": 0, "expiry_height": 210,
                "parent_hex": parent["parent_hex"], "output_index": parent["output_index"],
                "outputs": [{"value_zat": 3_000_000, "script_hex": raw} for raw in scripts], "fee_zat": 20_000})
            require(fee(funding, [zat(utxos(network.nodes, parent["txid"], [parent["output_index"]])[0]["value"])])
                    == 20_000, "capture_funding_fee")
            receipt["funding"] = base.accept("funding", [funding], [20_000])
            require(network.a.tip()[0] == 108, "capture_funding_height")
            mine_to(network, SLH_HEIGHT)
            classical_parent = authenticate_coinbase(network.nodes, 2, info["script_hex"])
            txs = {name: single_artifact(args, keys, producer, funding["txid"], index, 210, name)
                   for name, index in (("saved", 1), ("zero-before", 6), ("zero-after", 7),
                                       ("cache-before", 8), ("cache-after", 9))}
            classical = host_call(args.host, "classical-spend", recipe={"kind": "multisig",
                "transaction_version": args.version, "lock_time": 0, "expiry_height": 210,
                "parent_hex": funding["transaction_hex"], "output_index": 0,
                "outputs": [{"value_zat": 1_000_000, "script_hex": info["script_hex"]}], "fee_zat": 20_000})
            variants = authorization_variants(args, artifacts, classical, txs["saved"])
            txs["structural"], txs["changed-authorization"] = variants[2:]
            txs["classical-funding"] = host_call(args.host, "classical-spend", recipe={"kind": "multisig",
                "transaction_version": args.version, "lock_time": 0, "expiry_height": 210,
                "parent_hex": classical_parent["parent_hex"], "output_index": classical_parent["output_index"],
                "outputs": [{"value_zat": 3_000_000, "script_hex": script}], "fee_zat": 20_000})
            mixed = mixed_artifacts(args, artifacts, funding, keys, 210)
            for name, tx in [("funding", funding), *txs.items(),
                             *((case["name"], case["transaction"]) for case in mixed)]:
                identify(network.nodes, tx)
                write_json(artifacts / ("identified-" + name + ".json"), tx)
            require(fee(txs["classical-funding"], [zat(utxos(network.nodes, classical_parent["txid"],
                    [classical_parent["output_index"]])[0]["value"])]) == 20_000, "capture_classical_fee")
            require(txs["saved"]["txid"] == txs["changed-authorization"]["txid"]
                    and txs["saved"]["auth_digest"] != txs["changed-authorization"]["auth_digest"],
                    "capture_changed_authorization_identity")
            receipt["producer"] = producer
            control = CaptureControls(args, artifacts, network, attempts, funding, classical_parent)
            for stage in ("active", "reorg", "reactivated"):
                authenticated_outputs(network.nodes, funding["txid"], funding["outputs"])
                stages.append(active_windows(control, stage, txs, mixed))
                stages[-1]["replay"] = replay(network, txs, funding, classical_parent)
                if stage == "active":
                    tip = stages[-1]["replay"]["after"]
                    restored = rollback(network, tip["hash"], tip["height"] - 1)
                    require(restored == stages[-1]["replay"]["before"], "capture_reorg_no_rollback")
                    receipt["reorg"] = restored
                elif stage == "reorg":
                    boundary = network.a.rpc("getblockhash", SLH_HEIGHT - 1)
                    receipt["rollback"] = rollback(network, boundary, SLH_HEIGHT - 2)
                    require(common_tip(network.nodes)["height"] == 108, "capture_activation_no_rollback")
                    inactive, start = [], len(attempts.rows)
                    for case in mixed:
                        inactive.append(control.reject("inactive-" + case["name"], case["transaction"],
                            100_000, STANDARD_SIZE, "script"))
                    check_attempts(attempts, start, [row for name in MIXED_NAMES
                        for row in expected_calls("inactive-" + name, REJECTION_METHODS)])
                    receipt["inactive_refusals"] = inactive
                    network.mine()
                    require(common_tip(network.nodes)["height"] == 109, "capture_no_reactivation")
            receipt["final_tip"] = common_tip(network.nodes)
        receipt["nodes"] = network.metadata()
        receipt["observations"] = sealed_reports(args, network, stages, artifacts, receipt["builds"]["node"])
        require(len(receipt["observations"]) == 12, "capture_reports_missing")
        receipt["claims"] = {"functional_proposals_and_saved_bytes": True,
            "isolated_rpc_counts": False, "queue_drain_barrier": False,
            "deterministic_pending_completed_states": False, "resource_measurement": False}
    finally:
        keys.clear()  # Public deterministic fixture keys; no operational entropy changes.


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    for role in ("node", "host", "signer"):
        result.add_argument("--" + role, type=Path, required=True)
        result.add_argument("--" + role + "-build", type=Path, required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    result.add_argument("--version", type=int, choices=(5, 6), required=True)
    result.add_argument("--token", type=observations.valid_token, required=True)
    return result


def main(args):
    args.root = ROOT
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {"schema_version": 1, "contract": CONTRACT, "complete": False,
               "version": args.version, "token": args.token}
    write_json(artifacts / "execution.json", receipt)
    try:
        receipt["builds"] = {role: validate_build(read_json(getattr(args, role + "_build")),
            getattr(args, role), "node-slh" if role == "node" else role, runtime_required=role == "node")
            for role in ("node", "host", "signer")}
        before = source_state()
        execute(args, artifacts, receipt)
        require(source_state() == before, "capture_source_changed")
        require(all(sha256(getattr(args, role)) == build["binary_sha256"]
                    for role, build in receipt["builds"].items()), "capture_binary_changed")
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
