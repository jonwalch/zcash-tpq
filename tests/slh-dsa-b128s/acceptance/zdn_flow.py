#!/usr/bin/env python3
"""Bounded ZDN journey coordinator. Importing starts no process or RPC.

Only ZDN lifecycle commands dispatch here. Wallet, fault injection and cloud
audits have explicit human review gates. Receipts reference public evidence;
they are neither ZDN operation state nor a wallet payment journal.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from common import (AcceptanceError, FEATURE, canonical, read_json, require,
                    sha256, write_json)

SCHEMA = "tpq-zdn-qualification/v1"
BETA_SHA256 = "20bc7e52be2df2d78706d5e4c453bfa91e42feefcad83d550c5a1abc31a499d2"
PHASES = ("prepare", "network", "observe", "wallets", "fund-review", "fund",
          "pay5-review", "pay5", "pay6-review", "pay6", "update", "reobserve",
          "recovery", "uncertain", "restore", "pay-restored-review",
          "pay-restored", "negatives", "disconnect", "cleanup", "audit")
AUTOMATED = {"network", "observe", "update", "reobserve", "cleanup"}
PAYMENTS = {"fund", "pay5", "pay6", "pay-restored"}
PIN_ROLES = {"zdn", "wallet", "devnet", "config", "request", "chain", "profile",
             "prepare_receipt", "import_receipt", "build_receipt",
             "update_record", "update_manifest", "update_config"}
SLOTS = {"package.json", "descriptor.json", "native-rules.json", "wallet-profile.json",
         "seed-blocks.bin", "host-adapter", "compiled.json", "image.json",
         "image-manifest.json", "image-config.json", "zdn"}


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()), "fields")
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "digest")
    return value


def integer(value, minimum=0):
    require(type(value) is int and minimum <= value <= 2_100_000_000_000_000,
            "integer_zatoshi_or_count")
    return value


def text(value):
    require(type(value) is str and 0 < len(value) <= 512
            and all(32 <= ord(c) < 127 for c in value), "public_text")
    return value


def pin(value, *, check=False):
    fields(value, "path bytes sha256")
    require(type(value["path"]) is str and Path(value["path"]).is_absolute(), "absolute_path")
    integer(value["bytes"], 1)
    digest(value["sha256"])
    if check:
        require(sha256(value["path"]) == value["sha256"]
                and Path(value["path"]).stat().st_size == value["bytes"], "changed_input")
    return value


def reference(path):
    path = Path(path).absolute()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}


def validate_plan(plan):
    fields(plan, "schema beta_sha256 binding pins directory state_dir profile_alias launch payments")
    require(plan["schema"] == SCHEMA and plan["beta_sha256"] == BETA_SHA256, "plan_version")
    binding = fields(plan["binding"], "deployment_id request_sha256 native_fingerprint")
    require(str(uuid.UUID(binding["deployment_id"])) == binding["deployment_id"], "deployment_uuid")
    digest(binding["request_sha256"])
    digest(binding["native_fingerprint"])
    require(type(plan["pins"]) is dict and set(plan["pins"]) == PIN_ROLES, "pin_roles")
    for item in plan["pins"].values():
        pin(item)
    require(binding["request_sha256"] == plan["pins"]["request"]["sha256"], "request_binding")
    for name in ("directory", "state_dir"):
        require(type(plan[name]) is str and Path(plan[name]).is_absolute(), "absolute_directory")
    text(plan["profile_alias"])
    launch = fields(plan["launch"], "ami_id availability_zone reward_address native_port")
    for name in ("ami_id", "availability_zone", "reward_address"):
        text(launch[name])
    require(type(launch["native_port"]) is int and 1 <= launch["native_port"] <= 65535, "native_port")
    require(type(plan["payments"]) is dict and set(plan["payments"]) == PAYMENTS, "payments")
    for name, payment in plan["payments"].items():
        fields(payment, "version amount fee receiver_script sender recipient")
        require(type(payment["version"]) is int
                and payment["version"] == (6 if name in {"pay6", "pay-restored"} else 5), "tx_version")
        integer(payment["amount"], 1)
        integer(payment["fee"], 1)
        require(type(payment["receiver_script"]) is str
                and re.fullmatch(r"(?:[0-9a-f]{2})+", payment["receiver_script"]) is not None,
                "receiver_script")
        expected = {"fund": ("seed", "alice"), "pay5": ("alice", "bob"),
                    "pay6": ("bob", "alice"), "pay-restored": ("alice", "bob")}[name]
        require((payment["sender"], payment["recipient"]) == expected, "payment_direction")
    return plan


def check_inputs(plan, *, cleanup=False):
    """Check pinned bytes; native semantic/recompile checks remain ZDN's job."""
    for role, item in plan["pins"].items():
        if not cleanup or role == "zdn":
            pin(item, check=True)
    if cleanup:
        return  # Removal must not need installed signing tools or local adapter.
    request = read_json(plan["pins"]["request"]["path"])
    fields(request, "schema configSha256 trust compiled image build nodeCount blockIntervalSeconds artifacts")
    require(request["schema"] == "zdn-external-artifact-set/v1", "external_config")
    # Config::fingerprint identifies parsed Rust Config, not raw file bytes.
    # ZDN's require_config checks semantic compatibility during launch.
    digest(request["configSha256"])
    require(type(request["nodeCount"]) is int and request["nodeCount"] >= 2, "two_nodes_required")
    compiled = request["compiled"]
    require(type(compiled) is dict
            and compiled.get("nativeFingerprint") == plan["binding"]["native_fingerprint"]
            and FEATURE in compiled.get("cargoFeatures", []), "native_build_binding")
    artifacts = request["artifacts"]
    require(type(artifacts) is dict and set(artifacts) == SLOTS, "artifact_slots")
    for name, item in artifacts.items():
        fields(item, "bytes sha256")
        pin(dict(item, path=str(Path(plan["directory"]) / name)), check=True)
    require(artifacts["wallet-profile.json"]["sha256"] == plan["pins"]["profile"]["sha256"],
            "profile_binding")


def durable(path, value):
    write_json(path, value)
    descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def locked(directory):
    with (Path(directory) / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def initialize(plan_path, directory):
    plan = validate_plan(read_json(plan_path))
    check_inputs(plan)
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    durable(directory / "plan.json", plan)
    return hashlib.sha256(canonical(plan)).hexdigest()


def load(directory):
    directory = Path(directory)
    plan = validate_plan(read_json(directory / "plan.json"))
    plan_hash = sha256(directory / "plan.json")
    completed = {}
    gap = False
    for phase in PHASES:
        path = directory / (phase + ".json")
        if not path.exists():
            gap = True
            continue
        require(not gap, "phase_gap")
        row = read_json(path)
        fields(row, "phase plan_sha256 evidence")
        require(row["phase"] == phase and row["plan_sha256"] == plan_hash, "receipt_binding")
        pin(row["evidence"], check=True)
        evidence = read_json(row["evidence"]["path"])
        for item in evidence["references"]:
            pin(item, check=True)
        completed[phase] = evidence
    return plan, plan_hash, completed


def next_phase(completed):
    return next((name for name in PHASES if name not in completed), None)


def command(plan, phase):
    """Fixed argv from current cloud_cli.rs, never a shell command or hook."""
    require(phase in AUTOMATED, "human_review_required")
    binary = plan["pins"]["zdn"]["path"]
    saved = [plan["binding"]["deployment_id"], "--state-dir", plan["state_dir"],
             "--profile", plan["profile_alias"]]
    if phase == "network":
        launch = plan["launch"]
        return [binary, "devnet", "up", "--config", plan["pins"]["config"]["path"],
                "--state-dir", plan["state_dir"], "--external-request", plan["pins"]["request"]["path"],
                "--external-request-sha256", plan["binding"]["request_sha256"],
                "--external-directory", plan["directory"], "--external-native-port", str(launch["native_port"]),
                "--ami-id", launch["ami_id"], "--availability-zone", launch["availability_zone"],
                "--reward-address", launch["reward_address"], "--yes"]
    if phase in {"observe", "reobserve"}:
        return [binary, "devnet", "health", *saved, "--wait", "--timeout-seconds", "120"]
    if phase == "update":
        argv = [binary, "devnet", "update", *saved, "--node", "node-2"]
        for flag, role in (("--image-record", "update_record"), ("--image-manifest", "update_manifest"),
                           ("--image-config", "update_config")):
            argv += [flag, plan["pins"][role]["path"]]
        return argv + ["--acknowledge-storage-compatibility", "--yes"]
    return [binary, "devnet", "destroy", *saved, "--delete-data", "--yes"]


def dispatch(directory, approved_plan, *, cleanup=False, runner=subprocess.run):
    """One dispatch maximum. Unknown outcomes require ZDN-owned reconciliation."""
    directory = Path(directory)
    with locked(directory):
        plan, plan_hash, completed = load(directory)
        require(approved_plan == plan_hash, "explicit_plan_approval")
        phase = "cleanup" if cleanup else next_phase(completed)
        require(phase in AUTOMATED, "human_review_required")
        require(phase == "cleanup" or not (directory / "cleanup.dispatch.json").exists(), "cleanup_already_started")
        check_inputs(plan, cleanup=phase == "cleanup")
        argv = command(plan, phase)
        intent = directory / (phase + ".dispatch.json")
        require(not intent.exists(), "dispatch_already_attempted_reconcile_in_zdn")
        # Persist before launch. A crash, timeout or signal must never cause an
        # automatic redispatch. Neither stdout nor stderr is copied to evidence.
        durable(intent, {"phase": phase, "plan_sha256": plan_hash, "argv": argv})
        try:
            result = runner(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=7200, check=False)
            code = result.returncode
        except (OSError, subprocess.SubprocessError):
            code = None
        durable(directory / (phase + ".process.json"), {"returncode": code})
        require(type(code) is int and code == 0, "zdn_outcome_unknown_or_failed_review_saved_operation")
        return phase  # Exit zero alone never advances or qualifies a phase.


CHECKS = {
    "prepare": {"pins_reviewed", "public_only_import", "source_build_features_reviewed",
                "zdn_external_verify_passed", "ordinary_control_unchanged"},
    "network": {"saved_operation_reviewed", "bootstrap_complete", "transition_blocks_complete"},
    "observe": {"fresh_rules_both_nodes", "native_udp_peers", "empty_peer_sync", "relay_both_directions"},
    "wallets": {"persistent_managed_connect", "controlling_terminal", "fresh_alice_bob",
                "profile_authenticated", "no_password_capture"},
    "update": {"saved_operation_reviewed", "storage_mixed_version_reviewed", "retained_disks"},
    "reobserve": {"fresh_rules_both_nodes", "lagging_peer_catchup", "same_native_ids"},
    "recovery": {"zdn_managed_restart", "retained_node_data", "same_native_ids",
                 "same_private_keys_not_exported", "cookies_rotated_not_exported", "connection_reestablished"},
    "uncertain": {"accepted_reply_lost", "original_wallet_record", "reconciled_on_both_peers", "no_replacement_intent"},
    "restore": {"trusted_latest_snapshot", "receipt_independently_retained", "old_allocators_retired",
                "original_payments_reconciled", "known_authority_allocator"},
    "negatives": {"wrong_profile", "wrong_rules", "wrong_approval", "monitor_receive_refused",
                  "monitor_sign_refused", "monitor_submit_refused", "conflicting_spend_refused",
                  "interrupted_bootstrap_reconciled", "interrupted_update_reconciled"},
    "disconnect": {"participant_revoked", "managed_sessions_closed", "local_companion_removed"},
    "cleanup": {"saved_operation_reviewed", "destroy_without_local_companion", "owned_data_deleted"},
    "audit": {"owned_resources_absent", "protected_resources_preserved", "secret_leak_audit",
              "sessions_absent", "kms_deletion_status_recorded"},
}


def required_checks(phase):
    if phase in CHECKS:
        return CHECKS[phase]
    if phase in PAYMENTS:
        return {"wallet_journal_authoritative", "blocks_and_prevouts_independently_reviewed"}
    require(phase in PHASES and phase.endswith("-review"), "unknown_phase")
    return {"independent_review", "no_blind_digest_approval"}


def validate_payment(value, expected, completed, phase):
    fields(value, "proposal_id transaction_sha256 transaction txid version amount fee change receiver_script inputs output_index peers before after")
    for key in ("transaction_sha256", "txid"):
        digest(value[key])
    if phase == "fund":
        require(value["proposal_id"] is None, "funding_has_no_wallet_proposal")
    else:
        digest(value["proposal_id"])
    pin(value["transaction"], check=True)
    require(value["transaction"]["sha256"] == value["transaction_sha256"], "transaction_bytes")
    for key in ("version", "amount", "fee", "receiver_script"):
        require(type(value[key]) is type(expected[key]) and value[key] == expected[key], "payment_intent")
    with Path(value["transaction"]["path"]).open("rb") as stream:
        header = stream.read(4)
    require(len(header) == 4 and (int.from_bytes(header, "little") & 0x7fffffff) == value["version"],
            "transaction_version_bytes")
    integer(value["change"])
    require(type(value["inputs"]) is list and bool(value["inputs"]), "spent_outpoints")
    for item in value["inputs"]:
        fields(item, "txid index value")
        digest(item["txid"])
        integer(item["index"])
        integer(item["value"], 1)
    require(len({(item["txid"], item["index"]) for item in value["inputs"]}) == len(value["inputs"]),
            "duplicate_outpoint")
    require(sum(item["value"] for item in value["inputs"]) == value["amount"] + value["fee"] + value["change"],
            "independent_value_conservation")
    integer(value["output_index"])
    peers = value["peers"]
    require(type(peers) is list and len(peers) == 2, "two_peer_observations")
    for peer in peers:
        fields(peer, "node_id block_hash height txid transaction_sha256 spent_outpoints_authenticated receiver_output_authenticated")
        text(peer["node_id"])
        digest(peer["block_hash"])
        integer(peer["height"], 1)
        require(peer["txid"] == value["txid"] and peer["transaction_sha256"] == value["transaction_sha256"]
                and peer["spent_outpoints_authenticated"] is True
                and peer["receiver_output_authenticated"] is True, "peer_transaction_binding")
    require(peers[0]["node_id"] != peers[1]["node_id"]
            and (peers[0]["height"], peers[0]["block_hash"]) == (peers[1]["height"], peers[1]["block_hash"]),
            "canonical_inclusion")
    for name in ("before", "after"):
        fields(value[name], "alice bob")
        for balance in value[name].values():
            integer(balance)
    before, after = value["before"], dict(value["before"])
    if phase != "fund":
        after[expected["sender"]] -= expected["amount"] + expected["fee"]
    else:
        require(before == {"alice": 0, "bob": 0}, "fresh_wallet_balances")
    after[expected["recipient"]] += expected["amount"]
    require(value["after"] == after and min(after.values()) >= 0, "independent_integer_balances")
    previous = {"pay5": "fund", "pay6": "pay5", "pay-restored": "pay6"}.get(phase)
    if previous:
        require(before == completed[previous]["data"]["after"], "balance_continuity")
    if phase == "pay6":
        received = completed["pay5"]["data"]
        require(any(item == {"txid": received["txid"], "index": received["output_index"],
                             "value": received["amount"]} for item in value["inputs"]), "recipient_must_spend_v5_output")
    if phase == "pay-restored":
        require(all(value["proposal_id"] != completed[name]["data"]["proposal_id"]
                    and value["txid"] != completed[name]["data"]["txid"] for name in ("pay5", "pay6")),
                "restore_requires_new_payment")


def accept(directory, evidence_path):
    """Validate an independently reviewed public gate and advance exactly once."""
    directory = Path(directory)
    with locked(directory):
        plan, plan_hash, completed = load(directory)
        phase = next_phase(completed)
        require(phase is not None, "journey_complete")
        evidence_pin = reference(evidence_path)
        evidence = read_json(evidence_path)
        fields(evidence, "schema phase plan_sha256 binding reviewer checks references data")
        require(evidence["schema"] == SCHEMA and evidence["phase"] == phase
                and evidence["plan_sha256"] == plan_hash and evidence["binding"] == plan["binding"], "gate_binding")
        text(evidence["reviewer"])
        require(type(evidence["references"]) is list and len(evidence["references"]) >= 2, "independent_evidence_references")
        for item in evidence["references"]:
            pin(item, check=True)
        require(len({item["sha256"] for item in evidence["references"]}) >= 2, "distinct_evidence_references")
        fields(evidence["checks"], " ".join(required_checks(phase)))
        require(all(item is True for item in evidence["checks"].values()), "pending_or_failed_check")
        data = evidence["data"]
        if phase.endswith("-review"):
            name = phase.removesuffix("-review")
            fields(data, "intent approved_digest")
            require(data["intent"] == plan["payments"][name], "independent_intent")
            digest(data["approved_digest"])
        elif phase in PAYMENTS:
            validate_payment(data, plan["payments"][phase], completed, phase)
            approval = completed[phase + "-review"]["data"]["approved_digest"]
            require(approval == data["transaction_sha256" if phase == "fund" else "proposal_id"], "approval_binding")
        elif phase == "uncertain":
            fields(data, "original_phase proposal_id original_bytes_sha256 retry_transaction retried_bytes_sha256 txid")
            require(data["original_phase"] in {"pay5", "pay6"}, "uncertain_original_phase")
            original = completed[data["original_phase"]]["data"]
            require(data["proposal_id"] == original["proposal_id"] and data["txid"] == original["txid"]
                    and data["original_bytes_sha256"] == data["retried_bytes_sha256"] == original["transaction_sha256"],
                    "uncertain_exact_original_bytes")
            pin(data["retry_transaction"], check=True)
            require(data["retry_transaction"]["sha256"] == data["original_bytes_sha256"], "retry_file_bytes")
        elif phase == "recovery":
            fields(data, "native_ids_before native_ids_after cookie_rotation_receipt")
            before, after = data["native_ids_before"], data["native_ids_after"]
            require(type(before) is list and type(after) is list and len(before) == len(after) == 2,
                    "native_inventory")
            for item in before + after:
                text(item)
            require(len(set(before)) == 2 and before == after, "retained_native_identity")
            pin(data["cookie_rotation_receipt"], check=True)
        elif phase == "negatives":
            cases = read_json(Path(__file__).with_name("zdn_cases.json"))["negative_controls"]
            fields(data, "controls")
            require(type(data["controls"]) is dict and set(data["controls"]) == {row["id"] for row in cases},
                    "negative_control_matrix")
            for case in cases:
                result = fields(data["controls"][case["id"]], "reason_class effect evidence")
                require(result["reason_class"] == case["reason_class"]
                        and result["effect"] == case["effect"], "negative_control_result")
                pin(result["evidence"], check=True)
        elif phase == "restore":
            fields(data, "snapshot_receipt_sha256 old_allocator new_allocator")
            digest(data["snapshot_receipt_sha256"])
            require(data["snapshot_receipt_sha256"] in {item["sha256"] for item in evidence["references"]},
                    "snapshot_receipt_reference")
            text(data["old_allocator"])
            text(data["new_allocator"])
            require(data["old_allocator"] != data["new_allocator"], "retired_allocator")
        elif phase in AUTOMATED:
            fields(data, "operation_reference ready")
            text(data["operation_reference"])
            require(data["ready"] is True, "not_ready")
            require((directory / (phase + ".dispatch.json")).is_file(), "no_dispatch_evidence")
            # Nonzero/unknown exits can advance only after explicit human review
            # of saved ZDN reconciliation, supplied as one of the pinned refs.
        elif phase == "audit":
            fields(data, "kms_deletion")
            require(data["kms_deletion"] in {"not-applicable", "scheduled-pending", "deleted"}, "kms_status")
        else:
            fields(data, "")
        durable(directory / (phase + ".json"), {"phase": phase, "plan_sha256": plan_hash, "evidence": evidence_pin})
        return next_phase(dict(completed, **{phase: evidence}))


def gate_template(directory, output):
    """Write an explicitly pending review form; never manufacture approvals."""
    plan, plan_hash, completed = load(directory)
    phase = next_phase(completed)
    require(phase is not None, "journey_complete")
    durable(output, {"schema": SCHEMA, "phase": phase, "plan_sha256": plan_hash,
                     "binding": plan["binding"], "reviewer": "REVIEW_REQUIRED",
                     "checks": {name: False for name in sorted(required_checks(phase))},
                     "references": [], "data": {}})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("init")
    init.add_argument("plan", type=Path)
    init.add_argument("directory", type=Path)
    for action in ("next", "dispatch", "accept", "gate"):
        child = sub.add_parser(action)
        child.add_argument("directory", type=Path)
        if action == "dispatch":
            child.add_argument("--approve-plan", required=True)
            child.add_argument("--cleanup", action="store_true",
                               help="cleanup after a failed gate; leaves missing journey phases pending")
        if action == "accept":
            child.add_argument("evidence", type=Path)
        if action == "gate":
            child.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "init":
            print(initialize(args.plan, args.directory))
        elif args.action == "dispatch":
            print(dispatch(args.directory, args.approve_plan, cleanup=args.cleanup))
        elif args.action == "accept":
            print(accept(args.directory, args.evidence) or "complete; live evidence requires independent report review")
        elif args.action == "gate":
            gate_template(args.directory, args.output)
        else:
            plan, plan_hash, completed = load(args.directory)
            phase = next_phase(completed)
            print(json.dumps({"plan_sha256": plan_hash, "phase": phase,
                              "argv": command(plan, phase) if phase in AUTOMATED else None,
                              "human_checks": sorted(required_checks(phase)) if phase else []}, indent=2))
    except (AcceptanceError, OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "qualification input/gate refused; retain evidence and inspect product records\n")


if __name__ == "__main__":
    main()
