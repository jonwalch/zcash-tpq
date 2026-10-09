#!/usr/bin/env python3
"""HUMAN ONLY: bounded wallet test-hook errors, SIGKILL, quota and entropy controls.

Uses the cfg(test)-only ignored wallet driver and its existing private hooks.
Importing this module launches nothing. No node, OS entropy interposition, disk
filling, power-loss simulation or operational runtime fault flags are provided.
"""
import argparse
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import time

from common import (CONTRACT, AcceptanceError, read_json, require, sha256,
                    source_state, validate_build, write_json)

TEST = "payment::tests::faults::human_fault_case"
ENV = "SLH_WALLET_FAULT_REQUEST"
MAX_RECEIPT = 4096
PHASE_TIMEOUT = 240
STAGE_WAIT = 30
CASES = {
    "migration": ("CreateJournal", "CreateObjects", "ObjectsSync", "JournalSync", "WatchSync",
                  "ObjectWrite", "ObjectVerify", "ObjectSync", "ObjectPublish", "ObjectsSyncAfterPublish",
                  "RecoveryWrite", "RecoveryVerify", "RecoverySync", "RecoveryPublish", "RecoveryDirectorySync",
                  "FileWrite", "FileSync", "Publish", "DirectorySync"),
    "receive": ("FileWrite", "FileSync", "Publish", "DirectorySync"),
    "backup": ("Write", "FileSync", "Verify", "Publish", "DirectorySync"),
    "entropy": ("BeforeSign",),
    "final-publication": ("BeforeSign",),
    "quota": ("QuotaPreflight",),
}
PREPARED = ["eligible_prepared_payment", "reserved_input_and_change", "covering_backup"]
RECOVERED = ["old_or_complete_new", "cached_authorization_exact", "retry_exact",
             "reservation_retained", "no_cursor_reuse", "unknown_snapshot_monitor"]


def validate_receipt(value, request, pid, event):
    fields = {"schema_version", "token", "case", "stage", "mode", "phase", "pid", "event", "state_sha256", "checks"}
    require(type(value) is dict and set(value) == fields, "fault_receipt_schema")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and type(value["pid"]) is int and value["pid"] == pid and pid > 0,
            "fault_receipt_process")
    require(all(value[key] == request[key] for key in ("token", "case", "stage", "mode", "phase"))
            and value["event"] == event, "fault_receipt_identity")
    digest = value["state_sha256"]
    require(type(digest) is str and len(digest) == 64
            and all(ch in "0123456789abcdef" for ch in digest), "fault_state_hash")
    checks = (["named_stage_reached"] if event == "reached" else
              PREPARED if request["phase"] == "prepare" else
              RECOVERED if request["phase"] == "reopen" else
              ["operation_succeeded" if request["mode"] == "positive" else "exact_fault_error"])
    require(value["checks"] == checks, "fault_invariants_missing")
    return value


class Process:
    """One exact unit-test process; stdout/panic text is never public evidence."""
    def __init__(self, binary, request):
        self.request = request
        directory = Path(request["directory"])
        path = directory / (request["phase"] + "-request.json")
        write_json(path, request)
        env = dict(os.environ)
        env[ENV] = str(path)
        self.process = subprocess.Popen(
            [str(binary), "--ignored", "--exact", TEST, "--test-threads=1"],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pid = self.process.pid

    def wait(self, timeout):
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise AcceptanceError("fault_process_timeout") from None

    def reached(self):
        path = Path(self.request["directory"]) / "run-reached.json"
        deadline = time.monotonic() + STAGE_WAIT
        while time.monotonic() < deadline:
            if path.exists():
                value = validate_receipt(read_json(path, MAX_RECEIPT), self.request, self.pid, "reached")
                require(self.process.poll() is None, "fault_process_exited_before_kill")
                return value
            require(self.process.poll() is None, "fault_process_exited_before_stage")
            time.sleep(0.02)
        raise AcceptanceError("fault_stage_timeout")

    def kill(self):
        require(self.process.poll() is None, "fault_process_exited_before_kill")
        self.process.kill()
        return self.wait(10)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)


def phase(binary, request, evidence, *, factory=Process, persist=lambda: None):
    """Retain the attempted operation before launching; a failure never disappears."""
    attempt = {"phase": request["phase"], "complete": False, "pid": None,
               "returncode": None, "killed_after_stage": False, "receipts": []}
    evidence.append(attempt)
    persist()
    process = factory(binary, request)
    attempt["pid"] = process.pid
    persist()
    try:
        if request["phase"] == "run" and request["mode"] == "kill":
            attempt["receipts"].append(validate_receipt(process.reached(), request, process.pid, "reached"))
            persist()
            attempt["returncode"] = process.kill()
            require(attempt["returncode"] == -signal.SIGKILL, "wrong_fault_process_exit")
            attempt["killed_after_stage"] = True
            require(not (Path(request["directory"]) / "run-complete.json").exists(), "killed_operation_completed")
        else:
            attempt["returncode"] = process.wait(PHASE_TIMEOUT)
            if request["phase"] == "run":
                path = Path(request["directory"]) / "run-reached.json"
                if path.exists():
                    attempt["receipts"].append(validate_receipt(read_json(path, MAX_RECEIPT), request, process.pid, "reached"))
            require(attempt["returncode"] == 0, "fault_driver_assertion_failed")
            if request["phase"] == "run":
                require(len(attempt["receipts"]) == 1, "fault_stage_not_reached")
            path = Path(request["directory"]) / (request["phase"] + "-complete.json")
            attempt["receipts"].append(validate_receipt(read_json(path, MAX_RECEIPT), request, process.pid, "complete"))
        attempt["complete"] = True
    finally:
        process.close()
        persist()


def attempt(binary, case, stage, mode, output, *, factory=Process, persist=lambda: None):
    record = {"case": case, "stage": stage, "mode": mode, "complete": False,
              "token": secrets.token_hex(16), "phases": []}
    output.append(record)
    # Both roots and canonical authorization bytes remain inside this private
    # disposable tree. No caller-supplied wallet directory can enter the adapter.
    with tempfile.TemporaryDirectory(prefix="slh-wallet-fault-") as name:
        directory = Path(name).resolve()
        directory.chmod(0o700)
        for name in ("prepare", "run", "reopen"):
            request = {key: record[key] for key in ("case", "stage", "mode", "token")}
            request.update(directory=str(directory), phase=name)
            phase(binary, request, record["phases"], factory=factory, persist=persist)
        record["complete"] = True


def bracket(binary, case, stage, mode, output, *, factory=Process, persist=lambda: None):
    require(case in CASES and stage in CASES[case], "fault_case")
    require(mode in ("io", "kill") and (mode != "kill" or case in ("migration", "receive", "backup")), "fault_mode")
    group = {"case": case, "stage": stage, "mode": mode, "complete": False, "attempts": []}
    output.append(group)
    for role, selected in (("before", "positive"), ("fault", mode), ("after", "positive")):
        attempt(binary, case, stage, selected, group["attempts"], factory=factory, persist=persist)
        group["attempts"][-1]["role"] = role
    require(len({row["token"] for row in group["attempts"]}) == 3, "fault_reused_attempt")
    group["complete"] = True


def selection(case, mode):
    """Validate the entire requested matrix before starting any child."""
    require(case == "all" or case in CASES, "fault_case")
    require(mode in ("io", "kill", "both"), "fault_mode")
    selected = CASES if case == "all" else {case: CASES[case]}
    rows = []
    for name, stages in selected.items():
        can_kill = name in ("migration", "receive", "backup")
        require(mode != "kill" or can_kill, "fault_mode")
        modes = ("io", "kill") if mode == "both" and can_kill else ("io",) if mode == "both" else (mode,)
        rows.extend((name, stage, selected_mode) for stage in stages for selected_mode in modes)
    return rows


def run(args):
    require(os.name == "posix" and hasattr(signal, "SIGKILL"), "fault_platform_unsupported")
    selected = selection(args.case, args.mode)
    directory = args.artifacts.resolve()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    before = source_state()
    binary = args.wallet_tests.resolve()
    build = validate_build(read_json(args.wallet_build), binary, "wallet-faults")
    record = {"schema_version": 1, "contract": CONTRACT, "complete": False,
              "source": before, "build": build, "binary_sha256": sha256(binary),
              "platform": os.uname().sysname, "scope": "synthetic-wallet-library-faults-v1",
              "cases": [], "failure": None,
              "unsupported": ["power_loss", "os_disk_exhaustion", "os_entropy_suppression", "live_node_acceptance"]}
    receipt = directory / "execution.json"
    write_json(receipt, record)
    try:
        for case, stage, mode in selected:
            try:
                bracket(binary, case, stage, mode, record["cases"],
                        persist=lambda: write_json(receipt, record, fresh=False))
            finally:
                write_json(receipt, record, fresh=False)
        require(source_state() == before and sha256(binary) == record["binary_sha256"], "fault_source_or_binary_changed")
        record["complete"] = True
    except Exception as error:
        # Never copy panic/exception text: fixed diagnostics only. Partial
        # reached-stage receipts and phase statuses remain available on failure.
        record["failure"] = str(error) if isinstance(error, AcceptanceError) else "fault_unexpected_failure"
        raise
    finally:
        write_json(receipt, record, fresh=False)
    print(f"Fault receipt: {receipt}")


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--human-run", action="store_true", required=True)
    result.add_argument("--wallet-tests", type=Path, required=True)
    result.add_argument("--wallet-build", type=Path, required=True)
    result.add_argument("--artifacts", type=Path, required=True)
    result.add_argument("--case", choices=("all", *CASES), default="all")
    result.add_argument("--mode", choices=("io", "kill", "both"), default="both")
    return result


if __name__ == "__main__":
    run(parser().parse_args())
