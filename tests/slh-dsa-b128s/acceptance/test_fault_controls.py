"""Offline receipt/process mocks; never signs, spawns, kills or fills storage."""
import copy
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch

from common import AcceptanceError, read_json, write_json
import fault_controls as controls


def receipt(request, pid, event):
    checks = (["named_stage_reached"] if event == "reached" else
              controls.PREPARED if request["phase"] == "prepare" else
              controls.RECOVERED if request["phase"] == "reopen" else
              ["operation_succeeded" if request["mode"] == "positive" else "exact_fault_error"])
    return dict(schema_version=1, **{key: request[key] for key in ("case", "stage", "mode", "phase", "token")},
                pid=pid, event=event, state_sha256="ab" * 32, checks=list(checks))


class FakeProcess:
    def __init__(self, owner, request):
        self.owner, self.request = owner, request
        self.pid = 1000 + len(owner.calls)
        self.closed = self.killed = False
        owner.calls.append(self)
        self.fault = owner.mutation if request["mode"] != "positive" else None
        if owner.mutation == "after-positive" and len(owner.calls) >= 7:
            self.fault = "exit"
        if request["phase"] == "run" and self.fault != "missing-stage":
            value = receipt(request, self.pid, "reached")
            if self.fault == "wrong-token": value["token"] = "0" * 32
            if self.fault == "wrong-stage": value["stage"] = "other"
            if self.fault == "wrong-pid": value["pid"] += 1
            write_json(Path(request["directory"]) / "run-reached.json", value)
        if request["mode"] != "kill" or request["phase"] != "run" or self.fault == "kill-noop":
            value = receipt(request, self.pid, "complete")
            if self.fault == "missing-invariant" and request["phase"] == "reopen":
                value["checks"].remove("reservation_retained")
            write_json(Path(request["directory"]) / (request["phase"] + "-complete.json"), value)
    def wait(self, _timeout):
        if self.fault == "timeout": raise AcceptanceError("fault_process_timeout")
        return 17 if self.fault == "exit" else 0
    def reached(self):
        path = Path(self.request["directory"]) / "run-reached.json"
        if not path.exists(): raise AcceptanceError("fault_stage_timeout")
        return read_json(path)
    def kill(self):
        self.killed = True
        return 0 if self.fault == "wrong-exit" else -signal.SIGKILL
    def close(self): self.closed = True


class Factory:
    def __init__(self, mutation=None): self.mutation, self.calls = mutation, []
    def __call__(self, _binary, request): return FakeProcess(self, request)


class FaultControlsTests(unittest.TestCase):
    def run_case(self, mode="io", mutation=None, case="migration", stage="FileSync"):
        records, factory, persisted = [], Factory(mutation), []
        controls.bracket(Path("/unused-test-executable"), case, stage, mode, records,
                         factory=factory, persist=lambda: persisted.append(copy.deepcopy(records)))
        return records, factory, persisted

    def test_positive_fault_positive_requires_all_three_phases(self):
        for mode in ("io", "kill"):
            records, factory, persisted = self.run_case(mode)
            self.assertEqual(len(factory.calls), 9)
            self.assertTrue(all(process.closed for process in factory.calls))
            group = records[0]
            self.assertTrue(group["complete"])
            self.assertEqual([a["role"] for a in group["attempts"]], ["before", "fault", "after"])
            self.assertEqual([p["phase"] for p in group["attempts"][1]["phases"]], ["prepare", "run", "reopen"])
            self.assertTrue(all(a["complete"] for a in group["attempts"]))
            self.assertGreater(len(persisted), 18)
            public = repr(records)
            self.assertNotIn("directory", public)
            self.assertNotIn("backup.tpq", public)
            self.assertTrue(all(not Path(p.request["directory"]).exists() for p in factory.calls))
            self.assertEqual(sum(p.killed for p in factory.calls), 1 if mode == "kill" else 0)

    def test_negative_never_accepts_arbitrary_exit_or_noop(self):
        for mutation in ("exit", "timeout", "missing-stage", "wrong-token", "wrong-stage", "wrong-pid", "missing-invariant", "after-positive"):
            with self.subTest(mutation=mutation), self.assertRaises(AcceptanceError):
                self.run_case(mutation=mutation)

    def test_kill_requires_matching_reached_marker_and_sigkill(self):
        for mutation in ("missing-stage", "wrong-token", "wrong-stage", "wrong-pid", "wrong-exit", "kill-noop"):
            with self.subTest(mutation=mutation), self.assertRaises(AcceptanceError):
                self.run_case("kill", mutation)

    def test_failed_attempt_keeps_receipts_and_prevents_after_control(self):
        records, factory = [], Factory("wrong-exit")
        with self.assertRaisesRegex(AcceptanceError, "wrong_fault_process_exit"):
            controls.bracket(Path("/unused"), "migration", "FileSync", "kill", records, factory=factory)
        self.assertFalse(records[0]["complete"])
        self.assertEqual(len(records[0]["attempts"]), 2)
        phase = records[0]["attempts"][1]["phases"][-1]
        self.assertFalse(phase["complete"])
        self.assertEqual(phase["receipts"][0]["event"], "reached")
        self.assertEqual(phase["returncode"], 0)
        self.assertTrue(all(p.closed for p in factory.calls))

    def test_stage_identity_is_validated_before_any_kill(self):
        records, factory = [], Factory("wrong-token")
        with self.assertRaises(AcceptanceError):
            controls.bracket(Path("/unused"), "migration", "FileSync", "kill", records, factory=factory)
        self.assertFalse(any(p.killed for p in factory.calls))

    def test_each_prepared_case_and_stage_has_offline_bracketing(self):
        for case, stages in controls.CASES.items():
            for stage in stages:
                self.run_case(case=case, stage=stage)
        self.assertIn("ObjectsSyncAfterPublish", controls.CASES["migration"])

    def test_unsupported_kill_scope_and_unknown_stage_refuse(self):
        for case in ("entropy", "final-publication", "quota"):
            with self.assertRaisesRegex(AcceptanceError, "fault_mode"):
                self.run_case("kill", case=case, stage=controls.CASES[case][0])
        with self.assertRaisesRegex(AcceptanceError, "fault_case"):
            self.run_case(stage="not-a-stage")

    def test_complete_matrix_is_validated_before_any_execution(self):
        self.assertEqual(len(controls.selection("all", "both")), 59)
        self.assertEqual(len(controls.selection("all", "io")), 31)
        self.assertEqual(controls.selection("entropy", "both"), [("entropy", "BeforeSign", "io")])
        with self.assertRaisesRegex(AcceptanceError, "fault_mode"):
            controls.selection("all", "kill")

    def test_distinct_attempt_tokens_are_required(self):
        with patch.object(controls.secrets, "token_hex", return_value="ab" * 16):
            with self.assertRaisesRegex(AcceptanceError, "fault_reused_attempt"):
                self.run_case()

    def test_receipt_schema_and_exact_checks(self):
        request = dict(token="12" * 16, case="migration", stage="FileWrite", mode="io", phase="reopen")
        value = receipt(request, 42, "complete")
        self.assertIs(controls.validate_receipt(value, request, 42, "complete"), value)
        for mutate in (lambda v: v.update(secret="forbidden"), lambda v: v.update(pid=True),
                       lambda v: v.update(schema_version=True), lambda v: v.update(state_sha256="ff"),
                       lambda v: v.update(checks=controls.RECOVERED[:-1])):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(AcceptanceError):
                controls.validate_receipt(invalid, request, 42, "complete")

    def test_exact_test_process_command_no_cargo_or_wallet_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            request = dict(directory=directory, token="12" * 16, case="migration", stage="FileWrite", mode="io", phase="run")
            child = Mock(pid=73)
            child.poll.return_value = 0
            with patch.object(controls.subprocess, "Popen", return_value=child) as popen:
                process = controls.Process(Path("/test-executable"), request)
                args, kwargs = popen.call_args
                self.assertEqual(args[0], ["/test-executable", "--ignored", "--exact", controls.TEST, "--test-threads=1"])
                self.assertEqual(kwargs["env"][controls.ENV], str(Path(directory) / "run-request.json"))
                self.assertEqual(kwargs["stdout"], controls.subprocess.DEVNULL)
                process.close()
                child.kill.assert_not_called()

    def test_actual_process_adapter_refuses_early_exit_before_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            request = dict(directory=directory, token="12" * 16, case="migration", stage="FileWrite", mode="kill", phase="run")
            child = Mock(pid=73)
            child.poll.return_value = 23
            with patch.object(controls.subprocess, "Popen", return_value=child):
                process = controls.Process(Path("/test-executable"), request)
                with self.assertRaisesRegex(AcceptanceError, "fault_process_exited_before_stage"):
                    process.reached()
                child.kill.assert_not_called()


if __name__ == "__main__": unittest.main()
