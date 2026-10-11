"""Offline receipt/process mocks; never signs, spawns, kills or fills storage."""
import copy
from pathlib import Path
import re
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from common import ROOT, AcceptanceError, read_json, write_json
import fault_controls as controls

WALLET = ROOT / "crates/pq-wallet/src"
SOURCE = (WALLET / "payment/tests/faults.rs").read_text()
# The ignored Rust driver's own receipt check lists: prepare, run, reopen.
COMPLETE = [re.findall(r'"([a-z_]+)"', block)
            for block in re.findall(r'receipt\(\s*"complete",\s*&\[(.*?)\]', SOURCE, re.S)]


def receipt(request, pid, event):
    checks = (["named_stage_reached"] if event == "reached" else
              COMPLETE[0] if request["phase"] == "prepare" else
              COMPLETE[2] if request["phase"] == "reopen" else
              [COMPLETE[1][1] if request["mode"] == "positive" else COMPLETE[1][2]])
    return dict(schema_version=1, **{key: request[key] for key in ("case", "stage", "mode", "phase", "token")},
                pid=pid, event=event, state_sha256="ab" * 32, checks=list(checks))


def rust_request(request):
    """The ignored driver's Request deny_unknown_fields and validate() rules."""
    assert set(request) == {"directory", "token", "case", "stage", "mode", "phase"}
    directory = Path(request["directory"])
    assert directory.is_absolute() and directory.resolve() == directory
    assert directory.stat().st_mode & 0o077 == 0
    assert re.fullmatch("[0-9a-f]{32}", request["token"])
    assert request["mode"] in ("positive", "io", "kill") and request["phase"] in ("prepare", "run", "reopen")
    assert request["stage"] in controls.CASES[request["case"]]
    assert request["mode"] != "kill" or request["case"] in ("migration", "receive", "backup")


class FakeProcess:
    def __init__(self, owner, request):
        rust_request(request)
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

    def failed_case(self, mode, mutation, reason):
        records, factory = [], Factory(mutation)
        with self.assertRaisesRegex(AcceptanceError, reason):
            controls.bracket(Path("/unused"), "migration", "FileSync", mode, records, factory=factory)
        self.assertFalse(records[0]["complete"])
        self.assertTrue(all(process.closed for process in factory.calls))
        return factory

    def test_negative_never_accepts_arbitrary_exit_or_noop(self):
        # Fault-attempt processes are 4..6; the final positive attempt starts at 7.
        for mutation, reason, launched in (("exit", "fault_driver_assertion_failed", 4),
                                           ("timeout", "fault_process_timeout", 4),
                                           ("missing-stage", "fault_stage_not_reached", 5),
                                           ("wrong-token", "fault_receipt_identity", 5),
                                           ("wrong-stage", "fault_receipt_identity", 5),
                                           ("wrong-pid", "fault_receipt_process", 5),
                                           ("missing-invariant", "fault_invariants_missing", 6),
                                           ("after-positive", "fault_driver_assertion_failed", 7)):
            with self.subTest(mutation=mutation):
                factory = self.failed_case("io", mutation, reason)
                self.assertEqual(len(factory.calls), launched)

    def test_kill_requires_matching_reached_marker_and_sigkill(self):
        for mutation, reason in (("missing-stage", "fault_stage_timeout"), ("wrong-token", "fault_receipt_identity"),
                                 ("wrong-stage", "fault_receipt_identity"), ("wrong-pid", "fault_receipt_process"),
                                 ("wrong-exit", "wrong_fault_process_exit"), ("kill-noop", "killed_operation_completed")):
            with self.subTest(mutation=mutation):
                factory = self.failed_case("kill", mutation, reason)
                self.assertEqual(len(factory.calls), 5)
                self.assertEqual(factory.calls[-1].killed, mutation in ("wrong-exit", "kill-noop"))

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
        with self.assertRaisesRegex(AcceptanceError, "fault_receipt_identity"):
            controls.bracket(Path("/unused"), "migration", "FileSync", "kill", records, factory=factory)
        self.assertFalse(any(p.killed for p in factory.calls))

    def test_each_prepared_case_and_stage_has_offline_bracketing(self):
        seen = set()
        for case, stages in controls.CASES.items():
            for stage in stages:
                records, factory, _ = self.run_case(case=case, stage=stage)
                self.assertTrue(records[0]["complete"])
                # Every launched request passed the Rust driver's validate() rules.
                self.assertEqual([(p.request["mode"], p.request["phase"]) for p in factory.calls],
                                 [(mode, phase) for mode in ("positive", "io", "positive")
                                  for phase in ("prepare", "run", "reopen")])
                seen.update((p.request["case"], p.request["stage"]) for p in factory.calls)
        self.assertEqual(seen, {(case, stage) for case, rows in controls.CASES.items() for stage in rows})

    def test_python_cases_checks_and_test_identity_match_rust_driver(self):
        validate = SOURCE.split("fn validate(&self) {", 1)[1].split('_ => panic!("unknown fault case")', 1)[0]
        cases = {}
        for names, stages in re.findall(r'((?:"[a-z-]+"\s*\|\s*)*"[a-z-]+")\s*=>\s*&\[(.*?)\]', validate, re.S):
            for name in re.findall(r'"([a-z-]+)"', names):
                cases[name] = tuple(re.findall(r'"(\w+)"', stages))
        self.assertEqual(cases, controls.CASES)
        kill = re.search(r'self\.mode != "kill" \|\| matches!\(self\.case\.as_str\(\), ([^)]*)\)', SOURCE)
        self.assertEqual(set(re.findall(r'"([a-z-]+)"', kill.group(1))), {"migration", "receive", "backup"})
        self.assertEqual([case for case in controls.CASES if controls.selection(case, "both")[-1][2] == "kill"],
                         ["migration", "receive", "backup"])
        self.assertEqual(COMPLETE, [controls.PREPARED, ["positive", "operation_succeeded", "exact_fault_error"],
                                    controls.RECOVERED])
        self.assertEqual(SOURCE.count('receipt("reached", &["named_stage_reached"])'), 3)
        fields = SOURCE.split("struct Request {", 1)[1].split("}", 1)[0]
        self.assertEqual(re.findall(r"(\w+): \w+,", fields), ["directory", "token", "case", "stage", "mode", "phase"])
        self.assertIn("#[serde(deny_unknown_fields)]\nstruct Request {", SOURCE)
        self.assertIn(f'std::env::var_os("{controls.ENV}")', SOURCE)
        self.assertRegex(SOURCE, r'#\[test\]\n#\[ignore = "[^"]+"\]\nfn human_fault_case\(\) \{')
        module, test = controls.TEST.rsplit("::", 1)
        self.assertEqual((module, test), ("payment::tests::faults", "human_fault_case"))
        self.assertRegex((WALLET / "lib.rs").read_text(), r"(?m)^pub mod payment;$")
        self.assertRegex((WALLET / "payment/mod.rs").read_text(), r"(?m)^mod tests;$")
        self.assertRegex((WALLET / "payment/tests.rs").read_text(), r"(?m)^mod faults;$")

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
        for case, mode, reason in (("entropy", "kill", "fault_mode"), ("all", "kill", "fault_mode"),
                                   ("unknown", "io", "fault_case")):
            with self.subTest(case=case, mode=mode), tempfile.TemporaryDirectory() as directory:
                args = SimpleNamespace(case=case, mode=mode, artifacts=Path(directory) / "run",
                                       wallet_tests=Path(directory) / "tests", wallet_build=Path(directory) / "build.json")
                with patch.object(controls, "source_state", side_effect=AssertionError("source read")) as source, \
                        patch.object(controls, "validate_build", side_effect=AssertionError("build read")) as build, \
                        patch.object(controls, "bracket", side_effect=AssertionError("launched")) as bracket, \
                        self.assertRaisesRegex(AcceptanceError, reason):
                    controls.run(args)
                self.assertFalse(args.artifacts.exists())
                for mock in (source, build, bracket):
                    mock.assert_not_called()

    def test_distinct_attempt_tokens_are_required(self):
        with patch.object(controls.secrets, "token_hex", return_value="ab" * 16):
            with self.assertRaisesRegex(AcceptanceError, "fault_reused_attempt"):
                self.run_case()

    def test_receipt_schema_and_exact_checks(self):
        request = dict(token="12" * 16, case="migration", stage="FileWrite", mode="io", phase="reopen")
        value = receipt(request, 42, "complete")
        self.assertIs(controls.validate_receipt(value, request, 42, "complete"), value)
        for mutate, reason in ((lambda v: v.update(secret="forbidden"), "fault_receipt_schema"),
                               (lambda v: v.update(pid=True), "fault_receipt_process"),
                               (lambda v: v.update(schema_version=True), "fault_receipt_process"),
                               (lambda v: v.update(state_sha256="ff"), "fault_state_hash"),
                               (lambda v: v.update(state_sha256="AB" * 32), "fault_state_hash"),
                               (lambda v: v.update(event="reached"), "fault_receipt_identity"),
                               (lambda v: v.update(checks=COMPLETE[2][:-1]), "fault_invariants_missing"),
                               (lambda v: v.update(checks=COMPLETE[2][::-1]), "fault_invariants_missing")):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.subTest(reason=reason), self.assertRaisesRegex(AcceptanceError, reason):
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

    def actual(self, directory, child, mode="kill"):
        request = dict(directory=directory, token="12" * 16, case="migration", stage="FileWrite", mode=mode, phase="run")
        with patch.object(controls.subprocess, "Popen", return_value=child):
            return controls.Process(Path("/test-executable"), request), request

    def test_actual_process_adapter_converts_timeouts_and_kills_after_validated_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            child = Mock(pid=73)
            child.wait.side_effect = subprocess.TimeoutExpired("test-executable", 240)
            process, _ = self.actual(directory, child, "io")
            with self.assertRaisesRegex(AcceptanceError, "fault_process_timeout"):
                process.wait(240)
        with tempfile.TemporaryDirectory() as directory:
            child = Mock(pid=73)
            child.poll.return_value = None
            child.wait.return_value = -signal.SIGKILL
            process, request = self.actual(directory, child)
            with patch.object(controls, "STAGE_WAIT", 0), \
                    self.assertRaisesRegex(AcceptanceError, "fault_stage_timeout"):
                process.reached()
            value = write_json(Path(directory) / "run-reached.json", receipt(request, 73, "reached"))
            self.assertEqual(process.reached(), read_json(value))
            self.assertEqual(process.kill(), -signal.SIGKILL)
            child.kill.assert_called_once_with()
            child.wait.assert_called_once_with(timeout=10)
            write_json(value, receipt(request, 74, "reached"), fresh=False)
            with self.assertRaisesRegex(AcceptanceError, "fault_receipt_process"):
                process.reached()
            write_json(value, receipt(request, 73, "reached"), fresh=False)
            child.poll.return_value = 0
            with self.assertRaisesRegex(AcceptanceError, "fault_process_exited_before_kill"):
                process.reached()
            with self.assertRaisesRegex(AcceptanceError, "fault_process_exited_before_kill"):
                process.kill()
            child.kill.assert_called_once_with()

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
