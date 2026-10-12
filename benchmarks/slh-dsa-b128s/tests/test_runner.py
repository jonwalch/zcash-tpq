"""Synthetic process and artifact tests; no signer, node or benchmark is run."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import provenance
import run


class ProcessTests(unittest.TestCase):
    def test_streaming_preserves_lines_and_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "logs"
            lines = []
            result = run.supervise([sys.executable, "-c", "import sys; print('one'); print('two'); print('err', file=sys.stderr)"],
                                    root=directory, directory=output, timeout=3, max_bytes=1000,
                                    on_line=lambda pid, line: lines.append((pid, line)))
            self.assertEqual([line for _, line in lines], [b"one", b"two"])
            self.assertTrue(all(pid == result["pid"] for pid, _ in lines))
            self.assertEqual((output / "stderr.log").read_bytes(), b"err\n")

    def test_timeout_is_classified_and_child_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(run.ExecutionError) as failure:
                run.supervise([sys.executable, "-c", "import time; time.sleep(10)"], root=directory,
                              directory=Path(directory) / "logs", timeout=0.1, max_bytes=100)
            self.assertEqual(failure.exception.outcome, "timeout")
            with self.assertRaises(ProcessLookupError):
                os.kill(failure.exception.process_id, 0)

    def test_output_limit_and_partial_line_fail(self):
        for program, maximum, expected in (("print('x' * 10000)", 100, "output limit"),
                                            ("import sys; sys.stdout.write('partial')", 100, "partial final")):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(provenance.BenchmarkError, expected):
                    run.supervise([sys.executable, "-c", program], root=directory,
                                  directory=Path(directory) / "logs", timeout=3, max_bytes=maximum,
                                  on_line=lambda _pid, _line: None)

    def test_nonzero_exit_keeps_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "logs"
            with self.assertRaisesRegex(provenance.BenchmarkError, "status 7"):
                run.supervise([sys.executable, "-c", "print('retained'); raise SystemExit(7)"],
                              root=directory, directory=output, timeout=3, max_bytes=100)
            self.assertEqual((output / "stdout.log").read_text(), "retained\n")


class ProvenanceTests(unittest.TestCase):
    def test_json_rejects_duplicates_and_nonfinite(self):
        for value in (b'{"a": 1, "a": 2}', b'{"a": NaN}', b'{"a": Infinity}', b'{"a": 1e999}', '{}'.encode('utf16')):
            with self.subTest(value=value), self.assertRaises(provenance.BenchmarkError):
                provenance.strict_json(value)

    def test_artifact_inventory_rejects_tampering_and_extra_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "raw.jsonl").write_bytes(b'{}\n')
            inventory = provenance.artifact_inventory(root)
            provenance.verify_artifacts(root, inventory)
            (root / "new").write_bytes(b'new')
            with self.assertRaisesRegex(provenance.BenchmarkError, "inventory changed"):
                provenance.verify_artifacts(root, inventory)
            (root / "new").unlink()
            (root / "raw.jsonl").write_bytes(b'{"changed":true}\n')
            with self.assertRaises(provenance.BenchmarkError):
                provenance.verify_artifacts(root, inventory)

    def test_inventory_rejects_directory_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "link").symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(provenance.BenchmarkError, "artifact symlink"):
                provenance.artifact_inventory(root)

    def test_source_snapshot_requires_clean_tracked_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "input.rs").write_text("pub const N: u32 = 1;\n")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                            "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
            snapshot = provenance.source_state(root)
            self.assertEqual(len(snapshot["files"]), 1)
            (root / "input.rs").write_text("pub const N: u32 = 2;\n")
            with self.assertRaisesRegex(provenance.BenchmarkError, "commit source inputs"):
                provenance.source_state(root)

    def test_claim_is_exclusive_and_persistent(self):
        with tempfile.TemporaryDirectory() as directory:
            provenance.claim_run(directory)
            with self.assertRaises(FileExistsError):
                provenance.claim_run(directory)

    def test_build_overrides_are_part_of_identity(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(provenance, "command_output", return_value="test"), \
                patch.dict(os.environ, {"CARGO_HOME": directory, "CARGO_PROFILE_RELEASE_OPT_LEVEL": "0"}, clear=True):
            identity = provenance.toolchain(directory)
            self.assertEqual(identity["environment"]["CARGO_PROFILE_RELEASE_OPT_LEVEL"], "0")
            with patch.dict(os.environ, {"RUSTC": "custom-rustc"}):
                with self.assertRaisesRegex(provenance.BenchmarkError, "custom Cargo compiler"):
                    provenance.toolchain(directory)


class RegistrationTests(unittest.TestCase):
    def settings(self):
        return {"cases": ["verify"], "samples": 3, "warmup": 1, "repetitions": 2,
                "cache_mode": "repeated-input", "timeout_seconds_per_process": 10,
                "max_output_bytes_per_process": 4096}

    def test_bounds_rechecked_at_execution(self):
        self.assertEqual(run.validate_settings(self.settings()), 10)
        for key, value in (("samples", True), ("warmup", -1), ("cases", ["verify", "verify"]),
                           ("samples", 10001), ("timeout_seconds_per_process", 0)):
            settings = self.settings()
            settings[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(provenance.BenchmarkError):
                run.validate_settings(settings)

    def test_human_execution_switch_is_required(self):
        with self.assertRaisesRegex(provenance.BenchmarkError, "human measurement"):
            run.require_execute(argparse.Namespace(execute=False))

    def test_partial_jsonl_is_not_silently_discarded(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "raw.jsonl"
            raw.write_bytes(b'{"partial":')
            with self.assertRaisesRegex(ValueError, "missing final newline"):
                run.read_records(raw)

    def test_special_record_files_cannot_block_reporting(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "attempts.jsonl"
            os.mkfifo(raw)
            with self.assertRaisesRegex(provenance.BenchmarkError, "regular file"):
                run.read_records(raw)
            with self.assertRaisesRegex(provenance.BenchmarkError, "non-regular artifact"):
                provenance.artifact_inventory(directory)

    def test_total_limit_reserves_terminal_failure_record(self):
        settings = self.settings()
        settings.update(samples=9999, warmup=0, repetitions=10)
        with self.assertRaisesRegex(provenance.BenchmarkError, "reserves a failure"):
            run.validate_settings(settings)


class ExecutionTests(unittest.TestCase):
    """Exercise complete runner receipts with injected child output, no crypto."""

    def prepare(self, root, case="verify"):
        build = root / "build"
        build.mkdir()
        provenance.atomic_json(build / "build.json", {"synthetic": True})
        output = root / "run"
        output.mkdir()
        settings = {"cases": [case], "samples": 1, "warmup": 0, "repetitions": 1,
                    "cache_mode": "repeated-input", "timeout_seconds_per_process": 10,
                    "max_output_bytes_per_process": 4096}
        manifest = {"schema_version": 1, "kind": "primitive", "run_id": "synthetic",
                    "configuration_id": provenance.digest_value(settings), "settings": settings,
                    "build_directory": str(build), "build_receipt_sha256": provenance.sha256(build / "build.json"),
                    "build": {"synthetic": True}, "host": {"synthetic": True},
                    "host_profile": {"description": "mock", "cpu_model": "mock", "affinity": "mock",
                                     "power_policy": "mock", "effective_cpu_cores": 1, "memory_limit_bytes": 1024},
                    "expected_records": 2, "metric_catalog_sha256": provenance.sha256(HERE / "schema/metrics.json"),
                    "runner_sha256": provenance.sha256(HERE / "run.py")}
        provenance.atomic_json(output / "manifest.json", manifest)
        return output, manifest

    def child_rows(self, case, outcome=None):
        metric = "signature_verify_ns"
        base = {"case_id": "primitive." + case, "cache_mode": "repeated-input", "warmup": False,
                "outcome": outcome or ("expected_rejection" if case == "verify-invalid" else "success"),
                "unavailable": {}, "censored": []}
        return [{**base, "phase": "primitive", "metrics": {
            metric: 10, "attempt_elapsed_ns": 10, "process_cpu_ns": 5,
            "process_cpu_core_equivalents": 0.5, "rss_before_bytes": 100, "rss_after_bytes": 110,
            "public_key_bytes": 32, "message_bytes": 101, "signature_bytes": 7856}},
                {**base, "phase": "process", "outcome": "success", "metrics": {"process_peak_rss_bytes": 120}}]

    def execute(self, output, rows):
        def supervisor(_command, **kwargs):
            for row in rows:
                kwargs["on_line"](123, provenance.canonical(row))
            return {"pid": 123, "exit_code": 0, "elapsed_ns": 100, "output_bytes": 10}
        with patch.object(run, "validate_build", return_value={"synthetic": True}), \
                patch.object(run, "host_state", return_value={"synthetic": True}), \
                patch.object(run, "supervise", side_effect=supervisor):
            return run.execute(argparse.Namespace(execute=True, directory=output))

    def test_complete_receipt_reports_and_cannot_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, _ = self.prepare(root)
            receipt = self.execute(output, self.child_rows("verify"))
            self.assertTrue(receipt["complete"] and receipt["successful"])
            report = run.summarize_run(argparse.Namespace(directory=output, output=root / "report", process_id=None))
            self.assertTrue(report["successful"])
            with self.assertRaisesRegex(provenance.BenchmarkError, "already attempted"):
                self.execute(output, [])

    def test_short_success_exit_retains_explicit_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output, _ = self.prepare(Path(directory))
            with self.assertRaisesRegex(provenance.BenchmarkError, "missing child"):
                self.execute(output, self.child_rows("verify")[:1])
            receipt = provenance.read_json(output / "receipt.json")
            self.assertFalse(receipt["complete"])
            rows = run.read_records(output / "attempts.jsonl")
            self.assertEqual([row["outcome"] for row in rows], ["success", "error"])
            provenance.verify_artifacts(output, receipt["artifacts"])

    def test_wrong_case_outcome_cannot_succeed(self):
        for case, outcome in (("verify", "expected_rejection"), ("verify-invalid", "success")):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                output, _ = self.prepare(Path(directory), case)
                with self.assertRaisesRegex(provenance.BenchmarkError, "outcome mismatch"):
                    self.execute(output, self.child_rows(case, outcome))
                self.assertEqual(provenance.read_json(output / "receipt.json")["status"], "failed")

    def test_invalid_settings_do_not_claim_a_run(self):
        with tempfile.TemporaryDirectory() as directory:
            output, manifest = self.prepare(Path(directory))
            manifest["settings"]["samples"] = 0
            provenance.atomic_json(output / "manifest.json", manifest)
            with self.assertRaisesRegex(provenance.BenchmarkError, "registered bound"):
                self.execute(output, [])
            self.assertFalse((output / "receipt.json").exists())
            self.assertFalse((output / "execution.claim").exists())

    def test_changed_catalog_prevents_reinterpretation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, manifest = self.prepare(root)
            self.execute(output, self.child_rows("verify"))
            manifest["metric_catalog_sha256"] = "0" * 64
            provenance.atomic_json(output / "manifest.json", manifest)
            with self.assertRaisesRegex(provenance.BenchmarkError, "metric catalog changed"):
                run.summarize_run(argparse.Namespace(directory=output, output=root / "report", process_id=None))


if __name__ == "__main__":
    unittest.main()
