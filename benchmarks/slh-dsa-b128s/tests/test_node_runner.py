"""Bounded registration/replay/supervision fixtures; no node or resource run."""

import argparse
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import node_run
import node_sampling
import provenance
import results
import run


class NodeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.binary = self.root / "zakurad"
        self.binary.write_bytes(b"unexecuted unit-test binary bytes")
        self.config = self.root / "node.toml"
        self.config.write_text('[network]\nnetwork = "Regtest"\n[metrics]\nendpoint_addr = "127.0.0.1:18232"\n')
        inventory = [{"path": "Cargo.toml", "sha256": "a" * 64}]
        self.build = {"schema_version": 1, "contract": "slh-dsa-b-128s-exp-v1", "kind": "node-default",
                      "complete": True, "features": ["default-release-binaries"],
                      "command": ["cargo", "build", "--locked", "--release", "--no-default-features", "-p", "zakura",
                                  "--bin", "zakurad", "--target-dir", str(self.root / "target"),
                                  "--features", "default-release-binaries"],
                      "binary_sha256": provenance.sha256(self.binary),
                      "identity": {"schema_version": 1, "contract": "slh-dsa-b-128s-exp-v1", "suite_id": "f7",
                                   "backend": "disabled", "algorithm_revision": "b392fe82d2d9770142477a576a758a233888bc0a",
                                   "blake3_version": "1.8.5", "verifier_compiled": False, "runtime_supported": False},
                      "source": {"source_commit": "a" * 40, "source_inventory": inventory,
                                 "source_inventory_sha256": provenance.digest_value(inventory),
                                 "lock_sha256": "b" * 64, "fixture_lock_sha256": "c" * 64},
                      "rustc": "unit rustc", "cargo": "unit cargo", "environment": {name: None for name in (
                          "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "CC", "CXX", "CFLAGS", "CXXFLAGS", "CARGO_BUILD_TARGET")}}
        provenance.atomic_json(self.root / "build.json", self.build)
        self.profile = {"schema_version": 1, "network": "Regtest", "pid": 999999,
                        "binary_path": str(self.binary), "build_receipt_path": str(self.root / "build.json"),
                        "config_path": str(self.config), "metrics_url": "http://127.0.0.1:18232/metrics",
                        "process_identity": {"start_ticks": 42, "boot_id": "fixture-boot"},
                        "cgroup_path": None, "cgroup_boundary": None,
                        "workload": {"id": "idle", "description": "unit fixture", "fixture_sha256": None,
                                     "topology": "one declared process", "state": "unknown", "activity": "idle declaration"}}
        self.host = {"description": "unit host", "cpu_model": "fixture", "affinity": "unknown",
                     "power_policy": "unknown", "effective_cpu_cores": 1, "memory_limit_bytes": 1024**3}
        provenance.atomic_json(self.root / "profile.json", self.profile)
        provenance.atomic_json(self.root / "host.json", self.host)

    def plan(self, name="run", **kwargs):
        args = argparse.Namespace(node_profile=str(self.root / "profile.json"), host_profile=str(self.root / "host.json"),
                                  output=str(self.root / name), samples=1, interval_ms=10, timeout=2,
                                  max_output_bytes=1024 * 1024)
        vars(args).update(kwargs)
        return node_run.plan_node(args)

    def snapshot(self, index):
        at = index * 1_000_000_000 + 10
        process = {"kind": "process", "identity": {"pid": self.profile["pid"],
                   **self.profile["process_identity"], "proc_root": str(node_sampling.PROC_ROOT.resolve())},
                   "metrics": {"process_cpu_ns": index * 200, "process_user_cpu_ns": index * 150,
                               "process_system_cpu_ns": index * 50, "rss_current_bytes": 1000,
                               "process_peak_rss_bytes": 2000}, "unavailable": {}, "details": {},
                   "window_start_ns": at, "window_end_ns": at + 10}
        guard = copy.deepcopy(process)
        guard.update(window_start_ns=at + 40, window_end_ns=at + 50)
        binding = {"binary_sha256": provenance.sha256(self.binary), "config_sha256": provenance.sha256(self.config),
                   "binary_file_identity": {"dev": 1, "ino": 1, "size": 1, "mtime_ns": 1, "ctime_ns": 1},
                   "cgroup_membership": None, "endpoint_association": node_sampling.ASSOCIATION}
        return {"process": process, "process_guard": guard, "cgroup": None, "binding": binding,
                "mempool": {"window_start_ns": at + 20, "window_end_ns": at + 30,
                            "text": f"zcash_mempool_size_transactions {index}\nzcash_mempool_size_bytes {index * 100}\nzcash_mempool_cost_bytes {index * 200}\n",
                            "error": None}, "error": None}

    def frames(self, manifest):
        first, second = self.snapshot(0), self.snapshot(1)
        frames = [{"frame": "snapshot", "index": index, "evidence": evidence} for index, evidence in enumerate((first, second))]
        frames += [{"frame": "record", "index": index, "record": record}
                   for index, record in enumerate(node_sampling.records_from_snapshots(first, second, manifest, 0))]
        return frames

    def execute_fixture(self, manifest, frames=None, *, suffix="", name="run", maximum_timeout=None):
        frames = self.frames(manifest) if frames is None else frames
        encoded = b"".join(provenance.canonical(frame) + b"\n" for frame in frames)
        program = f"import sys,time; sys.stdout.buffer.write({encoded!r}); sys.stdout.buffer.flush(); {suffix or 'pass'}"
        supervise = run.supervise

        def fixture(argv, **kwargs):
            self.assertEqual(argv[:2], [sys.executable, str(HERE / "node_sampling.py")])
            if maximum_timeout is not None:
                kwargs["timeout"] = maximum_timeout
            return supervise([sys.executable, "-c", program], **kwargs)

        with patch.object(run, "supervise", side_effect=fixture):
            return node_run.execute_node(argparse.Namespace(directory=str(self.root / name), execute=True), manifest)

    def receipt(self, name="run"):
        receipt = provenance.read_json(self.root / name / "receipt.json")
        provenance.verify_artifacts(self.root / name, receipt["artifacts"])
        return receipt

    def test_plan_only_reads_static_registration(self):
        with patch.object(node_sampling, "collect", side_effect=AssertionError("must not sample")), \
                patch.object(node_sampling.collectors, "read_process", side_effect=AssertionError("must not read proc")), \
                patch.object(node_sampling.http.client, "HTTPConnection", side_effect=AssertionError("must not connect")), \
                patch.object(run.subprocess, "Popen", side_effect=AssertionError("must not execute")):
            manifest = self.plan()
        self.assertEqual(manifest["expected_records"], 2)
        self.assertEqual(manifest["node_identity"]["binary_sha256"], provenance.sha256(self.binary))
        self.assertFalse((self.root / "run/execution.claim").exists())

    def test_plan_exposes_request_budget_without_promising_completion(self):
        manifest = self.plan(samples=10, interval_ms=1000, timeout=30)
        budget = manifest["scope"]["time_budget"]
        self.assertEqual(budget["delay_total_ms"], 10000)
        self.assertEqual(budget["maximum_request_total_ms"], 22000)
        self.assertEqual(budget["remaining_after_delays_and_requests_ms"], -2000)
        self.assertIn("cannot cover", budget["warning"])
        self.assertFalse(budget["completion_guaranteed"])
        manifest = self.plan("more-headroom", samples=10, interval_ms=1000, timeout=40)
        budget = manifest["scope"]["time_budget"]
        self.assertEqual(budget["remaining_after_delays_and_requests_ms"], 8000)
        self.assertIsNone(budget["warning"])
        self.assertFalse(budget["completion_guaranteed"])

    def test_strict_registration_and_bounds(self):
        for change in ({"network": "Mainnet"}, {"pid": True}, {"extra": 1},
                       {"cgroup_path": "/outside", "cgroup_boundary": "/sys/fs/cgroup"},
                       {"process_identity": {"start_ticks": -1, "boot_id": "boot"}}):
            with self.subTest(change=change), self.assertRaises(provenance.BenchmarkError):
                node_run.validate_node_profile({**self.profile, **change})
        for kwargs in ({"samples": 0}, {"interval_ms": 0}, {"timeout": 1, "interval_ms": 1000},
                       {"max_output_bytes": 2**30}):
            with self.subTest(kwargs=kwargs), self.assertRaises(provenance.BenchmarkError):
                self.plan(**kwargs)

    def test_config_and_binary_must_match_registration(self):
        self.profile["metrics_url"] = "http://127.0.0.1:9999/metrics"
        provenance.atomic_json(self.root / "profile.json", self.profile)
        with self.assertRaisesRegex(provenance.BenchmarkError, "differs from node config"):
            self.plan()
        self.binary.write_bytes(b"changed")
        with self.assertRaisesRegex(provenance.BenchmarkError, "binary changed"):
            node_run.node_build(self.profile)

    def test_build_receipt_requires_exact_recipe_and_valid_source_hash(self):
        for field, value in (("complete", False), ("command", ["arbitrary"]), ("features", [])):
            with self.subTest(field=field):
                provenance.atomic_json(self.root / "build.json", {**self.build, field: value})
                with self.assertRaises(provenance.BenchmarkError):
                    node_run.node_build(self.profile)
        changed = copy.deepcopy(self.build)
        changed["source"]["source_inventory"][0]["sha256"] = "f" * 64
        provenance.atomic_json(self.root / "build.json", changed)
        with self.assertRaisesRegex(provenance.BenchmarkError, "inventory identity"):
            node_run.node_build(self.profile)

    def test_execute_opt_in_and_one_attempt_only(self):
        manifest = self.plan()
        with self.assertRaisesRegex(provenance.BenchmarkError, "--execute"):
            node_run.execute_node(argparse.Namespace(directory=str(self.root / "run"), execute=False), manifest)
        self.assertFalse((self.root / "run/execution.claim").exists())
        self.execute_fixture(manifest)
        with self.assertRaisesRegex(provenance.BenchmarkError, "already attempted"):
            self.execute_fixture(manifest)

    def test_success_replays_raw_records_and_reports_unavailable_peaks(self):
        manifest = self.plan()
        result = self.execute_fixture(manifest)
        self.assertTrue(result["complete"])
        self.assertFalse(result["successful"])
        receipt = self.receipt()
        self.assertEqual((receipt["records"], receipt["snapshots"]), (2, 2))
        records = run.read_records(self.root / "run/attempts.jsonl")
        self.assertEqual(records[0]["metrics"]["process_cpu_ns"], 200)
        self.assertIsNone(records[0]["metrics"]["process_peak_rss_bytes"])
        run.summarize_run(argparse.Namespace(directory=str(self.root / "run"), output=str(self.root / "report"), process_id=None))
        summary = provenance.read_json(self.root / "report/summary.json")
        self.assertEqual(summary["provenance"]["node_scope"]["samples"], 1)
        self.assertEqual(summary["provenance"]["source"], "a" * 40)
        self.assertIn("node_collection", summary["compatibility"])
        with self.assertRaisesRegex(results.ValidationError, "build-time toolchain provenance"):
            results.compare_summaries(summary, summary)
        (self.root / "run/evidence.jsonl").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(provenance.BenchmarkError, "artifact bytes"):
            self.receipt()

    def test_record_tampering_and_extra_records_preserve_failure(self):
        for mode in ("tamper", "extra", "missing"):
            with self.subTest(mode=mode):
                manifest = self.plan(mode)
                frames = self.frames(manifest)
                if mode == "tamper":
                    frames[2]["record"]["metrics"]["process_cpu_ns"] += 1
                elif mode == "extra":
                    frames.append({**frames[-1], "index": 2})
                else:
                    frames.pop()
                with self.assertRaises(provenance.BenchmarkError):
                    self.execute_fixture(manifest, frames, name=mode)
                receipt = self.receipt(mode)
                self.assertEqual(receipt["status"], "failed")
                self.assertFalse(receipt["complete"])
                self.assertEqual(run.read_records(self.root / mode / "attempts.jsonl")[-1]["outcome"], "error")

    def test_timeout_keeps_snapshot_and_never_signals_attached_pid(self):
        manifest = self.plan()
        with patch.object(run.os, "killpg", wraps=os.killpg) as kill, self.assertRaises(run.ExecutionError):
            self.execute_fixture(manifest, self.frames(manifest)[:1], suffix="time.sleep(10)", maximum_timeout=0.1)
        self.assertTrue(kill.called)
        self.assertTrue(all(call.args[0] != self.profile["pid"] for call in kill.call_args_list))
        receipt = self.receipt()
        self.assertEqual((receipt["snapshots"], receipt["outcome"]), (1, "timeout"))
        failure = run.read_records(self.root / "run/attempts.jsonl")[-1]
        self.assertEqual(failure["censored"], ["attempt_elapsed_ns"])
        with self.assertRaises(ProcessLookupError):
            os.kill(receipt["processes"][0]["pid"], 0)

    def test_truncated_and_output_limited_streams_preserve_partial_evidence(self):
        for mode, suffix, limit in (("truncated", "sys.stdout.write('partial')", 100000),
                                    ("output", "print('x' * 20000)", 8000)):
            with self.subTest(mode=mode):
                manifest = self.plan(mode, max_output_bytes=limit)
                with self.assertRaises(provenance.BenchmarkError):
                    self.execute_fixture(manifest, self.frames(manifest)[:1], suffix=suffix, name=mode)
                self.assertEqual(self.receipt(mode)["status"], "failed")

    def test_changed_config_after_plan_is_a_retained_failure_without_starting_child(self):
        manifest = self.plan()
        self.config.write_text(self.config.read_text() + "# changed\n")
        with patch.object(run, "supervise", side_effect=AssertionError("must not start")), \
                self.assertRaisesRegex(provenance.BenchmarkError, "registered node"):
            node_run.execute_node(argparse.Namespace(directory=str(self.root / "run"), execute=True), manifest)
        self.assertEqual(self.receipt()["records"], 1)

    def test_prelaunch_failure_with_no_process_remains_reportable(self):
        manifest = self.plan()
        # Opening evidence fails after the empty attempts stream was created,
        # before a sampler command or process exists.
        (self.root / "run/evidence.jsonl").touch()
        with patch.object(run, "supervise", side_effect=AssertionError("must not start")), \
                self.assertRaises(FileExistsError):
            node_run.execute_node(argparse.Namespace(directory=str(self.root / "run"), execute=True), manifest)
        receipt = self.receipt()
        self.assertEqual(receipt["processes"], [])
        self.assertEqual(receipt["records"], 0)
        self.assertEqual(receipt["failure"], "FileExistsError")
        result = run.summarize_run(argparse.Namespace(directory=str(self.root / "run"),
                                  output=str(self.root / "report"), process_id=None))
        self.assertFalse(result["complete"])
        self.assertFalse(result["successful"])
        summary = provenance.read_json(self.root / "report/summary.json")
        self.assertEqual(summary["groups"], [])
        self.assertEqual(summary["provenance"]["node_execution"], {})
        self.assertEqual(summary["provenance"]["execution_failure"], "FileExistsError")
        page = (self.root / "report/report.html").read_text()
        self.assertIn("Node collection failed (error): FileExistsError", page)
        self.assertIn("No sampler process was started", page)

    def test_prelaunch_failure_without_attempts_file_remains_reportable(self):
        manifest = self.plan()
        original_open = Path.open

        def deny_attempts(path, *args, **kwargs):
            if path == self.root / "run/attempts.jsonl" and args == ("xb",):
                raise PermissionError("cannot create attempts")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", deny_attempts), \
                patch.object(run, "supervise", side_effect=AssertionError("must not start")), \
                self.assertRaises(PermissionError):
            node_run.execute_node(argparse.Namespace(directory=str(self.root / "run"), execute=True), manifest)
        receipt = self.receipt()
        self.assertEqual(receipt["processes"], [])
        self.assertNotIn("attempts.jsonl", receipt["artifacts"])
        run.summarize_run(argparse.Namespace(directory=str(self.root / "run"),
                          output=str(self.root / "report"), process_id=None))
        summary = provenance.read_json(self.root / "report/summary.json")
        self.assertEqual(summary["groups"], [])
        self.assertEqual(summary["provenance"]["execution_failure"], "PermissionError")

    def test_comparison_ignores_pid_but_checks_workload_and_config(self):
        manifest = self.plan()
        other = copy.deepcopy(manifest)
        other["node_profile"].update(pid=12345, process_identity={"start_ticks": 900, "boot_id": "other-boot"})
        self.assertEqual(node_run.node_compatibility(manifest), node_run.node_compatibility(other))
        other["node_profile"]["workload"]["activity"] = "different activity"
        self.assertNotEqual(node_run.node_compatibility(manifest), node_run.node_compatibility(other))
        other = copy.deepcopy(manifest)
        other["node_identity"]["config_sha256"] = "a" * 64
        self.assertNotEqual(node_run.node_compatibility(manifest), node_run.node_compatibility(other))

    def test_registered_cgroup_adds_one_bound_population(self):
        self.profile.update(cgroup_path="/sys/fs/cgroup/job", cgroup_boundary="/sys/fs/cgroup")
        provenance.atomic_json(self.root / "profile.json", self.profile)
        manifest = self.plan()
        snapshots = [self.snapshot(index) for index in range(2)]
        for index, sample in enumerate(snapshots):
            at = sample["process"]["window_end_ns"]
            sample["binding"]["cgroup_membership"] = {"process_path": "/job", "resolved_process_path": "/sys/fs/cgroup/job",
                                                       "scope": "declared cgroup and descendants"}
            sample["cgroup"] = {"kind": "cgroup", "identity": {"path": "/sys/fs/cgroup/job", "device": 1, "inode": 2},
                                "metrics": {"cgroup_cpu_ns": 200 * index, "cgroup_user_cpu_ns": 150 * index,
                                            "cgroup_system_cpu_ns": 50 * index, "cgroup_throttled_ns": 10 * index,
                                            "cgroup_memory_current_bytes": 1000, "cgroup_memory_peak_bytes": 2000,
                                            "effective_cpu_cores": 2}, "unavailable": {}, "details": {},
                                "window_start_ns": at + 1, "window_end_ns": at + 5}
        frames = [{"frame": "snapshot", "index": index, "evidence": sample} for index, sample in enumerate(snapshots)]
        frames += [{"frame": "record", "index": index, "record": record} for index, record in
                   enumerate(node_sampling.records_from_snapshots(*snapshots, manifest, 0))]
        self.assertEqual(manifest["expected_records"], 3)
        self.execute_fixture(manifest, frames)
        self.assertEqual(self.receipt()["records"], 3)
        records = run.read_records(self.root / "run/attempts.jsonl")
        self.assertEqual(records[-1]["phase"], "resource-cgroup")
        self.assertEqual(records[-1]["metrics"]["effective_cpu_cores"], 2)
        changed = copy.deepcopy(manifest)
        changed["node_profile"]["cgroup_path"] = "/sys/fs/cgroup/other"
        self.assertNotEqual(node_run.node_compatibility(manifest), node_run.node_compatibility(changed))

    def test_partial_snapshot_and_cancelled_run_remain_inspectable(self):
        manifest = self.plan()
        partial = {name: None for name in ("process", "process_guard", "mempool", "binding", "cgroup")}
        partial["error"] = "process identity changed"
        with self.assertRaises(provenance.BenchmarkError):
            self.execute_fixture(manifest, [{"frame": "snapshot", "index": 0, "evidence": partial}],
                                 suffix="raise SystemExit(2)")
        self.assertEqual(self.receipt()["snapshots"], 1)
        manifest = self.plan("cancelled")
        with patch.object(run, "supervise", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            node_run.execute_node(argparse.Namespace(directory=str(self.root / "cancelled"), execute=True), manifest)
        self.assertEqual(self.receipt("cancelled")["outcome"], "cancelled")

    def test_disk_bound_failure_always_finalizes_receipt(self):
        manifest = self.plan()
        with patch.object(node_run, "_bound_artifacts", side_effect=provenance.BenchmarkError("disk limit")), \
                self.assertRaisesRegex(provenance.BenchmarkError, "disk limit"):
            self.execute_fixture(manifest)
        receipt = provenance.read_json(self.root / "run/receipt.json")
        self.assertEqual(receipt["status"], "failed")
        self.assertFalse(receipt["artifact_inventory_complete"])
        self.assertTrue((self.root / "run/execution.claim").is_file())

    def test_record_byte_bound_reserves_a_terminal_failure(self):
        manifest = self.plan()
        with patch.object(node_run, "MAX_INPUT_BYTES", node_run.MAX_RECORD_BYTES + 1), \
                self.assertRaisesRegex(provenance.BenchmarkError, "normalized record byte limit"):
            self.execute_fixture(manifest)
        self.assertEqual(self.receipt()["records"], 1)
        self.assertEqual(run.read_records(self.root / "run/attempts.jsonl")[0]["attempt_id"], "supervisor")


if __name__ == "__main__":
    unittest.main()
