"""Synthetic wallet runner tests. No signer, wallet, node or profiler is executed."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import payment_run
import provenance
import results
import run


def case(**changes):
    return {"algorithm": "slh-dsa-b128s", "version": "v5", "policy": "single",
            "inputs": 1, "inventory": "cached", **changes}


def settings(**changes):
    return {"cases": [case()], "samples": 1, "warmup": 0, "repetitions": 1,
            "timeout_seconds_per_process": 10, "max_output_bytes_per_process": 4096,
            "max_artifact_bytes_per_process": 4096, "checker_timeout_seconds": 10,
            "checker_max_output_bytes": 4096, **changes}


def rows(selected=None, *, samples=1, warmup=0):
    selected = selected or case()
    common = {"case_id": payment_run.case_id(selected), "cache_mode": selected["inventory"],
              "outcome": "success", "unavailable": {}, "censored": []}
    metric_names = payment_run.COMMON_METRICS | (payment_run.SLH_METRICS
        if selected["algorithm"] == payment_run.ALGORITHMS[0] else payment_run.CLASSICAL_METRICS)
    if selected["inventory"] == "generated":
        metric_names = metric_names | {"payment_inventory_ns"}
    metrics = {name: 10 for name in metric_names}
    metrics.update(payment_total_ns=100, attempt_elapsed_ns=102, process_cpu_core_equivalents=0.5,
                   transaction_bytes=8086, input_count=selected["inputs"],
                   signature_count=selected["inputs"] * (1 if selected["policy"] == "single" else 2))
    scope = ("prepared outside foreground; not measured for cached mode" if selected["inventory"] == "cached"
             else "wallet creation, key derivation, policy enrollment and verified backup publication inside foreground"
             if selected["algorithm"] == payment_run.ALGORITHMS[0] else "disposable classical key creation inside foreground")
    attempts = [{**common, "phase": "wallet", "warmup": index < warmup, "metrics": metrics.copy(),
                 "details": {"artifact_path": f"attempt-{index:06}.json", "inventory_timing": scope,
                             "artifact_sha256": hashlib.sha256(b'{"synthetic":true}\n').hexdigest(),
                             "public_fixture": True, "offline_fixture": True, "trusted_utxos": False,
                             "node_acceptance": False, "measurement_scope": "offline-wallet-with-durable-journal"
                             if selected["algorithm"] == "slh-dsa-b128s" else "classical-transaction-control-no-wallet-journal"}}
                for index in range(samples + warmup)]
    return attempts + [{**common, "phase": "process", "warmup": False,
                        "metrics": {"process_peak_rss_bytes": 1000}}]


class PaymentRegistrationTests(unittest.TestCase):
    def test_all_shapes_register_separate_identifiers(self):
        import itertools
        matrix = [dict(zip(payment_run.CASE_FIELDS, values))
                  for values in itertools.product(*payment_run.DIMENSION_CHOICES)]
        self.assertEqual(len({payment_run.case_id(item) for item in matrix}), 48)
        self.assertEqual(payment_run.validate_payment_settings(settings(cases=matrix)), 96)

    def test_bounds_and_dimensions_fail_closed(self):
        for field, value in (("samples", True), ("samples", 101), ("warmup", 11),
                             ("checker_timeout_seconds", 0), ("repetitions", 0),
                             ("max_artifact_bytes_per_process", 513 * 1024 * 1024),
                             ("cases", [case(), case()]), ("cases", [case(inputs=True)]),
                             ("cases", [case(version="v4")])):
            with self.subTest(field=field), self.assertRaises(provenance.BenchmarkError):
                payment_run.validate_payment_settings(settings(**{field: value}))
        with self.assertRaisesRegex(provenance.BenchmarkError, "4096"):
            payment_run.validate_payment_settings(settings(samples=100, repetitions=100))
        with self.assertRaisesRegex(provenance.BenchmarkError, "2 GiB"):
            payment_run.validate_payment_settings(settings(repetitions=10,
                                                  max_artifact_bytes_per_process=512 * 1024 * 1024))

    def test_scope_distinguishes_inventory_and_classical_controls(self):
        for selected in (case(), case(inventory="generated"), case(algorithm="ecdsa-secp256k1")):
            manifest = {"settings": settings(), "run_id": "run", "configuration_id": "configuration"}
            row = payment_run.normalize_payment_record(rows(selected)[0], manifest, selected, 0, 0, 123)
            self.assertEqual("payment_inventory_ns" in row["metrics"], selected["inventory"] == "generated")
            self.assertEqual("payment_prepare_persist_ns" in row["metrics"], selected["algorithm"] == "slh-dsa-b128s")
        for mutate in (lambda row: row["details"].update(artifact_path="../escape.json"),
                       lambda row: row["metrics"].update(input_count=2),
                       lambda row: row["metrics"].update(payment_sign_persist_ns=101),
                       lambda row: row["metrics"].update(payment_inventory_ns=0),
                       lambda row: row["details"].update(inventory_timing="cached means zero")):
            row = rows()[0]
            mutate(row)
            with self.assertRaises(provenance.BenchmarkError):
                payment_run.normalize_payment_record(row, manifest, case(), 0, 0, 123)

    def test_artifact_bounds_reject_escape_types_and_excess(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "attempt-000000.json"
            artifact.write_text("public")
            self.assertEqual(payment_run.bound_artifacts(root, max_bytes=6, max_files=1), {artifact.name})
            with self.assertRaisesRegex(provenance.BenchmarkError, "byte limit"):
                payment_run.bound_artifacts(root, max_bytes=5, max_files=1)
            with self.assertRaisesRegex(provenance.BenchmarkError, "file limit"):
                payment_run.bound_artifacts(root, max_bytes=6, max_files=0)
            artifact.unlink()
            artifact.symlink_to(root)
            with self.assertRaisesRegex(provenance.BenchmarkError, "regular files"):
                payment_run.bound_artifacts(root, max_bytes=6, max_files=1)


class PaymentExecutionTests(unittest.TestCase):
    def prepare(self, root, selected=None):
        selected = selected or case()
        build = root / "build"
        build.mkdir()
        provenance.atomic_json(build / "build.json", {"synthetic": True})
        output = root / "run"
        output.mkdir()
        configuration = settings(cases=[selected])
        manifest = {"schema_version": 1, "kind": "payment", "run_id": "synthetic",
                    "configuration_id": provenance.digest_value(configuration), "settings": configuration,
                    "build_directory": str(build), "build_receipt_sha256": provenance.sha256(build / "build.json"),
                    "build": {"synthetic": True}, "host": {"synthetic": True},
                    "host_profile": {"description": "mock", "cpu_model": "mock", "affinity": "mock",
                                     "power_policy": "mock", "effective_cpu_cores": 1, "memory_limit_bytes": 1024},
                    "expected_records": 2, "metric_catalog_sha256": provenance.sha256(HERE / "schema/metrics.json"),
                    "metric_catalog_extensions": {"payment": results.PAYMENT_CATALOG_SHA256},
                    "runner_sha256": provenance.sha256(HERE / "run.py"),
                    "instrumentation": {"run.py": provenance.sha256(HERE / "run.py")},
                    "reference_inputs": str(output / "reference-inputs"),
                    "independent_checker": {"reference": {"synthetic": True}, "checker_sha256": {"synthetic": True}},
                    "scope": payment_run.SCOPE}
        provenance.atomic_json(output / "manifest.json", manifest)
        return output, manifest

    def execute(self, output, manifest, *, child_rows=None, checker_changes=None, preflight_error=False,
                child_error=False, artifact_extra=False, artifact_replaced=False):
        selected = manifest["settings"]["cases"][0]
        child_rows = rows(selected) if child_rows is None else child_rows
        order = []

        def supervise(command, **kwargs):
            directory = provenance.fresh_directory(kwargs["directory"])
            (directory / "stderr.log").write_text("")
            emitted = []
            if "--preflight" in command or "--artifact" in command:
                order.append("preflight" if "--preflight" in command else "check")
                checked = {"schema_version": 1, "complete": True,
                           "reference": {"synthetic": True}, "checker_sha256": {"synthetic": True}}
                if "--artifact" in command:
                    path = Path(command[command.index("--artifact") + 1])
                    checked.update(algorithm=selected["algorithm"], version=int(selected["version"][1:]),
                                   policy=selected["policy"], inventory=selected["inventory"],
                                   input_count=selected["inputs"], transaction_bytes=8086,
                                   artifact_sha256=provenance.sha256(path))
                    checked.update(checker_changes or {})
                emitted = [checked]
            else:
                order.append("child")
                artifact_dir = Path(command[command.index("--artifact-directory") + 1])
                for index, row in enumerate(child_rows):
                    if row["phase"] == "wallet":
                        (artifact_dir / f"attempt-{index:06}.json").write_text('{"synthetic":true}\n')
                if artifact_extra:
                    (artifact_dir / "extra.json").write_text("{}")
                emitted = child_rows
            with (directory / "stdout.log").open("wb") as stream:
                for row in emitted:
                    line = provenance.canonical(row)
                    stream.write(line + b"\n")
                    stream.flush()
                    if kwargs.get("on_poll"):
                        kwargs["on_poll"]()
                    kwargs["on_line"](123, line)
            if artifact_replaced and order[-1] == "child":
                (artifact_dir / "attempt-000000.json").write_text('{"synthetic":null}\n')
            if (preflight_error and "--preflight" in command) or (child_error and order[-1] == "child"):
                raise run.ExecutionError("mock timeout", "timeout")
            return {"pid": 123, "exit_code": 0, "elapsed_ns": 100, "output_bytes": 100}

        with patch.object(run, "validate_build", return_value={"synthetic": True}), \
                patch.object(payment_run, "host_state", return_value={"synthetic": True}), \
                patch.object(payment_run, "checker_identity", return_value=manifest["independent_checker"]), \
                patch.object(payment_run, "INSTRUMENTS", ("run.py",)), \
                patch.object(run, "supervise", side_effect=supervise):
            receipt = run.execute(argparse.Namespace(execute=True, directory=output))
        return receipt, order

    def test_complete_cached_run_has_separate_checked_receipts_and_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, manifest = self.prepare(root)
            receipt, order = self.execute(output, manifest)
            self.assertEqual(order, ["preflight", "child", "check"])
            self.assertTrue(receipt["complete"] and receipt["successful"])
            self.assertEqual(len(receipt["independent_checks"]), 2)
            self.assertNotIn("receipt", receipt["independent_checks"][1])
            provenance.verify_artifacts(output, receipt["artifacts"])
            run.summarize_run(argparse.Namespace(directory=output, output=root / "report", process_id=None))
            summary = provenance.read_json(root / "report/summary.json")
            self.assertEqual(summary["metric_catalog_extensions"], {"payment": results.PAYMENT_CATALOG_SHA256})
            self.assertTrue(summary["successful"])
            document = (root / "report/report.html").read_text()
            self.assertIn("Wallet/payment stage overview", document)
            self.assertIn("Never add stage p50", document)
            self.assertIn("no equivalent durable wallet workflow", document)
            with self.assertRaisesRegex(provenance.BenchmarkError, "already attempted"):
                self.execute(output, manifest)

    def test_independent_failure_keeps_every_measured_attempt(self):
        for changed in ({"artifact_sha256": "0" * 64}, {"input_count": 2}, {"policy": "multisig"},
                        {"transaction_bytes": 8087}, {"complete": False}, {"reference": {"changed": True}}):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                output, manifest = self.prepare(Path(directory))
                with self.assertRaises(provenance.BenchmarkError):
                    self.execute(output, manifest, checker_changes=changed)
                receipt = provenance.read_json(output / "receipt.json")
                attempts = run.read_records(output / "attempts.jsonl")
                self.assertFalse(receipt["complete"])
                self.assertEqual([row["outcome"] for row in attempts], ["success", "success", "error"])
                self.assertEqual(attempts[-1]["phase"], "independent-check")
                provenance.verify_artifacts(output, receipt["artifacts"])

    def test_partial_wallet_error_preserves_observed_stage_and_missing_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            output, manifest = self.prepare(Path(directory))
            failed = rows()[0]
            failed["outcome"] = "error"
            failed["metrics"] = {name: value for name, value in failed["metrics"].items()
                                 if name in {"payment_total_ns", "attempt_elapsed_ns", "process_cpu_ns",
                                             "process_cpu_core_equivalents", "rss_before_bytes", "rss_after_bytes",
                                             "payment_wallet_setup_ns", "payment_prepare_persist_ns"}}
            failed["details"].pop("artifact_path")
            failed["details"].pop("artifact_sha256")
            failed["details"]["error"] = "mock signing journal failure"
            peak = rows()[-1]
            peak["outcome"] = "error"
            with self.assertRaises(run.ExecutionError):
                self.execute(output, manifest, child_rows=[failed, peak], child_error=True)
            saved = run.read_records(output / "attempts.jsonl")
            self.assertEqual(len(saved), 3)
            self.assertEqual(saved[0]["metrics"], failed["metrics"])
            self.assertEqual(saved[0]["details"]["error"], "mock signing journal failure")
            self.assertEqual(saved[1]["phase"], "process")
            self.assertNotIn("artifact_path", saved[0]["details"])

    def test_valid_same_size_substitution_cannot_replace_measured_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            output, manifest = self.prepare(Path(directory))
            with self.assertRaisesRegex(provenance.BenchmarkError, "measured payment artifact changed"):
                self.execute(output, manifest, artifact_replaced=True)
            saved = run.read_records(output / "attempts.jsonl")
            self.assertEqual([row["outcome"] for row in saved], ["success", "success", "error"])

    def test_preflight_failure_records_terminal_error_before_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            output, manifest = self.prepare(Path(directory))
            with self.assertRaises(run.ExecutionError):
                self.execute(output, manifest, preflight_error=True)
            receipt = provenance.read_json(output / "receipt.json")
            self.assertEqual(receipt["processes"], [])
            self.assertEqual(run.read_records(output / "attempts.jsonl")[0]["outcome"], "timeout")

    def test_child_short_output_and_timeout_preserve_failure(self):
        for options in ({"child_rows": rows()[:1]}, {"child_error": True}, {"artifact_extra": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                output, manifest = self.prepare(Path(directory))
                with self.assertRaises(provenance.BenchmarkError):
                    self.execute(output, manifest, **options)
                receipt = provenance.read_json(output / "receipt.json")
                self.assertEqual(receipt["status"], "failed")
                self.assertFalse(receipt["processes"][0]["complete"])
                self.assertNotEqual(run.read_records(output / "attempts.jsonl")[-1]["outcome"], "success")
                provenance.verify_artifacts(output, receipt["artifacts"])

    def test_payment_extension_cannot_change_after_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, manifest = self.prepare(root)
            self.execute(output, manifest)
            manifest["metric_catalog_extensions"]["payment"] = "0" * 64
            provenance.atomic_json(output / "manifest.json", manifest)
            with self.assertRaisesRegex(provenance.BenchmarkError, "payment metric catalog changed"):
                run.summarize_run(argparse.Namespace(directory=output, output=root / "report", process_id=None))


class PaymentReportTests(unittest.TestCase):
    def test_enclosing_quantiles_are_observed_not_sum_of_stage_quantiles(self):
        manifest = {"run_id": "synthetic", "configuration_id": "configuration", "settings": settings(samples=3)}
        records = []
        for index, row in enumerate(rows(samples=3)[:3]):
            row["metrics"].update(payment_prepare_persist_ns=[10, 40, 40][index],
                                  payment_sign_persist_ns=[40, 10, 40][index], payment_total_ns=[70, 90, 100][index])
            records.append(payment_run.normalize_payment_record(row, manifest, case(), 0, index, 1))
        summary = results.summarize(records, complete=True)
        metrics = next(group for group in summary["groups"] if group["outcome"] == "success")["metrics"]
        self.assertEqual(metrics["payment_total_ns"]["p50"], 90)
        self.assertEqual(metrics["payment_prepare_persist_ns"]["p50"] + metrics["payment_sign_persist_ns"]["p50"], 80)
        self.assertTrue(summary["successful"])

    def test_payment_comparison_requires_its_extension_but_old_primitives_do_not(self):
        from test_results import record
        primitive = results.summarize([record()], complete=True)
        self.assertNotIn("metric_catalog_extensions", primitive)
        payment = results.summarize([record(metrics={"payment_total_ns": 100})], complete=True)
        payment["compatibility"] = {"fixture": "synthetic"}
        changed = copy.deepcopy(payment)
        changed["metric_catalog_extensions"]["payment"] = "0" * 64
        with self.assertRaisesRegex(results.ValidationError, "payment metric catalog"):
            results.compare_summaries(payment, changed)


if __name__ == "__main__":
    unittest.main()
