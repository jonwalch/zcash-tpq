"""Synthetic wallet runner tests. No signer, wallet, node or profiler is executed."""

import argparse
import copy
import hashlib
import itertools
import json
import os
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


def storage_profile(**changes):
    return {"description": "synthetic test storage", "medium": "test medium",
            "filesystem": "operator-declared filesystem", "mount_options": "test options",
            "sync_policy": "test sync policy", **changes}


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
    def test_plan_registers_storage_without_changing_workload_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            storage = root / "wallet-storage"
            storage.mkdir()
            build = root / "build"
            build.mkdir()
            provenance.atomic_json(build / "build.json", {"synthetic": True})
            profile = {"description": "mock", "cpu_model": "mock", "affinity": "mock",
                       "power_policy": "mock", "effective_cpu_cores": 1, "memory_limit_bytes": 1024,
                       "wallet_storage": storage_profile()}
            provenance.atomic_json(root / "host.json", profile)
            parser = argparse.ArgumentParser()
            payment_run.add_payment_parser(parser.add_subparsers())
            arguments = ["plan-payment", "--build", str(build), "--output", str(root / "plan"),
                         "--host-profile", str(root / "host.json"), "--reference-inputs", str(root / "reference"),
                         "--wallet-storage-root", str(storage), "--samples", "1", "--warmup", "0", "--timeout", "10"]
            for name, value in case().items():
                arguments += ["--" + name, str(value)]
            args = parser.parse_args(arguments)
            with patch.object(run, "validate_build", return_value={"synthetic": True}), \
                    patch.object(provenance, "snapshot_payment_reference", side_effect=lambda _source, dest: provenance.fresh_directory(dest)), \
                    patch.object(payment_run, "checker_identity", return_value={"synthetic": True}):
                manifest = payment_run.plan_payment(args)
            self.assertEqual(manifest["wallet_storage"], payment_run.wallet_storage_identity(storage, storage_profile()))
            self.assertNotIn("wallet_storage", manifest["settings"])
            self.assertEqual(manifest["configuration_id"], provenance.digest_value(manifest["settings"]))
            self.assertEqual(manifest["instrumentation"]["src/config.rs"], provenance.sha256(HERE / "src/config.rs"))
            provenance.atomic_json(root / "host.json", {key: value for key, value in profile.items() if key != "wallet_storage"})
            args.output = str(root / "invalid-plan")
            with self.assertRaisesRegex(provenance.BenchmarkError, "wallet storage profile"):
                payment_run.plan_payment(args)
            self.assertFalse(Path(args.output).exists())

    def test_wallet_storage_requires_existing_nonsymlink_root_and_bounded_declarations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            identity = payment_run.wallet_storage_identity(root, storage_profile())
            self.assertEqual(identity["root"], str(root))
            self.assertEqual(identity["st_dev"], root.stat().st_dev)
            self.assertEqual(identity["st_ino"], root.stat().st_ino)
            self.assertEqual(identity["f_bsize"], os.statvfs(root).f_bsize)
            payment_run.validate_wallet_storage(identity, {"wallet_storage": storage_profile()})
            symlink = root / "alias"
            symlink.symlink_to(root, target_is_directory=True)
            regular = root / "file"
            regular.touch()
            for path in (root / "missing", symlink, regular):
                with self.subTest(path=path), self.assertRaises(provenance.BenchmarkError):
                    payment_run.wallet_storage_identity(path, storage_profile())
            for profile in (None, {}, storage_profile(medium=" "), storage_profile(sync_policy="x" * 513),
                            storage_profile(extra="unexpected"), storage_profile(filesystem=True)):
                with self.subTest(profile=profile), self.assertRaises(provenance.BenchmarkError):
                    payment_run.wallet_storage_identity(root, profile)

    def test_all_shapes_register_separate_identifiers(self):
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
        storage = root / "wallet-storage"
        storage.mkdir()
        configuration = settings(cases=[selected])
        manifest = {"schema_version": 1, "kind": "payment", "run_id": "synthetic",
                    "configuration_id": provenance.digest_value(configuration), "settings": configuration,
                    "build_directory": str(build), "build_receipt_sha256": provenance.sha256(build / "build.json"),
                    "build": {"synthetic": True}, "host": {"synthetic": True},
                    "host_profile": {"description": "mock", "cpu_model": "mock", "affinity": "mock",
                                     "power_policy": "mock", "effective_cpu_cores": 1, "memory_limit_bytes": 1024,
                                     "wallet_storage": storage_profile()},
                    "wallet_storage": payment_run.wallet_storage_identity(storage, storage_profile()),
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
                child_error=False, artifact_extra=False, artifact_replaced=False, on_child=None):
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
                if on_child is not None:
                    on_child(command)
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
            self.assertEqual(summary["compatibility"]["wallet_storage"], manifest["wallet_storage"])
            self.assertEqual(summary["provenance"]["wallet_storage"], manifest["wallet_storage"])
            self.assertTrue(summary["successful"])
            document = (root / "report/report.html").read_text()
            self.assertIn("Wallet/payment stage overview", document)
            self.assertIn("Never add stage p50", document)
            self.assertIn("no equivalent durable wallet workflow", document)
            self.assertIn("Registered wallet storage", document)
            self.assertIn(manifest["wallet_storage"]["root"], document)
            self.assertNotIn("Wallet storage identity is unavailable", document)
            with self.assertRaisesRegex(provenance.BenchmarkError, "already attempted"):
                self.execute(output, manifest)

    def test_changed_tmpdir_cannot_select_child_wallet_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, manifest = self.prepare(root)
            other = root / "other-temp"
            other.mkdir()
            commands = []
            with patch.dict(os.environ, {"TMPDIR": str(other)}):
                receipt, _ = self.execute(output, manifest, on_child=commands.append)
            self.assertTrue(receipt["successful"])
            self.assertEqual(len(commands), 1)
            command = commands[0]
            self.assertEqual(command[command.index("--wallet-storage-root") + 1], manifest["wallet_storage"]["root"])
            self.assertNotEqual(command[command.index("--wallet-storage-root") + 1], str(other))

    def test_changed_storage_is_rejected_before_claim_or_child_launch(self):
        for change in ("replace-root", "device", "profile", "missing-identity"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output, manifest = self.prepare(root)
                if change == "replace-root":
                    storage = Path(manifest["wallet_storage"]["root"])
                    storage.rename(root / "original-storage")
                    storage.mkdir()
                elif change == "device":
                    manifest["wallet_storage"]["st_dev"] += 1
                elif change == "profile":
                    manifest["host_profile"]["wallet_storage"]["medium"] = "changed medium"
                else:
                    del manifest["wallet_storage"]
                provenance.atomic_json(output / "manifest.json", manifest)
                commands = []
                with self.assertRaisesRegex(provenance.BenchmarkError, "wallet storage"):
                    self.execute(output, manifest, on_child=commands.append)
                self.assertEqual(commands, [])
                self.assertFalse((output / "execution.claim").exists())
                self.assertFalse((output / "receipt.json").exists())

    def test_replaced_storage_after_child_marks_run_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, manifest = self.prepare(root)

            def replace_storage(_command):
                storage = Path(manifest["wallet_storage"]["root"])
                storage.rename(root / "original-storage")
                storage.mkdir()

            with self.assertRaisesRegex(provenance.BenchmarkError, "wallet storage"):
                self.execute(output, manifest, on_child=replace_storage)
            receipt = provenance.read_json(output / "receipt.json")
            self.assertFalse(receipt["complete"])
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(len(receipt["independent_checks"]), 1)
            self.assertFalse(receipt["processes"][0]["complete"])

    def test_storage_identity_and_declarations_participate_in_report_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, manifest = self.prepare(root)
            self.execute(output, manifest)
            run.summarize_run(argparse.Namespace(directory=output, output=root / "report", process_id=None))
            original = provenance.read_json(root / "report/summary.json")
            results.compare_summaries(original, copy.deepcopy(original))
            for field, value in (("root", "/another/storage/root"), ("st_dev", 999999), ("f_flag", 999999),
                                 ("profile", storage_profile(medium="changed medium"))):
                with self.subTest(field=field):
                    changed = copy.deepcopy(original)
                    changed["compatibility"]["wallet_storage"][field] = value
                    if field == "profile":
                        changed["compatibility"]["host_profile"]["wallet_storage"] = value
                    with self.assertRaisesRegex(results.ValidationError, "compatib"):
                        results.compare_summaries(original, changed)

    def test_old_payment_reports_remain_readable_but_cannot_compare_without_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, manifest = self.prepare(root)
            self.execute(output, manifest)
            del manifest["wallet_storage"]
            del manifest["host_profile"]["wallet_storage"]
            provenance.atomic_json(output / "manifest.json", manifest)
            receipt = provenance.read_json(output / "receipt.json")
            receipt["manifest_sha256"] = provenance.sha256(output / "manifest.json")
            receipt["artifacts"] = provenance.artifact_inventory(output)
            provenance.atomic_json(output / "receipt.json", receipt)
            run.summarize_run(argparse.Namespace(directory=output, output=root / "report", process_id=None))
            summary = provenance.read_json(root / "report/summary.json")
            self.assertIsNone(summary["compatibility"]["wallet_storage"])
            self.assertIn("did not register wallet storage", summary["provenance"]["wallet_storage_unavailable"])
            document = (root / "report/report.html").read_text()
            self.assertIn("Wallet storage identity is unavailable", document)
            self.assertNotIn("Registered wallet storage", document)
            for remove_field in (False, True):
                historical = copy.deepcopy(summary)
                if remove_field:
                    historical["compatibility"].pop("wallet_storage")
                with self.assertRaisesRegex(results.ValidationError, "wallet storage"):
                    results.compare_summaries(historical, historical)

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
    def test_fixture_boundary_notice_uses_saved_scope_and_marks_legacy_unknown(self):
        from html_report import render_report
        from test_results import record
        summary = results.summarize([record(metrics={"payment_total_ns": 100})], complete=True)
        summary["provenance"] = {"payment_scope": {"fixture_preparation": "saved <boundary>"}}
        document = render_report(summary, results.METRIC_CATALOG)
        self.assertIn("saved &lt;boundary&gt;", document)
        self.assertNotIn("Fixture preparation boundaries were not registered", document)
        summary["provenance"]["payment_scope"] = {}
        legacy = render_report(summary, results.METRIC_CATALOG)
        self.assertIn("Fixture preparation boundaries were not registered", legacy)
        self.assertNotIn(payment_run.SCOPE["fixture_preparation"], legacy)

    def test_payment_comparison_bounds_allow_large_registered_identity_only(self):
        from test_results import record
        profile = storage_profile(**{field: "x" * 512 for field in payment_run.STORAGE_PROFILE_FIELDS})
        payment = results.summarize([record(metrics={"payment_total_ns": 100})], complete=True)
        payment["compatibility"] = {
            "host_profile": {"wallet_storage": profile},
            "wallet_storage": {"root": "/synthetic", "st_dev": 0, "st_ino": 0,
                               "f_bsize": 4096, "f_frsize": 4096, "f_flag": 0, "profile": profile},
            "settings": settings(cases=[dict(zip(payment_run.CASE_FIELDS, values))
                                        for values in itertools.product(*payment_run.DIMENSION_CHOICES)]),
            "independent_checker": {f"synthetic-input-{index:03}": "0" * 64 for index in range(80)}}
        with self.assertRaisesRegex(results.ValidationError, "byte limit"):
            results._bounded_json(payment["compatibility"])
        results.compare_summaries(payment, copy.deepcopy(payment))
        oversized = copy.deepcopy(payment)
        oversized["compatibility"]["extra"] = ["x" * 4096] * 16
        with self.assertRaisesRegex(results.ValidationError, "byte limit"):
            results.compare_summaries(oversized, oversized)
        primitive = results.summarize([record()], complete=True)
        primitive["compatibility"] = {"extra": ["x" * 4096] * 5}
        with self.assertRaisesRegex(results.ValidationError, "byte limit"):
            results.compare_summaries(primitive, primitive)

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
        payment["compatibility"] = {
            "fixture": "synthetic", "host_profile": {"wallet_storage": storage_profile()},
            "wallet_storage": {"root": "/synthetic", "st_dev": 0, "st_ino": 0,
                               "f_bsize": 4096, "f_frsize": 4096, "f_flag": 0, "profile": storage_profile()}}
        changed = copy.deepcopy(payment)
        changed["metric_catalog_extensions"]["payment"] = "0" * 64
        with self.assertRaisesRegex(results.ValidationError, "payment metric catalog"):
            results.compare_summaries(payment, changed)


if __name__ == "__main__":
    unittest.main()
