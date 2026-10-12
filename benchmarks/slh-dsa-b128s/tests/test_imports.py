"""Synthetic saved-evidence imports; no live collection or workload execution."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import imports
import provenance
import results


CONTEXT = {"run_id": "saved-run", "case_id": "case", "configuration_id": "configuration",
           "process_id": "source", "attempt_id": "base", "phase": "measure",
           "cache_mode": "warm", "warmup": False}


def profile(**updates):
    value = {"schema_version": 1, "context": dict(CONTEXT), "expected_records": 1, "complete": True,
             "host_profile": {"name": "synthetic-host"},
             "provenance": {"source_revision": "a" * 40, "binary_sha256": "b" * 64,
                            "config_sha256": "c" * 64}, "options": {}}
    value.update(updates)
    return value


def raw_record(**updates):
    value = {**CONTEXT, "schema_version": 1, "outcome": "success",
             "metrics": {"transaction_bytes": 10}, "unavailable": {}, "censored": []}
    value.update(updates)
    return value


def jsonl(rows):
    return "".join(json.dumps(row) + "\n" for row in rows)


def block_rows():
    common = {"node": "node", "process_trace_id": "epoch", "source": "block_sync_driver",
              "apply_token": 1, "height": 110, "hash": "ab" * 32, "apply_class": "full"}
    return [{**common, "event": "block_submit_queued", "ts": 1000},
            {**common, "event": "commit_start", "ts": 2000},
            {**common, "event": "commit_finish", "ts": 12000, "elapsed_ms": 10, "result": "committed"}]


def scrape(count=2, size=400):
    return (f"zcash_mempool_size_transactions {count}\nzcash_mempool_size_bytes {size}\n"
            "zcash_mempool_cost_bytes 500\n")


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.number = 0

    def args(self, kind="transaction", source="0001ff\n", selected_profile=None):
        self.number += 1
        prefix = self.root / str(self.number)
        prefix.mkdir()
        input_path = prefix / "input"
        input_path.write_bytes(source if isinstance(source, bytes) else source.encode())
        profile_path = prefix / "profile"
        profile_path.write_text(json.dumps(profile() if selected_profile is None else selected_profile))
        return argparse.Namespace(kind=kind, input=input_path, profile=profile_path, output=prefix / "output")

    def evidence(self, args):
        output = Path(args.output)
        receipt = provenance.read_json(output / "receipt.json")
        manifest = provenance.read_json(output / "manifest.json")
        self.assertEqual(receipt["manifest_sha256"], provenance.sha256(output / "manifest.json"))
        provenance.verify_artifacts(output, receipt["artifacts"])
        records = list(results.read_records(output / "attempts.jsonl"))
        return receipt, manifest, records

    def test_transaction_exact_bytes_and_operator_evidence_labels(self):
        args = self.args()
        with patch("subprocess.Popen", side_effect=AssertionError("no process launch")):
            report = imports.import_saved(args)
        self.assertTrue(report["complete"])
        receipt, manifest, records = self.evidence(args)
        self.assertTrue(receipt["successful"])
        self.assertEqual(records[0]["metrics"], {"transaction_bytes": 3})
        self.assertEqual(manifest["kind"], "import.transaction")
        self.assertFalse(manifest["provenance"]["authenticated"])
        self.assertFalse(manifest["adapter_metadata"]["evidence"]["workload_receipt_authenticated"])
        self.assertEqual(set(manifest["adapter_compatibility"]["implementation_sha256"]),
                         {"imports.py", "adapters.py", "collectors.py"})
        self.assertIn("validity", manifest["adapter_metadata"]["fidelity"])
        self.assertEqual((args.output / "source.input").read_bytes(), args.input.read_bytes())
        self.assertEqual((args.output / "profile.json").read_bytes(), args.profile.read_bytes())

    def test_profiles_fail_closed_on_unknown_fields_options_and_bad_types(self):
        invalid = [profile(extra=1), profile(schema_version=True), profile(expected_records=True),
                   profile(complete=1), profile(host_profile={}), profile(provenance={}),
                   profile(options={"shell_command": "never-run"}), profile(context={**CONTEXT, "extra": 1})]
        for selected in invalid:
            args = self.args(selected_profile=selected)
            with self.subTest(profile=selected), self.assertRaises(ValueError):
                imports.import_saved(args)
            self.assertFalse(args.output.exists())

    def test_profile_requires_valid_ids_and_rejects_nonfinite_unused_details(self):
        for selected in (profile(context={**CONTEXT, "run_id": "bad id"}),
                         profile(provenance={"unrelated": float("inf")}),
                         profile(host_profile={"unrelated": 10**100})):
            args = self.args(selected_profile=selected)
            with self.assertRaises(ValueError):
                imports.import_saved(args)

    def test_source_and_profile_must_be_regular_nonsymlink_bounded_files(self):
        args = self.args()
        link = args.input.parent / "input-link"
        link.symlink_to(args.input)
        with self.assertRaises(ValueError):
            imports._saved_bytes(link, 1000)
        fifo = args.input.parent / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            imports._saved_bytes(fifo, 1000)
        with self.assertRaises(ValueError):
            imports._saved_bytes(args.input, 1)

    def test_existing_output_is_never_overwritten(self):
        args = self.args()
        imports.import_saved(args)
        saved = (args.output / "receipt.json").read_bytes()
        with self.assertRaises(FileExistsError):
            imports.import_saved(args)
        self.assertEqual((args.output / "receipt.json").read_bytes(), saved)

    def test_incomplete_declaration_stays_incomplete_despite_matching_counts(self):
        args = self.args(selected_profile=profile(complete=False))
        imports.import_saved(args)
        receipt, _, _ = self.evidence(args)
        self.assertFalse(receipt["complete"])
        self.assertFalse(receipt["successful"])
        self.assertEqual(receipt["status"], "incomplete")

    def test_count_mismatch_keeps_failed_receipt_and_original_input(self):
        args = self.args(selected_profile=profile(expected_records=2))
        with self.assertRaisesRegex(ValueError, "record count mismatch"):
            imports.import_saved(args)
        receipt, _, records = self.evidence(args)
        self.assertEqual(len(records), 1)
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["status"], "failed")

    def test_normalized_import_preserves_process_attempt_failure_and_censoring(self):
        rows = [raw_record(process_id="p1", attempt_id="a1"),
                raw_record(process_id="p2", attempt_id="a2", outcome="timeout",
                           metrics={"propagation_admit_ns": 100}, censored=["propagation_admit_ns"])]
        args = self.args("normalized", jsonl(rows), profile(expected_records=2))
        imports.import_saved(args)
        receipt, _, actual = self.evidence(args)
        self.assertEqual(actual, rows)
        self.assertTrue(receipt["complete"])
        self.assertFalse(receipt["successful"])

    def test_normalized_import_preserves_warmups_alongside_measurements(self):
        rows = [raw_record(attempt_id="warm", warmup=True, metrics={"transaction_bytes": 999}),
                raw_record(attempt_id="sample", metrics={"transaction_bytes": 10})]
        args = self.args("normalized", jsonl(rows), profile(expected_records=2))
        imports.import_saved(args)
        _, manifest, actual = self.evidence(args)
        summary = results.summarize(actual, complete=True)
        self.assertEqual(summary["warmup_count"], 1)
        self.assertEqual(summary["groups"][0]["metrics"]["transaction_bytes"]["p99"], 10)
        self.assertEqual(manifest["adapter_compatibility"]["warmup_records"], 1)

    def test_normalized_wrong_context_duplicate_unknown_and_partial_records_fail(self):
        cases = [jsonl([raw_record(run_id="other")]), jsonl([raw_record(), raw_record()]),
                 jsonl([raw_record(units="ms")]), jsonl([raw_record()]).rstrip("\n"),
                 jsonl([raw_record()]).replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')]
        for source in cases:
            args = self.args("normalized", source, profile(expected_records=2 if source.count("\n") == 2 else 1))
            with self.subTest(source=source[:50]), self.assertRaises(ValueError):
                imports.import_saved(args)
            receipt = provenance.read_json(args.output / "receipt.json")
            self.assertFalse(receipt["complete"])
            self.assertEqual(receipt["status"], "failed")

    def test_block_probe_unknown_is_unavailable_and_declaration_is_labeled(self):
        for disabled in (False, True):
            selected = profile(options={"throughput_probe_disabled": disabled})
            if disabled:
                text = "[sync]\nparallel_cpu_threads = 2\n"
                selected["options"]["effective_config_toml"] = text
                selected["provenance"]["effective_config_sha256"] = hashlib.sha256(text.encode()).hexdigest()
            args = self.args("block-trace", jsonl(block_rows()),
                             selected)
            imports.import_saved(args)
            receipt, manifest, records = self.evidence(args)
            measured = records[0]["metrics"]["block_verify_commit_ns"]
            self.assertEqual(measured, 10_000_000 if disabled else None)
            self.assertEqual(receipt["successful"], disabled)
            if disabled:
                self.assertIn("operator-declared", manifest["adapter_metadata"]["probe_configuration_evidence"])
                self.assertEqual(records[0]["details"]["effective_config_sha256"],
                                 selected["provenance"]["effective_config_sha256"])
            else:
                self.assertIn("not established", manifest["adapter_metadata"]["probe_configuration_evidence"])

    def test_block_probe_declaration_requires_matching_saved_disabled_config(self):
        missing = profile(options={"throughput_probe_disabled": True})
        invalid = [missing]
        for text in ("[sync]\ndebug_blocksync_throughput_target_height = 100\n", "not TOML"):
            selected = profile(options={"throughput_probe_disabled": True, "effective_config_toml": text})
            selected["provenance"]["effective_config_sha256"] = hashlib.sha256(text.encode()).hexdigest()
            invalid.append(selected)
        invalid.append(profile(options={"throughput_probe_disabled": True, "effective_config_toml": "[sync]\n"}))
        for selected in invalid:
            args = self.args("block-trace", jsonl(block_rows()), selected)
            with self.subTest(options=selected["options"]), self.assertRaises(ValueError):
                imports.import_saved(args)
            receipt, _, records = self.evidence(args)
            self.assertFalse(receipt["complete"])
            self.assertEqual(records, [])

    def test_propagation_missing_peer_is_a_censored_timeout(self):
        common = {"schema_version": 1, "txid": "ab" * 32, "auth_digest": "cd" * 32,
                  "attempt_id": "attempt", "node": "origin", "process_epoch": "epoch",
                  "clock_domain": "declared-common-domain"}
        rows = [{**common, "event": "origin_submit", "monotonic_ns": 100},
                {**common, "event": "origin_admit", "monotonic_ns": 200}]
        selected = profile(expected_records=2, options={"expected_peers": {"remote": "epoch"},
                           "observation_end_ns": 500, "verified_clock_domain": "declared-common-domain"})
        args = self.args("propagation", jsonl(rows), selected)
        imports.import_saved(args)
        receipt, manifest, records = self.evidence(args)
        self.assertFalse(receipt["successful"])
        self.assertEqual(records[1]["outcome"], "timeout")
        self.assertEqual(records[1]["metrics"]["propagation_admit_ns"], 300)
        self.assertIn("propagation_admit_ns", records[1]["censored"])
        self.assertIn("not independently checked", manifest["adapter_metadata"]["clock_evidence"])

    def test_mempool_growth_uses_prior_scrape_embedded_in_hashed_profile(self):
        selected = profile(options={"monotonic_ns": 2_000_000_000, "process_epoch": "epoch",
                                    "previous_text": scrape(4, 800), "previous_monotonic_ns": 1_000_000_000,
                                    "previous_process_epoch": "epoch"})
        args = self.args("mempool", scrape(), selected)
        imports.import_saved(args)
        _, manifest, records = self.evidence(args)
        self.assertEqual(records[0]["metrics"]["mempool_growth_transactions_per_second"], -2)
        self.assertEqual(manifest["adapter_compatibility"]["growth_interval_ns"], 1_000_000_000)

    def test_resource_pair_uses_saved_snapshot_values_without_reading_processes(self):
        before = {"kind": "interface", "identity": {"interface": "veth0", "ifindex": 1,
                  "namespace": "fixture", "sys_root": "/synthetic"},
                  "metrics": {"interface_rx_bytes": 100, "interface_tx_bytes": 200},
                  "unavailable": {}, "details": {"scope": "synthetic isolated interface"},
                  "window_start_ns": 0, "window_end_ns": 10}
        after = copy.deepcopy(before)
        after.update(window_start_ns=1_000_000_000, window_end_ns=1_000_000_010)
        after["metrics"] = {"interface_rx_bytes": 500, "interface_tx_bytes": 1000}
        args = self.args("resources", json.dumps({"before": before, "after": after}))
        with patch("collectors.read_process", side_effect=AssertionError("no live reads")), \
             patch("collectors.read_interface", side_effect=AssertionError("no live reads")):
            imports.import_saved(args)
        _, _, records = self.evidence(args)
        self.assertEqual(records[0]["metrics"]["interface_rx_bytes_per_second"], 400)
        self.assertEqual(records[0]["metrics"]["interface_tx_bytes_per_second"], 800)

    def test_malformed_resource_envelope_fails_with_immutable_input_retained(self):
        args = self.args("resources", '{"before":{},"after":{},"command":"never-run"}')
        with self.assertRaisesRegex(ValueError, "resource pair fields"):
            imports.import_saved(args)
        receipt, _, records = self.evidence(args)
        self.assertEqual(records, [])
        self.assertEqual(receipt["status"], "failed")

    def test_different_run_observations_do_not_change_comparison_contract(self):
        first = self.args(source="0001\n")
        second_profile = profile(context={**CONTEXT, "run_id": "another-run", "process_id": "other-process"})
        second = self.args(source="0002\n", selected_profile=second_profile)
        imports.import_saved(first)
        imports.import_saved(second)
        _, a, _ = self.evidence(first)
        _, b, _ = self.evidence(second)
        self.assertEqual(a["settings"], b["settings"])
        self.assertEqual(a["adapter_compatibility"], b["adapter_compatibility"])
        self.assertNotEqual(a["adapter_metadata"], b["adapter_metadata"])


if __name__ == "__main__":
    unittest.main()
