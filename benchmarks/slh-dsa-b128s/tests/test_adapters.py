"""Saved synthetic event and scrape tests. No network or workload execution."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import adapters
from results import summarize, validate_record


CONTEXT = dict(run_id="unit", case_id="import", configuration_id="fixture", process_id="test",
               attempt_id="attempt", phase="measure", cache_mode="warm", warmup=False)


def block_rows(*, result="committed", apply_class="full", token=7, epoch="boot-a", node="node-a", offset=0):
    common = dict(node=node, process_trace_id=epoch, source="block_sync_driver", apply_token=token,
                  height=110, hash="ab" * 32, apply_class=apply_class)
    return [dict(common, event="block_submit_queued", ts=offset + 1000),
            dict(common, event="commit_start", ts=offset + 2000),
            dict(common, event="commit_finish", ts=offset + 12000, elapsed_ms=10, result=result)]


def propagation_rows():
    common = dict(schema_version=1, txid="ab" * 32, auth_digest="cd" * 32, attempt_id="broadcast-1",
                  clock_domain="verified-host-boot-a")
    return [dict(common, event="origin_submit", node="origin", process_epoch="origin-epoch", monotonic_ns=100),
            dict(common, event="origin_admit", node="origin", process_epoch="origin-epoch", monotonic_ns=200),
            dict(common, event="peer_receive", node="peer", process_epoch="peer-epoch", monotonic_ns=300),
            dict(common, event="peer_admit", node="peer", process_epoch="peer-epoch", monotonic_ns=500)]


def scrape(transactions=5, byte_count=400, cost=500):
    return (f"# TYPE zcash_mempool_size_transactions gauge\nzcash_mempool_size_transactions {transactions}\n"
            f"zcash_mempool_size_bytes {byte_count}\nzcash_mempool_cost_bytes {cost}\n")


class AdapterTests(unittest.TestCase):
    def valid(self, result):
        records, metadata = result
        for record in records:
            validate_record(record)
        self.assertEqual(len(records), len({(row["run_id"], row["process_id"], row["attempt_id"]) for row in records}))
        return records, metadata

    def block(self, rows=None, **kwargs):
        return self.valid(adapters.import_block_trace(block_rows() if rows is None else rows, CONTEXT,
                                                      throughput_probe_disabled=kwargs.pop("throughput_probe_disabled", True), **kwargs))

    def propagation(self, rows=None, **kwargs):
        values = dict(expected_peers={"peer": "peer-epoch"}, observation_end_ns=1000,
                      verified_clock_domain="verified-host-boot-a")
        values.update(kwargs)
        return self.valid(adapters.import_propagation(propagation_rows() if rows is None else rows, CONTEXT, **values))

    def test_exact_serialized_size_and_hash(self):
        records, metadata = self.valid(adapters.transaction_size("0001FF\n", CONTEXT))
        self.assertEqual(records[0]["metrics"]["transaction_bytes"], 3)
        self.assertEqual(metadata["serialized_sha256"], hashlib.sha256(b"\0\1\xff").hexdigest())
        self.assertIn("validity", metadata["fidelity"])

    def test_transaction_hex_rejects_ambiguous_input(self):
        for value in ("", "0", "0x00", "00 11", "00\n11", " 00", "00\n\n", "gg", 1):
            with self.subTest(value=value), self.assertRaises(adapters.AdapterError):
                adapters.transaction_size(value, CONTEXT)

    def test_full_block_elapsed_is_combined_metric(self):
        records, metadata = self.block()
        self.assertEqual(records[0]["metrics"]["block_verify_commit_ns"], 10_000_000)
        self.assertEqual(records[0]["metrics"]["trace_queue_ns"], 1_000_000)
        self.assertNotIn("block_verify_ns", records[0]["metrics"])
        self.assertNotIn("block_commit_ns", records[0]["metrics"])
        self.assertTrue(metadata["throughput_probe_disabled"])

    def test_checkpoint_not_mixed_with_full_verification(self):
        rows = block_rows() + block_rows(apply_class="checkpoint", token=8, offset=13000)
        records, _ = self.block(rows)
        self.assertEqual(records[1]["metrics"]["checkpoint_residence_ns"], 10_000_000)
        self.assertNotIn("block_verify_commit_ns", records[1]["metrics"])
        report = summarize(records, complete=True)
        self.assertEqual(report["missing_count"], 0)

    def test_probe_unknown_cannot_claim_block_validation(self):
        records, _ = self.block(throughput_probe_disabled=False)
        self.assertIsNone(records[0]["metrics"]["block_verify_commit_ns"])
        self.assertIn("probe", records[0]["unavailable"]["block_verify_commit_ns"])

    def test_noncommitted_and_timeout_retained(self):
        for result, outcome in (("timed_out", "timeout"), ("rejected", "unexpected_rejection"),
                                ("unavailable", "error"), ("duplicate", "error")):
            with self.subTest(result=result):
                record = self.block(block_rows(result=result))[0][0]
                self.assertEqual(record["outcome"], outcome)
                self.assertEqual(record["metrics"]["attempt_elapsed_ns"], 10_000_000)
                if result == "timed_out":
                    self.assertEqual(record["censored"], ["block_verify_commit_ns"])
                else:
                    self.assertIsNone(record["metrics"]["block_verify_commit_ns"])

    def test_block_missing_duplicate_and_wrong_hash_fail(self):
        for index in range(3):
            rows = block_rows()
            del rows[index]
            with self.subTest(missing=index), self.assertRaisesRegex(adapters.AdapterError, "incomplete"):
                self.block(rows)
            rows = block_rows()
            rows.append(copy.deepcopy(rows[index]))
            with self.subTest(duplicate=index), self.assertRaisesRegex(adapters.AdapterError, "duplicate"):
                self.block(rows)
        for field, value in (("hash", "cd" * 32), ("height", 111), ("apply_class", "checkpoint")):
            rows = block_rows()
            rows[-1][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(adapters.AdapterError, "mismatch"):
                self.block(rows)

    def test_block_epoch_and_token_separate_repeated_heights(self):
        rows = block_rows() + block_rows(epoch="boot-b") + block_rows(token=8, offset=13000)
        records, _ = self.block(rows)
        self.assertEqual(len(records), 3)

    def test_block_interleaving_does_not_require_global_timestamp_order(self):
        first, second = block_rows(), block_rows(token=8, offset=100)
        records, _ = self.block([second[0], first[0], first[1], second[1], second[2], first[2]])
        self.assertEqual(len(records), 2)

    def test_block_rejects_impossible_elapsed_and_order(self):
        rows = block_rows()
        rows[-1]["elapsed_ms"] = 100
        with self.assertRaisesRegex(adapters.AdapterError, "exceeds"):
            self.block(rows)
        rows[-1]["ts"] = 1000
        with self.assertRaisesRegex(adapters.AdapterError, "order"):
            self.block(rows)

    def test_block_header_rows_not_validation(self):
        headers = [dict(event="commit_finish", source="header_sync_driver", range_count=10,
                        range_start=110, elapsed_ms=5, result="committed")]
        with self.assertRaisesRegex(adapters.AdapterError, "no block-driver"):
            self.block(headers)
        records, metadata = self.block(block_rows() + headers)
        self.assertEqual(len(records), 1)
        self.assertEqual(metadata["ignored_rows"], 1)

    def test_block_stall_correlates_to_attempt(self):
        rows = block_rows()
        stalled = dict(rows[1], event="commit_stalled", ts=6000, elapsed_ms=4)
        record = self.block(rows[:2] + [stalled] + rows[2:])[0][0]
        self.assertEqual(record["details"]["stalls"], 1)
        stalled["ts"] = 50000
        with self.assertRaisesRegex(adapters.AdapterError, "outside"):
            self.block(rows + [stalled])

    def test_jsonl_duplicate_keys_and_invalid_lines_rejected(self):
        for text in ('{"event":"x","event":"y"}\n', '{}\n{"truncated":', '[]\n', '{"value":NaN}\n', '', '{}\n\n', '{}'):
            with self.subTest(text=text), self.assertRaises(adapters.AdapterError):
                self.block(text)

    def test_real_trace_jsonl_contract(self):
        text = "\n".join(json.dumps(row) for row in block_rows()) + "\n"
        self.assertEqual(self.block(text)[0][0]["details"]["apply_token"], 7)

    def test_propagation_explicit_stages_and_identity(self):
        records, metadata = self.propagation()
        self.assertEqual(records[0]["metrics"]["propagation_origin_admit_ns"], 100)
        self.assertEqual(records[1]["metrics"]["propagation_receive_ns"], 100)
        self.assertEqual(records[1]["metrics"]["propagation_admit_ns"], 300)
        self.assertIn("instrumentation", metadata["fidelity"])
        self.assertEqual(summarize(records, complete=True)["missing_count"], 0)

    def test_missing_admission_is_timeout_not_delivered(self):
        records, _ = self.propagation(propagation_rows()[:-1])
        peer = records[1]
        self.assertEqual(peer["outcome"], "timeout")
        self.assertEqual(peer["metrics"]["propagation_receive_ns"], 100)
        self.assertEqual(peer["metrics"]["propagation_admit_ns"], 800)
        self.assertEqual(peer["censored"], ["propagation_admit_ns"])
        report = summarize(records, complete=True)
        group = next(group for group in report["groups"] if "propagation_admit_ns" in group["metrics"])
        self.assertIsNone(group["metrics"]["propagation_admit_ns"]["p99"])
        self.assertFalse(report["successful"])

    def test_peer_with_no_logs_is_retained(self):
        records, _ = self.propagation(expected_peers={"peer": "peer-epoch", "silent-peer": "silent-epoch"})
        silent = next(record for record in records if record["details"].get("peer_node") == "silent-peer")
        self.assertEqual(silent["outcome"], "timeout")
        self.assertEqual(len(silent["censored"]), 2)

    def test_missing_origin_admission_cannot_start_propagation_timer(self):
        records, _ = self.propagation(propagation_rows()[:1])
        self.assertEqual(records[0]["outcome"], "timeout")
        self.assertEqual(records[1]["outcome"], "error")
        self.assertIsNone(records[1]["metrics"]["propagation_receive_ns"])

    def test_propagation_requires_verified_shared_clock(self):
        rows = propagation_rows()
        rows[-1]["clock_domain"] = "other-host"
        with self.assertRaisesRegex(adapters.AdapterError, "clock domain"):
            self.propagation(rows)
        with self.assertRaises(adapters.AdapterError):
            self.propagation(verified_clock_domain="")

    def test_propagation_rejects_epoch_mismatch_and_duplicates(self):
        rows = propagation_rows()
        rows[-1]["process_epoch"] = "restarted-peer"
        with self.assertRaisesRegex(adapters.AdapterError, "epoch"):
            self.propagation(rows)
        rows = propagation_rows()
        rows.append(copy.deepcopy(rows[-1]))
        with self.assertRaisesRegex(adapters.AdapterError, "duplicate"):
            self.propagation(rows)
        rows = propagation_rows()
        rows[1]["process_epoch"] = "restarted-origin"
        with self.assertRaisesRegex(adapters.AdapterError, "origin admission identity"):
            self.propagation(rows)

    def test_propagation_digest_and_attempt_are_correlation_keys(self):
        for field, value in (("txid", "ef" * 32), ("auth_digest", "ef" * 32), ("attempt_id", "different-attempt")):
            rows = propagation_rows()
            rows[-1][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(adapters.AdapterError, "origin_submit"):
                self.propagation(rows)

    def test_propagation_missing_boundary_and_negative_duration_rejected(self):
        rows = propagation_rows()
        del rows[2]
        with self.assertRaisesRegex(adapters.AdapterError, "receive boundary"):
            self.propagation(rows)
        rows = propagation_rows()
        rows[2]["monotonic_ns"] = 199
        with self.assertRaisesRegex(adapters.AdapterError, "precedes"):
            self.propagation(rows)
        with self.assertRaisesRegex(adapters.AdapterError, "cutoff"):
            self.propagation(observation_end_ns=400)

    def test_propagation_schema_strict(self):
        rows = propagation_rows()
        rows[0]["wall_clock"] = 0
        with self.assertRaisesRegex(adapters.AdapterError, "schema"):
            self.propagation(rows)
        rows = propagation_rows()
        rows[0]["auth_digest"] = "missing"
        with self.assertRaisesRegex(adapters.AdapterError, "digest"):
            self.propagation(rows)

    def test_mempool_actual_product_names_and_units(self):
        metrics, unavailable = adapters.parse_mempool_metrics(scrape())
        self.assertEqual(metrics, {"mempool_transactions": 5, "mempool_bytes": 400, "mempool_cost": 500})
        self.assertEqual(unavailable, {})

    def test_missing_mempool_capabilities_are_null(self):
        metrics, unavailable = adapters.parse_mempool_metrics("# unrelated\nother_metric nan\n")
        self.assertTrue(all(value is None for value in metrics.values()))
        self.assertEqual(set(metrics), set(unavailable))

    def test_mempool_strict_needed_lines_and_duplicates(self):
        values = ["not-a-number", "NaN", "+Inf", "-1", "0.5", "2 bad-timestamp", "1 2 3", "1e100000"]
        for value in values:
            with self.subTest(value=value), self.assertRaises(adapters.AdapterError):
                adapters.parse_mempool_metrics(f"zcash_mempool_size_bytes {value}")
        for text in (scrape() + "zcash_mempool_size_bytes 400\n",
                     'zcash_mempool_size_bytes{node="a",node="b"} 1',
                     'zcash_mempool_size_bytes{bad} 1',
                     'zcash_mempool_size_bytes{node="a" 1',
                     'zcash_mempool_size_bytes{node="a"}1',
                     '# TYPE zcash_mempool_size_bytes counter\nzcash_mempool_size_bytes 1',
                     'zcash_mempool_size_bytes{node="a\\t"} 1'):
            with self.subTest(text=text), self.assertRaises(adapters.AdapterError):
                adapters.parse_mempool_metrics(text)

    def test_mempool_exact_labels_escapes_and_integer_precision(self):
        text = 'zcash_mempool_size_bytes{node="a\\n\\\"\\\\}",} 9007199254740993 1234\n'
        metrics, _ = adapters.parse_mempool_metrics(text, labels={"node": 'a\n"\\}'})
        self.assertEqual(metrics["mempool_bytes"], 9007199254740993)
        metrics, _ = adapters.parse_mempool_metrics("zcash_mempool_size_bytes 4e2")
        self.assertEqual(metrics["mempool_bytes"], 400)

    def test_mempool_negative_growth_valid_not_counter_reset(self):
        records, _ = self.valid(adapters.import_mempool(scrape(3, 200), CONTEXT, monotonic_ns=2_000_000_000,
                                                       process_epoch="node-epoch", previous_text=scrape(),
                                                       previous_monotonic_ns=1_000_000_000, previous_process_epoch="node-epoch"))
        self.assertEqual(records[0]["metrics"]["mempool_growth_transactions_per_second"], -2)
        self.assertEqual(records[0]["metrics"]["mempool_growth_bytes_per_second"], -200)

    def test_mempool_restarts_and_invalid_intervals_rejected(self):
        for previous_epoch, previous_ts in (("different", 1), ("same", 2), ("same", 3)):
            with self.subTest(epoch=previous_epoch, ts=previous_ts), self.assertRaises(adapters.AdapterError):
                adapters.import_mempool(scrape(), CONTEXT, monotonic_ns=2, process_epoch="same",
                                        previous_text=scrape(), previous_monotonic_ns=previous_ts,
                                        previous_process_epoch=previous_epoch)

    def test_mempool_missing_prior_gauge_does_not_become_zero_growth(self):
        records, _ = self.valid(adapters.import_mempool(scrape(), CONTEXT, monotonic_ns=2_000_000_000,
                                                       process_epoch="same", previous_text="other 0\n",
                                                       previous_monotonic_ns=1_000_000_000, previous_process_epoch="same"))
        self.assertIsNone(records[0]["metrics"]["mempool_growth_bytes_per_second"])


if __name__ == "__main__":
    unittest.main()
