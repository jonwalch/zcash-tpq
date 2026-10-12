"""Synthetic checks for evidence validation; these run no benchmark workloads."""

import copy
import csv
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import results


def record(attempt="1", **changes):
    value = {
        "schema_version": 1,
        "run_id": "run-1", "case_id": "primitive.verify", "configuration_id": "config-1",
        "process_id": "process-1", "attempt_id": attempt,
        "phase": "measure", "cache_mode": "repeated-input", "warmup": False,
        "outcome": "success", "metrics": {"signature_verify_ns": 10},
        "unavailable": {}, "censored": [],
    }
    value.update(changes)
    return value


def group(summary, outcome="all_outcomes", **dimensions):
    matches = [item for item in summary["groups"] if item["outcome"] == outcome
               and all(item[key] == value for key, value in dimensions.items())]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one group, got {len(matches)}")
    return matches[0]


class RecordTests(unittest.TestCase):
    def test_valid_record_and_all_catalog_metrics(self):
        value = record(metrics={name: 1 for name in results.METRIC_CATALOG})
        self.assertIs(results.validate_record(value), value)

    def test_rejects_schema_unknown_fields_and_bad_identifiers(self):
        invalid = [record(schema_version=True), record(schema_version=2), record(units="ms")]
        for field in results.ID_FIELDS:
            for value in ("", " ", "a\nb", "a/b", "é", "x" * 129, 42, None):
                invalid.append(record(**{field: value}))
        value = record()
        del value["censored"]
        invalid.append(value)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(results.ValidationError):
                results.validate_record(value)

    def test_rejects_bad_outcome_and_warmup(self):
        for value in (record(outcome="failure"), record(outcome=None), record(warmup=0)):
            with self.subTest(value=value), self.assertRaises(results.ValidationError):
                results.validate_record(value)

    def test_rejects_nonfinite_bool_negative_integer_and_unknown_units(self):
        for value in (True, False, float("nan"), float("inf"), -float("inf"), -1, 1.0,
                      2**64, 10**1000, "10", {"value": 10, "unit": "ms"}):
            with self.subTest(value=value), self.assertRaises(results.ValidationError):
                results.validate_record(record(metrics={"signature_verify_ns": value}))
        with self.assertRaises(results.ValidationError):
            results.validate_record(record(metrics={"signature_verify_ms": 10}))

    def test_rates_may_be_fractional_and_only_growth_may_be_negative(self):
        results.validate_record(record(metrics={
            "mempool_growth_bytes_per_second": -0.5,
            "mempool_growth_transactions_per_second": -1.25,
            "process_cpu_core_equivalents": 1.5,
        }))
        for name in ("interface_tx_bytes_per_second", "process_cpu_core_equivalents",
                     "mempool_drain_transactions_per_second"):
            with self.subTest(name=name), self.assertRaises(results.ValidationError):
                results.validate_record(record(metrics={name: -1.5}))
        with self.assertRaises(results.ValidationError):
            results.validate_record(record(metrics={"effective_cpu_cores": 0}))

    def test_nulls_require_exact_reasons(self):
        results.validate_record(record(metrics={"process_peak_rss_bytes": None},
                                       unavailable={"process_peak_rss_bytes": "unsupported OS"}))
        invalid = [
            record(metrics={"signature_verify_ns": None}),
            record(unavailable={"signature_verify_ns": "unexpected reason"}),
            record(metrics={"signature_verify_ns": None}, unavailable={"signature_verify_ns": " "}),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(results.ValidationError):
                results.validate_record(value)

    def test_censored_bounds_must_be_numeric_unique_and_not_success(self):
        results.validate_record(record(outcome="timeout", censored=["signature_verify_ns"]))
        for value in (
            record(censored=["signature_verify_ns"]),
            record(outcome="timeout", censored=["missing"]),
            record(outcome="timeout", censored=["signature_verify_ns"] * 2),
            record(outcome="timeout", metrics={"signature_verify_ns": None},
                   unavailable={"signature_verify_ns": "timeout"}, censored=["signature_verify_ns"]),
        ):
            with self.subTest(value=value), self.assertRaises(results.ValidationError):
                results.validate_record(value)

    def test_bounded_json_details(self):
        results.validate_record(record(details={"clock": "monotonic", "preflight": True}))
        cyclic = {}
        cyclic["self"] = cyclic
        for details in ({"x": "x" * 4097}, {"x": float("nan")}, {"x": object()},
                        {1: "not a JSON key"}, [], {"x": [0] * 2048}, cyclic):
            with self.subTest(kind=type(details).__name__), self.assertRaises(results.ValidationError):
                results.validate_record(record(details=details))


class SummaryTests(unittest.TestCase):
    def test_nearest_rank_applies_to_every_registered_metric(self):
        records = [record(str(i), metrics={name: i for name in results.METRIC_CATALOG})
                   for i in range(1, 101)]
        summary = results.summarize(records, complete=True)
        self.assertTrue(summary["successful"])
        self.assertEqual(summary["status"], "complete")
        for name, metric in group(summary)["metrics"].items():
            with self.subTest(name=name):
                self.assertEqual([metric[key] for key in ("samples", "p50", "p95", "p99")],
                                 [100, 50, 95, 99])
                self.assertEqual(metric["unit"], results.METRIC_CATALOG[name]["unit"])

    def test_even_median_is_lower_middle_and_integer_precision_is_preserved(self):
        values = [2**63 + 3, 2**63 + 1, 2**63 + 4, 2**63 + 2]
        summary = results.summarize([record(str(i), metrics={"transaction_bytes": value})
                                     for i, value in enumerate(values)], complete=True)
        self.assertEqual(group(summary)["metrics"]["transaction_bytes"]["p50"], 2**63 + 2)

    def test_failed_attempts_remain_visible_beside_successful_quantiles(self):
        summary = results.summarize([
            record("1", metrics={"signature_verify_ns": 10}),
            record("2", outcome="expected_rejection", metrics={"signature_verify_ns": 20}),
            record("3", outcome="error", metrics={"signature_verify_ns": 500}),
        ], complete=True)
        self.assertFalse(summary["successful"])
        self.assertEqual(summary["outcome_counts"]["error"], 1)
        self.assertEqual(group(summary)["metrics"]["signature_verify_ns"]["p95"], 500)
        self.assertEqual(group(summary, "success")["metrics"]["signature_verify_ns"]["p95"], 10)
        self.assertEqual(group(summary, "expected_rejection")["observation_count"], 1)

    def test_expected_rejections_can_be_successful_evidence(self):
        summary = results.summarize([record(outcome="expected_rejection")], complete=True)
        self.assertTrue(summary["successful"])

    def test_timeouts_preserve_bounds_without_fake_percentiles(self):
        summary = results.summarize([
            record("1", outcome="success", metrics={"signature_verify_ns": 10}),
            record("2", outcome="timeout", metrics={"signature_verify_ns": 100},
                   censored=["signature_verify_ns"]),
        ], complete=True)
        total = group(summary)["metrics"]["signature_verify_ns"]
        self.assertEqual(total["samples"], 1)
        self.assertEqual(total["p99"], 10)
        self.assertEqual(total["censored_count"], 1)
        self.assertEqual(total["lower_bound_min"], 100)
        self.assertTrue(total["tail_incomplete"])
        timeout = group(summary, "timeout")["metrics"]["signature_verify_ns"]
        self.assertIsNone(timeout["p50"])
        self.assertIn("reason", timeout)
        self.assertFalse(summary["successful"])

    def test_warmups_are_not_observations_but_warmup_errors_are_visible(self):
        summary = results.summarize([
            record("warm", warmup=True, outcome="error", metrics={"signature_verify_ns": 999}),
            record("sample", metrics={"signature_verify_ns": 10}),
        ], complete=True)
        self.assertEqual(group(summary)["metrics"]["signature_verify_ns"]["p99"], 10)
        self.assertEqual(summary["warmup_outcome_counts"]["error"], 1)
        self.assertEqual(summary["measurement_outcome_counts"]["error"], 0)
        self.assertEqual(group(summary)["warmup_attempt_ids"], ["warm"])
        self.assertFalse(summary["successful"])

    def test_empty_warmup_only_and_unmeasured_populations_are_not_successful(self):
        for records in ([], [record(warmup=True)], [record(metrics={})]):
            with self.subTest(records=records):
                summary = results.summarize(records, complete=True)
                self.assertFalse(summary["successful"])
                self.assertEqual(summary["status"], "complete_with_issues")
        warmup = results.summarize([record(warmup=True)])
        self.assertIsNone(group(warmup)["metrics"]["signature_verify_ns"]["p50"])

    def test_unavailable_and_absent_values_are_distinct(self):
        summary = results.summarize([
            record("1", metrics={"transaction_bytes": 10, "process_peak_rss_bytes": None},
                   unavailable={"process_peak_rss_bytes": "unsupported"}),
            record("2", metrics={"transaction_bytes": 10}),
        ], complete=True)
        metric = group(summary)["metrics"]["process_peak_rss_bytes"]
        self.assertEqual(metric["unavailable_count"], 1)
        self.assertEqual(metric["missing_count"], 1)
        self.assertEqual(metric["unavailable_reasons"], {"unsupported": 1})
        self.assertIsNone(metric["p99"])
        self.assertEqual(summary["missing_count"], 1)
        self.assertFalse(summary["successful"])

    def test_interrupted_run_never_becomes_complete(self):
        summary = results.summarize([record()])
        self.assertFalse(summary["complete"])
        self.assertFalse(summary["successful"])
        self.assertEqual(summary["status"], "incomplete")

    def test_duplicate_attempt_identity_rejected_even_if_case_changes(self):
        with self.assertRaisesRegex(results.ValidationError, "duplicate attempt"):
            results.summarize([record(), record(case_id="another-case")])

    def test_runs_processes_phases_caches_and_configurations_never_pool(self):
        records = [record()]
        for field in results.DIMENSIONS:
            records.append(record(field, **{field: "different"}, metrics={"signature_verify_ns": 1000}))
        summary = results.summarize(records, complete=True)
        totals = [item for item in summary["groups"] if item["outcome"] == "all_outcomes"]
        self.assertEqual(len(totals), 7)
        self.assertTrue(all(item["metrics"]["signature_verify_ns"]["samples"] == 1 for item in totals))

    def test_input_and_group_count_bounds(self):
        with patch.object(results, "MAX_RECORDS", 1), self.assertRaises(results.ValidationError):
            results.summarize([record("1"), record("2")])
        with patch.object(results, "MAX_INPUT_BYTES", 1), self.assertRaises(results.ValidationError):
            results.summarize([record()])
        with patch.object(results, "MAX_GROUPS", 1), self.assertRaises(results.ValidationError):
            results.summarize([record()])


class InputAndReportTests(unittest.TestCase):
    def test_strict_jsonl_rejects_partial_duplicate_nonstandard_and_nonutf8_input(self):
        raw = json.dumps(record()).encode()
        invalid = [raw, raw + b"\n{", b"\n", raw.replace(b'"schema_version": 1',
                    b'"schema_version": 1, "schema_version": 1') + b"\n",
                   raw.replace(b'"signature_verify_ns": 10', b'"signature_verify_ns": NaN') + b"\n",
                   b'\xff\n', json.dumps(record()).encode("utf-16") + b"\n"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.jsonl"
            for data in invalid:
                path.write_bytes(data)
                with self.subTest(data=data[:80]), self.assertRaises(results.ValidationError):
                    list(results.read_records(path))
            path.write_bytes(raw + b"\n")
            self.assertEqual(list(results.read_records(path)), [record()])
            with patch.object(results, "MAX_RECORD_BYTES", 10), self.assertRaises(results.ValidationError):
                list(results.read_records(path))

    def test_reports_include_failures_and_escape_external_text(self):
        injected = '<script>alert("unsafe")</script>'
        summary = results.summarize([
            record(outcome="error", metrics={"rss_current_bytes": None},
                   unavailable={"rss_current_bytes": injected})
        ], complete=True)
        summary["sources"] = {"note": injected}
        with tempfile.TemporaryDirectory() as directory:
            files = results.write_reports(summary, directory)
            self.assertEqual(json.loads(Path(files["summary.json"]).read_text()), summary)
            page = Path(files["report.html"]).read_text()
            self.assertNotIn("<script>", page)
            self.assertIn("&lt;script&gt;", page)
            self.assertIn("complete_with_issues", page)
            with Path(files["summary.csv"]).open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["samples"], "0")
            self.assertEqual(json.loads(rows[0]["outcome_counts"])["error"], 1)
            with self.assertRaises(FileExistsError):
                results.write_reports(summary, directory)

    def test_empty_and_unmeasured_reports_keep_outcome_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            results.write_reports(results.summarize([]), Path(directory) / "empty")
            path = Path(directory) / "failed"
            results.write_reports(results.summarize([record(outcome="error", metrics={})]), path)
            with (path / "summary.csv").open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["metric"], "")
            self.assertEqual(json.loads(rows[0]["outcome_counts"])["error"], 1)


class ReportElements(HTMLParser):
    """Extract user-visible structure without a browser or external dependency."""

    def __init__(self, document):
        super().__init__()
        self.tags = []
        self.table_headers = []
        self._header = None
        self.links = []
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        attributes = dict(attrs)
        if tag == "th":
            self._header = ""
        if tag == "a":
            self.links.append(attributes.get("href"))

    def handle_data(self, data):
        if self._header is not None:
            self._header += data

    def handle_endtag(self, tag):
        if tag == "th":
            self.table_headers.append(self._header)
            self._header = None


class HtmlReportTests(unittest.TestCase):
    def render(self, records, **metadata):
        summary = results.summarize(records, complete=True)
        summary.update(metadata)
        with tempfile.TemporaryDirectory() as directory:
            files = results.write_reports(summary, directory)
            page = Path(files["report.html"]).read_text()
            self.assertEqual(json.loads(Path(files["summary.json"]).read_text()), summary)
            with Path(files["summary.csv"]).open(newline="") as handle:
                csv_rows = list(csv.DictReader(handle))
        return page, csv_rows

    def test_overview_precedes_collapsed_metadata_and_tables_have_focused_columns(self):
        page, _ = self.render([record("warm", warmup=True), record()],
                              provenance={"marker": "large-provenance-follows-results"})
        parsed = ReportElements(page)
        self.assertEqual(parsed.table_headers[:7],
                         ["Case / process", "Outcome", "p50 · median", "p95", "p99", "Exact n", "Coverage / details"])
        self.assertEqual(parsed.table_headers[7:13],
                         ["Metric", "p50 · median", "p95", "p99", "Exact n", "Coverage and interpretation"])
        self.assertEqual(len(parsed.table_headers), 19)  # timing overview, outcome, explicit audit view
        self.assertIn("summary.json", parsed.links)
        self.assertIn("summary.csv", parsed.links)
        self.assertLess(page.index("<table>"), page.index("large-provenance-follows-results"))
        self.assertIn("1 warmup records excluded from quantiles", page)
        self.assertIn("Producer finalized: yes · Evidence successful: yes", page)
        self.assertIn("<details class=\"audit\"><summary>Provenance", page)
        self.assertNotIn("script", parsed.tags)

    def test_readable_values_preserve_exact_large_integers_units_and_csv(self):
        exact_bytes = 2**63 + 1
        page, rows = self.render([record(metrics={"signature_verify_ns": 1_234_567,
                                                 "process_peak_rss_bytes": exact_bytes,
                                                 "signature_bytes": 7856})])
        self.assertIn("1.235 ms", page)
        self.assertIn("7,856 B", page)
        self.assertIn("GiB", page)
        self.assertIn(f"Exact: {exact_bytes} bytes", page)
        self.assertIn("Exact: 1234567 ns", page)
        self.assertIn(f'&quot;p99&quot;: {exact_bytes}', page)
        byte_rows = [row for row in rows if row["metric"] == "process_peak_rss_bytes"]
        self.assertTrue(all(row["p99"] == str(exact_bytes) for row in byte_rows))
        self.assertIn("Exact values and scope", page)
        self.assertIn("Lifetime high-water mark includes setup; not an operation peak.", page)

    def test_small_samples_and_one_peak_observation_have_nearby_caveats(self):
        records = [record(str(index), metrics={"signature_verify_ns": index * 1000})
                   for index in range(1, 11)]
        records.append(record("peak", phase="process-lifetime",
                              metrics={"process_peak_rss_bytes": 2**20}))
        page, _ = self.render(records)
        visible = page.split('<details class="audit">', 1)[0]
        self.assertIn('class="number">10</td>', visible)
        self.assertIn("Small sample: p95 and p99 are the observed maximum; tail stability is unproven.", visible)
        self.assertIn("One sample; all three percentiles repeat this value.", visible)
        self.assertIn("Process lifetime peak RSS", visible)
        self.assertIn("Record totals can include a separate final process-peak record", visible)

    def test_processes_and_failure_populations_remain_separate_and_visible(self):
        page, _ = self.render([
            record("success-1", metrics={"signature_verify_ns": 1_000_000}),
            record("success-2", process_id="process-2", metrics={"signature_verify_ns": 9_000_000}),
            record("rejection", outcome="expected_rejection", metrics={"signature_verify_ns": 2_000_000}),
            record("failure", outcome="error", metrics={}),
            record("timeout", outcome="timeout", metrics={"signature_verify_ns": 50_000_000},
                   censored=["signature_verify_ns"]),
        ])
        visible = page.split('<details class="audit">', 1)[0]
        self.assertEqual(visible.count('class="population"'), 5)
        self.assertIn("process-1", visible)
        self.assertIn("process-2", visible)
        self.assertIn("expected rejection · expected result", visible)
        self.assertIn("No metric values were recorded for this population.", visible)
        self.assertIn("1 censored lower bounds (50000000–50000000 ns); excluded from quantiles.", visible)
        self.assertIn("No exact samples; no quantiles.", visible)
        self.assertIn("Complete with issues", visible)
        self.assertIn("Combined outcome distributions (audit view)", page)
        self.assertIn("They are not additional measurements", page)

    def test_unavailable_missing_and_untrusted_reasons_are_not_hidden(self):
        injected = '<img src="bad" onerror="alert(1)">'
        page, _ = self.render([
            record("first", metrics={"rss_current_bytes": None},
                   unavailable={"rss_current_bytes": injected}),
            record("second", metrics={"signature_verify_ns": 12}),
        ])
        visible = page.split('<details class="audit">', 1)[0]
        self.assertIn("1 missing from recorded attempts.", visible)
        self.assertIn("1 unavailable: &lt;img", visible)
        self.assertIn("Incomplete tail", visible)
        self.assertNotIn("img", ReportElements(page).tags)

    def test_no_records_and_warmup_only_never_display_a_success_banner(self):
        for records in ([], [record(warmup=True)]):
            with self.subTest(records=records):
                page, _ = self.render(records)
                self.assertIn("Evidence successful: no", page)
                self.assertIn("no non-warmup observations", page)
                if records:
                    self.assertIn("No exact samples; no quantiles.", page)
                else:
                    self.assertIn("No measured populations are available.", page)

    def test_timing_overview_keeps_each_process_outcome_and_varying_scope_separate(self):
        page, _ = self.render([
            record("first", metrics={"signature_verify_ns": 1_000_000}),
            record("second", process_id="process-2", metrics={"signature_verify_ns": 9_000_000}),
            record("invalid", case_id="primitive.verify-invalid", outcome="expected_rejection",
                   metrics={"signature_verify_ns": 2_000_000}),
            record("other-run", run_id="run-2", configuration_id="config-2",
                   metrics={"signature_verify_ns": 5_000_000}),
            record("peak", phase="process", metrics={"process_peak_rss_bytes": 2**20}),
        ])
        overview = page.split('<section id="timing-overview">', 1)[1].split("</section>", 1)[0]
        self.assertEqual(overview.count("<tr>"), 5)  # four independent rows plus the header
        self.assertIn("Run: run-1", overview)
        self.assertIn("Run: run-2", overview)
        self.assertIn("Configuration: config-1", overview)
        self.assertIn("Configuration: config-2", overview)
        self.assertIn("expected rejection · expected result", overview)
        for milliseconds in (1, 2, 5, 9):
            self.assertIn(f">{milliseconds} ms</span>", overview)
        self.assertNotIn("all outcomes", overview)
        self.assertNotIn("Process lifetime peak RSS", overview)
        self.assertIn("4 primitive timing records · 1 separate process-peak records", page)
        self.assertIn('<div class="status">Complete</div>', page)
        self.assertLess(page.index('id="timing-overview"'), page.index('id="case-0"'))

    def test_serialized_transaction_label_does_not_claim_chain_acceptance(self):
        page, _ = self.render([record(metrics={"transaction_bytes": 8000})])
        self.assertIn("Serialized transaction size", page)
        self.assertNotIn("On-chain transaction size", page)


class ComparisonTests(unittest.TestCase):
    def matched(self, **record_changes):
        summary = results.summarize([record(**record_changes)], complete=True)
        summary["compatibility"] = {"hardware": "host-a", "case_configuration": "profile-1"}
        return summary

    def test_matched_processes_compare_without_matching_source_or_run_id(self):
        left = self.matched()
        right = self.matched(run_id="run-2", process_id="process-2",
                             metrics={"signature_verify_ns": 15})
        left["sources"] = {"revision": "a"}
        right["sources"] = {"revision": "b"}
        result = results.compare_summaries(left, right)
        metric = group(result)["metrics"]["signature_verify_ns"]
        self.assertEqual(metric["p50"], {"left": 10, "right": 15, "delta": 5, "change_percent": 50})
        self.assertEqual(group(result)["right"]["run_id"], "run-2")

    def test_incompatible_missing_metadata_incomplete_and_empty_rejected(self):
        left = self.matched()
        invalid = [self.matched() for _ in range(5)]
        invalid[0]["compatibility"] = {}
        invalid[1]["compatibility"]["hardware"] = "host-b"
        invalid[2]["complete"] = False
        invalid[3]["metric_catalog_sha256"] = "another-catalog"
        invalid[4]["observation_count"] = 0
        for right in invalid:
            with self.subTest(right=right), self.assertRaises(results.ValidationError):
                results.compare_summaries(left, right)

    def test_mismatched_populations_and_ambiguous_processes_rejected(self):
        left = self.matched()
        ambiguous = results.summarize([record(), record(process_id="other")], complete=True)
        ambiguous["compatibility"] = left["compatibility"]
        for right in (self.matched(case_id="different"),
                      self.matched(metrics={"transaction_bytes": 10}), ambiguous):
            with self.subTest(right=right), self.assertRaises(results.ValidationError):
                results.compare_summaries(left, right)

    def test_zero_and_extreme_rate_denominators_do_not_emit_nonfinite_percent(self):
        for before, after in ((0, 10), (1e-300, 1e10)):
            left = self.matched(metrics={"interface_rx_bytes_per_second": before})
            right = self.matched(metrics={"interface_rx_bytes_per_second": after})
            comparison = results.compare_summaries(left, right)
            self.assertIsNone(group(comparison)["metrics"]["interface_rx_bytes_per_second"]["p50"]["change_percent"])
            json.dumps(comparison, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
