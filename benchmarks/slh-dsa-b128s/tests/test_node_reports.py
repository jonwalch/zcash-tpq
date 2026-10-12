"""Synthetic presentation checks; no process sampling or network requests."""

import csv
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import results


def record(attempt, metrics, *, phase="resource-process", **changes):
    value = {
        "schema_version": 1, "run_id": "node-run", "case_id": "node-attached",
        "configuration_id": "node-config", "process_id": "pid-101", "attempt_id": attempt,
        "phase": phase, "cache_mode": "operator-declared", "warmup": False,
        "outcome": "success", "metrics": metrics, "unavailable": {}, "censored": [],
    }
    value.update(changes)
    return value


def provenance():
    return {
        "node_scope": {"samples": 3, "interval_ms": 1000, "planned_interval_total_ms": 3000,
                       "timeout_seconds": 10},
        "node_profile": {
            "network": "Regtest", "pid": 101, "binary_path": "/node/zakurad",
            "metrics_url": "http://127.0.0.1:9000/metrics",
            "workload": {"id": "idle-fixture", "description": "Attached idle Regtest node",
                         "fixture_sha256": "f" * 64, "state": "fresh empty chain",
                         "activity": "idle", "topology": "one node, no peers"},
        },
        "node_identity": {"binary_sha256": "a" * 64, "config_sha256": "b" * 64,
                          "source": {"source_commit": "c" * 40}},
        "node_execution": {"elapsed_ns": 3_050_000_000},
    }


class Tags(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.tags = []
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


class NodeReportTests(unittest.TestCase):
    def render(self, records, *, metadata=None):
        summary = results.summarize(records, complete=True)
        if metadata is not None:
            summary["provenance"] = metadata
        with tempfile.TemporaryDirectory() as directory:
            files = results.write_reports(summary, directory)
            page = Path(files["report.html"]).read_text()
            self.assertEqual(json.loads(Path(files["summary.json"]).read_text()), summary)
            with Path(files["summary.csv"]).open(newline="") as handle:
                rows = list(csv.DictReader(handle))
        return page, rows

    def test_node_schedule_scope_and_evidence_precede_metric_populations(self):
        page, _ = self.render([record("1", {"process_cpu_core_equivalents": 0.25,
                                             "rss_current_bytes": 2**20})], metadata=provenance())
        visible = page.split('<details class="audit">', 1)[0]
        self.assertLess(visible.index('id="node-scope"'), visible.index('id="node-overview"'))
        self.assertLess(visible.index('id="node-overview"'), visible.index('id="case-0"'))
        for text in ("3 intervals × 1000 ms requested delay between observations", "3000 ms total requested delay",
                     "3.05 s", "includes collection overhead", "PID 101", "/node/zakurad",
                     "idle-fixture", "fresh empty chain", "source_commit", "c" * 40, "f" * 64,
                     "operator declares", "not transaction or block latency",
                     "No isolated validation, admission, propagation or bandwidth measurement",
                     "Matched comparison unavailable", "Existing measurements remain readable",
                     "An observed sample maximum does not establish peak memory"):
            self.assertIn(text, visible)

    def test_gauges_signed_rates_and_cgroup_scopes_keep_their_own_quantiles(self):
        records = []
        for index, growth in enumerate((-3, -1, 2), 1):
            records.extend([
                record(f"mempool-{index}", {"mempool_transactions": index * 10,
                                            "mempool_bytes": index * 100,
                                            "mempool_growth_transactions_per_second": growth}, phase="mempool"),
                record(f"cgroup-{index}", {"cgroup_memory_current_bytes": index * 2**20},
                       phase="resource-cgroup"),
            ])
        page, rows = self.render(records, metadata=provenance())
        overview = page.split('<section id="node-overview">', 1)[1].split("</section>", 1)[0]
        self.assertIn("Mempool transaction count · gauge", overview)
        self.assertIn("Net transaction count growth", overview)
        self.assertIn("Current cgroup memory", overview)
        self.assertIn("-1 transactions/s", overview)
        self.assertIn("Phase: mempool", overview)
        self.assertIn("Phase: resource-cgroup", overview)
        self.assertNotIn("all outcomes", overview)
        metrics = {row["metric"]: row for row in rows if row["outcome"] == "success"}
        self.assertEqual([metrics["mempool_growth_transactions_per_second"][p] for p in ("p50", "p95", "p99")],
                         ["-1", "2", "2"])
        self.assertEqual(metrics["mempool_transactions"]["p50"], "20")
        self.assertEqual(metrics["cgroup_memory_current_bytes"]["p50"], str(2 * 2**20))
        self.assertTrue(all(row["samples"] == "3" for row in metrics.values()))

    def test_unavailable_lifetime_peaks_and_failed_intervals_remain_visible(self):
        page, rows = self.render([
            record("1", {"rss_current_bytes": 2**20, "process_peak_rss_bytes": None},
                   unavailable={"process_peak_rss_bytes": "attached process lifetime is unknown"}),
            record("2", {"rss_current_bytes": None, "process_peak_rss_bytes": None}, outcome="error",
                   unavailable={"rss_current_bytes": "process disappeared",
                                "process_peak_rss_bytes": "attached process lifetime is unknown"}),
        ], metadata=provenance())
        visible = page.split('<details class="audit">', 1)[0]
        for text in ("Evidence successful: no", "process disappeared", "attached process lifetime is unknown",
                     "No exact samples; no quantiles.", "Incomplete tail"):
            self.assertIn(text, visible)
        self.assertIn("Attached process and cgroup lifetime peaks are unavailable", visible)
        self.assertNotIn("Lifetime high-water mark includes setup", visible)
        peaks = [row for row in rows if row["metric"] == "process_peak_rss_bytes"]
        self.assertTrue(all(row["samples"] == "0" and row["p99"] == "" for row in peaks))
        self.assertTrue(any(row["outcome"] == "error" for row in rows))

    def test_untrusted_declarations_are_escaped_without_active_content(self):
        metadata = provenance()
        metadata["node_profile"]["workload"]["description"] = '<img src="x" onerror="alert(1)">'
        metadata["node_profile"]["binary_path"] = '<script>alert(2)</script>'
        page, _ = self.render([record("1", {"rss_current_bytes": 1})], metadata=metadata)
        self.assertIn("&lt;img", page)
        self.assertIn("&lt;script", page)
        self.assertNotIn("img", Tags(page).tags)
        self.assertNotIn("script", Tags(page).tags)

    def test_saved_resource_metrics_do_not_imply_registered_node_collection(self):
        page, _ = self.render([record("1", {"rss_current_bytes": 1})])
        self.assertNotIn('id="node-scope"', page)
        self.assertNotIn('id="node-overview"', page)
        self.assertIn("Current RSS", page)


if __name__ == "__main__":
    unittest.main()
