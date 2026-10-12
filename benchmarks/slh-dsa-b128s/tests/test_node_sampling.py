"""Fixture and mocked HTTP checks; no running process, endpoint or profiling."""

import copy
import hashlib
import http.client
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import node_sampling as sampling
from provenance import BenchmarkError
from results import summarize


GAUGES = ("zcash_mempool_size_transactions 3\nzcash_mempool_size_bytes 600\n"
          "zcash_mempool_cost_bytes 900\n")


class Clock:
    def __init__(self):
        self.value = 10_000_000_000

    def __call__(self):
        self.value += 100
        return self.value


class SamplingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.proc = self.root / "proc"
        self.clock = Clock()
        self.binary = self.root / "zakurad"
        self.binary.write_bytes(b"fixture executable, never executed")
        self.config = self.root / "node.toml"
        self.config.write_text('[network]\nnetwork = "Regtest"\n[metrics]\nendpoint_addr = "127.0.0.1:9999"\n')
        self.write("proc/71/cmdline", f"zakurad\0-c\0{self.config}\0start\0".encode())
        (self.proc / "71/exe").symlink_to(self.binary)
        self.write("proc/sys/kernel/random/boot_id", b"fixture-boot\n")
        self.process()
        self.profile = dict(pid=71, process_identity={"start_ticks": 42, "boot_id": "fixture-boot"},
                            binary_path=str(self.binary), config_path=str(self.config),
                            metrics_url="http://127.0.0.1:9999/metrics", cgroup_path=None,
                            cgroup_boundary=None, workload={"id": "fixture"})
        self.manifest = {"node_profile": self.profile, "node_identity": {
            "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "config_sha256": hashlib.sha256(self.config.read_bytes()).hexdigest()},
            "run_id": "test-node", "configuration_id": "fixture", "settings": {
                "samples": 2, "interval_ms": 1000, "timeout_seconds": 30}}
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(sampling, "PROC_ROOT", self.proc).start()
        mock.patch.object(sampling.sys, "platform", "linux").start()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def process(self, *, user=100, start=42, peak=500):
        fields = ["S"] + ["0"] * 21
        fields[11], fields[12], fields[19] = str(user), "50", str(start)
        self.write("proc/71/stat", ("71 (test ) name) " + " ".join(fields)).encode())
        self.write("proc/71/status", f"VmRSS: 400 kB\nVmHWM: {peak} kB\nCpus_allowed_list: 0-3\n".encode())

    def cgroup(self):
        boundary = self.root / "cgroup"
        self.profile.update(cgroup_path=str(boundary / "job"), cgroup_boundary=str(boundary))
        self.write("proc/self/mountinfo", f"36 25 0:32 / {boundary} rw - cgroup2 cgroup rw\n".encode())
        self.write("proc/71/cgroup", b"0::/job/child\n")
        self.write("cgroup/job/cpu.stat", b"usage_usec 3000\nuser_usec 2000\nsystem_usec 1000\nthrottled_usec 0\nnr_throttled 0\n")
        self.write("cgroup/job/memory.current", b"4096")
        self.write("cgroup/job/memory.peak", b"8192")
        self.write("cgroup/job/cpuset.cpus.effective", b"0-3")
        self.write("cgroup/job/cpu.max", b"100000 100000")

    def scrape(self, *args, **kwargs):
        return dict(window_start_ns=self.clock(), window_end_ns=self.clock(), text=GAUGES, error=None)

    def sleep(self, seconds):
        self.clock.value += int(seconds * 1_000_000_000)
        self.process(user=200 + self.clock.value // 1_000_000_000)

    def collect(self, **kwargs):
        frames = []
        with mock.patch.object(sampling, "_scrape", side_effect=self.scrape):
            sampling.collect(self.manifest, frames.append, clock=self.clock,
                             sleep=kwargs.get("sleep", self.sleep))
        return frames

    def test_static_config_never_samples_or_connects(self):
        with mock.patch.object(sampling.collectors, "read_process") as process, \
                mock.patch.object(sampling.http.client, "HTTPConnection") as connection:
            self.assertEqual(sampling.validate_endpoint_config(self.profile), ("127.0.0.1", 9999, "/metrics"))
            process.assert_not_called()
            connection.assert_not_called()

    def test_config_requires_regtest_and_matching_endpoint(self):
        for change in ('network = "Mainnet"', 'network = "Testnet"'):
            with self.subTest(change=change):
                self.config.write_text('[network]\n' + change + '\n[metrics]\nendpoint_addr="127.0.0.1:9999"')
                with self.assertRaisesRegex(BenchmarkError, "Regtest"):
                    sampling.validate_endpoint_config(self.profile)
        self.config.write_text('[network]\nnetwork="Regtest"\n[metrics]\nendpoint_addr="127.0.0.1:9998"')
        with self.assertRaisesRegex(BenchmarkError, "differs"):
            sampling.validate_endpoint_config(self.profile)

    def test_bad_config_tables_and_cli_without_opt_in_fail_before_collection(self):
        self.config.write_text("network=1\nmetrics=[]\n")
        with self.assertRaisesRegex(BenchmarkError, "tables"):
            sampling.validate_endpoint_config(self.profile)
        with mock.patch.object(sys, "argv", ["node_sampling.py", "--manifest", "not-opened.json"]), \
                mock.patch.object(sampling, "collect") as collect, \
                mock.patch.object(sampling, "read_json") as read, mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(sampling.main(), 1)
            collect.assert_not_called()
            read.assert_not_called()

    def test_endpoint_excludes_dns_credentials_and_nonlocal_routing(self):
        invalid = ["https://127.0.0.1:9999/", "http://localhost:9999/", "http://example.com:99/",
                   "http://10.0.0.1:99/", "http://user:pass@127.0.0.1:99/", "http://127.0.0.1/",
                   "http://127.0.0.1:99/?q=1", "http://127.0.0.1:99/#", "http://127.0.0.1:99/?",
                   "http://[::1%lo]:9999/",
                   "http://127.0.0.1:99/private", "http://127.0.0.1:99/\n"]
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(ValueError):
                sampling._endpoint(url)
        self.assertEqual(sampling._endpoint("http://[::1]:9999/"), ("::1", 9999, "/"))

    def test_collect_and_replay_preserve_interval_semantics(self):
        frames = self.collect()
        snapshots = [frame["evidence"] for frame in frames if frame["frame"] == "snapshot"]
        records = [frame["record"] for frame in frames if frame["frame"] == "record"]
        self.assertEqual(len(snapshots), 3)
        self.assertEqual(len(records), 4)
        replayed = [record for index, (left, right) in enumerate(zip(snapshots, snapshots[1:]))
                    for record in sampling.records_from_snapshots(left, right, self.manifest, index)]
        self.assertEqual(records, replayed)
        process, mempool = records[:2]
        self.assertGreater(process["metrics"]["process_cpu_ns"], 0)
        self.assertEqual(process["metrics"]["rss_current_bytes"], 409600)
        self.assertIsNone(process["metrics"]["process_peak_rss_bytes"])
        self.assertIsNone(process["metrics"]["process_cpu_normalized_percent"])
        self.assertIn("fresh subject", process["unavailable"]["process_peak_rss_bytes"])
        self.assertEqual(mempool["metrics"]["mempool_growth_bytes_per_second"], 0)
        self.assertIn("not independently proven", mempool["details"]["endpoint_association"])
        report = summarize(records)
        self.assertEqual(report["record_count"], 4)

    def test_optional_cgroup_is_subtree_accounting_with_no_peak(self):
        self.cgroup()
        frames = self.collect()
        records = [frame["record"] for frame in frames if frame["frame"] == "record"]
        self.assertEqual(len(records), 6)
        cgroup = records[2]
        self.assertEqual(cgroup["phase"], "resource-cgroup")
        self.assertEqual(cgroup["metrics"]["cgroup_cpu_ns"], 0)
        self.assertEqual(cgroup["metrics"]["effective_cpu_cores"], 1)
        self.assertIsNone(cgroup["metrics"]["cgroup_memory_peak_bytes"])
        self.assertIn("descendants", cgroup["details"]["source_details"]["scope"])

    def test_membership_rejects_unrelated_or_ambiguous_cgroup(self):
        self.cgroup()
        self.write("proc/71/cgroup", b"0::/other\n")
        with self.assertRaisesRegex(BenchmarkError, "does not contain"):
            sampling._membership(self.profile)
        self.write("proc/71/cgroup", b"0::/job\n")
        boundary = self.profile["cgroup_boundary"]
        self.write("proc/self/mountinfo", f"36 25 0:32 /subtree {boundary} rw - cgroup2 cgroup rw\n".encode())
        with self.assertRaisesRegex(BenchmarkError, "root mount"):
            sampling._membership(self.profile)

    def test_binding_detects_wrong_binary_config_and_start_command(self):
        baseline = sampling._binding(self.manifest)
        self.assertEqual(baseline["binary_sha256"], self.manifest["node_identity"]["binary_sha256"])
        self.manifest["node_identity"]["binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(BenchmarkError, "hash"):
            sampling._binding(self.manifest)
        self.manifest["node_identity"]["binary_sha256"] = baseline["binary_sha256"]
        self.write("proc/71/cmdline", b"zakurad\0start\0")
        with self.assertRaisesRegex(BenchmarkError, "explicit config"):
            sampling._binding(self.manifest)
        self.write("proc/71/cmdline", f"zakurad\0-c\0{self.config}\0start\0".encode())
        self.config.write_text(self.config.read_text() + "\n# changed\n")
        with self.assertRaisesRegex(BenchmarkError, "config changed"):
            sampling._binding(self.manifest, baseline)

    def test_early_evidence_survives_process_exit(self):
        frames = []

        def exit_subject(seconds):
            self.clock.value += int(seconds * 1_000_000_000)
            (self.proc / "71/stat").unlink()

        with mock.patch.object(sampling, "_scrape", side_effect=self.scrape), \
                self.assertRaisesRegex(BenchmarkError, "exited"):
            sampling.collect(self.manifest, frames.append, clock=self.clock, sleep=exit_subject)
        self.assertEqual(len(frames), 2)
        self.assertIsNone(frames[0]["evidence"]["error"])
        self.assertIn("exited", frames[1]["evidence"]["error"])
        self.assertIsNone(frames[1]["evidence"]["process"]["identity"])

    def test_reused_pid_and_changed_executable_are_fatal(self):
        for change in (lambda: self.process(start=43), lambda: self.binary.write_bytes(b"replacement")):
            with self.subTest(change=change):
                self.process()
                self.binary.write_bytes(b"fixture executable, never executed")
                frames = []

                def mutate(seconds):
                    self.clock.value += int(seconds * 1_000_000_000)
                    change()

                with mock.patch.object(sampling, "_scrape", side_effect=self.scrape), self.assertRaises(BenchmarkError):
                    sampling.collect(self.manifest, frames.append, clock=self.clock, sleep=mutate)
                self.assertEqual(len(frames), 2)
                self.assertIsNotNone(frames[-1]["evidence"]["error"])

    def test_replay_rejects_counter_reset_or_forged_binding(self):
        frames = self.collect()
        before, after = [frame["evidence"] for frame in frames if frame["frame"] == "snapshot"][:2]
        changed = copy.deepcopy(after)
        changed["process"]["metrics"]["process_cpu_ns"] = 0
        with self.assertRaisesRegex(BenchmarkError, "reset"):
            sampling.records_from_snapshots(before, changed, self.manifest, 0)
        changed = copy.deepcopy(after)
        changed["binding"]["binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(BenchmarkError, "registration"):
            sampling.records_from_snapshots(before, changed, self.manifest, 0)

    def test_scrape_errors_preserve_resources_and_never_become_zero(self):
        frames = self.collect()
        before, after = [frame["evidence"] for frame in frames if frame["frame"] == "snapshot"][:2]
        for failed in (before, after):
            pair = copy.deepcopy([before, after])
            target = pair[0] if failed is before else pair[1]
            target["mempool"].update(text=None, error="TimeoutError: fixture timeout")
            process, mempool = sampling.records_from_snapshots(*pair, self.manifest, 0)
            self.assertEqual(process["outcome"], "success")
            self.assertEqual(mempool["outcome"], "error")
            self.assertIsNone(mempool["metrics"]["mempool_growth_bytes_per_second"])
            if failed is after:
                self.assertIsNone(mempool["metrics"]["mempool_bytes"])
            else:
                self.assertEqual(mempool["metrics"]["mempool_bytes"], 600)

    def test_absent_metrics_are_unavailable_and_negative_growth_is_valid(self):
        frames = self.collect()
        before, after = [frame["evidence"] for frame in frames if frame["frame"] == "snapshot"][:2]
        after["mempool"]["text"] = "zcash_mempool_size_transactions 2\nzcash_mempool_size_bytes 500\n"
        record = sampling.records_from_snapshots(before, after, self.manifest, 0)[1]
        self.assertEqual(record["outcome"], "success")
        self.assertLess(record["metrics"]["mempool_growth_bytes_per_second"], 0)
        self.assertIsNone(record["metrics"]["mempool_cost"])
        self.assertIn("absent", record["unavailable"]["mempool_cost"])

    def test_process_replacement_during_scrape_is_retained(self):
        def swap(*args, **kwargs):
            observation = self.scrape()
            self.process(start=43)
            return observation

        frames = []
        with mock.patch.object(sampling, "_scrape", side_effect=swap), self.assertRaisesRegex(BenchmarkError, "during observation"):
            sampling.collect(self.manifest, frames.append, clock=self.clock, sleep=self.sleep)
        self.assertEqual(frames[0]["evidence"]["mempool"]["text"], GAUGES)
        self.assertEqual(frames[0]["evidence"]["process_guard"]["identity"]["start_ticks"], 43)


class HttpTests(unittest.TestCase):
    def scrape(self, *, status=200, body=GAUGES.encode(), headers=None, error=None, chunk_size=None):
        response = mock.Mock()
        response.status = status
        response.getheader.side_effect = lambda name, default=None: (headers or {}).get(name, default)
        chunk_size = chunk_size or len(body) or 1
        response.read1.side_effect = [body[index:index + chunk_size] for index in range(0, len(body), chunk_size)] + [b""]
        connection = mock.Mock()
        connection.getresponse.side_effect = error
        connection.getresponse.return_value = response
        with mock.patch.object(sampling.http.client, "HTTPConnection", return_value=connection) as factory:
            observation = sampling._scrape(("127.0.0.1", 9999, "/metrics"), deadline=100_000_000_000, clock=Clock())
        connection.close.assert_called_once()
        return observation, connection, factory

    def test_plain_http_is_bounded_and_timestamped(self):
        observation, connection, factory = self.scrape(headers={"Content-Length": str(len(GAUGES))}, chunk_size=8)
        self.assertEqual(observation["text"], GAUGES)
        self.assertIsNone(observation["error"])
        self.assertLess(observation["window_start_ns"], observation["window_end_ns"])
        factory.assert_called_once_with("127.0.0.1", 9999, timeout=2)
        connection.request.assert_called_once_with("GET", "/metrics", headers={
            "Accept": "text/plain", "Accept-Encoding": "identity", "Connection": "close"})

    def test_redirect_compression_and_oversize_are_errors(self):
        for options in ({"status": 302}, {"headers": {"Content-Encoding": "gzip"}},
                        {"headers": {"Content-Length": str(sampling.MAX_SCRAPE_BYTES + 1)}},
                        {"body": b"a" * (sampling.MAX_SCRAPE_BYTES + 1)}):
            with self.subTest(options=str(options)[:80]):
                observation, _, _ = self.scrape(**options)
                self.assertIsNotNone(observation["error"])
                self.assertIsNone(observation["text"])

    def test_timeout_truncation_and_malformed_gauges_are_errors(self):
        for options in ({"error": TimeoutError("fixture")}, {"error": http.client.BadStatusLine("fixture")},
                        {"headers": {"Content-Length": str(len(GAUGES) + 1)}},
                        {"body": b"zcash_mempool_size_bytes NaN\n"}):
            with self.subTest(options=options):
                observation, _, _ = self.scrape(**options)
                self.assertIsNotNone(observation["error"])


if __name__ == "__main__":
    unittest.main()
