"""Synthetic filesystem checks. No live process or resource measurement."""

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collectors
from results import validate_record


CONTEXT = dict(run_id="unit", case_id="resource", configuration_id="fixture", process_id="test",
               attempt_id="attempt", phase="measure", cache_mode="warm", warmup=False)


def clock_at(value):
    values = iter((value, value + 100))
    return lambda: next(values)


def stat(pid=71, user=100, system=50, start=42):
    fields = ["S"] + ["0"] * 21
    fields[11], fields[12], fields[19] = str(user), str(system), str(start)
    return f"{pid} (name with ) parentheses) " + " ".join(fields)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def process(self, *, user=100, system=50, start=42, rss=400, peak=500, at=0):
        self.write("proc/71/stat", stat(user=user, system=system, start=start))
        self.write("proc/71/status", f"VmRSS:\t{rss} kB\nVmHWM:\t{peak} kB\nCpus_allowed_list:\t0-3,8\n")
        self.write("proc/sys/kernel/random/boot_id", "fake-boot-identity\n")
        return collectors.read_process(71, proc_root=self.root / "proc", clock=clock_at(at), clock_ticks=100)

    def cgroup(self, *, cpu=1000, user=700, system=300, throttle=100, current=100, peak=200, at=0):
        self.write("cgroup/parent/job/cpu.stat", f"usage_usec {cpu}\nuser_usec {user}\nsystem_usec {system}\nthrottled_usec {throttle}\nnr_periods 10\nnr_throttled 2\n")
        self.write("cgroup/parent/job/memory.current", str(current))
        self.write("cgroup/parent/job/memory.peak", str(peak))
        self.write("cgroup/parent/job/cpuset.cpus.effective", "0-3\n")
        self.write("cgroup/parent/job/cpu.max", "200000 100000\n")
        self.write("cgroup/parent/cpu.max", "150000 100000\n")
        return collectors.read_cgroup(self.root / "cgroup/parent/job", boundary=self.root / "cgroup", clock=clock_at(at))

    def interface(self, *, rx=500, tx=1000, index=3, at=0, isolated=True):
        self.write("sys/class/net/veth-test/ifindex", str(index))
        self.write("sys/class/net/veth-test/statistics/rx_bytes", str(rx))
        self.write("sys/class/net/veth-test/statistics/tx_bytes", str(tx))
        return collectors.read_interface("veth-test", sys_root=self.root / "sys", namespace_id="fixture-netns",
                                         isolated=isolated, clock=clock_at(at))

    def record(self, first, second, **kwargs):
        record = collectors.resource_record(first, second, CONTEXT, **kwargs)
        return validate_record(record)

    def test_process_stat_names_and_units(self):
        sample = self.process()
        self.assertEqual(sample["metrics"]["process_cpu_ns"], 1_500_000_000)
        self.assertEqual(sample["metrics"]["rss_current_bytes"], 400 * 1024)
        self.assertEqual(sample["identity"]["start_ticks"], 42)
        self.assertEqual(sample["details"]["affinity_cores"], 5)
        self.assertEqual((sample["window_start_ns"], sample["window_end_ns"]), (0, 100))

    def test_process_cpu_rate_and_lifetime_peak(self):
        first = self.process()
        second = self.process(user=250, system=100, rss=450, peak=550, at=1_000_000_000)
        record = self.record(first, second, fresh_process=True, effective_cpu_cores=2)
        self.assertEqual(record["metrics"]["process_cpu_ns"], 2_000_000_000)
        self.assertEqual(record["metrics"]["process_cpu_core_equivalents"], 2)
        self.assertEqual(record["metrics"]["process_cpu_normalized_percent"], 100)
        self.assertEqual(record["metrics"]["process_peak_rss_bytes"], 550 * 1024)
        self.assertEqual(record["metrics"]["rss_before_bytes"], 400 * 1024)

    def test_peak_and_normalized_cpu_not_invented(self):
        record = self.record(self.process(), self.process(at=1_000_000_000))
        self.assertIsNone(record["metrics"]["process_peak_rss_bytes"])
        self.assertIsNone(record["metrics"]["process_cpu_normalized_percent"])
        self.assertIn("fresh", record["unavailable"]["process_peak_rss_bytes"])

    def test_affinity_caps_supplied_quota_entitlement(self):
        record = self.record(self.process(), self.process(at=1_000_000_000), effective_cpu_cores=20)
        self.assertEqual(record["metrics"]["effective_cpu_cores"], 5)

    def test_missing_process_stays_unavailable(self):
        first = collectors.read_process(9, proc_root=self.root, clock=clock_at(0))
        second = collectors.read_process(9, proc_root=self.root, clock=clock_at(1000))
        record = self.record(first, second)
        self.assertIsNone(record["metrics"]["process_cpu_ns"])
        self.assertIsNone(record["metrics"]["rss_current_bytes"])

    def test_pid_reuse_and_reboot_rejected(self):
        first = self.process()
        second = self.process(start=43, at=1000)
        with self.assertRaisesRegex(collectors.CollectionError, "identity changed"):
            self.record(first, second)
        second = self.process(at=1000)
        second["identity"]["boot_id"] = "other-boot"
        with self.assertRaisesRegex(collectors.CollectionError, "identity changed"):
            self.record(first, second)

    def test_process_counter_and_peak_resets_rejected(self):
        first = self.process()
        for second in (self.process(user=99, at=1000), self.process(peak=499, at=1000)):
            with self.assertRaisesRegex(collectors.CollectionError, "reset"):
                self.record(first, second)

    def test_pid_reuse_during_collection_rejected(self):
        self.process()
        original = collectors._read
        seen = []

        def read(path):
            if path.name == "stat":
                seen.append(path)
                return stat(start=len(seen)), None
            return original(path)

        with mock.patch.object(collectors, "_read", side_effect=read):
            with self.assertRaisesRegex(collectors.CollectionError, "reused"):
                collectors.read_process(71, proc_root=self.root / "proc", clock=clock_at(0), clock_ticks=100)

    def test_missing_boot_id_prevents_cpu_interval(self):
        self.process()
        (self.root / "proc/sys/kernel/random/boot_id").unlink()
        first = collectors.read_process(71, proc_root=self.root / "proc", clock=clock_at(0), clock_ticks=100)
        second = collectors.read_process(71, proc_root=self.root / "proc", clock=clock_at(1000), clock_ticks=100)
        self.assertIsNone(self.record(first, second)["metrics"]["process_cpu_ns"])

    def test_malformed_status_and_stat_rejected(self):
        self.process()
        self.write("proc/71/status", "VmRSS: 4 MB\n")
        with self.assertRaisesRegex(collectors.CollectionError, "malformed VmRSS"):
            collectors.read_process(71, proc_root=self.root / "proc", clock=clock_at(0), clock_ticks=100)
        self.write("proc/71/stat", "71 (missing) S 1")
        with self.assertRaisesRegex(collectors.CollectionError, "short"):
            collectors.read_process(71, proc_root=self.root / "proc", clock=clock_at(0), clock_ticks=100)

    def test_cgroup_quota_ancestors_and_units(self):
        first = self.cgroup()
        self.assertEqual(first["metrics"]["effective_cpu_cores"], 1.5)
        second = self.cgroup(cpu=1_501_000, user=1_000_700, system=500_300, throttle=1100, peak=250, at=1_000_000_000)
        record = self.record(first, second, fresh_cgroup=True)
        self.assertEqual(record["metrics"]["cgroup_cpu_ns"], 1_500_000_000)
        self.assertEqual(record["metrics"]["cgroup_cpu_normalized_percent"], 100)
        self.assertEqual(record["metrics"]["cgroup_throttled_ns"], 1_000_000)
        self.assertEqual(record["metrics"]["cgroup_memory_peak_bytes"], 250)

    def test_cgroup_without_boundary_keeps_entitlement_unknown(self):
        self.cgroup()
        sample = collectors.read_cgroup(self.root / "cgroup/parent/job", clock=clock_at(0))
        self.assertIsNone(sample["metrics"]["effective_cpu_cores"])
        self.assertIn("ancestor", sample["unavailable"]["effective_cpu_cores"])

    def test_cgroup_missing_quota_and_memory_peak_not_zero(self):
        self.cgroup()
        (self.root / "cgroup/parent/cpu.max").unlink()
        (self.root / "cgroup/parent/job/memory.peak").unlink()
        sample = collectors.read_cgroup(self.root / "cgroup/parent/job", boundary=self.root / "cgroup", clock=clock_at(0))
        self.assertIsNone(sample["metrics"]["effective_cpu_cores"])
        self.assertIsNone(sample["metrics"]["cgroup_memory_peak_bytes"])

    def test_cgroup_changed_entitlement_rejected(self):
        first = self.cgroup()
        second = self.cgroup(at=1000)
        second["metrics"]["effective_cpu_cores"] = 2
        with self.assertRaisesRegex(collectors.CollectionError, "entitlement changed"):
            self.record(first, second)

    def test_cgroup_malformed_quota_and_duplicate_counter_rejected(self):
        self.cgroup()
        self.write("cgroup/parent/job/cpu.max", "20 0")
        with self.assertRaisesRegex(collectors.CollectionError, "period is zero"):
            collectors.read_cgroup(self.root / "cgroup/parent/job", boundary=self.root / "cgroup", clock=clock_at(0))
        self.write("cgroup/parent/job/cpu.stat", "usage_usec 1\nusage_usec 2\n")
        with self.assertRaisesRegex(collectors.CollectionError, "duplicate"):
            collectors.read_cgroup(self.root / "cgroup/parent/job", clock=clock_at(0))

    def test_cgroup_boundary_must_contain_subject(self):
        self.cgroup()
        with self.assertRaisesRegex(collectors.CollectionError, "outside"):
            collectors.read_cgroup(self.root / "cgroup/parent/job", boundary=self.root / "different", clock=clock_at(0))

    def test_interface_interval_rates(self):
        record = self.record(self.interface(), self.interface(rx=2500, tx=5000, at=2_000_000_000))
        self.assertEqual(record["metrics"]["interface_rx_bytes"], 2000)
        self.assertEqual(record["metrics"]["interface_tx_bytes_per_second"], 2000)

    def test_nonisolated_interface_unavailable(self):
        record = self.record(self.interface(isolated=False), self.interface(isolated=False, at=1000))
        self.assertIsNone(record["metrics"]["interface_rx_bytes"])
        self.assertIn("isolation", record["unavailable"]["interface_rx_bytes"])

    def test_interface_identity_and_counter_reset(self):
        first = self.interface()
        for second in (self.interface(index=4, at=1000), self.interface(rx=1, at=1000)):
            with self.assertRaises(collectors.CollectionError):
                self.record(first, second)

    def test_interface_name_rejects_traversal(self):
        with self.assertRaises(collectors.CollectionError):
            collectors.read_interface("../../foo", sys_root=self.root)

    def test_window_overlap_and_reversed_clock_rejected(self):
        first = self.process()
        second = self.process(at=50)
        with self.assertRaisesRegex(collectors.CollectionError, "overlap"):
            self.record(first, second)
        with self.assertRaisesRegex(collectors.CollectionError, "backwards"):
            values = iter((20, 10))
            collectors.read_process(71, proc_root=self.root / "proc", clock=lambda: next(values), clock_ticks=100)

    def test_large_monotonic_epochs_preserve_rate_intervals(self):
        first = self.interface(at=10**18)
        second = self.interface(rx=501, at=10**18 + 1001)
        record = self.record(first, second)
        self.assertEqual(record["details"]["rate_interval_ns"], 1001)
        self.assertEqual(record["metrics"]["interface_rx_bytes_per_second"], 1_000_000_000 / 1001)

    def test_affinity_change_cannot_report_normalized_cpu(self):
        first, second = self.process(), self.process(at=1000)
        second["details"]["affinity_cores"] = 4
        with self.assertRaisesRegex(collectors.CollectionError, "affinity changed"):
            self.record(first, second, effective_cpu_cores=4)

    def test_cpuset_rejects_ambiguous_lists_without_expansion(self):
        self.assertEqual(collectors.cpuset_count("0-999999999"), 1_000_000_000)
        for value in ("", "1,1", "2-1", "0-3,2", "0,,3", "-1", "1-x"):
            with self.subTest(value=value), self.assertRaises(collectors.CollectionError):
                collectors.cpuset_count(value)

    def test_context_and_invalid_entitlement_rejected(self):
        first, second = self.process(), self.process(at=1000)
        for value in (0, -1, float("nan"), True):
            with self.subTest(value=value), self.assertRaises(collectors.CollectionError):
                self.record(first, second, effective_cpu_cores=value)
        with self.assertRaisesRegex(collectors.CollectionError, "context"):
            collectors.resource_record(first, second, {})


if __name__ == "__main__":
    unittest.main()
