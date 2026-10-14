"""Bounded startup-log and release-layout checks; no real nodes or downloads."""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "benchmark-snapshot.py"
SPEC = importlib.util.spec_from_file_location("benchmark_snapshot", SCRIPT)
assert SPEC and SPEC.loader
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


def cache_line(height, name="Zakura"):
    tip = f'Some((block::Hash("abcd"), Height({height})))' if height is not None else "None"
    return f"INFO init: loaded {name} state cache chain_tip={tip}\n"


class SnapshotStartupTests(unittest.TestCase):
    def test_supported_upgrade_and_networks(self):
        # The same startup event follows normal writable migration on each
        # network. No second, hard-coded Mainnet database open is performed.
        for network in ("mainnet", "testnet", "regtest-slh-dsa-b128s-v1-h110-t16-b64"):
            with self.subTest(network=network), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "startup.log"
                path.write_text(
                    f"moved state cache from state/v28/{network} to state/v29/{network}\n"
                    + cache_line(1234)
                )
                self.assertEqual(snapshot.wait_for_snapshot(path, os.getpid(), 1, 1234), 1234)

    def test_actual_startup_event_variants(self):
        for name in ("Zakura", "Zebra"):
            self.assertEqual(snapshot.cached_tip(cache_line(42, name)), 42)
        self.assertEqual(snapshot.cached_tip(cache_line(42).replace("chain_tip", "\x1b[1mchain_tip\x1b[0m")), 42)
        self.assertEqual(snapshot.cached_tip(json.dumps({"fields": {
            "message": "loaded Zakura state cache",
            "chain_tip": 'Some((block::Hash("abcd"), Height(42)))',
        }})), 42)

    def test_peer_and_sync_heights_do_not_prove_snapshot_reuse(self):
        for line in ("peer tip=Height(1800000)", "current_height=Height(1800000)", "1800000"):
            self.assertIsNone(snapshot.cached_tip(line))

    def test_missing_zero_or_malformed_initial_tip_is_rejected(self):
        for line in (cache_line(None), cache_line(0), "loaded Zakura state cache chain_tip=invalid"):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, "nonzero snapshot tip"):
                snapshot.cached_tip(line)

    def test_first_cache_event_cannot_be_replaced_by_later_sync(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "startup.log"
            path.write_text(cache_line(None) + cache_line(1800000))
            with self.assertRaisesRegex(ValueError, "genesis-sync"):
                snapshot.wait_for_snapshot(path, os.getpid(), 1)

    def test_wrong_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "startup.log"
            path.write_text(cache_line(42))
            with self.assertRaisesRegex(ValueError, "differs from expected 43"):
                snapshot.wait_for_snapshot(path, os.getpid(), 1, 43)

    def test_waits_for_migration_and_a_complete_log_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "startup.log"
            path.write_text("migrating database\n")
            writes = [cache_line(42)[:30], cache_line(42)[30:]]

            def finish_migration(_delay):
                with path.open("a") as log:
                    log.write(writes.pop(0))

            with mock.patch.object(snapshot.time, "sleep", side_effect=finish_migration):
                self.assertEqual(snapshot.wait_for_snapshot(path, os.getpid(), 1, 42), 42)
            self.assertFalse(writes)

    def test_wait_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "startup.log"
            path.write_text("migrating database\n")
            with self.assertRaisesRegex(ValueError, "timed out"):
                snapshot.wait_for_snapshot(path, os.getpid(), 0)

    def test_node_exit_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "startup.log"
            path.write_text("database open failed\n")
            with mock.patch.object(snapshot.os, "kill", side_effect=ProcessLookupError), \
                 self.assertRaisesRegex(ValueError, "node exited"):
                snapshot.wait_for_snapshot(path, 1234, 1)

    def test_oversized_log_line_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "startup.log"
            path.write_bytes(b"x" * (snapshot.MAX_LINE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "line exceeds"):
                snapshot.wait_for_snapshot(path, os.getpid(), 1)

    def test_cli_checks_saved_startup_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "startup.log"
            path.write_text(cache_line(42))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "startup", "--log", str(path),
                 "--pid", str(os.getpid()), "--timeout", "1", "--expected-height", "42"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Verified initial snapshot tip: 42", result.stdout)


class ReleaseLayoutTests(unittest.TestCase):
    def test_both_specs_are_checked_before_snapshot_setup(self):
        source = SCRIPT.with_name("checkpoint-sync-bench.sh").read_text()
        # Run only the real preflight call sequence, with all external operations
        # stubbed. No wrapper setup, git fetch, download, build, or node can run.
        preflight = source.split("\nensure_deps\nensure_bench_home\n", 1)[1]
        preflight = preflight.split("\nensure_snapshot\n", 1)[0] + "\nensure_snapshot\n"
        stubs = '''
ensure_source() { :; }
die() { exit 1; }
require_upstream_snapshot_layout() {
  printf 'source:%s\\n' "$1"
  [ "$1" != bad ]
}
python3() {
  printf 'release:%s\\n' "$6"
  [ "$6" != bad ]
}
ensure_snapshot() { echo snapshot; }
'''
        for build in ("source", ""):
            for primary, baseline in (("good", "good"), ("good", "bad"), ("bad", "good"), ("good", "")):
                with self.subTest(build=build, primary=primary, baseline=baseline):
                    result = subprocess.run(
                        ["bash", "-eu", "-o", "pipefail", "-c", stubs + preflight],
                        env={**os.environ, "BUILD_REF": build, "PRIMARY_SPEC": primary,
                             "BASELINE_SPEC": baseline, "SNAPSHOT_CHECK": str(SCRIPT), "GH_REPO": "owner/repo"},
                        capture_output=True, text=True, timeout=5, check=False,
                    )
                    accepted = "bad" not in (primary, baseline)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    lines = result.stdout.splitlines()
                    self.assertEqual("snapshot" in lines, accepted)
                    mode = "source" if build else "release"
                    self.assertEqual(lines[0], f"{mode}:{primary}")
                    if primary != "bad" and baseline:
                        self.assertEqual(lines[1], f"{mode}:{baseline}")

    def test_upstream_release_is_accepted(self):
        with mock.patch.object(snapshot, "urlopen", return_value=io.BytesIO(
            b'pub const STATE_DATABASE_KIND: &str = "state";'
        )) as fetch:
            snapshot.check_release_layout("owner/repo", "v1.2.3")
        self.assertEqual(fetch.call_args.args[0],
                         "https://raw.githubusercontent.com/owner/repo/v1.2.3/crates/zakura-state/src/constants.rs")
        self.assertEqual(fetch.call_args.kwargs, {"timeout": 60})

    def test_fork_or_unknown_release_layout_is_rejected(self):
        for source in (b'pub const STATE_DATABASE_KIND: &str = "state-tpq";', b"unknown layout"):
            with self.subTest(source=source), \
                 mock.patch.object(snapshot, "urlopen", return_value=io.BytesIO(source)), \
                 self.assertRaisesRegex(ValueError, "upstream state/"):
                snapshot.check_release_layout("owner/repo", "v1")

    def test_source_download_failure_is_not_compatibility(self):
        with mock.patch.object(snapshot, "urlopen", side_effect=OSError("download failed")), \
             self.assertRaises(OSError):
            snapshot.check_release_layout("owner/repo", "v1")

    def test_source_size_is_bounded(self):
        with mock.patch.object(snapshot, "urlopen", return_value=io.BytesIO(
            b"x" * (snapshot.MAX_SOURCE_BYTES + 1)
        )), self.assertRaisesRegex(ValueError, "inspection limit"):
            snapshot.check_release_layout("owner/repo", "v1")


if __name__ == "__main__":
    unittest.main()
