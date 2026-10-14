"""Exercise the benchmark snapshot guards with a fake binary, without a node."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = (
    "scripts/checkpoint-sync-bench.sh",
    "deploy/runner/feed_run.sh",
)


class SnapshotPreflightTests(unittest.TestCase):
    def test_binary_must_read_the_restored_tip(self):
        cases = (
            ("log line\n1800000\n", 0, "1800000", True),
            ("1800000\n", 0, "", True),
            ("error: incompatible transaction indexes\n", 0, "", False),
            ("", 0, "", False),
            ("0\n", 0, "", False),
            ("1800000\n1800001\n", 0, "", False),
            ("1800000\n", 1, "1800000", False),
            ("1800001\n", 0, "1800000", False),
        )
        with tempfile.TemporaryDirectory(prefix="snapshot preflight ") as tmp:
            directory = Path(tmp)
            binary = directory / "fake node"
            binary.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$@" > "$ARG_LOG"\n'
                'printf "%s" "$REPLY"\nexit "$STATUS"\n'
            )
            binary.chmod(0o755)
            arg_log = directory / "arguments"
            for script in SCRIPTS:
                source = (ROOT / script).read_text()
                guard = re.search(r"^check_snapshot_height\(\) \{\n.*?^\}", source, re.M | re.S)
                self.assertIsNotNone(guard)
                for reply, status, expected, accepted in cases:
                    with self.subTest(script=script, reply=reply, status=status, expected=expected):
                        # Extract the actual guard so wrapper setup, process cleanup,
                        # builds, downloads, and node starts cannot run in this test.
                        # The timeout shim preserves its arguments on macOS too.
                        shell = (
                            'timeout() { [ "$1" = 120 ] || return 99; shift; "$@"; }\n'
                            + guard[0]
                            + '\ncheck_snapshot_height "$@"\n'
                        )
                        result = subprocess.run(
                            ["bash", "-c", shell, "test", str(binary), "cache path", "config path", expected],
                            env={**os.environ, "REPLY": reply, "STATUS": str(status), "ARG_LOG": str(arg_log)},
                            text=True,
                            capture_output=True,
                            timeout=5,
                            check=False,
                        )
                        self.assertEqual(result.returncode == 0, accepted, result.stderr)
                        self.assertEqual(
                            arg_log.read_text().splitlines(),
                            ["-c", "config path", "tip-height", "--cache-dir", "cache path", "--network", "Mainnet"],
                        )


if __name__ == "__main__":
    unittest.main()
