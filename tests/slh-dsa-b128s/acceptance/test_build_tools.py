"""Offline recipe/receipt tests; no Cargo, wallet process or proof execution."""
import copy
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import build
import common


class ToolBuildTests(unittest.TestCase):
    def message(self, artifact):
        return {"reason": "compiler-artifact", "target": {
            "name": "zakura_pq_wallet", "kind": ["lib"],
            "src_path": str(common.ROOT / "crates/pq-wallet/src/lib.rs")},
            "profile": {"test": True}, "executable": str(artifact)}

    def test_new_kinds_have_exact_features_and_fault_tests_never_execute(self):
        for kind, features in (("host-shielded", ["shielded-fixtures"]),
                               ("wallet-faults", [common.FEATURE])):
            argv, name, selected = build.command(kind, Path("/private/target"))
            self.assertEqual(selected, features)
            self.assertIn("--locked", argv)
            self.assertIn("--no-default-features", argv)
            if kind == "wallet-faults":
                self.assertEqual(name, "wallet-fault-tests")
                self.assertEqual(argv[1], "test")
                self.assertIn("--no-run", argv)
                self.assertIn("--lib", argv)
                self.assertIn("--message-format=json", argv)
            record = {"schema_version": 1, "contract": common.CONTRACT, "kind": kind,
                      "complete": True, "source": {}, "command": argv, "features": features,
                      "binary_sha256": "11" * 32, "identity": None,
                      "rustc": "rustc", "cargo": "cargo", "environment": {}}
            with patch.object(common, "source_state", return_value={}), \
                    patch.object(common, "sha256", return_value="11" * 32):
                common.validate_build(record, Path(name), kind)
                for change in ({"features": []}, {"command": argv + ["--ignored"]},
                               {"identity": common.identity_expected(True, True)}):
                    with self.assertRaises(common.AcceptanceError):
                        common.validate_build(dict(record, **change), Path(name), kind)

    def test_exact_artifact_selection_refuses_ambiguous_or_foreign_executables(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "target"
            deps = target / "release/deps"
            deps.mkdir(parents=True)
            artifact = deps / "zakura_pq_wallet-abcdef"
            artifact.write_bytes(b"mock executable")
            messages = root / "messages"
            valid = self.message(artifact)
            messages.write_bytes(common.canonical(valid) + b"\n")
            self.assertEqual(build.wallet_test_artifact(messages, target), artifact)
            controls = [[], [valid, valid]]
            for section, field, value in (("target", "name", "another"),
                                          ("target", "kind", ["bin"]),
                                          ("target", "src_path", "/other/src/lib.rs"),
                                          ("profile", "test", 1)):
                changed = copy.deepcopy(valid)
                changed[section][field] = value
                controls.append([changed])
            for path in (root / artifact.name, deps / "unrelated", artifact / ".." / artifact.name):
                controls.append([dict(valid, executable=str(path))])
            for rows in controls:
                messages.write_bytes(b"".join(common.canonical(row) + b"\n" for row in rows))
                with self.assertRaises(common.AcceptanceError):
                    build.wallet_test_artifact(messages, target)
            artifact.unlink()
            other = root / "other"
            other.write_bytes(b"foreign")
            artifact.symlink_to(other)
            messages.write_bytes(common.canonical(valid) + b"\n")
            with self.assertRaises(common.AcceptanceError):
                build.wallet_test_artifact(messages, target)
            messages.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaises(common.AcceptanceError):
                build.wallet_test_artifact(messages, target)

    def test_mock_build_copies_selected_test_without_running_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(kind="wallet-faults", artifacts=Path(temporary) / "build")
            def cargo(argv, **kwargs):
                target = Path(argv[argv.index("--target-dir") + 1]) / "release/deps"
                target.mkdir(parents=True)
                artifact = target / "zakura_pq_wallet-abcd"
                artifact.write_bytes(b"mock wallet test")
                kwargs["stdout"].write(common.canonical(self.message(artifact)) + b"\n")
            with patch.object(build, "source_state", return_value={}), \
                    patch.object(build.subprocess, "check_output", return_value="toolchain"), \
                    patch.object(build.subprocess, "run", side_effect=cargo) as process, \
                    patch.dict(os.environ, {"CARGO_BUILD_TARGET": ""}), \
                    patch("sys.stdout", io.StringIO()):
                build.build(args)
            self.assertEqual(process.call_count, 1)
            record = common.read_json(args.artifacts / "build.json")
            self.assertIs(record["complete"], True)
            binary = args.artifacts / "wallet-fault-tests"
            self.assertEqual(binary.read_bytes(), b"mock wallet test")
            self.assertEqual(record["binary_sha256"], common.sha256(binary))

    def test_foreign_build_target_leaves_incomplete_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(kind="wallet-faults", artifacts=Path(temporary) / "build")
            with patch.object(build, "source_state", return_value={}), \
                    patch.object(build.subprocess, "check_output", return_value="toolchain"), \
                    patch.object(build.subprocess, "run") as process, \
                    patch.dict(os.environ, {"CARGO_BUILD_TARGET": "foreign-target"}):
                with self.assertRaisesRegex(common.AcceptanceError, "native_build_target_required"):
                    build.build(args)
            process.assert_not_called()
            self.assertIs(common.read_json(args.artifacts / "build.json")["complete"], False)


if __name__ == "__main__":
    unittest.main()
