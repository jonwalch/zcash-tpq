"""Offline recipe/receipt tests; no Cargo, wallet process or proof execution."""
import copy
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import build
import common
from generate_transactions import FixtureError


class SourceStateTests(unittest.TestCase):
    def git(self, root, *arguments):
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                               "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                               "-C", str(root), *arguments], check=True, capture_output=True,
                              text=True, timeout=30).stdout.strip()

    def checkout(self, root):
        files = {"Cargo.toml": "manifest", "Cargo.lock": "workspace lock",
                 "crates/example.rs": "source", "scripts/check.py": "script",
                 "tests/slh-dsa-b128s/acceptance/example.py": "adapter",
                 "tests/slh-dsa-b128s/fixture-signer/Cargo.lock": "signer lock"}
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        self.git(root, "init", "-q")
        self.commit(root)
        return files

    def commit(self, root):
        self.git(root, "add", "--all")
        self.git(root, "commit", "-qm", "fixture source")

    def test_source_state_accepts_checkout_without_removed_upstream_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = self.checkout(root)
            self.assertFalse((root / "crates/zakurad/tests/common/lightwalletd").exists())
            state = common.source_state(root)
            expected = [{"path": name, "sha256": hashlib.sha256(data.encode()).hexdigest()}
                        for name, data in sorted(files.items()) if Path(name).name != "Cargo.lock"]
            self.assertEqual(state["source_inventory"], expected)
            self.assertEqual(state["source_commit"], self.git(root, "rev-parse", "HEAD"))
            self.assertEqual(state["lock_sha256"], hashlib.sha256(b"workspace lock").hexdigest())
            self.assertEqual(state["fixture_lock_sha256"], hashlib.sha256(b"signer lock").hexdigest())

    def test_source_state_rejects_dirty_inputs_and_binds_committed_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.checkout(root)
            before = common.source_state(root)
            (root / "crates/example.rs").write_text("changed source")
            with self.assertRaisesRegex(common.AcceptanceError, "dirty_build_inputs"):
                common.source_state(root)
            self.commit(root)
            after = common.source_state(root)
            self.assertNotEqual(before["source_commit"], after["source_commit"])
            self.assertNotEqual(before["source_inventory_sha256"], after["source_inventory_sha256"])
            self.assertIn({"path": "crates/example.rs", "sha256": hashlib.sha256(b"changed source").hexdigest()},
                          after["source_inventory"])
            (root / "Cargo.lock").write_text("changed lock")
            with self.assertRaisesRegex(common.AcceptanceError, "dirty_build_inputs"):
                common.source_state(root)

    def test_source_state_rejects_tracked_symlinks_including_removed_upstream_aliases(self):
        aliases = ["crates/alias.rs"] + ["crates/zakurad/tests/common/lightwalletd/proto/" + name
                   for name in ("compact_formats.proto", "service.proto")]
        for name in aliases:
            with self.subTest(path=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.checkout(root)
                link = root / name
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(os.path.relpath(root / "crates/example.rs", link.parent))
                self.commit(root)
                with self.assertRaisesRegex(FixtureError, "source_file"):
                    common.source_state(root)


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
