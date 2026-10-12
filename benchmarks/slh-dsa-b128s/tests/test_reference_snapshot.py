"""Reference snapshots retain checked bytes without executing foreign code."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import provenance


class ReferenceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.metadata = self.root / "metadata"
        self.source = self.root / "source"
        self.destination = self.root / "snapshot"
        self.metadata.mkdir()
        self.source.mkdir()
        files = {"reference": {"slhdsa/lowlevel/slhdsa.py": b"raise RuntimeError('must not execute')\n",
                               "COPYING": b"reference license"},
                 "blake3_c": {"c/blake3.c": b"public hash source", "LICENSE": b"hash license"}}
        pins = {}
        for group, items in files.items():
            pins[group] = {"files": []}
            for name, data in items.items():
                path = self.source / group / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                pins[group]["files"].append({"path": name, "sha256": hashlib.sha256(data).hexdigest()})
        (self.metadata / "sources.json").write_text(json.dumps(pins))
        (self.metadata / "hash_shim.c").write_bytes(b"shim")
        library = self.source / "libslh_reference_blake3.so"
        library.write_bytes(b"not executable; snapshotting must not load it")
        receipt = {"schema_version": 1, "library_name": library.name,
                   "library_sha256": provenance.sha256(library),
                   "sources_sha256": provenance.sha256(self.metadata / "sources.json"),
                   "shim_sha256": provenance.sha256(self.metadata / "hash_shim.c"),
                   "command": ["/historical/compiler", "/historical/input.c"]}
        (self.source / "hash-build.json").write_text(json.dumps(receipt))
        context = patch.object(provenance, "REFERENCE_ROOT", self.metadata)
        context.start()
        self.addCleanup(context.stop)

    def snapshot(self):
        return provenance.snapshot_payment_reference(self.source, self.destination)

    def test_exact_pinned_bytes_and_receipt_are_retained_without_scratch(self):
        expected = provenance.artifact_inventory(self.source)
        (self.source / "scratch.txt").write_text("excluded")
        self.assertEqual(self.snapshot(), self.destination)
        self.assertEqual(provenance.artifact_inventory(self.destination), expected)
        (self.source / "blake3_c/c/blake3.c").write_bytes(b"later mutation")
        self.assertEqual(provenance.artifact_inventory(self.destination), expected)
        with self.assertRaises(FileExistsError):
            # Restore source first, so this checks the no-clobber destination.
            (self.source / "blake3_c/c/blake3.c").write_bytes(b"public hash source")
            self.snapshot()

    def test_changed_source_library_or_build_identity_fails_before_copy(self):
        for name in ("reference/slhdsa/lowlevel/slhdsa.py", "libslh_reference_blake3.so", "hash-build.json"):
            path = self.source / name
            before = path.read_bytes()
            path.write_bytes(b"changed")
            with self.subTest(name=name), self.assertRaises(provenance.BenchmarkError):
                self.snapshot()
            self.assertFalse(self.destination.exists())
            path.write_bytes(before)

    def test_symlink_file_or_parent_is_rejected(self):
        path = self.source / "blake3_c/c/blake3.c"
        original = path.read_bytes()
        target = self.root / "outside"
        target.write_bytes(original)
        path.unlink()
        path.symlink_to(target)
        with self.assertRaisesRegex(provenance.BenchmarkError, "reference symlink"):
            self.snapshot()
        path.unlink()
        path.write_bytes(original)
        parent = path.parent
        moved = self.root / "outside-directory"
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(provenance.BenchmarkError, "reference symlink"):
            self.snapshot()

    def test_unexpected_python_module_is_not_silently_removed(self):
        (self.source / "reference/slhdsa/lowlevel/extra.py").write_text("unexpected")
        with self.assertRaisesRegex(provenance.BenchmarkError, "Python inventory mismatch"):
            self.snapshot()

    def test_copy_bounds_and_library_path_allowlist(self):
        with patch.object(provenance, "MAX_REFERENCE_FILE", 2):
            with self.assertRaisesRegex(provenance.BenchmarkError, "file size limit"):
                self.snapshot()
        with patch.object(provenance, "MAX_REFERENCE_TOTAL", 2):
            with self.assertRaisesRegex(provenance.BenchmarkError, "snapshot size limit"):
                self.snapshot()
        path = self.source / "hash-build.json"
        receipt = json.loads(path.read_text())
        receipt["library_name"] = "../outside.so"
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(provenance.BenchmarkError, "unexpected reference library"):
            self.snapshot()


if __name__ == "__main__":
    unittest.main()
