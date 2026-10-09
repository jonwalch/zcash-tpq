"""Bounded file/Git/mock controls; no compilation, network or live services."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("release_content", Path(__file__).with_name("check.py"))
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class GitFixture:
    def __init__(self, root):
        self.root = root
        self.run("init", "-q")
        self.run("config", "user.name", "Public audit test")
        self.run("config", "user.email", "audit@example.invalid")
        self.write("README.md", "legitimate upstream content\n")
        self.base = self.commit("upstream")

    def run(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.PIPE).decode().strip()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, title):
        self.run("add", ".")
        self.run("commit", "-qm", title)
        return self.run("rev-parse", "HEAD")


class PathTests(unittest.TestCase):
    def test_relative_parent_paths_stay_within_tracked_checkout(self):
        manifest = b'[package]\nname="zakura-pq-wallet"\npublish=false\n[dependencies]\nx={path="../pq-cli"}\n'
        names = {"crates/pq-cli/Cargo.toml"}
        self.assertEqual(audit.manifest_paths("crates/pq-wallet/Cargo.toml", manifest, names, added=True),
                         "zakura-pq-wallet")
        for bad in ("../../../outside", "/private/outside"):
            with self.assertRaises(ValueError):
                audit.manifest_paths("crates/pq-wallet/Cargo.toml", manifest.replace(b"../pq-cli", bad.encode()), names, added=True)

    def test_dev_build_target_and_patch_sources_are_checked(self):
        for section in ("dev-dependencies", "build-dependencies", "target.'cfg(unix)'.dependencies", "patch.crates-io"):
            data = ('[' + section + ']\nx={path="../../outside"}\n').encode()
            with self.subTest(section=section), self.assertRaises(ValueError):
                audit.manifest_paths("crates/wallet/Cargo.toml", data, {}, added=False)
        with self.assertRaisesRegex(ValueError, "research Git"):
            audit.manifest_paths("Cargo.toml", b'[patch.crates-io]\nx={git="https://github.com/jonwalch/zcash-transparent-pq"}', {}, added=False)

    def test_alternate_backend_alias_and_publish_flag_fail(self):
        with self.assertRaisesRegex(ValueError, "renamed alternate"):
            audit.manifest_paths("Cargo.toml", b'[dependencies]\nx={package="ml-dsa",version="1"}', {}, added=False)
        for value in ("true", '[]'):
            with self.assertRaisesRegex(ValueError, "can publish"):
                audit.manifest_paths("Cargo.toml", ('[package]\nname="zakura-pq-wallet"\npublish='+value).encode(), {}, added=True)

    def test_workspace_globs_excludes_and_build_scripts_stay_in_checkout(self):
        names = {"Cargo.toml", "crates/a/Cargo.toml", "build.rs"}
        good = b'[workspace]\nmembers=["crates/*"]\ndefault-members=["crates/a"]\nexclude=["unused/*"]\n[package]\nbuild="build.rs"\n'
        audit.manifest_paths("Cargo.toml", good, names, added=False)
        for field in ("members", "default-members", "exclude"):
            for value in ("../outside", "/private/outside", "C:/outside"):
                data = ('[workspace]\n'+field+'=["'+value+'"]\n').encode()
                with self.subTest(field=field, path=value), self.assertRaises(ValueError):
                    audit.manifest_paths("Cargo.toml", data, names, added=False)
        for value in ("../outside/build.rs", "untracked.rs", "/private/build.rs"):
            with self.subTest(build=value), self.assertRaises(ValueError):
                audit.manifest_paths("Cargo.toml", ('[package]\nbuild="'+value+'"').encode(), names, added=False)

    def test_explicit_cargo_target_arrays_require_tracked_in_repo_sources(self):
        names = {"Cargo.toml", "src/main.rs"}
        for kind in ("bin", "test", "bench", "example"):
            for target in ("src/main.rs", "../outside.rs", "missing.rs", "/private/outside.rs"):
                data = ('[['+kind+']]\nname="public"\npath="'+target+'"\n').encode()
                with self.subTest(kind=kind, target=target):
                    if target == "src/main.rs":
                        audit.manifest_paths("Cargo.toml", data, names, added=False)
                    else:
                        with self.assertRaises(ValueError):
                            audit.manifest_paths("Cargo.toml", data, names, added=False)

    def test_historical_registration_can_precede_source_but_cannot_escape(self):
        names = {"Cargo.toml"}
        for template in ('[workspace]\nmembers=["PATH"]\n',
                         '[[test]]\nname="public"\npath="PATH"\n',
                         '[package]\nbuild="PATH"\n',
                         '[dependencies]\npublic={path="PATH"}\n'):
            registration = template.replace("PATH", "missing").encode()
            with self.subTest(form=template):
                audit.manifest_paths("Cargo.toml", registration, names, added=False, require_tracked_paths=False)
                with self.assertRaises(ValueError):
                    audit.manifest_paths("Cargo.toml", registration, names, added=False)
            for value in ("../outside", "/private/outside", "C:/outside"):
                for tracked in (False, True):
                    with self.subTest(form=template, path=value, require_tracked=tracked), self.assertRaises(ValueError):
                        audit.manifest_paths("Cargo.toml", template.replace("PATH", value).encode(), names,
                                             added=False, require_tracked_paths=tracked)

    def test_archive_and_package_traversal_and_private_files_fail(self):
        for value in ("../secret", "/absolute", "a/../secret", "a\\secret", "a//secret"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                audit.path_name(value)
        for value in ("experiments/private.txt", ".context/secret", "docs/remaining/plan.md", "crates/pq-sqisign/src/lib.rs"):
            with self.assertRaises(ValueError):
                audit.product_path(value)
        audit.product_path("docs/slh-dsa-b128s/protocol.md")
        audit.validate_package_list("crates/pq-wallet/Cargo.toml", ["Cargo.toml.orig", "src/lib.rs"],
                                    {"crates/pq-wallet/src/lib.rs"})
        for listing in (["src/untracked.txt"], ["../secret"], ["Cargo.toml", "Cargo.toml"]):
            with self.assertRaises(ValueError):
                audit.validate_package_list("crates/pq-wallet/Cargo.toml", listing, {})

    def test_cargo_copied_repository_readme_is_bound_to_tracked_source(self):
        audit.validate_package_list("crates/zakura-consensus/Cargo.toml", ["README.md"],
                                    {"README.md"}, {"README.md": "README.md"})
        with self.assertRaises(ValueError):
            audit.validate_package_list("crates/zakura-consensus/Cargo.toml", ["README.md"], {},
                                        {"README.md": "README.md"})


class GitTests(unittest.TestCase):
    def test_deleted_experiment_cannot_hide_in_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            fixture.write("experiments/notes.txt", "must never ship")
            fixture.commit("accidental private import")
            (fixture.root / "experiments/notes.txt").unlink()
            fixture.commit("delete notes")
            with patch.object(audit, "UPSTREAM", fixture.base), self.assertRaises(ValueError):
                audit.history(fixture.root, audit.tree(fixture.root, fixture.base), {"README.md", "experiments/notes.txt"})

    def test_foreign_root_merge_is_rejected_even_with_clean_current_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            main = fixture.run("branch", "--show-current")
            fixture.run("checkout", "-q", "--orphan", "foreign")
            fixture.run("rm", "-q", "-rf", ".")
            fixture.write("foreign.txt", "unrelated repository history")
            fixture.commit("foreign root")
            fixture.run("checkout", "-q", main)
            fixture.run("merge", "-q", "--allow-unrelated-histories", "foreign", "-m", "merge")
            with patch.object(audit, "UPSTREAM", fixture.base), self.assertRaisesRegex(ValueError, "foreign ancestry"):
                audit.history(fixture.root, audit.tree(fixture.root, fixture.base), {"README.md", "foreign.txt"})

    def test_unselected_foreign_ref_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            main = fixture.run("branch", "--show-current")
            fixture.run("checkout", "-q", "--orphan", "private-branch")
            fixture.commit("foreign root")
            fixture.run("checkout", "-q", main)
            with patch.object(audit, "UPSTREAM", fixture.base), self.assertRaisesRegex(ValueError, "unselected ref"):
                audit.other_ref_history(fixture.root)

    def test_actual_archive_matches_tracked_bytes_and_preserves_upstream_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            (fixture.root / "alias.md").symlink_to("README.md")
            fixture.commit("legitimate upstream alias")
            current = audit.tree(fixture.root, "HEAD")
            self.assertEqual(audit.archive(fixture.root, current)["files"], 2)
            audit.verify_paths(fixture.root, current, current, set())
            (fixture.root / "escaped").symlink_to("../outside")
            fixture.commit("external symlink")
            with self.assertRaises(ValueError):
                audit.verify_paths(fixture.root, current, audit.tree(fixture.root, "HEAD"), {"escaped"})

    def test_exact_ledger_rejects_missing_stale_and_unmapped_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            fixture.write("public.txt", "attributable new source")
            fixture.commit("product")
            base, current = audit.tree(fixture.root, fixture.base), audit.tree(fixture.root, "HEAD")
            record = {"schema_version": 1, "upstream": audit.UPSTREAM, "upstream_tree": audit.UPSTREAM_TREE,
                "note": "public test", "history_only": [], "files": [{"path": "public.txt",
                    "sha256": audit.sha(b"attributable new source"), "disposition": "new",
                    "reason": "new bounded adapter", "provenance": ["README.md"]}]}
            audit.validate_ledger(record, base, current, fixture.root)
            for change in ("missing", "stale", "provenance"):
                modified = copy.deepcopy(record)
                if change == "missing": modified["files"] = []
                elif change == "stale": modified["files"][0]["sha256"] = "00" * 32
                else: modified["files"][0]["provenance"] = ["missing.md"]
                with self.subTest(change=change), self.assertRaises(ValueError):
                    audit.validate_ledger(modified, base, current, fixture.root)

    def test_publication_gate_cannot_cover_only_one_step(self):
        current = {".github/workflows/release-binaries.yml": ("100644", "blob", "fake")}
        condition = "        if: ${{ !inputs.stage_release_assets && (github.repository == 'zakura-core/zakura' || " + audit.PUBLICATION_GATE + ") }}\n"
        text = "".join("      - name: " + step + "\n" + condition for step in ("Ensure release exists", "Upload assets to release"))
        with patch.object(audit, "blob", return_value=text.encode()):
            audit.publication_guard(Path("."), current)
        changed = text.replace(audit.PUBLICATION_GATE, "true", 1)
        with patch.object(audit, "blob", return_value=changed.encode()), self.assertRaises(ValueError):
            audit.publication_guard(Path("."), current)


if __name__ == "__main__":
    unittest.main()
