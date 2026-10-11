"""Bounded file/Git/mock controls; no compilation, network or live services."""
import copy
import importlib.util
from pathlib import Path
import re
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
        for bad, reason in (("../../../outside", "dependency escapes checkout"),
                            ("/private/outside", "absolute or invalid dependency path")):
            with self.subTest(path=bad), self.assertRaisesRegex(ValueError, reason):
                audit.manifest_paths("crates/pq-wallet/Cargo.toml", manifest.replace(b"../pq-cli", bad.encode()), names, added=True)

    def test_dev_build_target_and_patch_sources_are_checked(self):
        dependency = "untracked/outside dependency: outside/Cargo.toml"
        for section, untracked in (("dev-dependencies", dependency), ("build-dependencies", dependency),
                                   ("target.'cfg(unix)'.dependencies", dependency),
                                   ("patch.crates-io", "manifest path missing: outside")):
            def data(value):
                return ('[' + section + ']\nx={path="' + value + '"}\n').encode()
            with self.subTest(section=section):
                audit.manifest_paths("crates/wallet/Cargo.toml", data("../pq-cli"), {"crates/pq-cli/Cargo.toml"}, added=False)
                # From crates/wallet, ../../outside stays in the checkout but is untracked.
                with self.assertRaisesRegex(ValueError, re.escape(untracked) + "$"):
                    audit.manifest_paths("crates/wallet/Cargo.toml", data("../../outside"), {}, added=False)
                with self.assertRaisesRegex(ValueError, "dependency escapes checkout"):
                    audit.manifest_paths("crates/wallet/Cargo.toml", data("../../../outside"), {}, added=False,
                                         require_tracked_paths=False)
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
    def refreshed_fixture(self, root):
        fixture = GitFixture(root)
        main = fixture.run("branch", "--show-current")
        fixture.write("product.txt", "attributable product\n")
        fixture.commit("product before upstream refresh")
        fixture.run("checkout", "-qb", "upstream-refresh", fixture.base)
        fixture.write("upstream.txt", "authenticated upstream addition\n")
        upstream = fixture.commit("upstream update")
        fixture.run("checkout", "-q", main)
        return fixture, upstream

    def test_normal_upstream_merge_keeps_original_product_ancestry(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, upstream = self.refreshed_fixture(Path(temporary))
            fixture.run("merge", "-q", "--no-ff", upstream, "-m", "refresh upstream")
            with patch.multiple(audit, UPSTREAM=upstream, FOUNDATION=fixture.base):
                result = audit.history(fixture.root, audit.tree(fixture.root, fixture.base), {"product.txt"})
            self.assertEqual(result["commits"], 2)
            self.assertEqual(result["changed_paths"], 1)
            self.assertEqual(result["inherited_merge_entries"], 1)

    def test_upstream_merge_does_not_exempt_changed_resolution(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, upstream = self.refreshed_fixture(Path(temporary))
            fixture.run("merge", "-q", "--no-ff", "--no-commit", upstream)
            fixture.write("upstream.txt", "different unreviewed merge resolution\n")
            fixture.commit("merge with unrelated edit")
            with patch.multiple(audit, UPSTREAM=upstream, FOUNDATION=fixture.base), \
                    self.assertRaisesRegex(ValueError, "unreviewed historical path"):
                audit.history(fixture.root, audit.tree(fixture.root, fixture.base), {"product.txt"})

    def test_refresh_keeps_deleted_private_side_branch_history_visible(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, upstream = self.refreshed_fixture(Path(temporary))
            main = fixture.run("branch", "--show-current")
            fixture.run("checkout", "-qb", "private-import")
            fixture.write("experiments/notes.txt", "must never ship\n")
            fixture.commit("private import on second parent")
            (fixture.root / "experiments/notes.txt").unlink()
            fixture.commit("delete private import")
            fixture.run("checkout", "-q", main)
            fixture.run("merge", "-q", "--no-ff", "private-import", "-m", "merge clean-looking side branch")
            fixture.run("merge", "-q", "--no-ff", upstream, "-m", "refresh upstream")
            with patch.multiple(audit, UPSTREAM=upstream, FOUNDATION=fixture.base), \
                    self.assertRaisesRegex(ValueError, "private/generated path: experiments/notes.txt"):
                audit.history(fixture.root, audit.tree(fixture.root, fixture.base), {"product.txt", "experiments/notes.txt"})

    def test_second_parent_is_not_upstream_just_because_it_has_same_foundation(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, upstream = self.refreshed_fixture(Path(temporary))
            main = fixture.run("branch", "--show-current")
            fixture.run("checkout", "-qb", "unreviewed", fixture.base)
            fixture.write("unreviewed.txt", "not authenticated upstream\n")
            fixture.commit("unreviewed side branch")
            fixture.run("checkout", "-q", main)
            fixture.run("merge", "-q", "--no-ff", "unreviewed", "-m", "merge side branch")
            fixture.run("merge", "-q", "--no-ff", upstream, "-m", "refresh upstream")
            with patch.multiple(audit, UPSTREAM=upstream, FOUNDATION=fixture.base):
                with self.assertRaisesRegex(ValueError, "unreviewed historical path: unreviewed.txt"):
                    audit.history(fixture.root, audit.tree(fixture.root, fixture.base), {"product.txt"})
                # The side commit itself needs review, so only the merge's own
                # exemption count shows whether its second parent was trusted.
                result = audit.history(fixture.root, audit.tree(fixture.root, fixture.base),
                                       {"product.txt", "unreviewed.txt"})
            self.assertEqual(result["commits"], 4)
            self.assertEqual(result["changed_paths"], 2)
            self.assertEqual(result["inherited_merge_entries"], 1)

    def test_refresh_preserves_unselected_older_worker_and_rejects_its_deleted_notes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, upstream = self.refreshed_fixture(Path(temporary))
            main = fixture.run("branch", "--show-current")
            fixture.run("checkout", "-qb", "older-worker", fixture.base)
            fixture.write("worker.txt", "unpublished public work\n")
            worker = fixture.commit("older worker")
            fixture.run("checkout", "-q", main)
            fixture.run("merge", "-q", "--no-ff", upstream, "-m", "refresh upstream")
            with patch.multiple(audit, UPSTREAM=upstream, FOUNDATION=fixture.base):
                self.assertEqual(audit.other_ref_history(fixture.root)["extra_product_commits"], 1)
            fixture.run("checkout", "-q", "older-worker")
            fixture.write("experiments/notes.txt", "must never ship\n")
            fixture.commit("worker imports notes")
            (fixture.root / "experiments/notes.txt").unlink()
            fixture.commit("worker removes notes")
            fixture.run("checkout", "-q", main)
            with patch.multiple(audit, UPSTREAM=upstream, FOUNDATION=fixture.base), \
                    self.assertRaisesRegex(ValueError, "private/generated path: experiments/notes.txt"):
                audit.other_ref_history(fixture.root)
            self.assertTrue(audit.ancestor(fixture.root, fixture.base, worker))

    def test_baseline_tree_and_integration_requirements_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, upstream = self.refreshed_fixture(Path(temporary))
            pins = {"UPSTREAM": upstream, "UPSTREAM_TREE": fixture.run("rev-parse", upstream + "^{tree}"),
                    "FOUNDATION": fixture.base, "FOUNDATION_TREE": fixture.run("rev-parse", fixture.base + "^{tree}")}
            with patch.multiple(audit, **pins), self.assertRaisesRegex(ValueError, "not integrated"):
                audit.validate_baselines(fixture.root)
            fixture.run("merge", "-q", "--no-ff", upstream, "-m", "refresh upstream")
            with patch.multiple(audit, **pins):
                audit.validate_baselines(fixture.root)
            for key in ("FOUNDATION_TREE", "UPSTREAM_TREE"):
                with patch.multiple(audit, **(pins | {key: "00" * 20})), self.assertRaisesRegex(ValueError, "tree mismatch"):
                    audit.validate_baselines(fixture.root)
            swapped = {"UPSTREAM": pins["FOUNDATION"], "UPSTREAM_TREE": pins["FOUNDATION_TREE"],
                       "FOUNDATION": pins["UPSTREAM"], "FOUNDATION_TREE": pins["UPSTREAM_TREE"]}
            with patch.multiple(audit, **swapped), self.assertRaisesRegex(ValueError, "does not descend"):
                audit.validate_baselines(fixture.root)

    def test_deleted_experiment_cannot_hide_in_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            fixture.write("experiments/notes.txt", "must never ship")
            fixture.commit("accidental private import")
            (fixture.root / "experiments/notes.txt").unlink()
            fixture.commit("delete notes")
            with patch.multiple(audit, UPSTREAM=fixture.base, FOUNDATION=fixture.base), \
                    self.assertRaisesRegex(ValueError, "private/generated path: experiments/notes.txt"):
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
            with patch.multiple(audit, UPSTREAM=fixture.base, FOUNDATION=fixture.base), self.assertRaisesRegex(ValueError, "foreign ancestry"):
                audit.history(fixture.root, audit.tree(fixture.root, fixture.base), {"README.md", "foreign.txt"})

    def test_unselected_foreign_ref_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            main = fixture.run("branch", "--show-current")
            fixture.run("checkout", "-q", "--orphan", "private-branch")
            fixture.commit("foreign root")
            fixture.run("checkout", "-q", main)
            with patch.multiple(audit, UPSTREAM=fixture.base, FOUNDATION=fixture.base), self.assertRaisesRegex(ValueError, "unselected ref"):
                audit.other_ref_history(fixture.root)

    def test_unselected_registration_history_is_bounded_without_requiring_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            main = fixture.run("branch", "--show-current")
            fixture.run("checkout", "-qb", "registration")
            fixture.write("Cargo.toml", '[[test]]\nname="public"\npath="tests/later.rs"\n')
            registration = fixture.commit("register source arriving later")
            fixture.run("checkout", "-q", main)
            with patch.multiple(audit, UPSTREAM=fixture.base, FOUNDATION=fixture.base):
                self.assertEqual(audit.other_ref_history(fixture.root)["extra_product_commits"], 1)
            base = audit.tree(fixture.root, fixture.base)
            state = audit.tree(fixture.root, registration)
            with self.assertRaisesRegex(ValueError, "manifest path missing: tests/later.rs"):
                audit.verify_paths(fixture.root, base, state, {"Cargo.toml"})
            fixture.run("checkout", "-q", "registration")
            fixture.write("Cargo.toml", '[[test]]\nname="public"\npath="../outside.rs"\n')
            fixture.commit("outside path remains forbidden historically")
            fixture.run("checkout", "-q", main)
            with patch.multiple(audit, UPSTREAM=fixture.base, FOUNDATION=fixture.base), \
                    self.assertRaisesRegex(ValueError, "dependency escapes checkout"):
                audit.other_ref_history(fixture.root)

    def test_actual_archive_matches_tracked_bytes_and_preserves_upstream_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            (fixture.root / "alias.md").symlink_to("README.md")
            fixture.commit("legitimate upstream alias")
            current = audit.tree(fixture.root, "HEAD")
            self.assertEqual(audit.archive(fixture.root, current)["files"], 2)
            readme, alias = current["README.md"], current["alias.md"]
            for reason, inventory in (
                    ("archive omits tracked files", dict(current, **{"ghost.txt": readme})),
                    ("archive path inventory", {"README.md": readme}),
                    ("archive bytes differ", dict(current, **{"README.md": ("100644", "blob", alias[2])})),
                    ("archive symlink", dict(current, **{"alias.md": ("120000", "blob", readme[2])})),
                    ("archive member type", dict(current, **{"README.md": ("120000", "blob", readme[2])}))):
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    audit.archive(fixture.root, inventory)
            audit.verify_paths(fixture.root, current, current, set())
            with self.assertRaisesRegex(ValueError, "product symlink/submodule: alias.md"):
                audit.verify_paths(fixture.root, current, current, {"alias.md"})
            # An unchanged inherited symlink to an in-repo untracked path is
            # caught only by the tracked-target check.
            (fixture.root / "dangling.md").symlink_to("untracked.md")
            fixture.commit("symlink to untracked path")
            with self.assertRaisesRegex(ValueError, "symlink target outside tracked tree: dangling.md"):
                audit.verify_paths(fixture.root, current, audit.tree(fixture.root, "HEAD"), set())
            (fixture.root / "dangling.md").unlink()
            (fixture.root / "escaped").symlink_to("../outside")
            fixture.commit("external symlink")
            with self.assertRaisesRegex(ValueError, "dependency escapes checkout"):
                audit.verify_paths(fixture.root, current, audit.tree(fixture.root, "HEAD"), set())

    def test_exact_ledger_rejects_missing_stale_and_unmapped_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GitFixture(Path(temporary))
            fixture.write("public.txt", "attributable new source")
            fixture.commit("product")
            base, current = audit.tree(fixture.root, fixture.base), audit.tree(fixture.root, "HEAD")
            record = {"schema_version": 2, "upstream": audit.UPSTREAM, "upstream_tree": audit.UPSTREAM_TREE,
                "foundation": audit.FOUNDATION, "foundation_tree": audit.FOUNDATION_TREE,
                "note": "public test", "history_only": [], "files": [{"path": "public.txt",
                    "sha256": audit.sha(b"attributable new source"), "disposition": "new",
                    "reason": "new bounded adapter", "provenance": ["README.md"]}]}
            audit.validate_ledger(record, base, current, fixture.root)
            for change in ("missing", "stale", "provenance", "old-schema", "foundation", "upstream", "extra-key"):
                modified = copy.deepcopy(record)
                if change == "missing": modified["files"] = []
                elif change == "stale": modified["files"][0]["sha256"] = "00" * 32
                elif change == "provenance": modified["files"][0]["provenance"] = ["missing.md"]
                elif change == "old-schema": modified["schema_version"] = 1
                elif change in ("foundation", "upstream"): modified[change] = "00" * 20
                else: modified["extra"] = True
                with self.subTest(change=change), self.assertRaises(ValueError):
                    audit.validate_ledger(modified, base, current, fixture.root)

    def test_publication_gate_cannot_cover_only_one_step(self):
        current = {".github/workflows/release-binaries.yml": ("100644", "blob", "fake")}
        steps = ("Ensure release exists", "Upload assets to release")
        def workflow(gated):
            return "".join("      - name: " + step + "\n        if: ${{ !inputs.stage_release_assets && "
                           "(github.repository == 'zakura-core/zakura' || "
                           + (audit.PUBLICATION_GATE if step in gated else "true") + ") }}\n"
                           for step in steps).encode()
        with patch.object(audit, "blob", return_value=workflow(steps)):
            audit.publication_guard(Path("."), current)
        for step in steps:
            with self.subTest(step=step), patch.object(audit, "blob", return_value=workflow(set(steps) - {step})), \
                    self.assertRaisesRegex(ValueError, "publication condition changed: " + step + "$"):
                audit.publication_guard(Path("."), current)


if __name__ == "__main__":
    unittest.main()
