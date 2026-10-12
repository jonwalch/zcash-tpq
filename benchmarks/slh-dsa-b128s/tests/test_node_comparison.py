"""End-to-end saved node comparison checks, with mocked builds and observations."""

import argparse
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import node_run
import provenance
import results
import run
import test_node_build as build_tests


class NodeComparisonTests(unittest.TestCase):
    def setUp(self):
        self.build_fixture = build_tests.NodeBuildTests()
        self.build_fixture.setUp()
        self.addCleanup(self.build_fixture.doCleanups)
        self.runner = self.build_fixture.fixture
        self.root = self.runner.root

    def plan(self, name, kind="node-default", **build_options):
        self.build_fixture.build(name, kind=kind, **build_options)
        profile = self.build_fixture.registered(name)["node_profile"]
        provenance.atomic_json(self.root / "profile.json", profile)
        return self.runner.plan(name + "-run")

    def report(self, name, manifest):
        with patch.object(self.runner, "binary", Path(manifest["node_profile"]["binary_path"])):
            self.runner.execute_fixture(manifest, name=name + "-run")
        run.summarize_run(argparse.Namespace(directory=str(self.root / (name + "-run")),
                                            output=str(self.root / (name + "-report")), process_id=None))
        return provenance.read_json(self.root / (name + "-report/summary.json"))

    def test_default_and_slh_plan_report_and_compare_with_visible_build_variants(self):
        default = self.plan("default")
        slh = self.plan("slh", "node-slh")
        self.assertNotEqual(default["node_identity"]["binary_sha256"], slh["node_identity"]["binary_sha256"])
        self.assertEqual(default["configuration_id"], slh["configuration_id"])
        self.assertEqual(default["node_comparison_version"], 2)
        left, right = self.report("default", default), self.report("slh", slh)
        for name, kind in (("default", "node-default"), ("slh", "node-slh")):
            page = (self.root / (name + "-report/report.html")).read_text()
            self.assertIn("Build variant:</b> " + kind, page)
            self.assertIn("Full request allowances:", page)
            self.assertIn("Hard timeout cannot cover", page)
        self.assertEqual(left["compatibility"], right["compatibility"])
        self.assertNotIn("build", left["compatibility"]["node_collection"])
        comparison = results.compare_summaries(left, right)
        self.assertEqual(comparison["node_builds"], {
            "left": {"kind": "node-default", "features": ["default-release-binaries"]},
            "right": {"kind": "node-slh", "features": ["default-release-binaries", "experimental-slh-dsa-b128s"]},
        })
        self.assertTrue(comparison["groups"])
        self.assertEqual(comparison["groups"][0]["configuration_id"], default["configuration_id"])
        results.compare_summaries(left, left)
        results.compare_summaries(right, right)

    def test_cross_build_comparison_still_rejects_different_compiler_and_observation_conditions(self):
        baseline = self.plan("baseline")
        optimized = self.plan("optimized", "node-slh", opt="0")
        left, right = self.report("baseline", baseline), self.report("optimized", optimized)
        self.assertEqual(baseline["configuration_id"], optimized["configuration_id"])
        with self.assertRaisesRegex(results.ValidationError, "incompatible"):
            results.compare_summaries(left, right)
        for field in ("config_sha256", "workload", "resources"):
            changed = copy.deepcopy(left)
            identity = changed["compatibility"]["node_collection"]
            if field == "config_sha256":
                identity[field] = "f" * 64
            elif field == "workload":
                identity[field]["activity"] = "different load"
            else:
                identity[field]["cgroup"] = True
            with self.subTest(field=field), self.assertRaisesRegex(results.ValidationError, "incompatible"):
                results.compare_summaries(left, changed)
        changed = copy.deepcopy(left)
        changed["compatibility"]["toolchain"]["workspace_manifest_profiles"] = {"release": {"lto": "thin"}}
        with self.assertRaisesRegex(results.ValidationError, "incompatible"):
            results.compare_summaries(left, changed)

    def test_new_comparison_requires_complete_toolchain_and_valid_build_variant(self):
        summary = self.report("one", self.plan("one"))
        for provenance_value in (None, [], "invalid"):
            changed = copy.deepcopy(summary)
            changed["provenance"] = provenance_value
            with self.subTest(provenance=provenance_value), self.assertRaisesRegex(results.ValidationError, "build-time toolchain"):
                results.compare_summaries(changed, changed)
        for variant in (None, {}, {"kind": "node-default", "features": ["experimental-slh-dsa-b128s"]},
                        {"kind": "unknown", "features": []}):
            changed = copy.deepcopy(summary)
            changed["provenance"]["node_build"] = variant
            with self.subTest(variant=variant), self.assertRaisesRegex(results.ValidationError, "build-time toolchain"):
                results.compare_summaries(changed, changed)
        for compiler in (None, {}, {**summary["compatibility"]["toolchain"], "workspace_manifest_profiles": None}):
            changed = copy.deepcopy(summary)
            changed["compatibility"]["toolchain"] = compiler
            with self.subTest(compiler=compiler), self.assertRaisesRegex(results.ValidationError, "build-time toolchain"):
                results.compare_summaries(changed, changed)

    def test_historical_plan_and_configuration_identity_are_preserved(self):
        manifest = self.plan("historical")
        manifest.pop("node_comparison_version")
        expected = provenance.digest_value({"settings": manifest["settings"], "node": node_run.node_compatibility(manifest)})
        manifest["configuration_id"] = expected
        provenance.atomic_json(self.root / "historical-run/manifest.json", manifest)
        summary = self.report("historical", manifest)
        self.assertIn("build", summary["compatibility"]["node_collection"])
        self.assertNotIn("comparison_identity_version", summary["compatibility"]["node_collection"])
        self.assertTrue(all(group["configuration_id"] == expected for group in summary["groups"]))
        results.compare_summaries(summary, summary)

    def test_complete_profile_metadata_is_stored_once_with_depth_headroom(self):
        (self.root / "Cargo.toml").write_text('[profile.release.package."*"]\ndebug = 1\n')
        manifest = self.plan("profile")
        metadata = {**run.compatibility_metadata(manifest), "node_collection": node_run.node_compatibility(manifest)}
        results._bounded_json(metadata)
        self.assertNotIn("build", metadata["node_collection"])
        self.assertEqual(metadata["toolchain"]["workspace_manifest_profiles"], {"release": {"package": {"*": {"debug": 1}}}})
        # One more report-level container still fits; the old duplicate reached
        # the depth limit before this wrapper was present.
        results._bounded_json({"comparison": metadata})


if __name__ == "__main__":
    unittest.main()
