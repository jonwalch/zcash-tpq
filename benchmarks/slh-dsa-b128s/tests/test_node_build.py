"""Build/compatibility regression fixtures; compiler and build execution are mocked."""

import argparse
import copy
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import node_build
import node_run
import provenance
import results
import run
import test_node_reports as report_tests
import test_node_runner as runner_tests


class NodeBuildTests(unittest.TestCase):
    def setUp(self):
        self.fixture = runner_tests.NodeRunnerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        (self.root / "Cargo.toml").write_text("[workspace]\n")

    @staticmethod
    def compiler_output(argv, root):
        return "unit rustc" if argv[0] == "rustc" else "unit cargo"

    def fake_build(self, argv, **kwargs):
        self.assertEqual(kwargs["root"], self.root)
        self.assertEqual(argv[:5], [sys.executable, str(self.root / "tests/slh-dsa-b128s/acceptance/build.py"),
                                   "--human-run", "--kind", argv[4]])
        directory = Path(argv[-1])
        directory.mkdir()
        (directory / "zakurad").write_bytes(self.fixture.binary.read_bytes())
        acceptance = copy.deepcopy(self.fixture.build)
        acceptance["kind"] = argv[4]
        enabled = acceptance["kind"] == "node-slh"
        if enabled:
            (directory / "zakurad").write_bytes(self.fixture.binary.read_bytes() + b" SLH fixture")
            acceptance["binary_sha256"] = provenance.sha256(directory / "zakurad")
        acceptance["features"] = ["default-release-binaries"] + (["experimental-slh-dsa-b128s"] if enabled else [])
        acceptance["command"][-1] = ",".join(acceptance["features"])
        acceptance["identity"].update(backend="portable-rust" if enabled else "disabled",
                                      verifier_compiled=enabled, runtime_supported=enabled)
        acceptance["command"][10] = str(directory / "target")
        provenance.atomic_json(directory / "build.json", acceptance)
        (directory / "build.log").write_text("mocked compiler output\n")
        kwargs["on_poll"]()
        return {"pid": 100, "exit_code": 0, "elapsed_ns": 1000, "output_bytes": 8}

    def build(self, name="built", *, opt="3", incremental=None, operation=None, kind="node-default"):
        environment = {"CARGO_HOME": str(self.root / "cargo-home"), "CARGO_PROFILE_RELEASE_OPT_LEVEL": opt}
        if incremental is not None:
            environment["CARGO_INCREMENTAL"] = incremental
        with patch.dict(os.environ, environment, clear=True), patch.object(run, "ROOT", self.root), \
                patch.object(provenance, "command_output", side_effect=self.compiler_output) as probes, \
                patch.object(run, "supervise", side_effect=operation or self.fake_build):
            receipt = node_build.build_node(argparse.Namespace(output=str(self.root / name), kind=kind,
                                                              timeout=30, execute=True))
            self.assertEqual(len(probes.call_args_list), 4)
            self.assertTrue(all(call.args[1] == self.root for call in probes.call_args_list))
        return receipt

    def registered(self, name="built"):
        profile = {**self.fixture.profile, "binary_path": str(self.root / name / "acceptance/zakurad"),
                   "build_receipt_path": str(self.root / name / "build.json")}
        build = node_run.node_build(profile)
        return {"node_profile": profile, "build": build, "node_identity": node_run.node_identity(profile, build)}

    def summary(self, manifest):
        summary = results.summarize([report_tests.record("1", {"rss_current_bytes": 1024})], complete=True)
        summary["compatibility"] = {"kind": "node-collection", "node_collection": node_run.node_compatibility(manifest),
                                    "toolchain": provenance.toolchain_compatibility(manifest["build"].get("toolchain"))}
        return summary

    def test_wrapper_reuses_helper_and_retains_unchanged_receipt(self):
        receipt = self.build()
        self.assertTrue(receipt["complete"])
        inner = provenance.read_json(self.root / "built/acceptance/build.json")
        self.assertEqual(set(inner), set(self.fixture.build))
        self.assertEqual(receipt["acceptance_receipt_sha256"], provenance.sha256(self.root / "built/acceptance/build.json"))
        self.assertEqual(receipt["toolchain"], receipt["toolchain_after"])
        registered = self.registered()
        self.assertEqual(registered["build"]["toolchain"], receipt["toolchain"])
        # Offline registration must never infer historical settings from this host.
        with patch.object(node_build, "_capture_toolchain", side_effect=AssertionError("must not probe")):
            self.registered()
        self.build("second")
        results.compare_summaries(self.summary(registered), self.summary(self.registered("second")))

    def test_optimization_levels_cannot_compare(self):
        self.build("opt0", opt="0")
        self.build("opt3", opt="3")
        left, right = (self.summary(self.registered(name)) for name in ("opt0", "opt3"))
        self.assertEqual(left["compatibility"]["toolchain"]["environment"]["CARGO_PROFILE_RELEASE_OPT_LEVEL"], "0")
        with self.assertRaisesRegex(results.ValidationError, "incompatible"):
            results.compare_summaries(left, right)

    def test_workspace_profile_defaults_and_package_overrides_cannot_compare(self):
        variants = (("defaults", '[profile.release]\nopt-level = 0\nlto = false\n',
                                  '[profile.release]\nopt-level = 3\nlto = "thin"\n'),
                    ("package", '[profile.release.package.zakura]\nopt-level = 0\n',
                                 '[profile.release.package.zakura]\nopt-level = 3\n'),
                    ("build-override", '[profile.release.build-override]\nopt-level = 0\n',
                                        '[profile.release.build-override]\nopt-level = 3\n'))
        for name, before, after in variants:
            with self.subTest(name=name):
                (self.root / "Cargo.toml").write_text(before)
                self.build(name + "0")
                (self.root / "Cargo.toml").write_text(after)
                self.build(name + "3")
                left, right = (self.summary(self.registered(name + suffix)) for suffix in ("0", "3"))
                self.assertNotEqual(left["compatibility"]["toolchain"]["workspace_manifest_profiles"],
                                    right["compatibility"]["toolchain"]["workspace_manifest_profiles"])
                with self.assertRaisesRegex(results.ValidationError, "incompatible"):
                    results.compare_summaries(left, right)

    def test_whole_profile_table_is_canonical_and_independent_of_manifest_formatting(self):
        (self.root / "Cargo.toml").write_text('[profile.release]\nopt-level = 3\n[profile.ci]\ninherits = "release"\n')
        first = self.build("first")
        self.assertEqual(first["toolchain"]["workspace_manifest_profiles"],
                         {"release": {"opt-level": 3}, "ci": {"inherits": "release"}})
        (self.root / "Cargo.toml").write_text('# same profiles, different order\n[profile.ci]\ninherits="release"\n'
                                             '[profile.release]\nopt-level=3\n')
        self.build("second")
        results.compare_summaries(self.summary(self.registered("first")), self.summary(self.registered("second")))

    def test_incremental_build_setting_cannot_compare(self):
        self.build("incremental0", incremental="0")
        self.build("incremental1", incremental="1")
        left, right = (self.summary(self.registered(name)) for name in ("incremental0", "incremental1"))
        self.assertEqual(left["compatibility"]["toolchain"]["environment"]["CARGO_INCREMENTAL"], "0")
        self.assertEqual(right["compatibility"]["toolchain"]["environment"]["CARGO_INCREMENTAL"], "1")
        with self.assertRaisesRegex(results.ValidationError, "incompatible"):
            results.compare_summaries(left, right)

    def test_profile_or_incremental_changes_during_build_preserve_failure(self):
        for setting in ("profile", "incremental"):
            with self.subTest(setting=setting):
                (self.root / "Cargo.toml").write_text('[profile.release.package.zakura]\nopt-level=0\n')

                def mutate(argv, **kwargs):
                    execution = self.fake_build(argv, **kwargs)
                    if setting == "profile":
                        (self.root / "Cargo.toml").write_text('[profile.release.package.zakura]\nopt-level=3\n')
                    else:
                        os.environ["CARGO_INCREMENTAL"] = "1"
                    return execution

                with self.assertRaisesRegex(provenance.BenchmarkError, "changed during compilation"):
                    self.build(setting, incremental="0", operation=mutate)
                receipt = provenance.read_json(self.root / setting / "build.json")
                self.assertFalse(receipt["complete"])
                self.assertNotEqual(receipt["toolchain"], receipt["toolchain_after"])

    def test_missing_or_malformed_profile_and_incremental_evidence_cannot_compare(self):
        self.build()
        original = self.summary(self.registered())
        for value in (None, [], {"release": []}):
            summary = copy.deepcopy(original)
            summary["compatibility"]["toolchain"]["workspace_manifest_profiles"] = value
            summary["compatibility"]["node_collection"]["build"]["toolchain"]["workspace_manifest_profiles"] = value
            with self.subTest(value=value), self.assertRaisesRegex(results.ValidationError, "build-time toolchain provenance"):
                results.compare_summaries(summary, summary)
        for field in ("workspace_manifest_profiles", "CARGO_INCREMENTAL"):
            summary = copy.deepcopy(original)
            for identity in (summary["compatibility"]["toolchain"],
                             summary["compatibility"]["node_collection"]["build"]["toolchain"]):
                (identity if field == "workspace_manifest_profiles" else identity["environment"]).pop(field, None)
            with self.subTest(field=field), self.assertRaisesRegex(results.ValidationError, "build-time toolchain provenance"):
                results.compare_summaries(summary, summary)

    def test_cargo_configuration_hash_and_search_order_are_recorded(self):
        (self.root / ".cargo").mkdir()
        config = self.root / ".cargo/config.toml"
        config.write_text('[profile.release]\nopt-level = 0\n')
        self.build("config0")
        config.write_text('[profile.release]\nopt-level = 3\n')
        self.build("config3")
        left, right = (self.summary(self.registered(name)) for name in ("config0", "config3"))
        settings = left["compatibility"]["toolchain"]["cargo_configurations"][0]
        self.assertEqual(settings["location"], {"checkout_relative": ".cargo/config.toml"})
        self.assertEqual(settings["search_roles"], ["ancestor"])
        self.assertNotEqual(left["compatibility"]["toolchain"], right["compatibility"]["toolchain"])
        with self.assertRaisesRegex(results.ValidationError, "incompatible"):
            results.compare_summaries(left, right)

    def test_changed_configuration_during_build_preserves_failure(self):
        (self.root / ".cargo").mkdir()
        config = self.root / ".cargo/config.toml"
        config.write_text('[profile.release]\nopt-level = 0\n')

        def mutate(argv, **kwargs):
            result = self.fake_build(argv, **kwargs)
            config.write_text('[profile.release]\nopt-level = 3\n')
            return result

        with self.assertRaisesRegex(provenance.BenchmarkError, "changed during compilation"):
            self.build(operation=mutate)
        receipt = provenance.read_json(self.root / "built/build.json")
        self.assertFalse(receipt["complete"])
        self.assertNotEqual(receipt["toolchain"], receipt["toolchain_after"])
        self.assertTrue((self.root / "built/acceptance/build.log").exists())
        with self.assertRaisesRegex(provenance.BenchmarkError, "complete benchmark"):
            self.registered()

    def test_interrupted_build_retains_both_layers_and_cannot_resume(self):
        def interrupt(argv, **kwargs):
            self.fake_build(argv, **kwargs)
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.build(operation=interrupt)
        receipt = provenance.read_json(self.root / "built/build.json")
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["failure"], "KeyboardInterrupt")
        self.assertIsNotNone(receipt["toolchain"])
        self.assertTrue((self.root / "built/acceptance/build.log").exists())
        with self.assertRaises(FileExistsError):
            self.build()

    def test_supervisor_bounds_and_timeout_metadata(self):
        def timeout(argv, **kwargs):
            self.assertEqual(kwargs["timeout"], 30)
            self.assertEqual(kwargs["max_bytes"], 64 * 1024 * 1024)
            self.fake_build(argv, **kwargs)
            error = run.ExecutionError("fixture deadline", "timeout")
            error.process_id, error.elapsed_ns = 900, 1000
            raise error

        with self.assertRaises(run.ExecutionError):
            self.build(operation=timeout)
        receipt = provenance.read_json(self.root / "built/build.json")
        self.assertEqual(receipt["execution"], {"pid": 900, "elapsed_ns": 1000, "outcome": "timeout"})
        self.assertFalse(receipt["complete"])

    def test_acceptance_build_log_is_bounded(self):
        with patch.object(node_build, "MAX_BUILD_LOG_BYTES", 1), self.assertRaisesRegex(
                provenance.BenchmarkError, "build log byte limit"):
            self.build()
        self.assertFalse(provenance.read_json(self.root / "built/build.json")["complete"])

    def test_oversized_log_after_last_supervisor_poll_is_rejected(self):
        def grow_after_poll(argv, **kwargs):
            execution = self.fake_build(argv, **kwargs)
            (Path(argv[-1]) / "build.log").write_bytes(b"x" * 100)
            return execution

        with patch.object(node_build, "MAX_BUILD_LOG_BYTES", 50), self.assertRaisesRegex(
                provenance.BenchmarkError, "build log byte limit"):
            self.build(operation=grow_after_poll)
        self.assertFalse(provenance.read_json(self.root / "built/build.json")["complete"])

    def test_plan_bounds_the_complete_comparison_identity(self):
        self.build()
        profile = self.registered()["node_profile"]
        provenance.atomic_json(self.root / "profile.json", profile)
        manifest = self.fixture.plan()
        metadata = {**run.compatibility_metadata(manifest), "node_collection": node_run.node_compatibility(manifest)}
        results._bounded_json(metadata)
        receipt = provenance.read_json(self.root / "built/build.json")
        for name in ("toolchain", "toolchain_after"):
            receipt[name]["environment"]["CARGO_PROFILE_RELEASE_DEBUG"] = "a" * 4096
            receipt[name]["environment"]["CARGO_PROFILE_RELEASE_OPT_LEVEL"] = "b" * 4096
            receipt[name]["environment"]["CARGO_PROFILE_RELEASE_LTO"] = "c" * 4096
            receipt[name]["environment"]["CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS"] = "d" * 4096
        provenance.atomic_json(self.root / "built/build.json", receipt)
        with self.assertRaisesRegex(results.ValidationError, "byte limit"):
            self.fixture.plan("oversized")
        self.assertFalse((self.root / "oversized").exists())

    def test_wrapper_environment_and_cargo_config_rejected_before_build(self):
        variants = [({"RUSTC_WRAPPER": "cache-tool"}, None), ({"CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER": "cache-tool"}, None),
                    ({}, '[build]\nrustc-wrapper = "cache-tool"\n'),
                    ({}, '[env]\nRUSTC = "custom-rustc"\n')]
        for index, (environment, config) in enumerate(variants):
            with self.subTest(environment=environment, config=config):
                config_path = self.root / ".cargo/config.toml"
                config_path.parent.mkdir(exist_ok=True)
                config_path.write_text(config or "")
                with patch.dict(os.environ, {"CARGO_HOME": str(self.root / "cargo-home"), **environment}, clear=True), \
                        patch.object(run, "ROOT", self.root), patch.object(run, "supervise") as child, \
                        patch.object(provenance, "command_output", side_effect=AssertionError("must reject before probes")), \
                        self.assertRaisesRegex(provenance.BenchmarkError, "custom Cargo"):
                    node_build.build_node(argparse.Namespace(output=str(self.root / f"wrapper{index}"),
                                                            kind="node-default", timeout=30, execute=True))
                child.assert_not_called()
                self.assertFalse(provenance.read_json(self.root / f"wrapper{index}/build.json")["complete"])

    def test_missing_and_malformed_metadata_never_compare(self):
        self.build()
        original = self.summary(self.registered())
        for change in (None, {}, {**original["compatibility"]["toolchain"], "cargo_configurations": None},
                       {**original["compatibility"]["toolchain"], "cargo_configuration_identity_version": True},
                       {**original["compatibility"]["toolchain"], "environment": {}}):
            with self.subTest(change=change):
                summary = copy.deepcopy(original)
                summary["compatibility"]["toolchain"] = change
                summary["compatibility"]["node_collection"]["build"]["toolchain"] = change
                with self.assertRaisesRegex(results.ValidationError, "build-time toolchain provenance"):
                    results.compare_summaries(summary, summary)
        historical = copy.deepcopy(original)
        del historical["compatibility"]["toolchain"]
        del historical["compatibility"]["node_collection"]["build"]["toolchain"]
        with self.assertRaisesRegex(results.ValidationError, "build-time toolchain provenance"):
            results.compare_summaries(historical, historical)

    def test_legacy_build_registration_still_works_with_unchanged_compatibility(self):
        build = node_run.node_build(self.fixture.profile)
        self.assertNotIn("toolchain", build)
        manifest = {"node_profile": self.fixture.profile, "build": build,
                    "node_identity": node_run.node_identity(self.fixture.profile, build)}
        self.assertEqual(set(node_run.node_compatibility(manifest)["build"]),
                         {"kind", "features", "rustc", "cargo", "environment"})
        with self.assertRaisesRegex(results.ValidationError, "build-time toolchain provenance"):
            results.compare_summaries(self.summary(manifest), self.summary(manifest))

    def test_rejects_changed_inner_receipt_or_binary(self):
        self.build()
        inner = self.root / "built/acceptance/build.json"
        inner.write_bytes(inner.read_bytes() + b"\n")
        with self.assertRaisesRegex(provenance.BenchmarkError, "acceptance receipt changed"):
            self.registered()
        self.build("binary")
        (self.root / "binary/acceptance/zakurad").write_bytes(b"changed")
        with self.assertRaisesRegex(provenance.BenchmarkError, "binary changed"):
            self.registered("binary")

    def test_moved_build_keeps_historical_paths_and_can_register_and_plan(self):
        self.build()
        before = self.registered()
        original = {name: (self.root / "built" / name).read_bytes()
                    for name in ("build.json", "acceptance/build.json", "acceptance/zakurad")}
        shutil.move(self.root / "built", self.root / "copied-to-collection-host")
        after = self.registered("copied-to-collection-host")
        self.assertEqual(after["build"], before["build"])
        self.assertEqual(after["node_identity"], before["node_identity"])
        for name, contents in original.items():
            self.assertEqual((self.root / "copied-to-collection-host" / name).read_bytes(), contents)
        provenance.atomic_json(self.root / "profile.json", after["node_profile"])
        planned = self.fixture.plan("moved-plan")
        self.assertEqual(planned["build"], before["build"])
        results.compare_summaries(self.summary(before), self.summary(after))

    def test_moved_build_still_rejects_changed_receipts_and_binaries(self):
        for name, artifact, message in (("receipt", "acceptance/build.json", "acceptance receipt changed"),
                                        ("binary", "acceptance/zakurad", "binary changed")):
            with self.subTest(artifact=artifact):
                self.build(name)
                moved = "moved-" + name
                shutil.move(self.root / name, self.root / moved)
                path = self.root / moved / artifact
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaisesRegex(provenance.BenchmarkError, message):
                    self.registered(moved)

    def test_historical_commands_must_agree_after_directory_move(self):
        self.build()
        shutil.move(self.root / "built", self.root / "moved")
        path = self.root / "moved/build.json"
        original = provenance.read_json(path)
        for directory, message in (("relative/acceptance", "wrapper command"),
                                    (str(self.root / "wrong-name"), "wrapper command"),
                                    (str(self.root / "other/acceptance"), "wrapped build target")):
            with self.subTest(directory=directory):
                receipt = copy.deepcopy(original)
                receipt["command"][6] = directory
                with self.assertRaisesRegex(provenance.BenchmarkError, message):
                    node_build.unwrap_build(path, receipt)

    def test_wrapper_and_registration_hash_each_distinct_binary_once(self):
        with patch.object(node_build, "sha256", wraps=provenance.sha256) as outer_hash, \
                patch.object(node_run, "sha256", wraps=provenance.sha256) as inner_hash:
            self.build()
        calls = outer_hash.call_args_list + inner_hash.call_args_list
        self.assertEqual(sum(Path(call.args[0]).name == "zakurad" for call in calls), 1)
        with patch.object(node_run, "sha256", wraps=provenance.sha256) as hashes:
            registered = self.registered()
        self.assertEqual(sum(Path(call.args[0]).name == "zakurad" for call in hashes.call_args_list), 1)
        # A different selected executable is permitted only if its own bytes match.
        selected = self.root / "separate-zakurad"
        shutil.copyfile(self.root / "built/acceptance/zakurad", selected)
        profile = {**registered["node_profile"], "binary_path": str(selected)}
        with patch.object(node_run, "sha256", wraps=provenance.sha256) as hashes:
            self.assertEqual(node_run.node_build(profile), registered["build"])
        paths = [Path(call.args[0]) for call in hashes.call_args_list]
        self.assertEqual(paths.count(self.root / "built/acceptance/zakurad"), 1)
        self.assertEqual(paths.count(selected), 1)
        selected.write_bytes(b"changed selected binary")
        with self.assertRaisesRegex(provenance.BenchmarkError, "binary changed"):
            node_run.node_build(profile)

    def test_rejects_toolchain_that_disagrees_with_acceptance(self):
        self.build()
        for field in ("rustc", "cargo", "environment"):
            with self.subTest(field=field):
                receipt = provenance.read_json(self.root / "built/build.json")
                for name in ("toolchain", "toolchain_after"):
                    if field == "environment":
                        receipt[name][field]["CFLAGS"] = "-O0"
                    else:
                        receipt[name][field] = "different version"
                with self.assertRaisesRegex(provenance.BenchmarkError, "differs from recorded"):
                    node_build.unwrap_build(self.root / "built/build.json", receipt)

    def test_rejects_incomplete_wrapper_even_when_acceptance_finished(self):
        self.build()
        receipt = provenance.read_json(self.root / "built/build.json")
        for changes in ({"complete": False}, {"toolchain_after": None}, {"toolchain": None},
                        {"acceptance_receipt": "../build.json"}, {"execution": None}):
            with self.subTest(changes=changes), self.assertRaises(provenance.BenchmarkError):
                node_build.unwrap_build(self.root / "built/build.json", {**receipt, **changes})

    def test_execute_required_before_any_directory_or_compiler_action(self):
        with patch.object(node_build, "_capture_toolchain") as compiler, self.assertRaisesRegex(
                provenance.BenchmarkError, "--execute"):
            node_build.build_node(argparse.Namespace(output=str(self.root / "built"), kind="node-default",
                                                     timeout=30, execute=False))
        compiler.assert_not_called()
        self.assertFalse((self.root / "built").exists())


if __name__ == "__main__":
    unittest.main()
