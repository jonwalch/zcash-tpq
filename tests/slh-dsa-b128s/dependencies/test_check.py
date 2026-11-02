import copy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check

NODES = ("zakura", "zakura-consensus", "zakura-rpc")
NODE_FEATURES = ("experimental-slh-dsa-b128s", "other-node-feature")
SLH = ("experimental-slh-dsa-b128s",)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


class DependencyGuardTests(unittest.TestCase):
    def test_cargo_tree_versions_features_and_repeated_nodes(self):
        tree = check.parse_tree(
            "zakura-pq-slh-dsa-b-verify v0.1.0 (/product/crates/verify)|\n"
            "blake3 v1.8.5|std\nblake3 v1.8.5|std (*)\n"
        )
        check.validate_tree(tree, required=(check.VERIFY, "blake3"))
        self.assertEqual(len(tree["blake3"]), 1)

    def test_missing_or_unexpected_tree_cannot_pass(self):
        for text in ("", "warning: unexpected output", "blake3"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                check.parse_tree(text)
        with self.assertRaises(ValueError):
            check.validate_tree({"blake3": {("1.8.5", ("std",))}}, required=(check.VERIFY,))

    def test_forbidden_dependencies_are_rejected(self):
        for name in (check.SIGN, check.WALLET, "ml-dsa", "pq-sqisign", "slh-fixture-host", "slh-dsa", "fips204", "fips205"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check.validate_tree({name: {("0.1.0", ())}}, forbidden=(check.SIGN, check.WALLET))

    def test_hash_pin_and_parallel_feature_are_checked(self):
        for build in (("1.8.4", ("std",)), ("1.8.5", ("std", "rayon"))):
            with self.subTest(build=build), self.assertRaises(ValueError):
                check.validate_tree({"blake3": {build}})

    def test_target_and_optional_default_edges_are_checked(self):
        # Real Cargo graph resolution only: local empty libraries, no build or
        # registry dependencies. At least one dependency is inactive on the host.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["node", "sign", "wallet", "devnet", "chain", "sha2", "toml", "hkdf"]\nresolver = "2"\n'
            )
            for path, package in (("node", "zakura-consensus"),
                                  ("sign", check.SIGN), ("wallet", check.WALLET),
                                  ("devnet", check.DEVNET), ("chain", "zakura-chain"),
                                  ("sha2", "sha2"), ("toml", "toml"), ("hkdf", "hkdf")):
                (root / path / "src").mkdir(parents=True)
                (root / path / "src/lib.rs").write_text("")
                (root / path / "Cargo.toml").write_text(
                    f'[package]\nname = "{package}"\nversion = "0.1.0"\nedition = "2021"\n'
                )
            with (root / "node/Cargo.toml").open("a") as manifest:
                manifest.write(
                    f"[target.'cfg(windows)'.dependencies]\n{check.SIGN} = {{ path = \"../sign\" }}\n"
                    f"[target.'cfg(not(windows))'.dependencies]\n{check.WALLET} = {{ path = \"../wallet\" }}\n"
                )
            with (root / "devnet/Cargo.toml").open("a") as manifest:
                manifest.write(
                    '[features]\ndefault = ["wallet"]\n'
                    'adapter = ["dep:sha2", "dep:toml"]\n'
                    f'wallet = ["{check.WALLET}/experimental-slh-dsa-b128s"]\n[dependencies]\n'
                    'zakura-chain = { path = "../chain" }\n'
                    f'{check.WALLET} = {{ path = "../wallet", default-features = false, features = ["public-profile"] }}\n'
                    'sha2 = { path = "../sha2", optional = true }\n'
                    'toml = { path = "../toml", optional = true }\n'
                    'hkdf = { path = "../hkdf", optional = true }\n'
                )
            with (root / "wallet/Cargo.toml").open("a") as manifest:
                manifest.write(
                    '[features]\ndefault = []\npublic-profile = []\n'
                    f'experimental-slh-dsa-b128s = ["public-profile", "dep:{check.SIGN}"]\n'
                    f'[dependencies]\n{check.SIGN} = {{ path = "../sign", optional = true }}\n'
                )
            with (root / "chain/Cargo.toml").open("a") as manifest:
                manifest.write(
                    '[features]\ndefault = []\n[dependencies]\n'
                    f'{check.SIGN} = {{ path = "../sign", optional = true }}\n'
                )
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root,
                           check=True, capture_output=True, timeout=120)
            with patch.object(check, "ROOT", root):
                tree = check.graph("zakura-consensus", edges="normal,build,dev")
            self.assertIn(check.SIGN, tree)
            self.assertIn(check.WALLET, tree)
            for forbidden in (check.SIGN, check.WALLET):
                with self.subTest(forbidden=forbidden), self.assertRaisesRegex(
                    ValueError, "forbidden packages"
                ):
                    check.validate_tree(tree, forbidden=(forbidden,))

            forbidden = (check.SIGN, check.CLI, check.NATIVE, check.CONTEXT, check.VERIFY)
            public_forbidden = (*forbidden, "zakura-chain", "hkdf", "argon2", "chacha20poly1305", "rand_core")
            adapter_forbidden = (*forbidden, check.BENCH, "hkdf", "argon2", "password-hash")
            with patch.object(check, "ROOT", root):
                check.validate_tree(check.graph(check.DEVNET),
                                    required=("zakura-chain", check.WALLET, check.SIGN))
                check.validate_tree(check.graph(check.DEVNET, no_default_features=True),
                                    required=("zakura-chain", check.WALLET), forbidden=forbidden)
                adapter = check.graph(check.DEVNET, ("adapter",), no_default_features=True)
                check.validate_tree(adapter, required=("zakura-chain", check.WALLET, "sha2", "toml"),
                                    forbidden=adapter_forbidden)
                self.assertTrue(all("public-profile" in features for _, features in adapter[check.WALLET]))
                check.validate_tree(check.graph(check.WALLET, ("public-profile",), no_default_features=True),
                                    required=(check.WALLET,), forbidden=public_forbidden)
                # An adapter-only secret-key dependency must not hide behind
                # the clean no-default-features graph.
                manifest = root / "devnet/Cargo.toml"
                original = manifest.read_text()
                manifest.write_text(original.replace(
                    'adapter = ["dep:sha2", "dep:toml"]',
                    'adapter = ["dep:sha2", "dep:toml", "dep:hkdf"]'))
                check.validate_tree(check.graph(check.DEVNET, no_default_features=True),
                                    required=("zakura-chain", check.WALLET), forbidden=forbidden)
                with self.assertRaisesRegex(ValueError, "forbidden packages: \\['hkdf'\\]"):
                    check.validate_tree(check.graph(check.DEVNET, ("adapter",), no_default_features=True),
                                        required=("zakura-chain", check.WALLET), forbidden=adapter_forbidden)
                manifest.write_text(original)
                # The public feature itself must not enable signing, either
                # for standalone use or through either devnet consumer profile.
                manifest = root / "wallet/Cargo.toml"
                original = manifest.read_text()
                manifest.write_text(original.replace(
                    'public-profile = []', f'public-profile = ["dep:{check.SIGN}"]'))
                for package, features, required, excluded in (
                    (check.WALLET, ("public-profile",), (check.WALLET,), public_forbidden),
                    (check.DEVNET, (), ("zakura-chain", check.WALLET), forbidden),
                    (check.DEVNET, ("adapter",), ("zakura-chain", check.WALLET), adapter_forbidden),
                ):
                    with self.subTest(public_signing=package, features=features), self.assertRaisesRegex(ValueError, "forbidden packages"):
                        check.validate_tree(check.graph(package, features, no_default_features=True),
                                            required=required, forbidden=excluded)
                manifest.write_text(original)
                # Root --no-default-features does not disable transitive defaults.
                # Check a chain default and a wallet dependency that loses its
                # default-features=false protection independently.
                for path in ("chain", "wallet"):
                    manifest = root / path / "Cargo.toml"
                    original = manifest.read_text()
                    manifest.write_text(original.replace(
                        'default = []', f'default = ["dep:{check.SIGN}"]'))
                    devnet_manifest = root / "devnet/Cargo.toml"
                    devnet_original = devnet_manifest.read_text()
                    if path == "wallet":
                        check.validate_tree(check.graph(check.DEVNET, no_default_features=True),
                                            required=("zakura-chain", check.WALLET), forbidden=forbidden)
                        devnet_manifest.write_text(devnet_original.replace('default-features = false, ', ''))
                    for features, excluded in (((), forbidden), (("adapter",), adapter_forbidden)):
                        with self.subTest(transitive_default=path, features=features), self.assertRaisesRegex(ValueError, "forbidden packages"):
                            check.validate_tree(check.graph(check.DEVNET, features, no_default_features=True),
                                                required=("zakura-chain", check.WALLET), forbidden=excluded)
                    manifest.write_text(original)
                    devnet_manifest.write_text(devnet_original)


class IsolationPolicyTests(unittest.TestCase):
    """Run check() over canned metadata and graphs; Cargo is not invoked.

    This table restates the isolation policy independently of check.py:
    (package, features, edges, no_default_features) -> (required, forbidden).
    """

    def setUp(self):
        c = check
        self.policy = {}
        for node in NODES:
            self.policy[(node, (), "normal,build")] = ((), (c.VERIFY, c.NATIVE, c.SIGN, c.WALLET, c.CLI, c.CONTEXT))
            self.policy[(node, NODE_FEATURES, "normal,build,dev")] = ((), (c.SIGN, c.WALLET, c.CLI))
        self.policy.update({
            ("zakura-consensus", SLH, "normal,build"): ((c.NATIVE, c.VERIFY, c.CONTEXT), (c.SIGN, c.WALLET, c.CLI)),
            (c.WALLET, (), "normal,build"): ((), (c.VERIFY, c.NATIVE, c.SIGN, c.CONTEXT)),
            (c.WALLET, SLH, "normal,build"): ((c.SIGN, c.VERIFY), ()),
            (c.CLI, (), "normal,build"): ((), (c.WALLET, c.VERIFY, c.NATIVE, c.SIGN, c.CONTEXT)),
            (c.CLI, SLH, "normal,build"): ((c.WALLET, c.SIGN, c.VERIFY, c.NATIVE, c.CONTEXT), ()),
            (c.NATIVE, (), "normal,build"): ((c.VERIFY, c.CONTEXT), (c.SIGN, c.WALLET, c.CLI)),
            (c.VERIFY, (), "normal,build"): ((c.VERIFY, "blake3"),
                                             (c.SIGN, c.WALLET, c.CLI, c.NATIVE, c.CONTEXT, "rayon", "rand_core")),
            (c.DEVNET, (), "normal,build"): (("zakura-chain", c.WALLET, c.SIGN, c.VERIFY, c.NATIVE, c.CONTEXT),
                                              (c.CLI,)),
        })
        self.policy = {(*key, False): (required, (*forbidden, c.BENCH))
                       for key, (required, forbidden) in self.policy.items()}
        self.policy[(c.WALLET, ("public-profile",), "normal,build", True)] = (
            (c.WALLET,), (c.SIGN, c.CLI, c.NATIVE, c.VERIFY, c.CONTEXT, "zakura-chain",
                          "hkdf", "argon2", "chacha20poly1305", "rand_core", c.BENCH))
        self.policy[(c.DEVNET, (), "normal,build", True)] = (
            ("zakura-chain", c.WALLET), (c.SIGN, c.CLI, c.NATIVE, c.CONTEXT, c.VERIFY, c.BENCH))
        self.policy[(c.DEVNET, ("adapter",), "normal,build", True)] = (
            ("zakura-chain", c.WALLET),
            (c.SIGN, c.CLI, c.NATIVE, c.CONTEXT, c.VERIFY, "hkdf", "argon2", "password-hash", c.BENCH))
        self.policy[(c.BENCH, (), "normal,build,dev", False)] = (
            (c.BENCH, c.SIGN, c.VERIFY, c.WALLET, c.NATIVE, c.CONTEXT, "blake3"),
            (c.CLI, "zakura", "zakura-consensus", "zakura-state", "zakura-network"))

    def clean_trees(self):
        trees = {}
        for key, (required, _) in self.policy.items():
            trees[key] = {name: {("0.1.0", ("default",))} for name in (key[0], *required)}
            trees[key]["blake3"] = {("1.8.5", ("std",))}
            if key[0] == check.WALLET and key[1] == ("public-profile",):
                trees[key]["zeroize"] = {("1.8.2", ())}
            if key[0] == check.DEVNET and key[1] == ("adapter",):
                # Shared chain dependencies and public adapter helpers do not
                # establish wallet signing or key generation support.
                for name in ("chacha20poly1305", "rand_core", "zeroize", "sha2", "toml"):
                    trees[key][name] = {("0.1.0", ())}
        return trees

    def metadata(self, omit=(), extra=()):
        names = (*NODES, check.VERIFY, check.NATIVE, check.SIGN, check.WALLET, check.CLI,
                 check.CONTEXT, check.DEVNET, "zakura-chain")
        packages = [{"name": name, "source": None, "manifest_path": str(check.ROOT / "crates" / name / "Cargo.toml"),
                     "features": {feature: [] for feature in NODE_FEATURES} if name in NODES else {}}
                    for name in names if name not in omit]
        packages.append({"name": "blake3", "source": REGISTRY, "features": {},
                         "manifest_path": "/cargo-home/registry/src/blake3-1.8.5/Cargo.toml"})
        return {"packages": packages + list(extra)}

    def run_check(self, trees=None, metadata=None):
        trees = self.clean_trees() if trees is None else trees
        raw = json.dumps(self.metadata() if metadata is None else metadata)
        requested = []

        def cargo(*args):
            self.assertEqual(args, ("metadata", "--format-version", "1", "--all-features"))
            return raw

        def graph(package, features=(), edges="normal,build", *, no_default_features=False):
            requested.append((package, tuple(features), edges, no_default_features))
            return copy.deepcopy(trees[requested[-1]])

        with patch.object(check, "cargo", side_effect=cargo), patch.object(check, "graph", side_effect=graph):
            return check.check(), requested

    def test_every_graph_is_requested_once_and_clean_graphs_pass(self):
        results, requested = self.run_check()
        self.assertEqual(sorted(requested), sorted(self.policy))
        self.assertEqual([row["case"] for row in results], [
            "zakura-default", "zakura-all-features", "zakura-consensus-default", "zakura-consensus-all-features",
            "zakura-rpc-default", "zakura-rpc-all-features", "consensus-slh", "wallet-default", "wallet-public-profile", "wallet-slh",
            "cli-default", "cli-slh", "tpq-devnet-default", "tpq-devnet-no-default-features",
            "tpq-devnet-adapter",
            "native-verifier-only", "primitive-verifier-only", "isolated-benchmark"])

    def test_each_forbidden_package_is_rejected_in_its_graph(self):
        for key, (_, forbidden) in self.policy.items():
            for name in forbidden:
                with self.subTest(graph=key, forbidden=name):
                    trees = self.clean_trees()
                    trees[key][name] = {("0.1.0", ())}
                    with self.assertRaisesRegex(ValueError, "^" + re.escape(f"forbidden packages: {[name]}") + "$"):
                        self.run_check(trees)

    def test_each_required_package_is_enforced_in_its_graph(self):
        for key, (required, _) in self.policy.items():
            for name in required:
                with self.subTest(graph=key, required=name):
                    trees = self.clean_trees()
                    del trees[key][name]
                    with self.assertRaisesRegex(ValueError, "^" + re.escape(f"missing packages: {[name]}") + "$"):
                        self.run_check(trees)

    def test_historical_orchard_builder_is_rejected_in_every_node_graph(self):
        for key in self.policy:
            if key[0] not in NODES:
                continue
            with self.subTest(graph=key):
                trees = self.clean_trees()
                trees[key]["zakura-orchard"] = {("3.0.0", ("circuit",)), ("2.2.0", ("circuit",))}
                with self.assertRaisesRegex(ValueError, "historical Orchard builder in node graph"):
                    self.run_check(trees)

    def test_metadata_requires_local_paths_product_packages_and_no_alternate_backend(self):
        outside = [str(Path("/outside-product/helper/Cargo.toml")),
                   str(check.ROOT / "crates" / ".." / ".." / "outside-product" / "Cargo.toml")]
        for manifest_path in outside:
            with self.subTest(manifest_path=manifest_path), \
                    self.assertRaisesRegex(ValueError, "^path dependency outside product$"):
                self.run_check(metadata=self.metadata(extra=[
                    {"name": "local-helper", "source": None, "manifest_path": manifest_path, "features": {}}]))
        for name in (check.VERIFY, check.NATIVE, check.SIGN, check.WALLET, check.CLI):
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, "^SLH product package missing$"):
                self.run_check(metadata=self.metadata(omit=(name,)))
        with self.assertRaisesRegex(ValueError, "^unapproved PQ backend: ml-dsa$"):
            self.run_check(metadata=self.metadata(extra=[
                {"name": "ml-dsa", "source": REGISTRY, "features": {},
                 "manifest_path": "/cargo-home/registry/src/ml-dsa-0.1.0/Cargo.toml"}]))


if __name__ == "__main__":
    unittest.main()
