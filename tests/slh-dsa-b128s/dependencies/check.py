#!/usr/bin/env python3
"""Check SLH dependency isolation without compiling or executing a node."""

import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
VERIFY = "zakura-pq-slh-dsa-b-verify"
NATIVE = "zakura-pq-slh-dsa-b-exp"
SIGN = "zakura-pq-slh-dsa-b-sign"
WALLET = "zakura-pq-wallet"
CLI = "zakura-pq-cli"
CONTEXT = "zakura-pq-tx-context"
PQ_BACKEND = re.compile(r"(?:ml[-_]?dsa|sqisign|slh[-_]?dsa|fips20[45])", re.IGNORECASE)
ALLOWED_PQ = {VERIFY, NATIVE, SIGN, "slh-dsa-b128s-fixture-host"}
PACKAGE = re.compile(r"^([\w-]+) v([^\s]+)(?: \([^\n]*\))?\|([^\n]*)$")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_backend(name):
    require(not PQ_BACKEND.search(name) or name in ALLOWED_PQ, f"unapproved PQ backend: {name}")


def cargo(*args):
    return subprocess.check_output(
        ["cargo", *args, "--locked", "--offline"],
        cwd=ROOT, text=True, timeout=120,
    )


def parse_tree(output):
    packages = {}
    for line in output.splitlines():
        line = line.removesuffix(" (*)")
        match = PACKAGE.fullmatch(line)
        require(match is not None, f"unexpected cargo tree line: {line!r}")
        name, version, features = match.groups()
        packages.setdefault(name, set()).add((version, tuple(features.split(","))))
    require(bool(packages), "empty dependency tree")
    return packages


def validate_tree(packages, *, required=(), forbidden=()):
    names = set(packages)
    require(set(required) <= names, f"missing packages: {sorted(set(required) - names)}")
    require(not (set(forbidden) & names), f"forbidden packages: {sorted(set(forbidden) & names)}")
    for name, builds in packages.items():
        check_backend(name)
        require("fixture" not in name, f"fixture package in consumer graph: {name}")
        if name == "blake3":
            for version, features in builds:
                require(version == "1.8.5", "changed BLAKE3 pin")
                require("rayon" not in features, "BLAKE3 Rayon feature in consumer graph")


def graph(package, features=(), edges="normal,build"):
    args = ["tree", "-p", package, "--prefix", "none", "--format", "{p}|{f}", "-e", edges,
            "--target", "all"]
    if features:
        args += ["--features", ",".join(f"{package}/{feature}" for feature in features)]
    return parse_tree(cargo(*args))


def check():
    metadata = json.loads(cargo("metadata", "--format-version", "1", "--all-features"))
    packages = {package["name"]: package for package in metadata["packages"]}
    for package in metadata["packages"]:
        check_backend(package["name"])
        if package["source"] is None:
            require(Path(package["manifest_path"]).resolve().is_relative_to(ROOT), "path dependency outside product")
    require(all(name in packages for name in (VERIFY, NATIVE, SIGN, WALLET, CLI)), "SLH product package missing")

    results = []

    def record(label, package, features=(), required=(), forbidden=(), edges="normal,build"):
        tree = graph(package, features, edges)
        validate_tree(tree, required=required, forbidden=forbidden)
        results.append({"case": label, "package_count": len(tree), "edges": edges})

    # Check node roots separately to avoid workspace-wide feature unification.
    for package in ("zakura", "zakura-consensus", "zakura-rpc"):
        record(f"{package}-default", package, forbidden=(VERIFY, NATIVE, SIGN, WALLET, CLI, CONTEXT))
        record(f"{package}-all-features", package, tuple(packages[package]["features"]),
               forbidden=(SIGN, WALLET, CLI), edges="normal,build,dev")
    record("consensus-slh", "zakura-consensus", ("experimental-slh-dsa-b128s",),
           required=(NATIVE, VERIFY, CONTEXT), forbidden=(SIGN, WALLET, CLI))
    record("wallet-default", WALLET, forbidden=(VERIFY, NATIVE, SIGN, CONTEXT))
    record("wallet-slh", WALLET, ("experimental-slh-dsa-b128s",), required=(SIGN, VERIFY))
    record("cli-default", CLI, forbidden=(WALLET, VERIFY, NATIVE, SIGN, CONTEXT))
    record("cli-slh", CLI, ("experimental-slh-dsa-b128s",),
           required=(WALLET, SIGN, VERIFY, NATIVE, CONTEXT))
    record("native-verifier-only", NATIVE, required=(VERIFY, CONTEXT), forbidden=(SIGN, WALLET, CLI))
    primitive = graph(VERIFY)
    validate_tree(primitive, required=(VERIFY, "blake3"), forbidden=(SIGN, WALLET, CLI, NATIVE, CONTEXT, "rayon", "rand_core"))
    results.append({"case": "primitive-verifier-only", "package_count": len(primitive), "edges": "normal,build"})
    return results


if __name__ == "__main__":
    print(json.dumps({"dependency_checks": check()}, indent=2))
