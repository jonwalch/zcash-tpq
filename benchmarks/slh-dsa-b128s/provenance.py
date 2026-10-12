"""Bounded source and artifact identities; importing this module runs nothing.

Adapted from product acceptance/common.py and research measurements/run.py.
See NOTICE and sources.json for the exact sources and adaptation scope.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import tomllib

MAX_JSON = 16 * 1024 * 1024
REFERENCE_ROOT = Path(__file__).resolve().parents[2] / "tests/slh-dsa-b128s/reference"
MAX_REFERENCE_FILE = 8 * 1024 * 1024
MAX_REFERENCE_TOTAL = 32 * 1024 * 1024


class BenchmarkError(ValueError):
    """Invalid benchmark input or incomplete execution."""


def require(condition, reason):
    if not condition:
        raise BenchmarkError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest_value(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "expected a regular file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def strict_json(data):
    require(len(data) <= MAX_JSON, "JSON size limit")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise BenchmarkError("non-finite JSON number")

    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), "non-finite JSON number")
        return number

    try:
        if isinstance(data, bytes):
            data = data.decode("utf8")
        return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant,
                          parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise BenchmarkError("invalid JSON") from error


def read_json(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "expected a regular JSON file")
    with path.open("rb") as stream:
        return strict_json(stream.read(MAX_JSON + 1))


def atomic_json(path, value):
    path = Path(path)
    require(not path.is_symlink(), "refuse symlink output")
    data = canonical(value) + b"\n"
    require(len(data) <= MAX_JSON, "JSON output size limit")
    descriptor, name = tempfile.mkstemp(prefix=".receipt-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def claim_run(directory):
    """Exclusive persistent claim; interrupted runs cannot be executed again."""
    with (Path(directory) / "execution.claim").open("xb") as stream:
        stream.write(b"This run has been attempted. Register a fresh directory.\n")
        stream.flush()
        os.fsync(stream.fileno())


def fresh_directory(path):
    path = Path(path).absolute()
    require(not path.is_symlink(), "refuse symlink directory")
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    return path


def command_output(argv, root):
    result = subprocess.run(argv, cwd=root, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60)
    require(len(result.stdout) <= MAX_JSON, "command output size limit")
    return result.stdout.decode("utf8")


def source_state(root):
    """Hash all tracked worktree bytes, not only the current Git revision."""
    root = Path(root).resolve()
    require(not command_output(["git", "status", "--porcelain", "--untracked-files=all"], root),
            "commit source inputs before registering a build")
    names = command_output(["git", "ls-files", "-z"], root).split("\0")
    inventory = []
    for name in sorted(filter(None, names)):
        path = root / name
        if path.is_symlink():
            require(path.resolve().is_relative_to(root), "source symlink escapes checkout")
            data = os.readlink(path).encode()
            item = {"path": name, "kind": "symlink", "sha256": hashlib.sha256(data).hexdigest()}
        else:
            item = {"path": name, "kind": "file", "sha256": sha256(path)}
        inventory.append(item)
    require(bool(inventory), "empty source inventory")
    return {"commit": command_output(["git", "rev-parse", "HEAD"], root).strip(),
            "tree": command_output(["git", "rev-parse", "HEAD^{tree}"], root).strip(),
            "files": inventory, "inventory_sha256": digest_value(inventory)}


def toolchain(root, *, source_root=None):
    # Cargo searches the invocation directory's ancestors and Cargo home. Hash
    # configuration without copying possible registry credentials into receipts.
    root = Path(root).resolve()
    source_root = Path(source_root).resolve() if source_root is not None else root
    require(root.is_relative_to(source_root), "Cargo invocation must be inside the source checkout")
    paths = {}
    for parent in (root, *root.parents):
        for name in ("config", "config.toml"):
            paths.setdefault(parent / ".cargo" / name, []).append("ancestor")
    cargo_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    if not cargo_home.is_absolute():
        cargo_home = root / cargo_home
    cargo_home = cargo_home.resolve()
    for name in ("config", "config.toml"):
        paths.setdefault(cargo_home / name, []).append("cargo_home")
    configs = []
    # Preserve search precedence and both filename forms. Hashing the unused
    # .toml form when legacy config exists is deliberately conservative.
    for path, roles in paths.items():
        if path.exists():
            config = tomllib.loads(path.read_text())
            require(not any(config.get("build", {}).get(name) for name in
                            ("rustc", "rustc-wrapper", "rustc-workspace-wrapper")),
                    "custom Cargo compiler or wrapper is not supported")
            require(not {"RUSTC", "CARGO_BUILD_RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}
                    .intersection(config.get("env", {})), "custom Cargo compiler environment is not supported")
            location = ({"checkout_relative": str(path.relative_to(source_root))}
                        if path.is_relative_to(source_root) else {"external_absolute": str(path)})
            configs.append({"path": str(path), "location": location,
                            "search_roles": roles, "sha256": sha256(path)})
    require(not any(os.environ.get(name) for name in ("RUSTC", "CARGO_BUILD_RUSTC",
                "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER",
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")), "custom Cargo compiler or wrapper is not supported")
    names = {"RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CC", "CXX",
             "CFLAGS", "CXXFLAGS", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET",
             "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}
    names.update(name for name in os.environ if name.startswith(
        ("CARGO_PROFILE_", "CARGO_BUILD_", "CARGO_TARGET_")))
    return {"rustc": command_output(["rustc", "-vV"], root).strip(),
            "cargo": command_output(["cargo", "-V"], root).strip(),
            "cargo_configuration_identity_version": 1,
            "cargo_configurations": configs,
            "environment": {name: os.environ.get(name) for name in sorted(names)}}


def toolchain_compatibility(identity):
    """Ignore only the checkout prefix, keeping raw paths in build provenance.

    Old receipts have no scoped locations or search order. Keep their absolute
    paths as a conservative identity instead of guessing missing provenance.
    """
    if identity is None or identity.get("cargo_configuration_identity_version") != 1:
        return identity
    return {**identity, "cargo_configurations": [
        {key: value for key, value in config.items() if key != "path"}
        for config in identity["cargo_configurations"]]}


def host_state():
    """Portable host facts; entitlement is not inferred from host CPU count."""
    return {"system": platform.system(), "release": platform.release(),
            "machine": platform.machine(), "processor": platform.processor(),
            "logical_cpus_reported": os.cpu_count(), "python": platform.python_version(),
            "effective_cpu_entitlement": None,
            "effective_cpu_entitlement_reason": "must be supplied by the registered host profile"}


def artifact_inventory(directory):
    directory = Path(directory)
    result = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), "artifact symlink")
        require(path.is_file() or path.is_dir(), "non-regular artifact")
        if path.is_file() and path != directory / "receipt.json":
            result[str(path.relative_to(directory))] = sha256(path)
    return result


def verify_artifacts(directory, inventory):
    require(type(inventory) is dict, "artifact inventory must be an object")
    actual = artifact_inventory(directory)
    require(actual == inventory, "artifact bytes or inventory changed")


def snapshot_payment_reference(source, destination):
    """Retain checked independent inputs without importing or executing them.

    Only the pinned reference sources, licenses, hash vectors and prepared hash
    library are copied. Build command paths in the receipt stay as historical
    provenance; they are never interpreted as commands or copy destinations.
    The payment checker validates and loads this snapshot in a separate process.
    """
    source = Path(source).absolute()
    require(source.is_dir() and not source.is_symlink(), "regular reference directory required")
    pins = read_json(REFERENCE_ROOT / "sources.json")
    expected = {}
    for group in ("reference", "blake3_c"):
        for item in pins[group]["files"]:
            name = Path(group) / item["path"]
            require(not name.is_absolute() and ".." not in name.parts,
                    "invalid pinned reference path")
            require(str(name) not in expected, "duplicate pinned reference path")
            expected[str(name)] = item["sha256"]

    copied = {}
    total = 0

    def retain(name, expected_hash=None):
        nonlocal total
        path = source
        for component in Path(name).parts:
            path = path / component
            require(not path.is_symlink(), "reference symlink")
        require(path.is_file(), "regular reference file required")
        with path.open("rb") as stream:
            data = stream.read(MAX_REFERENCE_FILE + 1)
        require(len(data) <= MAX_REFERENCE_FILE, "reference file size limit")
        total += len(data)
        require(total <= MAX_REFERENCE_TOTAL, "reference snapshot size limit")
        if expected_hash is not None:
            require(hashlib.sha256(data).hexdigest() == expected_hash, "reference source hash mismatch")
        copied[name] = data
        return data

    receipt = strict_json(retain("hash-build.json"))
    require(type(receipt) is dict and receipt.get("schema_version") == 1,
            "reference build receipt schema")
    require(receipt.get("sources_sha256") == sha256(REFERENCE_ROOT / "sources.json")
            and receipt.get("shim_sha256") == sha256(REFERENCE_ROOT / "hash_shim.c"),
            "reference build source mismatch")
    library = receipt.get("library_name")
    require(library in ("libslh_reference_blake3.dylib", "libslh_reference_blake3.so"),
            "unexpected reference library name")
    require(type(receipt.get("library_sha256")) is str, "reference library hash required")
    retain(library, receipt["library_sha256"])
    for name, digest in expected.items():
        retain(name, digest)
    # Match the independent loader's Python inventory check instead of silently
    # cleaning an unexpected Python implementation out of the supplied inputs.
    python_files = {str(path.relative_to(source)) for path in
                    (source / "reference/slhdsa/lowlevel").rglob("*.py")}
    require(python_files == {name for name in expected if name.endswith(".py")},
            "reference Python inventory mismatch")

    destination = fresh_directory(destination)
    for name, data in copied.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("xb") as stream:
            stream.write(data)
        path.chmod(0o400)
    return destination
