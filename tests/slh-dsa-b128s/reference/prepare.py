#!/usr/bin/env python3
"""Fetch checked test-only sources and build independent portable C BLAKE3."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import urllib.request

HERE = Path(__file__).resolve().parent
SOURCES = json.loads((HERE / "sources.json").read_text())
MAX_DOWNLOAD_BYTES = 40_000_000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked(path, expected):
    data = Path(path).read_bytes()
    if digest(data) != expected:
        raise ValueError(f"source hash mismatch: {path}")
    return data


def fetch(url, path, expected):
    if path.exists():
        checked(path, expected)
        return
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES or digest(data) != expected:
        raise ValueError(f"download size/hash mismatch: {url}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)


def prepare(destination, compiler="cc"):
    for group in ("reference", "blake3_c"):
        source = SOURCES[group]
        prefix = source["repository"].replace(
            "https://github.com/", "https://raw.githubusercontent.com/"
        )
        for item in source["files"]:
            url = f"{prefix}/{source['commit']}/{item['path']}"
            fetch(url, destination / group / item["path"], item["sha256"])
    compiler = shutil.which(compiler)
    if compiler is None:
        raise ValueError("C compiler not found")
    c = destination / "blake3_c/c"
    suffix = ".dylib" if platform.system() == "Darwin" else ".so"
    library = destination / ("libslh_reference_blake3" + suffix)
    command = [
        compiler, "-O2", "-shared", "-fPIC", "-DBLAKE3_USE_NEON=0",
        "-DBLAKE3_NO_SSE2", "-DBLAKE3_NO_SSE41", "-DBLAKE3_NO_AVX2",
        "-DBLAKE3_NO_AVX512", "-I", str(c), str(HERE / "hash_shim.c"),
        *[str(c / name) for name in (
            "blake3.c", "blake3_dispatch.c", "blake3_portable.c"
        )],
        "-o", str(library),
    ]
    subprocess.run(command, check=True, timeout=60)
    receipt = {
        "schema_version": 1,
        "command": command,
        "library_name": library.name,
        "library_sha256": digest(library.read_bytes()),
        "shim_sha256": digest((HERE / "hash_shim.c").read_bytes()),
        "sources_sha256": digest((HERE / "sources.json").read_bytes()),
        "compiler_sha256": digest(Path(compiler).read_bytes()),
        "compiler": subprocess.check_output(
            [compiler, "--version"], text=True, timeout=30
        ),
    }
    (destination / "hash-build.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--compiler", default="cc")
    args = parser.parse_args()
    prepare(args.destination.resolve(), args.compiler)
