# SPDX-License-Identifier: LGPL-3.0-or-later
"""Independent Python SLH logic plus independently compiled portable C BLAKE3.

The checked loader executes the pinned independent verifier and never imports
the Rust verifier. This test-only reference is LGPL-3.0-or-later.
"""

import importlib
import sys
import types

from prepare import SOURCES, checked, HERE
import ctypes
import json


class Reference:
    def __init__(self, inputs):
        directory = inputs / "reference"
        source = {}
        for item in SOURCES["reference"]["files"]:
            source[item["path"]] = checked(directory / item["path"], item["sha256"])
        expected = {item["path"] for item in SOURCES["reference"]["files"] if item["path"].endswith(".py")}
        actual = {p.relative_to(directory).as_posix() for p in (directory / "slhdsa/lowlevel").rglob("*.py")}
        if actual != expected:
            raise ValueError("reference Python inventory mismatch")
        # Skip upstream's high-level ASN.1 packaging: load the checked source
        # modules directly. Reject ambient imports or stale bytecode extensions.
        if any(name == "slhdsa" or name.startswith("slhdsa.") for name in sys.modules):
            raise ValueError("reference already imported; use a fresh process")
        for name, path in [("slhdsa", directory / "slhdsa"), ("slhdsa.lowlevel", directory / "slhdsa/lowlevel")]:
            package = types.ModuleType(name)
            package.__path__ = [str(path)]
            sys.modules[name] = package
        # Execute verified bytes explicitly, so .pyc/.so files cannot override
        # the recorded Python implementation. Dependency order is intentional.
        for name in ["addresses", "_utils", "parameters", "wots", "xmss", "fors", "hypertree", "slhdsa"]:
            full = "slhdsa.lowlevel." + name
            path = directory / "slhdsa/lowlevel" / (name + ".py")
            module = types.ModuleType(full)
            module.__file__ = str(path)
            sys.modules[full] = module
            exec(compile(source["slhdsa/lowlevel/" + name + ".py"], str(path), "exec"), module.__dict__)
        self.parameters = importlib.import_module("slhdsa.lowlevel.parameters")
        self.scheme = importlib.import_module("slhdsa.lowlevel.slhdsa")
        receipt = json.loads((inputs / "hash-build.json").read_text())
        checked(HERE / "sources.json", receipt["sources_sha256"])
        checked(HERE / "hash_shim.c", receipt["shim_sha256"])
        if receipt["library_name"] not in ("libslh_reference_blake3.dylib", "libslh_reference_blake3.so"):
            raise ValueError("unexpected hash library name")
        for item in SOURCES["blake3_c"]["files"]:
            checked(inputs / "blake3_c" / item["path"], item["sha256"])
        library = inputs / receipt["library_name"]
        checked(library, receipt["library_sha256"])
        self.lib = ctypes.CDLL(str(library))
        self.lib.slh_reference_xof.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p]
        self.lib.slh_reference_xof.restype = None
        xof = self.xof

        class BlakeParameter(self.parameters.Parameter):
            def Hmsg(self, r, seed, root, msg):
                return xof(b"".join((r, seed, root, msg)), self.m)
            def PRF(self, seed, secret, adrs):
                return xof(b"".join((seed, adrs.to_bytes(), secret)), self.n)
            def PRFmsg(self, secret, rand, msg):
                return xof(b"".join((secret, rand, msg)), self.n)
            def F(self, seed, adrs, msg):
                return xof(b"".join((seed, adrs.to_bytes(), msg)), self.n)
            H = F
            Tl = F

        self.profile = BlakeParameter(0, 16, 63, 7, 9, 12, 14, 4, 30)

    def xof(self, data, length, mode=0, key=None):
        if length < 0 or length > 4096 or mode not in (0, 1, 2):
            raise ValueError("XOF bounds")
        if mode == 1 and (key is None or len(key) != 32):
            raise ValueError("key length")
        if mode == 2 and (key is None or not key.endswith(b"\0")):
            raise ValueError("context terminator")
        out = ctypes.create_string_buffer(length)
        self.lib.slh_reference_xof(data, len(data), out, length, mode, key)
        return out.raw

    @staticmethod
    def frame(message, context):
        if len(context) > 255 or len(message) > 65536:
            raise ValueError("message/context bound")
        return b"\0" + bytes([len(context)]) + context + message

    def verify(self, pk, sig, message, context=b""):
        if len(pk) != 32 or len(sig) != 7856 or len(context) > 255 or len(message) > 65536:
            return False
        return self.scheme.verify(self.frame(message, context), sig, (pk[:16], pk[16:]), self.profile)

    def hash_vectors(self, inputs):
        item = next(x for x in SOURCES["blake3_c"]["files"] if x["path"] == "test_vectors/test_vectors.json")
        vectors = json.loads(checked(inputs / "blake3_c" / item["path"], item["sha256"]))
        for case in vectors["cases"]:
            msg = bytes(i % 251 for i in range(case["input_len"]))
            for mode, name, key in [(0, "hash", None), (1, "keyed_hash", vectors["key"].encode()), (2, "derive_key", vectors["context_string"].encode() + b"\0")]:
                expected = bytes.fromhex(case[name])
                if self.xof(msg, len(expected), mode, key) != expected:
                    raise ValueError(f"BLAKE3 vector mismatch: {case['input_len']} {name}")
        return len(vectors["cases"]) * 3
