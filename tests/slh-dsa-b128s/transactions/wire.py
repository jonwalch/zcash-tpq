"""Independent transparent-only ZIP 244/229 parsing/digests.
SPDX-License-Identifier: MIT OR Apache-2.0
Adapted from the independently authored hash-four-payments wire checker.
No candidate or production digest imports.
"""
import hashlib
VERSIONS = {5: (0x80000005, 0x26A7270A), 6: (0x80000006, 0xD884B698)}
def le32(value):
    return value.to_bytes(4, "little")


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self):
        return int.from_bytes(self.take(4), "little")

    def compact(self):
        first = self.take(1)[0]
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}.get(first)
        value = first if size is None else int.from_bytes(self.take(size), "little")
        if compact(value) != self.data[self.pos - 1 - (size or 0):self.pos]:
            raise ValueError("non-minimal CompactSize")
        return value

    def script(self, maximum):
        length = self.compact()
        if length > maximum:
            raise ValueError("script cap")
        return self.take(length)


def parse_output(reader):
    value = int.from_bytes(reader.take(8), "little")
    if value > 21_000_000 * 100_000_000:
        raise ValueError("monetary range")
    return {"value": value, "script": reader.script(10000)}


def parse_transaction(raw):
    """Transparent-only v5/v6, consuming every byte; shielded bundles must be empty."""
    if len(raw) > 2_000_000:
        raise ValueError("transaction cap")
    r = Reader(raw)
    header = r.u32()
    version = header & 0x7FFFFFFF
    if header >> 31 != 1 or version not in VERSIONS or r.u32() != VERSIONS[version][1]:
        raise ValueError("unsupported transaction header")
    tx = {"version": version, "header": header, "branch": r.u32(), "lock_time": r.u32(),
          "expiry": r.u32(), "inputs": [], "outputs": []}
    count = r.compact()
    if not 1 <= count <= 32:
        raise ValueError("input cap")
    for _ in range(count):
        prevout = r.take(36)
        if prevout == bytes(32) + b"\xff" * 4:
            raise ValueError("coinbase input")
        script = r.script(131072)
        tx["inputs"].append({"outpoint": prevout, "script": script, "sequence": r.u32()})
    if len({i["outpoint"] for i in tx["inputs"]}) != count:
        raise ValueError("duplicate outpoint")
    count = r.compact()
    if not 1 <= count <= 64:
        raise ValueError("output cap")
    for _ in range(count):
        tx["outputs"].append(parse_output(r))
    if any(len(output["script"]) > 10000 for output in tx["outputs"]):
        raise ValueError("output script cap")
    if sum(output["value"] for output in tx["outputs"]) > 2_100_000_000_000_000:
        raise ValueError("output amount sum")
    # Sapling spends/outputs, Orchard actions, and v6 Ironwood actions: all empty.
    empty = 3 if version == 5 else 4
    if r.take(empty) != bytes(empty) or r.pos != len(raw):
        raise ValueError("expected empty shielded bundles and no trailing data")
    return tx


def blake(person, data):
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


def output_bytes(o):
    return o["value"].to_bytes(8, "little") + compact(len(o["script"])) + o["script"]


def input_digest(tx, previous, index):
    """ZIP 244 (v5) / ZIP 229 (v6) SIGHASH_ALL for a transparent-only transaction."""
    if len(previous) != len(tx["inputs"]) or not 0 <= index < len(previous):
        raise ValueError("ordered spent-output context")
    prevouts = blake(b"ZTxIdPrevoutHash", b"".join(i["outpoint"] for i in tx["inputs"]))
    amounts = blake(b"ZTxTrAmountsHash", b"".join(p["value"].to_bytes(8, "little") for p in previous))
    scripts = blake(b"ZTxTrScriptsHash", b"".join(compact(len(p["script"])) + p["script"] for p in previous))
    sequences = blake(b"ZTxIdSequencHash", b"".join(le32(i["sequence"]) for i in tx["inputs"]))
    outputs = blake(b"ZTxIdOutputsHash", b"".join(output_bytes(o) for o in tx["outputs"]))
    spent, txin = previous[index], tx["inputs"][index]
    selected = blake(b"Zcash___TxInHash", txin["outpoint"] + spent["value"].to_bytes(8, "little")
                     + compact(len(spent["script"])) + spent["script"] + le32(txin["sequence"]))
    transparent = blake(b"ZTxIdTranspaHash", b"\x01" + prevouts + amounts + scripts + sequences + outputs + selected)
    header = blake(b"ZTxIdHeadersHash", le32(tx["header"]) + le32(VERSIONS[tx["version"]][1])
                   + le32(tx["branch"]) + le32(tx["lock_time"]) + le32(tx["expiry"]))
    parts = header + transparent + blake(b"ZTxIdSaplingHash", b"")
    if tx["version"] == 5:
        parts += blake(b"ZTxIdOrchardHash", b"")
    else:
        parts += blake(b"ZTxIdOrchardH_v6", b"") + blake(b"ZTxIdIronwd_H_v6", b"")
    return blake(b"ZcashTxHash_" + le32(tx["branch"]), parts)


def serialize(tx):
    return (b"".join(le32(n) for n in (tx["header"], VERSIONS[tx["version"]][1], tx["branch"], tx["lock_time"], tx["expiry"]))
            + compact(len(tx["inputs"])) + b"".join(i["outpoint"] + compact(len(i["script"])) + i["script"] + le32(i["sequence"]) for i in tx["inputs"])
            + compact(len(tx["outputs"])) + b"".join(output_bytes(o) for o in tx["outputs"])
            + bytes(3 if tx["version"] == 5 else 4))
