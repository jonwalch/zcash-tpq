"""Bounded independent checker tests; no measurement or resource sampling."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("payment_checks", HERE.parent / "payment_checks.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
W = C.WIRE

# SEC 2 generator and its first two public multiples, independent fixed answers.
PUBLICS = [bytes.fromhex(value) for value in (
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")]


def der(r, s):
    values = []
    for value in (r, s):
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] >= 128:
            raw = b"\0" + raw
        values.append(b"\x02" + bytes([len(raw)]) + raw)
    body = b"".join(values)
    return b"\x30" + bytes([len(body)]) + body


def push(raw):
    return (bytes([len(raw)]) if len(raw) <= 75 else b"\x4c" + bytes([len(raw)])) + raw


def classical(version=5, count=1, multi=False):
    keys = PUBLICS if multi else PUBLICS[:1]
    redeem = (b"\x52" if multi else b"") + b"".join(push(key) for key in keys) + (b"\x53\xae" if multi else b"\xac")
    script = b"\xa9\x14" + hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest() + b"\x87"
    previous = [{"value": 10_000_000, "script": script} for _ in range(count)]
    fee = 400 * max(2, count * (2 if multi else 1))
    tx = dict(version=version, header=0x80000000 + version, branch=C.ORACLE.NU7,
              lock_time=0, expiry=130, inputs=[dict(outpoint=bytes([i+1]) * 32 + W.le32(i), script=b"", sequence=0xffffffff) for i in range(count)],
              outputs=[dict(value=count*10_000_000-5_000_000, script=script), dict(value=5_000_000-fee, script=script)])
    unsigned = W.serialize(tx)
    messages = []
    for index, txin in enumerate(tx["inputs"]):
        message = W.input_digest(tx, previous, index)
        signatures = []
        # Public mathematical fixture, k=1 and d=1/2, not a production signer.
        for secret in range(1, 3 if multi else 2):
            r = C.G[0]
            s = (int.from_bytes(message, "big") + r * secret) % C.N
            s = min(s, C.N - s)
            signatures.append(der(r, s) + b"\x01")
        txin["script"] = (b"\0" if multi else b"") + b"".join(push(sig) for sig in signatures) + push(redeem)
        messages.append(dict(input_index=index, message_hex=message.hex()))
    return dict(schema_version=1, algorithm="ecdsa-secp256k1", version=version,
                policy="multisig" if multi else "single", input_count=count, inventory="cached",
                offline_fixture=True, trusted_utxos=False, node_acceptance=False,
                transaction_hex=W.serialize(tx).hex(), unsigned_transaction_hex=unsigned.hex(),
                previous_outputs_hex=[W.output_bytes(p).hex() for p in previous], messages=messages,
                wallet=dict(durable_write_available=False))



def structural_slh(version=5, count=2, multi=True):
    """Reframe public signatures for structural-only tests, with an exact mock."""
    source = json.loads((C.ROOT / f"tests/slh-dsa-b128s/fixtures/data/v{version}-{'2of3' if multi else '1of1'}.json").read_bytes())
    tx = W.parse_transaction(bytes.fromhex(source["transaction_hex"]))
    tx.update(lock_time=0, expiry=130)
    first = tx["inputs"][0]
    tx["inputs"] = [dict(first, outpoint=bytes([i+1]) * 32 + W.le32(i), sequence=0xffffffff) for i in range(count)]
    descriptor, records = C.ORACLE.decode_authorization(first["script"])
    lock = C.ORACLE.lock_script(descriptor)
    previous = [dict(value=10_000_000, script=lock) for _ in range(count)]
    input_bytes = sum(40 + len(W.compact(len(i["script"]))) + len(i["script"]) for i in tx["inputs"])
    fee = 400 * max(2, (input_bytes + 149) // 150, 3)
    tx["outputs"] = [dict(value=count*10_000_000-5_000_000, script=lock), dict(value=5_000_000-fee, script=lock)]
    effects = copy.deepcopy(tx)
    for item in effects["inputs"]:
        item["script"] = b""
    unsigned_hex = W.serialize(effects).hex()
    messages, accepted = [], set()
    for index in range(count):
        message = C.ORACLE.message(tx, "Regtest", previous, index)[1]
        messages.append(dict(input_index=index, message_hex=message.hex()))
        accepted.update((bytes.fromhex(r["public_key_hex"]), bytes.fromhex(r["signature_hex"]), message, b"") for r in records)
    entry = dict(role=0, policy_hex=descriptor.hex(), origins=[dict(wallet_id=bytes([i+1]).hex()*16, account=0, index=0) for i in range(3 if multi else 1)])
    change = dict(entry, role=1)
    profile = dict(network=2, genesis_hash="11"*32, nu7_branch_id="77190ad9", nu7_activation_height=2,
                   pq_activation_height=4, max_tx_pq_checks=16, max_block_pq_checks=64)
    prev_hex = [W.output_bytes(p).hex() for p in previous]
    receiver = C.FORMATS.receiver(descriptor)
    proposal = dict(format="ZcashTransparentPQ/proposal/v1", profile=profile, tip=dict(height=110,hash="22"*32),
                    transaction_hex=unsigned_hex, inputs=[dict(entry=entry, spent_output_hex=raw) for raw in prev_hex],
                    outputs=[dict(kind="payment",entry=None,receiver=receiver), dict(kind="change",entry=change,receiver=receiver)])
    artifact = dict(schema_version=1, algorithm="slh-dsa-b128s", version=version, policy="multisig" if multi else "single",
                    input_count=count, inventory="generated", offline_fixture=True, trusted_utxos=False,node_acceptance=False,
                    transaction_hex=W.serialize(tx).hex(), unsigned_transaction_hex=unsigned_hex, previous_outputs_hex=prev_hex,
                    messages=messages,wallet=dict(proposal=proposal))
    return artifact, lambda *args: args in accepted


def no_slh(*_):
    raise AssertionError("classical controls must not call SLH verifier")


def changed_transaction(artifact, mutate, rebind=False):
    result = copy.deepcopy(artifact)
    tx = W.parse_transaction(bytes.fromhex(result["transaction_hex"]))
    mutate(tx)
    result["transaction_hex"] = W.serialize(tx).hex()
    if rebind:
        effects = copy.deepcopy(tx)
        for item in effects["inputs"]:
            item["script"] = b""
        result["unsigned_transaction_hex"] = W.serialize(effects).hex()
        previous = [W.parse_output(W.Reader(bytes.fromhex(item))) for item in result["previous_outputs_hex"]]
        for index in range(len(tx["inputs"])):
            result["messages"][index]["message_hex"] = W.input_digest(tx, previous, index).hex()
    return result


class IndependentPaymentChecks(unittest.TestCase):
    def test_all_classical_versions_shapes_and_input_counts(self):
        for version in (5, 6):
            for count in (1, 2, 5):
                for multi in (False, True):
                    with self.subTest(version=version, count=count, multi=multi):
                        artifact = classical(version, count, multi)
                        result = C.evaluate(artifact, no_slh)
                        self.assertEqual(result["transaction_bytes"], len(bytes.fromhex(artifact["transaction_hex"])))
                        self.assertEqual(result["signature_checks"], count * (2 if multi else 1))
                        self.assertEqual(result["mutation_checks"], 2 * count + 2)
                        self.assertEqual(result["fee_zat"], 400 * max(2, count * (2 if multi else 1)))
                        self.assertFalse(result["node_acceptance"])

    def test_slh_structure_and_wallet_proposal_use_separate_oracles(self):
        for version in (5, 6):
            for multi in (False, True):
                artifact, verifier = structural_slh(version, 2, multi)
                checked = C.evaluate(artifact, verifier)
                self.assertTrue(checked["wallet_proposal_checked"])
                self.assertEqual(checked["signature_checks"], 4 if multi else 2)
                altered = copy.deepcopy(artifact)
                altered["wallet"]["proposal"]["transaction_hex"] += "00"
                with self.assertRaisesRegex(ValueError, "wallet proposal transaction"):
                    C.evaluate(altered, verifier)
                altered = copy.deepcopy(artifact)
                altered["wallet"]["proposal"]["outputs"][0]["receiver"] = "tpqreg1" + "q" * 62
                with self.assertRaises(ValueError):
                    C.evaluate(altered, verifier)

    def test_mutation_callback_results_are_strict_booleans_and_exceptions_escape(self):
        artifact, valid = structural_slh()
        for non_boolean in (None, 0, "", []):
            def broken(*args):
                return True if valid(*args) else non_boolean
            with self.subTest(result=repr(non_boolean)), self.assertRaisesRegex(ValueError, "mutation"):
                C.evaluate(artifact, broken)
        def broken(*args):
            if valid(*args):
                return True
            raise RuntimeError("reference failure is not rejection")
        with self.assertRaisesRegex(RuntimeError, "reference failure"):
            C.evaluate(artifact, broken)
        with self.assertRaisesRegex(ValueError, "signature rejection"):
            C.evaluate(artifact, lambda *_: None)
        with self.assertRaisesRegex(ValueError, "mutation"):
            C.evaluate(artifact, lambda *_: True)

    def test_signature_corruption_and_altered_effects_do_not_pass(self):
        initial = classical()
        def corrupt(tx):
            raw = bytearray(tx["inputs"][0]["script"])
            raw[10] ^= 1
            tx["inputs"][0]["script"] = bytes(raw)
        with self.assertRaisesRegex(ValueError, "signature rejection"):
            C.evaluate(changed_transaction(initial, corrupt), no_slh)
        def different_outpoint(tx):
            tx["inputs"][0]["outpoint"] = b"\x09" * 32 + W.le32(0)
        with self.assertRaisesRegex(ValueError, "signature rejection"):
            C.evaluate(changed_transaction(initial, different_outpoint, rebind=True), no_slh)
        with self.assertRaisesRegex(ValueError, "effects"):
            C.evaluate(changed_transaction(initial, different_outpoint), no_slh)

    def test_metadata_trust_and_schema_are_not_inferred(self):
        initial = classical()
        changes = [("trusted_utxos", True), ("node_acceptance", True), ("offline_fixture", False),
                   ("input_count", True), ("version", True), ("schema_version", True),
                   ("inventory", "warm-cpu-cache"), ("algorithm", "production-verifier")]
        for name, value in changes:
            altered = copy.deepcopy(initial)
            altered[name] = value
            with self.subTest(field=name), self.assertRaises(ValueError):
                C.evaluate(altered, no_slh)
        altered = copy.deepcopy(initial)
        altered["unexpected"] = "no silent schema extension"
        with self.assertRaises(ValueError):
            C.evaluate(altered, no_slh)
        altered = copy.deepcopy(initial)
        altered["messages"][0]["message_hex"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "message mismatch"):
            C.evaluate(altered, no_slh)

    def test_noncanonical_wire_and_previous_outputs_rejected(self):
        initial = classical()
        raw = bytes.fromhex(initial["transaction_hex"])
        initial["transaction_hex"] = (raw[:20] + b"\xfd\x01\x00" + raw[21:]).hex()
        with self.assertRaisesRegex(ValueError, "non-minimal"):
            C.evaluate(initial, no_slh)
        initial = classical()
        initial["previous_outputs_hex"][0] += "00"
        with self.assertRaisesRegex(ValueError, "previous output"):
            C.evaluate(initial, no_slh)

    def test_fee_uses_actual_encoded_size(self):
        initial = classical(6, 5, True)
        def change_fee(tx):
            tx["outputs"][1]["value"] += 400
        altered = changed_transaction(initial, change_fee, rebind=True)
        with self.assertRaisesRegex(ValueError, "fee/change"):
            C.evaluate(altered, no_slh)

    def test_classical_strict_der_key_and_push_constraints(self):
        self.assertEqual(C.classical_known_answer(), 2)
        r, s = C.G[0], C.G[0] + 1
        with self.assertRaises(ValueError):
            C.strict_der(der(r, C.N - s))
        with self.assertRaises(ValueError):
            C.strict_der(der(r, s) + b"\x00")
        with self.assertRaises(ValueError):
            C.strict_der(b"\x30\x07\x02\x02\x00\x01\x02\x01\x01")
        for key in (b"\x04" + bytes(32), b"\x02" + C.P.to_bytes(32, "big"), b"\x02" + bytes(32)):
            with self.assertRaises(ValueError):
                C.compressed_key(key)
        for raw in (b"\x4c\x01\x00", b"\x01", b"\x4d\x01\x00\x00"):
            with self.assertRaises(ValueError):
                C.pushes(raw)
        initial = classical(5, 1, True)
        def nonzero_dummy(tx):
            tx["inputs"][0]["script"] = b"\x51" + tx["inputs"][0]["script"][1:]
        with self.assertRaisesRegex(ValueError, "dummy"):
            C.evaluate(changed_transaction(initial, nonzero_dummy), no_slh)

    def test_missing_reference_and_symlink_artifacts_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaises(OSError):
                C.reference_identity(root)
            regular = root / "artifact.json"
            regular.write_bytes(b"{}")
            link = root / "link.json"
            link.symlink_to(regular)
            with self.assertRaisesRegex(ValueError, "symlink"):
                C.bounded_file(link)
            link_dir = root / "linked"
            link_dir.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                C.bounded_file(link_dir / "artifact.json")
            with self.assertRaisesRegex(ValueError, "bounded"):
                C.bounded_file(regular, 1)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):
            C.ORACLE.strict_json(b'{"schema_version":1,"schema_version":1}')


if __name__ == "__main__":
    unittest.main()
