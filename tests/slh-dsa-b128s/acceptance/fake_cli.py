"""Strict offline test double for public command assembly, never cryptography.

Only test_acceptance imports this. No subprocess/network/terminal API is used.
Revision, canonical transport and local-origin checks model the existing public
CLI boundary so tests catch mistakes in complete driver flows.
"""
import copy
import hashlib
from pathlib import Path

from common import canonical, fingerprint, read_json, require, write_json
from wallet_live import PARTIAL_FORMAT, key_commitment, reference


class FakeCli:
    def __init__(self, nodes):
        self.oracle = reference()
        self.nodes = nodes
        self.wallets, self.watches, self.snapshots = {}, {}, {}
        self.calls = []
        self.counter = 0

    def result(self, value):
        return canonical(value)

    def canonical_file(self, path):
        raw = Path(path).read_bytes()
        return self.oracle.canonical(raw, 262144)

    def write_backup(self, path, manifest):
        path = Path(path)
        path.write_bytes(b"fake encrypted backup, no key material")
        path.chmod(0o600)
        self.wallets[path] = copy.deepcopy(manifest)

    def restored(self, manifest):
        self.counter += 1
        return dict(manifest, allocator_id=f"{self.counter:032x}", revision=manifest["revision"] + 1,
                    retired_receive_end=manifest["receive_end"], retired_change_end=manifest["change_end"])

    def __call__(self, command, *args, secret=False, success=True, prompts=None):
        expected = {"create-slh-exp": 2, "inspect": 1, "export": 2, "key-export": 4, "enroll": 4,
                    "watch-create": 4, "propose": 5, "review": 5, "sign": 7, "assemble": 6,
                    "payment-history-export": 3, "snapshot-save": 3, "restore": 3,
                    "sync": 3, "receive": 1, "status": 1, "watch-import": 3,
                    "refresh-propose": 5, "refresh-review": 5, "refresh-approve": 6, "submit": 4, "payments": 2}
        if command in expected:
            require(len(args) == expected[command], "fake_cli_arity_" + command)
        elif command == "enroll-prepare":
            require(6 <= len(args) <= 34 and len(args) % 2 == 0, "fake_enrollment_arity")
        elif command == "snapshot-restore":
            require(len(args) in (3, 5), "fake_snapshot_arity")
        else:
            raise AssertionError(command)
        self.calls.append(command)
        if command == "create-slh-exp":
            self.counter += 1
            manifest = dict(self.oracle.sample_manifest(), wallet_id=f"{self.counter:032x}",
                            allocator_id=f"{1000 + self.counter:032x}", entries=[], receive_end=0, change_end=0)
            self.write_backup(args[0], manifest)
            return b"created"
        if command == "inspect":
            return self.result(self.wallets[Path(args[0])])
        if command == "export":
            write_json(args[1], self.wallets[Path(args[0])])
            return b"exported"
        if command == "key-export":
            manifest = self.wallets[Path(args[0])]
            role = 0 if args[1] == "receive" else 1
            key = hashlib.sha256(canonical([manifest["wallet_id"], role, args[2]])).hexdigest()
            exchange = {"format": "ZcashTransparentPQ/experimental/slh-dsa-b-128s/key-exchange/v1",
                "index": args[2], "role": role, "profile": manifest["profile"],
                "suite": 247, "wallet_id": manifest["wallet_id"], "public_key_hex": key}
            write_json(args[3], exchange)
            digest = hashlib.sha256(b"ZcashTransparentPQ/experimental/slh-dsa-b-128s/key-exchange/v1\0"
                                    + canonical(exchange)).hexdigest()
            return self.result({"exchange": exchange, "fingerprint": digest})
        if command == "enroll-prepare":
            manifest, role = self.canonical_file(args[0]), 0 if args[1] == "receive" else 1
            public = [self.canonical_file(path) for path in args[4::2]]
            public.sort(key=lambda item: key_commitment(bytes.fromhex(item["public_key_hex"])))
            entry = {"role": role, "policy_hex": self.oracle.policy(args[2],
                [bytes.fromhex(item["public_key_hex"]) for item in public]).hex(),
                "origins": [{"account": 0, "index": item["index"], "wallet_id": item["wallet_id"]} for item in public]}
            manifest["entries"].append(entry)
            manifest["entries"].sort(key=lambda item: (item["role"], next(origin["index"]
                for origin in item["origins"] if origin["wallet_id"] == manifest["wallet_id"])))
            manifest["receive_end" if role == 0 else "change_end"] += 1
            manifest["revision"] += 1
            self.oracle.check_manifest(manifest)
            write_json(args[3], manifest)
            return self.result({"inventory": manifest, "fingerprint": fingerprint(manifest), "threshold": args[2]})
        if command == "enroll":
            original = self.wallets[Path(args[0])]
            candidate = self.canonical_file(args[1])
            require(candidate["revision"] == original["revision"] + 1, "fake_enrollment_revision")
            require(args[2] == fingerprint(candidate), "fake_enrollment_fingerprint")
            self.oracle.check_manifest_update(original, candidate)
            self.write_backup(args[3], candidate)
            return b"enrolled"
        if command == "watch-create":
            inventory = self.canonical_file(args[0])
            require(args[1] == fingerprint(inventory), "fake_pairing")
            path = Path(args[2]); path.mkdir(mode=0o700)
            self.watches[path] = {"manifest": inventory, "mode": args[3], "partials": [], "raw": None,
                                  "receive_next": inventory["retired_receive_end"], "proposal": None, "balance": 3_000_000}
            return self.result({"mode": args[3]})
        if command == "watch-import":
            watch = self.watches[Path(args[0])]
            candidate = self.canonical_file(args[1])
            self.oracle.check_manifest_update(watch["manifest"], candidate)
            require(args[2] == fingerprint(candidate), "fake_import_fingerprint")
            watch["manifest"] = candidate
            return b"imported"
        if command == "submit":
            require(self.watches[Path(args[1])]["mode"] == "monitor" and not success,
                    "fake_monitor_submission")
            return b"this watcher does not own the receiver allocator"
        if command == "payments":
            require(self.watches[Path(args[0])]["proposal"] is None, "fake_missing_key_has_authorization")
            return b"[]"
        if command in ("propose", "review"):
            manifest = self.wallets[Path(args[0])]
            intent = self.canonical_file(args[3])
            policy = bytes.fromhex(manifest["entries"][0]["policy_hex"])
            auth = self.oracle.authorization_bytes(policy[2], policy[3])
            size = 36 + len(self.oracle.compact_size(auth)) + auth + 4
            fee = max(2, (size + 149) // 150) * 400
            value = self.watches[Path(args[1])]["balance"]
            change = value - intent["amount"] - fee
            change_entry = next(entry for entry in manifest["entries"] if entry["role"] == 1)
            proposal = {"inputs": [{"entry": manifest["entries"][0]}], "outputs": [{"entry": None}],
                        "transaction_hex": "00", "tip": {"height": self.nodes[0].tip()[0], "hash": self.nodes[0].tip()[1]}}
            if change:
                proposal["outputs"].append({"entry": change_entry})
            if command == "propose":
                write_json(args[4], proposal)
            else:
                require(self.canonical_file(args[4]) == proposal, "fake_proposal")
            watch = self.watches[Path(args[1])]
            if watch["proposal"] != proposal:
                watch.update(proposal=proposal, partials=[], raw=None)
            identifier = hashlib.sha256(canonical(proposal)).hexdigest()
            local = next(origin["index"] for origin in change_entry["origins"] if origin["wallet_id"] == manifest["wallet_id"])
            review = {"checks": policy[2], "fee": fee, "conventional_fee": fee,
                "final_bytes": self.oracle.transaction_bytes(intent["version"], [(policy[2], policy[3])], 2 if change else 1),
                "proposal_id": identifier, "local_change": {"local_index": local, "advancement": None} if change else None,
                "change_value": change, "version": intent["version"], "tip": proposal["tip"], "expiry_height": 130}
            watch["review"] = review
            return self.result(review)
        if command in ("refresh-propose", "refresh-review", "refresh-approve"):
            watch = self.watches[Path(args[1])]
            proposal = copy.deepcopy(watch["proposal"])
            proposal["tip"] = {"height": self.nodes[0].tip()[0], "hash": self.nodes[0].tip()[1]}
            identifier = hashlib.sha256(canonical(proposal)).hexdigest()
            review = dict(watch["review"], proposal_id=identifier, tip=proposal["tip"])
            if command == "refresh-propose":
                write_json(args[4], proposal)
            else:
                require(self.canonical_file(args[4]) == proposal, "fake_refresh_proposal")
            if command == "refresh-approve":
                if args[5] != identifier:
                    require(not success, "fake_refresh_wrong_approval")
                    return b"proposal, approved intent or partial authorization does not match"
                watch["partials"] = [dict(partial, proposal_id=identifier) for partial in watch["partials"]]
                watch.update(proposal=proposal, review=review)
            return self.result(review)
        if command == "sign":
            proposal = self.canonical_file(args[4])
            identifier = hashlib.sha256(canonical(proposal)).hexdigest()
            if args[5] != identifier:
                require(not success, "fake_unapproved_success")
                return b"proposal, approved intent or partial authorization does not match"
            manifest = self.wallets[Path(args[0])]
            directory = Path(args[6]); directory.mkdir(mode=0o700)
            watch = self.watches[Path(args[1])]
            for index, item in enumerate(proposal["inputs"]):
                slot = next(slot for slot, origin in enumerate(item["entry"]["origins"])
                            if origin["wallet_id"] == manifest["wallet_id"])
                origin = item["entry"]["origins"][slot]
                key = hashlib.sha256(canonical([manifest["wallet_id"], 0, origin["index"]])).hexdigest()
                partial = {"input_index": index, "signer_index": slot, "format": PARTIAL_FORMAT,
                           "proposal_id": identifier, "public_key_hex": key, "signature_hex": "55" * 7856}
                write_json(directory / f"input-{index:04}-signer-{slot:02}.json", partial)
                if partial not in watch["partials"]:
                    watch["partials"].append(partial)
            watch["proposal"] = proposal
            return b"signed"
        if command == "assemble":
            proposal = self.canonical_file(args[4])
            policy = bytes.fromhex(proposal["inputs"][0]["entry"]["policy_hex"])
            if len(list(Path(args[5]).iterdir())) != policy[2]:
                require(not success, "fake_subquorum_success")
                return b"not enough distinct partials for every input threshold"
            intent = self.canonical_file(args[3])
            size = self.oracle.transaction_bytes(intent["version"], [(policy[2], policy[3])], len(proposal["outputs"]))
            self.watches[Path(args[1])]["raw"] = "00" * size
            return b"assembled"
        if command == "payment-history-export":
            watch = self.watches[Path(args[0])]
            directory = Path(args[2]); directory.mkdir(mode=0o700)
            write_json(directory / "proposal.json", watch["proposal"])
            write_json(directory / "payment.json", {"mode": watch["mode"]})
            for partial in watch["partials"]:
                write_json(directory / f'input-{partial["input_index"]:04}-signer-{partial["signer_index"]:02}.json', partial)
            if watch["raw"]:
                (directory / "signed-transaction.hex").write_text(watch["raw"])
            write_json(directory / "complete.json", {"format": "ZcashTransparentPQ/payment-export/v1"})
            return b"exported"
        if command == "snapshot-save":
            directory = Path(args[2]); directory.mkdir(mode=0o700)
            self.snapshots[directory] = copy.deepcopy(self.watches[Path(args[1])])
            return self.result({"receipt_fingerprint": "11" * 32, "receipt": {"journal": {"generation": 1}}})
        if command in ("restore", "snapshot-restore"):
            if command == "restore":
                manifest = self.wallets[Path(args[0])]
                watch = {"manifest": manifest, "partials": [], "raw": None, "proposal": None, "balance": 3_000_000}
                directory, mode, authority = Path(args[2]), "monitor", "unknown"
            else:
                watch = copy.deepcopy(self.snapshots[Path(args[0])])
                manifest = watch["manifest"]
                directory, authority = Path(args[1]), args[2]
                mode = "allocator" if authority == "known" else "monitor"
            directory.mkdir(mode=0o700)
            manifest = self.restored(manifest)
            self.write_backup(directory / "backup-restored.tpq", manifest)
            (directory / "watch").mkdir(mode=0o700)
            watch.update(manifest=manifest, mode=mode, receive_next=manifest["retired_receive_end"])
            self.watches[directory / "watch"] = watch
            return self.result({"mode": mode, "authority": authority})
        if command in ("sync", "status"):
            watch = self.watches[Path(args[0])]
            return self.result({"mode": watch["mode"], "scan": {"complete_at_checkpoint": True,
                "checkpoint": {"height": self.nodes[0].tip()[0], "hash": self.nodes[0].tip()[1]},
                "confirmed_zatoshis": watch["balance"]}})
        if command == "receive":
            watch = self.watches[Path(args[0])]
            manifest = watch["manifest"]
            if watch["mode"] == "monitor" or watch["receive_next"] == manifest["receive_end"]:
                require(not success, "fake_receive_authority")
                return b"rejected"
            entry = manifest["entries"][watch["receive_next"]]
            watch["receive_next"] += 1
            return self.oracle.receiver(bytes.fromhex(entry["policy_hex"])).encode("ascii")
        raise AssertionError(command)
