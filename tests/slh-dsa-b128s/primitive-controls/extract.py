#!/usr/bin/env python3
"""Extract two public, valid FIPS 205 signatures as wrong-profile controls."""

import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "reference"))
from prepare import checked, fetch

SOURCE = {
    "repository": "https://github.com/usnistgov/ACVP-Server",
    "commit": "975de31eb83d87039ec88934fdc47d8c312b892d",
    "path": "gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json",
    "sha256": "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792",
}
SELECTION = ((19, 266, "SLH-DSA-SHA2-128s"), (25, 343, "SLH-DSA-SHAKE-128s"))


def extract(data):
    document = json.loads(data)
    cases = []
    for group_id, case_id, profile in SELECTION:
        group = next(group for group in document["testGroups"] if group["tgId"] == group_id)
        if (group["parameterSet"], group["signatureInterface"], group["preHash"]) != (
            profile, "external", "pure"
        ):
            raise ValueError("selected source profile changed")
        case = next(case for case in group["tests"] if case["tcId"] == case_id)
        if case["testPassed"] is not True:
            raise ValueError("wrong-profile control must be a valid source signature")
        cases.append({
            "parameter_set": profile,
            "tg_id": group_id,
            "tc_id": case_id,
            "valid_in_source_profile": True,
            **{target: bytes.fromhex(case[source]).hex() for target, source in (
                ("public_key", "pk"), ("signature", "signature"),
                ("message", "message"), ("context", "context"),
            )},
        })
    return {"schema_version": 1, "source": SOURCE, "cases": cases}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_cache", type=Path)
    parser.add_argument("--output", type=Path, default=HERE / "wrong-profiles.json")
    args = parser.parse_args()
    prefix = SOURCE["repository"].replace("https://github.com/", "https://raw.githubusercontent.com/")
    fetch(f"{prefix}/{SOURCE['commit']}/{SOURCE['path']}", args.source_cache, SOURCE["sha256"])
    result = extract(checked(args.source_cache, SOURCE["sha256"]))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("Extracted two public external-Pure source-valid controls")
