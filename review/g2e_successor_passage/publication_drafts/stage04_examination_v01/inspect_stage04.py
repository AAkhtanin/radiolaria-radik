#!/usr/bin/env python3
"""Inspect Stage 4 saved data. No application imports, network, or execution.

Default: validate the exact detached index and XML reader.
--verify-evidence --root PATH: also validate all indexed primary bytes/selectors.
This is a documentation-side inspector, not the Radik runtime or a new admission.
"""
from __future__ import annotations

import argparse
from collections import Counter
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any
import xml.etree.ElementTree as ET

INDEX_SHA256 = "5cd11dc66c2a566d33e872745f289459e9b24e85c3d137821b88f92e0accaf28"
XML_SHA256 = "db26c693404dc4b69afa05f62a8d495cbbae5ffd260bc97d053cab5cc644dc14"
SOURCE_ID = "ea4a2dc46ddb9ca24b92c10c2c1d968471b0247e155d24249e60796eab9adfe0"
VERDICT = "STAGE04_CLOSED_PASS_COMPOSITE_INFORMATIONAL_SCOPE"
MAX_FILE_BYTES = 64 * 1024 * 1024

class InspectionError(ValueError):
    """A declared data binding could not be checked."""

def require(condition: bool, message: str) -> None:
    if not condition:
        raise InspectionError(message)

def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in obj, f"Duplicate JSON key: {key}")
        obj[key] = value
    return obj

def parse_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
                      parse_constant=lambda x: (_ for _ in ()).throw(
                          InspectionError(f"Nonfinite JSON value: {x}")))

def read_bytes(path: Path) -> bytes:
    require(path.is_file(), f"Required file is missing: {path}")
    require(path.stat().st_size <= MAX_FILE_BYTES, f"File exceeds inspection bound: {path}")
    raw = path.read_bytes()
    require(len(raw) <= MAX_FILE_BYTES, f"File grew beyond inspection bound: {path}")
    return raw

def pinned_bytes(path: Path, expected: str) -> bytes:
    raw = read_bytes(path)
    require(hashlib.sha256(raw).hexdigest() == expected, f"SHA-256 mismatch: {path}")
    return raw

def resolve_pointer(document: Any, pointer: str) -> Any:
    require(isinstance(pointer, str), "JSON pointer must be a string")
    if pointer == "":
        return document
    require(pointer.startswith("/"), f"Invalid JSON pointer: {pointer}")
    item = document
    for raw_token in pointer[1:].split("/"):
        require(re.search(r"~(?![01])", raw_token) is None,
                f"Invalid JSON pointer escape: {raw_token}")
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(item, list):
            require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None,
                    f"Invalid array index: {token}")
            index = int(token)
            require(index < len(item), f"Array index missing: {pointer}")
            item = item[index]
        elif isinstance(item, dict):
            require(token in item, f"Object member missing: {pointer}")
            item = item[token]
        else:
            raise InspectionError(f"Pointer descends into a scalar: {pointer}")
    return item

def check_index(index_path: Path, xml_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    index = parse_json(pinned_bytes(index_path, INDEX_SHA256))
    xml_raw = pinned_bytes(xml_path, XML_SHA256)
    require(b"<!DOCTYPE" not in xml_raw.upper() and b"<!ENTITY" not in xml_raw.upper(),
            "XML declarations with DTD/entities are not accepted")
    reader = ET.fromstring(xml_raw)
    require(index["acceptance"]["Stage04"] == VERDICT, "Unexpected Stage 4 verdict")
    require(index["acceptance"]["Stage04_complete"] is True, "Stage 4 not marked complete")
    require(index["editorial_record"] is True and index["telemetry_created"] is False,
            "Index provenance changed")
    require(index["informational_profile"]["application_source_identity_sha256"] == SOURCE_ID,
            "Unexpected application source identity")
    require(reader.findtext("status") == VERDICT, "Reader/index status mismatch")
    require(len(index["scenario_steps"]) == 20, "Expected 20 P31 commands")
    require(len(index["historical_scenario_steps"]) == 3, "Expected 3 P30 indexed episodes")
    require(len(index["claims"]) == 11 and len(index["evidence"]) == 94,
            "Unexpected claims/evidence count")
    require(len(index["coverage"]) == 10, "Unexpected coverage count")
    require(len(index["original_stage04_criteria"]) == 9, "Unexpected original criteria count")
    require(len(index["deferred"]) == 21, "Unexpected deferred register count")
    require(all(row["status"] == "accepted" for row in index["coverage"]),
            "Unaccepted current coverage row")
    ids = [e["id"] for e in index["evidence"]]
    require(len(set(ids)) == len(ids), "Duplicate evidence ID")
    xml_ids = [e.get("id") for e in reader.iter() if e.get("id") is not None]
    require(len(set(xml_ids)) == len(xml_ids), "Duplicate XML ID")
    require([e.get("id") for e in reader.findall("claim_route")] ==
            [c["id"] for c in index["claims"]], "Reader/index claim route mismatch")
    steps = index["scenario_steps"]
    xml_steps = reader.findall("scenario/step")
    require(len(xml_steps) == len(steps), "Reader/index command count mismatch")
    for step, xml_step in zip(steps, xml_steps):
        require(xml_step.get("id") == step["id"], "Reader/index order mismatch")
        require(xml_step.get("status") == step["actual_outcome"], "Reader/index outcome mismatch")
        require(int(xml_step.get("role_calls", "-1")) == step["counts"]["new_role_rows"],
                "Reader/index role count mismatch")
        require(xml_step.get("evidence") in step["evidence_refs"], "Reader/index source mismatch")
    for group in ("scenario_steps", "historical_scenario_steps", "claims", "coverage", "maintenance"):
        for record in index[group]:
            for field in ("evidence_refs", "request_input_refs"):
                require(all(e in ids for e in record.get(field, [])),
                        f"Unknown evidence ID in {group}/{record.get('id')}")
    require(sum(s["counts"]["new_role_rows"] for s in steps) == 9, "P31 role count mismatch")
    require(sum(s["counts"]["native_E_calls"] for s in steps) == 0, "P31 must not include E")
    require(sum(s["counts"]["effects"] for s in steps) == 0, "P31 effects changed")
    runs = {r["id"]: r for r in index["runs"]}
    for measurement in reader.findall("measurement"):
        run = runs[measurement.get("run")]
        for xml_key, json_key in (("owner_wall_seconds", "owner_wall_seconds"),
                                  ("native_seconds", "cumulative_native_seconds"),
                                  ("real_role_calls", "real_role_calls"),
                                  ("native_E_calls", "native_E_calls")):
            require(Decimal(measurement.get(xml_key)) == Decimal(str(run[json_key])),
                    f"Measurement mismatch: {run['id']}/{json_key}")
    require(runs["P31"]["console_ledger_after"] - runs["P31"]["console_ledger_before"] == 9,
            "Ledger delta mismatch")
    require(runs["P31"]["SAVE_calls"] == 0 and runs["P31"]["external_effects"] == 0,
            "P31 SAVE/effect count mismatch")
    require(all(c["exit_code"] == 0 and c["reaped"] is True for c in runs["P31"]["children"]),
            "Normal process closure mismatch")
    details = {
        "index_sha256": INDEX_SHA256, "reader_sha256": XML_SHA256,
        "application_source_identity_sha256": SOURCE_ID,
        "claims": len(index["claims"]), "evidence_routes": len(ids),
        "distinct_primary_paths": len({e["relative_path"] for e in index["evidence"]}),
        "p30_indexed_episodes": 3, "p31_command_steps": 20, "p31_role_calls": 9,
        "p31_outcomes": dict(Counter(s["actual_outcome"] for s in steps)),
        "current_coverage_rows": 10, "original_criteria": 9,
        "recorded_stage04_verdict": VERDICT,
    }
    return index, details

def safe_source(base: Path, relative: str, boundary: Path) -> Path:
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(),
            "Evidence path must be relative")
    candidate = base / relative
    resolved = candidate.resolve(strict=False)
    require(resolved.is_relative_to(boundary), f"Evidence path escapes root: {relative}")
    # A symlink to an in-root object is also refused: exact regular-file layout is expected.
    current = candidate
    while current != current.parent:
        require(not current.is_symlink(), f"Symlink in evidence route: {relative}")
        current = current.parent
        if current == boundary:
            break
    return resolved

def verify_routes(index: dict[str, Any], base: Path, boundary: Path) -> dict[str, Any]:
    boundary = boundary.resolve(strict=True)
    require(base.resolve().is_relative_to(boundary), "Dossier is outside declared root")
    cache: dict[Path, tuple[bytes, str, Any]] = {}
    pointers = 0
    file_ranges = 0
    for entry in index["evidence"]:
        path = safe_source(base, entry["relative_path"], boundary)
        if path not in cache:
            raw = read_bytes(path)
            cache[path] = (raw, hashlib.sha256(raw).hexdigest(), None)
        raw, digest, document = cache[path]
        require(len(raw) == entry["bytes"], f"Byte length mismatch: {entry['id']}")
        require(digest == entry["sha256"], f"Evidence SHA-256 mismatch: {entry['id']}")
        selector = entry["selector"]
        if selector["type"] == "json_pointer":
            if document is None:
                document = parse_json(raw)
                cache[path] = (raw, digest, document)
            resolve_pointer(document, selector["value"])
            pointers += 1
        elif selector["type"] == "file":
            ranges = re.findall(r"(\d+)\s*[-–]\s*(\d+)", selector["value"])
            require(bool(ranges), f"Unrecognized file selector: {entry['id']}")
            line_count = len(raw.decode("utf-8").splitlines())
            require(all(1 <= int(a) <= int(b) <= line_count for a, b in ranges),
                    f"Selected line range is missing: {entry['id']}")
            file_ranges += 1
        else:
            raise InspectionError(f"Unsupported selector: {entry['id']}")
    return {"distinct_primary_files_checked": len(cache),
            "evidence_routes_checked": len(index["evidence"]),
            "json_pointers_resolved": pointers,
            "file_range_selectors_present": file_ranges,
            "file_range_semantics_evaluated": False}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    parser.add_argument("--index", type=Path, default=here / "claims_evidence.json")
    parser.add_argument("--xml", type=Path, default=here / "READ_RADIK_STAGE04.xml")
    parser.add_argument("--verify-evidence", action="store_true")
    parser.add_argument("--root", type=Path, help="Allowed repository or extracted-return root")
    args = parser.parse_args()
    try:
        require(not args.verify_evidence or args.root is not None,
                "--verify-evidence requires --root; no unrestricted path resolution")
        index, details = check_index(args.index, args.xml)
        result: dict[str, Any] = {
            "result": "INDEX_AND_READER_CONSISTENT", **details,
            "primary_evidence_verified": False,
            "cryptographic_signatures_verified": False,
            "application_executed": False, "provider_called": False,
            "stage_acceptance_reawarded": False,
            "publication_authority_granted": False,
            "inspection_only": True,
        }
        if args.verify_evidence:
            result.update(verify_routes(index, args.index.resolve().parent, args.root))
            result["result"] = "INDEXED_EVIDENCE_BYTES_AND_SELECTORS_MATCH"
            result["primary_evidence_verified"] = True
            result["scope"] = "Exact indexed bytes and selector presence, not semantic or signature verification"
        else:
            result["scope"] = "Detached index/XML only; full primary evidence NOT checked"
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (InspectionError, OSError, ValueError, KeyError, TypeError, ET.ParseError) as exc:
        print(json.dumps({"result": "INSPECTION_INCOMPLETE_OR_FAILED", "error": str(exc),
                          "primary_evidence_verified": False,
                          "application_executed": False, "provider_called": False},
                         indent=2, ensure_ascii=True))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
