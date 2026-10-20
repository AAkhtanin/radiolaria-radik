"""Read-only compatibility inspection. Does not import or admit application code."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "source" / "reference"
PINNED_COMMIT = "800f38c3407b3f4ec93dc943c977ffeecb614881"
PINNED_TREE = "d665994930e50c7f10d5f928d57ceb7aac758203"
PINNED_ORIGIN = "https://github.com/AAkhtanin/hedgehog-os.git"


def git(*args):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    return subprocess.check_output(
        ["git", "-C", str(SOURCE), *args], env=env, text=True,
        stderr=subprocess.PIPE, timeout=30,
    ).strip()


def inspect():
    before = json.loads((ROOT / "review" / "reference-before.json").read_text())
    current = {"commit": git("rev-parse", "HEAD"),
               "tree": git("rev-parse", "HEAD^{tree}"),
               "origin": git("remote", "get-url", "origin")}
    failures = []
    if current != {"commit": PINNED_COMMIT, "tree": PINNED_TREE,
                   "origin": PINNED_ORIGIN}:
        failures.append("reference_identity_changed")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        failures.append("reference_not_clean")
    paths = set(git("ls-files", "-z").split("\0")) - {""}
    if paths != set(before["files"]):
        failures.append("reference_inventory_changed")
    for relative, digest in before["files"].items():
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            failures.append("invalid_reference_inventory")
            break
        target = SOURCE / path
        if target.is_symlink() or not target.is_file():
            failures.append("reference_shape_changed:" + relative)
        elif hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            failures.append("reference_bytes_changed:" + relative)
    report_path = ROOT / "review" / "acceptance.json"
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    return {"status": "BLOCKED_WITH_CONCRETE_GAP" if not failures else "FAIL_CLOSED_REFERENCE_CHANGED",
            "project_root": str(ROOT), "reference": current,
            "reference_files_checked": len(before["files"]),
            "reference_bytes_unchanged": not failures, "failures": failures,
            "scope": "MECHANICAL_PREFLIGHT_ONLY",
            "runtime_admission": "NOT_ADMITTED",
            "model_calls": 0, "save_effects": 0,
            "blockers": report.get("blockers", []),
            "report": str(report_path)}


def main():
    parser = argparse.ArgumentParser(description="Проверка подготовки Radik; живой runtime пока не допущен.")
    parser.add_argument("--preflight", action="store_true", help="Проверить неизменность reference и показать точные blockers.")
    args = parser.parse_args()
    if not args.preflight:
        parser.error("Доступна только --preflight; совместимость runtime ещё не подтверждена.")
    try:
        result = inspect()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        result = {"status": "FAIL_CLOSED_PREFLIGHT", "error_type": type(exc).__name__,
                  "runtime_admission": "NOT_ADMITTED", "model_calls": 0, "save_effects": 0}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2


if __name__ == "__main__":
    sys.exit(main())
