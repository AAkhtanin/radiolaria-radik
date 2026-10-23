"""Use one reviewed engineering admission through the final ordinary supervisor."""
import time
STARTED_NS = time.monotonic_ns()
STARTED_UTC = int(time.time())
import argparse
import hashlib
import json
from pathlib import Path
import types

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = PROJECT/'review/stage07_pure_capability_passage/v01'


def exact(reference):
    path = Path(reference['path'])
    path = path if path.is_absolute() else PROJECT/path
    if path.is_symlink() or not path.is_file(): raise ValueError('stage07_probe_reference_path')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != reference['sha256'] or len(raw) != reference['size_bytes']:
        raise ValueError('stage07_probe_reference_changed')
    return raw


def current_reviewer_matches(record, read_reference, binding_path):
    """Bind current grants to the owner's exact reviewer designation.

    This is a pinned local record boundary, not a cryptographic identity proof.
    Historical reviews keep their original author and are checked separately.
    """
    reference = record.get('reviewer_binding_ref')
    if type(reference) is not dict or reference.get('path') != str(binding_path):
        return False
    binding = json.loads(read_reference(reference))
    reviewer = binding.get('reviewer')
    return (binding.get('schema') == 'radik.stage07.reviewer_binding.v1'
        and binding.get('status') == 'OWNER_DESIGNATED_CURRENT_REVIEWER'
        and binding.get('scope') == 'STAGE07_V01'
        and binding.get('source_authors') == ['/root', '/root/stage05_g4_contract']
        and type(reviewer) is str and 1 <= len(reviewer) <= 160
        and reviewer.isascii()
        and all(char.isalnum() or char in '/_-.@:' for char in reviewer)
        and reviewer not in binding['source_authors']
        and reviewer != '/root/private_remote_controls'
        and record.get('reviewer') == reviewer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    raw = (PROJECT/args.grant).read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.sha256: raise ValueError('stage07_probe_grant_changed')
    grant = json.loads(raw)
    if not current_reviewer_matches(grant, exact, BASE/'reviewer_binding.json') or grant['approved_executor'] != '/root':
        raise ValueError('stage07_probe_independent_grant')
    admission_ref = grant['probe_admission_ref']
    admission = json.loads(exact(admission_ref))
    manifest = json.loads(exact(admission['code_manifest_ref']))
    path = BASE/'owner_terminal.py'
    row = next(r for r in manifest['files'] if r['path'] == str(path))
    module = types.ModuleType('stage07_checked_owner_supervisor')
    module.__file__ = str(path)
    exec(compile(exact(row), str(path), 'exec'), module.__dict__)
    reference, receipt = module.supervise(admission, admission_ref=admission_ref,
        run_directory=BASE/'offline_attempts'/grant['actual_id']/'work', mode='engineering',
        started_ns=STARTED_NS, started_utc=STARTED_UTC)
    print('ENGINEERING_RETURN '+json.dumps(dict(receipt_ref=reference,
        status=receipt['status'], owner_actual=False, model_calls=0), sort_keys=True), flush=True)
    return 0 if receipt['status'] == 'CLOSED' and receipt['primary_failure'] is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
