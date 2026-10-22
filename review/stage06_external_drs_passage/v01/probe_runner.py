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
BASE = PROJECT/'review/stage06_external_drs_passage/v01'


def exact(reference):
    path = Path(reference['path'])
    path = path if path.is_absolute() else PROJECT/path
    if path.is_symlink() or not path.is_file(): raise ValueError('stage06_probe_reference_path')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != reference['sha256'] or len(raw) != reference['size_bytes']:
        raise ValueError('stage06_probe_reference_changed')
    return raw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    raw = (PROJECT/args.grant).read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.sha256: raise ValueError('stage06_probe_grant_changed')
    grant = json.loads(raw)
    if grant['reviewer'] != '/root/private_remote_controls' or grant['approved_executor'] != '/root':
        raise ValueError('stage06_probe_independent_grant')
    admission_ref = grant['probe_admission_ref']
    admission = json.loads(exact(admission_ref))
    manifest = json.loads(exact(admission['code_manifest_ref']))
    path = BASE/'owner_terminal.py'
    row = next(r for r in manifest['files'] if r['path'] == str(path))
    module = types.ModuleType('stage06_checked_owner_supervisor')
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
