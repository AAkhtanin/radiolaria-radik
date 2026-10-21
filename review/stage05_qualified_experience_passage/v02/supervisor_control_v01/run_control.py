"""Exercise the unchanged parent timing branches with one inert local child.

Only finite control constants and paths are substituted after exact source
admission. No candidate application or native module is imported by this test.
"""
import time
CONTROL_STARTED_NS = time.monotonic_ns()

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage05_qualified_experience_passage/v02'
CONTROL = BASE + '/supervisor_control_v01'
SELF = CONTROL + '/run_control.py'
CHILD = CONTROL + '/fault_child.py'
PARENT = BASE + '/taskstore_remainder_supervisor.py'
PARENT_SHA256 = '788e1d68cf67a77b68f3868c16f1a73e5af1be487d806f56043a0a239af94246'
ACTUAL = 'SUPERVISOR_FAULT_V01'
OUTPUT = PROJECT / BASE / 'offline_actual' / ACTUAL / 'supervisor'
WORK = PROJECT / BASE / 'offline_actual' / ACTUAL / 'unused_child_work'
NS = 10**9
HARD_NS = CONTROL_STARTED_NS + 45 * NS


def require(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(reference):
    path = PROJECT / reference['path']
    require(path.is_relative_to(PROJECT) and '..' not in path.parts, 'control_pin_scope')
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'control_pin_symlink')
        if parent == PROJECT:
            break
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= 1048576, 'control_pin_regular')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
        'control_pin_changed')
    require(digest(raw) == reference['sha256']
        and ('size_bytes' not in reference or len(raw) == reference['size_bytes']),
        'control_pin_hash')
    return raw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    require(args.grant == CONTROL + '/taskstore_remainder_grant.json', 'control_grant_path')
    grant = json.loads(exact(dict(path=args.grant, sha256=args.sha256)))
    require(grant['control_wrapper_ref']['path'] == SELF
        and grant['runner_ref']['path'] == CHILD
        and grant['outer_supervisor_ref']['path'] == PARENT
        and grant['outer_supervisor_ref']['sha256'] == PARENT_SHA256,
        'control_source_paths')
    exact(grant['control_wrapper_ref'])
    exact(grant['runner_ref'])
    parent_raw = exact(grant['outer_supervisor_ref'])
    require(Path(sys.executable).resolve() == (PROJECT / '.venv-plan/bin/python').resolve(),
        'control_interpreter')
    require(grant['control_scope'] == 'ONE_INERT_CHILD_IGNORES_SIGINT_SIGTERM'
        and grant['expected_child_count'] == 1, 'control_reviewed_scope')

    subject = dict(__name__='reviewed_supervisor_control_subject', __file__=str(PROJECT / PARENT))
    exec(compile(parent_raw, str(PROJECT / PARENT), 'exec'), subject)
    require((subject['MAX_SECONDS'], subject['WORK_SECONDS'], subject['CLEANUP_SECONDS'],
        subject['FINAL_SECONDS']) == (900, 830, 30, 40), 'control_original_constants')
    require(subject['PROJECT'] == PROJECT and subject['SELF'] == PARENT,
        'control_original_identity')
    substitutions = dict(BASE=CONTROL, FIXTURE=CHILD, ACTUAL=ACTUAL,
        OUTPUT=OUTPUT, WORK=WORK, MAX_SECONDS=45, WORK_SECONDS=2,
        CLEANUP_SECONDS=30, FINAL_SECONDS=13,
        STARTED_NS=CONTROL_STARTED_NS, STOP_NS=CONTROL_STARTED_NS + 2 * NS,
        HARD_NS=HARD_NS)
    subject.update(substitutions)
    require(time.monotonic_ns() < subject['STOP_NS'], 'control_preparation_cutoff')
    status = subject['main']()
    require(status == 1, 'control_expected_stop_exit')
    require(time.monotonic_ns() < HARD_NS, 'control_final_deadline')
    receipt_raw = (OUTPUT / 'receipt.json').read_bytes()
    completion_raw = (OUTPUT / 'completion.json').read_bytes()
    receipt, completion = json.loads(receipt_raw), json.loads(completion_raw)
    stdout_raw = (OUTPUT / 'child_stdout.raw').read_bytes()
    require(receipt['status'] == 'STOPPED_NO_RETRY'
        and receipt['primary_stop'] == 'OUTER_WORK_DEADLINE'
        and receipt['supervisor_error'] is None, 'control_parent_stop')
    require(receipt['child_reaped'] is True
        and receipt['child_exit_code'] == -signal.SIGKILL, 'control_killed_and_reaped')
    require([item['signal'] for item in receipt['signals']] == ['SIGINT', 'SIGTERM', 'SIGKILL'],
        'control_signal_sequence')
    first, term, kill = [item['elapsed_seconds'] for item in receipt['signals']]
    require(first >= 2 and term - first >= 9.9 and kill - first >= 14.9
        and kill - first < 30, 'control_unchanged_escalation_timing')
    require(stdout_raw == b'CONTROL_CHILD_READY_IGNORES_INT_TERM\n'
        and receipt['stdout_ref']['sha256'] == digest(stdout_raw)
        and receipt['stdout_ref']['size_bytes'] == len(stdout_raw), 'control_stdout_exact')
    require(completion['child_reaped'] is True
        and completion['receipt_readback_verified'] is True
        and completion['stdout_readback_verified'] is True
        and completion['no_deadline_renewal'] is True
        and completion['receipt_ref']['sha256'] == digest(receipt_raw)
        and completion['receipt_ref']['size_bytes'] == len(receipt_raw)
        and receipt['hard_deadline_ns'] == HARD_NS
        and completion['hard_deadline_ns'] == HARD_NS
        and completion['elapsed_wall_seconds'] < 45, 'control_final_receipt')
    result = dict(schema='radik.stage05.outer_supervisor_fault_control.v01', status='PASS',
        grant_sha256=args.sha256, control_wrapper_ref=grant['control_wrapper_ref'],
        parent_source_ref=grant['outer_supervisor_ref'], child_source_ref=grant['runner_ref'],
        tested_scope='ONE_REAL_INERT_CHILD_IGNORES_SIGINT_SIGTERM_THEN_SIGKILL_REAP_AND_PERSIST',
        parent_branches_unchanged=True, substitutions={key: str(value) if isinstance(value, Path)
            else value for key, value in substitutions.items()},
        receipt_ref=completion['receipt_ref'], completion_ref=dict(
            path=(OUTPUT / 'completion.json').relative_to(PROJECT).as_posix(),
            sha256=digest(completion_raw), size_bytes=len(completion_raw)),
        exact_child_count=1, application_imports=False, native_imports=False,
        provider_calls=0, credential_reads=False, production_writes=False,
        elapsed_wall_seconds=(time.monotonic_ns()-CONTROL_STARTED_NS)/NS)
    raw = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    require(time.monotonic_ns() < HARD_NS, 'control_result_deadline')
    path = OUTPUT / 'control_result.json'
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(path.read_bytes() == raw and time.monotonic_ns() < HARD_NS, 'control_result_readback')
    print('SUPERVISOR_FAULT_CONTROL_PASS ' + digest(raw), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
