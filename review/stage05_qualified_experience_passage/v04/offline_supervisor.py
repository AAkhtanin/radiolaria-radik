"""Own one source-admitted offline child and its nonrenewable wall-clock limit.

This stdlib supervisor imports no candidate code. Its independent clock, process
group and receipt do not depend on catchable application exceptions or cleanup.
"""
import time
STARTED_NS = time.monotonic_ns()

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage05_qualified_experience_passage/v04'
SELF = BASE + '/offline_supervisor.py'
TOTAL_SECONDS = 300
NS = 10**9
MAX_SECONDS = TOTAL_SECONDS
WORK_SECONDS = 0
CLEANUP_SECONDS = 0
FINAL_SECONDS = 0
HARD_NS = STARTED_NS + TOTAL_SECONDS*NS
STOP_NS = 0
OUTPUT = None
WORK = None
INVOCATION_REF = None
CHILD_STARTED = False
CHILD_REAPED = False
MAX_STDOUT = 33554432


def require(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def exact(reference, *, executable=False):
    path = Path(reference['path'])
    path = path if path.is_absolute() else PROJECT / path
    require(path.is_relative_to(PROJECT) and '..' not in path.parts, 'outer_pin_scope')
    if executable:
        require(path == PROJECT / '.venv-plan/bin/python', 'outer_interpreter_path')
        raw = path.read_bytes()
    else:
        for parent in (path, *path.parents):
            require(not parent.is_symlink(), 'outer_pin_symlink')
            if parent == PROJECT:
                break
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= 67108864, 'outer_pin_regular')
            raw = stream.read(before.st_size + 1)
            after = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(identity(before) == identity(after) and len(raw) == before.st_size,
            'outer_pin_changed')
    require(digest(raw) == reference['sha256']
        and ('size_bytes' not in reference or len(raw) == reference['size_bytes']), 'outer_pin_hash')
    return raw


def save(name, value):
    require(time.monotonic_ns() < HARD_NS, 'outer_final_deadline')
    raw = canonical(value)
    path = OUTPUT / name
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(path.read_bytes() == raw, 'outer_final_readback')
    return dict(path=path.relative_to(PROJECT).as_posix(), sha256=digest(raw), size_bytes=len(raw))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    global MAX_SECONDS, WORK_SECONDS, CLEANUP_SECONDS, FINAL_SECONDS, HARD_NS, STOP_NS, OUTPUT, WORK
    global INVOCATION_REF, CHILD_STARTED, CHILD_REAPED
    require(args.grant.startswith(BASE + '/grants/') and args.grant.endswith('.json')
        and '..' not in Path(args.grant).parts, 'outer_grant_path')
    actual = Path(args.grant).stem
    require(type(actual) is str and 1 <= len(actual) <= 80
        and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for c in actual), 'outer_actual_id')
    actual_root = PROJECT / BASE / 'offline_actual'
    OUTPUT = actual_root / actual / 'supervisor'; WORK = actual_root / actual / 'work'
    require(not (actual_root / actual).exists(), 'outer_uncertain_retry_refused')
    OUTPUT.mkdir(parents=True, mode=0o700)
    INVOCATION_REF = save('invocation.json', dict(
        schema='radik.stage05.offline_invocation.v01', actual_id=actual,
        grant_path=args.grant, grant_sha256=args.sha256,
        started_monotonic_ns=STARTED_NS, automatic_retry=False,
        status='PREPARATION_ENTERED_REQUIRES_CLOSED_ACCOUNTING'))
    grant_raw = exact(dict(path=args.grant, sha256=args.sha256))
    grant = json.loads(grant_raw)
    require(grant['reviewer'] == '/root/private_remote_controls'
        and grant['approved_executor'] == '/root' and grant['approved_invocation_count'] == 1
        and grant['network'] == 'DENIED'
        and grant['production_writes_allowed'] is False
        and grant['real_AUTH_provider_native_E_SAVE_allowed'] is False
        and grant['automatic_retry'] is False, 'outer_independent_grant')
    require(grant['actual_id'] == actual, 'outer_grant_actual_binding')
    provisional_used = grant['prior_charged_ns']
    provisional_limit = grant['outer_limits']['total_seconds']
    require(type(provisional_used) is int and 0 <= provisional_used < TOTAL_SECONDS*NS
        and type(provisional_limit) is int and 0 < provisional_limit*NS <= TOTAL_SECONDS*NS-provisional_used,
        'outer_provisional_remaining_budget')
    HARD_NS = STARTED_NS + provisional_limit*NS
    require(type(actual) is str and 1 <= len(actual) <= 80
        and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for c in actual), 'outer_actual_id')
    fixture = grant['runner_ref']['path']
    require(grant['outer_supervisor_ref']['path'] == SELF and fixture.startswith(BASE + '/')
        and fixture.endswith('.py') and '..' not in Path(fixture).parts, 'outer_code_paths')
    exact(grant['outer_supervisor_ref'])
    exact(grant['runner_ref'])
    exact(grant['interpreter_ref'], executable=True)
    prior_refs = grant['prior_execution_review_refs']
    require(type(prior_refs) is list and len(prior_refs) <= 64, 'outer_budget_history')
    used_ns = 0
    prior_ids = []
    for reference in prior_refs:
        require(reference['path'].startswith(BASE + '/execution_accounting/')
            and reference['path'].endswith('.json'), 'outer_prior_accounting_path')
        previous = json.loads(exact(reference))
        identity = previous['actual_id']
        require(identity not in prior_ids and identity != actual
            and previous['schema'] == 'radik.stage05.offline_execution_accounting.v01'
            and previous['reviewer'] == '/root/private_remote_controls'
            and previous['status'] == 'CLOSED_EXECUTION_ACCOUNTED'
            and previous['total_budget_seconds'] == TOTAL_SECONDS
            and previous['prior_execution_review_refs'] == prior_refs[:len(prior_ids)]
            and previous['prior_charged_ns'] == used_ns
            and previous['closure_confirmed'] is True and previous['full_readback_verified'] is True
            and previous['final_tool_outcome_observed'] is True
            and type(previous['charged_execution_ns']) is int
            and 0 < previous['charged_execution_ns'] <= TOTAL_SECONDS*NS-used_ns
            and previous['cumulative_charged_ns'] == used_ns+previous['charged_execution_ns'],
            'outer_budget_prior_incomplete')
        invocation = json.loads(exact(previous['invocation_ref']))
        require(invocation['actual_id'] == identity
            and invocation['grant_sha256'] == previous['grant_ref']['sha256'], 'outer_prior_invocation')
        exact(previous['grant_ref'])
        require(type(previous['evidence_refs']) is list and previous['evidence_refs'],
            'outer_prior_closed_evidence')
        for evidence in previous['evidence_refs']:
            require(evidence['path'].startswith(BASE + '/offline_actual/' + identity + '/'),
                'outer_prior_evidence_scope')
            exact(evidence)
        used_ns += previous['charged_execution_ns']
        prior_ids.append(identity)
    actual_root = PROJECT / BASE / 'offline_actual'
    observed_ids = set()
    if actual_root.exists():
        require(actual_root.is_dir() and not actual_root.is_symlink(), 'outer_budget_root')
        for item in actual_root.iterdir():
            require(item.is_dir() and not item.is_symlink(), 'outer_budget_unknown_entry')
            observed_ids.add(item.name)
    require(observed_ids == set(prior_ids) | {actual}, 'outer_budget_unaccounted_run')
    require(grant['total_budget_seconds'] == TOTAL_SECONDS
        and grant['prior_charged_ns'] == used_ns, 'outer_budget_cannot_reset')
    limits = grant['outer_limits']
    require(type(limits) is dict and set(limits) == {'total_seconds','work_seconds','cleanup_seconds','final_seconds'}
        and all(type(n) is int and n > 0 for n in limits.values())
        and limits['total_seconds'] == sum(limits[k] for k in ('work_seconds','cleanup_seconds','final_seconds'))
        and limits['cleanup_seconds'] <= 30 and limits['final_seconds'] >= 5
        and limits['total_seconds']*NS <= TOTAL_SECONDS*NS-used_ns, 'outer_reviewed_limits')
    MAX_SECONDS = limits['total_seconds']; WORK_SECONDS = limits['work_seconds']
    CLEANUP_SECONDS = limits['cleanup_seconds']; FINAL_SECONDS = limits['final_seconds']
    HARD_NS = STARTED_NS + MAX_SECONDS*NS; STOP_NS = STARTED_NS + WORK_SECONDS*NS
    require(time.monotonic_ns() < STOP_NS, 'outer_preparation_deadline')
    OUTPUT = actual_root / actual / 'supervisor'; WORK = actual_root / actual / 'work'
    require(OUTPUT.is_dir() and not WORK.exists(), 'outer_uncertain_retry_refused')
    save('reservation.json', dict(grant_sha256=args.sha256, invocation_count=1,
        automatic_retry=False, started_monotonic_ns=STARTED_NS, hard_deadline_ns=HARD_NS,
        actual_id=actual, prior_execution_review_refs=prior_refs, prior_charged_ns=used_ns,
        total_budget_seconds=TOTAL_SECONDS))
    argv = [str(PROJECT / '.venv-plan/bin/python'), '-I', '-B', fixture,
        '--grant', args.grant, '--sha256', args.sha256]
    child = None
    selector = selectors.DefaultSelector()
    stdout_path = OUTPUT / 'child_stdout.raw'
    raw_hash = hashlib.sha256()
    size = 0
    eof = False
    stop_ns = None
    reason = None
    signals = []
    supervisor_error = None

    def signal_child(sig, name):
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                child.poll()
            else:
                signals.append(dict(signal=name, elapsed_seconds=(time.monotonic_ns()-STARTED_NS)/NS))

    def drain(stream, timeout):
        nonlocal size, eof
        for key, _ in selector.select(timeout):
            raw = os.read(key.fd, 65536)
            if not raw:
                eof = True
                selector.unregister(key.fileobj)
                continue
            require(size + len(raw) <= MAX_STDOUT, 'outer_stdout_bound')
            stream.write(raw)
            stream.flush()
            raw_hash.update(raw)
            size += len(raw)

    with stdout_path.open('xb') as stream:
        try:
            require(time.monotonic_ns() < STOP_NS, 'outer_preparation_deadline')
            child = subprocess.Popen(argv, cwd=PROJECT, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'})
            CHILD_STARTED = True
            os.set_blocking(child.stdout.fileno(), False)
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                now = time.monotonic_ns()
                if stop_ns is None and now >= STOP_NS:
                    stop_ns, reason = now, 'OUTER_WORK_DEADLINE'
                    signal_child(signal.SIGINT, 'SIGINT')
                if stop_ns is not None:
                    elapsed = (now-stop_ns)/NS
                    names = {item['signal'] for item in signals}
                    if elapsed >= 10 and 'SIGTERM' not in names:
                        signal_child(signal.SIGTERM, 'SIGTERM')
                    if elapsed >= 15 and 'SIGKILL' not in names:
                        signal_child(signal.SIGKILL, 'SIGKILL')
                    if elapsed >= CLEANUP_SECONDS:
                        break
                if child.poll() is not None and eof:
                    break
                drain(stream, 0.05)
        except BaseException as error:
            supervisor_error = dict(error_class=type(error).__name__,
                code='OUTER_SUPERVISOR_FAILURE', raw_error_recorded=False)
            reason = reason or 'OUTER_SUPERVISOR_FAILURE'
        finally:
            cleanup_started = time.monotonic_ns() if stop_ns is None else stop_ns
            cleanup_deadline = min(cleanup_started + CLEANUP_SECONDS * NS,
                HARD_NS - FINAL_SECONDS * NS)
            if child is not None:
                if child.poll() is None:
                    signal_child(signal.SIGKILL, 'SIGKILL')
                remaining = max(0, (cleanup_deadline-time.monotonic_ns())/NS)
                try:
                    child.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    reason = 'OUTER_CHILD_REAP_UNCONFIRMED'
                try:
                    while not eof and time.monotonic_ns() < cleanup_deadline:
                        drain(stream, 0.02)
                except BaseException as error:
                    reason = reason or 'OUTER_STDOUT_DRAIN_FAILURE'
                    supervisor_error = supervisor_error or dict(error_class=type(error).__name__,
                        code='OUTER_STDOUT_DRAIN_FAILURE', raw_error_recorded=False)
                CHILD_REAPED = child.returncode is not None
                child.stdout.close()
            selector.close()
            stream.flush()
            os.fsync(stream.fileno())
    require(time.monotonic_ns() < HARD_NS, 'outer_final_deadline')
    raw = stdout_path.read_bytes()
    require(len(raw) == size and digest(raw) == raw_hash.hexdigest(), 'outer_stdout_readback')
    child_reaped = child is not None and child.returncode is not None
    receipt = dict(schema='radik.stage05.offline_outer_receipt.v01',
        status='CHILD_RETURNED_REQUIRES_INDEPENDENT_REVIEW' if child_reaped and child.returncode == 0
            and reason is None else 'STOPPED_NO_RETRY',
        grant_sha256=args.sha256, argv=argv, automatic_retry=False,
        outer_limits=grant['outer_limits'], preparation_included=True,
        started_monotonic_ns=STARTED_NS, hard_deadline_ns=HARD_NS,
        elapsed_wall_seconds=(time.monotonic_ns()-STARTED_NS)/NS,
        child_pid=None if child is None else child.pid, child_reaped=child_reaped,
        child_exit_code=None if child is None else child.returncode,
        primary_stop=reason, supervisor_error=supervisor_error, signals=signals,
        stdout_ref=dict(path=stdout_path.relative_to(PROJECT).as_posix(),
            sha256=raw_hash.hexdigest(), size_bytes=size),
        offline_candidate_control=True, owner_actual=False, actual_id=actual,
        prior_charged_ns=used_ns, total_budget_seconds=TOTAL_SECONDS)
    reference = save('receipt.json', receipt)
    # Charge the measured parent interval plus a five-second final readback
    # reserve. A later grant cannot reclaim this conservative closing charge.
    charged_ns = min(MAX_SECONDS*NS, time.monotonic_ns()-STARTED_NS + 5*NS)
    require(charged_ns + used_ns <= TOTAL_SECONDS*NS, 'outer_cumulative_budget_exhausted')
    completion_ref = save('completion.json', dict(
        schema='radik.stage05.cumulative_offline_completion.v01', actual_id=actual,
        receipt_ref=reference, receipt_readback_verified=True,
        stdout_readback_verified=True, child_reaped=child_reaped,
        elapsed_wall_seconds=(time.monotonic_ns()-STARTED_NS)/NS,
        charged_execution_ns=charged_ns, closing_readback_reserve_seconds=5,
        prior_execution_review_refs=prior_refs, prior_charged_ns=used_ns,
        cumulative_charged_ns=used_ns+charged_ns, total_budget_seconds=TOTAL_SECONDS,
        hard_deadline_ns=HARD_NS, no_deadline_renewal=True))
    exact(completion_ref)
    require(time.monotonic_ns()-STARTED_NS <= charged_ns, 'outer_closing_readback_overrun')
    print('OFFLINE_CONTROL_RETURN ' + json.dumps(dict(status=receipt['status'],
        child_exit_code=receipt['child_exit_code'], child_reaped=child_reaped,
        primary_stop=reason, receipt_ref=reference, completion_ref=completion_ref,
        cumulative_charged_ns=used_ns+charged_ns), sort_keys=True), flush=True)
    return 0 if receipt['status'] == 'CHILD_RETURNED_REQUIRES_INDEPENDENT_REVIEW' else 1


if __name__ == '__main__':
    try:
        result_code = main()
    except BaseException as error:
        # A preparation failure is retained even before a child exists. Only an
        # independent review of the final tool outcome may charge and close it.
        if OUTPUT is not None and INVOCATION_REF is not None:
            raw = canonical(dict(schema='radik.stage05.offline_parent_failure.v01',
                invocation_ref=INVOCATION_REF, error_type=type(error).__name__,
                raw_error_recorded=False, child_started=CHILD_STARTED,
                child_reaped=CHILD_REAPED,
                elapsed_wall_ns=time.monotonic_ns()-STARTED_NS))
            with (OUTPUT/'parent_failure.json').open('xb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            require((OUTPUT/'parent_failure.json').read_bytes() == raw, 'outer_failure_readback')
        raise
    raise SystemExit(result_code)
