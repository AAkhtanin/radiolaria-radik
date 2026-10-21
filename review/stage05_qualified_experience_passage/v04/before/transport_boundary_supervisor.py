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
BASE = 'review/stage05_qualified_experience_passage/v03'
SELF = BASE + '/transport_boundary_supervisor.py'
FIXTURE = BASE + '/transport_boundary_controls.py'
ACTUAL = 'TRANSPORT_BOUNDARY_V01'
OUTPUT = PROJECT / BASE / 'offline_actual' / ACTUAL / 'supervisor'
WORK = PROJECT / BASE / 'offline_actual' / ACTUAL / 'work'
MAX_SECONDS = 300
WORK_SECONDS = 260
CLEANUP_SECONDS = 30
FINAL_SECONDS = 10
NS = 10**9
STOP_NS = STARTED_NS + WORK_SECONDS * NS
HARD_NS = STARTED_NS + MAX_SECONDS * NS
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
    require(args.grant == BASE + '/transport_boundary_grant.json', 'outer_grant_path')
    grant_raw = exact(dict(path=args.grant, sha256=args.sha256))
    grant = json.loads(grant_raw)
    require(grant['reviewer'] == '/root/private_remote_controls'
        and grant['approved_executor'] == '/root' and grant['approved_invocation_count'] == 1
        and grant['actual_id'] == ACTUAL and grant['network'] == 'DENIED'
        and grant['production_writes_allowed'] is False
        and grant['real_AUTH_provider_native_E_SAVE_allowed'] is False
        and grant['automatic_retry'] is False, 'outer_independent_grant')
    require(grant['outer_supervisor_ref']['path'] == SELF
        and grant['runner_ref']['path'] == FIXTURE, 'outer_code_paths')
    exact(grant['outer_supervisor_ref'])
    exact(grant['runner_ref'])
    exact(grant['interpreter_ref'], executable=True)
    require(grant['outer_limits'] == dict(total_seconds=MAX_SECONDS,
        work_seconds=WORK_SECONDS, cleanup_seconds=CLEANUP_SECONDS,
        final_seconds=FINAL_SECONDS), 'outer_reviewed_limits')
    require(not OUTPUT.exists() and not WORK.exists(), 'outer_uncertain_retry_refused')
    OUTPUT.mkdir(parents=True, mode=0o700)
    save('reservation.json', dict(grant_sha256=args.sha256, invocation_count=1,
        automatic_retry=False, started_monotonic_ns=STARTED_NS, hard_deadline_ns=HARD_NS))
    argv = [str(PROJECT / '.venv-plan/bin/python'), '-I', '-B', FIXTURE,
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
        source_review_only=True, owner_actual=False)
    reference = save('receipt.json', receipt)
    save('completion.json', dict(receipt_ref=reference, receipt_readback_verified=True,
        stdout_readback_verified=True, child_reaped=child_reaped,
        elapsed_wall_seconds=(time.monotonic_ns()-STARTED_NS)/NS,
        hard_deadline_ns=HARD_NS, no_deadline_renewal=True))
    print('TRANSPORT_BOUNDARY_RETURN ' + json.dumps(dict(status=receipt['status'],
        child_exit_code=receipt['child_exit_code'], child_reaped=child_reaped,
        primary_stop=reason, receipt_ref=reference), sort_keys=True), flush=True)
    return 0 if receipt['status'] == 'CHILD_RETURNED_REQUIRES_INDEPENDENT_REVIEW' else 1


if __name__ == '__main__':
    raise SystemExit(main())
