#!/usr/bin/env python3
"""Run short isolated stdlib supervisor fault controls after independent review.

No application, native runtime, AUTH, model, or SAVE module is imported. The only
child is a finite signal fixture under this passage. Existing state is not read.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import types

BASE = Path(__file__).absolute().parent
PROJECT = BASE.parents[2]
REVIEWER = '/root/private_remote_controls'


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def pinned_modules(review_sha256):
    review_path = BASE/'supervisor_source_review.json'
    raw = review_path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == review_sha256, 'controls_review_changed')
    review = json.loads(raw)
    names = ('owner_terminal.py', 'supervisor_timing.py', 'supervisor_controls.py')
    require(review.get('schema') == 'radik.stage05.supervisor_source_review.v01'
        and review.get('reviewer') == REVIEWER
        and review.get('status') == 'SOURCE_ACCEPTED_FOR_SHORT_SUPERVISOR_CONTROLS'
        and review.get('application_execution_allowed') is False
        and set(review.get('pins', {})) == set(names), 'controls_source_review_scope')
    sources = {}
    for name in names:
        path = BASE/name
        require(not path.is_symlink() and path.is_file(), 'controls_source_file')
        sources[name] = path.read_bytes()
        require(hashlib.sha256(sources[name]).hexdigest() == review['pins'][name],
            'controls_source_changed')
    result = []
    for name in names[:2]:
        module = types.ModuleType('stage05_control_'+name[:-3])
        module.__file__ = str(BASE/name)
        exec(compile(sources[name], module.__file__, 'exec', dont_inherit=True), module.__dict__)
        result.append(module)
    return result


class UnreapedChild:
    """Deterministic kernel-wait failure fixture; never an OS process identifier."""
    def __init__(self):
        self.sent = []

    def poll(self):
        return None

    def wait(self, timeout=None):
        raise subprocess.TimeoutExpired('unreaped_fixture', timeout)

    def send_signal(self, value):
        self.sent.append(value)


def run(owner, timing, workspace):
    require(not workspace.exists() and workspace.parent == BASE/'controls_actual',
        'controls_new_owned_workspace')
    workspace.mkdir(mode=0o700)
    results = []
    started = time.monotonic_ns()
    limits = dict(timing.LIMITS, cleanup_seconds=0.45, interrupt_grace_seconds=0.1,
        terminate_grace_seconds=0.1, kill_wait_seconds=0.15)
    cleanup = timing.CleanupBoundary(started_ns=started, limits=limits)
    first = cleanup.begin(started+1)
    same = cleanup.begin(started+50_000_000)
    require(first == same == cleanup.stop_ns
        and cleanup.end_ns() == first+350_000_000, 'controls_cleanup_clock_renewed')
    results.append(dict(name='saved_stop_instant_across_paths', status='PASS',
        first_stop_ns=first, second_stop_ns=same, end_ns=cleanup.end_ns()))

    # Past cleanup budget refuses an additional window even if another finally runs.
    fake = UnreapedChild()
    expired_start = time.monotonic_ns()-2_000_000_000
    expired = timing.CleanupBoundary(started_ns=expired_start, limits=limits)
    expired.begin(expired_start)
    closed = owner.bounded_cleanup(fake, stop_ns=expired.begin(time.monotonic_ns()),
        limits=limits, signals=expired.signals, started_ns=expired_start)
    require(closed is False and not fake.sent and not expired.signals,
        'controls_expired_cleanup_resignalled')
    results.append(dict(name='expired_cleanup_does_not_restart', status='PASS',
        child_reaped=closed, signals=expired.signals))

    # The owned child ignores INT/TERM; KILL is issued only to this Popen object.
    fixture = workspace/'signal_child.py'
    fixture.write_text("import signal,time\nsignal.signal(signal.SIGINT,signal.SIG_IGN)\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nprint('READY',flush=True)\ntime.sleep(20)\n", encoding='utf-8')
    lock = workspace/'owner.lock'
    descriptor = os.open(lock, os.O_CREAT|os.O_EXCL|os.O_RDWR, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX|fcntl.LOCK_NB)
    child = None
    before = time.monotonic_ns()
    boundary = timing.CleanupBoundary(started_ns=before, limits=limits)
    try:
        child = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(fixture)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True, pass_fds=(descriptor,), start_new_session=True)
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            require(bool(ready.select(timeout=2)), 'controls_child_ready_deadline')
            require(os.read(child.stdout.fileno(), 6) == b'READY\n',
                'controls_child_not_ready')
        require(child.poll() is None, 'controls_child_exited_before_lock_check')
        require(owner.release_owned_lock(descriptor, child_started=True,
            receipt={'lock_explicit_unlock_permitted': False}) is False,
            'controls_premature_explicit_unlock')
        descriptor = None
        contender = os.open(lock, os.O_RDWR)
        try:
            try:
                fcntl.flock(contender, fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                blocked = True
            else:
                blocked = False
            require(blocked, 'controls_child_lock_not_held')
        finally:
            os.close(contender)
        stop = boundary.begin(time.monotonic_ns())
        reaped = owner.bounded_cleanup(child, stop_ns=stop, limits=limits,
            signals=boundary.signals, started_ns=before)
        second_reaped = owner.bounded_cleanup(child,
            stop_ns=boundary.begin(time.monotonic_ns()), limits=limits,
            signals=boundary.signals, started_ns=before)
        require(reaped and second_reaped and child.returncode == -signal.SIGKILL
            and [row['action'] for row in boundary.signals] == ['INTERRUPT','TERMINATE','KILL'],
            'controls_exact_child_cleanup')
        contender = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(contender, fcntl.LOCK_EX|fcntl.LOCK_NB)
            require(owner.release_owned_lock(contender, child_started=True,
                receipt={'lock_explicit_unlock_permitted': reaped}),
                'controls_lock_not_released')
            contender = None
        finally:
            if contender is not None:
                os.close(contender)
        results.append(dict(name='exact_child_signal_once_reap_then_unlock', status='PASS',
            child_pid=child.pid, child_exit_code=child.returncode, child_reaped=reaped,
            cleanup=boundary.measurement(), elapsed_seconds=(time.monotonic_ns()-before)/1e9))
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        if child is not None and child.stdout is not None:
            child.stdout.close()
        if descriptor is not None:
            os.close(descriptor)

    receipt = dict(primary_failure=None, secondary_failures=[])
    first_failure = timing.fallback('FIXTURE_PRIMARY', 'FixtureError', 'NATIVE')
    secondary = timing.fallback('FIXTURE_CLEANUP_FAILURE', 'FixtureCleanupError')
    owner.retain_failure(receipt, first_failure, timing)
    owner.retain_failure(receipt, secondary, timing)
    require(receipt['primary_failure'] == first_failure
        and receipt['secondary_failures'] == [secondary], 'controls_primary_failure_overwritten')
    results.append(dict(name='primary_cause_survives_cleanup_failure', status='PASS', **receipt))
    return dict(schema='radik.stage05.supervisor_controls.v01', status='PASS',
        control_count=len(results), controls=results, elapsed_seconds=(time.monotonic_ns()-started)/1e9,
        application_imports=0, native_calls=0, AUTH_calls=0, model_calls=0, SAVE_calls=0,
        owner_actual_started=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-review-sha256', required=True)
    parser.add_argument('--workspace-name', required=True)
    args = parser.parse_args()
    require(args.workspace_name.isascii() and args.workspace_name.replace('_','').isalnum(),
        'controls_workspace_name')
    owner, timing = pinned_modules(args.source_review_sha256)
    root = BASE/'controls_actual'
    root.mkdir(mode=0o700, exist_ok=True)
    workspace = root/args.workspace_name
    result = run(owner,timing,workspace)
    raw = canonical(result)+b'\n'
    path = workspace/'result.json'
    with path.open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    require(path.read_bytes() == raw, 'controls_result_readback')
    print(json.dumps(dict(status=result['status'],control_count=result['control_count'],
        elapsed_seconds=result['elapsed_seconds'],result_path=str(path.relative_to(PROJECT)),
        sha256=hashlib.sha256(raw).hexdigest()),sort_keys=True))


if __name__ == '__main__':
    main()
