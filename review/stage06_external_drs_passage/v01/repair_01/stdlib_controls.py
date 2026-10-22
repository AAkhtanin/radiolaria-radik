"""Isolated supervisor fault controls; no application, native or owner entry.

Exact reviewed stdlib-only sources are pinned before compilation. Each case
substitutes admission loading and uses one disposable stdlib sleeping child.
The actual supervisor failure/finally path, journal writer and cleanup run.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import types

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = PROJECT/'review/stage06_external_drs_passage/v01'
HERE = BASE/'repair_01'


def require(ok, label):
    if not ok:
        raise AssertionError(label)


def load_sources(review):
    sources = {}
    for row in review['source_refs']:
        path = Path(row['path'])
        require(path.is_relative_to(PROJECT) and not path.is_symlink(), 'source_scope')
        raw = path.read_bytes()
        require(len(raw) == row['size_bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
            'source_pin')
        sources[row['name']] = (path, raw)
    require(sources['controls'][0] == Path(__file__).absolute(), 'self_pin')
    return sources


def module(sources, name):
    path, raw = sources[name]
    value = types.ModuleType('isolated_stage06_'+name)
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec', dont_inherit=True), value.__dict__)
    return value


def case(sources, root, code, fault):
    root.mkdir(mode=0o700)
    owner = module(sources, 'owner')
    adapter = module(sources, 'adapter')
    timing = module(sources, 'timing')
    legacy = module(sources, 'legacy')
    owner.PROJECT = legacy.PROJECT = root
    owner.BASE = root/'stage06'
    owner.CANDIDATE = root/'unused_candidate'
    owner.LOCK = root/'control.lock'
    owner.LOCK.write_bytes(b'')
    owner.LOCK.chmod(0o600)
    owner._SOURCE_PINS = {str(sources['owner'][0]): dict(sha256=hashlib.sha256(sources['owner'][1]).hexdigest())}
    attempt = owner.BASE/'offline_attempts'/'CONTROL'
    attempt.mkdir(parents=True)
    run = attempt/'work'
    limits = dict(operation_seconds=10, native_seconds=20, early_checkpoint_seconds=2,
        semantic_idle_seconds=3, cleanup_seconds=20, interrupt_grace_seconds=10,
        terminate_grace_seconds=5, kill_wait_seconds=5, model_wait_seconds=600)
    admission = dict(limits=limits, live_guards=[], task_selector='isolated_stdlib_control',
        code_manifest_ref={'control_only': True}, interpreter_ref={'path': sys.executable})
    admission_ref = dict(path=str(root/'synthetic_admission.json'), sha256='0'*64, size_bytes=0)
    scenario = dict(producer_input={}, recipient_input={})
    events, spawned, clocks, stops = [], [], [], []
    original_clock = adapter.OperationClock

    def make_clock(*args, **kwargs):
        clock = original_clock(*args, **kwargs)
        original_stop = clock.stop
        def stop(reason, now_ns=None):
            result = original_stop(reason, now_ns)
            stops.append(dict(requested=reason, stop_ns=clock.stop_ns, stop_reason=clock.stop_reason))
            return result
        clock.stop = stop
        clocks.append(clock)
        return clock
    adapter.OperationClock = make_clock
    owner.load_admission = lambda *args, **kwargs: (admission, {}, scenario, adapter, timing, legacy)
    original_popen = subprocess.Popen
    original_put = legacy.put
    original_read = owner.read_ref
    original_fsync = os.fsync
    original_cleanup = legacy.bounded_cleanup
    writing = [False]
    persistence_attempts = [0]

    def popen(argv, **kwargs):
        require(len(spawned) == 0, 'only_one_stdlib_child')
        child = original_popen([sys.executable, '-I', '-S', '-B', '-c',
            'import time; time.sleep(15)'], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=False, bufsize=0,
            env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})
        spawned.append(child)
        clock = clocks[0]
        if code == 'STAGE06_OPERATION_LIMIT':
            clock.deadline_ns = clock.started_ns
        elif code == 'STAGE06_NATIVE_LIMIT':
            clock.peer_intervals['producer_1']['started_ns'] = clock.started_ns-21*10**9
        elif code == 'STAGE06_EARLY_CHECKPOINT_TIMEOUT':
            clock.first_native_ns = clock.started_ns-2*10**9
        elif code == 'STAGE06_SEMANTIC_IDLE_LIMIT':
            clock.first_native_ns = clock.started_ns-3*10**9
            clock.first_checkpoint_ns = clock.first_native_ns
            clock.last_checkpoint_ns = clock.first_native_ns
        else:
            raise AssertionError('finite_limit_case')
        return child

    def fsync(fd):
        result = original_fsync(fd)
        if writing[0]:
            events.append('first_failure_fsync')
        return result

    def put(path, value, **kwargs):
        if path.name != 'first_failure.json':
            return original_put(path, value, **kwargs)
        events.append('first_failure_write_started')
        persistence_attempts[0] += 1
        require(kwargs['cap'] == 65536, 'journal_byte_cap')
        require(clocks[0].stop_reason == code, 'clock_stopped_before_write')
        require(value['primary_failure']['code'] == code and value['cleanup_started'] is False,
            'first_cause_before_cleanup')
        if fault == 'write':
            raise OSError('synthetic write failure; never projected')
        if fault == 'timeout':
            time.sleep(2)
            raise AssertionError('persistence_timer_did_not_interrupt')
        writing[0] = True
        try:
            result = original_put(path, value, **kwargs)
        finally:
            writing[0] = False
        events.append('durable_put_readback_completed')
        return result

    def read(reference, **kwargs):
        if Path(reference['path']).name == 'first_failure.json':
            if fault == 'readback':
                raise ValueError('stage06_primary_failure_readback')
            result = original_read(reference, **kwargs)
            events.append('first_failure_explicit_readback_completed')
            return result
        return original_read(reference, **kwargs)

    def cleanup(child, **kwargs):
        events.append('cleanup_started')
        require(persistence_attempts[0] == 1, 'one_persistence_attempt_before_cleanup')
        if fault is None or fault == 'secondary':
            require(events.count('first_failure_fsync') == 2, 'file_and_directory_fsync')
            require(events.index('first_failure_explicit_readback_completed') < events.index('cleanup_started'),
                'readback_precedes_cleanup')
            journal = json.loads((run/'first_failure.json').read_bytes())
            require(journal['primary_failure']['code'] == code and journal['stop_reason'] == code,
                'durable_exact_primary')
        result = original_cleanup(child, **kwargs)
        events.append('child_reaped_by_cleanup')
        if fault in ('secondary', 'write'):
            raise ValueError('stage06_child_cleanup')
        return result

    subprocess.Popen = popen
    os.fsync = fsync
    legacy.put = put
    legacy.bounded_cleanup = cleanup
    owner.read_ref = read
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    captured = io.StringIO()
    started = time.monotonic_ns()
    try:
        with contextlib.redirect_stdout(captured):
            receipt_ref, receipt = owner.supervise(admission, admission_ref=admission_ref,
                run_directory=run, mode='engineering', started_ns=started, started_utc=int(time.time()))
    finally:
        subprocess.Popen = original_popen
        os.fsync = original_fsync
        for child in spawned:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
    elapsed = time.monotonic_ns()-started
    require(receipt['status'] == 'STOPPED_NO_RETRY', 'stopped_receipt')
    require(receipt['primary_failure']['code'] == code, 'receipt_exact_primary')
    require(receipt['measurement']['stop_reason'] == code, 'receipt_clock_exact_primary')
    require(all(row['stop_reason'] == code and row['stop_ns'] == stops[0]['stop_ns'] for row in stops),
        'first_stop_immutable_after_secondary')
    require('PRIMARY_FAILURE phase=STAGE06_OWNER_TERMINAL code='+code+' ' in captured.getvalue(),
        'terminal_exact_primary')
    require(receipt['all_children_reaped'] is True and receipt['lock_released'] is True
        and all(child.poll() is not None for child in spawned), 'mandatory_cleanup_completed')
    stored = json.loads(Path(receipt_ref['path']).read_bytes())
    require(stored['primary_failure']['code'] == code
        and stored['measurement']['stop_reason'] == code
        and stored['all_children_reaped'] is True, 'final_receipt_readback')
    finalization = run/'finalization_failure.json'
    if finalization.exists():
        require(json.loads(finalization.read_bytes())['primary_failure']['code'] == code,
            'late_failure_preserves_primary')
    require(signal.getsignal(signal.SIGALRM) == previous_handler
        and signal.getitimer(signal.ITIMER_REAL) == previous_timer, 'timer_restored')
    if fault in ('write', 'readback', 'timeout'):
        require(receipt['first_failure_persistence'] == 'FAILED_NO_RETRY', 'persistence_failure_recorded')
        require(any(row['phase'] == 'STAGE06_PRIMARY_FAILURE_PERSISTENCE' for row in receipt['secondary_failures']),
            'persistence_error_separate')
        if fault == 'timeout':
            require(any(row['code'] == 'stage06_primary_failure_persistence_timeout'
                for row in receipt['secondary_failures']), 'timeout_exact_secondary')
    else:
        require(receipt['first_failure_persistence'] == 'DURABLE_READBACK_VERIFIED', 'journal_verified')
    if fault in ('secondary', 'write'):
        require(any(row['code'] == 'stage06_child_cleanup' for row in receipt['secondary_failures']),
            'cleanup_error_secondary')
    require(persistence_attempts[0] == 1, 'no_retry_of_journal')
    (root/'terminal.txt').write_text(captured.getvalue())
    return dict(code=code, fault=fault, status='PASS', elapsed_ns=elapsed, events=events,
        receipt_ref=receipt_ref, child_pids=[child.pid for child in spawned], children_reaped=True,
        stop_history=stops, native_Work_calls=0, model_calls=0, owner_scenario_runs=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--review-sha256', required=True)
    args = parser.parse_args()
    raw = (HERE/'controls_source_review.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == args.review_sha256, 'review_pin')
    review = json.loads(raw)
    require(review['reviewer'] == '/root/private_remote_controls'
        and review['status'] == 'ACCEPTED_FOR_ONE_ISOLATED_STDLIB_CONTROL_RUN'
        and review['approved_invocations'] == 1, 'execution_scope')
    sources = load_sources(review)
    root = HERE/'controls_run_01'
    root.mkdir(mode=0o700)
    rows = []
    started = time.monotonic_ns()
    codes = ('STAGE06_OPERATION_LIMIT', 'STAGE06_NATIVE_LIMIT',
        'STAGE06_EARLY_CHECKPOINT_TIMEOUT', 'STAGE06_SEMANTIC_IDLE_LIMIT')
    cases = [(code, None) for code in codes]
    cases += [(codes[0], fault) for fault in ('write', 'readback', 'timeout', 'secondary')]
    for index, (code, fault) in enumerate(cases, 1):
        rows.append(case(sources, root/('CASE_'+str(index)), code, fault))
    result = dict(schema='radik.stage06.supervisor_repair_controls.v1', status='PASS',
        reviewed_sources=review['source_refs'], cases=rows, elapsed_ns=time.monotonic_ns()-started,
        synthetic_clock_states=True, actual_supervisor_failure_and_cleanup=True,
        actual_stdlib_children_only=True, owner_entry_called=False, native_Work_calls=0, model_calls=0)
    with (root/'result.json').open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps(dict(status='PASS', cases=len(rows), elapsed_ns=result['elapsed_ns'])))


if __name__ == '__main__':
    main()
