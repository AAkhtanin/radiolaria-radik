#!/usr/bin/env python3
"""Finite ordinary-entry supervision for one ordinary U3 application process.

Cold and warm tasks remain inside one fresh application scope. Native Wasmtime
workers retain their public argv, limits, execution and reap behavior. The parent
creates no native Root, capability, admission or permission.
"""
import time
STARTED_NS = time.monotonic_ns()
STARTED_UTC = int(time.time())
import argparse
import concurrent.futures
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import types
import uuid

PROJECT = Path(__file__).absolute().parents[3]
PREFIX = 'review/stage07_pure_capability_passage/v01'
BASE = PROJECT/PREFIX
CANDIDATE = BASE/'candidate'
LOCK = PROJECT/'review/direct_plan_passage/owner_start.lock'
MAX_BYTES = 67108864
_SOURCE_PINS = {}
_FAILURE_CODES = frozenset()
STATIC_FAILURE_CODES = frozenset(('stage07_', 'stage07_admission_already_reserved', 'stage07_bootstrap_child_closed', 'stage07_child_cleanup', 'stage07_child_closed_before_expected_message', 'stage07_child_entry_failed', 'stage07_child_final_receipt_missing', 'stage07_child_nonzero_exit', 'stage07_child_return_integrity', 'stage07_event', 'stage07_failure', 'stage07_owner_admission_hash', 'stage07_restart_fresh_process_and_key', 'stage07_restart_requires_actual_reap', 'stage07_supervision_failure', 'stage07_template_anchor_not_dynamic', 'stage07_terminal_admission_identity', 'stage07_terminal_bootstrap_bound', 'stage07_terminal_bootstrap_short_write', 'stage07_terminal_deadline', 'stage07_terminal_entry_receipt', 'stage07_terminal_event_binding', 'stage07_terminal_event_clock', 'stage07_terminal_event_label', 'stage07_terminal_event_readback_scope', 'stage07_terminal_failure_frame_binding', 'stage07_terminal_failure_frames', 'stage07_terminal_failure_projection', 'stage07_terminal_finite_limits', 'stage07_terminal_fresh_run', 'stage07_terminal_independent_admission', 'stage07_terminal_interpreter_path', 'stage07_terminal_line_buffer_bound', 'stage07_terminal_lock_identity', 'stage07_terminal_manifest', 'stage07_terminal_module_path', 'stage07_terminal_native_span', 'stage07_terminal_peer_report_binding', 'stage07_terminal_peer_report_path', 'stage07_terminal_public_keys_once', 'stage07_terminal_public_message', 'stage07_terminal_public_message_bound', 'stage07_terminal_public_session', 'stage07_terminal_reference_changed', 'stage07_terminal_reference_path', 'stage07_terminal_reference_regular', 'stage07_terminal_reference_shape', 'stage07_terminal_reference_symlink', 'stage07_terminal_scenario_ref', 'stage07_terminal_self_pin', 'stage07_terminal_source_inventory', 'stage07_terminal_source_missing', 'stage07_terminal_stdout_line_bound', 'stage07_terminal_stdout_shape', 'stage07_terminal_stream_bound', 'stage07_terminal_stream_short_write'))
PUBLIC_KINDS = frozenset(('PUBLIC_KEYS', 'READY', 'SESSION_CLOSED', 'DONE', 'ENTRY_FAILURE'))
STATIC_FAILURE_CODES |= frozenset((
    'STAGE07_OPERATION_LIMIT', 'STAGE07_NATIVE_LIMIT',
    'STAGE07_EARLY_CHECKPOINT_TIMEOUT', 'STAGE07_SEMANTIC_IDLE_LIMIT',
    'stage07_primary_failure_persistence_failed',
    'stage07_primary_failure_persistence_timeout',
    'stage07_primary_failure_timer_unavailable',
    'stage07_primary_failure_readback',
))


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode()


def read_ref(reference, *, cap=MAX_BYTES, platform=False):
    require(type(reference) is dict and {'path', 'sha256', 'size_bytes'} <= set(reference),
        'stage07_terminal_reference_shape')
    path = Path(reference['path'])
    allowed_root = Path(sys.base_prefix).resolve() if platform else PROJECT
    require(path.is_absolute() and path.is_relative_to(allowed_root)
        and type(reference['size_bytes']) is int and 0 <= reference['size_bytes'] <= cap,
        'stage07_terminal_reference_path')
    for node in (path, *path.parents):
        require(not node.is_symlink(), 'stage07_terminal_reference_symlink')
        if node == allowed_root:
            break
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size == reference['size_bytes'], 'stage07_terminal_reference_regular')
        raw = stream.read(cap+1)
        after = os.fstat(stream.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        and len(raw) == reference['size_bytes']
        and hashlib.sha256(raw).hexdigest() == reference['sha256'],
        'stage07_terminal_reference_changed')
    return raw


def reference(path):
    path = Path(path).absolute()
    raw = path.read_bytes()
    result = dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))
    read_ref(result)
    return result


def safe_failure(error, phase='STAGE07_OWNER_TERMINAL'):
    payload = getattr(error, 'stage07_failure', None)
    if type(payload) is dict and {'phase','error_class','code'} <= set(payload) \
            and set(payload) <= {'phase','error_class','code','frames'} \
            and all(type(payload[key]) is str and re.fullmatch('[A-Za-z0-9_:./-]{1,160}',payload[key])
                for key in ('phase','error_class','code')):
        return dict(payload)
    code = error.args[0] if isinstance(error, ValueError) and error.args else ''
    if type(code) is not str or code not in _FAILURE_CODES | STATIC_FAILURE_CODES:
        code = 'stage07_supervision_failure'
    frames = []; trace = error.__traceback__
    while trace is not None:
        path = str(Path(trace.tb_frame.f_code.co_filename).absolute())
        if path in _SOURCE_PINS:
            frames.append(dict(path=path, function=trace.tb_frame.f_code.co_name,
                line=trace.tb_lineno, sha256=_SOURCE_PINS[path]['sha256']))
        trace = trace.tb_next
    return dict(phase=phase, error_class=type(error).__name__, code=code, frames=frames[-24:])


def load_module(path, expected):
    raw = read_ref(expected)
    require(Path(expected['path']) == path, 'stage07_terminal_module_path')
    module = types.ModuleType('stage07_'+path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def persist_first_failure(receipt, clock, run, put, *, cleanup_started):
    """One exclusive 64-KiB journal attempt within the original cleanup clock.

    SIGALRM interrupts ordinary blocking filesystem calls after at most one
    second. An uninterruptible kernel I/O stall is not a hard wall guarantee.
    The saved stop and cleanup deadline are never renewed by this attempt.
    """
    deadline = min(clock.cleanup.end_ns(), time.monotonic_ns()+10**9)
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
        'stage07_primary_failure_timer_unavailable')
    previous = signal.getsignal(signal.SIGALRM)

    def expired(signum, frame):
        raise ValueError('stage07_primary_failure_persistence_timeout')

    signal.signal(signal.SIGALRM, expired)
    try:
        remaining = (deadline-time.monotonic_ns())/1e9
        require(remaining > 0, 'stage07_primary_failure_persistence_timeout')
        signal.setitimer(signal.ITIMER_REAL, remaining)
        value = dict(schema='radik.stage07.first_failure.v1',
            operation_id=receipt['operation_id'], admission_ref=receipt['admission_ref'],
            primary_failure=receipt['primary_failure'], status='STOPPED_NO_RETRY',
            native_worker_refusal=receipt.get('primary_worker_refusal'),
            stop_ns=clock.stop_ns, stop_reason=clock.stop_reason,
            cleanup_deadline_ns=clock.cleanup.end_ns(), cleanup_started=cleanup_started,
            automatic_retry=False)
        ref = put(run/'first_failure.json', value, cap=65536)
        require(json.loads(read_ref(ref, cap=65536)) == value,
            'stage07_primary_failure_readback')
        require(time.monotonic_ns() < deadline, 'stage07_primary_failure_persistence_timeout')
        return ref
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def load_admission(admission_ref, *, mode):
    global _SOURCE_PINS, _FAILURE_CODES
    admission = json.loads(read_ref(admission_ref, cap=8388608))
    expected = ('OWNER_COMMAND_SOURCE_READY_NOT_EXECUTED' if mode == 'owner'
        else 'SOURCE_ACCEPTED_FOR_BOUNDED_ENGINEERING_PROBE')
    require(admission.get('schema') == 'radik.stage07.owner_admission.v1'
        and admission.get('reviewer') == '/root/private_remote_controls'
        and admission.get('status') == expected and admission.get('mode') == mode
        and admission.get('task_selector') == ('pure_capability_owner_v01' if mode == 'owner'
            else 'pure_capability_probe_v01')
        and admission.get('expected_model_calls') == 0
        and admission.get('approved_owner_invocations') == (1 if mode == 'owner' else 0),
        'stage07_terminal_independent_admission')
    manifest = json.loads(read_ref(admission['code_manifest_ref'], cap=8388608))
    require(manifest.get('schema') == 'radik.stage07.source_manifest.v1'
        and manifest.get('environment_root') == str(PROJECT)
        and manifest.get('candidate_root') == str(CANDIDATE), 'stage07_terminal_manifest')
    require(type(manifest['files']) is list and 1 <= len(manifest['files']) <= 12000
        and len({row['path'] for row in manifest['files']}) == len(manifest['files']),
        'stage07_terminal_source_inventory')
    for row in manifest['files']:
        read_ref(row, platform=row.get('classification') == 'platform')
    _SOURCE_PINS = {row['path']: row for row in manifest['files']}
    _FAILURE_CODES = frozenset(manifest['failure_codes'])
    pins = {row['path']: row for row in manifest['files']}
    for relative in ('owner_terminal.py', 'supervisor_timing.py'):
        require(str(BASE/relative) in pins, 'stage07_terminal_source_missing')
    require(read_ref(pins[str(Path(__file__).absolute())]) == Path(__file__).read_bytes(),
        'stage07_terminal_self_pin')
    for row in admission['live_guards']:
        read_ref(row)
    require(type(admission['scenario_refs']) is list and len(admission['scenario_refs']) == 1,
        'stage07_terminal_scenario_ref')
    scenario = json.loads(read_ref(admission['scenario_refs'][0], cap=1048576))
    require(scenario.get('task_selector') == admission['task_selector'],
        'stage07_terminal_scenario_selector')
    interpreter = admission['interpreter_ref']
    require(interpreter['path'] == str(PROJECT/'.venv-plan/bin/python'),
        'stage07_terminal_interpreter_path')
    read_ref(interpreter)
    limits = admission['limits']
    require(type(limits) is dict and 0 < limits['operation_seconds'] <= 900
        and 0 < limits['native_seconds'] <= 900
        and 0 < limits['cleanup_seconds'] <= 30
        and limits['interrupt_grace_seconds'] == 10
        and limits['terminate_grace_seconds'] == 5
        and limits['kill_wait_seconds'] == 5
        and 0 < limits['early_checkpoint_seconds'] <= limits['operation_seconds']
        and 0 < limits['semantic_idle_seconds'] <= limits['operation_seconds'],
        'stage07_terminal_finite_limits')
    adapter = load_module(BASE/'supervisor_timing.py', pins[str(BASE/'supervisor_timing.py')])
    timing, legacy = adapter.load_primitives(PROJECT)
    return admission, manifest, scenario, adapter, timing, legacy


def _absolute(reference_value):
    result = dict(reference_value)
    path = Path(result['path'])
    result['path'] = str(path if path.is_absolute() else PROJECT/path)
    return result


def supervise(admission, *, admission_ref, run_directory, mode, started_ns, started_utc):
    """Run one granted operation; the engineering caller owns its outer budget."""
    checked, manifest, scenario, adapter, timing, legacy = load_admission(admission_ref, mode=mode)
    require(checked == admission, 'stage07_terminal_admission_identity')
    run = Path(run_directory).absolute()
    parent = BASE/('owner_terminal_runs' if mode == 'owner' else 'offline_attempts')
    valid_run = (run.parent == parent if mode == 'owner' else
        run.name == 'work' and run.parent.parent == parent and run.parent.is_dir())
    require(valid_run and not run.exists(), 'stage07_terminal_fresh_run')
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    run.mkdir(mode=0o700)
    limits = dict(admission['limits'])
    clock = adapter.OperationClock(timing, started_ns=started_ns, limits=limits)
    receipt = dict(schema='radik.stage07.owner_terminal_receipt.v1', mode=mode,
        operation_id=uuid.uuid4().hex, admission_ref=admission_ref,
        code_manifest_ref=admission['code_manifest_ref'], source_review_only=False,
        started_ns=started_ns, started_utc=started_utc, primary_failure=None,
        secondary_failures=[], children=[], checkpoints=[], bootstrap_refs=[],
        public_message_refs=[], models_called=0, auth_calls=0,
        automatic_retry=False, owner_operation=(mode == 'owner'),
        previous_admission_reused=False, restored_authority=False,
        task_selector=admission['task_selector'],
        status='OPEN', all_children_reaped=False, lock_released=False,
        child_start_or_closure_unconfirmed=False)
    children = []
    selector = selectors.DefaultSelector()
    pipes = []
    lock_fd = None
    reservation_ref = None
    reservation_path = None
    streams = []
    last_status_ns = started_ns
    cleanup_started = False

    def put(path, value, cap=4194304):
        return _absolute(legacy.put(path, value, cap=cap))

    def failure(error):
        value = safe_failure(error)
        receipt['status'] = 'STOPPED_NO_RETRY'
        if receipt['primary_failure'] is None:
            receipt['primary_failure'] = value
            clock.stop(value['code'])
            try:
                receipt['first_failure_ref'] = persist_first_failure(
                    receipt, clock, run, put, cleanup_started=cleanup_started)
                receipt['first_failure_persistence'] = 'DURABLE_READBACK_VERIFIED'
            except BaseException as persistence_error:
                detail = safe_failure(persistence_error, phase='STAGE07_PRIMARY_FAILURE_PERSISTENCE')
                if detail['code'] not in ('stage07_primary_failure_persistence_timeout',
                        'stage07_primary_failure_timer_unavailable', 'stage07_primary_failure_readback'):
                    detail['code'] = 'stage07_primary_failure_persistence_failed'
                receipt['secondary_failures'].append(detail)
                receipt['first_failure_persistence'] = 'FAILED_NO_RETRY'
            frames = value.get('frames', [])
            last = frames[-1] if frames else None
            location = (last['path']+':'+last['function']+':'+str(last['line'])) if last else 'UNAVAILABLE'
            try:
                print('PRIMARY_FAILURE phase='+value['phase']+' code='+value['code']+
                    ' error_class='+value['error_class']+' source_location='+location, flush=True)
            except BaseException as output_error:
                receipt['secondary_failures'].append(safe_failure(output_error,
                    phase='STAGE07_PRIMARY_FAILURE_OUTPUT'))
        elif value != receipt['primary_failure'] and value not in receipt['secondary_failures']:
            receipt['secondary_failures'].append(value)
        clock.stop(value['code'])

    def guards():
        for row in admission['live_guards']:
            read_ref(row)

    def check_deadline():
        reason = clock.due_reason(time.monotonic_ns())
        require(reason is None, reason or 'stage07_terminal_deadline')

    def spawn(folder):
        role, session = 'application', 1
        check_deadline(); guards()
        name = role+'_'+str(session)
        clock.attach(name)
        launch = dict(schema='radik.stage07.application_launch.v1',
            code_manifest_ref=admission['code_manifest_ref'], admission_ref=admission_ref,
            reservation_ref=reservation_ref, mode=mode, operation_id=receipt['operation_id'],
            operation_started_ns=started_ns, operation_deadline_ns=clock.deadline_ns,
            operation_started_utc=started_utc, role=role, session=session,
            folder=str(folder),
            owner_lock_fd=lock_fd, limits=limits, task_selector=admission['task_selector'])
        launch_ref = put(run/(name+'_launch.json'), launch)
        stdout_path, stderr_path = run/(name+'_stdout.raw'), run/(name+'_stderr.raw')
        stdout_file = stdout_path.open('xb'); stderr_file = stderr_path.open('xb')
        streams.extend((stdout_file, stderr_file))
        argv = [admission['interpreter_ref']['path'], '-I', '-S', '-B',
            str(CANDIDATE/'config/launch.py'), '--console', '--stage07-pure-capability',
            '--stage07-launch', launch_ref['path'], '--stage07-role', role,
            '--stage07-session', str(session), '--owner-lock-fd', str(lock_fd)]
        receipt['child_start_or_closure_unconfirmed'] = True
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=CANDIDATE, env={'PATH': '/usr/bin:/bin',
            'LANG': 'en_US.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'},
            pass_fds=(lock_fd,), start_new_session=(mode == 'owner'), bufsize=0)
        receipt['child_start_or_closure_unconfirmed'] = False
        state = dict(name=name, role=role, session=session, folder=folder, child=child,
            launch_ref=launch_ref, messages=[], event_sequence=0, final_entry=None,
            stdout_buffer=b'', stderr_bytes=0, stdout_bytes=0, signals=[], eof=set(),
            stdout_file=stdout_file, stderr_file=stderr_file, public_key=None, process_group=os.getpgid(child.pid),
            returncode=None, reaped=False, stdout_path=stdout_path, stderr_path=stderr_path)
        children.append(state)
        for kind in ('stdout', 'stderr'):
            stream = getattr(child, kind)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (state, kind))
        print('STAGE07_CHILD_STARTED role='+role+' session='+str(session)+' pid='+str(child.pid), flush=True)
        return state

    def peer_failure(detail, state):
        require(type(detail) is dict and {'code','error_class'} <= set(detail)
            and set(detail) <= {'code','error_class','frames'}
            and all(type(detail[key]) is str and re.fullmatch('[A-Za-z0-9_:./-]{1,160}',detail[key])
                for key in ('code','error_class')), 'stage07_terminal_failure_projection')
        frames = detail.get('frames', [])
        require(type(frames) is list and len(frames) <= 24, 'stage07_terminal_failure_frames')
        for frame in frames:
            require(type(frame) is dict and set(frame) == {'path','function','line','sha256'}
                and frame['path'] in _SOURCE_PINS
                and frame['sha256'] == _SOURCE_PINS[frame['path']]['sha256']
                and type(frame['line']) is int and frame['line'] > 0
                and type(frame['function']) is str
                and re.fullmatch('[A-Za-z_<>][A-Za-z0-9_<>]{0,127}',frame['function']),
                'stage07_terminal_failure_frame_binding')
        error = ValueError(detail['code'])
        error.stage07_failure = dict(phase='STAGE07_'+state['role'].upper(), **detail)
        raise error

    def receive_line(state, raw):
        require(len(raw) <= 1048576, 'stage07_terminal_stdout_line_bound')
        value = json.loads(raw)
        require(type(value) is dict, 'stage07_terminal_stdout_shape')
        if set(value) == {'stage07_event'}:
            event = value['stage07_event']
            require(type(event) is dict and event.get('pid') == state['child'].pid
                and event.get('role') == state['role'] and event.get('session') == state['session']
                and event.get('operation_started_ns') == started_ns
                and event.get('sequence') == state['event_sequence']+1,
                'stage07_terminal_event_binding')
            now = time.monotonic_ns()
            require(type(event.get('at_monotonic_ns')) is int
                and started_ns <= event['at_monotonic_ns'] <= now
                and event.get('wall_ns') == event['at_monotonic_ns']-started_ns
                and type(event.get('cpu_ns')) is int and event['cpu_ns'] >= 0,
                'stage07_terminal_event_clock')
            ref = event['ref']
            require(Path(ref['path']).is_relative_to(state['folder']/'entry_sessions'),
                'stage07_terminal_event_readback_scope')
            body = json.loads(read_ref(ref, cap=16777216))
            state['event_sequence'] += 1
            label = event['label']
            require(type(label) is str and re.fullmatch('[A-Za-z0-9_]{1,80}', label),
                'stage07_terminal_event_label')
            receipt['checkpoints'].append(dict(child=state['name'], event=event))
            if label == 'primary_refusal':
                require(type(body)is dict and set(body)=={'native_span','witness_ref','worker'},
                    'stage07_terminal_worker_failure_shape')
                detail=body['worker']
                require(type(detail)is dict and set(detail)=={'code','error_class','phase','status',
                    'return_code','process_reaped','detail_integer'} and detail['code'] in _FAILURE_CODES
                    and type(detail['error_class'])is str
                    and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,63}',detail['error_class'])
                    and (detail['detail_integer'] is None or type(detail['detail_integer'])is int
                        and 0<=detail['detail_integer']<=255), 'stage07_terminal_worker_failure_code')
                witness=body['witness_ref']
                require(Path(witness['path']).is_relative_to(state['folder']),
                    'stage07_terminal_worker_failure_witness')
                read_ref(witness,cap=16777216)
                receipt['primary_worker_refusal']=body
                print('NATIVE_WORKER_REFUSAL code='+detail['code']+' error_class='+detail['error_class']+
                    ' detail_integer='+str(detail['detail_integer'])+' witness='+witness['path'],flush=True)
                error=ValueError(detail['code'])
                error.stage07_failure=dict(phase='STAGE07_NATIVE_WORKER',code=detail['code'],
                    error_class=detail['error_class'],frames=[])
                raise error
            if label in ('native_enter', 'native_exit'):
                require(type(body) is dict and type(body.get('span_id')) is str,
                    'stage07_terminal_native_span')
                clock.native_event(state['name'], entering=label == 'native_enter',
                    span_id=body['span_id'], at_ns=event['at_monotonic_ns'], observed_ns=now)
            elif label == 'ordinary_entry_closed':
                require(state['final_entry'] is None and body.get('operation_id') == receipt['operation_id']
                    and body.get('role') == state['role'] and body.get('session') == state['session'],
                    'stage07_terminal_entry_receipt')
                state['final_entry'] = dict(reference=ref, value=body)
                if body.get('status') != 'CLOSED' or body.get('primary_failure') is not None:
                    detail = body.get('primary_failure') or dict(code='stage07_child_entry_failed',
                        error_class='PeerEntryFailure')
                    peer_failure(detail, state)
            elif label in ('cold_need_observed','cold_search','cold_root','cold_generated','cold_admitted',
                    'cold_consumed','memory_written','warm_need_observed','warm_admitted','warm_consumed',
                    'controls_need_observed','control_positive_admitted','control_refusals','controls_consumed',
                    'disabled_need_observed','controlled_expiry','controls_completed'):
                clock.checkpoint(label=label, reference=ref, observed_ns=now)
            print('STAGE07_CHECKPOINT role='+state['role']+' session='+str(state['session'])+
                ' label='+label+' wall_s='+format(event['wall_ns']/1e9, '.3f')+
                ' cpu_s='+format(event['cpu_ns']/1e9, '.3f')+
                ' remaining_s='+format(max(0,clock.deadline_ns-now)/1e9, '.3f'), flush=True)
            return
        require(value.get('kind') == 'ENTRY_FAILURE'
            and value.get('role') == 'application' and value.get('session') == 1,
            'stage07_terminal_public_message')
        peer_failure(value.get('failure'), state)

    def pump():
        nonlocal last_status_ns
        check_deadline()
        for key, _ in selector.select(timeout=min(0.05, max(0,(clock.deadline_ns-time.monotonic_ns())/1e9))):
            state, kind = key.data
            block = os.read(key.fd, 65536)
            if not block:
                selector.unregister(key.fileobj); state['eof'].add(kind)
                continue
            state[kind+'_bytes'] += len(block)
            require(state[kind+'_bytes'] <= 33554432, 'stage07_terminal_stream_bound')
            file = state[kind+'_file']
            require(file.write(block) == len(block), 'stage07_terminal_stream_short_write')
            file.flush(); os.fsync(file.fileno())
            if kind == 'stdout':
                state['stdout_buffer'] += block
                require(len(state['stdout_buffer']) <= 1048576, 'stage07_terminal_line_buffer_bound')
                while b'\n' in state['stdout_buffer']:
                    line, state['stdout_buffer'] = state['stdout_buffer'].split(b'\n', 1)
                    if line:
                        receive_line(state, line)
        now = time.monotonic_ns()
        if now-last_status_ns >= 30*10**9:
            print('STAGE07_STATUS wall_s='+format((now-started_ns)/1e9,'.3f')+
                ' native_s='+format(clock.native_ns(now)/1e9,'.3f')+
                ' last_checkpoint='+str((clock.last_checkpoint or {}).get('label','NONE'))+
                ' remaining_s='+format(max(0,clock.deadline_ns-now)/1e9,'.3f'), flush=True)
            last_status_ns = now
        for state in children:
            code = state['child'].poll()
            if code is not None and code != 0 and len(state['eof']) == 2:
                require(False, 'stage07_child_nonzero_exit')

    def close_child(state):
        while state['child'].poll() is None or len(state['eof']) < 2:
            pump()
        code = state['child'].wait(timeout=0)
        require(code == 0 and not state['stdout_buffer'], 'stage07_child_return_integrity')
        require(state['final_entry'] is not None
            and not clock.process_clocks[state['name']].native_spans,
            'stage07_child_final_receipt_missing')
        state['reaped'], state['returncode'] = True, code
        clock.closed(state['name'])
        print('STAGE07_CHILD_CLOSED role='+state['role']+' session='+str(state['session'])+
            ' pid='+str(state['child'].pid)+' exit='+str(code)+' reaped=true', flush=True)

    try:
        check_deadline()
        lock_fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(lock_fd); current = LOCK.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
            and (info.st_dev,info.st_ino) == (current.st_dev,current.st_ino),
            'stage07_terminal_lock_identity')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        guards()
        reservation_dir = BASE/'reservations'
        reservation_dir.mkdir(mode=0o700, exist_ok=True)
        reservation_path = reservation_dir/(admission_ref['sha256']+'.json')
        require(not reservation_path.exists(), 'stage07_admission_already_reserved')
        reservation_ref = put(reservation_path, dict(schema='radik.stage07.operation_reservation.v1',
            state='OPEN', operation_id=receipt['operation_id'], admission_ref=admission_ref,
            code_manifest_ref=admission['code_manifest_ref'], mode=mode,
            run_directory=str(run), supervisor_pid=os.getpid(),
            operation_started_ns=started_ns, operation_started_utc=started_utc,
            operation_deadline_ns=clock.deadline_ns, limits=limits,
            task_selector=admission['task_selector'], automatic_retry=False, one_use=True))
        receipt['reservation_ref'] = reservation_ref
        folder = run/'application'; folder.mkdir(mode=0o700)
        put(folder/'scenario.json', scenario)
        availability = put(run/'required_output_availability.json', dict(
            operation_id=receipt['operation_id'], application_folder=str(folder),
            checked_before_child=True))
        receipt['output_availability_ref'] = availability
        app = spawn(folder)
        while app['final_entry'] is None:
            require(app['child'].poll() is None or len(app['eof']) < 2,
                'stage07_child_closed_before_expected_message')
            pump()
        report = app['final_entry']['value']['report']
        expected = ('PASS_STAGE07_PURE_CAPABILITY_OWNER' if mode == 'owner'
            else 'PASS_STAGE07_PURE_CAPABILITY_PROBE')
        require(type(report) is dict and report.get('status') == expected
            and report.get('task_selector') == admission['task_selector'],
            'stage07_terminal_report_binding')
        close_child(app)
        if mode == 'owner':
            try: os.killpg(app['child'].pid, 0)
            except ProcessLookupError: receipt['owned_application_group_closed'] = True
            else: raise ValueError('stage07_worker_group_not_closed')
        guards(); check_deadline()
        receipt['status'] = 'CLOSED'
    except BaseException as error:
        failure(error)
    finally:
        cleanup_started = True
        live = [state for state in children if state['child'].poll() is None]
        if live:
            stop = clock.stop((receipt['primary_failure'] or {}).get('code','stage07_child_cleanup'))
            # The accepted per-child primitive shares ONE saved stop. Parallel
            # waits prevent the second peer from receiving a fresh cleanup budget.
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(live))
            pending = [(state, executor.submit(legacy.bounded_cleanup, state['child'],
                stop_ns=stop, limits=limits, signals=state['signals'], started_ns=started_ns))
                for state in live]
            for state, future in pending:
                try:
                    state['reaped'] = bool(future.result(timeout=max(0,
                        clock.cleanup.end_ns()-time.monotonic_ns())/1e9))
                    state['returncode'] = state['child'].poll()
                except BaseException as error:
                    failure(error)
            executor.shutdown(wait=False)
        for state in children:
            try:
                if state['child'].poll() is not None:
                    state['returncode'] = state['child'].wait(timeout=0)
                    state['reaped'] = True
                    clock.closed(state['name'])
                for kind in ('stdout','stderr'):
                    getattr(state['child'],kind).close()
            except BaseException as error:
                failure(error)
        if mode == 'owner' and children:
            for state in children:
                try:
                    os.killpg(state['child'].pid, 0)
                except ProcessLookupError:
                    receipt['owned_application_group_closed'] = True
                    continue
                failure(ValueError('stage07_worker_group_cleanup_required'))
                stop = clock.stop(receipt['primary_failure']['code'])
                while time.monotonic_ns() < clock.cleanup.end_ns():
                    try: os.killpg(state['child'].pid, signal.SIGKILL)
                    except ProcessLookupError:
                        receipt['owned_application_group_closed'] = True
                        break
                    time.sleep(min(0.02, max(0, clock.cleanup.end_ns()-time.monotonic_ns())/1e9))
                if not receipt.get('owned_application_group_closed'):
                    failure(ValueError('stage07_worker_group_closure_unconfirmed'))
                receipt['forced_worker_reap_proven'] = False
        try: selector.close()
        except BaseException as error: failure(error)
        for fd in pipes:
            try: os.close(fd)
            except OSError: pass
        for stream in streams:
            try: stream.flush(); os.fsync(stream.fileno()); stream.close()
            except BaseException as error: failure(error)
        receipt['all_children_reaped'] = (all(state['reaped'] for state in children)
            and not receipt['child_start_or_closure_unconfirmed'])
        receipt['all_owned_processes_closed'] = (receipt['all_children_reaped']
            and (mode != 'owner' or receipt.get('owned_application_group_closed', not children)))
        for state in children:
            output_refs = {}
            for kind in ('stdout', 'stderr'):
                try: output_refs[kind+'_ref'] = reference(state[kind+'_path'])
                except BaseException as error:
                    output_refs[kind+'_ref'] = None; failure(error)
            receipt['children'].append(dict(role=state['role'],session=state['session'],
                pid=state['child'].pid, launch_ref=state['launch_ref'],
                exit_code=state['returncode'], reaped=state['reaped'], signals=state['signals'],
                final_entry=state['final_entry'], **output_refs))
        try: guards(); receipt['live_guards_preserved'] = True
        except BaseException as error:
            receipt['live_guards_preserved'] = False; failure(error)
        if lock_fd is not None:
            try:
                if receipt['all_owned_processes_closed']:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN); receipt['lock_released'] = True
                os.close(lock_fd)
            except BaseException as error: failure(error)
        if receipt['primary_failure'] is not None or not receipt['all_owned_processes_closed']:
            receipt['status'] = 'STOPPED_NO_RETRY'
        try: check_deadline()
        except BaseException as error: failure(error)
        receipt['measurement'] = clock.measurement(time.monotonic_ns())
        receipt_ref = None
        try:
            receipt_ref = put(run/'receipt.json', receipt, cap=8388608)
            if reservation_ref is not None:
                put(run/'operation_close.json', dict(schema='radik.stage07.operation_close.v1',
                    state=receipt['status'], reservation_ref=reservation_ref, receipt_ref=receipt_ref,
                    all_children_reaped=receipt['all_children_reaped'], lock_released=receipt['lock_released'],
                    primary_failure=receipt['primary_failure'], reservation_reset_allowed=False))
            # A completed write does not authorize a late successful return.
            check_deadline()
        except BaseException as error:
            failure(error)
            # The printed first cause remains primary when final storage itself fails.
            print('STAGE07_FINAL_PERSISTENCE_FAILED primary_code='+
                receipt['primary_failure']['code'], flush=True)
            try:
                put(run/'finalization_failure.json', dict(
                    schema='radik.stage07.finalization_failure.v1', status='STOPPED_NO_RETRY',
                    primary_failure=receipt['primary_failure'],
                    secondary_failures=receipt['secondary_failures'], retained_receipt_ref=receipt_ref,
                    operation_deadline_ns=clock.deadline_ns, observed_ns=time.monotonic_ns(),
                    final_tool_return_authoritative=True, deadline_renewed=False))
            except BaseException as secondary:
                failure(secondary)
    return receipt_ref, receipt


def main():
    parser = argparse.ArgumentParser(description='Finite ordinary native external-DRS owner operation.')
    parser.add_argument('--admission-sha256', required=True)
    parser.add_argument('--admission-file', choices=('owner_admission.json', 'owner_admission_02.json'),
        default='owner_admission.json')
    args = parser.parse_args()
    admission_ref = reference(BASE/args.admission_file)
    require(admission_ref['sha256'] == args.admission_sha256, 'stage07_owner_admission_hash')
    admission, _, _, _, _, _ = load_admission(admission_ref, mode='owner')
    name = 'OWNER_'+time.strftime('%Y%m%dT%H%M%S',time.gmtime())+'_'+uuid.uuid4().hex
    ref, result = supervise(admission, admission_ref=admission_ref,
        run_directory=BASE/'owner_terminal_runs'/name, mode='owner',
        started_ns=STARTED_NS, started_utc=STARTED_UTC)
    print('STAGE07_RETURN status='+result['status']+' receipt='+
        (ref['path'] if ref is not None else 'UNAVAILABLE'),flush=True)
    return 0 if result['status'] == 'CLOSED' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as error:
        value = safe_failure(error)
        print('PRIMARY_FAILURE phase='+value['phase']+' code='+value['code']+
            ' error_class='+value['error_class'],flush=True)
        raise SystemExit(1)
