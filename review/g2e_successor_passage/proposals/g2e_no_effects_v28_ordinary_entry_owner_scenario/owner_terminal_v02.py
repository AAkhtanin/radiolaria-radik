#!/usr/bin/env python3
"""P28 V02: reserve one exact-admission ordinary owner scenario before effects.

P23 mechanisms retained: pin-before-import, first-cause precedence, durable raw
partials, exact-child signals, bounded reap and inherited-lock release policy.
No candidate application/native/provider module is imported by this supervisor.
The accepted original timer source remains immutable; its algorithms are reused.
"""
import time
STARTED_NS = time.monotonic_ns()
STARTED_UTC = int(time.time())
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import types
import uuid


PRODUCTION_PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
PROJECT = Path(__file__).absolute().parents[4]
PREFIX = 'review/g2e_successor_passage/proposals/g2e_no_effects_v28_ordinary_entry_owner_scenario'
SELF = PREFIX + '/owner_terminal_v02.py'
RESERVATIONS = 'state/p28_owner_scenario_reservations'
TIMING = PREFIX + '/supervisor_timing.py'
ADMISSION = PREFIX + '/owner_admission.json'
ACTIVATOR = PREFIX + '/activate_profile.py'
REHEARSAL_SEAL = PREFIX + '/rehearsal_seal.json'
LOCK = 'review/direct_plan_passage/owner_start.lock'
MAX_INPUT = 67108864
MAX_ADMISSION = 8388608
REVIEWER = '/root/p20_reviewer'
INTERPRETER_REF = dict(path=str(PRODUCTION_PROJECT/'.venv-plan/bin/python'),
    sha256='2477b47fa3ae65b9574eb18a15edb364e96948eaa1875ad3f1c80d780efc9c12',
    size_bytes=52448, mode=0o755)


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def show(value):
    try:
        print(value, flush=True)
    except Exception:
        # Display loss must not prevent the already-owned child's closure.
        pass


def token(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_:./-]{1,256}', value),
        'terminal_diagnostic_token')
    return value


def logical(value):
    require(type(value) is str and value and not value.startswith('/') and
        all(part not in ('', '.', '..', '.git', '.codex', '.aws', 'Arena', 'arena')
            for part in value.split('/')), 'terminal_path_refused')
    return value


def parents(path):
    require(path.is_absolute() and path.is_relative_to(PROJECT), 'terminal_owned_path')
    current = PROJECT
    require(not current.is_symlink() and current.is_dir(), 'terminal_project_refused')
    for part in path.relative_to(PROJECT).parts[:-1]:
        current = current / part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not current.is_symlink(),
            'terminal_parent_refused')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode,
        info.st_nlink, info.st_uid, info.st_mtime_ns, info.st_ctime_ns)


def read_bytes(path, cap=MAX_INPUT):
    parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            before.st_uid == os.geteuid() and 0 <= before.st_size <= cap,
            'terminal_regular_read_refused')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(before.st_size + 1)
            after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size and identity(before) == identity(after),
            'terminal_unstable_read')
        return raw, before
    finally:
        if fd is not None:
            os.close(fd)


def verify_interpreter(reference):
    """The owned application copy reuses one separately admitted real environment."""
    require(type(reference) is dict and reference == INTERPRETER_REF,
        'terminal_exact_real_interpreter_reference')
    target = Path(reference['path'])
    require(PRODUCTION_PROJECT.resolve(strict=True) == PRODUCTION_PROJECT,
        'terminal_real_environment_root')
    for node in (target, *target.parents):
        require(not node.is_symlink(), 'terminal_interpreter_symlink')
        if node == PRODUCTION_PROJECT:
            break
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            before.st_uid == os.geteuid() and before.st_size == reference['size_bytes']
            and stat.S_IMODE(before.st_mode) == reference['mode'],
            'terminal_interpreter_regular_identity')
        raw = stream.read(reference['size_bytes']+1)
        after = os.fstat(stream.fileno())
    require(len(raw) == reference['size_bytes'] and identity(before) == identity(after)
        and hashlib.sha256(raw).hexdigest() == reference['sha256'],
        'terminal_interpreter_changed')
    return str(target)


def put(path, value, *, cap=4194304):
    """Exclusive durable publication; no previous actual may be overwritten."""
    raw = canonical(value) + b'\n'
    require(len(raw) <= cap, 'terminal_receipt_bound')
    parents(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        require(stream.write(raw) == len(raw), 'terminal_short_write')
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    require(read_bytes(path, cap)[0] == raw, 'terminal_receipt_readback')
    return dict(path=str(path.relative_to(PROJECT)), sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw))


def checked_reference(reference, *, cap=MAX_INPUT, prefixes=None):
    require(type(reference) is dict and set(reference) == {'path', 'sha256', 'size_bytes'}
        and type(reference['size_bytes']) is int and 0 <= reference['size_bytes'] <= cap
        and type(reference['sha256']) is str and re.fullmatch('[0-9a-f]{64}', reference['sha256']),
        'terminal_reference_shape')
    name = logical(reference['path'])
    require(prefixes is None or any(name.startswith(prefix) for prefix in prefixes),
        'terminal_reference_scope')
    raw, _ = read_bytes(PROJECT / name, cap)
    require(len(raw) == reference['size_bytes'] and
        hashlib.sha256(raw).hexdigest() == reference['sha256'], 'terminal_reference_changed')
    return raw


def verify_pins(pins, before_pin, *, install_files=None):
    require(type(pins) is dict and 1 <= len(pins) <= 1024, 'terminal_finite_source_inventory')
    for name, sha in pins.items():
        before_pin()
        require(type(sha) is str and re.fullmatch('[0-9a-f]{64}', sha),
            'terminal_source_pin_shape')
        source = name
        if install_files is not None and name in install_files:
            alias = install_files[name]
            require(type(alias) is dict and set(alias) == {'path', 'sha256'}
                and alias['sha256'] == sha and alias['path'] == PREFIX+'/after/'+name,
                'terminal_install_alias_shape')
            source = alias['path']
        raw, _ = read_bytes(PROJECT / logical(source))
        require(hashlib.sha256(raw).hexdigest() == sha, 'terminal_input_changed')


def load_pinned_timing(pins):
    raw, _ = read_bytes(PROJECT / TIMING)
    require(hashlib.sha256(raw).hexdigest() == pins.get(TIMING), 'terminal_helper_source_changed')
    module = types.ModuleType('radik_p28_supervisor_timing')
    module.__file__ = str(PROJECT / TIMING)
    exec(compile(raw, module.__file__, 'exec', dont_inherit=True), module.__dict__)
    return module


def prepare_installation(admission, manifest, *, lock_fd, rehearsal_sha, before_pin):
    """Execute only pinned setup support under the existing canonical owner lock.

    Candidate active-path hashes are checked through finite manifest aliases
    before installation. Afterward every installed code pin is checked again.
    """
    gate_name = 'config.application_profile_gate'
    require(gate_name not in sys.modules, 'terminal_profile_gate_already_loaded')
    alias = manifest['install_files']['config/application_profile_gate.py']
    raw, _ = read_bytes(PROJECT/logical(alias['path']))
    require(hashlib.sha256(raw).hexdigest() == admission['code_pins']['config/application_profile_gate.py'],
        'terminal_candidate_gate_changed')
    gate = types.ModuleType(gate_name)
    gate.__file__ = str(PROJECT/alias['path'])
    sys.modules[gate_name] = gate
    try:
        exec(compile(raw, gate.__file__, 'exec', dont_inherit=True), gate.__dict__)
        selected = gate.load_profile(PROJECT, admission['ordinary_profile_manifest_ref'])
        require(selected['manifest'] == manifest, 'terminal_install_manifest_binding')
        context = None if rehearsal_sha is None else gate.rehearsal_context(PROJECT, rehearsal_sha)
        if context is None:
            gate.owner_eligibility(PROJECT, selected)
        before_pin()
        raw, _ = read_bytes(PROJECT/ACTIVATOR)
        require(hashlib.sha256(raw).hexdigest() == admission['code_pins'].get(ACTIVATOR),
            'terminal_activator_changed')
        installer = types.ModuleType('radik_p28_owner_installation')
        installer.__file__ = str(PROJECT/ACTIVATOR)
        exec(compile(raw, installer.__file__, 'exec', dont_inherit=True), installer.__dict__)
        result = installer.activate(PROJECT, rehearsal_context=context, owner_lock_fd=lock_fd)
        verify_pins(admission['code_pins'], before_pin)
        return result
    finally:
        sys.modules.pop(gate_name, None)


def load_admission(expected_sha, rehearsal_sha, before_pin):
    require(type(expected_sha) is str and re.fullmatch('[0-9a-f]{64}', expected_sha),
        'terminal_admission_hash')
    require((PROJECT == PRODUCTION_PROJECT) == (rehearsal_sha is None),
        'terminal_rehearsal_copy_required')
    raw, _ = read_bytes(PROJECT / ADMISSION, MAX_ADMISSION)
    require(hashlib.sha256(raw).hexdigest() == expected_sha, 'terminal_admission_changed')
    value = json.loads(raw)
    require(value.get('schema') == 'radik.p28.owner_terminal_admission.v01'
        and value.get('independent_reviewer') == REVIEWER
        and value.get('automatic_retry') is False
        and value.get('model_observation_after_handoff') is False,
        'terminal_admission_profile')
    pins = value.get('code_pins')
    manifest = json.loads(checked_reference(value['ordinary_profile_manifest_ref'], cap=MAX_ADMISSION))
    require(type(manifest) is dict and manifest.get('pins') == pins
        and manifest.get('source_review_ref') == value.get('source_review_ref')
        and type(manifest.get('install_files')) is dict
        and manifest['install_files'] and set(manifest['install_files']) <= set(pins),
        'terminal_candidate_install_inventory')
    verify_pins(pins, before_pin, install_files=manifest['install_files'])
    argv = value.get('argv')
    require(type(argv) is list and len(argv) >= 7 and argv[0] == '.venv-plan/bin/python'
        and argv[1:4] == ['-I', '-S', '-B']
        and argv[4] == 'config/launch.py' and argv[5:7] == ['--console', '--owner-scenario']
        and {SELF, TIMING, ACTIVATOR, argv[4]}.issubset(pins)
        and argv[0] not in pins, 'terminal_ordinary_argv_required')
    require(all(type(arg) is str and 0 < len(arg) <= 1024 for arg in argv),
        'terminal_argv_shape')
    # The independent source grant is finite and does not refer to its future actual.
    review = json.loads(checked_reference(value['source_review_ref'], cap=MAX_ADMISSION))
    require(review.get('reviewer') == REVIEWER and review.get('code_pins') == pins
        and review.get('interpreter_ref') == value.get('interpreter_ref')
        and review.get('source_only_rehearsal_authorized') is True,
        'terminal_independent_source_review')
    verify_interpreter(value.get('interpreter_ref'))
    if rehearsal_sha is not None:
        require(re.fullmatch('[0-9a-f]{64}', rehearsal_sha), 'terminal_rehearsal_hash')
        seal_raw, _ = read_bytes(PROJECT / REHEARSAL_SEAL, MAX_ADMISSION)
        require(hashlib.sha256(seal_raw).hexdigest() == rehearsal_sha,
            'terminal_rehearsal_seal_changed')
        seal = json.loads(seal_raw)
        require(seal.get('schema') == 'radik.p28.isolated_rehearsal_seal.v01'
            and seal.get('reviewer') == REVIEWER and seal.get('owned_copy_root') == str(PROJECT)
            and seal.get('production_root') == str(PRODUCTION_PROJECT)
            and seal.get('environment_root') == str(PRODUCTION_PROJECT)
            and seal.get('code_pins') == pins and seal.get('source_review_ref') == value['source_review_ref']
            and seal.get('real_AUTH_provider_native_E_SAVE_allowed') is False
            and seal.get('production_writes_allowed') is False
            and seal.get('network') == 'DENIED', 'terminal_rehearsal_scope')
    else:
        require(value.get('owner_execution_authorized') is True
            and value.get('status') == 'OWNER_EXECUTION_ADMITTED_AFTER_SOURCE_AND_REHEARSAL',
            'terminal_owner_source_and_rehearsal_required')
        result = json.loads(checked_reference(value['rehearsal_result_review_ref'], cap=MAX_ADMISSION))
        require(result.get('reviewer') == REVIEWER and result.get('code_pins') == pins
            and result.get('all_required_controls_passed') is True
            and result.get('owner_execution_authorized') is True,
            'terminal_independent_rehearsal_result')
    return value, manifest


def acquire_lock(expected):
    """P23 exact lock identity, shared through launch/bootstrap/reexec."""
    target = PROJECT / LOCK
    parents(target)
    fd = os.open(target, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.geteuid() and info.st_nlink == 1,
            'terminal_lock_regular')
        actual = dict(device=info.st_dev, inode=info.st_ino, owner=info.st_uid,
            mode=stat.S_IMODE(info.st_mode), links=info.st_nlink)
        require(actual == expected, 'terminal_lock_identity_changed')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = target.lstat()
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
            'terminal_lock_path_changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def bounded_cleanup(child, *, stop_ns, limits, signals, started_ns):
    """P23 bounded exact-child waits; never signal a process group or unrelated PID."""
    if child is None:
        return True
    schedule = (('INTERRUPT', 0, signal.SIGINT),
        ('TERMINATE', limits['interrupt_grace_seconds'], signal.SIGTERM),
        ('KILL', limits['interrupt_grace_seconds'] + limits['terminate_grace_seconds'], signal.SIGKILL))
    end_ns = min(stop_ns + int(limits['cleanup_seconds'] * 1e9),
        stop_ns + int((limits['interrupt_grace_seconds'] +
            limits['terminate_grace_seconds'] + limits['kill_wait_seconds']) * 1e9))
    for name, offset, signum in schedule:
        if child.poll() is not None:
            child.wait(timeout=0)
            return True
        when_ns = stop_ns + int(offset * 1e9)
        remaining = min(when_ns, end_ns) - time.monotonic_ns()
        if remaining > 0:
            try:
                child.wait(timeout=remaining / 1e9)
                return True
            except subprocess.TimeoutExpired:
                pass
        if child.poll() is not None:
            child.wait(timeout=0)
            return True
        if time.monotonic_ns() >= end_ns:
            return False
        if not any(row['action'] == name for row in signals):
            try:
                child.send_signal(signum)
            except ProcessLookupError:
                if child.poll() is not None:
                    child.wait(timeout=0)
                    return True
            signals.append(dict(action=name, elapsed_wall_ns=time.monotonic_ns()-started_ns))
        if name == 'KILL':
            try:
                child.wait(timeout=max(0, end_ns-time.monotonic_ns()) / 1e9)
                return True
            except subprocess.TimeoutExpired:
                return False
    return child.poll() is not None


def retain_failure(receipt, value, timing):
    value = timing.failure(value)
    primary = receipt['primary_failure'] is None
    if primary:
        receipt['primary_failure'] = value
    elif value != receipt['primary_failure'] and value not in receipt['secondary_failures']:
        receipt['secondary_failures'].append(value)
    show(('PRIMARY_FAILURE' if primary else 'SECONDARY_FAILURE') + ' phase=' +
        value['phase'] + ' code=' + value['code'] + ' error_class=' + value['error_class'])


def supervise(profile, *, started_ns, lock_fd, launch, timing, run,
        interrupted=lambda: False, popen=subprocess.Popen):
    """The P23 parent loop with P28 scoped timing and independent raw readbacks."""
    limits = profile['limits']
    deadline = timing.Deadline(started_ns, limits=limits)
    binding = hashlib.sha256(canonical(launch)).hexdigest()
    child = None
    log = None
    pending = b''
    stdout_size = 0
    sequence = 0
    eof = False
    final = None
    monitor_error = None
    required_failure = None
    last_display_ns = started_ns
    latest_cpu_ns = 0
    useful = set()
    required_refs = []
    receipt = dict(schema='radik.p28.owner_terminal_receipt.v01', status='NOT_LAUNCHED',
        approved_argv=profile['argv'], launch_ref=profile.get('launch_ref'),
        operation_started_ns=started_ns, operation_deadline_ns=deadline.deadline_ns,
        limits=limits, primary_failure=None, secondary_failures=[], signals=[],
        child_reaped=False, automatic_retry=False, model_observation_after_handoff=False,
        supervisor_model_calls=0, supervisor_native_calls=0,
        native_acceptance_inferred=False, runtime_adoption=False)
    try:
        fd = os.open(run/'child_stdout.raw', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        log = os.fdopen(fd, 'wb', buffering=0)
        argv = [verify_interpreter(profile['interpreter_ref']), *profile['argv'][1:]]
        argv[4] = str(PROJECT/argv[4])
        argv.extend(('--owner-operation-started-ns', str(started_ns),
            '--owner-operation-deadline-ns', str(deadline.deadline_ns),
            '--owner-operation-started-utc', str(launch['operation_started_utc']),
            '--owner-supervisor-launch', str((run/'launch.json').relative_to(PROJECT)),
            '--owner-run-binding', binding, '--owner-lock-fd', str(lock_fd)))
        if profile.get('rehearsal_seal_sha256') is not None:
            argv.extend(('--rehearsal-seal-sha256', profile['rehearsal_seal_sha256']))
        receipt['actual_argv'] = list(argv)
        child = popen(argv, cwd=PROJECT.parent if profile.get('home_directory') is None else
            Path(profile['home_directory']), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env={'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C'},
            close_fds=True, pass_fds=(lock_fd,), start_new_session=True)
        receipt['child_pid'] = child.pid
        os.set_blocking(child.stdout.fileno(), False)
        while True:
            now_ns = time.monotonic_ns()
            try:
                raw = os.read(child.stdout.fileno(), 65536)
                if not raw:
                    eof = True
            except BlockingIOError:
                raw = b''
            # Preserve every new byte before parsing, including malformed partials.
            if raw:
                require(log.write(raw) == len(raw), 'terminal_stdout_short_write')
                os.fsync(log.fileno())
                stdout_size += len(raw)
            require(stdout_size <= limits['stdout_bytes'], 'terminal_stdout_bound')
            parts = (pending + raw).split(b'\n')
            pending = parts.pop()
            require(len(pending) <= limits['event_row_bytes'], 'terminal_partial_row_bound')
            for part in parts:
                if not part:
                    continue
                try:
                    row = json.loads(part)
                except (ValueError, UnicodeError):
                    continue
                if type(row) is not dict or row.get('schema') != timing.SCHEMA:
                    continue
                require(len(part)+1 <= limits['event_row_bytes'], 'terminal_event_row_bound')
                timing.event_shape(row, child_pid=child.pid, run_binding=binding,
                    operation_started_ns=started_ns)
                require(row['sequence'] == sequence + 1 and sequence < limits['event_rows'],
                    'terminal_event_sequence')
                sequence += 1
                latest_cpu_ns = row['elapsed_process_cpu_ns']
                kind = row['kind']
                # The cause is retained before any later coalesced checkpoint/return.
                if kind in ('PRIMARY_FAILURE', 'REQUIRED_WITNESS_UNAVAILABLE'):
                    value = timing.failure(row.get('failure'))
                    if kind == 'REQUIRED_WITNESS_UNAVAILABLE' and required_failure is None:
                        required_failure = value
                    retain_failure(receipt, value, timing)
                if receipt['primary_failure'] is not None and deadline.stop_ns is None:
                    deadline.stop_ns = time.monotonic_ns()
                    deadline.reason = 'REQUIRED_WITNESS_UNAVAILABLE' if required_failure is not None else \
                        receipt['primary_failure']['code']
                    due = 'INTERRUPT'
                else:
                    due = deadline.action(time.monotonic_ns(), owner_interrupt=interrupted(),
                        required_failure=required_failure is not None)
                if due and receipt['primary_failure'] is None:
                    retain_failure(receipt, timing.fallback(deadline.reason, 'SupervisorStop'), timing)
                if due and child.poll() is None:
                    child.send_signal(dict(INTERRUPT=signal.SIGINT, TERMINATE=signal.SIGTERM,
                        KILL=signal.SIGKILL)[due])
                    receipt['signals'].append(dict(action=due,
                        elapsed_wall_ns=time.monotonic_ns()-started_ns))
                verified = False
                if kind in ('E_ENTER', 'REPORT_READBACK_ACK') and deadline.stop_ns is None:
                    raw_evidence = checked_reference(row.get('readback_ref'),
                        cap=limits['evidence_bytes'], prefixes=profile['evidence_prefixes'])
                    require(len(raw_evidence) > 0, 'terminal_empty_readback')
                    verified = True
                    required_refs.append(dict(row['readback_ref']))
                    if kind == 'REPORT_READBACK_ACK' and row.get('useful') is True:
                        key = (row['readback_ref']['path'], row['readback_ref']['sha256'])
                        require(key not in useful, 'terminal_duplicate_useful_readback')
                        useful.add(key)
                granted = deadline.event(row, observed_ns=time.monotonic_ns(),
                    readback_verified=verified)
                if granted:
                    show('MILESTONE phase=E wall=%.3fs processCPU=%.3fs report=%s path=%s' % (
                        (time.monotonic_ns()-started_ns)/1e9, latest_cpu_ns/1e9,
                        token(row['report_kind']), logical(row['readback_ref']['path'])))
                elif kind in ('PHASE_ENTER', 'E_ENTER', 'E_EXIT'):
                    show('PHASE phase=%s wall=%.3fs processCPU=%.3fs' % (
                        deadline.phase, (time.monotonic_ns()-started_ns)/1e9, latest_cpu_ns/1e9))
                if kind == 'FINAL':
                    require(final is None and type(row.get('success')) is bool,
                        'terminal_final_shape')
                    final = dict(row)
                    if row.get('failure') is not None:
                        retain_failure(receipt, row['failure'], timing)
            now_ns = time.monotonic_ns()
            if now_ns-last_display_ns >= int(limits['status_seconds']*1e9):
                last_display_ns = now_ns
                show('STATUS phase=%s wall=%.1fs processCPU(last)=%.3fs native=%.1fs remaining=%.1fs milestone=%s' % (
                    deadline.phase, (now_ns-started_ns)/1e9, latest_cpu_ns/1e9,
                    deadline.native_used_ns(now_ns)/1e9, max(0, deadline.deadline_ns-now_ns)/1e9,
                    'NONE' if deadline.last_useful_identity is None else
                    deadline.last_useful_identity['report_kind']))
            action = deadline.action(now_ns, owner_interrupt=interrupted(),
                required_failure=required_failure is not None)
            if receipt['primary_failure'] is not None and deadline.stop_ns is None:
                deadline.stop_ns, deadline.reason = now_ns, receipt['primary_failure']['code']
                action = 'INTERRUPT'
            if action:
                if receipt['primary_failure'] is None:
                    retain_failure(receipt, timing.fallback(deadline.reason, 'SupervisorStop'), timing)
                if child.poll() is None:
                    child.send_signal(dict(INTERRUPT=signal.SIGINT, TERMINATE=signal.SIGTERM,
                        KILL=signal.SIGKILL)[action])
                    receipt['signals'].append(dict(action=action, elapsed_wall_ns=now_ns-started_ns))
            code = child.poll()
            if code is not None and eof:
                break
            if deadline.stop_ns is not None and now_ns-deadline.stop_ns >= int(limits['cleanup_seconds']*1e9):
                break
            time.sleep(limits['poll_seconds'])
    except BaseException as error:
        code = error.args[0] if type(error) is ValueError and len(error.args) == 1 else 'SANITIZED_MONITOR_FAILURE'
        code = code if type(code) is str and re.fullmatch('[A-Za-z0-9_]{1,160}', code) else 'SANITIZED_MONITOR_FAILURE'
        monitor_error = timing.fallback(code, type(error).__name__)
        retain_failure(receipt, monitor_error, timing)
    finally:
        if child is not None and child.poll() is None:
            if deadline.stop_ns is None:
                deadline.stop_ns, deadline.reason = time.monotonic_ns(), 'SUPERVISOR_FAILURE'
            try:
                bounded_cleanup(child, stop_ns=deadline.stop_ns, limits=limits,
                    signals=receipt['signals'], started_ns=started_ns)
            except BaseException as error:
                retain_failure(receipt, timing.fallback('CLEANUP_EXCEPTION', type(error).__name__), timing)
        reaped = child is None or child.poll() is not None
        receipt['child_reaped'] = child is not None and reaped
        receipt['child_exit_code'] = None if child is None else child.returncode
        if child is not None:
            # After a monitor refusal, keep the already-produced tail as raw
            # evidence. Reap precedes this finite nonblocking drain.
            if reaped and log is not None and not eof:
                try:
                    while stdout_size <= limits['stdout_bytes']:
                        try:
                            raw = os.read(child.stdout.fileno(), 65536)
                        except BlockingIOError:
                            break
                        if not raw:
                            eof = True
                            break
                        require(log.write(raw) == len(raw), 'terminal_stdout_short_write')
                        os.fsync(log.fileno())
                        stdout_size += len(raw)
                    if stdout_size > limits['stdout_bytes']:
                        retain_failure(receipt, timing.fallback('TERMINAL_STDOUT_BOUND'), timing)
                except BaseException:
                    retain_failure(receipt, timing.fallback('STDOUT_TAIL_PRESERVATION_FAILED'), timing)
            try:
                child.stdout.close()
            except BaseException:
                retain_failure(receipt, timing.fallback('STDOUT_CLOSE_FAILED'), timing)
        if log is not None:
            try:
                log.close()
            except BaseException:
                retain_failure(receipt, timing.fallback('LOG_CLOSE_FAILED'), timing)
        if receipt['child_exit_code'] == timing.EMERGENCY_IO_EXIT:
            emergency = timing.fallback('REQUIRED_WITNESS_CHANNEL_IO_FAILED',
                'EmergencyChannelIO', 'REQUIRED_WITNESS_AVAILABILITY')
            # As in P23, a broken emergency channel outranks a derived monitor
            # failure, but cannot erase an earlier known application cause.
            if receipt['primary_failure'] == monitor_error and required_failure is None:
                receipt['primary_failure'] = None
            retain_failure(receipt, emergency, timing)
        if not reaped:
            retain_failure(receipt, timing.fallback('CLEANUP_UNCONFIRMED', 'CleanupUnconfirmed'), timing)
        if pending:
            retain_failure(receipt, timing.fallback('TERMINAL_FINAL_PARTIAL_OUTPUT'), timing)
        for reference in required_refs if receipt['primary_failure'] is None else ():
            try:
                reason = deadline.due_reason(time.monotonic_ns())
                if reason is not None:
                    if deadline.stop_ns is None:
                        deadline.stop_ns = deadline.deadline_ns if reason == 'OPERATION_LIMIT' else time.monotonic_ns()
                        deadline.reason = reason
                    retain_failure(receipt, timing.fallback(reason, 'SupervisorStop'), timing)
                    break
                checked_reference(reference, cap=limits['evidence_bytes'],
                    prefixes=profile['evidence_prefixes'])
                reason = deadline.due_reason(time.monotonic_ns())
                if reason is not None:
                    if deadline.stop_ns is None:
                        deadline.stop_ns = deadline.deadline_ns if reason == 'OPERATION_LIMIT' else time.monotonic_ns()
                        deadline.reason = reason
                    retain_failure(receipt, timing.fallback(reason, 'SupervisorStop'), timing)
                    break
            except BaseException:
                retain_failure(receipt, timing.fallback('REQUIRED_WITNESS_UNAVAILABLE',
                    'RequiredWitnessLoss', 'REQUIRED_WITNESS_AVAILABILITY'), timing)
                break
        if receipt['primary_failure'] is None:
            reason = deadline.due_reason(time.monotonic_ns())
            if reason is not None:
                if deadline.stop_ns is None:
                    deadline.stop_ns = deadline.deadline_ns if reason == 'OPERATION_LIMIT' else time.monotonic_ns()
                    deadline.reason = reason
                retain_failure(receipt, timing.fallback(reason, 'SupervisorStop'), timing)
        if receipt['primary_failure'] is None:
            missing = ('CHILD_CLOSED_WITHOUT_FINAL_RETURN' if final is None else
                'CHILD_REPORTED_FAILURE_WITHOUT_PRIMARY' if final['success'] is not True else
                'CHILD_EXIT_NONZERO_WITHOUT_PRIMARY' if receipt['child_exit_code'] != 0 else
                'OPEN_PROVIDER_OR_NATIVE_SPAN_AT_CLOSE' if deadline.provider_span is not None or
                    deadline.native_spans else
                'E_NOT_ENTERED_OR_CLOSED' if profile.get('require_one_e', True) and
                    (deadline.e_entered_ns is None or deadline.e_exited_ns is None) else
                'E_EARLY_CHECKPOINT_NOT_ACCEPTED' if deadline.e_entered_ns is not None and
                    deadline.first_checkpoint_ns is None else None)
            if missing is not None:
                retain_failure(receipt, timing.fallback(missing), timing)
        receipt.update(status='CLEANUP_UNCONFIRMED' if not reaped else
            'CHILD_CLOSED_REVIEW_REQUIRED' if receipt['primary_failure'] is None else 'STOPPED_NO_RETRY',
            deadline_measurement=deadline.measurement(time.monotonic_ns()),
            monitor_error=monitor_error, required_witness_failure=required_failure,
            final_event=final, stdout_bytes=stdout_size, stdout_eof_observed=eof,
            events=sequence, useful_readback_count=len(useful),
            cleanup_budget_seconds=limits['cleanup_seconds'],
            lock_explicit_unlock_permitted=reaped)
        put(run/'receipt.json', receipt, cap=limits['receipt_bytes'])
        show('CLOSED status='+receipt['status']+' child_reaped='+str(receipt['child_reaped'])+
            ' receipt='+str((run/'receipt.json').relative_to(PROJECT)))
    return receipt


def release_owned_lock(fd, *, child_started, receipt):
    allowed = not child_started or receipt is not None and receipt['lock_explicit_unlock_permitted']
    if allowed:
        fcntl.flock(fd, fcntl.LOCK_UN)
    # A live child's inherited description retains the flock after this close.
    os.close(fd)
    return bool(allowed)


def reservation_directory(lock_fd, expected_lock):
    """Prepare only the one-use reservation directory under the canonical flock."""
    target = PROJECT/LOCK
    parents(target)
    info = os.fstat(lock_fd)
    current = target.lstat()
    require((current.st_dev,current.st_ino) == (info.st_dev,info.st_ino)
        and dict(device=info.st_dev,inode=info.st_ino,owner=info.st_uid,
            mode=stat.S_IMODE(info.st_mode),links=info.st_nlink) == expected_lock,
        'terminal_reservation_canonical_lock_identity')
    fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    directory = PROJECT/RESERVATIONS
    parents(directory)
    if not directory.exists() and not directory.is_symlink():
        directory.mkdir(mode=0o700)
        fd = os.open(directory.parent,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and not directory.is_symlink()
        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
        'terminal_reservation_directory')
    return directory


def reservation_target(admission_sha):
    require(type(admission_sha) is str and re.fullmatch('[0-9a-f]{64}',admission_sha),
        'terminal_reservation_admission_hash')
    return PROJECT/RESERVATIONS/(admission_sha+'.json')


def refuse_existing_reservation(admission_sha):
    """History is evidence only. Every existing reservation refuses another run."""
    target = reservation_target(admission_sha)
    if not target.exists() and not target.is_symlink():
        return
    name = str(target.relative_to(PROJECT))
    run = 'UNAVAILABLE'
    outcome_name = 'UNAVAILABLE'
    outcome_status = 'UNCONFIRMED'
    try:
        raw,info = read_bytes(target,65536)
        require(stat.S_IMODE(info.st_mode) == 0o600,'terminal_reservation_mode')
        value = json.loads(raw)
        require(type(value) is dict and value.get('schema') == 'radik.p28.owner_scenario_reservation.v01'
            and value.get('admission_sha256') == admission_sha
            and value.get('status') == 'RESERVED_OUTCOME_NOT_YET_PUBLISHED',
            'terminal_existing_reservation_shape')
        candidate_run = logical(value.get('run'))
        require(candidate_run.startswith(PREFIX+'/owner_terminal_runs/') and
            re.fullmatch(r'OWNER_[0-9]{8}T[0-9]{6}_[0-9a-f]{32}',
                candidate_run[len(PREFIX+'/owner_terminal_runs/'):]),
            'terminal_existing_reservation_locator')
        run = candidate_run
        outcome_name = run+'/reservation_outcome.json'
        require(value.get('outcome_path') == outcome_name,
            'terminal_existing_reservation_outcome_locator')
        path = PROJECT/outcome_name
        if path.exists() or path.is_symlink():
            outcome_raw,_ = read_bytes(path,131072)
            outcome = json.loads(outcome_raw)
            require(type(outcome) is dict and outcome.get('schema') == 'radik.p28.owner_scenario_reservation_outcome.v01'
                and outcome.get('admission_sha256') == admission_sha and outcome.get('run') == run
                and outcome.get('status') in ('NOT_LAUNCHED','CHILD_CLOSED','CLEANUP_UNCONFIRMED',
                    'CHILD_START_OR_CLOSURE_UNCONFIRMED'), 'terminal_existing_reservation_outcome')
            outcome_status = outcome['status']
    except BaseException:
        # A malformed or incomplete old record cannot authorize a new attempt.
        outcome_status = 'UNCONFIRMED'
    show('RESERVATION_REFUSED run='+run+' reservation='+name+
        ' outcome='+outcome_name+' outcome_status='+outcome_status)
    raise ValueError('terminal_owner_scenario_admission_already_reserved')


def reserve_owner_scenario(admission_sha,admission,run):
    """Exclusive immutable admission-SHA reservation before installation or child."""
    target = reservation_target(admission_sha)
    name = str(run.relative_to(PROJECT))
    raw,_ = read_bytes(PROJECT/SELF)
    require(hashlib.sha256(raw).hexdigest() == admission['code_pins'][SELF],
        'terminal_reservation_supervisor_source_changed')
    source_ref = dict(path=SELF,sha256=admission['code_pins'][SELF],size_bytes=len(raw))
    value = dict(schema='radik.p28.owner_scenario_reservation.v01',
        status='RESERVED_OUTCOME_NOT_YET_PUBLISHED',admission_sha256=admission_sha,
        run=name,outcome_path=name+'/reservation_outcome.json',
        source_review_ref=admission['source_review_ref'],supervisor_source_ref=source_ref,
        operation_started_ns=STARTED_NS,operation_started_utc=STARTED_UTC,
        supervisor_pid=os.getpid(),canonical_lock_identity=admission['lock_identity'],
        one_use=True,automatic_retry=False,native_acceptance_inferred=False)
    reference = put(target,value,cap=65536)
    show('RESERVED run='+name+' reservation='+reference['path'])
    return reference


def publish_reservation_outcome(reservation_ref,admission_sha,run,*,receipt,
        supervision_attempted,prelaunch_failure):
    """Publish once; an absent receipt after entering supervision stays ambiguous."""
    checked_reference(reservation_ref,cap=65536)
    child_pid = receipt.get('child_pid') if type(receipt) is dict else None
    receipt_ref = None
    if type(receipt) is dict:
        raw,_ = read_bytes(run/'receipt.json',4194304)
        require(json.loads(raw) == receipt,'terminal_reservation_receipt_binding')
        receipt_ref = dict(path=str((run/'receipt.json').relative_to(PROJECT)),
            sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
    if type(child_pid) is int and child_pid > 0:
        started = True
        reaped = receipt.get('child_reaped') is True
        status = 'CHILD_CLOSED' if reaped else 'CLEANUP_UNCONFIRMED'
        basis = 'ACTUAL_PID_IN_DURABLE_SUPERVISOR_RECEIPT'
    elif type(receipt) is dict and 'child_pid' not in receipt:
        started,reaped,status = False,False,'NOT_LAUNCHED'
        basis = 'NO_CHILD_CREATED_IN_COMPLETED_SUPERVISOR_RECEIPT'
    elif not supervision_attempted:
        started,reaped,status = False,False,'NOT_LAUNCHED'
        basis = 'SUPERVISION_NOT_ENTERED'
    else:
        started,reaped,status = None,None,'CHILD_START_OR_CLOSURE_UNCONFIRMED'
        basis = 'SUPERVISION_ENTERED_WITHOUT_CONFIRMED_RECEIPT'
    primary = receipt.get('primary_failure') if type(receipt) is dict else prelaunch_failure
    outcome = dict(schema='radik.p28.owner_scenario_reservation_outcome.v01',
        status=status,admission_sha256=admission_sha,run=str(run.relative_to(PROJECT)),
        reservation_ref=reservation_ref,receipt_ref=receipt_ref,
        child_started=started,child_pid=child_pid,child_reaped=reaped,
        child_start_evidence=basis,child_exit_code=receipt.get('child_exit_code') if type(receipt) is dict else None,
        child_status=receipt.get('status') if type(receipt) is dict else None,
        primary_failure=primary,supervision_attempted=supervision_attempted,
        operation_started_ns=STARTED_NS,operation_started_utc=STARTED_UTC,
        outcome_recorded_monotonic_ns=time.monotonic_ns(),outcome_recorded_utc=int(time.time()),
        automatic_retry=False,reservation_reset_allowed=False,
        supervisor_model_calls=0,native_acceptance_inferred=False)
    return put(run/'reservation_outcome.json',outcome,cap=131072)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--admission-sha256', required=True)
    parser.add_argument('--rehearsal-seal-sha256')
    args = parser.parse_args()
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
        and sys.version_info[:2] == (3, 14) and Path(__file__).absolute() == PROJECT/SELF,
        'terminal_selected_interpreter')
    lock_fd = None
    receipt = None
    run = None
    child_started = False
    supervision_attempted = False
    reservation_ref = None
    prelaunch_failure = None
    exit_code = 2
    interrupted = [False]
    previous = {}
    try:
        def before_pin():
            require(not interrupted[0] and time.monotonic_ns() < STARTED_NS+7800*1000000000,
                'terminal_prelaunch_operation_limit')
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, lambda _s, _f: interrupted.__setitem__(0, True))
        admission, manifest = load_admission(args.admission_sha256, args.rehearsal_seal_sha256, before_pin)
        timing = load_pinned_timing(admission['code_pins'])
        require(admission.get('limits') == timing.LIMITS, 'terminal_reviewed_limits_changed')
        require(Path(sys.prefix) == PRODUCTION_PROJECT/'.venv-plan'
            and Path(sys.executable).absolute() == Path(admission['interpreter_ref']['path']),
            'terminal_selected_interpreter_prefix')
        lock_fd = acquire_lock(admission['lock_identity'])
        reservation_directory(lock_fd,admission['lock_identity'])
        refuse_existing_reservation(args.admission_sha256)
        runs = PROJECT/PREFIX/'owner_terminal_runs'
        parents(runs)
        if not runs.exists():
            runs.mkdir(mode=0o700)
        name = datetime.now(timezone.utc).strftime('OWNER_%Y%m%dT%H%M%S_')+uuid.uuid4().hex
        run = runs/name
        run.mkdir(mode=0o700)
        reservation_ref = reserve_owner_scenario(args.admission_sha256,admission,run)
        installation = prepare_installation(admission, manifest, lock_fd=lock_fd,
            rehearsal_sha=args.rehearsal_seal_sha256, before_pin=before_pin)
        installation_ref = put(run/'installation_receipt.json', installation)
        launch = dict(schema='radik.p28.owner_terminal_launch.v01',
            status='SOURCE_VERIFIED_BEFORE_CHILD', admission_sha256=args.admission_sha256,
            rehearsal_seal_sha256=args.rehearsal_seal_sha256,
            source_review_ref=admission['source_review_ref'],
            ordinary_profile_manifest_ref=admission['ordinary_profile_manifest_ref'],
            installation_receipt_ref=installation_ref,
            owner_scenario_reservation_ref=reservation_ref,
            approved_argv=admission['argv'], supervisor_pid=os.getpid(),
            interpreter_ref=admission['interpreter_ref'], environment_root=str(PRODUCTION_PROJECT),
            inherited_lock_fd=lock_fd, operation_started_ns=STARTED_NS,
            operation_started_utc=STARTED_UTC,
            operation_deadline_ns=STARTED_NS+timing.LIMITS['operation_seconds']*1000000000,
            limits=timing.LIMITS, automatic_retry=False,
            model_observation_after_handoff=False)
        launch_ref = put(run/'launch.json', launch)
        before_pin()
        show('START ordinary owner scenario; total<=7800s native<=3600s E-readback<=600s E-idle<=900s cleanup<=30s; ceilings are not ETA')
        child_started = True
        supervision_attempted = True
        receipt = supervise(dict(argv=admission['argv'], limits=timing.LIMITS,
            interpreter_ref=admission['interpreter_ref'],
            evidence_prefixes=admission['evidence_prefixes'],
            home_directory=admission.get('home_directory', str(Path.home())),
            require_one_e=args.rehearsal_seal_sha256 is None,
            rehearsal_seal_sha256=args.rehearsal_seal_sha256, launch_ref=launch_ref),
            started_ns=STARTED_NS, lock_fd=lock_fd, launch=launch, timing=timing,
            run=run, interrupted=lambda: interrupted[0])
        exit_code = 0 if receipt['status'] == 'CHILD_CLOSED_REVIEW_REQUIRED' else 2
    except BaseException as error:
        code = error.args[0] if type(error) is ValueError and len(error.args) == 1 else 'SUPERVISOR_PREPARATION_FAILED'
        code = code if type(code) is str and re.fullmatch('[A-Za-z0-9_]{1,160}', code) else 'SUPERVISOR_PREPARATION_FAILED'
        prelaunch_failure = dict(phase='OWNER_TERMINAL',code=code,error_class=type(error).__name__)
        known_primary = type(receipt) is dict and receipt.get('primary_failure') is not None
        show(('SECONDARY_FAILURE' if known_primary else 'PRIMARY_FAILURE')+
            ' phase=OWNER_TERMINAL code='+code+' error_class='+type(error).__name__)
        if run is not None and not child_started:
            try:
                put(run/'receipt.json', dict(schema='radik.p28.owner_prelaunch_failure.v01',
                    status='NOT_LAUNCHED_NO_RETRY', primary_failure=dict(phase='OWNER_TERMINAL',
                    code=code, error_class=type(error).__name__), child_started=False,
                    operation_started_ns=STARTED_NS, elapsed_wall_ns=time.monotonic_ns()-STARTED_NS,
                    automatic_retry=False, model_calls=0, native_calls=0))
            except BaseException:
                show('PRELAUNCH_RECEIPT_UNAVAILABLE child_started=false')
        exit_code = 2
    finally:
        if reservation_ref is not None:
            try:
                outcome_ref = publish_reservation_outcome(reservation_ref,args.admission_sha256,run,
                    receipt=receipt,supervision_attempted=supervision_attempted,
                    prelaunch_failure=prelaunch_failure)
                show('RESERVATION_OUTCOME path='+outcome_ref['path'])
            except BaseException:
                known_primary = prelaunch_failure is not None or type(receipt) is dict and receipt.get('primary_failure') is not None
                show(('SECONDARY_FAILURE' if known_primary else 'PRIMARY_FAILURE')+
                    ' phase=OWNER_SCENARIO_RESERVATION code=RESERVATION_OUTCOME_UNAVAILABLE error_class=ReservationPublicationError')
                exit_code = 2
        if lock_fd is not None:
            release_owned_lock(lock_fd, child_started=child_started, receipt=receipt)
        for signum, old in previous.items():
            signal.signal(signum, old)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
