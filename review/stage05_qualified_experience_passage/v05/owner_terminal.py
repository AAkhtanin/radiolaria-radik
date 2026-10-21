#!/usr/bin/env python3
"""Stage05 finite ordinary qualified-experience scenario, derived from P31.

P23 mechanisms retained: pin-before-import, first-cause precedence, durable raw
partials, exact-child signals, bounded reap and inherited-lock release policy.
No candidate application/native/provider module is imported by this supervisor.
The accepted original timer source remains immutable; its algorithms are reused.
"""
import time
STARTED_NS = time.monotonic_ns()
STARTED_UTC = int(time.time())
import argparse
import ast
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
PROJECT = Path(__file__).absolute().parents[3]
PREFIX = 'review/stage05_qualified_experience_passage/v05'
SELF = PREFIX + '/owner_terminal.py'
RESERVATIONS = 'state/stage05_owner_scenario_reservations'
TIMING = PREFIX + '/supervisor_timing.py'
ADMISSION = PREFIX + '/owner_admission.json'
ACTIVATOR = PREFIX + '/activate_profile.py'
REHEARSAL_SEAL = PREFIX + '/rehearsal_seal.json'
LOCK = 'review/direct_plan_passage/owner_start.lock'
MAX_INPUT = 67108864
MAX_ADMISSION = 8388608
REVIEWER = '/root/private_remote_controls'
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


STAGE05_CHECKPOINTS = frozenset((
    'cold_current_consumer', 'qualified_current_consumer',
    'prospective_scenario', 'ordinary_accepted_result', 'cold_allocated_work',
    'qualified_feedback', 'qualified_allocated_work', 'causal_chain_verified',
    'unscorable_audit_control', 'current_eligibility_controls',
    'aged_current_check', 'unrelated_prospective_task', 'unrelated_accepted_result',
    'unrelated_current_consumer', 'source_revision_before', 'source_revision_after',
    'source_revision_stale_binding_refused',
))
DISPLAY_PHASES = frozenset((
    'BOOTSTRAP', 'SETUP', 'INTAKE', 'PROVIDER', 'NATIVE', 'PERSISTENCE', 'FINALIZATION',
))
DISPLAY_SPANS = frozenset((
    'ordinary_bootstrap', 'ordinary_scenario', 'stage05_cold_decision',
    'stage05_prospective_feedback', 'stage05_subsequent_work',
    'stage05_unscorable_control', 'stage05_eligibility_controls',
    'stage05_aged_current_check', 'stage05_unrelated_task', 'stage05_unrelated_consumer',
    'stage05_source_revision_refusal',
))


def progress_line(row, *, readback_verified, native_ns, remaining_ns):
    """Format validated events only; this grants no progress or acceptance credit."""
    kind = row.get('kind')
    label = None
    if kind == 'STATUS' and row.get('stage') == 'STAGE05_CHECKPOINT':
        step = row.get('step')
        if not readback_verified or type(step) is not str or step not in STAGE05_CHECKPOINTS:
            return None
        label = 'Checkpoint read back: '+step+'; evidence_sha256='+row['readback_ref']['sha256']
    elif kind in ('PHASE_ENTER', 'PHASE_EXIT') and row.get('phase') in DISPLAY_PHASES:
        span = row.get('span_id')
        name = row['phase']+('/'+span if span in DISPLAY_SPANS else '')
        label = 'Phase '+('entered: ' if kind == 'PHASE_ENTER' else 'exited: ')+name
        label += '; execution event only'
    if label is None:
        return None
    return label+'; total wall=%.3f s, CPU=%.3f s, native=%.3f s, remaining=%.3f s.'%(
        row['elapsed_wall_ns']/1e9, row['elapsed_process_cpu_ns']/1e9,
        native_ns/1e9, max(0, remaining_ns)/1e9)


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
    module = types.ModuleType('radik_stage05_supervisor_timing')
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
    require(type(argv) is list and len(argv) == 6 and argv[0] == '.venv-plan/bin/python'
        and argv[1:4] == ['-I', '-S', '-B']
        and argv[4] == 'config/launch.py' and argv[5:] == ['--console']
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



def selected_owner_acknowledgement(admission, selected_attempt):
    """Bind an explicit CLI decision; archive data alone cannot select an ACK."""
    expected = 'radik-call:c146081f7b9a4d649f3c7e916189271e'
    value = admission.get('selected_unknown_acknowledgement')
    require(selected_attempt == expected and type(value) is dict
        and set(value) == {'selected_attempt_id', 'proposal_ref', 'review_ref'}
        and value['selected_attempt_id'] == expected, 'terminal_explicit_unknown_decision_required')
    for key in ('proposal_ref', 'review_ref'):
        checked_reference(value[key], cap=MAX_ADMISSION, prefixes=(PREFIX+'/',))
    return dict(value)


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


STAGE05_SCENARIO_STAGES = frozenset((
    'UNKNOWN', 'ORDINARY_TASK', 'COLD_DECISION', 'PROSPECTIVE_FEEDBACK',
    'SUBSEQUENT_WORK', 'CAUSAL_CHECKS', 'UNSCORABLE_CONTROL',
    'ELIGIBILITY_CONTROLS', 'AGED_CURRENT_CHECK', 'UNRELATED_TASK',
    'UNRELATED_CONSUMER', 'SOURCE_REVISION_REFUSAL', 'FINALIZATION',
))
STAGE05_NATIVE_STAGES = frozenset((
    'UNKNOWN', 'G4_BOOTSTRAP_ADVANCE', 'G4_BOOTSTRAP_ARTIFACT', 'G4_HISTORY',
    'G4_ALLOCATION', 'G4_TASK_ROOT', 'G4_REVISION', 'G4_PRE_DISPATCH_PERSISTENCE',
    'G4_ALLOCATED_ADVANCE', 'G4_ALLOCATED_ARTIFACT', 'G4_FINAL_CHECKS', 'G4_CUSTODY',
))
STAGE05_FRAME_FUNCTIONS = frozenset(('<module>', '<lambda>', '<genexpr>',
    '<listcomp>', '<dictcomp>', '<setcomp>'))


def diagnostic_source_pins(manifest):
    """Use only the finite independently admitted application and native paths."""
    result = {path: value for path, value in manifest['pins'].items() if path.endswith('.py')}
    for item in manifest['native_files'].values():
        path, value = item['path'], item['sha256']
        if path.endswith('.py'):
            require(path not in result or result[path] == value, 'stage05_failure_source_identity')
            result[path] = value
    require(len(result) <= 4096 and all(type(path) is str and path == Path(path).as_posix()
        and not Path(path).is_absolute() and not any(part in ('.', '..', 'private', '.git')
        for part in Path(path).parts) and len(path) <= 1024 and type(value) is str
        and re.fullmatch('[0-9a-f]{64}', value) for path, value in result.items()),
        'stage05_failure_source_identity')
    return result


def transport_diagnostic_tables(source_pins):
    """Read only pinned literal registries; do not import or execute application code."""
    name = 'app/stage04_diagnostics.py'
    raw, _ = read_bytes(PROJECT / name)
    require(hashlib.sha256(raw).hexdigest() == source_pins.get(name), 'terminal_transport_registry_pin')
    names = {'OWNED_ERROR_CODES', 'MEMORY_ERROR_CODES', 'RETURN_ERROR_CODES', 'TYPED_GUARD_NAMES',
        'SAFE_ERROR_TYPES', 'TRANSPORT_FAILURE_SUBSTAGES', 'TRANSPORT_FAILURE_CATEGORIES'}
    nodes = {node.targets[0].id: node.value for node in ast.parse(raw, filename=name).body
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in names}
    require(set(nodes) == names, 'terminal_transport_registry_inventory')
    def literal(node, depth=0):
        require(depth <= 8, 'terminal_transport_registry_depth')
        if isinstance(node, ast.Name) and node.id in nodes:
            return literal(nodes[node.id], depth+1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return literal(node.left, depth+1) | literal(node.right, depth+1)
        require(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'frozenset'
            and len(node.args) == 1 and not node.keywords, 'terminal_transport_registry_literal')
        value = ast.literal_eval(node.args[0])
        require(type(value) in (set, tuple) and len(value) <= 8192
            and all(type(item) is str and 0 < len(item) <= 256 for item in value),
            'terminal_transport_registry_values')
        return frozenset(value)
    return {key: literal(node) for key, node in nodes.items()}


def terminal_transport_failure(value, source_pins):
    """Validate closed categories and each admitted frame before display."""
    fields = {'schema', 'failure_category', 'substage', 'original_type', 'original_code',
        'terminal_observed', 'source_identity_sha256', 'source_frames', 'omitted_frames',
        'unadmitted_frames', 'traceback_truncated', 'raw_error_recorded', 'locals_recorded', 'frame_basis'}
    require(type(value) is dict and set(value) == fields, 'terminal_transport_failure_shape')
    tables = transport_diagnostic_tables(source_pins)
    codes = tables['OWNED_ERROR_CODES'] | tables['MEMORY_ERROR_CODES'] | tables['RETURN_ERROR_CODES'] | {'SANITIZED_OPERATION_FAILURE'}
    require(value['schema'] == 'radik.plan_transport_failure.v01'
        and type(value['failure_category']) is str and value['failure_category'] in tables['TRANSPORT_FAILURE_CATEGORIES']
        and type(value['substage']) is str and value['substage'] in tables['TRANSPORT_FAILURE_SUBSTAGES']
        and type(value['original_type']) is str and value['original_type'] in tables['SAFE_ERROR_TYPES']
        and type(value['original_code']) is str and value['original_code'] in codes
        and type(value['terminal_observed']) is bool and type(value['traceback_truncated']) is bool
        and value['raw_error_recorded'] is False and value['locals_recorded'] is False
        and value['frame_basis'] == 'SOURCE_VALIDATOR_PINS_CAPTURED_BEFORE_RESERVATION'
        and type(value['source_identity_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['source_identity_sha256'])
        and type(value['source_frames']) is list and len(value['source_frames']) <= 32
        and all(type(value[key]) is int and 0 <= value[key] <= 128
            for key in ('omitted_frames', 'unadmitted_frames')),
        'terminal_transport_failure_closed_fields')
    require(not(value['failure_category'] == 'PRETERMINAL_UNCERTAIN' and value['terminal_observed'])
        and not(value['failure_category'] == 'POSTTERMINAL_LOCAL' and not value['terminal_observed']),
        'terminal_transport_terminal_consistency')
    frames = []
    for frame in value['source_frames']:
        require(type(frame) is dict and set(frame) == {'path', 'sha256', 'line', 'function'}
            and type(frame['path']) is str and frame['path'] in source_pins
            and type(frame['sha256']) is str and frame['sha256'] == source_pins[frame['path']]
            and type(frame['line']) is int and 1 <= frame['line'] <= 1000000
            and type(frame['function']) is str and len(frame['function']) <= 96
            and (re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', frame['function'])
                or frame['function'] in STAGE05_FRAME_FUNCTIONS), 'terminal_transport_failure_frame')
        frames.append(dict(frame))
    return dict(value, source_frames=frames)


def stage05_failure_context(row, source_pins):
    """Validate the exact-child attachment before displaying safe source coordinates."""
    value = row.get('failure_context')
    require(type(value) is dict and set(value)-{'transport_failure'} == {'schema', 'scenario_stage', 'native_stage',
        'source_frames', 'omitted_frames', 'unadmitted_frames', 'traceback_truncated',
        'raw_error_recorded', 'locals_recorded'}
        and value['schema'] == 'radik.stage05.failure_context.v01'
        and type(value['scenario_stage']) is str and value['scenario_stage'] in STAGE05_SCENARIO_STAGES
        and type(value['native_stage']) is str and value['native_stage'] in STAGE05_NATIVE_STAGES
        and value['raw_error_recorded'] is False and value['locals_recorded'] is False
        and type(value['traceback_truncated']) is bool
        and type(value['source_frames']) is list and len(value['source_frames']) <= 32
        and all(type(value[key]) is int and 0 <= value[key] <= 128
            for key in ('omitted_frames', 'unadmitted_frames')), 'terminal_stage05_failure_context')
    frames = []
    for frame in value['source_frames']:
        require(type(frame) is dict and set(frame) == {'path', 'sha256', 'line', 'function'}
            and type(frame['path']) is str and frame['path'] in source_pins
            and type(frame['sha256']) is str and frame['sha256'] == source_pins[frame['path']]
            and type(frame['line']) is int and 1 <= frame['line'] <= 1000000
            and type(frame['function']) is str and len(frame['function']) <= 96
            and (re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', frame['function'])
                or frame['function'] in STAGE05_FRAME_FUNCTIONS), 'terminal_stage05_failure_frame')
        frames.append(dict(frame))
    result = dict(value, source_frames=frames, event_sequence=row['sequence'],
        reference_readback_verified=False)
    show('STAGE05_FAILURE_CONTEXT scenario='+value['scenario_stage']+' native='+value['native_stage'])
    for frame in frames:
        show('SOURCE_FRAME '+frame['path']+':'+str(frame['line'])+' '+frame['function']+' sha256='+frame['sha256'])
    if 'transport_failure' in value:
        transport = terminal_transport_failure(value['transport_failure'], source_pins)
        result['transport_failure'] = transport
        show('TRANSPORT_FAILURE category='+transport['failure_category']+' substage='+transport['substage']
            +' original='+transport['original_type']+'/'+transport['original_code']
            +' terminal_observed='+str(transport['terminal_observed']))
        for frame in transport['source_frames']:
            show('TRANSPORT_SOURCE_FRAME '+frame['path']+':'+str(frame['line'])+' '+frame['function']+' sha256='+frame['sha256'])
    return result


def required_witness_diagnostic(row, *, evidence_prefixes):
    """Retain safe exact-child context without delaying stop for another file read.

    The diagnostic reference is a locator from the durable raw event. It is not
    accepted as a useful checkpoint or an independently read-back report here.
    """
    detail=dict(event_sequence=row['sequence'],reference_readback_verified=False)
    for key in ('component','e_call_id','report_kind','stage','primary_code','primary_error_class'):
        if key in row:
            detail[key]=token(row[key])
    if 'diagnostic_ref' in row:
        ref=row['diagnostic_ref']
        require(type(ref)is dict and set(ref)=={'path','sha256','size_bytes'}
            and type(ref['size_bytes'])is int and 0<=ref['size_bytes']<=1048576
            and type(ref['sha256'])is str and re.fullmatch('[0-9a-f]{64}',ref['sha256']),
            'terminal_required_diagnostic_reference_shape')
        name=logical(ref['path'])
        require(any(name.startswith(prefix) for prefix in evidence_prefixes),
            'terminal_required_diagnostic_reference_scope')
        detail['diagnostic_ref']=dict(ref)
    return detail


def show_required_witness(detail):
    fields=['REQUIRED_WITNESS_DIAGNOSTIC']
    for key in ('component','e_call_id','report_kind','stage','primary_code','primary_error_class'):
        if key in detail:
            fields.append(key+'='+detail[key])
    if 'diagnostic_ref' in detail:
        fields.append('diagnostic_path='+detail['diagnostic_ref']['path'])
    show(' '.join(fields))


def load_scenario_inputs(admission):
    """Read a reviewed prospective scenario; its expectations precede execution."""
    source = json.loads(checked_reference(admission['scenario_input_ref'], cap=1048576,
        prefixes=(PREFIX+'/inputs/',)))
    require(source.get('schema') == 'radik.stage05.qualified_experience_inputs.v01'
        and source.get('command') == 'experience'
        and source.get('expected_role_calls') == 6
        and source.get('expected_primary_role_calls') == source.get('expected_unrelated_role_calls') == 3
        and source.get('scenario_mode') == 'remaining_only'
        and source.get('expected_starting_attempts') == 50
        and type(source.get('prior_actual_evidence')) is dict
        and source['prior_actual_evidence'].get('authority_restored') is False
        and source.get('native_E_calls') == 0
        and source.get('effects') == 0,
        'terminal_experience_input_contract')
    prior = source['prior_actual_evidence']
    for reference in [prior['receipt_ref'], prior['partial_acceptance_ref'], *prior['checkpoint_refs']]:
        checked_reference(reference, prefixes=('review/stage05_qualified_experience_passage/',
            'workspace/owner_documents/review/stage05/'))
    return source


def file_reference(path, *, cap=MAX_INPUT):
    raw, _ = read_bytes(path, cap)
    return dict(path=str(path.relative_to(PROJECT)), sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))


class CommandRefusal(ValueError):
    """Carry only the application's already-projected primary failure."""
    def __init__(self, detail):
        self.failure = dict(phase=token(detail.get('phase')),code=token(detail.get('code')),
            error_class=token(detail.get('type')))
        super().__init__(self.failure['code'])


class OrdinaryDriver:
    """Drive the ordinary experience command and inspect durable observations."""
    ROUTES = ((('EXPERIENCE', 'experience'), ('EXIT', 'exit')),)

    def __init__(self, inputs, run):
        self.inputs, self.run = inputs, run
        self.process_index, self.position, self.pending = 0, 0, None
        self.ready = False
        self.initial_attempts = None
        self.last_ledger = None
        self.last_witness = None
        self.initial_history = None
        self.steps, self.prompt_seen = [], set()
        self.experience = None

    def begin_process(self, index):
        require(index == 0 and self.process_index == 0 and self.pending is None,
            'terminal_driver_process_order')

    def _remaining(self):
        return self.ROUTES[self.process_index][self.position:]

    def next_line(self, row):
        require(self.ready and row.get('prompt_id') == 'command',
            'terminal_experience_unexpected_prompt')
        identity = (row.get('command_sequence'), row.get('prompt_id'))
        require(identity not in self.prompt_seen and self.pending is None and self._remaining(),
            'terminal_driver_repeated_prompt')
        self.prompt_seen.add(identity)
        step, command = self._remaining()[0]
        self.pending = dict(step=step, command=command, sequence=row['command_sequence'])
        return command

    def _ledger(self, witness):
        before, after = witness['ledger_before'], witness['ledger_after']
        require(type(before) is dict and type(after) is dict
            and type(after.get('attempts')) is list and after.get('active_attempt_id') is None,
            'terminal_driver_ledger_shape')
        if self.initial_attempts is None:
            require(len(before['attempts']) == self.inputs['expected_starting_attempts']
                and hashlib.sha256(canonical(before['attempts'])).hexdigest() ==
                    self.inputs['expected_historical_prefix_sha256'], 'terminal_driver_selected_predecessor')
            self.initial_attempts = list(before['attempts'])
        require(after['attempts'][:len(self.initial_attempts)] == self.initial_attempts
            and after['attempts'][:len(before['attempts'])] == before['attempts'],
            'terminal_driver_historical_ledger_changed')
        if self.last_ledger is not None:
            require(before['attempts'] == self.last_ledger['attempts'],
                'terminal_driver_between_command_attempts')
        count = len(after['attempts'])-len(before['attempts'])
        require(0 <= len(after['attempts'])-len(self.initial_attempts) <= self.inputs['expected_role_calls'],
            'terminal_driver_scenario_role_call_limit')
        self.last_ledger = after
        return count

    def observe_ready(self, witness):
        require(not self.ready and witness['status'] == 'READY', 'terminal_driver_ready_shape')
        require(self._ledger(witness) == 0, 'terminal_ready_model_calls')
        state = witness['store_state']
        require(state['active_task_id'] is None, 'terminal_driver_ready_active_task')
        self.initial_history = {key:list(value['history']) for key,value in state['tasks'].items()}
        self.ready = True

    def complete(self, row, witness, reference):
        require(self.pending is not None and row.get('command_sequence') == self.pending['sequence']
            and witness.get('command_sequence') == self.pending['sequence']
            and witness.get('command') == self.pending['command'], 'terminal_driver_completion_binding')
        step, command = self._remaining()[0]
        status = witness.get('status')
        if status == 'REFUSED':
            raise CommandRefusal(witness.get('error', {}))
        require(status == ('EXIT' if command == 'exit' else 'COMPLETED'),
            'terminal_step_unexpected_status:'+step)
        count = self._ledger(witness)
        require(count == (self.inputs['expected_role_calls'] if command == 'experience' else 0),
            'terminal_step_model_count:'+step)
        state = witness['store_state']
        require(state['active_task_id'] is None, 'terminal_step_active_task:'+step)
        for task_id, history in self.initial_history.items():
            require(state['tasks'][task_id]['history'][:len(history)] == history,
                'terminal_historical_task_changed')
        if command == 'experience':
            value = witness.get('qualified_experience_result')
            require(type(value) is dict
                and value.get('schema') == 'radik.stage05.qualified_experience_result.v01'
                and value.get('status') == 'OWNER_SCENARIO_COMPLETED_REQUIRES_REVIEW'
                and value.get('actual_model_calls') == self.inputs['expected_role_calls']
                and value.get('native_E_calls') == 0 and value.get('effects') == 0
                and value.get('scenario_mode') == 'remaining_only'
                and value.get('completed_scope') == 'FRESH_REMAINING_ONLY'
                and value.get('repeated_G4_allocations') == value.get('repeated_aged_consumers') == 0
                and value.get('prior_closed_process_authority_restored') is False
                and value.get('prior_actual_evidence') == self.inputs['prior_actual_evidence']
                and type(value.get('observations')) is list and value['observations'],
                'terminal_experience_result_contract')
            require([row['step'] for row in value['observations']] == [
                'prospective_scenario', 'ordinary_accepted_result', 'cold_current_consumer',
                'qualified_feedback', 'qualified_current_consumer', 'causal_chain_verified',
                'unrelated_prospective_task', 'unrelated_accepted_result', 'unrelated_current_consumer',
                'source_revision_before', 'source_revision_after', 'source_revision_stale_binding_refused'],
                'terminal_remaining_checkpoint_sequence')
            self.experience = value
        self.steps.append(dict(step=step, status=status, new_attempts=count, readback_ref=reference))
        put(self.run/('step_%02d_%s.json'%(len(self.steps),step)),self.steps[-1],cap=65536)
        self.last_witness = witness
        self.position += 1
        self.pending = None
        return step,status

    def process_closed(self, index):
        require(index == 0 and not self._remaining() and self.pending is None,
            'terminal_driver_incomplete_process')
        self.process_index += 1

    def result(self):
        require(self.process_index == 1 and len(self.steps) == 2 and self.experience is not None
            and len(self.last_ledger['attempts'])-len(self.initial_attempts) == self.inputs['expected_role_calls'],
            'terminal_driver_incomplete_experience_route')
        return dict(schema='radik.stage05.experience_driver_result.v01',
            status='ROUTE_OBSERVED_REQUIRES_INDEPENDENT_ACCEPTANCE', steps=self.steps,
            actual_new_role_attempts=self.inputs['expected_role_calls'], native_E_calls=0,
            qualified_experience_result=self.experience, Stage05_acceptance='NOT_INFERRED',
            model_observation_after_handoff=False, automatic_retry=False)


def supervise(profile, *, started_ns, lock_fd, launch, timing, run,
        interrupted=lambda: False, popen=subprocess.Popen, before_cleanup=lambda: None):
    """One shared clock and one ordinary stdin consumer."""
    limits = profile['limits']
    deadline = timing.Deadline(started_ns,limits=limits)
    driver = OrdinaryDriver(profile['scenario_inputs'],run)
    receipt = dict(schema='radik.stage05.experience_owner_terminal_receipt.v01', status='NOT_LAUNCHED',
        approved_argv=profile['argv'],operation_started_ns=started_ns,operation_deadline_ns=deadline.deadline_ns,
        limits=limits,primary_failure=None,secondary_failures=[],signals=[],children=[],child_reaped=False,
        automatic_retry=False,model_observation_after_handoff=False,supervisor_model_calls=0,
        supervisor_native_calls=0,native_E_allowed=False,native_acceptance_inferred=False,
        runtime_adoption=False,lock_explicit_unlock_permitted=True)
    child = None
    cleanup = timing.CleanupBoundary(started_ns=started_ns, limits=limits)
    total_cpu = 0
    try:
        for process_index in range(1):
            require(receipt['primary_failure'] is None and (child is None or child.poll() is not None),
                'terminal_first_child_not_reaped_before_restart')
            require(deadline.due_reason(time.monotonic_ns()) is None,'terminal_shared_deadline_before_process')
            driver.begin_process(process_index)
            child = None
            child_run = run/('process_%d'%(process_index+1));child_run.mkdir(mode=0o700)
            child_launch = dict(launch,process_index=process_index+1,
                prior_child_receipt_ref=None if process_index == 0 else receipt['children'][0]['receipt_ref'])
            child_launch_ref = put(child_run/'launch.json',child_launch)
            binding = hashlib.sha256(canonical(child_launch)).hexdigest()
            argv = [verify_interpreter(profile['interpreter_ref']),*profile['argv'][1:]]
            argv[4] = str(PROJECT/argv[4])
            argv.extend(('--owner-operation-started-ns',str(started_ns),
                '--owner-operation-deadline-ns',str(deadline.deadline_ns),
                '--owner-operation-started-utc',str(launch['operation_started_utc']),
                '--owner-supervisor-launch',child_launch_ref['path'],'--owner-run-binding',binding,
                '--owner-lock-fd',str(lock_fd)))
            if profile.get('rehearsal_seal_sha256') is not None:
                argv.extend(('--rehearsal-seal-sha256',profile['rehearsal_seal_sha256'], '--rehearsal-action', 'ordinary_console'))
            sub = dict(schema='radik.stage05.experience_child_receipt.v01', process_index=process_index+1,
                argv=argv,launch_ref=child_launch_ref,events=0,final_event=None,
                child_reaped=False,signals=cleanup.signals,readbacks=[],step_refs=[],primary_failure=None)
            pending = b'';stdout_size = 0;eof = False;latest_cpu = 0;last_display = started_ns
            log = None
            try:
                fd = os.open(child_run/'child_stdout.raw',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                log = os.fdopen(fd,'wb',buffering=0)
                child = popen(argv,cwd=profile.get('home_directory',str(PROJECT.parent)),stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},
                    close_fds=True,pass_fds=(lock_fd,),start_new_session=True)
                receipt['child_pid'] = child.pid
                receipt['lock_explicit_unlock_permitted'] = False
                sub['child_pid'] = child.pid
                os.set_blocking(child.stdout.fileno(),False)
                while True:
                    try:
                        raw = os.read(child.stdout.fileno(),65536)
                        if not raw:eof = True
                    except BlockingIOError:raw = b''
                    if raw:
                        require(log.write(raw) == len(raw),'terminal_stdout_short_write');os.fsync(log.fileno())
                        stdout_size += len(raw)
                    require(stdout_size <= limits['stdout_bytes'],'terminal_stdout_bound')
                    parts = (pending+raw).split(b'\n');pending = parts.pop()
                    require(len(pending) <= limits['event_row_bytes'],'terminal_partial_row_bound')
                    for part in parts:
                        if not part:continue
                        # Human input prompts may precede the machine record on the same line.
                        offset = part.find(b'{"')
                        if offset < 0:continue
                        try:row = json.loads(part[offset:])
                        except (ValueError,UnicodeError):continue
                        if type(row) is not dict or row.get('schema') != timing.SCHEMA:continue
                        timing.event_shape(row,child_pid=child.pid,run_binding=binding,operation_started_ns=started_ns)
                        require(row['sequence'] == sub['events']+1 and sub['events'] < limits['event_rows'],
                            'terminal_event_sequence')
                        sub['events'] += 1;latest_cpu = row['elapsed_process_cpu_ns']
                        kind = row['kind']
                        require(kind not in ('E_ENTER','E_EXIT') and row['phase'] != 'E','terminal_stage05_E_forbidden')
                        if kind in ('PRIMARY_FAILURE','REQUIRED_WITNESS_UNAVAILABLE'):
                            retain_failure(receipt,row['failure'],timing)
                        failure_context = None
                        if kind == 'PRIMARY_FAILURE' and row.get('stage') == 'STAGE05_FAILURE':
                            failure_context = stage05_failure_context(row, profile['diagnostic_source_pins'])
                            contexts = receipt.setdefault('stage05_failure_contexts', [])
                            require(len(contexts) < 16, 'terminal_stage05_failure_context_bound')
                            contexts.append(failure_context)
                        verified = False;witness = None
                        ref = row.get('readback_ref')
                        if ref is not None:
                            witness = json.loads(checked_reference(ref,cap=limits['evidence_bytes'],
                                prefixes=profile['evidence_prefixes']))
                            sub['readbacks'].append(ref);sub['last_readback_ref']=ref;verified = True
                            if failure_context is not None:
                                require(type(witness) is dict and type(witness.get('body')) is dict
                                    and witness['body'].get('failure_context') == row['failure_context'],
                                    'terminal_stage05_failure_readback_binding')
                                failure_context['reference_readback_verified'] = True
                                failure_context['readback_ref'] = dict(ref)
                        deadline.event(row,observed_ns=time.monotonic_ns(),readback_verified=verified)
                        if receipt['primary_failure'] is not None:continue
                        display_now = time.monotonic_ns()
                        progress = progress_line(row, readback_verified=verified,
                            native_ns=deadline.native_used_ns(display_now),
                            remaining_ns=deadline.deadline_ns-display_now)
                        if progress is not None:show(progress)
                        stage = row.get('stage')
                        if kind == 'STATUS' and stage == 'CONSOLE_READY':
                            require(verified,'terminal_console_ready_readback')
                            require(type(witness) is dict and set(witness)=={'classification','type','body'}
                                and witness['classification']=='PORTABLE_EVIDENCE_NOT_LIVE_AUTHORITY'
                                and witness['type']=='builtins.dict','terminal_console_witness_wrapper')
                            driver.observe_ready(witness['body'])
                            show('Process %d: ordinary console and fresh operation ready; wall=%.3f s, CPU=%.3f s, remaining=%.3f s.'%(
                                process_index+1,(time.monotonic_ns()-started_ns)/1e9,(total_cpu+latest_cpu)/1e9,
                                max(0,deadline.deadline_ns-time.monotonic_ns())/1e9))
                        elif kind == 'STATUS' and stage == 'CONSOLE_COMMAND_COMPLETED':
                            require(verified,'terminal_console_command_readback')
                            require(type(witness) is dict and set(witness)=={'classification','type','body'}
                                and witness['classification']=='PORTABLE_EVIDENCE_NOT_LIVE_AUTHORITY'
                                and witness['type']=='builtins.dict','terminal_console_witness_wrapper')
                            step,status = driver.complete(row,witness['body'],ref)
                            show('Step %s completed: %s; wall=%.3f s, CPU=%.3f s, remaining=%.3f s; evidence=%s'%(
                                step,status,(time.monotonic_ns()-started_ns)/1e9,(total_cpu+latest_cpu)/1e9,
                                max(0,deadline.deadline_ns-time.monotonic_ns())/1e9,ref['path']))
                        elif kind == 'STATUS' and stage == 'CONSOLE_INPUT_REQUIRED':
                            line = driver.next_line(row)
                            if row['prompt_id'] == 'command':show('Starting step '+driver.pending['step']+'.')
                            raw_line = (line+'\n').encode('utf-8')
                            require(len(raw_line) <= 8193,'terminal_stdin_line_bound')
                            child.stdin.write(raw_line);child.stdin.flush()
                        if kind == 'FINAL':
                            require(sub['final_event'] is None and verified and type(row.get('success')) is bool,'terminal_final_shape')
                            sub['final_event'] = row
                            if not row['success']:
                                retain_failure(receipt,row.get('failure') or timing.fallback('TERMINAL_FINAL_REFUSAL'),timing)
                    now = time.monotonic_ns()
                    action = deadline.action(now,owner_interrupt=interrupted())
                    if receipt['primary_failure'] is not None and deadline.stop_ns is None:
                        deadline.stop_ns,deadline.reason = now,receipt['primary_failure']['code'];action = 'INTERRUPT'
                    if action:
                        if receipt['primary_failure'] is None:retain_failure(receipt,timing.fallback(deadline.reason,'SupervisorStop'),timing)
                        if child.poll() is None:
                            child.send_signal({'INTERRUPT':signal.SIGINT,'TERMINATE':signal.SIGTERM,'KILL':signal.SIGKILL}[action])
                            sub['signals'].append(dict(action=action,elapsed_wall_ns=now-started_ns))
                    if now-last_display >= int(limits['status_seconds']*1e9):
                        last_display = now
                        show('Waiting for step %s: wall=%.1f s, CPU=%.3f s, native=%.1f s, remaining=%.1f s; no completed-step evidence yet.'%(
                            'START' if driver.pending is None else driver.pending['step'],(now-started_ns)/1e9,
                            (total_cpu+latest_cpu)/1e9,deadline.native_used_ns(now)/1e9,max(0,deadline.deadline_ns-now)/1e9))
                    if child.poll() is not None and eof:break
                    if deadline.stop_ns is not None and now-deadline.stop_ns >= int(limits['cleanup_seconds']*1e9):break
                    time.sleep(limits['poll_seconds'])
            except BaseException as error:
                code = error.args[0] if type(error) is ValueError and error.args else 'TERMINAL_DRIVER_OR_MONITOR_FAILURE'
                if type(code) is not str or not re.fullmatch('[A-Za-z0-9_:./-]{1,256}',code):code = 'TERMINAL_DRIVER_OR_MONITOR_FAILURE'
                retain_failure(receipt,error.failure if type(error) is CommandRefusal else
                    timing.fallback(code,type(error).__name__),timing)
                if sub.get('last_readback_ref') is not None:
                    show('Last evidence before stop: '+sub['last_readback_ref']['path'])
            finally:
                if child is not None and child.poll() is None:
                    stop = cleanup.begin(time.monotonic_ns(), known_stop_ns=deadline.stop_ns)
                    deadline.stop_ns = stop
                    before_cleanup()
                    bounded_cleanup(child,stop_ns=stop,limits=limits,signals=sub['signals'],started_ns=started_ns)
                reaped = child is not None and child.poll() is not None
                if reaped:
                    child.wait(timeout=0)
                    if not eof and log is not None:
                        while stdout_size <= limits['stdout_bytes']:
                            try:raw = os.read(child.stdout.fileno(),65536)
                            except BlockingIOError:break
                            if not raw:eof = True;break
                            require(log.write(raw)==len(raw),'terminal_stdout_tail_write');stdout_size += len(raw)
                        os.fsync(log.fileno())
                    child.stdin.close();child.stdout.close()
                if log is not None:log.close()
                sub.update(child_reaped=reaped,child_exit_code=None if child is None else child.returncode,
                    stdout_bytes=stdout_size,stdout_eof_observed=eof,elapsed_process_cpu_ns=latest_cpu,
                    primary_failure=receipt['primary_failure'])
                if not reaped:retain_failure(receipt,timing.fallback('CLEANUP_UNCONFIRMED'),timing)
                if receipt['primary_failure'] is None:
                    try:
                        require(not pending and stdout_size <= limits['stdout_bytes'],'terminal_final_output_boundary')
                        require(sub['child_exit_code']==0 and sub['final_event'] is not None and sub['final_event']['success'],
                            'terminal_child_final_required')
                        require(not deadline.native_spans and deadline.provider_span is None,'terminal_open_span_at_restart')
                        require(not (PROJECT/'state/normal_session_active.json').exists(),'terminal_normal_operation_not_closed')
                        ledger_raw,_ = read_bytes(PROJECT/'state/console_model_turns.json')
                        ledger = json.loads(ledger_raw)
                        require(ledger['active_attempt_id'] is None,'terminal_restart_active_attempt')
                        operation_ref=driver.last_witness['normal_operation_ref']
                        require(type(operation_ref)is dict and set(operation_ref)=={'path','sha256'}
                            and operation_ref['path'].startswith('state/normal_operations/'),'terminal_operation_reference')
                        operation_raw,_=read_bytes(PROJECT/logical(operation_ref['path']),1048576)
                        require(hashlib.sha256(operation_raw).hexdigest()==operation_ref['sha256'],'terminal_operation_changed')
                        closed_path=PROJECT/logical(operation_ref['path']+'.closed')
                        close_raw,_=read_bytes(closed_path,1048576);closed=json.loads(close_raw)
                        require(closed.get('schema')=='radik.normal_operation_close.v01'
                            and closed['operation_ref']==operation_ref and closed['disposition']=='EXITED'
                            and closed['active_attempt_id'] is None and closed['counted']==len(ledger['attempts'])
                            and closed['final_head']==ledger['ledger_sha256'],'terminal_operation_close_readback')
                        sub['operation_close_ref']=file_reference(closed_path,cap=1048576)
                        driver.process_closed(process_index)
                    except BaseException as error:
                        cause=error.args[0] if type(error) is ValueError and error.args else 'TERMINAL_PROCESS_CLOSURE_VALIDATION'
                        retain_failure(receipt,timing.fallback(cause,type(error).__name__),timing)
                sub['primary_failure']=receipt['primary_failure']
                sub['receipt_ref'] = put(child_run/'receipt.json',dict(sub),cap=limits['receipt_bytes'])
                receipt['children'].append(sub)
                receipt['child_reaped'] = all(r['child_reaped'] for r in receipt['children'])
                receipt['lock_explicit_unlock_permitted'] = receipt['child_reaped']
                total_cpu += latest_cpu
                show('Process %d closed: exit=%s, reaped=%s.'%(process_index+1,str(sub['child_exit_code']),str(reaped)))
            if receipt['primary_failure'] is not None:break
        if receipt['primary_failure'] is None:
            result = driver.result()
            receipt['scenario_result_ref'] = put(run/'scenario_result.json',result,cap=limits['receipt_bytes'])
    except BaseException as error:
        code = error.args[0] if type(error) is ValueError and error.args else 'TERMINAL_EXPERIENCE_CLOSURE_FAILURE'
        if type(code) is not str or not re.fullmatch('[A-Za-z0-9_:./-]{1,256}',code):code = 'TERMINAL_EXPERIENCE_CLOSURE_FAILURE'
        retain_failure(receipt,timing.fallback(code,type(error).__name__),timing)
    finally:
        if child is not None and child.poll() is None:
            try:
                stop = cleanup.begin(time.monotonic_ns(), known_stop_ns=deadline.stop_ns)
                deadline.stop_ns = stop
                bounded_cleanup(child,stop_ns=stop,limits=limits,
                    signals=cleanup.signals,started_ns=started_ns)
            except BaseException:retain_failure(receipt,timing.fallback('CLEANUP_EXCEPTION'),timing)
        reaped = child is None or child.poll() is not None
        receipt['child_reaped'] = child is not None and reaped
        receipt['lock_explicit_unlock_permitted'] = reaped
        receipt['child_exit_code'] = None if child is None else child.returncode
        receipt.update(status='CLEANUP_UNCONFIRMED' if not reaped else
            'CHILD_CLOSED_REVIEW_REQUIRED' if receipt['primary_failure'] is None and len(receipt['children'])==1 else 'STOPPED_NO_RETRY',
            deadline_measurement=deadline.measurement(time.monotonic_ns()),
            cleanup_measurement=cleanup.measurement(), signals=list(cleanup.signals), completed_steps=driver.steps,
            elapsed_children_cpu_ns=total_cpu)
        put(run/'receipt.json',receipt,cap=limits['receipt_bytes'])
        show('CLOSED status='+receipt['status']+' receipt='+str((run/'receipt.json').relative_to(PROJECT)))
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
    parser.add_argument('--acknowledge-unknown', required=True)
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
            require(not interrupted[0] and time.monotonic_ns() < STARTED_NS+2400*1000000000,
                'terminal_prelaunch_operation_limit')
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, lambda _s, _f: interrupted.__setitem__(0, True))
        admission, manifest = load_admission(args.admission_sha256, args.rehearsal_seal_sha256, before_pin)
        owner_ack = selected_owner_acknowledgement(admission, args.acknowledge_unknown)
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
            selected_unknown_acknowledgement=owner_ack,
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
        show('Stage05 remaining-only: explicit selected UNKNOWN acknowledgement, then one fresh ordinary operation, at most 6 new role calls in two cold rounds, no E or repeated G4/aged controls. Operation limit 5400 s; cumulative native limit 1500 s; model response limit 600 s; cleanup limit 30 s. Limits are not an ETA.')
        scenario_inputs = load_scenario_inputs(admission)
        child_started = True
        supervision_attempted = True
        receipt = supervise(dict(argv=admission['argv'], limits=timing.LIMITS,
            interpreter_ref=admission['interpreter_ref'],
            evidence_prefixes=admission['evidence_prefixes'],
            home_directory=admission.get('home_directory', str(Path.home())),
            scenario_inputs=scenario_inputs, diagnostic_source_pins=diagnostic_source_pins(manifest),
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
