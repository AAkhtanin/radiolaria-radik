#!/usr/bin/env python3
"""Stage04 finite ordinary stdin closure, derived from the admitted P30 supervisor.

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
PREFIX = 'review/g2e_successor_passage/proposals/g2e_no_effects_v31_stage04_closure'
SELF = PREFIX + '/owner_terminal.py'
RESERVATIONS = 'state/p28_owner_scenario_reservations'
TIMING = 'review/g2e_successor_passage/proposals/g2e_no_effects_v28_ordinary_entry_owner_scenario/supervisor_timing.py'
ADMISSION = PREFIX + '/owner_admission.json'
ACTIVATOR = PREFIX + '/activate_profile.py'
REHEARSAL_SEAL = PREFIX + '/rehearsal_seal.json'
LOCK = 'review/direct_plan_passage/owner_start.lock'
MAX_INPUT = 67108864
MAX_ADMISSION = 8388608
REVIEWER = '/root/s04_reviewer'
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
    show(('Первичная причина остановки: PRIMARY_FAILURE' if primary else 'Дополнительная ошибка: SECONDARY_FAILURE') + ' phase=' +
        value['phase'] + ' code=' + value['code'] + ' error_class=' + value['error_class'])


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
    """Re-read exact fictional inputs; the driver never supplies model claims."""
    source = json.loads(checked_reference(admission['scenario_input_ref'], cap=1048576,
        prefixes=(PREFIX+'/inputs/',)))
    require(source.get('schema') == 'radik.stage04.closure_inputs.v01'
        and set(source.get('tasks', {})) == {'A', 'B', 'C'}
        and source.get('held_out_C_reviewer') == REVIEWER,
        'terminal_closure_input_contract')
    for label, count, profile in (('A', 1, 'explain'), ('B', 3, 'verify'), ('C', 4, 'verify')):
        task = source['tasks'][label]
        require(type(task) is dict and task.get('profile') == profile
            and type(task.get('documents')) is list and len(task['documents']) == count,
            'terminal_closure_task_contract')
        for key, bound in (('goal',2048),('criterion',2048)):
            require(type(task.get(key)) is str and 0 < len(task[key].encode()) <= bound
                and '\n' not in task[key] and '\r' not in task[key], 'terminal_input_line')
        require(task.get('supplied_candidate') is None if profile == 'explain' else
            type(task.get('supplied_candidate')) is str and 0 < len(task['supplied_candidate'].encode()) <= 4096
            and '\n' not in task['supplied_candidate'] and '\r' not in task['supplied_candidate'],
            'terminal_input_candidate')
        require(len({ref['path'] for ref in task['documents']}) == count, 'terminal_input_duplicate')
        for ref in task['documents']:
            raw = checked_reference(ref, cap=16384, prefixes=(PREFIX+'/inputs/',))
            require(raw and b'\0' not in raw, 'terminal_input_document')
            raw.decode('utf-8',errors='strict')
    require(source['tasks']['B']['goal'] != source['tasks']['C']['goal']
        and source['tasks']['B']['criterion'] != source['tasks']['C']['criterion'],
        'terminal_successor_new_meaning_required')
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
    """Finite stdin script plus evidence checks, never an application executor."""
    ROUTES = (
        (('A_SETUP','task','A'),('A1','run','A'),('A2','continue','A','exceptions'),
         ('A3','continue','A','conditions'),('A4','continue','A','conditions'),
         ('B_SETUP','task','B'),('B1','run','B'),('B2','continue','B','unknowns'),
         ('A_SELECT','select','A'),('A5','run-memory','A'),('A6_CANCEL','cancel','A'),
         ('A6_REFUSAL','run','A'),('A6_RESULT','result','A'),('B_SELECT','select','B'),
         ('C_SETUP','task','C'),('C1','run','C'),('R1','exit','C')),
        (('R2_SELECT','select','C'),('R2','run-memory','C'),('R2_EXIT','exit','C')))

    def __init__(self, inputs, run):
        self.inputs, self.run = inputs, run
        self.task_ids, self.saved, self.steps = {}, {}, []
        self.process_index, self.position, self.pending = 0, 0, None
        self.ready = False
        self.initial_attempts = None
        self.last_ledger = None
        self.last_witness = None
        self.first_ready = None
        self.first_operation = None
        self.initial_history = None
        self.prompt_seen = set()
        self.rounds = []
        self.cold_dependencies = {}
        self.memory_producers = {}

    def begin_process(self, index):
        require(index == self.process_index and self.pending is None, 'terminal_driver_process_order')
        self.position, self.ready, self.prompt_seen = 0, False, set()

    def _remaining(self):
        return self.ROUTES[self.process_index][self.position:]

    def next_line(self, row):
        require(self.ready, 'terminal_driver_input_before_ready')
        prompt = row.get('prompt_id')
        identity = (row.get('command_sequence'), prompt, row.get('source_index'))
        require(identity not in self.prompt_seen, 'terminal_driver_repeated_prompt')
        self.prompt_seen.add(identity)
        if prompt == 'command':
            require(self.pending is None and self._remaining(), 'terminal_driver_unexpected_command_prompt')
            action = self._remaining()[0]
            label, command, task = action[:3]
            self.pending = dict(step=label, command=command, task=task, sequence=row['command_sequence'])
            if command == 'task':
                line = 'task '+self.inputs['tasks'][task]['goal']
            elif command == 'exit':
                line = 'exit'
            else:
                require(task in self.task_ids, 'terminal_driver_missing_task')
                line = command+' '+self.task_ids[task]
            return line
        require(self.pending is not None and row.get('command_sequence') == self.pending['sequence'],
            'terminal_driver_nested_prompt_binding')
        action = self._remaining()[0]
        task = self.inputs['tasks'][action[2]]
        if self.pending['command'] == 'task':
            if prompt == 'source_count': return str(len(task['documents']))
            if prompt == 'source_path':
                index = row.get('source_index')
                require(type(index) is int and 1 <= index <= len(task['documents']), 'terminal_driver_source_index')
                ref = task['documents'][index-1]
                checked_reference(ref,cap=16384,prefixes=(PREFIX+'/inputs/',))
                return str(PROJECT/ref['path'])
            if prompt == 'criterion': return task['criterion']
            if prompt == 'candidate': return task['supplied_candidate']
        if self.pending['command'] == 'continue':
            kind = action[3]
            if prompt == 'continue_kind': return kind
            if prompt == 'continue_indexes':
                accepted = self.last_witness['selected_result']
                allowed = {'exceptions':('exception',),'conditions':('condition',),
                    'unknowns':('unknown','contradiction')}[kind]
                choices = [str(i+1) for i,c in enumerate(accepted['proposal']['claims']) if c['kind'] in allowed]
                require(1 <= len(choices) <= 8, 'terminal_actual_required_claim_missing:'+action[0])
                return ','.join(choices)
        raise ValueError('terminal_driver_unexpected_prompt:'+str(prompt))

    def _ledger(self, witness):
        before, after = witness['ledger_before'], witness['ledger_after']
        require(type(before) is dict and type(after) is dict and type(after.get('attempts')) is list
            and after.get('active_attempt_id') is None, 'terminal_driver_ledger_shape')
        if self.initial_attempts is None:
            self.initial_attempts = list(before['attempts'])
        require(after['attempts'][:len(self.initial_attempts)] == self.initial_attempts,
            'terminal_driver_historical_ledger_changed')
        require(after['attempts'][:len(before['attempts'])] == before['attempts'],
            'terminal_driver_command_ledger_changed')
        if self.last_ledger is not None:
            require(before['attempts'] == self.last_ledger['attempts'], 'terminal_driver_between_command_attempts')
        new = len(after['attempts'])-len(before['attempts'])
        require(0 <= len(after['attempts'])-len(self.initial_attempts) <= 9, 'terminal_driver_nine_call_limit')
        self.last_ledger = after
        return new

    def observe_ready(self, witness):
        require(not self.ready and witness['status'] == 'READY', 'terminal_driver_ready_shape')
        self._ledger(witness)
        state = witness['store_state']
        require(state['active_task_id'] is None, 'terminal_driver_ready_active_task')
        if self.process_index == 0:
            self.initial_history = {key:list(value['history']) for key,value in state['tasks'].items()}
            self.first_ready = witness
            self.first_operation = witness.get('normal_operation_ref')
        else:
            require(witness.get('normal_operation_ref') is not None and witness.get('normal_operation_ref') != self.first_operation,
                'terminal_restart_new_normal_operation')
            require(witness.get('controller_snapshots') == {}, 'terminal_restart_restored_controller')
            for key in ('A','B','C'):
                require(self.task_ids[key] in state['tasks'], 'terminal_restart_task_history_lost')
            for label in ('A','B','C'):
                task_id=self.task_ids[label]
                require(state['tasks'][task_id]==self.last_witness['store_state']['tasks'][task_id],
                    'terminal_restart_task_state_changed')
            require(state['tasks'][self.task_ids['C']]['spec'] == self.saved['C1']['task'],
                'terminal_restart_C_spec_changed')
        self.ready = True

    def _accepted(self, witness, task):
        value = witness.get('selected_result')
        require(type(value) is dict and value.get('task_id') == self.task_ids[task]
            and value.get('root',{}).get('result',{}).get('decision') == 'ACCEPT'
            and value.get('work',{}).get('provider_calls') == 0
            and value['work'].get('effects') == 0, 'terminal_driver_accepted_native_work_required')
        invocation = value['actual_work']['invocation']
        require(invocation['candidate_id'] is None and invocation['packet_id'] is None,
            'terminal_driver_pure_invocation_carrier')
        return value

    def complete(self, row, witness, reference):
        require(self.pending is not None and row.get('command_sequence') == self.pending['sequence']
            and witness.get('command_sequence') == self.pending['sequence']
            and witness.get('command') == self.pending['command'], 'terminal_driver_completion_binding')
        action = self._remaining()[0]
        step, command, label = action[:3]
        status = witness.get('status')
        expected = 'EXHAUSTED' if step == 'A4' else 'REFUSED' if step == 'A6_REFUSAL' else 'EXIT' if command == 'exit' else 'COMPLETED'
        if status == 'REFUSED' and expected != 'REFUSED':
            raise CommandRefusal(witness.get('error',{}))
        require(status == expected, 'terminal_step_unexpected_status:'+step)
        count = self._ledger(witness)
        require(count == (3 if step in ('A1','B1','C1') else 0), 'terminal_step_model_count:'+step)
        state = witness['store_state']
        round_observation = witness.get('round_observation')
        round_steps = ('A1','A2','A3','A4','B1','B2','A5','C1','R2')
        if step in round_steps:
            require(type(round_observation) is dict and round_observation['started'] is True
                and round_observation['closure'] is not None, 'terminal_round_not_closed:'+step)
            binding = round_observation['binding']
            scope = binding['normal_round_scope']
            mode = 'COLD' if step in ('A1','B1','C1') else 'MEMORY_ONLY' if step in ('A5','R2') else 'NATIVE_CONTINUE'
            require(scope['mode'] == mode and binding['max_attempts'] == (3 if mode=='COLD' else 0)
                and scope['operation_ref'] == witness['normal_operation_ref'], 'terminal_round_scope:'+step)
            ref = scope['grant_ref']
            require(set(ref)=={'path','sha256'} and ref['path'].startswith('state/normal_rounds/'),
                'terminal_round_reference_shape')
            grant_raw,_ = read_bytes(PROJECT/logical(ref['path']),1048576)
            require(hashlib.sha256(grant_raw).hexdigest()==ref['sha256'],'terminal_round_grant_changed')
            close_path = PROJECT/logical(ref['path']+'.closed')
            close_raw,_ = read_bytes(close_path,1048576);closed=json.loads(close_raw)
            require(closed.get('schema')=='radik.normal_round_close.v01' and closed['grant_ref']==ref
                and closed['counted']==len(witness['ledger_after']['attempts'])
                and closed['active_attempt_id'] is None,'terminal_round_close_readback')
            if step in ('A1','B1','C1'):
                self.cold_dependencies[label]=binding['dependencies_sha256']
                if step=='C1':require(binding['dependencies_sha256']!=self.cold_dependencies['B'],
                    'terminal_C_semantic_dependency_identity_unchanged')
            self.rounds.append(dict(step=step,round_id=binding['round_id'],mode=mode,
                grant_ref=dict(ref,size_bytes=len(grant_raw)),close_ref=file_reference(close_path,cap=1048576)))
        elif step == 'A6_REFUSAL':
            require(round_observation is None,'terminal_cancel_unexpected_grant')
        require(state['active_task_id'] is None, 'terminal_step_active_task:'+step)
        for task_id, history in self.initial_history.items():
            require(state['tasks'][task_id]['history'][:len(history)] == history, 'terminal_historical_task_changed')
        if command == 'task':
            task_id = witness.get('task_id') or state['selected_task_id']
            require(task_id not in self.task_ids.values() and task_id not in self.initial_history, 'terminal_new_task_identity')
            self.task_ids[label] = task_id
            spec = state['tasks'][task_id]['spec']
            desired = self.inputs['tasks'][label]
            require(type(spec) is dict and all(spec[key] == desired[key] for key in
                ('goal','profile','criterion','supplied_candidate'))
                and len(spec['source_ids']) == len(desired['documents']), 'terminal_new_task_spec')
            if label == 'C':
                require(spec['predecessor_task_id'] == self.task_ids['B'] and
                    state['tasks'][self.task_ids['B']]['spec'] == self.saved['B1']['task'], 'terminal_C_predecessor_immutable')
        elif step in ('A1','B1','C1','A2','A3','B2','A5','R2'):
            value = self._accepted(witness,label)
            self.saved[step] = value
            if step in ('A1','A2','A3','B1','B2','C1'):
                snapshot=witness['controller_snapshots'][self.task_ids[label]]
                writes=[event for event in snapshot['memory_events'] if event.get('operation')=='WRITEBACK'
                    and event.get('actual_result_id')==value['result_id']]
                require(len(writes)==1,'terminal_actual_memory_producer_missing:'+step)
                self.memory_producers[value['result_id']]=writes[0]
            if step in ('A1','B1','C1'):
                desired = self.inputs['tasks'][label]
                require(value['task']['goal'] == desired['goal'] and value['task']['criterion'] == desired['criterion']
                    and len(value['sources']) == len(desired['documents'])
                    and value['semantic_pipeline']['memory_origin'] is None, 'terminal_cold_actual_scope')
                require(sorted(item['sha256'] for item in value['sources']) ==
                    sorted(item['sha256'] for item in desired['documents']), 'terminal_actual_source_bytes')
                kinds = {claim['kind'] for claim in value['proposal']['claims']}
                if step == 'A1': require({'condition','exception'} <= kinds, 'terminal_actual_required_claim_missing:A1')
                if step == 'B1': require(bool(kinds & {'unknown','contradiction'}), 'terminal_actual_required_claim_missing:B1')
                if label != 'A': require(value['business']['supplied_candidate'] == desired['supplied_candidate'],
                    'terminal_supplied_candidate_consumption')
            elif step in ('A2','A3','B2'):
                number = 2 if step == 'A3' else 1
                audit = next((r for r in value['work']['actual_results'] if r['work_id'] == 'revision_audit'+str(number)),None)
                require(audit is not None and audit['status'] == ('COMPLETED' if step == 'A2' else 'SKIPPED_GUARD_FALSE'),
                    'terminal_revision_actual_guard:'+step)
                base = self.saved['A1' if label == 'A' else 'B1']
                require(value['task'] == base['task'] and value['goal'] == base['goal'], 'terminal_revision_task_mutated')
                require(value['business']['revision_focus']['kind'] == {'A2':'focus_exceptions','A3':'focus_conditions','B2':'review_unknowns'}[step],
                    'terminal_revision_actual_focus')
            else:
                origin = value['semantic_pipeline']['memory_origin']
                require(type(origin) is dict,'terminal_actual_memory_origin_missing')
                candidates = [self.saved[key] for key in (('A1','A2','A3') if step=='A5' else ('C1',))]
                matches = [prior for prior in candidates if prior['result_id']==origin.get('result_id')]
                require(len(matches)==1,'terminal_actual_memory_saved_A_or_C_identity')
                prior = matches[0]
                producer=self.memory_producers[prior['result_id']]
                require(origin['record_id']==producer['record_id'] and origin['payload_sha256']==producer['payload_sha256']
                    and origin['accepted_at']==producer['original_accepted_at']
                    and origin['valid_to']<=producer['valid_to'],'terminal_actual_memory_original_payload_changed')
                actual_material=value['actual_work']['material_context']
                require(actual_material['mode']=='memory' and actual_material['memory_origin']==origin
                    and actual_material['prior']=={key:prior[key] for key in
                        ('proposal','business','result_id','result_sha256','accepted_at','valid_to')},
                    'terminal_actual_memory_consumer_prior_bytes')
                require(origin['prior_task_id'] == self.task_ids[label]
                    and origin['result_id'] == prior['result_id']
                    and origin['accepted_at'] == prior['accepted_at'] == value['accepted_at']
                    and origin['historical_valid_to'] == prior['valid_to'] and value['valid_to'] <= prior['valid_to']
                    and value['sources'] == prior['sources']
                    and value['root']['result']['decision_id'] != prior['root']['result']['decision_id'],
                    'terminal_actual_memory_descent_identity')
                rows = value['work']['actual_results']
                require(any(r['status'] == 'COMPLETED' and r['work_id'] == 'memory0' for r in rows),
                    'terminal_actual_memory_work_required')
        elif step == 'A4':
            native_refusal=round_observation.get('native_refusal')
            require(type(native_refusal) is dict and native_refusal.get('status')=='EXHAUSTED'
                and native_refusal.get('reason')=='work_task_revision_exhausted',
                'terminal_actual_native_revision_exhaustion_required')
            require(witness['selected_result'] == self.saved['A3']
                and state['tasks'][self.task_ids['A']]['status'] == 'FAILED', 'terminal_exhaustion_history_not_preserved')
            previous = self.saved['A3']['work']['actual_results']
            snap = witness['controller_snapshots'][self.task_ids['A']]
            require(snap['result']['work']['actual_results'] == previous, 'terminal_exhaustion_work_dispatched')
        elif step.startswith('A6'):
            require(state['tasks'][self.task_ids['A']]['status'] == 'CANCELLED'
                and witness['selected_result'] == self.saved['A5'], 'terminal_cancel_history_not_preserved')
            if step == 'A6_REFUSAL':
                require(witness.get('error',{}).get('code') in ('task_cancelled_before_dispatch','task_round_cancelled'),
                    'terminal_cancel_wrong_refusal')
        self.steps.append(dict(step=step,status=status,task_id=self.task_ids.get(label),new_attempts=count,
            process_index=self.process_index+1,readback_ref=reference))
        put(self.run/('step_%02d_%s.json'%(len(self.steps),step)),self.steps[-1],cap=65536)
        self.last_witness = witness
        self.position += 1
        self.pending = None
        return step,status

    def process_closed(self,index):
        require(index == self.process_index and not self._remaining() and self.pending is None,
            'terminal_driver_incomplete_process')
        self.process_index += 1

    def result(self):
        require(self.process_index == 2 and len(self.rounds)==9 and len({r['round_id'] for r in self.rounds})==9
            and len(self.last_ledger['attempts'])-len(self.initial_attempts) == 9,
            'terminal_driver_incomplete_two_process_route')
        return dict(schema='radik.stage04.closure_driver_result.v01', status='ROUTE_OBSERVED_REQUIRES_INDEPENDENT_ACCEPTANCE',
            task_ids=self.task_ids,steps=self.steps,rounds=self.rounds,actual_new_role_attempts=9,native_E_calls=0,
            actual_started_rounds=9,cancel_refusal_grants=0,cancel_refusal_basis='CURRENT_PREPARE_ROUND_SOURCES_REFUSES_BEFORE_GRANT',
            model_observation_after_handoff=False,automatic_retry=False,
            Stage04_acceptance='REQUIRES_COMPOSITE_REVIEW_WITH_ACCEPTED_P30_E')


def supervise(profile, *, started_ns, lock_fd, launch, timing, run,
        interrupted=lambda: False, popen=subprocess.Popen):
    """One shared P28 clock and two sequential ordinary stdin consumers."""
    limits = profile['limits']
    deadline = timing.Deadline(started_ns,limits=limits)
    driver = OrdinaryDriver(profile['scenario_inputs'],run)
    receipt = dict(schema='radik.stage04.closure_owner_terminal_receipt.v01', status='NOT_LAUNCHED',
        approved_argv=profile['argv'],operation_started_ns=started_ns,operation_deadline_ns=deadline.deadline_ns,
        limits=limits,primary_failure=None,secondary_failures=[],signals=[],children=[],child_reaped=False,
        automatic_retry=False,model_observation_after_handoff=False,supervisor_model_calls=0,
        supervisor_native_calls=0,native_E_allowed=False,native_acceptance_inferred=False,
        runtime_adoption=False,lock_explicit_unlock_permitted=True)
    child = None
    total_cpu = 0
    try:
        for process_index in range(2):
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
            sub = dict(schema='radik.stage04.closure_child_receipt.v01', process_index=process_index+1,
                argv=argv,launch_ref=child_launch_ref,events=0,final_event=None,
                child_reaped=False,signals=[],readbacks=[],step_refs=[],primary_failure=None)
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
                        require(kind not in ('E_ENTER','E_EXIT') and row['phase'] != 'E','terminal_stage04_E_forbidden')
                        if kind in ('PRIMARY_FAILURE','REQUIRED_WITNESS_UNAVAILABLE'):
                            retain_failure(receipt,row['failure'],timing)
                        verified = False;witness = None
                        ref = row.get('readback_ref')
                        if ref is not None:
                            witness = json.loads(checked_reference(ref,cap=limits['evidence_bytes'],
                                prefixes=profile['evidence_prefixes']))
                            sub['readbacks'].append(ref);sub['last_readback_ref']=ref;verified = True
                        deadline.event(row,observed_ns=time.monotonic_ns(),readback_verified=verified)
                        if receipt['primary_failure'] is not None:continue
                        stage = row.get('stage')
                        if kind == 'STATUS' and stage == 'CONSOLE_READY':
                            require(verified,'terminal_console_ready_readback')
                            require(type(witness) is dict and set(witness)=={'classification','type','body'}
                                and witness['classification']=='PORTABLE_EVIDENCE_NOT_LIVE_AUTHORITY'
                                and witness['type']=='builtins.dict','terminal_console_witness_wrapper')
                            driver.observe_ready(witness['body'])
                            show('Процесс %d: обычная консоль и новая операция готовы; wall=%.3f с, CPU=%.3f с, осталось=%.3f с.'%(
                                process_index+1,(time.monotonic_ns()-started_ns)/1e9,(total_cpu+latest_cpu)/1e9,
                                max(0,deadline.deadline_ns-time.monotonic_ns())/1e9))
                        elif kind == 'STATUS' and stage == 'CONSOLE_COMMAND_COMPLETED':
                            require(verified,'terminal_console_command_readback')
                            require(type(witness) is dict and set(witness)=={'classification','type','body'}
                                and witness['classification']=='PORTABLE_EVIDENCE_NOT_LIVE_AUTHORITY'
                                and witness['type']=='builtins.dict','terminal_console_witness_wrapper')
                            step,status = driver.complete(row,witness['body'],ref)
                            show('Шаг %s завершён: %s; wall=%.3f с, CPU=%.3f с, осталось=%.3f с; свидетельство=%s'%(
                                step,status,(time.monotonic_ns()-started_ns)/1e9,(total_cpu+latest_cpu)/1e9,
                                max(0,deadline.deadline_ns-time.monotonic_ns())/1e9,ref['path']))
                        elif kind == 'STATUS' and stage == 'CONSOLE_INPUT_REQUIRED':
                            line = driver.next_line(row)
                            if row['prompt_id'] == 'command':show('Начинаю шаг '+driver.pending['step']+'.')
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
                        show('Ожидание шага %s: wall=%.1f с, CPU=%.3f с, native=%.1f с, осталось=%.1f с; завершение шага ещё не получено.'%(
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
                    show('Свидетельство перед остановкой: '+sub['last_readback_ref']['path'])
            finally:
                if child is not None and child.poll() is None:
                    stop = deadline.stop_ns or time.monotonic_ns()
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
                show('Процесс %d закрыт: exit=%s, reap=%s.'%(process_index+1,str(sub['child_exit_code']),str(reaped)))
            if receipt['primary_failure'] is not None:break
        if receipt['primary_failure'] is None:
            result = driver.result()
            receipt['scenario_result_ref'] = put(run/'scenario_result.json',result,cap=limits['receipt_bytes'])
    except BaseException as error:
        code = error.args[0] if type(error) is ValueError and error.args else 'TERMINAL_TWO_PROCESS_CLOSURE_FAILURE'
        if type(code) is not str or not re.fullmatch('[A-Za-z0-9_:./-]{1,256}',code):code = 'TERMINAL_TWO_PROCESS_CLOSURE_FAILURE'
        retain_failure(receipt,timing.fallback(code,type(error).__name__),timing)
    finally:
        if child is not None and child.poll() is None:
            try:bounded_cleanup(child,stop_ns=deadline.stop_ns or time.monotonic_ns(),limits=limits,
                signals=receipt['signals'],started_ns=started_ns)
            except BaseException:retain_failure(receipt,timing.fallback('CLEANUP_EXCEPTION'),timing)
        reaped = child is None or child.poll() is not None
        receipt['child_reaped'] = child is not None and reaped
        receipt['lock_explicit_unlock_permitted'] = reaped
        receipt['child_exit_code'] = None if child is None else child.returncode
        receipt.update(status='CLEANUP_UNCONFIRMED' if not reaped else
            'TWO_CHILDREN_CLOSED_REVIEW_REQUIRED' if receipt['primary_failure'] is None and len(receipt['children'])==2 else 'STOPPED_NO_RETRY',
            deadline_measurement=deadline.measurement(time.monotonic_ns()),completed_steps=driver.steps,
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
        show('Начало Stage04 A/B/C/R: два последовательных процесса, не более 9 новых role calls, E запрещён. Общий предел 7800 с; native суммарно 3600 с; ответ модели 600 с; cleanup 30 с. Это пределы, не прогноз.')
        scenario_inputs = load_scenario_inputs(admission)
        child_started = True
        supervision_attempted = True
        receipt = supervise(dict(argv=admission['argv'], limits=timing.LIMITS,
            interpreter_ref=admission['interpreter_ref'],
            evidence_prefixes=admission['evidence_prefixes'],
            home_directory=admission.get('home_directory', str(Path.home())),
            scenario_inputs=scenario_inputs,
            rehearsal_seal_sha256=args.rehearsal_seal_sha256, launch_ref=launch_ref),
            started_ns=STARTED_NS, lock_fd=lock_fd, launch=launch, timing=timing,
            run=run, interrupted=lambda: interrupted[0])
        exit_code = 0 if receipt['status'] == 'TWO_CHILDREN_CLOSED_REVIEW_REQUIRED' else 2
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
