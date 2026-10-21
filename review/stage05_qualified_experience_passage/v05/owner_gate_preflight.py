"""Bounded read-only execution of the real production profile predicate.

Final project metadata uses ordinary gate readers and the unchanged REAL_PROJECT.
Separate negative JSON fixtures exercise the same production-shared validator.
No installer, owner main, reservation, AUTH, application or native entry runs.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage05_qualified_experience_passage/v05'
SELF = BASE + '/owner_gate_preflight.py'
PROPOSAL = BASE + '/owner_gate_preflight_proposal.json'
WORK = None


def require(ok, code):
    if not ok:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(relative):
    require(type(relative) is str and relative == Path(relative).as_posix()
        and not Path(relative).is_absolute() and all(part not in
            ('', '.', '..', '.git', '.codex', 'private', 'Arena', 'arena')
            and not part.startswith(('.env', '.venv')) for part in relative.split('/')),
        'owner_gate_control_path')
    path = PROJECT / relative
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'owner_gate_control_symlink')
        if item == PROJECT:
            break
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= 67108864, 'owner_gate_control_regular')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink,
        s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
        'owner_gate_control_read_changed')
    return raw


def exact(reference):
    raw = read(reference['path'])
    require(digest(raw) == reference['sha256'] and len(raw) == reference['size_bytes'],
        'owner_gate_control_pin')
    return raw


def persist(name, value):
    require(re.fullmatch(r'[a-z0-9_]+\.json', name), 'owner_gate_control_output_name')
    path = WORK / name
    raw = canonical(value) + b'\n'
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    relative = path.relative_to(PROJECT).as_posix()
    require(read(relative) == raw, 'owner_gate_control_output_readback')
    return dict(path=relative, sha256=digest(raw), size_bytes=len(raw))


def fence(allowed):
    stdlib = Path(sys.base_prefix).resolve()
    def audit(event, args):
        if event.startswith(('socket.', 'subprocess.')) or event in (
                'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec',
                'ctypes.dlopen', 'ctypes.dlsym'):
            raise ValueError('owner_gate_control_external_action_refused')
        if event == 'import' and args:
            require(str(args[0]).split('.')[0] not in ('app', 'config', 'hedgehog'),
                'owner_gate_control_application_import_refused')
        if event == 'open' and args and not isinstance(args[0], int):
            path = Path(os.fsdecode(args[0])).absolute()
            mode, flags = args[1:3]
            writing = isinstance(mode, str) and any(c in mode for c in 'wax+')
            writing = writing or isinstance(flags, int) and bool(flags &
                (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            require('..' not in path.parts and (path.is_relative_to(WORK) if writing
                else path.is_relative_to(WORK) or path in allowed
                or path.resolve().is_relative_to(stdlib)), 'owner_gate_control_io_scope')
        if event in ('os.remove', 'os.unlink', 'os.rmdir', 'os.mkdir', 'os.rename',
                'os.chmod', 'os.chown', 'os.link', 'os.symlink', 'os.truncate'):
            for value in args[:2] if event in ('os.rename', 'os.link', 'os.symlink') else args[:1]:
                if isinstance(value, (str, bytes, Path)):
                    require(Path(os.fsdecode(value)).absolute().is_relative_to(WORK),
                        'owner_gate_control_mutation_scope')
    sys.addaudithook(audit)


def load_gate(reference, name):
    raw = exact(reference)
    module = types.ModuleType(name)
    module.__file__ = str(PROJECT / reference['path'])
    sys.modules[name] = module
    exec(compile(raw, module.__file__, 'exec', dont_inherit=True), module.__dict__)
    require(module.REAL_PROJECT == PROJECT, 'owner_gate_control_real_project_unchanged')
    require(module.rehearsal_context(PROJECT) is None, 'owner_gate_control_no_rehearsal')
    return module


def refused(call, expected):
    try:
        call()
    except ValueError as error:
        require(type(error) is ValueError and error.args == (expected,),
            'owner_gate_control_wrong_refusal')
        return expected
    raise ValueError('owner_gate_control_expected_refusal')


def main():
    global WORK
    started = time.monotonic_ns()
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    require(re.fullmatch(re.escape(BASE) + r'/grants/OWNER_GATE_V[0-9]{2}\.json', args.grant),
        'owner_gate_control_grant_path')
    raw = read(args.grant)
    require(digest(raw) == args.sha256, 'owner_gate_control_grant_hash')
    grant = json.loads(raw)
    require(grant['reviewer'] == '/root/private_remote_controls'
        and grant['approved_executor'] == '/root' and grant['approved_invocation_count'] == 1
        and args.grant == BASE + '/grants/' + grant['actual_id'] + '.json'
        and grant['network'] == 'DENIED' and grant['production_writes_allowed'] is False
        and grant['real_AUTH_provider_native_E_SAVE_allowed'] is False
        and grant['automatic_retry'] is False and grant['total_budget_seconds'] == 300,
        'owner_gate_control_independent_grant')
    require(grant['runner_ref']['path'] == SELF and grant['proposal_ref']['path'] == PROPOSAL,
        'owner_gate_control_grant_sources')
    exact(grant['runner_ref'])
    proposal = json.loads(exact(grant['proposal_ref']))
    refs = proposal['input_refs']
    require(type(refs) is list and 1 <= len(refs) <= 4096
        and len({r['path'] for r in refs}) == len(refs), 'owner_gate_control_finite_inventory')
    before = {r['path']: exact(r) for r in refs}
    WORK = PROJECT / BASE / 'offline_actual' / grant['actual_id'] / 'work'
    require(not WORK.exists(), 'owner_gate_control_no_retry')
    WORK.mkdir(parents=True, mode=0o700)
    fence({PROJECT / r['path'] for r in refs} | {PROJECT / args.grant,
        PROJECT / SELF, PROJECT / PROPOSAL})
    persist('reservation.json', dict(actual_id=grant['actual_id'], grant_sha256=args.sha256,
        automatic_retry=False, production_owner_reservation_created=False,
        cumulative_prior_charged_ns=grant['prior_charged_ns']))
    trace = []
    gate_files = {str(PROJECT / proposal[k]['path']) for k in ('old_gate_ref', 'final_gate_ref')}
    def observe(frame, event, arg):
        if event == 'call' and frame.f_code.co_filename in gate_files:
            name = frame.f_code.co_name
            require(name not in ('select', 'require_external_owner'),
                'owner_gate_control_unplanned_entry')
            if name in ('load_profile', 'owner_eligibility', 'validate_owner_focused_review'):
                trace.append(dict(path=frame.f_code.co_filename.removeprefix(str(PROJECT) + '/'),
                    function=name, line=frame.f_code.co_firstlineno))
    sys.setprofile(observe)
    try:
        old = load_gate(proposal['old_gate_ref'], '_radik_v04_actual_owner_gate')
        old_selected = old.load_profile(PROJECT, proposal['old_manifest_ref'])
        original_refusal = refused(lambda: old.owner_eligibility(PROJECT, old_selected),
            'profile_gate_focused_wiring_admission')
        gate = load_gate(proposal['final_gate_ref'], '_radik_v05_final_owner_gate')
        selected = gate.load_profile(PROJECT, proposal['final_manifest_ref'])
        final_admission = json.loads(exact(proposal['final_admission_ref']))
        require(selected['manifest'] == json.loads(exact(proposal['final_manifest_ref'])),
            'owner_gate_control_final_manifest_identity')
        accepted = gate.owner_eligibility(PROJECT, selected)
        require(accepted == final_admission, 'owner_gate_control_final_admission_identity')
        focused = json.loads(exact(proposal['final_focused_ref']))
        require(final_admission['rehearsal_result_review_ref'] == proposal['final_focused_ref'],
            'owner_gate_control_final_focused_reference')
        require(gate.validate_owner_focused_review(PROJECT, final_admission) == focused,
            'owner_gate_control_final_shared_predicate')
        cases = []
        mutations = (
            ('incompatible_status', 'status', 'ACCEPTED_REPAIR_CONTROLS_FOR_ONE_FUTURE_EXPLICIT_OWNER_REMAINDER'),
            ('arbitrary_pass', 'status', 'PASS'),
            ('wrong_reviewer', 'reviewer', '/root/unaccepted_reviewer'),
            ('false_controls', 'all_required_controls_passed', False),
            ('false_owner_authorization', 'owner_execution_authorized', False),
            ('changed_focused_pins', 'code_pins', dict(final_admission['code_pins'],
                **{'config/application_profile_gate.py': '0' * 64})),
        )
        for label, field, value in mutations:
            negative = copy.deepcopy(focused)
            negative[field] = value
            reference = persist('negative_' + label + '.json', negative)
            admission = copy.deepcopy(final_admission)
            admission['rehearsal_result_review_ref'] = reference
            code = refused(lambda: gate.validate_owner_focused_review(PROJECT, admission),
                'profile_gate_focused_wiring_admission')
            cases.append(dict(case=label, refusal=code, test_data_ref=reference,
                production_shared_function='validate_owner_focused_review'))
        for label, field, value in (
                ('changed_reference_hash', 'sha256', '0' * 64),
                ('changed_reference_size', 'size_bytes', proposal['final_focused_ref']['size_bytes'] + 1)):
            admission = copy.deepcopy(final_admission)
            admission['rehearsal_result_review_ref'][field] = value
            code = refused(lambda: gate.validate_owner_focused_review(PROJECT, admission),
                'profile_gate_reference_changed')
            cases.append(dict(case=label, refusal=code,
                production_shared_function='validate_owner_focused_review'))
    finally:
        sys.setprofile(None)
    for reference in refs:
        require(exact(reference) == before[reference['path']], 'owner_gate_control_input_mutated')
    for name in proposal['must_remain_absent']:
        require(not (PROJECT / name).exists(), 'owner_gate_control_production_marker_created')
    result = dict(schema='radik.stage05.real_production_owner_gate_preflight.v05',
        status='PASS_REAL_PRODUCTION_OWNER_GATE_READ_ONLY_PREFLIGHT',
        actual_id=grant['actual_id'], proposal_ref=grant['proposal_ref'],
        original_pair_refusal=original_refusal, final_pair_passed=True,
        original_gate_ref=proposal['old_gate_ref'], final_gate_ref=proposal['final_gate_ref'],
        final_manifest_ref=proposal['final_manifest_ref'], final_admission_ref=proposal['final_admission_ref'],
        final_focused_ref=proposal['final_focused_ref'], production_root=str(PROJECT),
        REAL_PROJECT_rebound=False, project_reader_replaced=False, rehearsal_used=False,
        candidate_gate_loaded_after_exact_pin=True, loaded_module_trace=trace,
        negative_cases=cases, inputs_unchanged=len(refs),
        production_owner_reservation_created=False, installer_called=False,
        owner_main_called=False, production_ACK_applied=False,
        AUTH_provider_model_native_SAVE_calls=0, Stage05_acceptance=False,
        elapsed_wall_ns=time.monotonic_ns() - started)
    ref = persist('result.json', result)
    print('OWNER_GATE_PREFLIGHT_RETURN ' + json.dumps(ref, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
