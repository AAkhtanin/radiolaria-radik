"""Read the exact future owner admission and exercise refusal gates; spawn nothing."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import time
import types

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = PROJECT/'review/stage07_pure_capability_passage/v01'
OUTPUT = BASE/'resume_20261023_02/owner_command_preflight_actual'


def require(value, code):
    if not value:
        raise ValueError(code)


def exact(reference):
    path = Path(reference['path'])
    path = path if path.is_absolute() else PROJECT/path
    require(path.is_relative_to(PROJECT) and not path.is_symlink(), 'preflight_reference_scope')
    raw = path.read_bytes()
    require(len(raw) == reference['size_bytes']
        and hashlib.sha256(raw).hexdigest() == reference['sha256'], 'preflight_reference_changed')
    return raw


def save(name, value):
    path = OUTPUT/name
    raw = (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(path.read_bytes() == raw, 'preflight_readback')
    return dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))


def reservation_inventory():
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((BASE/'reservations').glob('*.json'))}


def main():
    started = time.monotonic_ns()
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    path = PROJECT/args.grant
    raw = path.read_bytes()
    require(path.is_relative_to(BASE/'resume_20261023_02/independent_review')
        and hashlib.sha256(raw).hexdigest() == args.sha256, 'preflight_grant_pin')
    grant = json.loads(raw)
    binding = json.loads(exact(grant['reviewer_binding_ref']))
    require(grant['reviewer'] == binding['reviewer'] == '/root/stage07_recovery_reviewer'
        and grant['status'] == 'ACCEPTED_FOR_ONE_ZERO_CHILD_OWNER_COMMAND_PREFLIGHT'
        and grant['approved_executor'] == '/root' and grant['approved_invocations'] == 1
        and grant['owner_execution_allowed'] is False, 'preflight_independent_grant')
    require(exact(grant['source_ref']) == Path(__file__).read_bytes(), 'preflight_self_pin')
    exact(grant['interpreter_ref'])
    admission_ref = grant['owner_admission_ref']
    admission = json.loads(exact(admission_ref))
    owner_source = exact(grant['owner_terminal_ref'])
    require(Path(grant['owner_terminal_ref']['path']) == BASE/'owner_terminal.py',
        'preflight_owner_source_path')
    before = reservation_inventory()
    owner_runs_before = sorted(str(path) for path in (BASE/'owner_terminal_runs').glob('*'))
    OUTPUT.mkdir(exist_ok=False)
    def audit(event, arguments):
        if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system',
                'os.posix_spawn', 'os.fork', 'os.forkpty'):
            raise PermissionError('preflight_process_or_network_forbidden')
        if event == 'open' and isinstance(arguments[0], (str, bytes)):
            mode, flags = arguments[1], arguments[2]
            writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if writing:
                target = Path(os.fsdecode(arguments[0])).absolute()
                require(target.is_relative_to(OUTPUT), 'preflight_write_scope')
        if event in ('os.mkdir', 'os.remove', 'os.rename', 'os.rmdir'):
            raise PermissionError('preflight_mutation_forbidden')
    sys.addaudithook(audit)
    module = types.ModuleType('stage07_exact_owner_preflight')
    module.__file__ = str(BASE/'owner_terminal.py')
    exec(compile(owner_source, module.__file__, 'exec'), module.__dict__)
    checked, manifest, scenario, *_ = module.load_admission(admission_ref, mode='owner')
    require(checked == admission and scenario['task_selector'] == 'pure_capability_owner_v01',
        'preflight_owner_selection')
    controls = []
    mutations = [
        ('source_author', lambda value: value.update(reviewer='/root'), 'stage07_terminal_independent_admission'),
        ('retired_reviewer', lambda value: value.update(reviewer='/root/private_remote_controls'), 'stage07_terminal_independent_admission'),
        ('missing_binding', lambda value: value.pop('reviewer_binding_ref'), 'stage07_terminal_independent_admission'),
        ('wrong_binding_path', lambda value: value['reviewer_binding_ref'].update(path=str(BASE/'not_the_binding.json')), 'stage07_terminal_independent_admission'),
        ('wrong_binding_hash', lambda value: value['reviewer_binding_ref'].update(sha256='0'*64), 'stage07_terminal_reference_changed'),
        ('focus_in_owner_mode', lambda value: value.update(task_selector='pure_capability_expiry_tail_v01'), 'stage07_terminal_independent_admission'),
        ('owner_count_zero', lambda value: value.update(approved_owner_invocations=0), 'stage07_terminal_independent_admission'),
    ]
    for label, mutate, expected in mutations:
        value = copy.deepcopy(admission)
        mutate(value)
        reference = save(label+'.json', value)
        try:
            module.load_admission(reference, mode='owner')
        except ValueError as error:
            require(error.args == (expected,), 'preflight_refusal_reason')
        else:
            raise ValueError('preflight_refusal_missing')
        controls.append(dict(control=label, exact_refusal=expected, input_ref=reference))
    require(before == reservation_inventory()
        and owner_runs_before == sorted(str(path) for path in (BASE/'owner_terminal_runs').glob('*')),
        'preflight_no_owner_operation')
    require(not any(name == 'app' or name.startswith('app.') or name == 'hedgehog'
        or name.startswith('hedgehog.') for name in sys.modules), 'preflight_no_application_import')
    command = shlex.join(grant['future_owner_argv'])
    require(grant['future_owner_argv'] == [str(PROJECT/'.venv-plan/bin/python'), '-I', '-S', '-B',
        str(BASE/'owner_terminal.py'), '--admission-file', Path(admission_ref['path']).name,
        '--admission-sha256', admission_ref['sha256']], 'preflight_exact_command')
    result = dict(schema='radik.stage07.owner_command_preflight_result.v1',
        status='PREFLIGHT_PASSED_OWNER_NOT_EXECUTED', admission_ref=admission_ref,
        source_ref=grant['owner_terminal_ref'], future_owner_argv=grant['future_owner_argv'],
        command=command, command_sha256=hashlib.sha256(command.encode()).hexdigest(),
        controls=controls, positive_load_admission_passed=True, reservations_unchanged=True,
        owner_runs_unchanged=True, application_imports=0, child_processes=0,
        native_Work_calls=0, model_calls=0, owner_execution_performed=False,
        elapsed_ns=time.monotonic_ns()-started)
    reference = save('result.json', result)
    print(json.dumps(dict(result_ref=reference, status=result['status'], elapsed_ns=result['elapsed_ns']), sort_keys=True))


if __name__ == '__main__':
    main()
