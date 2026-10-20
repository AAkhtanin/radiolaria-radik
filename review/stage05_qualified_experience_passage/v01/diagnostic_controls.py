"""One independently admitted, isolated closed-diagnostic control passage.

Only the pinned diagnostic module is executed. Scenario and G3 code are parsed
as source; no application package, native consumer or provider is imported.
"""
import argparse
import ast
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
PREFIX = 'review/stage05_qualified_experience_passage/v01'
SELF = PREFIX + '/diagnostic_controls.py'
PROPOSAL = PREFIX + '/diagnostic_code_additions.json'
DIAGNOSTICS = PREFIX + '/after/app/stage04_diagnostics.py'
SCENARIO = PREFIX + '/after/app/qualified_experience_scenario.py'
EXPERIENCE = PREFIX + '/after/app/qualified_experience.py'
STARTED = time.monotonic()


def require(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(relative):
    require(type(relative) is str and relative and not relative.startswith('/')
        and '\\' not in relative and all(part not in ('', '.', '..', '.git',
        '.codex', '.aws', 'private', 'local_operator', 'local_operator_private')
        and not part.startswith('.venv') for part in relative.split('/')),
        'diagnostic_control_path')
    target = PROJECT
    for part in relative.split('/'):
        target /= part
        require(not target.is_symlink(), 'diagnostic_control_symlink')
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= 2 * 1024 * 1024, 'diagnostic_control_file_bound')
        raw = stream.read(2 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
        item.st_mtime_ns, item.st_ctime_ns, item.st_nlink)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
        'diagnostic_control_read_stability')
    return raw


def verify(reference):
    require(type(reference) is dict and set(reference) == {'path', 'sha256', 'size_bytes'},
        'diagnostic_control_reference')
    raw = read(reference['path'])
    require(digest(raw) == reference['sha256'] and len(raw) == reference['size_bytes'],
        'diagnostic_control_reference_changed')
    return raw


def put(directory, name, value):
    require(re.fullmatch('[a-z_]+[.]json', name) is not None, 'diagnostic_control_output_name')
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        require(stream.write(raw) == len(raw), 'diagnostic_control_short_write')
        stream.flush()
        os.fsync(stream.fileno())
    require(path.read_bytes() == raw, 'diagnostic_control_output_readback')


def fence(directory):
    def audit(event, args):
        if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system',
                'os.fork', 'os.posix_spawn', 'os.exec'):
            raise ValueError('diagnostic_control_external_action_refused')
        if event == 'open' and args and isinstance(args[0], (str, bytes, Path)):
            path = Path(os.fsdecode(args[0])).absolute()
            require(not set(path.parts).intersection(('private', '.codex', '.aws',
                'Arena', 'arena', 'local_operator', 'local_operator_private')),
                'diagnostic_control_private_read_refused')
            mode, flags = args[1:3]
            writing = isinstance(mode, str) and any(flag in mode for flag in 'wax+')
            writing = writing or isinstance(flags, int) and bool(flags & (1 | 2 | 64 | 512 | 1024))
            require(not writing or path.is_relative_to(directory),
                'diagnostic_control_production_write_refused')
        if event in ('os.mkdir', 'os.remove', 'os.unlink', 'os.rmdir', 'os.rename', 'os.chmod'):
            values = args[:2] if event == 'os.rename' else args[:1]
            for value in values:
                if isinstance(value, (str, bytes, Path)):
                    require(Path(os.fsdecode(value)).absolute().is_relative_to(directory),
                        'diagnostic_control_production_mutation_refused')
    sys.addaudithook(audit)


def static_checks(scenario_raw, experience_raw):
    scenario = ast.parse(scenario_raw)
    handlers = [node for node in ast.walk(scenario) if isinstance(node, ast.ExceptHandler)
        and isinstance(node.type, ast.Name) and node.type.id == 'BaseException']
    matched = False
    for handler in handlers:
        calls = [node for node in ast.walk(handler) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)]
        observed = [node for node in calls if node.func.id == 'observe_failure'
            and any(item.arg == 'step' and isinstance(item.value, ast.Constant)
                and item.value.value == 'STAGE05_EXPERIENCE' for item in node.keywords)]
        projected = [node for node in calls if node.func.id == 'project_error']
        if observed and projected and observed[0].lineno < projected[0].lineno:
            matched = True
    require(matched, 'diagnostic_control_scenario_first_observation')
    experience = ast.parse(experience_raw)
    calls = [node for node in ast.walk(experience) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == 'require'
        and len(node.args) == 2 and isinstance(node.args[0], ast.UnaryOp)
        and isinstance(node.args[0].op, ast.Not) and isinstance(node.args[0].operand, ast.Name)
        and node.args[0].operand.id == 'causal_errors']
    require(len(calls) == 1 and isinstance(calls[0].args[1], ast.Constant)
        and calls[0].args[1].value == 'experience_native_causal_proof',
        'diagnostic_control_causal_literal')


def main():
    require(sys.dont_write_bytecode, 'diagnostic_control_requires_B')
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    require(args.grant.startswith(PREFIX + '/') and args.grant.endswith('.json'),
        'diagnostic_control_grant_path')
    grant_raw = read(args.grant)
    require(digest(grant_raw) == args.sha256, 'diagnostic_control_grant_changed')
    grant = json.loads(grant_raw)
    require(grant.get('schema') == 'radik.stage05.diagnostic_control_grant.v01'
        and grant.get('status') == 'SOURCE_ACCEPTED_FOR_PINNED_DIAGNOSTIC_CONTROLS'
        and grant.get('reviewer') == '/root/private_remote_controls'
        and grant.get('approved_executor') == '/root'
        and grant.get('approved_invocation_count') == 1
        and grant.get('automatic_retry') is False
        and grant.get('production_writes_allowed') is False
        and grant.get('real_AUTH_provider_native_E_SAVE_allowed') is False,
        'diagnostic_control_independent_admission')
    require(grant['runner_ref']['path'] == SELF
        and verify(grant['runner_ref']) == read(SELF), 'diagnostic_control_runner_pin')
    require(grant['proposal_ref']['path'] == PROPOSAL, 'diagnostic_control_proposal_path')
    proposal = json.loads(verify(grant['proposal_ref']))
    expected = {item['path']: item['proposed_after_sha256'] for item in proposal['changed_sources']}
    require(set(expected) == {DIAGNOSTICS, SCENARIO, EXPERIENCE}
        and grant['source_pins'] == expected, 'diagnostic_control_source_closure')
    sources = {name: read(name) for name in expected}
    require(all(digest(raw) == expected[name] for name, raw in sources.items()),
        'diagnostic_control_preimport_pin')
    for reference in proposal['source_refs']:
        verify(reference)
    for reference in grant['production_guard_refs']:
        verify(reference)
    identifier = grant['actual_id']
    require(type(identifier) is str and re.fullmatch('[A-Z0-9_]{1,64}', identifier),
        'diagnostic_control_actual_id')
    parent = PROJECT / PREFIX / 'diagnostics_actual'
    require(not parent.is_symlink(), 'diagnostic_control_output_symlink')
    parent.mkdir(exist_ok=True, mode=0o700)
    directory = parent / identifier
    directory.mkdir(mode=0o700)
    fence(directory)
    put(directory, 'reservation.json', dict(grant_sha256=args.sha256, one_use=True,
        automatic_retry=False, source_only=True))
    result = dict(status='STARTED', semantic_acceptance=False, owner_actual=False,
        model_calls=0, native_work_calls=0, application_package_imports=0,
        source_pins=expected, checks=[])
    try:
        static_checks(sources[SCENARIO], sources[EXPERIENCE])
        result['checks'].append('STATIC_SCENARIO_FIRST_OBSERVATION_AND_G3_LITERAL')
        module = types.ModuleType('radik_stage05_closed_diagnostic_control')
        module.__file__ = str(PROJECT / DIAGNOSTICS)
        exec(compile(sources[DIAGNOSTICS], module.__file__, 'exec', dont_inherit=True), module.__dict__)
        codes = proposal['literal_additions']
        require(type(codes) is list and 1 <= len(codes) <= 512
            and len(codes) == len(set(codes)), 'diagnostic_control_finite_codes')
        for code in codes:
            require(time.monotonic() - STARTED < 30, 'diagnostic_control_deadline')
            error = ValueError(code)
            first = module.observe_failure(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
            later = module.observe_failure(error, phase='TASK_EXECUTION', step='INTERACTIVE_TASK')
            require(first['code'] == later['code'] == code
                and first['step'] == later['step'] == 'STAGE05_EXPERIENCE'
                and module.safe_projection(later)['code'] == code
                and code in module.projection_line(later), 'diagnostic_control_exact_code_preservation')
        result['checks'].append('ALL_EXACT_NEW_NATIVE_AND_G3_CODES_PRESERVED')
        result['literal_codes_checked'] = len(codes)
        for text in ('UNREVIEWED_DIAGNOSTIC_SENTINEL_78c135',
                'g4_reference:UNREVIEWED_DIAGNOSTIC_SENTINEL_78c135',
                'experience_native_causal_proof:UNREVIEWED_DIAGNOSTIC_SENTINEL_78c135'):
            value = module.project_error(ValueError(text), phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
            require(value['code'] == 'SANITIZED_OPERATION_FAILURE'
                and text not in module.projection_line(value), 'diagnostic_control_unknown_text_disclosure')
        result['checks'].append('ARBITRARY_AND_PREFIX_LOOKALIKE_TEXT_SANITIZED')
        require(not any(name == 'app' or name.startswith('app.') for name in sys.modules),
            'diagnostic_control_application_package_import')
        require(all(read(name) == raw for name, raw in sources.items()),
            'diagnostic_control_source_changed')
        for reference in grant['production_guard_refs']:
            verify(reference)
        result['checks'].append('SOURCE_AND_PRODUCTION_GUARDS_UNCHANGED')
        result['status'] = 'PASS_PINNED_CLOSED_DIAGNOSTICS_ONLY'
        return 0
    except BaseException as error:
        result['status'] = 'STOPPED_NO_RETRY'
        closed = {'diagnostic_control_scenario_first_observation', 'diagnostic_control_causal_literal',
            'diagnostic_control_finite_codes', 'diagnostic_control_deadline',
            'diagnostic_control_exact_code_preservation', 'diagnostic_control_unknown_text_disclosure',
            'diagnostic_control_application_package_import', 'diagnostic_control_source_changed',
            'diagnostic_control_reference_changed'}
        code = error.args[0] if type(error) is ValueError and len(error.args) == 1 else None
        result['failure'] = dict(error_class=type(error).__name__,
            code=code if type(code) is str and code in closed else 'diagnostic_control_failed')
        return 2
    finally:
        result['elapsed_wall_seconds'] = time.monotonic() - STARTED
        put(directory, 'result.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
