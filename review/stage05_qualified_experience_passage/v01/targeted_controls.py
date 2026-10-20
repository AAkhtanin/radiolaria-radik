"""Pinned AST extracts and recorded-event projection; never an application run."""
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
from types import SimpleNamespace


PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
PREFIX = 'review/stage05_qualified_experience_passage/v01'
SELF = PREFIX + '/targeted_controls.py'
PROPOSAL = PREFIX + '/targeted_controls_proposal.json'
OWNER = PREFIX + '/owner_terminal.py'
ENTRY = PREFIX + '/after/app/ordinary_entry.py'
RUNTIME = PREFIX + '/after/app/runtime.py'
SCENARIO = PREFIX + '/after/app/qualified_experience_scenario.py'
DIAGNOSTICS = PREFIX + '/after/app/stage04_diagnostics.py'
COPY = PREFIX + '/rehearsal_actual/ORDINARY_V01/ordinary/source_under_test/'
PROCESS = COPY + PREFIX + '/owner_terminal_runs/ordinary/process_1/'
SCHEMA = 'radik.p28.owner_event.v01'
STARTED = time.monotonic()


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(relative):
    require(type(relative) is str and relative and not relative.startswith('/')
        and '\\' not in relative and all(part not in ('', '.', '..', '.git', '.codex',
        '.aws', 'private', 'local_operator', 'local_operator_private', 'Arena', 'arena')
        and not part.startswith(('.venv', '.env')) for part in relative.split('/')),
        'targeted_control_path')
    path = PROJECT
    require(not path.is_symlink(), 'targeted_control_project_symlink')
    for part in relative.split('/'):
        path /= part
        require(not path.is_symlink(), 'targeted_control_symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 <= before.st_size <= 2 * 1024 * 1024, 'targeted_control_read_bound')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
        item.st_mtime_ns, item.st_ctime_ns, item.st_nlink)
    require(len(raw) == before.st_size and identity(before) == identity(after),
        'targeted_control_read_stability')
    return raw


def verify(reference):
    require(type(reference) is dict and set(reference) == {'path', 'sha256', 'size_bytes'},
        'targeted_control_reference_shape')
    raw = read(reference['path'])
    require(digest(raw) == reference['sha256'] and len(raw) == reference['size_bytes'],
        'targeted_control_pin_changed')
    return raw


def put(directory, name, value):
    require(name in ('reservation.json', 'result.json'), 'targeted_control_output_name')
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        require(stream.write(raw) == len(raw), 'targeted_control_short_write')
        stream.flush()
        os.fsync(stream.fileno())
    require((directory / name).read_bytes() == raw, 'targeted_control_output_readback')


def fence(directory):
    def audit(event, args):
        if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system',
                'os.fork', 'os.posix_spawn', 'os.exec'):
            raise ValueError('targeted_control_external_action_refused')
        if event == 'import' and args:
            require(not str(args[0]).startswith(('app', 'hedgehog', 'config.')),
                'targeted_control_application_import_refused')
        if event == 'open' and args and isinstance(args[0], (str, bytes, Path)):
            path = Path(os.fsdecode(args[0])).absolute()
            require(not set(path.parts).intersection(('private', '.codex', '.aws',
                '.git', 'Arena', 'arena', 'local_operator', 'local_operator_private'))
                and not any(part.startswith('.env') for part in path.parts),
                'targeted_control_private_read_refused')
            mode, flags = args[1:3]
            writing = isinstance(mode, str) and any(flag in mode for flag in 'wax+')
            writing = writing or isinstance(flags, int) and bool(flags &
                (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            require(not writing or path.is_relative_to(directory), 'targeted_control_write_refused')
        if event in ('os.mkdir', 'os.remove', 'os.unlink', 'os.rmdir', 'os.rename', 'os.chmod'):
            for value in args[:2] if event == 'os.rename' else args[:1]:
                if isinstance(value, (str, bytes, Path)):
                    require(Path(os.fsdecode(value)).absolute().is_relative_to(directory),
                        'targeted_control_mutation_refused')
    sys.addaudithook(audit)


def extract(raw, *, name, constants=(), functions=(), extra=None):
    """Compile only explicitly named top-level definitions, never module startup."""
    tree = ast.parse(raw, filename=name)
    selected = []
    found = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            symbol = node.targets[0].id
            if symbol in constants:
                require(all(not isinstance(child, (ast.Attribute, ast.Subscript, ast.Lambda))
                    and (not isinstance(child, ast.Call) or isinstance(child.func, ast.Name)
                        and child.func.id == 'frozenset') for child in ast.walk(node.value)),
                    'targeted_control_constant_expression')
                selected.append(node)
                found.add(symbol)
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            require(not node.decorator_list and not any(isinstance(child, (ast.Import, ast.ImportFrom,
                ast.Global, ast.Nonlocal)) for child in ast.walk(node)), 'targeted_control_function_scope')
            selected.append(node)
            found.add(node.name)
    require(found == set(constants) | set(functions), 'targeted_control_extract_inventory')
    builtins = dict(frozenset=frozenset, type=type, len=len, getattr=getattr, str=str,
        int=int, bool=bool, max=max, all=all, set=set, BaseException=BaseException,
        ValueError=ValueError)
    namespace = {'__builtins__': builtins, '__name__': 'radik_reviewed_ast_extract'}
    namespace.update(extra or {})
    module = ast.Module(body=selected, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), name + ':reviewed_extract', 'exec', dont_inherit=True), namespace)
    return namespace


def calls(tree, name):
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == name]


def static_controls(sources):
    runtime = ast.parse(sources[RUNTIME])
    scenario = ast.parse(sources[SCENARIO])
    run_task = [node for node in ast.walk(runtime) if isinstance(node, ast.FunctionDef) and node.name == 'run_task']
    require(len(run_task) == 1, 'targeted_control_run_task_definition')
    task = run_task[0]
    defaults = dict(zip((arg.arg for arg in task.args.kwonlyargs), task.args.kw_defaults))
    require(isinstance(defaults.get('prepare_continuation'), ast.Constant)
        and defaults['prepare_continuation'].value is True, 'targeted_control_default_continuation_preserved')
    guarded = [node for node in ast.walk(task) if isinstance(node, ast.If)
        and isinstance(node.test, ast.BoolOp) and isinstance(node.test.op, ast.And)
        and isinstance(node.test.values[0], ast.Name) and node.test.values[0].id == 'prepare_continuation'
        and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
            and child.func.attr == 'prepare_source_continuation' for part in node.body for child in ast.walk(part))]
    require(len(guarded) == 1, 'targeted_control_only_continuation_preparation_guarded')
    explicit = [(name, node, kw.value) for name, tree in ((RUNTIME, runtime), (SCENARIO, scenario))
        for node in calls(tree, 'run_task') for kw in node.keywords if kw.arg == 'prepare_continuation']
    require(len(explicit) == 1 and explicit[0][0] == SCENARIO
        and isinstance(explicit[0][2], ast.Constant) and explicit[0][2].value is False,
        'targeted_control_only_stage05_opt_out')
    initialized = [kw.value for node in calls(scenario, 'dict') for kw in node.keywords
        if kw.arg == 'actual_model_calls']
    require(len(initialized) == 1 and isinstance(initialized[0], ast.Constant)
        and initialized[0].value is None, 'targeted_control_unobserved_model_count_none')
    first = [node for node in calls(task, 'observe_failure') if any(kw.arg == 'step'
        and isinstance(kw.value, ast.Name) and kw.value.id == 'active_step' for kw in node.keywords)]
    require(first and first[0].lineno < min(node.lineno for node in calls(task, 'record_secondary')),
        'targeted_control_task_first_failure_bound')
    branches = [node for node in ast.walk(runtime) if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
        and node.test.left.id == 'command' and any(isinstance(value, ast.Constant)
            and value.value == 'experience' for value in node.test.comparators)]
    require(len(branches) == 1, 'targeted_control_experience_branch')
    branch = branches[0]
    assignments = [node for node in branch.body if isinstance(node, ast.Assign)]
    require(any(any(isinstance(t, ast.Name) and t.id == 'active_step' for t in node.targets)
        and isinstance(node.value, ast.Constant) and node.value.value == 'STAGE05_EXPERIENCE'
        for node in assignments), 'targeted_control_stage05_active_step')
    owned = [node for node in branch.body if isinstance(node, ast.Try) and calls(node, 'run_experience')]
    require(len(owned) == 1 and any(isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == 'active_step' for t in node.targets)
        and isinstance(node.value, ast.Name) and node.value.id == 'prior_step' for node in owned[0].finalbody),
        'targeted_control_active_step_restored')
    owner = sources[OWNER].decode()
    require("deadline.event(row,observed_ns=time.monotonic_ns(),readback_verified=verified)\n"
        "                        if receipt['primary_failure'] is not None:continue\n"
        "                        display_now = time.monotonic_ns()\n"
        "                        progress = progress_line(row, readback_verified=verified," in owner,
        'targeted_control_display_after_validation')
    return dict(scope='AST_ONLY_RUNTIME_AND_SCENARIO', default_continuation=True,
        stage05_only_explicit_opt_out=True, initial_model_call_count=None,
        first_failure_uses_active_step=True, stage05_step_restored_in_finally=True,
        application_execution=False)


def timing_controls(function, legacy, reference, recorded_launch):
    fixture = json.loads(canonical(recorded_launch))
    fixture['source_review_ref'] = reference
    launch_name = PREFIX + '/owner_terminal_runs/SYNTHETIC_TIMING/process_1/launch.json'
    manifest = {'source_review_ref': reference}
    reads = []
    active = [fixture]

    def reader(project, name):
        require(project == 'SYNTHETIC_PROJECT' and name == launch_name, 'targeted_control_fixture_read_scope')
        reads.append(name)
        return canonical(active[0])

    gate = SimpleNamespace(_read=reader, require=require)

    def arguments(launch):
        return SimpleNamespace(owner_supervisor_launch=launch_name, owner_scenario=False,
            owner_run_binding=digest(canonical(launch)), **{'owner_' + name: launch[name]
                for name in ('operation_started_ns', 'operation_deadline_ns', 'operation_started_utc')})

    args = arguments(fixture)
    require(function('SYNTHETIC_PROJECT', args, manifest, gate, inherited_clock=True)
        == PREFIX + '/supervisor_timing.py', 'targeted_control_stage05_timing')
    fixtures = ['BOUND_STAGE05_FINAL_REVIEW_REFERENCE']
    for label, change, inherited in (
            ('PLAIN_CONSOLE_LEGACY', {'owner_supervisor_launch': None}, False),
            ('OLD_OWNER_PATH_LEGACY', {'owner_supervisor_launch': 'review/old/owner_terminal_runs/x'}, True),
            ('OWNER_SCENARIO_LEGACY', {'owner_scenario': True}, True)):
        modified = SimpleNamespace(**vars(args))
        for key, value in change.items():
            setattr(modified, key, value)
        count = len(reads)
        require(function('SYNTHETIC_PROJECT', modified, manifest, gate, inherited_clock=inherited) == legacy
            and len(reads) == count, 'targeted_control_legacy_timing_unchanged')
        fixtures.append(label)
    for label in ('BINDING', 'SOURCE_REVIEW', 'START_NS', 'DEADLINE_NS', 'START_UTC', 'PROCESS_INDEX'):
        active[0] = json.loads(canonical(fixture))
        changed = arguments(active[0])
        if label == 'BINDING':
            changed.owner_run_binding = '0' * 64
        elif label == 'SOURCE_REVIEW':
            active[0]['source_review_ref']['sha256'] = '0' * 64
            changed = arguments(active[0])
        elif label == 'PROCESS_INDEX':
            active[0]['process_index'] = 2
            changed = arguments(active[0])
        else:
            key = {'START_NS': 'owner_operation_started_ns', 'DEADLINE_NS': 'owner_operation_deadline_ns',
                'START_UTC': 'owner_operation_started_utc'}[label]
            setattr(changed, key, getattr(changed, key) + 1)
        try:
            function('SYNTHETIC_PROJECT', changed, manifest, gate, inherited_clock=True)
        except ValueError as error:
            require(error.args == ('ordinary_stage05_launch_binding',), 'targeted_control_timing_wrong_refusal')
        else:
            raise ValueError('targeted_control_timing_mutation_accepted')
        fixtures.append('REFUSED_' + label)
    return dict(scope='SYNTHETIC_HELPER_FIXTURES_ONLY', cases=fixtures,
        final_source_review_reference=reference,
        copied_launch_basis=PROCESS + 'launch.json', actual_launch_or_runtime=False)


def replay_controls(namespace, inputs):
    function = namespace['progress_line']
    launch = json.loads(inputs[PROCESS + 'launch.json'])
    receipt = json.loads(inputs[PROCESS + 'receipt.json'])
    require(receipt['child_reaped'] is True, 'targeted_control_recorded_child_not_closed')
    rows = []
    for line in inputs[PROCESS + 'child_stdout.raw'].splitlines():
        start = line.find(b'{"')
        if start < 0:
            continue
        try:
            row = json.loads(line[start:])
        except (ValueError, UnicodeError):
            continue
        if type(row) is dict and row.get('schema') == SCHEMA:
            rows.append(row)
    require(0 < len(rows) == receipt['events'] <= 8192, 'targeted_control_recorded_event_count')
    output = []
    actual_checkpoints = []
    native_spans = set()
    provider = None
    prior_at = launch['operation_started_ns']
    native_ns = 0
    for index, row in enumerate(rows, 1):
        require(row['sequence'] == index and row['child_pid'] == receipt['child_pid']
            and row['run_binding'] == digest(canonical(launch))
            and row['operation_started_ns'] == launch['operation_started_ns']
            and type(row['at_monotonic_ns']) is int and row['at_monotonic_ns'] >= prior_at
            and row['elapsed_wall_ns'] == row['at_monotonic_ns'] - launch['operation_started_ns']
            and type(row['elapsed_process_cpu_ns']) is int and row['elapsed_process_cpu_ns'] >= 0,
            'targeted_control_recorded_event_binding')
        if native_spans and provider is None:
            native_ns += row['at_monotonic_ns'] - prior_at
        prior_at = row['at_monotonic_ns']
        kind = row['kind']
        if kind in ('PHASE_ENTER', 'PHASE_EXIT'):
            enter = kind == 'PHASE_ENTER'
            if row['phase'] == 'PROVIDER':
                require(provider is None if enter else provider == row['span_id'], 'targeted_control_recorded_provider_span')
                provider = row['span_id'] if enter else None
            elif row['native']:
                require((row['span_id'] not in native_spans) if enter else (row['span_id'] in native_spans),
                    'targeted_control_recorded_native_span')
                if enter:
                    native_spans.add(row['span_id'])
                else:
                    native_spans.remove(row['span_id'])
        ref = row.get('readback_ref')
        verified = ref is not None and COPY + ref['path'] in inputs
        if verified:
            raw = inputs[COPY + ref['path']]
            require(digest(raw) == ref['sha256'] and len(raw) == ref['size_bytes'], 'targeted_control_recorded_readback')
        projected = function(row, readback_verified=verified, native_ns=native_ns,
            remaining_ns=launch['operation_deadline_ns'] - row['at_monotonic_ns'])
        if row.get('stage') == 'STAGE05_CHECKPOINT':
            require(verified and projected is not None and row['step'] in projected
                and ref['sha256'] in projected, 'targeted_control_actual_checkpoint_projection')
            actual_checkpoints.append(row['step'])
        if kind in ('PHASE_ENTER', 'PHASE_EXIT'):
            require(projected is not None and 'execution event only' in projected
                and row['phase'] in projected, 'targeted_control_actual_phase_projection')
        if projected is not None:
            output.append(dict(sequence=index, kind=kind, line=projected, readback_verified=verified))
    require(not native_spans and provider is None, 'targeted_control_recorded_spans_closed')
    synthetic = []
    base = dict(kind='STATUS', phase='PERSISTENCE', stage='STAGE05_CHECKPOINT',
        elapsed_wall_ns=1250000000, elapsed_process_cpu_ns=250000000,
        readback_ref=dict(sha256='a' * 64))
    for step in sorted(namespace['STAGE05_CHECKPOINTS']):
        row = dict(base, step=step)
        line = function(row, readback_verified=True, native_ns=500000000, remaining_ns=2000000000)
        require(line == 'Checkpoint read back: ' + step + '; evidence_sha256=' + 'a' * 64
            + '; total wall=1.250 s, CPU=0.250 s, native=0.500 s, remaining=2.000 s.',
            'targeted_control_synthetic_checkpoint_format')
        require(function(row, readback_verified=False, native_ns=0, remaining_ns=0) is None,
            'targeted_control_unverified_checkpoint_displayed')
        synthetic.append(dict(step=step, observed_in_actual=step in actual_checkpoints,
            classification='SYNTHETIC_PROJECTION_ONLY', result='PASS'))
    for step in ('UNREVIEWED_SENTINEL_73b9', {'not': 'a token'}):
        require(function(dict(base, step=step), readback_verified=True, native_ns=0, remaining_ns=0) is None,
            'targeted_control_unknown_checkpoint_displayed')
    require(function(dict(base, kind='HEARTBEAT'), readback_verified=True, native_ns=0, remaining_ns=0) is None,
        'targeted_control_heartbeat_credit')
    for span in sorted(namespace['DISPLAY_SPANS']) + ['UNREVIEWED_SENTINEL_73b9']:
        for kind in ('PHASE_ENTER', 'PHASE_EXIT'):
            line = function(dict(base, kind=kind, phase='NATIVE', span_id=span),
                readback_verified=False, native_ns=0, remaining_ns=-1)
            require('execution event only' in line and 'remaining=0.000 s' in line
                and 'UNREVIEWED_SENTINEL_73b9' not in line
                and ((span in line) == (span in namespace['DISPLAY_SPANS'])),
                'targeted_control_synthetic_phase_projection')
    return dict(scope='RECORDED_V01_DISPLAY_REPLAY_AND_SEPARATE_SYNTHETIC_CONTROLS',
        recorded_rows=len(rows), actual_checkpoint_steps=actual_checkpoints,
        actual_projection=output, synthetic_checkpoint_cases=synthetic,
        synthetic_phase_cases=2 * (len(namespace['DISPLAY_SPANS']) + 1),
        native_clock='Reconstructed from recorded phase intervals; no new execution.',
        semantic_progress_credit=False, native_acceptance=False)


def main():
    require(sys.dont_write_bytecode, 'targeted_control_requires_B')
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    require(args.grant.startswith(PREFIX + '/') and args.grant.endswith('.json'), 'targeted_control_grant_path')
    grant_raw = read(args.grant)
    require(digest(grant_raw) == args.sha256, 'targeted_control_grant_pin')
    grant = json.loads(grant_raw)
    require(grant.get('schema') == 'radik.stage05.targeted_control_grant.v01'
        and grant.get('status') == 'SOURCE_ACCEPTED_FOR_AST_AND_RECORDED_REPLAY'
        and grant.get('reviewer') == '/root/private_remote_controls'
        and grant.get('approved_executor') == '/root' and grant.get('approved_invocation_count') == 1
        and grant.get('automatic_retry') is False and grant.get('production_writes_allowed') is False
        and grant.get('application_native_model_execution_allowed') is False,
        'targeted_control_independent_grant')
    require(grant['runner_ref']['path'] == SELF and verify(grant['runner_ref']) == read(SELF), 'targeted_control_self_pin')
    require(grant['proposal_ref']['path'] == PROPOSAL, 'targeted_control_proposal_path')
    proposal = json.loads(verify(grant['proposal_ref']))
    require({r['path'] for r in proposal['source_refs']} == {OWNER, ENTRY, RUNTIME, SCENARIO, DIAGNOSTICS},
        'targeted_control_source_inventory')
    sources = {ref['path']: verify(ref) for ref in proposal['source_refs']}
    require(1 <= len(proposal['recorded_refs']) <= 16, 'targeted_control_recorded_inventory_bound')
    inputs = {ref['path']: verify(ref) for ref in proposal['recorded_refs']}
    require(all(name.startswith(COPY) for name in inputs), 'targeted_control_recorded_scope')
    final_review = grant['timing_fixture_source_review_ref']
    require(final_review['path'] == PREFIX + '/runtime_source_review.json', 'targeted_control_final_review_scope')
    verify(final_review)
    guards = grant['production_guard_refs']
    require(type(guards) is list and 1 <= len(guards) <= 32, 'targeted_control_guard_bound')
    for reference in guards:
        verify(reference)
    identifier = grant['actual_id']
    require(type(identifier) is str and re.fullmatch('[A-Z0-9_]{1,64}', identifier), 'targeted_control_actual_id')
    parent = PROJECT / PREFIX / 'targeted_controls_actual'
    require(not parent.is_symlink(), 'targeted_control_output_parent')
    parent.mkdir(exist_ok=True, mode=0o700)
    directory = parent / identifier
    directory.mkdir(mode=0o700)
    fence(directory)
    put(directory, 'reservation.json', dict(grant_sha256=args.sha256, one_use=True, automatic_retry=False))
    result = dict(status='STARTED', model_calls=0, native_work_calls=0, application_module_imports=0,
        actual_owner_run=False, semantic_acceptance=False, source_refs=proposal['source_refs'],
        recorded_refs=proposal['recorded_refs'])
    try:
        result['static_controls'] = static_controls(sources)
        progress = extract(sources[OWNER], name=OWNER,
            constants=('STAGE05_CHECKPOINTS', 'DISPLAY_PHASES', 'DISPLAY_SPANS'), functions=('progress_line',))
        result['display_controls'] = replay_controls(progress, inputs)
        timing = extract(sources[ENTRY], name=ENTRY, constants=('PREFIX',),
            functions=('_operation_timing_name',), extra={'json': json, 'hashlib': hashlib})
        result['timing_controls'] = timing_controls(timing['_operation_timing_name'],
            timing['PREFIX'] + '/supervisor_timing.py', final_review,
            json.loads(inputs[PROCESS + 'launch.json']))
        diagnostics = extract(sources[DIAGNOSTICS], name=DIAGNOSTICS,
            constants=('OWNED_ERROR_CODES', 'MEMORY_ERROR_CODES', 'RETURN_ERROR_CODES', 'TYPED_GUARD_NAMES'),
            functions=('_closed', '_attribute', '_code'))
        codes = ('console_continuation_preparation_flag', 'ordinary_stage05_launch_binding',
            'informational_insufficient_validity')
        for code in codes:
            require(diagnostics['_code'](ValueError(code)) == code, 'targeted_control_literal_projection')
        require(diagnostics['_code'](ValueError('ordinary_stage05_launch_binding:UNREVIEWED_SENTINEL_73b9'))
            == 'SANITIZED_OPERATION_FAILURE', 'targeted_control_arbitrary_diagnostic_disclosure')
        result['diagnostic_controls'] = dict(scope='THREE_LITERAL_CODE_PROJECTIONS_ONLY', preserved=list(codes),
            arbitrary_suffix_sanitized=True, whole_diagnostic_module_imported=False)
        require(time.monotonic() - STARTED < 30, 'targeted_control_deadline')
        require(not any(name == 'app' or name.startswith(('app.', 'hedgehog.')) for name in sys.modules),
            'targeted_control_application_import')
        for reference in proposal['source_refs'] + proposal['recorded_refs'] + guards + [final_review]:
            verify(reference)
        result['status'] = 'PASS_AST_HELPERS_RECORDED_PROJECTION_ONLY'
        return 0
    except BaseException as error:
        result['status'] = 'STOPPED_NO_RETRY'
        result['failure'] = dict(type=type(error).__name__, raw_error_recorded=False)
        return 2
    finally:
        result['elapsed_wall_seconds'] = time.monotonic() - STARTED
        put(directory, 'result.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
