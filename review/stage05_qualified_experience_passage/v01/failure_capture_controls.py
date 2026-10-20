"""One-use pinned AST helper controls; no application, native Work or model execution."""
import argparse
import ast
import builtins
from contextlib import contextmanager
import copy
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
SELF = PREFIX + '/failure_capture_controls.py'
PROPOSAL = PREFIX + '/failure_capture_controls_proposal.json'
OWNER = PREFIX + '/owner_terminal.py'
SCENARIO = PREFIX + '/after/app/qualified_experience_scenario.py'
DIAGNOSTICS = PREFIX + '/after/app/stage04_diagnostics.py'
STRATEGY = PREFIX + '/after/app/qualified_strategy.py'
WORK = 'review/g2e_successor_passage/proposals/g2e_no_effects_v28_ordinary_entry_owner_scenario/native_runtime/hedgehog/kernel/work_composition_v01.py'
HOST = 'review/g2e_successor_passage/proposals/g2e_no_effects_v28_ordinary_entry_owner_scenario/native_runtime/hedgehog/work_execution_host_v01.py'
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


def extract(raw, name, constants=(), functions=(), extra=None, decorators=()):
    tree = ast.parse(raw, filename=name)
    selected = []
    found = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in constants:
                require(not any(isinstance(x, (ast.Attribute, ast.Subscript, ast.Lambda)) for x in ast.walk(node.value)), 'failure_control_constant_scope')
                selected.append(node); found.add(node.targets[0].id)
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            require(all(isinstance(d, ast.Name) and d.id in decorators for d in node.decorator_list)
                and not any(isinstance(x, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)) for x in ast.walk(node)), 'failure_control_function_scope')
            selected.append(node); found.add(node.name)
    require(found == set(constants) | set(functions), 'failure_control_extract_inventory')
    namespace = dict(__builtins__=vars(builtins), __name__='radik_reviewed_ast_helpers')
    namespace.update(extra or {})
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), name+':reviewed_ast_extract', 'exec'), namespace)
    return namespace


def expect_refusal(call, code):
    try: call()
    except ValueError as error:
        require(error.args == (code,), 'failure_control_wrong_refusal')
    else: raise ValueError('failure_control_refusal_missing')


def diagnostics_namespace(raw):
    # The unchanged historical stream decoder is outside this control's scope.
    # Its no-stream dependency accepts only None; every synthetic error uses it.
    def no_stream_metadata(value):
        require(value is None, 'failure_control_nonempty_stream_out_of_scope')
        return None
    return extract(raw, DIAGNOSTICS, constants=('OWNED_ERROR_CODES', 'MEMORY_ERROR_CODES',
        'RETURN_ERROR_CODES', 'MEMORY_WRITEBACK_CODES', 'TYPED_GUARD_NAMES', 'PHASES', 'STEPS', 'PERSISTENCE_STATES',
        'SAFE_ERROR_TYPES', 'MAX_SECONDARY_FAILURES', '_STATE_KEY', '_CORE_FIELDS'),
        functions=('_closed', '_attribute', '_name', '_code', '_secondary_valid', '_state',
            'project_error', 'observe_failure', 'record_secondary'),
        extra={'project_stream_event': no_stream_metadata})


def literal_controls(sources, diagnostics):
    literals = set()
    for path in (WORK, HOST):
        for node in ast.walk(ast.parse(sources[path], filename=path)):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name): continue
            index = 1 if node.func.id in ('require', '_require', '_native_require') else 0 if node.func.id == 'ValueError' else None
            if index is not None and len(node.args) > index and isinstance(node.args[index], ast.Constant):
                value = node.args[index].value
                if type(value) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_:./-]{1,160}', value): literals.add(value)
    require(len(literals) == 237, 'failure_control_native_literal_count')
    for code in sorted(literals | {'stage05_failure_source_identity', 'qualified_native_revision_not_active'}):
        require(diagnostics['_code'](ValueError(code)) == code, 'failure_control_native_literal_projection')
    for value in ('work_task_stale_snapshot:UNREVIEWED_SENTINEL_93b1', 'host_task_time_not_current suffix', 'UNREVIEWED_SENTINEL_93b1'):
        require(diagnostics['_code'](ValueError(value)) == 'SANITIZED_OPERATION_FAILURE', 'failure_control_unknown_text_disclosure')
    expect_refusal(lambda: diagnostics['project_stream_event']({'synthetic':'nonempty'}), 'failure_control_nonempty_stream_out_of_scope')
    return dict(exact_native_literals=len(literals), own_literals=2, unknown_messages_sanitized=3,
        native_modules_imported=False, dynamic_wrapper_parsing=False, stream_record_validation='OUT_OF_SCOPE_NONEMPTY_REFUSED')


def synthetic_trace(depth, filename, error):
    # Deliberately synthetic code coordinates test the classifier, not loaded-code admission.
    code = 'def synthetic_frame(depth, error):\n    if depth:\n        return synthetic_frame(depth-1, error)\n    raise error\n'
    namespace = {}
    exec(compile(code, str(filename), 'exec'), namespace)
    try: namespace['synthetic_frame'](depth, error)
    except BaseException as caught: return caught, code
    raise ValueError('failure_control_synthetic_exception_missing')


def frame_controls(sources):
    constants = ('STAGE05_SCENARIO_STAGES', 'STAGE05_NATIVE_STAGES', 'STAGE05_FRAME_FUNCTIONS')
    child = extract(sources[SCENARIO], SCENARIO, constants, ('diagnostic_source_pins', '_failure_context'),
        dict(Path=Path, re=re, require=require))
    displayed = []
    parent = extract(sources[OWNER], OWNER, constants, ('diagnostic_source_pins', 'stage05_failure_context', 'retain_failure'),
        dict(Path=Path, re=re, require=require, show=displayed.append))
    relative = '_synthetic_owned_frame.py'
    error, code = synthetic_trace(40, PROJECT/relative, ValueError('work_task_stale_snapshot'))
    pin = digest(code.encode())
    manifest = dict(pins={relative:pin}, native_files={})
    error._radik_stage05_native_stage = 'G4_BOOTSTRAP_ADVANCE'
    detail = child['_failure_context'](PROJECT, manifest, error, 'COLD_DECISION')
    require(len(detail['source_frames']) == 32 and detail['omitted_frames'] == 9
        and detail['unadmitted_frames'] >= 1 and detail['traceback_truncated'] is False
        and detail['native_stage'] == 'G4_BOOTSTRAP_ADVANCE', 'failure_control_frame_bound')
    deep, _ = synthetic_trace(140, PROJECT/relative, ValueError('work_task_stale_snapshot'))
    deep_detail = child['_failure_context'](PROJECT, manifest, deep, 'COLD_DECISION')
    require(deep_detail['traceback_truncated'] is True and len(deep_detail['source_frames']) == 32, 'failure_control_trace_depth')
    foreign, _ = synthetic_trace(0, '/UNREVIEWED_SENTINEL_93b1/private_frame.py', ValueError('x'))
    foreign._radik_stage05_native_stage = 'UNREVIEWED_SENTINEL_93b1'
    hidden = child['_failure_context'](PROJECT, manifest, foreign, 'COLD_DECISION')
    require(hidden['source_frames'] == [] and hidden['native_stage'] == 'UNKNOWN'
        and 'UNREVIEWED_SENTINEL_93b1' not in json.dumps(hidden), 'failure_control_private_frame_disclosure')
    require(parent['diagnostic_source_pins'](manifest) == child['diagnostic_source_pins'](manifest) == {relative:pin}, 'failure_control_source_map_alignment')
    conflicting = dict(pins={relative:pin}, native_files={'item':dict(path=relative, sha256='0'*64)})
    expect_refusal(lambda: child['diagnostic_source_pins'](conflicting), 'stage05_failure_source_identity')
    core = dict(phase='STAGE05_EXPERIENCE', error_class='ValueError', code='work_task_stale_snapshot')
    row = dict(kind='PRIMARY_FAILURE', stage='STAGE05_FAILURE', sequence=1, failure=core, failure_context=detail)
    receipt = dict(primary_failure=None, secondary_failures=[])
    parent['retain_failure'](receipt, core, SimpleNamespace(failure=lambda value:dict(value)))
    accepted = parent['stage05_failure_context'](row, {relative:pin})
    require(accepted['reference_readback_verified'] is False and receipt['primary_failure'] == core, 'failure_control_pre_readback_primary')
    for key, value in (('native_stage','UNREVIEWED_SENTINEL_93b1'), ('scenario_stage','UNREVIEWED_SENTINEL_93b1')):
        bad = copy.deepcopy(row);bad['failure_context'][key] = value
        expect_refusal(lambda: parent['stage05_failure_context'](bad,{relative:pin}), 'terminal_stage05_failure_context')
    for key,value in (('sha256','0'*64), ('path','private/UNREVIEWED_SENTINEL_93b1'), ('line',0), ('function','UNREVIEWED_SENTINEL_93b1 invalid')):
        bad=copy.deepcopy(row);bad['failure_context']['source_frames'][0][key]=value
        expect_refusal(lambda: parent['stage05_failure_context'](bad,{relative:pin}), 'terminal_stage05_failure_frame')
    require('UNREVIEWED_SENTINEL_93b1' not in '\n'.join(displayed), 'failure_control_terminal_disclosure')
    # Extract just the reviewed readback-binding branch, excluding any supervisor startup or I/O.
    tree=ast.parse(sources[OWNER]);supervise=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='supervise')
    branch=next(n for n in ast.walk(supervise) if isinstance(n,ast.If) and ast.unparse(n.test)=='failure_context is not None'
        and any(isinstance(x,ast.Constant) and x.value=='terminal_stage05_failure_readback_binding' for x in ast.walk(n)))
    fn=ast.parse('def check_binding(failure_context, witness, row, ref):\n    pass\n').body[0];fn.body=copy.deepcopy(branch.body)
    namespace=dict(require=require)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),OWNER+':readback_branch','exec'),namespace)
    ref=dict(path='synthetic/result.json',sha256='0'*64,size_bytes=1)
    namespace['check_binding'](accepted,dict(body=dict(failure_context=detail)),row,ref)
    require(accepted['reference_readback_verified'] is True and accepted['readback_ref']==ref,'failure_control_readback_binding')
    expect_refusal(lambda:namespace['check_binding'](accepted,dict(body=dict(failure_context={})),row,ref),'terminal_stage05_failure_readback_binding')
    parent['retain_failure'](receipt,dict(phase='OWNER_TERMINAL',error_class='ValueError',code='terminal_stage05_failure_readback_binding'),SimpleNamespace(failure=lambda value:dict(value)))
    require(receipt['primary_failure']==core and len(receipt['secondary_failures'])==1,'failure_control_readback_replaced_primary')
    return dict(scope='SYNTHETIC_AST_PROJECTION_AND_READBACK_BINDING_ONLY', admitted_frames=32,
        trace_depth_cap=128, mutation_refusals=7, complete_source_file_readback_exercised=False,
        readback_binding_positive=True, readback_binding_negative=True, first_cause_preserved=True,
        arbitrary_sentinel_disclosed=False, source_coordinates_are_synthetic=True)


def annotation_controls(raw):
    namespace=extract(raw,STRATEGY,('NATIVE_STAGES',),('_native_stage',),dict(contextmanager=contextmanager),decorators=('contextmanager',))
    scope=namespace['_native_stage']
    class GetterFailure(ValueError):
        def __getattribute__(self,key):
            if key=='_radik_stage05_native_stage':raise RuntimeError('synthetic_annotation_get')
            return super().__getattribute__(key)
    class SetterFailure(ValueError):
        def __setattr__(self,key,value):
            if key=='_radik_stage05_native_stage':raise RuntimeError('synthetic_annotation_set')
            return super().__setattr__(key,value)
    class HostileEquality:
        def __eq__(self,other):raise RuntimeError('synthetic_equality')
    for original in (ValueError('x'),GetterFailure('x'),SetterFailure('x')):
        try:
            with scope('G4_BOOTSTRAP_ADVANCE'):raise original
        except BaseException as error:require(error is original,'failure_control_annotation_replaced_primary')
        else:raise ValueError('failure_control_annotation_swallowed_primary')
    original=ValueError('x');original._radik_stage05_native_stage=HostileEquality()
    try:
        with scope('G4_HISTORY'):
            with scope('G4_BOOTSTRAP_ARTIFACT'):raise original
    except BaseException as error:
        require(error is original and error._radik_stage05_native_stage=='G4_BOOTSTRAP_ARTIFACT','failure_control_first_stage')
    else:raise ValueError('failure_control_annotation_swallowed_primary')
    original=ValueError('x')
    try:
        with scope('UNREVIEWED_SENTINEL_93b1'):raise original
    except BaseException as error:require(error is original and not hasattr(error,'_radik_stage05_native_stage'),'failure_control_unknown_stage')
    else:raise ValueError('failure_control_annotation_swallowed_primary')
    return dict(synthetic_cases=5, primary_identity_preserved=True, first_closed_stage_preserved=True, hostile_annotation_ignored=True)


def precedence_controls(sources,diagnostics):
    tree=ast.parse(sources[SCENARIO]);run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run')
    phase=next(n for n in run.body if isinstance(n,ast.FunctionDef)and n.name=='phase')
    maker=ast.parse("def make_phase(report,event_sink):\n    scenario_stage='ORDINARY_TASK'\n    pass\n    return phase\n").body[0]
    maker.body[1]=copy.deepcopy(phase)
    namespace=dict(diagnostics,contextmanager=contextmanager,time=time)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[maker],type_ignores=[])),SCENARIO+':phase_extract','exec'),namespace)
    for mode in ('phase_exit','measurement'):
        original=ValueError('work_task_stale_snapshot')
        class BadReport(dict):
            def setdefault(self,*args):raise RuntimeError('synthetic_measurement')
        def events(value):
            if value['kind']=='PHASE_EXIT':raise RuntimeError('synthetic_phase_exit')
        report=BadReport()if mode=='measurement'else{}
        try:
            with namespace['make_phase'](report,events)('cold_decision'):raise original
        except BaseException as error:
            require(error is original and len(diagnostics['project_error'](error)['secondary_failures'])==1,'failure_control_phase_primary')
        else:raise ValueError('failure_control_phase_swallowed_primary')
    handler=next(n for n in run.body if isinstance(n,ast.Try)).handlers[0]
    shell=ast.parse('def exercise(original, project, manifest, scenario_stage, report, output, event_sink):\n    try:\n        raise original\n    except BaseException as error:\n        pass\n').body[0]
    shell.body[0].handlers[0]=copy.deepcopy(handler)
    baseline=dict(schema='radik.stage05.failure_context.v01',scenario_stage='COLD_DECISION',native_stage='UNKNOWN',
        source_frames=[],omitted_frames=0,unadmitted_frames=0,traceback_truncated=False,raw_error_recorded=False,locals_recorded=False)
    for mode in ('success','context_capture','persist','event_emit'):
        events_seen=[];original=ValueError('host_task_time_not_current')
        def capture(*args):
            if mode=='context_capture':raise RuntimeError('synthetic_context_capture')
            return dict(baseline)
        def persist(*args):
            if mode=='persist':raise RuntimeError('synthetic_persist')
            return dict(path='synthetic/result.json',sha256='0'*64,bytes=1)
        def events(value):
            events_seen.append(value)
            if mode=='event_emit':raise RuntimeError('synthetic_event_emit')
        env=dict(diagnostics,_failure_context=capture,persist=persist)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(shell)],type_ignores=[])),SCENARIO+':except_extract','exec'),env)
        try:env['exercise'](original,PROJECT,{},'COLD_DECISION',{},PROJECT,events)
        except BaseException as error:
            projected=diagnostics['project_error'](error)
            require(error is original and projected['code']=='host_task_time_not_current'
                and projected['step']=='STAGE05_EXPERIENCE' and len(projected['secondary_failures'])==(0 if mode=='success' else 1),'failure_control_catch_primary')
        else:raise ValueError('failure_control_catch_swallowed_primary')
        require(len(events_seen)==1 and events_seen[0]['failure']['code']=='host_task_time_not_current','failure_control_direct_primary_event')
    return dict(synthetic_phase_cases=2, synthetic_failure_catch_cases=4, primary_identity_and_code_preserved=True,
        event_emitted_after_capture_or_persistence_refusal=True, persisted_report_bytes_tested=False)


def static_revision_control(raw):
    tree=ast.parse(raw);run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run')
    revision=next(n for n in ast.walk(run) if isinstance(n,ast.With) and any(isinstance(x,ast.Constant)and x.value=='G4_REVISION'for x in ast.walk(n.items[0])))
    texts=[ast.unparse(n)for n in revision.body]
    require(any('type(revision) is work.WorkContinuationOutcomeV01 and revision.status == \'ACTIVE\''in text for text in texts)
        and texts[-1]=='revised = revision.program','failure_control_revision_outcome_guard')
    captures=[n for n in ast.walk(run)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='dict'
        and any(k.arg=='revision_outcome'and isinstance(k.value,ast.Name)and k.value.id=='revision'for k in n.keywords)]
    require(len(captures)==2 and all(any(k.arg=='program'and isinstance(k.value,ast.Name)and k.value.id=='revised'for k in n.keywords)for n in captures),'failure_control_revision_witness')
    persist=next(n for n in ast.walk(run)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='_persist'
        and n.args and isinstance(n.args[0],ast.Constant)and n.args[0].value=='qualified_allocation_pre_dispatch')
    dispatch=next(n for n in ast.walk(run)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='advance'
        and len(n.args)==1 and isinstance(n.args[0],ast.Name)and n.args[0].id=='revised')
    require(persist.lineno<dispatch.lineno,'failure_control_pre_dispatch_order')
    return dict(scope='AST_ONLY_PUBLIC_RESULT_BINDING', active_type_guard=True, program_selected=True, complete_outcome_retained_twice=True, pre_dispatch_order=True)


def main():
    require(sys.dont_write_bytecode,'failure_control_requires_B')
    parser=argparse.ArgumentParser();parser.add_argument('--grant',required=True);parser.add_argument('--sha256',required=True);args=parser.parse_args()
    require(args.grant.startswith(PREFIX+'/')and args.grant.endswith('.json'),'failure_control_grant_path')
    raw=read(args.grant);require(digest(raw)==args.sha256,'failure_control_grant_pin');grant=json.loads(raw)
    require(grant.get('schema')=='radik.stage05.failure_capture_control_grant.v01'
        and grant.get('status')=='SOURCE_ACCEPTED_FOR_PINNED_AST_CONTROLS'
        and grant.get('reviewer')=='/root/private_remote_controls'and grant.get('approved_executor')=='/root'
        and grant.get('approved_invocation_count')==1 and grant.get('automatic_retry')is False
        and grant.get('production_writes_allowed')is False and grant.get('application_native_model_execution_allowed')is False,
        'failure_control_independent_grant')
    require(grant['runner_ref']['path']==SELF and verify(grant['runner_ref'])==read(SELF),'failure_control_self_pin')
    require(grant['proposal_ref']['path']==PROPOSAL,'failure_control_proposal_path');proposal=json.loads(verify(grant['proposal_ref']))
    require({r['path']for r in proposal['source_refs']}=={OWNER,SCENARIO,DIAGNOSTICS,STRATEGY,WORK,HOST},'failure_control_source_inventory')
    sources={r['path']:verify(r)for r in proposal['source_refs']}
    guards=grant['production_guard_refs'];require(type(guards)is list and 1<=len(guards)<=32,'failure_control_guard_bound')
    for reference in guards:verify(reference)
    identifier=grant['actual_id'];require(type(identifier)is str and re.fullmatch('[A-Z0-9_]{1,64}',identifier),'failure_control_actual_id')
    parent=PROJECT/PREFIX/'failure_capture_controls_actual';require(not parent.is_symlink(),'failure_control_output_parent');parent.mkdir(exist_ok=True,mode=0o700)
    directory=parent/identifier;directory.mkdir(mode=0o700);fence(directory)
    put(directory,'reservation.json',dict(grant_sha256=args.sha256,one_use=True,automatic_retry=False))
    result=dict(status='STARTED',model_calls=0,native_work_calls=0,application_module_imports=0,actual_owner_run=False,
        semantic_acceptance=False,all_runtime_examples_are_synthetic=True,source_refs=proposal['source_refs'])
    try:
        result['active_control']='DIAGNOSTIC_EXTRACTION'
        diagnostics=diagnostics_namespace(sources[DIAGNOSTICS])
        result['active_control']='LITERAL_CONTROLS'
        result['literal_controls']=literal_controls(sources,diagnostics)
        result['active_control']='FRAME_CONTROLS'
        result['frame_controls']=frame_controls(sources)
        result['active_control']='ANNOTATION_CONTROLS'
        result['annotation_controls']=annotation_controls(sources[STRATEGY])
        result['active_control']='PRECEDENCE_CONTROLS'
        result['precedence_controls']=precedence_controls(sources,diagnostics)
        result['active_control']='REVISION_STATIC_CONTROL'
        result['revision_static_control']=static_revision_control(sources[STRATEGY])
        require(time.monotonic()-STARTED<30,'failure_control_deadline')
        require(not any(name=='app'or name.startswith(('app.','hedgehog.'))for name in sys.modules),'failure_control_application_import')
        for reference in proposal['source_refs']+guards:verify(reference)
        result['status']='PASS_SYNTHETIC_AST_HELPERS_ONLY';return 0
    except BaseException as error:
        result['status']='STOPPED_NO_RETRY'
        code=error.args[0] if type(error)is ValueError and len(error.args)==1 else None
        result['failure']=dict(type=type(error).__name__,code=code if type(code)is str and code in proposal['control_failure_codes']else'SANITIZED_CONTROL_FAILURE',raw_error_recorded=False)
        return 2
    finally:
        result['elapsed_wall_seconds']=time.monotonic()-STARTED;put(directory,'result.json',result);print(json.dumps(result,sort_keys=True),flush=True)


if __name__=='__main__':raise SystemExit(main())
