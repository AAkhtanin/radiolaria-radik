"""Trusted pre-import pin gate; no candidate imports in status mode."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

PROJECT = Path(__file__).resolve().parents[1]
APP_FILES = ('app/__init__.py', 'app/contracts.py', 'app/intake.py', 'app/budget.py',
             'app/memory.py', 'app/native_authority.py', 'app/native_document.py',
             'app/evidence.py', 'app/codex_transport.py', 'app/controller.py', 'app/runtime.py',
             'app/save_quota.py', 'app/semantic_membrane.py')


def pins_match(review, required):
    pins = review.get('pins', {})
    for name in required:
        path = PROJECT / name
        if Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('preimport_dependency_path_invalid:' + name)
        if path.is_symlink() or not path.is_file() or pins.get(name) != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError('preimport_pin_mismatch:' + name)


def load_review(name, *, status, scope, required):
    path = PROJECT / 'review' / name
    if path.is_symlink() or not path.is_file():
        raise ValueError('required_independent_review_missing:' + name)
    review = json.loads(path.read_bytes())
    if review.get('status') != status or review.get('scope') != scope or not review.get('reviewer'):
        raise ValueError('required_independent_review_not_accepted:' + name)
    pins_match(review, required)
    pins_match(review, tuple(review.get('pins', {})))
    return review


def status():
    report = PROJECT / 'review/canonical_semantic_passage/status.json'
    if not report.is_file(): report = PROJECT / 'review/before_owner_run_fix_passage/status.json'
    if not report.is_file(): report = PROJECT / 'review/direct_plan_passage/status.json'
    if not report.is_file(): report = PROJECT / 'review/fix_transport_passage/status.json'
    if not report.is_file(): report = PROJECT / 'review/after_login_live_passage/status.json'
    if not report.is_file(): report = PROJECT / 'review/login_local_deny_passage/status.json'
    if not report.is_file(): report = PROJECT / 'review/bootstrap_live_passage/status.json'
    if not report.is_file(): report = PROJECT / 'review/current_passage/status.json'
    value = json.loads(report.read_bytes()) if report.is_file() else {
        'status': 'CANDIDATE_UNDER_IMPLEMENTATION', 'runtime': 'NOT_ADMITTED',
        'primary_gap': 'Own initialize/catalog and effective model boundary are not confirmed.'}
    ledger_path = PROJECT / 'state/model_turns.json'
    ledger = json.loads(ledger_path.read_bytes()) if ledger_path.is_file() else {'attempts': []}
    return dict(value, shared_counted_attempts=len(ledger['attempts']), shared_attempt_ceiling=16)


def preimport_phase(phase, *, save_target=None, interactive=False):
    """Source admission authorizes only its phase, never general runtime access."""
    if phase == 'demo':
        raise ValueError('general_runtime_not_authorized_by_bounded_handoff')
    if phase == 'live_exam':
        raise ValueError('direct_plan_requires_reviewed_owner_start_entry')
    elif phase == 'exam':
        load_review('current_passage/source_review.json', status='ACCEPTED_FOR_RESEARCH',
            scope='APPLICATION_ISOLATED_RESEARCH_ONLY', required=APP_FILES +
                ('review/exam_document.py', 'config/launch.py', 'config/preflight.py'))
    else:
        raise ValueError('execution_phase_not_supported')


def _early_failure(args,error):
    import time
    import re
    if args is not None and getattr(args, 'stage07_pure_capability', False):
        code = error.args[0] if isinstance(error, ValueError) and error.args else ''
        if type(code) is not str or not re.fullmatch('[A-Za-z0-9_:./-]{1,160}',code):
            code = 'stage07_native_launch_failure'
        print(json.dumps(dict(kind='ENTRY_FAILURE', role=args.stage07_role, session=args.stage07_session,
            failure=dict(code=code,error_class=type(error).__name__)),sort_keys=True),flush=True)
        return 2
    code=getattr(error,'code',None)
    if type(code)is not str:code=error.args[0]if error.args and type(error.args[0])is str else'ordinary_bootstrap_failure'
    if not re.fullmatch('[a-z][a-z0-9_]{1,159}',code):code='ordinary_bootstrap_failure'
    failure=dict(phase='AUTH'if type(error).__name__=='PlanAuthError'else'ORDINARY_BOOTSTRAP',
        error_class=type(error).__name__,code=code)
    print('PRIMARY_FAILURE phase='+failure['phase']+' code='+code+' error_class='+failure['error_class'],flush=True)
    started=getattr(args,'owner_operation_started_ns',None)if args is not None else None
    binding=getattr(args,'owner_run_binding',None)if args is not None else None
    if type(started)is int and re.fullmatch('[0-9a-f]{64}',binding or''):
        for sequence,kind in ((1,'PRIMARY_FAILURE'),(2,'FINAL')):
            observed_ns=time.monotonic_ns()
            row=dict(schema='radik.p28.owner_event.v01',child_pid=os.getpid(),run_binding=binding,
                operation_started_ns=started,sequence=sequence,kind=kind,phase='FINALIZATION',
                at_monotonic_ns=observed_ns,elapsed_wall_ns=max(0,observed_ns-started),
                elapsed_process_cpu_ns=time.process_time_ns(),elapsed_main_thread_cpu_ns=time.thread_time_ns(),failure=failure)
            if kind=='FINAL':row['success']=False
            print(json.dumps(row,sort_keys=True,separators=(',',':')),flush=True)
    return 2


def _stage07_launch(args):
    """Pin the ordinary child entry before its explicit native-only exec."""
    if not args.console or any((args.status, args.exam, args.demo, args.live_exam,
            args.preflight, args.save, args.interactive, args.owner_scenario,
            args.rehearsal_seal_sha256)):
        raise ValueError('stage07_launch_exclusive_mode')
    if any(getattr(args, key) is None for key in ('stage07_launch', 'stage07_role',
            'stage07_session', 'owner_lock_fd')):
        raise ValueError('stage07_launch_arguments')
    environment = PROJECT.parents[3]
    prefix = environment/'review/stage07_pure_capability_passage/v01'
    path = Path(args.stage07_launch)
    if not path.is_absolute() or path.is_symlink() or not any(
            path.is_relative_to(prefix/name) for name in ('owner_terminal_runs','offline_attempts')):
        raise ValueError('stage07_launch_path')
    launch = json.loads(path.read_bytes())
    ref = launch['code_manifest_ref']
    manifest_path = Path(ref['path'])
    if manifest_path.parent != prefix or not re.fullmatch(
            r'source_manifest(?:_(?:PROBE|OWNER)_[0-9]{2})?\.json', manifest_path.name) or manifest_path.is_symlink():
        raise ValueError('stage07_launch_manifest_path')
    raw = manifest_path.read_bytes()
    if len(raw) != ref['size_bytes'] or hashlib.sha256(raw).hexdigest() != ref['sha256']:
        raise ValueError('stage07_launch_manifest_changed')
    manifest = json.loads(raw)
    if manifest['environment_root'] != str(environment) or manifest['candidate_root'] != str(PROJECT):
        raise ValueError('stage07_launch_root_identity')
    pins = {row['path']: row for row in manifest['files']}
    for relative in ('config/launch.py', 'config/__init__.py', 'app/__init__.py',
            'config/stage07_bootstrap.py', 'app/ordinary_entry.py',
            'review/transport/radik_owner_start.py'):
        target = PROJECT/relative
        for ancestor in (target, *target.parents):
            if ancestor.is_symlink(): raise ValueError('stage07_launch_source_symlink')
            if ancestor == environment: break
        raw = target.read_bytes(); expected = pins[str(target)]
        if len(raw) != expected['size_bytes'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
            raise ValueError('stage07_launch_source_changed')
    forwarded = ['--console', '--stage07-pure-capability']
    for key in ('stage07_launch','stage07_role',
            'stage07_session','owner_lock_fd'):
        forwarded.extend(('--'+key.replace('_','-'), str(getattr(args,key))))
    os.execv(sys.executable, [sys.executable, '-I', '-S', '-B',
        str(PROJECT/'review/transport/radik_owner_start.py'), *forwarded])


def main():
    parser = argparse.ArgumentParser(description='Консоль Radik с проверкой допуска до импорта приложения.')
    parser.add_argument('--console', action='store_true', help='Open the admitted ordinary informational console.')
    parser.add_argument('--stage07-pure-capability', action='store_true')
    parser.add_argument('--stage07-launch')
    parser.add_argument('--stage07-role', choices=('application',))
    parser.add_argument('--stage07-session', type=int, choices=(1,))
    parser.add_argument('--owner-scenario',action='store_true')
    parser.add_argument('--owner-operation-started-ns',type=int)
    parser.add_argument('--owner-operation-deadline-ns',type=int)
    parser.add_argument('--owner-operation-started-utc',type=int)
    parser.add_argument('--owner-supervisor-launch')
    parser.add_argument('--owner-run-binding')
    parser.add_argument('--owner-lock-fd',type=int)
    parser.add_argument('--rehearsal-seal-sha256')
    parser.add_argument('--rehearsal-action',choices=('entry','ordinary_console','ordinary_controls','restart_read','grant_stage','grant_review'),default='entry')
    parser.add_argument('--status', action='store_true', help='Показать текущее состояние и модельный счётчик.')
    parser.add_argument('--exam', action='store_true', help='Запустить принятый изолированный исследовательский экзамен без модели.')
    parser.add_argument('--demo', action='store_true', help='Запустить допущенный первый живой срез.')
    parser.add_argument('--live-exam', action='store_true', help='Запустить только допущенный ограниченный live-экзамен.')
    parser.add_argument('--save', metavar='NAME.txt', help='Явно сохранить принятый результат в output/.')
    parser.add_argument('--interactive', action='store_true', help='После сравнения принимать команды обновления и сохранения.')
    parser.add_argument('--preflight', action='store_true', help='Проверить неизменность public reference.')
    args = parser.parse_args()
    global _LAUNCH_ARGS
    _LAUNCH_ARGS=args
    if args.stage07_pure_capability:
        return _stage07_launch(args)
    if any(getattr(args,key) is not None for key in ('stage07_launch','stage07_role',
            'stage07_session')):
        raise ValueError('stage07_launch_flags_require_mode')
    if sum((args.exam,args.demo,args.live_exam,args.preflight,args.console)) > 1:
        parser.error('Choose exactly one execution phase.')
    if args.live_exam and (args.save or args.interactive):
        parser.error('The bounded live exam fixes its scenario and single SAVE target.')
    if (args.save or args.interactive) and not args.demo:
        parser.error('--save and --interactive require --demo')
    if not sys.dont_write_bytecode:
        parser.error('launcher requires Python -B')
    if args.preflight:
        import preflight
        result = preflight.inspect()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result['reference_bytes_unchanged'] else 2
    if args.console:
        require_profile=PROJECT/'state/application_profile.json'
        if not require_profile.is_file():raise ValueError('ordinary_console_current_profile_activation_required')
        activation=json.loads(require_profile.read_bytes());reference=activation['profile_ref']
        manifest=json.loads((PROJECT/reference['path']).read_bytes())
        if hashlib.sha256((PROJECT/reference['path']).read_bytes()).hexdigest()!=reference['sha256']:
            raise ValueError('ordinary_launch_manifest_changed')
        gate_path=PROJECT/'config/application_profile_gate.py'
        if hashlib.sha256(gate_path.read_bytes()).hexdigest()!=manifest['pins']['config/application_profile_gate.py']:
            raise ValueError('ordinary_launch_gate_changed')
        if (PROJECT/'config/__init__.py').exists():raise ValueError('ordinary_launch_namespace_initializer')
        sys.path.insert(0,str(PROJECT))
        from config.application_profile_gate import select,rehearsal_context,environment_root
        context=rehearsal_context(PROJECT,args.rehearsal_seal_sha256)
        if args.rehearsal_action!='entry'and context is None:raise ValueError('ordinary_rehearsal_action_refused')
        selected=select(PROJECT)
        if selected is None:raise ValueError('ordinary_console_current_profile_activation_required')
        python=environment_root(PROJECT)/'.venv-plan/bin/python'
        forwarded=[]
        if args.owner_scenario:forwarded.append('--owner-scenario')
        for name in ('owner_operation_started_ns','owner_operation_deadline_ns','owner_operation_started_utc',
                'owner_supervisor_launch','owner_run_binding','owner_lock_fd','rehearsal_seal_sha256'):
            value=getattr(args,name)
            if value is not None:forwarded.extend(('--'+name.replace('_','-'),str(value)))
        if context is not None:forwarded.extend(('--rehearsal-action',args.rehearsal_action))
        os.execv(str(python),[str(python),'-I','-S','-B',str(PROJECT/'review/transport/radik_owner_start.py'),'--console',*forwarded])
    if not args.exam and not args.demo and not args.live_exam:
        print(json.dumps(status(), ensure_ascii=False, indent=2))
        return 0
    try:
        preimport_phase('exam' if args.exam else 'live_exam' if args.live_exam else 'demo',
            save_target=args.save, interactive=args.interactive)
        sys.path.insert(0, str(PROJECT / 'source/reference'))
        sys.path.insert(0, str(PROJECT))
        os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
        if args.exam:
            from review.exam_document import main as exam_main
            return exam_main()
        if args.live_exam:
            from app.runtime import bounded_live_exam
            return bounded_live_exam()
        from app.runtime import main as runtime_main
        return runtime_main(save_target=args.save, interactive=args.interactive)
    except (ValueError, OSError, KeyError) as error:
        print(json.dumps({'status': 'FAIL_CLOSED_LAUNCH', 'reason': str(error), 'runtime': 'NOT_ADMITTED'}, ensure_ascii=False))
        return 2


if __name__ == '__main__':
    try:code=main()
    except (ValueError,OSError,KeyError)as error:code=_early_failure(globals().get('_LAUNCH_ARGS'),error)
    raise SystemExit(code)
