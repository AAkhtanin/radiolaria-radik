"""Finite synthetic controls for the new absolute offline execution envelope.

Extract only reviewed stdlib supervisor functions. No application import, real
alarm, process, AUTH, provider or native Work is performed by these controls.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage05_qualified_experience_passage/v02'
SELF = BASE + '/supervisor_completion_controls.py'
RUNNER = BASE + '/rehearsal_runner.py'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class Clock:
    ns = 1000000000

    def monotonic_ns(self):
        return self.ns

    def monotonic(self):
        return self.ns / 1000000000


class Signals:
    SIGALRM = 14
    ITIMER_REAL = 0

    def __init__(self):
        self.calls = []
        self.handler = None

    def signal(self, kind, callback):
        require(kind == self.SIGALRM, 'control_signal_kind')
        self.handler = callback

    def setitimer(self, kind, seconds):
        require(kind == self.ITIMER_REAL, 'control_timer_kind')
        self.calls.append(seconds)


class OwnedPath:
    """No filesystem access: synthetic main paths have only these operations."""
    def __init__(self, name):
        self.name = name

    def __truediv__(self, name):
        return OwnedPath(self.name + '/' + str(name))

    def __str__(self):
        return self.name

    def mkdir(self, **_kwargs):
        return None


def extracted(raw):
    names = {'cancel_work_alarm', 'enter_final_window', 'work_alarm',
             'final_alarm', 'check_deadline', 'main'}
    tree = ast.parse(raw, filename=RUNNER)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name in names]
    require({node.name for node in nodes} == names, 'control_function_closure')
    return compile(ast.Module(body=nodes, type_ignores=[]), RUNNER, 'exec')


def namespace(code):
    clock, signals = Clock(), Signals()
    ns = dict(time=clock, signal=signals, require=require, json=json,
              canonical=canonical, sha=sha, STARTED_NS=1000000000, STARTED=1.0,
              STARTED_UTC=1, WORK_SECONDS=865, CLEANUP_SECONDS=30,
              FINAL_READBACK_SECONDS=5, MAX_SECONDS=900,
              WORK_DEADLINE_NS=866000000000, HARD_DEADLINE_NS=901000000000,
              ACTIVE_DEADLINE_NS=866000000000, REAL=OwnedPath('/owned'),
              PREFIX=BASE, SELF=RUNNER)
    exec(code, ns)
    return ns, clock, signals


def run_controls(raw):
    code = extracted(raw)
    results = []
    ns, clock, signals = namespace(code)
    clock.ns = 865000000000
    ns['enter_final_window']()
    require(signals.calls[-1] == 36.0, 'control_first_absolute_remaining')
    clock.ns = 875000000000
    ns['enter_final_window']()
    require(signals.calls[-1] == 26.0 and ns['ACTIVE_DEADLINE_NS'] == 901000000000,
            'control_final_window_not_renewed')
    results.append('REENTER_FINAL_WINDOW_KEEPS_ABSOLUTE_DEADLINE')
    clock.ns = 866000000000
    try:
        ns['work_alarm'](14, None)
    except ValueError as error:
        require(error.args == ('exam_absolute_work_cutoff',), 'control_work_cutoff_code')
    else:
        raise ValueError('control_work_cutoff_missing')
    require(signals.handler is ns['final_alarm'] and signals.calls[-1] == 35.0,
            'control_cleanup_keeps_hard_alarm')
    results.append('WORK_CUTOFF_ARMS_EXISTING_CLEANUP_AND_READBACK_BOUNDARY')
    clock.ns = 901000000000
    try:
        ns['check_deadline']()
    except ValueError as error:
        require(error.args == ('exam_absolute_deadline',), 'control_hard_deadline_code')
    else:
        raise ValueError('control_hard_deadline_missing')
    results.append('HARD_BOUNDARY_REFUSES_FURTHER_FILE_WORK')

    for case in ('success', 'final_guard_failure', 'final_write_failure',
                 'post_readback_deadline', 'primary_and_guard_failure'):
        ns, clock, signals = namespace(code)
        outputs, writes, guard_calls = [], [], []
        grant = dict(reviewer='/root/private_remote_controls', approved_executor='/root',
                     approved_invocation_count=1, network='DENIED', production_writes_allowed=False,
                     real_AUTH_provider_native_E_SAVE_allowed=False,
                     status='SOURCE_ACCEPTED_FOR_ISOLATED_STAGE05_ORDINARY_WIRING',
                     runner_ref={'path': RUNNER}, interpreter_ref=dict(path='/owned/.venv-plan/bin/python',
                     sha256=sha(b'interpreter')), cases=[dict(name='ordinary')], actual_id='SYNTHETIC',
                     max_seconds=900, work_seconds=865, cleanup_seconds=30, final_readback_seconds=5)
        grant_raw = canonical(grant)
        args = SimpleNamespace(grant='grant.json', sha256=sha(grant_raw))

        class Parser:
            def add_argument(self, *_args, **_kwargs):
                return None

            def parse_args(self):
                return args

        def read(_root, name):
            return grant_raw if name == 'grant.json' else b'interpreter' if name == '.venv-plan/bin/python' else b'runner'

        def guard(_grant):
            guard_calls.append(True)
            if (case == 'final_guard_failure' and len(guard_calls) == 3
                    or case == 'primary_and_guard_failure' and len(guard_calls) == 2):
                raise ValueError('control_secondary_guard_failure')

        def case_run(*_args):
            if case == 'primary_and_guard_failure':
                raise ValueError('control_original_primary')
            return dict(status='SYNTHETIC_SUCCESS')

        def put(_root, name, value):
            writes.append(name)
            if name.endswith('/result.json'):
                if case == 'final_write_failure':
                    raise ValueError('control_result_write_failure')
                if case == 'post_readback_deadline':
                    clock.ns = ns['HARD_DEADLINE_NS'] + 1
            return dict(path=name, sha256=sha(value), size_bytes=len(value))

        ns.update(argparse=SimpleNamespace(ArgumentParser=Parser), read=read,
                  verify=lambda *_args: b'runner', guard=guard, put=put,
                  install_parent_fence=lambda _grant: None,
                  copy_case=lambda *_args: OwnedPath('/owned/copy'), case_run=case_run,
                  safe_error=lambda error: dict(error_class=type(error).__name__, code=error.args[0]),
                  print=lambda value, **_kwargs: outputs.append(json.loads(value)))
        exit_code = ns['main']()
        require(len(outputs) == 1, 'control_single_final_result')
        result = outputs[0]
        require(exit_code == (0 if case == 'success' else 2), 'control_truthful_final_exit')
        require(result['status'] == ('PASS_SOURCE_ONLY_STAGE05_ORDINARY_WIRING'
                    if case == 'success' else 'STOPPED_NO_RETRY'), 'control_truthful_final_status')
        require(signals.calls[-1] == 0, 'control_alarm_closed')
        if case == 'primary_and_guard_failure':
            require(result['failure']['code'] == 'control_original_primary'
                    and result['guard_failure']['code'] == 'control_secondary_guard_failure',
                    'control_primary_preserved')
        results.append(dict(case=case, exit_code=exit_code, status=result['status'],
                            primary=result.get('failure'), result_write_attempts=sum(
                                name.endswith('/result.json') for name in writes)))
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant-sha256', required=True)
    args = parser.parse_args()
    grant_path = ROOT / BASE / 'supervisor_completion_control_grant.json'
    grant_raw = grant_path.read_bytes()
    require(sha(grant_raw) == args.grant_sha256, 'control_grant_identity')
    grant = json.loads(grant_raw)
    require(grant['reviewer'] == '/root/private_remote_controls'
            and grant['status'] == 'ACCEPTED_ONE_SYNTHETIC_SUPERVISOR_CONTROL'
            and grant['approved_invocation_count'] == 1, 'control_independent_grant')
    verified_sources = {}
    for ref in grant['source_refs']:
        raw = (ROOT / ref['path']).read_bytes()
        require(len(raw) == ref['size_bytes'] and sha(raw) == ref['sha256'], 'control_source_pin')
        verified_sources[ref['path']] = raw
    require({row['path'] for row in grant['source_refs']} == {SELF, RUNNER}, 'control_exact_source_closure')
    output = ROOT / BASE / 'supervisor_completion_controls_actual' / 'CONTROLS_V01'
    output.mkdir(parents=True, exist_ok=False)
    (output / 'reservation.json').write_bytes(canonical(dict(grant_sha256=args.grant_sha256, retry=False)))
    result = dict(status='PASS_SYNTHETIC_CONTROL_ONLY', cases=run_controls(verified_sources[RUNNER]),
                  application_imports=0, native_calls=0, real_processes=0, real_alarms=0,
                  AUTH_calls=0, provider_calls=0, owner_actual=False)
    (output / 'result.json').write_bytes(canonical(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
