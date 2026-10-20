"""A finite current-controller tail through genuine historical memory descent.

Only an exact historical record/payload pair is copied as inert evidence. The
ordinary public application memory path performs current eligibility, new Root
approval, bounded payload descent, new semantic family/Host/Work and final Root.
No accepted controller or permission is reconstructed. Missing or expired history
stops without a model fallback. This diagnoses the G3/G4 adapter tail and does not
certify the console source path, the original cold run or an owner operation.
"""
import argparse
from dataclasses import replace
import hashlib
import importlib.abc
import importlib.machinery
import json
import os
from pathlib import Path
import signal
import sys
import time

PASSAGE = 'review/stage05_qualified_experience_passage/v01'
OWNED_PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
INPUT = PASSAGE + '/inputs/g4_bootstrap_inert_v01.json'
RUNNER = PASSAGE + '/g4_native_tail_fixture.py'
MEMORY_INPUTS = (
    'work/drsmeaning_v01_9c079e9b8a6fa59c55e9b2d41494b742c9cbfd861784f32d5cc088d58293cf10.json',
    'payloads/75ed1f31f84572cf4a003eb9b76b2636b82dede2de073e1a64e117ef01244fd6.json',
)
MEMORY_PREFIX = PASSAGE + '/inputs/g4_tail_memory_v01/'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


class PinnedFinder(importlib.abc.MetaPathFinder):
    def __init__(self, root, pins, loaded):
        self.root, self.pins, self.loaded = root, pins, loaded

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in ('app', 'hedgehog', 'review', 'config'):
            return None
        search = path if path is not None else [str(self.root / 'source/reference'
                                                   if fullname == 'hedgehog' else self.root)]
        spec = importlib.machinery.PathFinder.find_spec(fullname, search)
        if spec is None:
            raise ImportError('g4_fixture_protected_import_absent')
        if spec.origin is None:
            require(spec.submodule_search_locations and all(Path(p).resolve().is_relative_to(self.root)
                for p in spec.submodule_search_locations), 'g4_fixture_namespace_outside_source')
            return spec
        source = Path(spec.origin).resolve()
        require(source.is_relative_to(self.root) and source.suffix == '.py', 'g4_fixture_import_outside_source')
        relative = str(source.relative_to(self.root))
        require(relative in self.pins, 'g4_fixture_unreviewed_import')
        raw = source.read_bytes()
        require(sha(raw) == self.pins[relative], 'g4_fixture_import_changed')
        loaded = self.loaded

        class Loader(importlib.abc.Loader):
            def create_module(self, _spec):
                return None

            def exec_module(self, module):
                require(source.read_bytes() == raw, 'g4_fixture_import_race')
                module.__file__ = str(source)
                loaded.append(dict(module=fullname, path=relative, sha256=sha(raw)))
                exec(compile(raw, str(source), 'exec'), module.__dict__)

        spec.loader = Loader()
        return spec


def install_audit_fence(root, workspace):
    environment = tuple(Path(value).resolve() for value in (sys.prefix, sys.base_prefix))
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    forbidden_parts = {'.codex', '.ssh', '.aws', '.azure', '.gnupg'}
    forbidden_names = {'auth.json', '.netrc', '.env', 'credentials', 'credentials.json'}

    def path_value(value):
        require(isinstance(value, (str, bytes, os.PathLike)), 'g4_fixture_audit_nonpath')
        path = Path(os.fsdecode(value)).resolve()
        require(not forbidden_parts.intersection(path.parts) and path.name not in forbidden_names,
                'g4_fixture_credential_path')
        return path

    def writable(value):
        require(path_value(value).is_relative_to(workspace), 'g4_fixture_write_outside_workspace')

    def audit(event, args):
        if event.startswith(('socket.', 'subprocess.', 'ctypes.')) or event in (
            'os.system', 'os.posix_spawn', 'os.posix_spawnp', 'os.exec', 'os.fork', 'os.forkpty',
            'pty.spawn', 'os.chdir', 'os.fchdir'):
            raise PermissionError('g4_fixture_external_operation')
        if event == 'open':
            name, mode, flags = args
            if type(name) is int:
                require(name >= 0, 'g4_fixture_invalid_descriptor')
                return
            path = path_value(name)
            writing = bool((flags or 0) & write_flags) or any(c in (mode or '') for c in 'wax+')
            if writing:
                writable(path)
            else:
                require(path.is_relative_to(root) or path.is_relative_to(workspace)
                    or any(path.is_relative_to(prefix) for prefix in environment), 'g4_fixture_read_outside_scope')
        elif event in ('os.rename', 'os.link', 'os.symlink'):
            writable(args[0]); writable(args[1])
        elif event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.chown',
                       'os.truncate', 'os.utime', 'os.setxattr', 'os.removexattr'):
            writable(args[0])

    sys.addaudithook(audit)


def failure(error, stage, root, pins, reason_codes):
    code = (error.args[0] if len(error.args) == 1 and type(error.args[0]) is str
            and error.args[0] in reason_codes else 'UNLISTED_SOURCE_REASON')
    frames, node = [], error.__traceback__
    while node is not None:
        path = Path(node.tb_frame.f_code.co_filename).resolve()
        if path.is_relative_to(root):
            relative = str(path.relative_to(root))
            if relative in pins:
                frames.append(dict(path=relative, sha256=pins[relative], line=node.tb_lineno,
                                   function=node.tb_frame.f_code.co_name))
        node = node.tb_next
    return dict(type=type(error).__name__, code=code, stage=stage, frames=frames[-24:],
                raw_error_recorded=False, locals_recorded=False, original_exception_preserved=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--source-review', required=True)
    parser.add_argument('--source-review-sha256', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--deadline-seconds', type=int, default=200)
    args = parser.parse_args()
    anchor = (OWNED_PROJECT / PASSAGE / 'offline_actual').resolve(strict=True)
    root, workspace = Path(args.source_root).resolve(strict=True), Path(args.workspace).resolve()
    review_path = Path(args.source_review).resolve(strict=True)
    require(root.is_relative_to(anchor) and workspace.is_relative_to(anchor) and root != anchor
        and workspace != anchor and not root.is_relative_to(workspace) and not workspace.is_relative_to(root)
        and review_path.is_relative_to(OWNED_PROJECT / PASSAGE), 'g4_fixture_owned_anchor')
    require(not workspace.exists() and not workspace.is_symlink() and 1 <= args.deadline_seconds <= 200,
            'g4_fixture_workspace_or_limit')
    review_raw = review_path.read_bytes()
    require(sha(review_raw) == args.source_review_sha256, 'g4_fixture_review_pin')
    review = json.loads(review_raw)
    require(review['schema'] == 'radik.stage05.g4_native_tail_source_admission.v01'
        and review['decision'] == 'ACCEPTED_FOR_FRESH_MEMORY_DESCENT_NATIVE_TAIL_ONLY'
        and review['owner_actual_allowed'] is False and review['ordinary_acceptance_allowed'] is False,
        'g4_fixture_independent_admission')
    pins, reason_codes = review['pins'], review['reason_codes']
    require(type(pins) is dict and RUNNER in pins and INPUT in pins and all(MEMORY_PREFIX + name in pins for name in MEMORY_INPUTS)
        and type(reason_codes) is list and all(type(x) is str for x in reason_codes), 'g4_fixture_review_shape')
    for relative, expected in pins.items():
        path = root / relative
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
            and not path.is_symlink() and path.resolve().is_relative_to(root), 'g4_fixture_pin_path')
        require(sha(path.read_bytes()) == expected, 'g4_fixture_source_pin')
    require(Path(__file__).resolve() == root / RUNNER and sha(Path(__file__).read_bytes()) == pins[RUNNER],
            'g4_fixture_runner_pin')
    workspace.mkdir(parents=True, mode=0o700)
    loaded, phases = [], []
    result = dict(schema='radik.stage05.g4_native_tail_result.v01', status='STOPPED_NO_RETRY',
        scope='FRESH_MEMORY_DESCENT_CONTROLLER_AND_G3_G4_TAIL_NOT_OWNER_COLD_ROUTE', owner_actual=False,
        ordinary_acceptance=False, historical_permission_restored=False, source_review_sha256=sha(review_raw),
        loaded_modules=loaded, phases=phases, real_provider_calls=0, AUTH_calls=0, SAVE_calls=0, native_E_calls=0)
    started, stage = time.monotonic(), 'IMPORTS'
    sys.dont_write_bytecode = True
    sys.meta_path.insert(0, PinnedFinder(root, pins, loaded))
    sys.path[:0] = [str(root), str(root / 'source/reference')]
    install_audit_fence(root, workspace)

    def persist(name, value):
        raw = canonical(value)
        path = workspace / (name + '_' + sha(raw) + '.json')
        with path.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        require(path.read_bytes() == raw, 'g4_fixture_evidence_readback')
        return dict(path=str(path.relative_to(workspace)), bytes=len(raw), sha256=sha(raw))

    def phase(name, callback):
        nonlocal stage
        stage, before = name, time.monotonic()
        print('G4_NATIVE_TAIL_PHASE ' + name, flush=True)
        value = callback()
        phases.append(dict(name=name, seconds=time.monotonic() - before))
        result['last_completed_phase'] = name
        persist('checkpoint', result)
        return value

    def deadline(_signal, _frame):
        raise TimeoutError('g4_fixture_deadline')

    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, args.deadline_seconds)
    try:
        from app import qualified_strategy as strategy, qualified_experience as experience
        from app import native_authority as authority, dynamic_native
        from app.task_spec import TaskSpec

        def read_inert():
            raw = (root / INPUT).read_bytes()
            require(sha(raw) == pins[INPUT], 'g4_fixture_input_changed')
            value = json.loads(raw)
            require(value['schema'] == 'radik.stage05.g4_bootstrap_inert_fixture.v01'
                and value['classification'] == 'HISTORICAL_ADVISORY_DATA_NOT_AUTHORITY', 'g4_fixture_inert_input')
            strategy._source_gate(value['material'])
            return value

        fixture = phase('CURRENT_RAW_SOURCE_READ', read_inert)
        payload_path = root / (MEMORY_PREFIX + MEMORY_INPUTS[1])
        historical = json.loads(payload_path.read_bytes())['outcome']
        now = int(time.time())
        require(now < historical['valid_to'], 'g4_tail_historical_memory_expired')
        result['historical_clocks'] = dict(accepted_at=historical['accepted_at'],
            valid_to=historical['valid_to'], fixture_started_at=now, extended=False)
        source = fixture['material']
        current_spec = dict(source['task'], created_at=now,
            task_id='radik-task:' + sha(canonical(dict(fixture='g4_native_tail', input=pins[INPUT], now=now)))[:32])
        spec = TaskSpec.from_plain(current_spec)
        project = workspace / 'project'
        project.mkdir(mode=0o700)

        class NoProvider:
            def __init__(self):
                self.calls = 0

            def propose(self, **_kwargs):
                self.calls += 1
                raise ValueError('g4_tail_role_call_forbidden')

        client = NoProvider()
        events = []
        controller = dynamic_native.DynamicDocumentController(project, client, task_spec=spec,
            source_reader=lambda: read_inert()['material']['sources'], clock=lambda: int(time.time()),
            on_event=events.append)
        for relative in MEMORY_INPUTS:
            raw = (root / (MEMORY_PREFIX + relative)).read_bytes()
            require(sha(raw) == pins[MEMORY_PREFIX + relative], 'g4_tail_memory_input_changed')
            destination = controller.memory.directory / relative
            require(not destination.exists(), 'g4_tail_memory_destination_exists')
            with destination.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            require(destination.read_bytes() == raw, 'g4_tail_memory_copy_changed')
        result['copied_history'] = [dict(source=MEMORY_PREFIX + name, sha256=pins[MEMORY_PREFIX + name])
                                    for name in MEMORY_INPUTS]
        accepted = phase('FRESH_MEMORY_DESCENT_AND_CURRENT_NATIVE_CONTROLLER', lambda: controller.run(require_memory=True))
        require(client.calls == 0 and accepted.controller is controller and controller.role_run is None
            and controller.memory_origin is not None and accepted.plain['accepted_at'] == historical['accepted_at']
            and accepted.plain['valid_to'] <= historical['valid_to'], 'g4_tail_fresh_current_controller')
        controller.validate_native()
        result['fresh_controller'] = persist('fresh_controller', authority.plain(dict(
            task=spec.plain(), accepted=accepted.plain, memory_origin=controller.memory_origin,
            events=events, memory_events=controller.memory.events)))
        result['coverage_limitations'] = [
            'Current controller uses the admitted memory route, not the original cold three-role route.',
            'The source reader reopens pinned raw fixture bytes; TaskStore ordinary console source admission is not exercised.',
            'Historical acceptance clocks are retained; only newly reviewed source and Work create the current accepted controller.',
            'No owner operation, model semantics, AUTH, provider, SAVE, E, public publication or Stage05 closure is claimed.',
        ]
        selected = experience.QualifiedExperience(project / 'state/qualified_experience', on_event=events.append)
        cold = phase('COLD_G3_CURRENT_DECISION', lambda: selected.consume(controller, cold=True))
        result['cold_G3'] = persist('cold_G3', cold.report)
        cold_work = phase('COLD_G4_ACTUAL_NATIVE_WORK', lambda: strategy.run(controller, cold, label='cold'))
        result['cold_G4'] = persist('cold_G4', cold_work)
        feedback = phase('PROSPECTIVE_G3_OBSERVATION', lambda: selected.observe(controller, predicted=True, expected_fp=500000000))
        result['feedback'] = persist('feedback', feedback)
        qualified = phase('QUALIFIED_G3_CURRENT_DECISION', lambda: selected.consume(controller))
        result['qualified_G3'] = persist('qualified_G3', qualified.report)
        qualified_work = phase('QUALIFIED_G4_ACTUAL_NATIVE_WORK', lambda: strategy.run(controller, qualified, label='qualified'))
        result['qualified_G4'] = persist('qualified_G4', qualified_work)
        require(cold.report['selected_operation'] != qualified.report['selected_operation']
            and qualified.report['prior_fp'] == -62500000, 'g4_tail_actual_g3_change')
        require(cold_work['consumed_units'] == qualified_work['consumed_units'] == 9
            and cold_work['budget_total'] == qualified_work['budget_total'] == 9
            and cold_work['allocation_counts'] == {'quotation':4, 'qualification':3}
            and qualified_work['allocation_counts'] == {'quotation':3, 'qualification':4}, 'g4_tail_actual_redistribution')
        controls = phase('EXPLICIT_TEMPORAL_AND_SCOPE_CONTROLS', lambda: selected.eligibility_controls(controller))
        result['controls'] = persist('controls', controls)
        unscorable = phase('UNSCORABLE_AUDIT_ONLY', lambda: selected.audit_unscorable(controller, reason='UNSCORABLE_MODEL_RESPONSE'))
        result['unscorable'] = persist('unscorable', unscorable)
        require(client.calls == 0 and controller.current_policy()['save_allowed'] is False
            and controller.host.registry.action_packet_lifecycle_entries == (), 'g4_tail_no_effects_or_roles')
        result['events'] = persist('events', events)
        result['status'] = 'FRESH_MEMORY_DESCENT_NATIVE_TAIL_OBSERVED_REQUIRES_INDEPENDENT_REVIEW'
    except BaseException as error:
        result['primary_failure'] = failure(error, stage, root, pins, reason_codes)
        try:
            native_stage = getattr(error, '_radik_stage05_native_stage', None)
            if type(native_stage) is str and native_stage in (
                'G4_BOOTSTRAP_ADVANCE', 'G4_BOOTSTRAP_ARTIFACT', 'G4_HISTORY', 'G4_ALLOCATION',
                'G4_TASK_ROOT', 'G4_REVISION', 'G4_PRE_DISPATCH_PERSISTENCE', 'G4_ALLOCATED_ADVANCE',
                'G4_ALLOCATED_ARTIFACT', 'G4_FINAL_CHECKS', 'G4_CUSTODY'):
                result['primary_failure']['native_stage'] = native_stage
        except BaseException:
            pass
        print('G4_NATIVE_TAIL_STOP ' + canonical(result['primary_failure']).decode(), flush=True)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        result['seconds'] = time.monotonic() - started
        reference = persist('result', result)
        print('G4_NATIVE_TAIL_RESULT ' + canonical(reference).decode(), flush=True)
    return 0 if result['status'] == 'FRESH_MEMORY_DESCENT_NATIVE_TAIL_OBSERVED_REQUIRES_INDEPENDENT_REVIEW' else 1


if __name__ == '__main__':
    raise SystemExit(main())
