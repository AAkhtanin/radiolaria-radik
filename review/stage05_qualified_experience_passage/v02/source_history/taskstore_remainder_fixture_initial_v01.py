"""One fresh unrelated current consumer and its actual source-revision refusal.

Three typed role responses use the unchanged, explicitly synthetic HTTP route.
Historical V02 witnesses are read only as inert exact bytes. No historical state,
controller, capture, memory validity, Root or permission is restored. This is a
compositional remainder control, not a complete ordinary or owner execution.
The separately admitted parent supervisor owns the original absolute deadline.
"""
import time
STARTED_NS = time.monotonic_ns()
STARTED_UTC = int(time.time())

import argparse
import ast
import hashlib
import importlib.abc
import importlib.machinery
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import types
import uuid

REAL = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage05_qualified_experience_passage/v02'
SELF = BASE + '/taskstore_remainder_fixture.py'
ACTUAL = 'TASKSTORE_REMAINDER_V01'
COPY = REAL / BASE / 'rehearsal_actual' / ACTUAL
WORK = REAL / BASE / 'offline_actual' / ACTUAL / 'work'
ROOT = COPY / 'ordinary/source_under_test'
MAX_SECONDS = 900
WORK_SECONDS = 830
CLEANUP_SECONDS = 30
FINAL_READBACK_SECONDS = 40
WORK_DEADLINE_NS = STARTED_NS + WORK_SECONDS * 10**9
HARD_DEADLINE_NS = STARTED_NS + MAX_SECONDS * 10**9
CLEANUP_DEADLINE_NS = None
FINAL_DEADLINE_NS = None
COPY_SUPPORT = None
OUTER_STARTED_NS = None
FIRST_STOP = None


class OuterWorkStopped(BaseException):
    """A parent stop is outside Exception-based transport failure handling."""


def retain_first_stop(code):
    global FIRST_STOP
    if FIRST_STOP is not None:
        return
    FIRST_STOP = dict(code=code, phase='OFFLINE_REMAINDER', raw_error_recorded=False,
        elapsed_from_outer_ns=time.monotonic_ns()-OUTER_STARTED_NS)
    # This bounded receipt precedes application cleanup and has no application
    # imports, ledger validation, source inventory traversal or permission effect.
    if WORK.exists():
        raw = canonical(FIRST_STOP)
        try:
            fd = os.open(WORK/'first_stop.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        except OSError:
            pass
    print('TASKSTORE_REMAINDER_STOP '+json.dumps(FIRST_STOP, sort_keys=True), flush=True)


def parent_stop(_signal, _frame):
    retain_first_stop('OUTER_WORK_DEADLINE')
    raise OuterWorkStopped()



def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(root, reference, name):
    path = root / reference['path']
    require(path.resolve().is_relative_to(root) and not path.is_symlink(), 'seam_source_path')
    raw = path.read_bytes()
    require(len(raw) == reference['size_bytes'] and sha(raw) == reference['sha256']
            and name not in sys.modules, 'seam_preimport_pin')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


class PinnedFinder(importlib.abc.MetaPathFinder):
    """The installed native loader separately owns its exact finite native map."""
    def __init__(self, root, pins, loaded):
        self.root, self.pins, self.loaded = root, pins, loaded

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in ('app', 'review', 'config'):
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path or [str(self.root)])
        require(spec is not None, 'seam_unadmitted_import')
        if spec.origin is None:
            require(spec.submodule_search_locations and all(Path(value).resolve().is_relative_to(self.root)
                for value in spec.submodule_search_locations), 'seam_namespace_path')
            return spec
        source = Path(spec.origin).resolve()
        require(source.is_relative_to(self.root) and source.suffix == '.py', 'seam_import_path')
        relative = source.relative_to(self.root).as_posix()
        raw = source.read_bytes()
        require(relative in self.pins and sha(raw) == self.pins[relative], 'seam_import_pin')
        loaded = self.loaded

        class Loader(importlib.abc.Loader):
            def create_module(self, _spec):
                return None

            def exec_module(self, module):
                require(source.read_bytes() == raw, 'seam_import_race')
                module.__file__ = str(source)
                loaded.append(dict(module=fullname, path=relative, sha256=sha(raw)))
                exec(compile(raw, str(source), 'exec', dont_inherit=True), module.__dict__)

        spec.loader = Loader()
        return spec


def install_fence():
    environment = tuple(Path(value).resolve() for value in (sys.prefix, sys.base_prefix))
    forbidden = {'.git', '.codex', '.ssh', '.aws', '.azure', '.gnupg', 'private', 'Arena', 'arena'}
    forbidden_names = {'auth.json', '.netrc', '.env', 'credentials', 'credentials.json'}
    flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def path(value):
        result = Path(os.fsdecode(value)).resolve()
        require(not forbidden.intersection(result.parts) and result.name not in forbidden_names,
                'seam_private_path')
        return result

    def writable(value):
        target = path(value)
        require(target.is_relative_to(COPY) or target.is_relative_to(WORK), 'seam_production_write')

    def audit(event, args):
        if event.startswith(('socket.', 'subprocess.', 'ctypes.')) or event in (
                'os.system', 'os.posix_spawn', 'os.posix_spawnp', 'os.exec', 'os.fork',
                'os.forkpty', 'pty.spawn', 'os.chdir', 'os.fchdir'):
            raise PermissionError('seam_external_operation')
        if event == 'open':
            name, mode, open_flags = args
            if type(name) is int:
                require(name >= 0, 'seam_descriptor')
                return
            target = path(name)
            writing = bool((open_flags or 0) & flags) or any(c in (mode or '') for c in 'wax+')
            if writing:
                writable(name)
            else:
                require(target.is_relative_to(REAL) or any(target.is_relative_to(p) for p in environment),
                        'seam_read_scope')
        elif event in ('os.rename', 'os.link', 'os.symlink'):
            writable(args[0]); writable(args[1])
        elif event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.chown',
                       'os.truncate', 'os.utime', 'os.setxattr', 'os.removexattr'):
            writable(args[0])
    sys.addaudithook(audit)


def final_cutoff(_signal, _frame):
    signal.setitimer(signal.ITIMER_REAL, 0)
    raise OuterWorkStopped()


def cleanup_cutoff(_signal, _frame):
    signal.setitimer(signal.ITIMER_REAL, 0)
    raise TimeoutError('seam_cleanup_cutoff')


def enter_cleanup():
    global CLEANUP_DEADLINE_NS
    if CLEANUP_DEADLINE_NS is None:
        CLEANUP_DEADLINE_NS = min(time.monotonic_ns() + CLEANUP_SECONDS * 10**9,
                                 HARD_DEADLINE_NS - FINAL_READBACK_SECONDS * 10**9)
    if COPY_SUPPORT is not None:
        COPY_SUPPORT.ACTIVE_DEADLINE_NS = CLEANUP_DEADLINE_NS
    signal.signal(signal.SIGALRM, cleanup_cutoff)
    remaining = (CLEANUP_DEADLINE_NS-time.monotonic_ns())/1e9
    # An expired repeated entry is handled by check_cleanup inside the caller's
    # protected try, so it cannot interrupt before final readback is installed.
    signal.setitimer(signal.ITIMER_REAL, remaining if remaining > 0 else 0)


def check_cleanup():
    require(CLEANUP_DEADLINE_NS is not None and time.monotonic_ns() < CLEANUP_DEADLINE_NS,
            'seam_cleanup_cutoff')


def enter_final_readback():
    global FINAL_DEADLINE_NS
    if FINAL_DEADLINE_NS is None:
        FINAL_DEADLINE_NS = min(time.monotonic_ns() + FINAL_READBACK_SECONDS * 10**9,
                               HARD_DEADLINE_NS)
    if COPY_SUPPORT is not None:
        COPY_SUPPORT.ACTIVE_DEADLINE_NS = FINAL_DEADLINE_NS
    signal.signal(signal.SIGALRM, final_cutoff)
    signal.setitimer(signal.ITIMER_REAL, max(0.000001, (FINAL_DEADLINE_NS-time.monotonic_ns())/1e9))


def check_deadline():
    if time.monotonic_ns() >= WORK_DEADLINE_NS:
        retain_first_stop('OUTER_WORK_DEADLINE')
        raise OuterWorkStopped()


def capture_loaded(root, pins):
    rows = []
    for name, module in tuple(sys.modules.items()):
        if name.split('.')[0] not in ('app', 'config', 'review', 'hedgehog', 'demo'):
            continue
        filename = getattr(module, '__file__', None)
        if filename is None:
            continue
        path = Path(filename).resolve()
        require(path.is_relative_to(root), 'seam_loaded_outside_copy')
        relative = path.relative_to(root).as_posix()
        require(relative in pins and sha(path.read_bytes()) == pins[relative], 'seam_loaded_pin')
        rows.append(dict(module=name, path=relative, sha256=pins[relative]))
    return sorted(rows, key=lambda row: row['module'])


def run_current(root, manifest, grant, runner, lock_fd, result, checkpoint):
    pins = dict(manifest['pins'])
    require(grant['helper_refs'] == [], 'seam_current_typed_producer_only')
    loaded = result['loaded_modules']
    finder = PinnedFinder(root, pins, loaded)
    sys.meta_path.insert(0, finder)
    sys.path.insert(0, str(root))
    sys.dont_write_bytecode = True
    from config import native_profile_loader
    native_profile_loader.install(root)
    from config.application_profile_gate import rehearsal_context
    from app import budget, contracts, openai_plan_transport as transport, ordinary_rehearsal
    from app import dynamic_native, task_spec, task_store, normal_session, qualified_strategy
    from app import native_authority as authority, stage04_diagnostics as diagnostics
    from app import qualified_experience_scenario as scenario
    from app.qualified_experience import QualifiedExperience
    from app.runtime import _information_policy_reader

    operation_id, run_id = str(uuid.uuid4()), uuid.uuid4().hex[:12]
    operation_ref = normal_session.open_operation(root, owner_lock_fd=lock_fd,
        owner_operation_id=operation_id, run_id=run_id,
        source_review_ref=manifest['source_review_ref'], source_admission_ref=manifest['source_admission_ref'],
        source_identity_sha256=contracts.digest(manifest['pins']),
        auth_source_identity_sha256=manifest['auth_source_identity_sha256'],
        profile_ref=dict(path=grant['manifest_ref']['path'], sha256=grant['manifest_ref']['sha256']))
    operation = normal_session.validate_operation(root, operation_ref)
    client = None
    primary = None
    try:
        counter = budget.TurnBudget.for_scope(root, 'console')
        counter.set_console_operation(operation_id, run_id)
        counter.set_normal_operation(operation_ref)
        initial_ledger = counter.snapshot()
        require(len(initial_ledger['attempts']) == grant['starting_counted_attempts'] == 44
                and initial_ledger['active_attempt_id'] is None, 'seam_starting_ledger')
        def source_validator():
            check_deadline()
            for relative, expected in pins.items():
                require(sha(runner.read(root, relative)) == expected, 'seam_current_source_pin')
            return dict(scope='EXPLICIT_SYNTHETIC_HTTP_UNRELATED_REMAINDER',
                source_pins_sha256=contracts.digest(pins), source_review_sha256=grant['source_review_ref']['sha256'],
                synthetic_catalog=True, synthetic_grant=True, live_authority=False)

        context = rehearsal_context(root, grant['cases'][0]['rehearsal_seal_ref']['sha256'])
        auth = ordinary_rehearsal.make_auth(root, context)

        def admission_validator(*, preflight_receipt, role):
            require(role in ('orchestrator', 'architect', 'critic'), 'seam_typed_role_scope')
            ordinary_rehearsal.validate_fixture_catalog(root, context, preflight_receipt)
            return True

        # Use the current typed inert route through the unmodified transport's
        # _connection and _send checks. No connection or owner gate is replaced.
        client = transport.OpenAIPlanTransport(project=root, auth=auth, budget=counter,
            observation_directory='review/finalized_observations', source_validator=source_validator,
            admission_validator=admission_validator)
        client.budget_scope = 'console'
        client._ordinary_profile_manifest = manifest
        require(type(auth) is ordinary_rehearsal.RehearsalAuth
            and client._catalog is None and client._grant is None, 'seam_typed_transport_origin')
        checkpoint('typed_transport_binding', dict(auth_type='app.ordinary_rehearsal.RehearsalAuth',
            context_sha256=context.seal_sha256,
            transport_type='app.openai_plan_transport.OpenAIPlanTransport',
            synthetic_http_producer='app.ordinary_rehearsal',
            catalog_initially_empty=True, current_transport_dispatch_unchanged=True,
            real_AUTH_provider_calls=0, real_authority=False))
        store = task_store.TaskStore(root / 'workspace/owner_documents', require_existing=True)
        initial_tasks = json.loads(canonical(store.state))
        require(len(initial_tasks['tasks']) == 11, 'seam_starting_tasks')
        historical_refs = grant['historical_evidence_refs']
        require(type(historical_refs) is list and 1 <= len(historical_refs) <= 16,
            'remainder_historical_evidence_bound')
        allowed_history = BASE+'/rehearsal_actual/TASKSTORE_SEAM_V02/ordinary/source_under_test/workspace/owner_documents/'
        require(all(ref['path'].startswith(allowed_history) for ref in historical_refs),
            'remainder_historical_evidence_scope')
        historical_before = [dict(reference=ref, observed_sha256=sha(runner.verify(REAL, ref)))
            for ref in historical_refs]
        accepted_ref = grant['historical_accepted_result_ref']
        require(accepted_ref in historical_refs, 'remainder_historical_accepted_membership')
        historical = json.loads(runner.verify(REAL, accepted_ref))
        require(historical['classification'] == 'PORTABLE_EVIDENCE_NOT_LIVE_AUTHORITY'
            and historical['type'] == 'builtins.dict', 'remainder_historical_evidence_class')
        old_task = historical['body']['result']['task_id']
        old_root = historical['body']['result']['root_context']['root_id']
        checkpoint('historical_inert_bytes', dict(files=historical_before,
            original_task_id=old_task, original_root=old_root,
            imported_into_live_store=False, old_validity_extended=False,
            live_foreign_capture_rejection_tested=False))
        controllers = {}

        def run_task(task_id, *, prepare_continuation):
            require(prepare_continuation is False, 'seam_E_not_authorized')
            check_deadline()
            spec = store.spec(task_id)
            sources = store.prepare_round_sources(spec)
            dependencies = dict(meaning_key=task_spec.meaning_key(spec, sources),
                                sources=dynamic_native.descriptors(sources))
            binding = counter.begin_task_round(task_id=task_id, profile=spec.profile,
                task_spec_sha256=contracts.digest(spec.plain()), dependencies_sha256=contracts.digest(dependencies),
                max_attempts=3, mode='COLD')
            started = False
            task_error = None
            try:
                store.begin(task_id, sources, operation_round=binding)
                started = True
                controller = dynamic_native.DynamicDocumentController(store.project, client,
                    task_spec=spec, source_reader=store.source_reader(spec),
                    policy_reader=_information_policy_reader(store.project,
                        dynamic_native.informational_valid_to(int(time.time())), informational_delta=True),
                    informational_delta=True, operation_deadline=STARTED_UTC + WORK_SECONDS)
                controllers[task_id] = controller
                accepted = controller.run()
                require(controller.memory_origin is None, 'seam_fresh_cold_controller')
                store.complete(task_id, accepted.plain)
            except BaseException as error:
                task_error = error
                if started and store.state['active_task_id'] == task_id:
                    try:
                        store.fail(task_id)
                    except BaseException as secondary:
                        diagnostics.record_secondary(error, secondary, phase='FINALIZATION', step='STAGE05_EXPERIENCE')
                raise
            finally:
                try:
                    counter.end_task_round()
                except BaseException as secondary:
                    if task_error is None:
                        raise
                    diagnostics.record_secondary(task_error, secondary, phase='FINALIZATION', step='STAGE05_EXPERIENCE')
            return accepted

        input_ref = dict(path=BASE+'/inputs/scenario.json',
            sha256=manifest['pins'][BASE+'/inputs/scenario.json'])
        input_raw = runner.read(root, input_ref['path'])
        require(sha(input_raw) == input_ref['sha256'], 'remainder_scenario_input_pin')
        inputs = json.loads(input_raw)['unrelated']
        source_key = 'stage05:remainder:'+run_id+':alder'
        source_id = store.register_source(source_key, 'Fictional Alder museum terms',
            inputs['source_text'].encode('utf-8'))
        task_id = store.create(goal=inputs['goal'], source_ids=(source_id,),
            profile=inputs['ordinary_profile'], criterion=inputs['criterion'], topic=inputs['topic'])
        require(task_id != old_task, 'remainder_distinct_task_required')
        checkpoint('unrelated_prospective_task', dict(task=store.spec(task_id).plain(),
            source_id=source_id, expected_synthetic_role_calls=3,
            historical_task_id=old_task, historical_captures_loaded=False))
        phase_started = time.monotonic_ns()
        accepted = run_task(task_id, prepare_continuation=False)
        controller = controllers[task_id]
        require(controller.accepted is not None and controller.memory_origin is None
            and controller.root_id != old_root, 'remainder_fresh_unrelated_controller')
        checkpoint('unrelated_accepted_result', dict(result=accepted.plain,
            source_scope=controller.initial_sources,
            elapsed_wall_ns=time.monotonic_ns()-phase_started, synthetic_role_calls=3))
        after_roles = counter.snapshot()
        experience = QualifiedExperience(root/'workspace/owner_documents/review/stage05_remainder'/run_id)
        history_before = experience.history_snapshot()
        phase_started = time.monotonic_ns()
        binding = experience.consume(controller)
        history_after = experience.history_snapshot()
        require(binding.report['history_ref'] is None and binding.report['prior_fp'] == 0
            and binding.report['outcome_to_history_refs'] == []
            and binding.report['history_disposition'] == 'COLD_OR_NONMATCHING'
            and binding.report['mandatory_check'] is not None
            and binding.report['provider_calls'] == binding.report['effect_calls'] == 0
            and history_before == history_after, 'remainder_unrelated_current_consumer')
        checkpoint('unrelated_current_consumer', dict(actual_task_id=task_id,
            historical_task_id=old_task, historical_files=historical_before,
            consumer=binding.report, history_before=history_before, history_after=history_after,
            elapsed_wall_ns=time.monotonic_ns()-phase_started,
            claim='FRESH_UNRELATED_CURRENT_CONSUMER_NO_HISTORY',
            live_foreign_capture_rejection_tested=False))
        check_deadline()
        before_sources = store.source_reader(store.spec(task_id))()
        require(len(before_sources) == 1 and before_sources[0]['source_ref'] == source_id
            and before_sources[0]['text'] == inputs['source_text'], 'remainder_source_revision_preimage')
        native_before = dict(results=authority.plain(controller.results),
            events=authority.plain(controller.events), evidence_refs=authority.plain(controller.evidence_refs))
        history_before_revision = experience.history_snapshot()
        checkpoint('source_revision_before', dict(source_id=source_id, approved_sources=before_sources,
            history=history_before_revision, native=native_before, old_binding_id=binding.report['binding_id']))
        changed_bytes = (inputs['source_text']+' Updated source: the garden is also closed during snowfall.').encode('utf-8')
        require(store.register_source(source_key, 'Fictional Alder museum terms', changed_bytes) == source_id,
            'remainder_source_logical_identity')
        after_sources = store.source_reader(store.spec(task_id))()
        require(len(after_sources) == 1 and after_sources[0]['source_ref'] == source_id
            and after_sources[0]['revision'] == before_sources[0]['revision']+1
            and after_sources[0]['sha256'] == sha(changed_bytes)
            and after_sources[0]['sha256'] != before_sources[0]['sha256']
            and after_sources[0]['text'].encode('utf-8') == changed_bytes,
            'remainder_actual_source_revision')
        checkpoint('source_revision_after', dict(source_id=source_id,
            approved_sources=after_sources, raw_utf8_hex=changed_bytes.hex()))
        try:
            qualified_strategy.run(controller, binding, label='qualified')
        except ValueError as error:
            require(error.args == ('dynamic_current_sources_changed',), 'remainder_wrong_stale_refusal')
            refusal = error.args[0]
        else:
            raise ValueError('remainder_stale_binding_consumed')
        native_after = dict(results=authority.plain(controller.results),
            events=authority.plain(controller.events), evidence_refs=authority.plain(controller.evidence_refs))
        history_after_revision = experience.history_snapshot()
        require(native_before == native_after and history_before_revision == history_after_revision,
            'remainder_stale_refusal_changed_native_history')
        checkpoint('source_revision_stale_binding_refused', dict(refusal_code=refusal,
            consumer='qualified_strategy.run', old_binding_id=binding.report['binding_id'],
            before_sources=before_sources, after_sources=after_sources,
            native_before=native_before, native_after=native_after,
            history_before=history_before_revision, history_after=history_after_revision,
            native_dispatch_reached=False, prior_reapplied=False,
            binding_scope='FRESH_UNRELATED_TASK_CURRENT_NO_HISTORY_BINDING'))
        historical_after = [dict(reference=ref, observed_sha256=sha(runner.verify(REAL, ref)))
            for ref in historical_refs]
        require(historical_after == historical_before, 'remainder_historical_bytes_changed')
        require(counter.snapshot()['attempts'] == after_roles['attempts'], 'remainder_native_provider_calls')
        result['remainder'] = dict(unrelated_task_id=task_id,
            historical_task_id=old_task, fresh_current_consumer=True,
            actual_source_revision_refusal=refusal, historical_bytes_unchanged=True,
            live_foreign_capture_rejection_tested=False,
            repeated_G4_allocations=0, repeated_aged_consumers=0)
        final_ledger = counter.snapshot()
        require(final_ledger['attempts'][:44] == initial_ledger['attempts']
            and len(final_ledger['attempts']) - 44 == 3 and final_ledger['active_attempt_id'] is None,
            'seam_exact_synthetic_role_budget')
        require(all(store.state['tasks'][key] == row for key, row in initial_tasks['tasks'].items()),
                'seam_historical_tasks_changed')
        checkpoint('normal_operation_final_state', dict(operation_ref=operation_ref, operation=operation,
            ledger=final_ledger, tasks=store.state, synthetic_role_attempts=3,
            real_provider_calls=0, old_44_attempts_preserved=True, old_11_tasks_preserved=True))
        result['loaded_modules'] = capture_loaded(root, pins)
        result['status'] = 'OBSERVED_REMAINDER_REQUIRES_INDEPENDENT_REVIEW'
    except BaseException as error:
        primary = error
        if isinstance(error, OuterWorkStopped):
            result['primary_failure'] = FIRST_STOP or dict(code='OUTER_WORK_DEADLINE', raw_error_recorded=False)
        diagnostics.observe_failure(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        if 'primary_failure' not in result:
            result['primary_failure'] = diagnostics.project_error(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
            checkpoint('primary_failure_before_cleanup', result['primary_failure'])
        try:
            result['failure_context'] = scenario._failure_context(root, manifest, error, 'UNKNOWN')
        except BaseException as secondary:
            result['failure_context_secondary'] = dict(type=type(secondary).__name__, raw_error_recorded=False)
        raise
    finally:
        enter_cleanup()
        for name, call in (
                ('client_close', lambda: client.close() if client is not None else None),
                ('normal_operation_close', lambda: normal_session.close_operation(root,
                    owner_lock_fd=lock_fd, operation_ref=operation_ref, failed=primary is not None))):
            try:
                check_cleanup()
                checkpoint(name, call())
            except BaseException as secondary:
                # An elapsed cutoff is never a recoverable secondary exception.
                # In particular, do not start the next cleanup call with a
                # canceled alarm after the deadline handler has fired.
                if time.monotonic_ns() >= CLEANUP_DEADLINE_NS:
                    raise
                if primary is None:
                    raise
                diagnostics.record_secondary(primary, secondary, phase='FINALIZATION', step='STAGE05_EXPERIENCE')
                result.setdefault('cleanup_failures', []).append(dict(action=name,
                    failure=diagnostics.project_error(secondary, phase='FINALIZATION', step='STAGE05_EXPERIENCE')))


def main():
    global COPY_SUPPORT, OUTER_STARTED_NS, WORK_DEADLINE_NS, HARD_DEADLINE_NS
    signal.signal(signal.SIGINT, parent_stop)
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    grant_path = REAL / args.grant
    require(grant_path.resolve().is_relative_to(REAL / BASE) and not grant_path.is_symlink(), 'seam_grant_path')
    raw = grant_path.read_bytes()
    require(sha(raw) == args.sha256, 'seam_grant_hash')
    grant = json.loads(raw)
    require(grant['schema'] == 'radik.stage05.taskstore_remainder_grant.v01'
        and grant['reviewer'] == '/root/private_remote_controls' and grant['approved_executor'] == '/root'
        and grant['approved_invocation_count'] == 1 and grant['network'] == 'DENIED'
        and grant['production_writes_allowed'] is False and grant['real_AUTH_provider_native_E_SAVE_allowed'] is False
        and grant['status'] == 'SOURCE_ACCEPTED_FOR_TARGETED_TASKSTORE_REMAINDER'
        and grant['max_seconds'] == MAX_SECONDS and grant['work_seconds'] == WORK_SECONDS
        and grant['cleanup_seconds'] == CLEANUP_SECONDS
        and grant['final_readback_seconds'] == FINAL_READBACK_SECONDS and grant['actual_id'] == ACTUAL,
        'seam_independent_grant')
    require(grant['outer_limits'] == dict(total_seconds=MAX_SECONDS,
        work_seconds=WORK_SECONDS, cleanup_seconds=CLEANUP_SECONDS,
        final_seconds=FINAL_READBACK_SECONDS), 'remainder_outer_limits')
    outer = REAL/BASE/'offline_actual'/ACTUAL/'supervisor/reservation.json'
    require(not outer.is_symlink() and outer.is_file(), 'remainder_outer_reservation')
    outer_reservation = json.loads(outer.read_bytes())
    require(outer_reservation['grant_sha256'] == args.sha256
        and outer_reservation['invocation_count'] == 1
        and outer_reservation['automatic_retry'] is False,
        'remainder_outer_reservation_binding')
    OUTER_STARTED_NS = outer_reservation['started_monotonic_ns']
    require(type(OUTER_STARTED_NS) is int and OUTER_STARTED_NS <= STARTED_NS,
        'remainder_outer_original_clock')
    WORK_DEADLINE_NS = OUTER_STARTED_NS+WORK_SECONDS*10**9
    HARD_DEADLINE_NS = OUTER_STARTED_NS+MAX_SECONDS*10**9
    require(outer_reservation['hard_deadline_ns'] == HARD_DEADLINE_NS,
        'remainder_outer_hard_deadline')
    check_deadline()
    require(grant['runner_ref']['path'] == SELF and sha(Path(__file__).read_bytes()) == grant['runner_ref']['sha256'],
            'seam_runner_pin')
    require(len(grant['cases']) == 1 and grant['cases'][0]['name'] == 'ordinary'
        and grant['cases'][0]['owned_copy_root'] == str(ROOT), 'seam_exact_copy_root')
    require(not COPY.exists() and not WORK.exists(), 'seam_uncertain_retry_refused')
    require(grant['interpreter_ref']['path'] == str(REAL / '.venv-plan/bin/python')
        and Path(sys.executable).absolute() == REAL / '.venv-plan/bin/python'
        and sha((REAL / '.venv-plan/bin/python').read_bytes()) == grant['interpreter_ref']['sha256'],
        'seam_interpreter_pin')
    COPY.mkdir(parents=True, mode=0o700)
    WORK.mkdir(parents=True, mode=0o700)
    install_fence()
    runner = load(REAL, grant['copy_runner_ref'], 'stage05_seam_copy_support')
    COPY_SUPPORT = runner
    runner.ACTIVE_DEADLINE_NS = WORK_DEADLINE_NS
    runner.guard(grant)
    runner.put(WORK, 'reservation.json', canonical(dict(grant_sha256=args.sha256,
        automatic_retry=False, invocation_count=1, preparation_included=True)))
    result = dict(schema='radik.stage05.taskstore_remainder_result.v01', status='STOPPED_NO_RETRY',
        scope='ONE_FRESH_UNRELATED_CURRENT_CONSUMER_AND_OWN_SOURCE_REVISION_REFUSAL',
        original_ordinary_prefix_reexecution=False, full_ordinary_cli_actual=False, owner_actual=False,
        real_provider_calls=0, real_AUTH_calls=0, native_E_calls=0, effects=0,
        source_review_ref=grant['source_review_ref'], automatic_retry=False,
        preparation_included=True, max_seconds=MAX_SECONDS, work_seconds=WORK_SECONDS,
        cleanup_seconds=CLEANUP_SECONDS, final_readback_seconds=FINAL_READBACK_SECONDS,
        observations=[], loaded_modules=[])
    lock = None
    supervisor = None
    sequence = 0

    def checkpoint(name, value):
        nonlocal sequence
        require(re.fullmatch('[A-Za-z_]{1,64}', name) is not None, 'seam_checkpoint_name')
        sequence += 1
        reference = runner.put(WORK, '%03d_%s.json' % (sequence, name), canonical(value))
        result['observations'].append(dict(name=name, reference=reference,
            elapsed_wall_ns=time.monotonic_ns()-STARTED_NS))
        print('TASKSTORE_REMAINDER_CHECKPOINT ' + name + ' ' + str(reference['path']), flush=True)
        return reference

    try:
        check_deadline()
        root = runner.copy_case(grant, grant['cases'][0])
        manifest = json.loads(runner.verify(root, grant['manifest_ref']))
        require(manifest['pins'] == grant['code_pins'], 'seam_manifest_pin_scope')
        supervisor = load(root, grant['supervisor_ref'], 'stage05_seam_installation_support')
        info = (root / supervisor.LOCK).stat()
        lock = supervisor.acquire_lock(dict(device=info.st_dev, inode=info.st_ino,
            owner=info.st_uid, mode=stat.S_IMODE(info.st_mode), links=info.st_nlink))
        checkpoint('preserving_installation', supervisor.prepare_installation(dict(code_pins=grant['code_pins'],
            ordinary_profile_manifest_ref=grant['manifest_ref']), manifest, lock_fd=lock,
            rehearsal_sha=grant['cases'][0]['rehearsal_seal_ref']['sha256'], before_pin=check_deadline))
        run_current(root, manifest, grant, runner, lock, result, checkpoint)
    except BaseException as error:
        result['status'] = 'STOPPED_NO_RETRY'
        if 'primary_failure' not in result:
            # Unknown text is never exported; owned frame coordinates identify
            # a failure before the independently admitted projector is loaded.
            detail = runner.safe_error(error)
            detail['code'] = 'UNPROJECTED_SETUP_FAILURE'
            result['primary_failure'] = detail
        print('TASKSTORE_REMAINDER_STOP ' + json.dumps(result['primary_failure'], sort_keys=True), flush=True)
    finally:
        enter_cleanup()
        cleanup_action = 'LOCK_RELEASE'
        try:
            check_cleanup()
            if lock is not None:
                result['lock_released'] = supervisor.release_owned_lock(lock, child_started=False,
                    receipt={'lock_explicit_unlock_permitted': True})
            cleanup_action = 'PRODUCTION_GUARD'
            check_cleanup()
            runner.guard(grant)
            result['production_guard_unchanged'] = True
        except BaseException as error:
            result['status'] = 'STOPPED_NO_RETRY'
            result['cleanup_confirmed'] = False
            code = ('SEAM_CLEANUP_DEADLINE' if time.monotonic_ns() >= CLEANUP_DEADLINE_NS else
                    'SEAM_LOCK_RELEASE_FAILED' if cleanup_action == 'LOCK_RELEASE' else
                    'SEAM_PRODUCTION_GUARD_FAILED')
            result['cleanup_failure'] = dict(type=type(error).__name__, code=code,
                phase='FINALIZATION', step='TASKSTORE_SEAM_CLEANUP', raw_error_recorded=False)
            if 'primary_failure' not in result:
                result['primary_failure'] = result['cleanup_failure']
                print('TASKSTORE_REMAINDER_STOP ' + json.dumps(result['primary_failure'], sort_keys=True), flush=True)
            else:
                print('TASKSTORE_REMAINDER_SECONDARY_STOP ' + json.dumps(result['cleanup_failure'], sort_keys=True), flush=True)
        finally:
            enter_final_readback()
            try:
                result['elapsed_wall_seconds'] = (time.monotonic_ns()-STARTED_NS)/1e9
                require(time.monotonic_ns() < FINAL_DEADLINE_NS, 'seam_absolute_final_cutoff')
                result_ref = runner.put(WORK, 'result.json', canonical(result))
                require(time.monotonic_ns() < FINAL_DEADLINE_NS, 'seam_absolute_final_cutoff')
                completion = dict(status=result['status'], result_ref=result_ref,
                    result_readback_verified=True, production_guard_unchanged=result.get('production_guard_unchanged') is True,
                    post_result_readback_wall_seconds=(time.monotonic_ns()-STARTED_NS)/1e9,
                    preparation_included=True, deadline_renewed=False,
                    outer_started_monotonic_ns=OUTER_STARTED_NS, original_work_deadline_ns=WORK_DEADLINE_NS, cleanup_deadline_ns=CLEANUP_DEADLINE_NS,
                    final_readback_deadline_ns=FINAL_DEADLINE_NS, original_hard_deadline_ns=HARD_DEADLINE_NS)
                runner.put(WORK, 'completion.json', canonical(completion))
                require(time.monotonic_ns() < FINAL_DEADLINE_NS, 'seam_absolute_final_cutoff')
                print('TASKSTORE_REMAINDER_RETURN ' + result['status'], flush=True)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
    return 0 if result['status'] == 'OBSERVED_REMAINDER_REQUIRES_INDEPENDENT_REVIEW' else 1


if __name__ == '__main__':
    raise SystemExit(main())
