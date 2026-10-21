"""One fresh TaskStore-reader seam in a separately admitted, finite copied state.

The six typed role responses are explicit synthetic HTTP fixtures. Actual current
TaskStore readers, normal-operation budgets, Root, Host and PURE Work execute.
This does not repeat or certify the ordinary CLI/AUTH entry, owner model semantics,
or a complete owner run. No historical controller or permission is restored.
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
SELF = BASE + '/taskstore_seam_fixture.py'
ACTUAL = 'TASKSTORE_SEAM_V01'
COPY = REAL / BASE / 'rehearsal_actual' / ACTUAL
WORK = REAL / BASE / 'offline_actual' / ACTUAL / 'work'
ROOT = COPY / 'ordinary/source_under_test'
LEGACY = 'review/stage04_dynamic_passage'
MAX_SECONDS = 900
WORK_SECONDS = 865
CLEANUP_SECONDS = 30
FINAL_READBACK_SECONDS = 5
WORK_DEADLINE_NS = STARTED_NS + WORK_SECONDS * 10**9
HARD_DEADLINE_NS = STARTED_NS + MAX_SECONDS * 10**9
CLEANUP_DEADLINE_NS = None
FINAL_DEADLINE_NS = None
COPY_SUPPORT = None
INPUT_REASONS = (
    'root_decision_input_invalid', 'root_review_packet_invalid',
    'root_decision_identity_mismatch', 'root_decision_post_vv_invalid',
    'root_decision_gt_advisory_invalid', 'root_decision_policy_state_invalid',
    'root_decision_permission_state_invalid', 'root_decision_temporal_state_invalid',
    'root_decision_conflict_state_invalid', 'root_decision_prior_state_invalid',
    'root_decision_candidate_binding_invalid', 'root_decision_transition_blocked',
)


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


def cutoff(_signal, _frame):
    signal.setitimer(signal.ITIMER_REAL, 0)
    raise TimeoutError('seam_absolute_work_cutoff')


def final_cutoff(_signal, _frame):
    signal.setitimer(signal.ITIMER_REAL, 0)
    raise TimeoutError('seam_absolute_final_cutoff')


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
    require(time.monotonic_ns() < WORK_DEADLINE_NS, 'seam_absolute_work_cutoff')


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
    for reference in grant['helper_refs']:
        raw = runner.verify(root, reference)
        require(reference['path'] not in pins or pins[reference['path']] == sha(raw), 'seam_helper_collision')
        pins[reference['path']] = sha(raw)
    loaded = result['loaded_modules']
    finder = PinnedFinder(root, pins, loaded)
    sys.meta_path.insert(0, finder)
    sys.path.insert(0, str(root))
    sys.dont_write_bytecode = True
    from config import native_profile_loader
    native_profile_loader.install(root)
    from app import budget, contracts, plan_auth, openai_plan_transport as transport
    from app import dynamic_native, task_spec, task_store, normal_session, qualified_strategy
    from app import native_authority as authority, stage04_diagnostics as diagnostics
    from app import qualified_experience_scenario as scenario
    from app.runtime import _information_policy_reader

    helpers = {item['path']: item for item in grant['helper_refs']}
    wire = load(root, helpers[LEGACY + '/dynamic_wire.py'], 'stage05_seam_reviewed_wire')
    producer = load(root, helpers[LEGACY + '/native_cases.py'], 'stage05_seam_reviewed_producer')
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
        client, client_root = wire.create_wire_client(WORK, 'taskstore_seam', transport=transport,
            controller=None, contracts=contracts, budget_module=budget, auth_module=plan_auth,
            policy_bytes=runner.read(root, 'config/model_policy.json'),
            product_factory=producer.product_factory(route='short', optional_exceptions=False),
            project_override=root, console_budget=counter)
        require(client_root == root, 'seam_client_root')

        def source_validator():
            check_deadline()
            for relative, expected in pins.items():
                require(sha(runner.read(root, relative)) == expected, 'seam_current_source_pin')
            return dict(scope='EXPLICIT_SYNTHETIC_HTTP_CURRENT_TASKSTORE_SEAM',
                source_pins_sha256=contracts.digest(pins), source_review_sha256=grant['source_review_ref']['sha256'],
                synthetic_catalog=True, synthetic_grant=True, live_authority=False)

        # The fixture identity does not stand in for independent source admission.
        # Every synthetic request separately rechecks the exact admitted closure.
        client.source_validator = source_validator
        client._ordinary_profile_manifest = manifest
        store = task_store.TaskStore(root / 'workspace/owner_documents', require_existing=True)
        initial_tasks = json.loads(canonical(store.state))
        require(len(initial_tasks['tasks']) == 11, 'seam_starting_tasks')
        controllers = {}

        def event_sink(event):
            check_deadline()
            if event.get('kind') in ('PHASE_ENTER', 'PHASE_EXIT', 'STATUS', 'PRIMARY_FAILURE'):
                checkpoint('event', event)
                print('TASKSTORE_SEAM_EVENT ' + json.dumps(event, sort_keys=True), flush=True)

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
            # Use the actual registered reader and wall clock, with no clock or
            # reader substitution. Timestamp drift alone is not source revision.
            first = qualified_strategy._source_material(controller)
            first_time = first['sources'][0]['observed_at']
            wait = max(0.001, first_time + 1.01 - time.time())
            require(wait <= 1.1, 'seam_real_clock_wait_bound')
            time.sleep(wait)
            second = qualified_strategy._source_material(controller)
            require(first['sources'][0]['observed_at'] < second['sources'][0]['observed_at']
                and qualified_strategy._source_identity(first) == qualified_strategy._source_identity(second),
                'seam_observation_time_is_not_source_identity')
            checkpoint('real_reader_observation_tick', dict(task_id=task_id, first=first, second=second,
                real_clock=True, unchanged_source_identity=True, reader_replaced=False))
            if len(controllers) == 1:
                review = authority.root_review('seam:blocked:' + run_id, {'task_id': task_id},
                    {'current_source': False}, int(time.time()), transaction_id='seam:blocked:' + run_id,
                    root=controller.root_id, task_id=task_id)
                plain = authority.root_plain(review)
                require(plain['result']['decision'] == 'BLOCKED_FAIL_CLOSED'
                    and all(plain['result'][key] is False for key in
                        ('permission_created', 'final_output_created', 'effect_requested')),
                    'seam_failed_check_accepted')
                require(plain['input']['permission_state']['permission_required'] is False,
                        'seam_blocked_root_permission')
                checkpoint('actual_blocked_Root', plain)
            return accepted

        native_ref = manifest['native_files']['hedgehog/kernel/root_decision_v01.py']
        native_raw = runner.verify(root, dict(native_ref, size_bytes=len(runner.read(root, native_ref['path']))))
        input_values = [ast.literal_eval(node.value) for node in ast.parse(native_raw).body
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '_INPUT_REASONS'
                                                    for target in node.targets)]
        require(input_values == [INPUT_REASONS], 'seam_native_reason_inventory')
        projections = [diagnostics.project_error(ValueError(code), phase='TASK_EXECUTION',
                        step='STAGE05_EXPERIENCE') for code in INPUT_REASONS]
        require([item['code'] for item in projections] == list(INPUT_REASONS), 'seam_native_reason_projection')
        sentinel = 'UNREVIEWED_ERROR_CONTENT_SEAM_37c9'
        unknown = diagnostics.project_error(ValueError(sentinel), phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        require(unknown['code'] == 'SANITIZED_OPERATION_FAILURE'
            and sentinel not in canonical(unknown).decode(), 'seam_unknown_reason_not_sanitized')
        checkpoint('closed_native_diagnostics', dict(control='SYNTHETIC_VALUEERROR_PROJECTION',
            native_reason_count=len(projections), projections=projections, unknown=unknown,
            historical_unknown_failure_recovered=False))
        result['scenario'] = scenario.run(store=store, run_task=run_task, controllers=controllers,
            client=client, operation=operation, event_sink=event_sink)
        final_ledger = counter.snapshot()
        require(final_ledger['attempts'][:44] == initial_ledger['attempts']
            and len(final_ledger['attempts']) - 44 == 6 and final_ledger['active_attempt_id'] is None,
            'seam_exact_synthetic_role_budget')
        require(all(store.state['tasks'][key] == row for key, row in initial_tasks['tasks'].items()),
                'seam_historical_tasks_changed')
        checkpoint('normal_operation_final_state', dict(operation_ref=operation_ref, operation=operation,
            ledger=final_ledger, tasks=store.state, synthetic_role_attempts=6,
            real_provider_calls=0, old_44_attempts_preserved=True, old_11_tasks_preserved=True))
        result['loaded_modules'] = capture_loaded(root, pins)
        result['status'] = 'OBSERVED_TARGETED_TASKSTORE_SEAM_REQUIRES_INDEPENDENT_REVIEW'
    except BaseException as error:
        primary = error
        diagnostics.observe_failure(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        result['primary_failure'] = diagnostics.project_error(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        result['failure_context'] = scenario._failure_context(root, manifest, error, 'UNKNOWN')
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
    global COPY_SUPPORT
    signal.signal(signal.SIGALRM, cutoff)
    signal.setitimer(signal.ITIMER_REAL, max(0.000001, (WORK_DEADLINE_NS-time.monotonic_ns())/1e9))
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    grant_path = REAL / args.grant
    require(grant_path.resolve().is_relative_to(REAL / BASE) and not grant_path.is_symlink(), 'seam_grant_path')
    raw = grant_path.read_bytes()
    require(sha(raw) == args.sha256, 'seam_grant_hash')
    grant = json.loads(raw)
    require(grant['schema'] == 'radik.stage05.taskstore_seam_grant.v01'
        and grant['reviewer'] == '/root/private_remote_controls' and grant['approved_executor'] == '/root'
        and grant['approved_invocation_count'] == 1 and grant['network'] == 'DENIED'
        and grant['production_writes_allowed'] is False and grant['real_AUTH_provider_native_E_SAVE_allowed'] is False
        and grant['status'] == 'SOURCE_ACCEPTED_FOR_TARGETED_TASKSTORE_SEAM'
        and grant['max_seconds'] == MAX_SECONDS and grant['work_seconds'] == WORK_SECONDS
        and grant['cleanup_seconds'] == CLEANUP_SECONDS
        and grant['final_readback_seconds'] == FINAL_READBACK_SECONDS and grant['actual_id'] == ACTUAL,
        'seam_independent_grant')
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
    result = dict(schema='radik.stage05.taskstore_seam_result.v01', status='STOPPED_NO_RETRY',
        scope='SYNTHETIC_TYPED_ROLES_WITH_REAL_TASKSTORE_READERS_AND_NATIVE_CONSUMERS',
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
        print('TASKSTORE_SEAM_CHECKPOINT ' + name + ' ' + str(reference['path']), flush=True)
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
        print('TASKSTORE_SEAM_STOP ' + json.dumps(result['primary_failure'], sort_keys=True), flush=True)
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
                print('TASKSTORE_SEAM_STOP ' + json.dumps(result['primary_failure'], sort_keys=True), flush=True)
            else:
                print('TASKSTORE_SEAM_SECONDARY_STOP ' + json.dumps(result['cleanup_failure'], sort_keys=True), flush=True)
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
                    original_work_deadline_ns=WORK_DEADLINE_NS, cleanup_deadline_ns=CLEANUP_DEADLINE_NS,
                    final_readback_deadline_ns=FINAL_DEADLINE_NS, original_hard_deadline_ns=HARD_DEADLINE_NS)
                runner.put(WORK, 'completion.json', canonical(completion))
                require(time.monotonic_ns() < FINAL_DEADLINE_NS, 'seam_absolute_final_cutoff')
                print('TASKSTORE_SEAM_RETURN ' + result['status'], flush=True)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
    return 0 if result['status'] == 'OBSERVED_TARGETED_TASKSTORE_SEAM_REQUIRES_INDEPENDENT_REVIEW' else 1


if __name__ == '__main__':
    raise SystemExit(main())
