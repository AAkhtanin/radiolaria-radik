"""Bounded native U3 archive tasks; source-reviewed owner/probe entry.

LocalDRS has an explicitly controlled logical clock. This module never claims
UTC-persistent code memory, provider execution, or restored action permission.
"""
import hashlib
import json
import os
import re
import time
from dataclasses import fields, replace
from pathlib import Path

from hedgehog.drs import LocalDRS
from app import pure_capability_work as native

SCHEMA = 'radik.stage07.pure_capability_scenario.v01'
SELECTORS = ('pure_capability_owner_v01', 'pure_capability_probe_v01')
TICKS = {'cold': 1014, 'warm': 1015, 'controls': 1016, 'disabled': 1017}
IDENTITY_WAT = b'(module (func (export "transform") (param i32) (result i32) local.get 0))'


def save(path, value):
    data = native.canonical(value) + b'\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    native.require(path.read_bytes() == data, 'stage07_witness_readback')
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}


def worker_summary(value):
    return {key: getattr(value, key) for key in ('status', 'reason', 'phase', 'engine_version',
        'profile_version', 'configuration_sha256', 'elapsed_seconds', 'return_code', 'process_reaped', 'measured_fuel')} | {
        'stdout_sha256': hashlib.sha256(value.stdout).hexdigest(),
        'stderr_sha256': hashlib.sha256(value.stderr).hexdigest(), 'trial_count': len(value.trials)}



WORKER_CODES = frozenset((
    'worker_wall_timeout', 'worker_output_limit', 'worker_process_failed', 'engine_pin_mismatch',
    'worker_request_shape', 'worker_request_source', 'worker_input_domain', 'worker_resource_limit',
    'worker_imports', 'worker_output_domain', 'worker_message_limit', 'worker_source_limit', 'worker_source_format',
    'profile_truncated', 'profile_integer_range', 'profile_integer_encoding', 'profile_trailing_data',
    'profile_byte_limit', 'profile_raw_wasm_required', 'profile_function_type', 'profile_function_count',
    'profile_exact_export', 'profile_body_count', 'profile_local_groups', 'profile_local_type_or_count',
    'profile_block_type', 'profile_nesting', 'profile_branch_depth', 'profile_local_index',
    'profile_required_sections', 'profile_section_forbidden', 'profile_opcode_forbidden', 'pure_oracle_mismatch'))


def safe_worker_failure(attempt):
    """Project exact closed native reasons; arbitrary worker text remains evidence."""
    value = attempt.worker_result
    reason = attempt.reason
    error_class = None
    if type(reason) is str and ':' in reason:
        prefix, rest = reason.split(':', 1)
        if prefix in ('ValueError', 'TypeError', 'RuntimeError', 'WasmtimeError', 'Trap', 'ModuleNotFoundError'):
            error_class, reason = prefix, rest
    detail = None
    code = reason if type(reason) is str and reason in WORKER_CODES else 'stage07_worker_reason_not_closed'
    if type(reason) is str:
        match = re.fullmatch(r'(profile_section_forbidden|profile_opcode_forbidden):([0-9]{1,3})', reason)
        if match is not None and 0 <= int(match.group(2)) <= 255:
            code, detail = match.group(1), int(match.group(2))
    phase = value.phase if value.phase in ('startup', 'conversion', 'compile', 'trials', 'complete',
        'trial_refused', 'rejection') else 'UNRECOGNIZED'
    return dict(code=code, error_class=error_class, detail_integer=detail, phase=phase,
        status=value.status if value.status in ('REFUSED', 'SUCCEEDED') else 'UNRECOGNIZED',
        return_code=value.return_code, process_reaped=value.process_reaped)


def resource(task):
    return native.hosts.inspect_pure_need_resources_v01(task['host'], task_id=task['permission'].task_id)


def refusal(task, name, expected, operation):
    """Retain an exact public refusal plus observed absence of forbidden Work."""
    host = task['host']
    before = dict(attempts=len(host.work_attempts), membership=len(host.admitted_catalogue),
        guest_calls=len(host.pure_guest_evidence), revision=host.state_revision,
        resources=native.plain(resource(task)))
    task['current']()
    try:
        operation()
    except ValueError as error:
        if type(error.args) is not tuple or error.args != (expected,):
            raise
    else:
        raise ValueError('stage07_required_refusal_absent')
    after = dict(attempts=len(host.work_attempts), membership=len(host.admitted_catalogue),
        guest_calls=len(host.pure_guest_evidence), revision=host.state_revision,
        resources=native.plain(resource(task)))
    native.require(all(before[key] == after[key] for key in ('attempts', 'membership', 'guest_calls')),
        'stage07_refused_branch_executed_work')
    return dict(control=name, reason=expected, before=before, after=after,
        forbidden_work_executed=False, scope='PUBLIC_NATIVE_REFUSAL')


def run(project, *, folder, scenario, task_selector, on_event, observe_loaded):
    """Execute only this admitted invocation; no prior authority or demo import."""
    started, cpu_started, utc_started = time.monotonic_ns(), time.process_time_ns(), time.time_ns()
    folder = Path(folder)
    native.require(type(scenario) is dict and set(scenario) == {'schema', 'task_selector', 'invocation_id',
        'sources', 'work_wall_seconds'}, 'stage07_scenario_shape')
    native.require(scenario['schema'] == SCHEMA and scenario['task_selector'] == task_selector
        and task_selector in SELECTORS, 'stage07_scenario_selector')
    native.require(type(scenario['invocation_id']) is str and len(scenario['invocation_id']) == 32
        and all(c in '0123456789abcdef' for c in scenario['invocation_id']), 'stage07_invocation_identity')
    native.require(type(scenario['work_wall_seconds']) is int and 1 <= scenario['work_wall_seconds'] <= 240,
        'stage07_work_wall_bound')
    native.require(type(scenario['sources']) is dict and set(scenario['sources']) == set(TICKS), 'stage07_source_set')
    deadline = started + scenario['work_wall_seconds'] * 1_000_000_000
    store_path = folder / 'capability_drs'
    native.require(not store_path.exists() and not store_path.is_symlink(), 'stage07_fresh_store_required')
    store_path.mkdir(parents=True)
    store = LocalDRS(store_path)
    witnesses, workers, tasks = {}, [], {}
    own_root = 'root:radik:stage07:' + scenario['invocation_id']
    # The same owned Root scopes LocalDRS; every task receives a new opaque Host.
    input_dir = folder / 'input'
    input_dir.mkdir(exist_ok=False)
    bindings = {}
    for label in TICKS:
        source = scenario['sources'][label]
        native.require(type(source) is dict and set(source) == {'document', 'revision'}, 'stage07_source_shape')
        code, revision = native.parse_document(source['document'])
        native.require(type(source['revision']) is int and source['revision'] == revision, 'stage07_input_revision')
        path = input_dir / (label + '.txt')
        raw = source['document'].encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        native.require(path.read_bytes() == raw, 'stage07_input_readback')
        bindings[label] = dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw),
            revision=revision, intake_utc_ns=utc_started, deadline_monotonic_ns=deadline)

    def current(label):
        binding = bindings[label]
        native.require(time.monotonic_ns() < deadline and utc_started <= time.time_ns()
            < utc_started + scenario['work_wall_seconds'] * 1_000_000_000,
            'stage07_actual_source_window_expired')
        path = Path(binding['path'])
        native.require(path.is_file() and not path.is_symlink(), 'stage07_source_file_type')
        raw = path.read_bytes()
        native.require(len(raw) == binding['size_bytes'] and hashlib.sha256(raw).hexdigest() == binding['sha256'],
            'stage07_current_source_changed')
        return binding.copy()

    def checkpoint(label, value):
        ref = save(folder / 'witnesses' / (label + '.json'), value)
        witnesses[label] = ref
        on_event(label, {'witness_ref': ref, 'elapsed_ns': time.monotonic_ns() - started,
            'cpu_ns': time.process_time_ns() - cpu_started, 'remaining_ns': max(0, deadline - time.monotonic_ns())})
        return ref

    def bounded(label, operation):
        native.require(time.monotonic_ns() < deadline, 'stage07_work_deadline')
        for task in tasks.values():
            task['current']()
        tick, cpu = time.monotonic_ns(), time.process_time_ns()
        on_event('native_enter', {'span_id': label, 'task_selector': task_selector})
        try:
            result = operation()
        except BaseException:
            # Retain full observed public native state before observational cleanup.
            try:
                failure_ref = save(folder / 'primary_failure_state.json', dict(native_span=label,
                    tasks={k: native.task_witness(v) for k, v in tasks.items()}))
                if label == 'warm_full_retrieval_admission' and 'warm' in tasks:
                    attempts = tasks['warm']['host'].pure_admission_attempts
                    if attempts and not attempts[-1].admitted:
                        on_event('primary_refusal', dict(native_span=label, witness_ref=failure_ref,
                            worker=safe_worker_failure(attempts[-1])))
            except BaseException:
                pass
            # Preserve the original native failure if observational cleanup fails.
            try:
                on_event('native_exit', {'span_id': label, 'status': 'FAILED',
                    'elapsed_ns': time.monotonic_ns() - tick, 'cpu_ns': time.process_time_ns() - cpu})
            except BaseException:
                pass
            raise
        on_event('native_exit', {'span_id': label, 'status': 'RETURNED',
            'elapsed_ns': time.monotonic_ns() - tick, 'cpu_ns': time.process_time_ns() - cpu})
        native.require(time.monotonic_ns() < deadline, 'stage07_work_deadline')
        return result

    def positive_admission(label, attempt, package, ref):
        if package is None or not attempt.admitted:
            projected = safe_worker_failure(attempt)
            error = ValueError(projected['code'])
            try:
                on_event('primary_refusal', dict(native_span=label, witness_ref=ref, worker=projected))
            except BaseException:
                pass
            raise error
        native.require(len(attempt.worker_result.trials) == 256, 'stage07_positive_admission_trial_count')

    def build(label, optional=True):
        current(label)
        result = bounded(label + '_baseline', lambda: native.build_task(
            task_id='task:radik:stage07:' + scenario['invocation_id'] + ':' + label,
            root_id=own_root, document=scenario['sources'][label]['document'], logical_time=TICKS[label],
            current_reader=lambda: current(label), optional=optional))
        tasks[label] = result
        checkpoint(label + '_need_observed', native.task_witness(result))
        return result

    def finish(label, task, package):
        current(label)
        outcome = bounded(label + '_continuation', lambda: native.continue_task(task, package))
        for value in task['host'].pure_guest_evidence:
            workers.append(worker_summary(value.worker_result))
        checkpoint(label + '_consumed', {'task': native.task_witness(task),
            'continuation': {k: native.plain(v) for k, v in outcome.items() if k != 'common'}})
        return outcome

    observe_loaded('stage07_before_native')
    cold = build('cold')
    cold['current']()
    cold_search = native.memory.search_pure_need_v01(store, host=cold['host'], need=cold['need'])
    native.memory.validate_pure_search_v01(cold_search, host=cold['host'])
    native.require(cold_search.result.candidate_count == 0 and cold_search.result.candidates == (), 'stage07_cold_store_not_empty')
    checkpoint('cold_search', cold_search)
    review = native.review(cold, cold['need'].need_id, 'approve_finite_archive_generation',
        dict(source_binding=cold['source_binding'], controlled_logical_time=TICKS['cold']))
    checkpoint('cold_root', review)
    cold['current']()
    proposal = native.pure.generate_controlled_pure_candidate_v01(cold['host'], need=cold['need'], expected_revision=cold['host'].state_revision)
    native.require(proposal.oracle == native.pure.pure_need_oracle_v01(cold['need'])
        and proposal.source_freeze == native.pure.pure_source_freeze_v01(), 'stage07_generation_precommit')
    checkpoint('cold_generated', proposal)
    cold['current']()
    attempt, package = bounded('cold_full_admission', lambda: native.pure.admit_pure_candidate_v01(cold['host'],
        need=cold['need'], source=proposal.wat, source_format='wat', contract_version=native.pure.CONTRACT_VERSION,
        expected_revision=cold['host'].state_revision))
    workers.append(worker_summary(attempt.worker_result))
    admitted_ref = checkpoint('cold_admission_return', dict(attempt=attempt, package=package))
    positive_admission('cold_full_admission', attempt, package, admitted_ref)
    on_event('cold_admitted', {'witness_ref': admitted_ref})
    cold_final = finish('cold', cold, package)
    cold['current']()
    record = native.memory.write_pure_memory_v01(store, host=cold['host'], package=package, proposal=proposal)
    native.memory.validate_pure_memory_record_v01(record, package=package, host=cold['host'])
    checkpoint('memory_written', record)

    warm = build('warm')
    native.require(warm['host'] is not cold['host'] and warm['need'].permission.task_id != cold['need'].permission.task_id,
        'stage07_fresh_warm_host')
    retrieval = bounded('warm_full_retrieval_admission', lambda: native.memory.retrieve_pure_memory_v01(
        store, host=warm['host'], need=warm['need']))
    native.memory.validate_pure_memory_retrieval_v01(retrieval, host=warm['host'], need=warm['need'])
    workers.append(worker_summary(retrieval.attempt.worker_result))
    native.require(len(retrieval.attempt.worker_result.trials) == 256 and not warm['host'].pure_generation_proposals,
        'stage07_warm_full_admission_without_generation')
    checkpoint('warm_admitted', retrieval)
    warm_final = finish('warm', warm, retrieval.package)

    controls = build('controls')
    host, need = controls['host'], controls['need']
    observations = []
    observations.append(refusal(controls, 'drs_budget', 'pure_drs_budget', lambda: native.hosts.reserve_pure_need_work_v01(
        host, need=need, kind='drs', byte_count=need.permission.max_drs_bytes + 1, expected_revision=host.state_revision)))
    controls['current']()
    control_proposal = native.pure.generate_controlled_pure_candidate_v01(host, need=need, expected_revision=host.state_revision)
    bad, absent = bounded('control_wrong_oracle', lambda: native.pure.admit_pure_candidate_v01(host, need=need,
        source=IDENTITY_WAT, source_format='wat', contract_version=native.pure.CONTRACT_VERSION, expected_revision=host.state_revision))
    workers.append(worker_summary(bad.worker_result))
    checkpoint('control_oracle_return', dict(attempt=bad, package=absent))
    native.require(absent is None and bad.reason == 'pure_oracle_mismatch' and len(bad.worker_result.trials) == 256
        and len(host.work_attempts) == 1 and len(host.admitted_catalogue) == 2 and not host.pure_guest_evidence,
        'stage07_wrong_oracle_control')
    observations.append(dict(control='wrong_oracle', attempt=native.plain(bad), forbidden_work_executed=False))
    observations.append(refusal(controls, 'wrong_version', 'pure_admission_contract_version', lambda:
        native.pure.admit_pure_candidate_v01(host, need=need, source=control_proposal.wat, source_format='wat',
            contract_version='affine-u8-v00', expected_revision=host.state_revision)))
    good, control_package = bounded('control_positive_admission', lambda: native.pure.admit_pure_candidate_v01(host,
        need=need, source=control_proposal.wat, source_format='wat', contract_version=native.pure.CONTRACT_VERSION,
        expected_revision=host.state_revision))
    workers.append(worker_summary(good.worker_result))
    positive_ref = checkpoint('control_positive_return', dict(attempt=good, package=control_package))
    positive_admission('control_positive_admission', good, control_package, positive_ref)
    on_event('control_positive_admitted', {'witness_ref': positive_ref})
    observations.append(refusal(controls, 'admission_budget', 'pure_admission_exhausted', lambda:
        native.pure.admit_pure_candidate_v01(host, need=need, source=control_proposal.wat, source_format='wat',
            contract_version=native.pure.CONTRACT_VERSION, expected_revision=host.state_revision)))
    drift = control_package.wasm[:-1] + bytes((control_package.wasm[-1] ^ 1,))
    observations.append(refusal(controls, 'wrong_bytes', 'pure_package_byte_drift', lambda:
        native.pure.validate_admitted_pure_package_v01(replace(control_package, wasm=drift,
            wasm_sha256=hashlib.sha256(drift).hexdigest()), host=host, need=need)))
    observations.append(refusal(controls, 'foreign_admission', 'pure_foreign_admission', lambda:
        native.pure.validate_admitted_pure_package_v01(package, host=host, need=need)))
    observations.append(refusal(controls, 'stale_host_revision', 'pure_stale_host_revision', lambda:
        native.hosts.install_admitted_pure_capability_v01(host, package=control_package, need=need,
            expected_revision=host.state_revision - 1)))
    checkpoint('control_refusals', observations)
    control_final = finish('controls', controls, control_package)

    disabled = build('disabled', optional=False)
    disabled_before = len(disabled['host'].work_attempts)
    try:
        native.work.observe_missing_pure_need_v01(disabled['context'])
    except ValueError as error:
        native.require(error.args == ('pure_task_permission_absent',), 'stage07_optional_refusal_reason')
        optional_reason = error.args[0]
    else:
        raise ValueError('stage07_optional_refusal_missing')
    native.require(disabled_before == len(disabled['host'].work_attempts) == 1
        and not disabled['host'].pure_generation_proposals and not disabled['host'].pure_admission_attempts
        and not disabled['host'].pure_guest_evidence, 'stage07_optional_bypass')
    # A separate monotonically later query refuses the unchanged original record.
    # This is an explicitly controlled eligibility observation, not Host revival.
    original_memory = native.canonical(record)
    kwargs = {f.name: getattr(retrieval.query, f.name) for f in fields(retrieval.query)
        if f.name not in ('query_id', 'temporal_query_version')}
    expired_query = native.memory.resolution.build_drs_temporal_query_v01(**(kwargs | {
        'as_of': 2001, 'evaluation_time': 2001, 'evaluation_time_source': 'EXPLICIT_CONTROLLED_FUTURE_EXPIRY'}))
    expired = native.memory.resolution.evaluate_drs_candidate_v01(semantic_address=record.meaning.semantic_address,
        query=expired_query, meaning_record=record.meaning)
    native.require(not expired.eligible_for_ranking and expired.reason_codes
        and native.canonical(record) == original_memory, 'stage07_expired_memory_control')
    checkpoint('controlled_expiry', dict(scope='CONTROLLED_FUTURE_QUERY_NO_HOST_TIME_RESET',
        query=expired_query, evaluation=expired, unchanged_record_sha256=hashlib.sha256(original_memory).hexdigest()))

    checkpoint('controls_completed', dict(refusals=observations, optional_reason=optional_reason,
        optional_task=native.task_witness(disabled), positive_neighbor=control_final['label']))
    observe_loaded('stage07_after_native')
    for label in TICKS:
        current(label)
    native.require(all(value['process_reaped'] and value['return_code'] == 0 for value in workers), 'stage07_worker_reaping')
    native.require(resource(cold).generation_attempts == 1 and resource(cold).admission_attempts == 1
        and resource(warm).generation_attempts == 0 and resource(warm).admission_attempts == 1,
        'stage07_cold_warm_accounting')
    report = dict(schema='radik.stage07.pure_capability_result.v01',
        status='PASS_STAGE07_PURE_CAPABILITY_OWNER' if task_selector == SELECTORS[0] else 'PASS_STAGE07_PURE_CAPABILITY_PROBE',
        task_selector=task_selector, invocation_id=scenario['invocation_id'], witnesses=witnesses,
        source_bindings=bindings, cold_label=cold_final['label'], warm_label=warm_final['label'],
        cold_encoded=cold_final['expected_encoded'], warm_encoded=warm_final['expected_encoded'],
        controlled_provenance='CONTROLLED_DETERMINISTIC', temporal_profile='CONTROLLED_LOGICAL_U3',
        native_ticks=TICKS, future_expiry_tick=2001, fresh_invocation_store=True,
        utc_persistent_memory_claim=False, actual_utc_intake_ns=utc_started, operation_deadline_monotonic_ns=deadline,
        provider_calls=0, model_calls=0, generic_save_calls=0, action_packets=0,
        resources={k: native.plain(resource(v)) for k, v in tasks.items() if v['need'] is not None},
        worker_results=workers, elapsed_ns=time.monotonic_ns() - started, cpu_ns=time.process_time_ns() - cpu_started)
    save(folder / 'result.json', report)
    return report
