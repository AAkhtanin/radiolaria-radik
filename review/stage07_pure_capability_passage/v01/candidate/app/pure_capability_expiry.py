"""Focused temporal evidence evaluation; never reconstruct Host authority."""
import hashlib
import json
import time
from dataclasses import dataclass, fields
from pathlib import Path

from app import pure_capability_work as native

FOCUS_SELECTOR = 'pure_capability_expiry_tail_v01'


def assert_expired_memory(record, query, checkpoint):
    """Check the same repaired expiry boundary in normal and focused routes."""
    original_memory = native.canonical(record)
    kwargs = {f.name: getattr(query, f.name) for f in fields(query)
        if f.name not in ('query_id', 'temporal_query_version')}
    expired_query = native.memory.resolution.build_drs_temporal_query_v01(**(kwargs | {
        'as_of': 2001, 'evaluation_time': 2001}))
    expired = native.memory.resolution.evaluate_drs_candidate_v01(semantic_address=record.meaning.semantic_address,
        query=expired_query, meaning_record=record.meaning)
    native.require(expired_query.evaluation_time_source == 'INJECTED_CURRENT_DECISION_TIME'
        and expired.query_state == 'BLOCKED_BY_TIME' and not expired.eligible_for_ranking
        and not expired.validity_interval_passed and not expired.ttl_freshness_passed
        and not expired.temporal_hard_gate_passed and not expired.required_time_axes_passed
        and not expired.required_evidence_passed
        and expired.reason_codes == ('drs_time_validity_interval_invalid', 'drs_time_ttl_expired',
            'drs_required_evidence_missing')
        and all(getattr(expired, name) for name in ('scope_passed', 'lifecycle_passed', 'policy_compatible',
            'schema_compatible', 'provenance_passed', 'authority_envelope_passed', 'forbidden_changes_passed',
            'conflict_passed', 'quarantine_passed', 'deadend_passed', 'action_intent_passed',
            'g2a_action_history_passed', 'permission_boundary_passed'))
        and native.canonical(record) == original_memory, 'stage07_expired_memory_control')
    checkpoint('controlled_expiry', dict(scope='CONTROLLED_FUTURE_QUERY_NO_HOST_TIME_RESET',
        interpretation='INELIGIBLE_FOR_RANKING_RETRIEVAL_AND_ADMISSION_NOT_ATTEMPTED_IN_THIS_CONTROL',
        query=expired_query, evaluation=expired, unchanged_record_sha256=hashlib.sha256(original_memory).hexdigest()))


@dataclass(frozen=True)
class HistoricalMeaningEvidence:
    meaning: object


def meaning_from_evidence(value):
    """Rebuild typed context through public builders, without Host or retrieval."""
    address = native.memory.address
    def select(source, names):
        return {name: source[name] for name in names.split()}
    semantic = address.build_semantic_address_v01(**select(value['semantic_address'],
        'namespace domain subject_class intent_class meaning_schema_id meaning_schema_version'))
    pointers = tuple(address.build_artifact_pointer_v01(**select(pointer,
        'storage_class object_reference content_sha256 media_type byte_length access_policy_id sensitivity_class summary_read_permitted payload_read_permitted'),
        allowed_use_classes=tuple(pointer['allowed_use_classes']),
        forbidden_use_classes=tuple(pointer['forbidden_use_classes'])) for pointer in value['artifact_pointers'])
    envelope = address.build_drs_time_envelope_v01(**select(value['time_envelope'],
        'pt_created_at kt_as_of et_observed_at ct_context_anchor ttl_seconds valid_from valid_to source_observed_at source_reported_at system_ingested_at system_verified_at freshness_policy_id'))
    authority = address.build_drs_authority_envelope_v01(**select(value['authority_envelope'],
        'authority_class owning_local_root_id source_root_decision_input_id source_root_decision_id source_root_decision_hash authority_scope_fingerprint root_acceptance_state recording_component'))
    meaning = address.build_meaning_record_v01(**select(value,
        'predecessor_record_id supersession_reason safe_summary resonance_reason persistent_lifecycle_state reuse_policy_class policy_version content_fingerprint recording_component'),
        semantic_address=semantic, artifact_pointers=pointers, memory_pointers=(), lineage_edges=(),
        time_envelope=envelope, authority_envelope=authority,
        **{name: tuple(value[name]) for name in
            ('semantic_tags', 'source_reference_ids', 'risk_hints', 'conflict_hints', 'schema_versions')})
    native.require(address.meaning_record_to_plain_data_v01(meaning) == value,
        'stage07_focused_meaning_roundtrip')
    return meaning


def run_focused(project, *, folder, scenario, task_selector, on_event, observe_loaded, save_record):
    """Observe missing expiry and current ordinary finalization, with zero Work."""
    from config.stage07_io import read_ref
    started, cpu_started = time.monotonic_ns(), time.process_time_ns()
    native.require(task_selector == FOCUS_SELECTOR
        and type(scenario) is dict and set(scenario) ==
            {'schema', 'task_selector', 'invocation_id', 'historical_refs', 'work_wall_seconds'}
        and scenario['schema'] == 'radik.stage07.focused_expiry_tail_scenario.v1'
        and scenario['task_selector'] == FOCUS_SELECTOR
        and type(scenario['work_wall_seconds']) is int and 1 <= scenario['work_wall_seconds'] <= 30,
        'stage07_focused_scenario')
    identity = scenario['invocation_id']
    native.require(type(identity) is str and len(identity) == 32
        and all(char in '0123456789abcdef' for char in identity), 'stage07_focused_identity')
    folder = Path(folder)
    deadline = started + scenario['work_wall_seconds'] * 10**9
    expected = Path(project).parents[3] / 'review/stage07_pure_capability_passage/v01/offline_attempts/PROBE_02/work/application/witnesses'
    refs = scenario['historical_refs']
    native.require(type(refs) is dict and set(refs) == {'memory', 'warm'}
        and refs['memory']['path'] == str(expected/'memory_written.json')
        and refs['warm']['path'] == str(expected/'warm_admitted.json'), 'stage07_focused_input_selection')
    raw = {name: read_ref(reference) for name, reference in refs.items()}
    values = {name: json.loads(data) for name, data in raw.items()}
    native.require(values['memory']['meaning'] == values['warm']['meaning'],
        'stage07_focused_meaning_binding')
    witnesses = {}
    def checkpoint(label, value):
        native.require(time.monotonic_ns() < deadline, 'stage07_focused_deadline')
        reference = save_record(folder/'witnesses'/(label+'.json'), value)
        witnesses[label] = reference
        on_event(label, dict(witness_ref=reference, elapsed_ns=time.monotonic_ns()-started,
            cpu_ns=time.process_time_ns()-cpu_started, remaining_ns=max(0,deadline-time.monotonic_ns())))
        return reference
    checkpoint('historical_inputs_read', dict(input_refs=refs,
        interpretation='HISTORICAL_CONTEXT_DATA_ONLY', Host_restored=False, authority_restored=False))
    callbacks = (native.hosts.observe_local_capability_code_v01,
        native.memory.address.build_semantic_address_v01,
        native.memory.address.build_artifact_pointer_v01,
        native.memory.address.build_drs_time_envelope_v01,
        native.memory.address.build_drs_authority_envelope_v01,
        native.memory.address.build_meaning_record_v01,
        native.memory.resolution.build_drs_temporal_query_v01,
        native.memory.resolution.evaluate_drs_candidate_v01)
    observations = []
    for callback in callbacks:
        snapshot = native.hosts.observe_local_capability_code_v01(callback)
        observations.append(dict(public_symbol=snapshot.public_symbol,
            source_path=callback.__code__.co_filename, source_sha256=snapshot.source_sha256,
            loaded_callable_code_verified=True, capability_admission_created=False))
    checkpoint('focused_native_callbacks', observations)
    on_event('native_enter', dict(span_id='focused_temporal_evaluation', task_selector=task_selector))
    tick, cpu = time.monotonic_ns(), time.process_time_ns()
    try:
        record = HistoricalMeaningEvidence(meaning_from_evidence(values['memory']['meaning']))
        query_data = values['warm']['query']
        kwargs = {key: tuple(value) if type(value) is list else value
            for key, value in query_data.items() if key not in ('query_id', 'temporal_query_version')}
        query = native.memory.resolution.build_drs_temporal_query_v01(**kwargs)
        native.require(native.memory.resolution.drs_temporal_query_to_plain_data_v01(query) == query_data,
            'stage07_focused_query_roundtrip')
        positive = native.memory.resolution.evaluate_drs_candidate_v01(
            semantic_address=record.meaning.semantic_address, query=query, meaning_record=record.meaning)
        native.require(positive.eligible_for_ranking and native.plain(positive) == values['warm']['evaluation'],
            'stage07_focused_positive_evaluation')
        checkpoint('focused_temporal_positive', dict(query=query, evaluation=positive,
            interpretation='CURRENT_EVALUATOR_OVER_HISTORICAL_DATA_NO_RETRIEVAL_OR_HOST'))
        assert_expired_memory(record, query, checkpoint)
    except BaseException:
        try:
            on_event('native_exit', dict(span_id='focused_temporal_evaluation', status='FAILED',
                elapsed_ns=time.monotonic_ns()-tick, cpu_ns=time.process_time_ns()-cpu))
        except BaseException:
            pass
        raise
    on_event('native_exit', dict(span_id='focused_temporal_evaluation', status='RETURNED',
        elapsed_ns=time.monotonic_ns()-tick, cpu_ns=time.process_time_ns()-cpu))
    for name, reference in refs.items():
        native.require(read_ref(reference) == raw[name], 'stage07_focused_input_immutable')
    observe_loaded('focused_after_native')
    report = dict(schema='radik.stage07.focused_expiry_tail_result.v1',
        status='PASS_STAGE07_FOCUSED_EXPIRY_TAIL', task_selector=task_selector, invocation_id=identity,
        scope='FOCUSED_TEMPORAL_EVALUATOR_AND_ORDINARY_FINALIZATION_ONLY', witnesses=witnesses,
        historical_input_refs=refs, worker_results=[], actual_current_native_workers=0,
        actual_Work_dispatches=0, generation_calls=0, admission_calls=0, retrieval_calls=0,
        Host_restored=False, authority_restored=False, provider_calls=0, model_calls=0,
        generic_save_calls=0, action_packets=0, full_semantic_scenario_pass=False,
        elapsed_ns=time.monotonic_ns()-started, cpu_ns=time.process_time_ns()-cpu_started)
    checkpoint('focused_tail_ready', dict(current_worker_count=0, full_semantic_scenario_pass=False))
    save_record(folder/'result.json', report)
    return report
