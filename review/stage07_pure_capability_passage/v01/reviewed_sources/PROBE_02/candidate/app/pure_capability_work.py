"""Actual PURE archive Work and native same-task U3 continuation.

Native memory uses the declared controlled logical profile; actual UTC source
freshness is independently checked by the application. No reference demo is run.
"""
import base64
import hashlib
import json
import re
from dataclasses import fields, is_dataclass, replace
from datetime import datetime, timezone
from types import MappingProxyType

from hedgehog import action_commit_packet_v02 as action
from hedgehog import capability_admission_v01 as pure
from hedgehog import capability_memory_binding_v01 as memory
from hedgehog import context_packets as packets, structured_rationale as rationale
from hedgehog import work_execution_host_v01 as hosts
from hedgehog.kernel import abi_v01 as abi, effect_firewall_v01 as firewall
from hedgehog.kernel import execution_mode_router_v01 as router, work_composition_v01 as work


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def plain(value):
    if value is None or type(value) in (str, int, bool, float):
        return value
    if type(value) is bytes:
        return {'encoding': 'base64', 'bytes': base64.b64encode(value).decode(),
            'sha256': hashlib.sha256(value).hexdigest(), 'size_bytes': len(value)}
    if isinstance(value, (dict, MappingProxyType)):
        return {str(k): plain(v) for k, v in value.items()}
    if type(value) in (tuple, list):
        return [plain(v) for v in value]
    if type(value) is abi.KernelArtifactV01:
        return abi.kernel_artifact_to_plain_dict_v01(value)
    if type(value) is firewall.AdmittedCapabilityV01:
        return plain(firewall.snapshot_admitted_capability_v01(value))
    if is_dataclass(value):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value) if not f.name.startswith('_')}
    raise ValueError('stage07_unsupported_witness_type')


def canonical(value):
    return json.dumps(plain(value), sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def parse_document(document):
    require(type(document) is str and len(document) <= 512, 'stage07_source_document_bound')
    match = re.fullmatch(r'Archive shelf request\.\nSource code: ([0-9]+)\.\nRevision: ([1-9][0-9]*)\.\nUse: informational shelf label only\.\n', document)
    require(match is not None, 'stage07_source_document_shape')
    code, revision = map(int, match.groups())
    require(0 <= code <= 255, 'stage07_source_code_range')
    return code, revision


def validate_inputs(definition, inputs):
    reasons = firewall.validate_capability_values_v01(definition.input_fields, inputs)
    if not reasons:
        values = {v.parameter_name: v.value for v in inputs}
        try:
            if 'document' in values:
                parse_document(values['document'])
            else:
                require(type(values['value']) is int and 0 <= values['value'] <= 255, 'stage07_encoded_value_range')
        except (ValueError, TypeError):
            reasons = ('stage07_work_input_invalid',)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=inputs,
        invocation_id=None, valid=not reasons, reason_codes=reasons)


def execute_baseline(invocation):
    code, revision = parse_document(next(v.value for v in invocation.inputs if v.parameter_name == 'document'))
    return tuple(action.build_action_effect_parameter_record_v01(parameter_name=k, value_type=t, value=v)
        for k, t, v in (('revision', 'INTEGER', revision), ('source_code', 'INTEGER', code),
            ('state', 'TEXT', 'NEEDS_SHELF_ENCODING')))


def execute_label(invocation):
    value = next(v.value for v in invocation.inputs if v.parameter_name == 'value')
    label = 'SHELF-%02d-BIN-%02d' % (value // 16, value % 16)
    return (action.build_action_effect_parameter_record_v01(parameter_name='label', value_type='TEXT', value=label),)


def validate_outputs(definition, invocation, output):
    reasons = firewall.validate_capability_values_v01(definition.output_fields, output)
    expected = execute_baseline(invocation) if any(v.parameter_name == 'document' for v in invocation.inputs) else execute_label(invocation)
    if not reasons and output != expected:
        reasons = ('stage07_work_output_mismatch',)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=output,
        invocation_id=invocation.invocation_id, valid=not reasons, reason_codes=reasons)


def literal(name, kind, value):
    return work.WorkInputBindingV01(name, work.WorkLiteralV01(action.build_action_effect_parameter_record_v01(
        parameter_name=name, value_type=kind, value=value)))


def admit(operation, input_fields, output_fields, executor, host_ref):
    callbacks = (validate_inputs, validate_outputs, executor)
    code = tuple(hosts.observe_local_capability_code_v01(fn) for fn in callbacks)
    def field(name, kind):
        return firewall.build_capability_field_v01(name=name, value_type=kind, required=True, consequential=False)
    definition = firewall.build_capability_definition_v01(operation_id='radik.stage07.' + operation,
        version='v01', effect_kind='PURE', business_semantics=None,
        input_fields=tuple(field(*x) for x in input_fields), output_fields=tuple(field(*x) for x in output_fields),
        resource_refs=(), input_validator_ref=code[0].public_symbol, output_validator_ref=code[1].public_symbol,
        executor_ref=code[2].public_symbol, code_sha256s=tuple((x.public_symbol, x.source_sha256) for x in code))
    return hosts.admit_local_capability_v01(definition=definition, input_validator=validate_inputs,
        output_validator=validate_outputs, executor=executor, catalogue_revision=0, host_instance_ref=host_ref)


def source_context(task_id, now):
    """Real owner-declared informational request; deterministic proposal is advisory."""
    suffix = digest(dict(task=task_id, now=now))
    route_id, proposal_id = 'stage07:route:' + suffix, 'stage07:proposal:' + suffix
    vectors, guards = ('stage07:bounded_archive_label',), ('stage07:current_local_root',)
    business = packets.build_business_request_context_packet(packet_id='stage07:business:' + suffix,
        created_by='radik:stage07:owned_intake', domain='RADIK_ARCHIVE_SHELF', request_id=task_id,
        business_subject='Archive shelf label', requested_action='derive_informational_shelf_label',
        user_visible_summary='Derive a shelf label from approved current archive source.')
    reference = dict(source='G2C_BUSINESS_REQUEST_CONTEXT_PACKET_V01', packet_id=business['packet_id'],
        request_id=task_id, domain_id=business['domain'])
    route = packets.build_orchestrator_route_context_packet(packet_id='stage07:route_context:' + suffix,
        created_by='radik:stage07:deterministic_route', source_refs=(reference,), domain=business['domain'],
        allowed_routes=(route_id,), required_guards=guards, selected_vector_ids=vectors,
        route_validation_expectations=dict(root_review_required=True, selected_only_allowed_vectors=True),
        orchestrator_is_root=False, creates_action_commit_packet=False, calls_connectors=False)
    proposal = dict(proposal_id=proposal_id, suggested_route=route_id, selected_vector_ids=vectors,
        required_guards=guards, reason='Bounded current shelf source requires local Root review.',
        confidence=1.0, needs_review=True, uncertainty_notes=('Historical capability material creates no permission.',),
        root_review_required=True, truth_claimed=False, authority_claimed=False, action_permission_claimed=False,
        final_output_claimed=False, connector_command_claimed=False, drs_write_claimed=False,
        plan_graph_claimed=False, bypass_root_claimed=False,
        semantic_observations=('The local task requests an informational shelf-label calculation.',),
        route_reasoning=('Use approved source evidence and the current local Root.',),
        rejected_route_reasoning=('Direct effects are outside this task.',),
        guard_reasoning=('Current source, status and Root review are required.',),
        vector_reasoning=('Only the bounded shelf-label task is relevant.',),
        authority_boundary_reasoning=('A code candidate creates no authority before current admission.',))
    structured = rationale.build_orchestrator_structured_rationale(observed_semantics=proposal['semantic_observations'],
        route_selection_reason=proposal['route_reasoning'], rejected_routes=proposal['rejected_route_reasoning'],
        required_guards_reasoning=proposal['guard_reasoning'], selected_vector_reasoning=proposal['vector_reasoning'],
        uncertainty_notes=proposal['uncertainty_notes'], authority_boundary=proposal['authority_boundary_reasoning'],
        root_review_required=True)
    def item(text, kind):
        return packets.semantic_evidence_item(text, source='runtime_canonicalization', evidence_kind=kind, confidence_label='high')
    bsep = packets.build_bounded_semantic_evidence_packet(packet_id='stage07:bsep:' + suffix,
        source_refs=(reference,), domain=business['domain'], source_role='orchestrator', target_role='architect',
        source_route_id=route_id, source_proposal_id=proposal_id, source_context_packet_id=route['packet_id'],
        source_structured_rationale_ref='structured_rationale_v01:' + digest(structured),
        observed_semantic_facts=(item(proposal['semantic_observations'][0], 'observed_fact'),),
        missing_evidence=(item('Local current Root review must precede the Work.', 'missing_evidence'),),
        uncertainty_notes=(item(proposal['uncertainty_notes'][0], 'uncertainty'),),
        risk_boundary_notes=(item('No action permission is requested.', 'risk_boundary'),),
        rejected_action_routes=(item('Consequential routes are not allowed.', 'rejected_route'),),
        required_approvals_or_conditions=(item('Current local Root approval is required.', 'approval_condition'),),
        authority_boundary_notes=(item(proposal['authority_boundary_reasoning'][0], 'authority_boundary'),),
        selected_vector_ids=vectors, required_guards=guards)
    return router.build_execution_mode_source_context_v01(business_request_context_packet=business,
        bsep_packet=bsep, bsep_route_context_packet=route, bsep_orchestrator_proposal=proposal,
        bsep_structured_rationale=structured, sealed_replay_evidence=None, replay_source_manifest=None,
        replay_source_domain_projection=None, replay_source_safe_file_contents=(), replay_anchor_publication=None,
        replay_anchored_verification=None, replay_supplied_anchor_publication_id=None, replay_reconstructed_manifest=None,
        replay_reconstructed_domain_projection=None, replay_reconstructed_safe_file_contents=(), g2a_inspection=None,
        g2a_registry=None, g2a_packet_id=None, g2a_corridor=None, g2a_corridor_step=None,
        g2a_current_dependency_observations=(), g2a_logical_time_bridge=None, g2a_evaluation_time=now,
        g2a_evaluation_time_source='radik:stage07:controlled_logical_u3', g2a_evaluation_context_id=task_id,
        g2a_transition_registry_profile=None, g2b_resolution_report=None, g2b_compatibility_projections=(),
        g2b_use_time=None, g2b_root_kernel=None, g2b_root_decision_input=None, g2b_root_decision_result=None,
        g2b_writeback_evidence=None)



def build_task(*, task_id, root_id, document, logical_time, current_reader, optional=True):
    """Current intake -> actual baseline -> missing need; no code hash is supplied."""
    source_binding = current_reader()
    value, revision = parse_document(document)
    require(source_binding['revision'] == revision, 'stage07_source_revision')
    host_ref = 'host:' + task_id
    baseline = admit('archive_baseline', (('document', 'TEXT'),),
        (('source_code', 'INTEGER'), ('revision', 'INTEGER'), ('state', 'TEXT')), execute_baseline, host_ref)
    consumer = admit('archive_label', (('value', 'INTEGER'),), (('label', 'TEXT'),), execute_label, host_ref)
    catalogue = (baseline, consumer)
    source = source_context(task_id, logical_time)
    require(router.validate_execution_mode_source_context_v01(source).validation_status == 'PASS', 'stage07_source_context')
    stamp = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()
    semantic = abi.build_kernel_artifact_v01(abi_version='v1.0', artifact_id='semantic:' + task_id,
        artifact_type='SemanticArchitectProposal', schema_version='v1', transaction_id='transaction:' + task_id,
        owner_root_id=root_id, source_component='radik:stage07:controlled', authority_class='ADVISORY', lifecycle_state='PROPOSED',
        payload=dict(pure_need=dict(contract_version=pure.CONTRACT_VERSION, work_id='need', multiplier=3, offset=7),
            source_binding=source_binding, provenance='CONTROLLED_DETERMINISTIC',
            temporal_profile='CONTROLLED_LOGICAL_U3', actual_utc_source_binding=source_binding),
        trace_refs=('intent:' + task_id,), parent_refs=(source.bsep_packet['packet_id'],),
        time_envelope=dict(pt_created_at=stamp(logical_time), kt_asof=stamp(logical_time), et_observed_at=None,
            ct_session_anchor=task_id, ttl_seconds=60, freshness_class='static',
            valid_from=stamp(logical_time), valid_to=stamp(logical_time + 60)))
    items = (
        work.WorkItemV01('baseline', baseline.definition.definition_id, root_id,
            (literal('document', 'TEXT', document),), (), (), None, None),
        work.WorkItemV01('need', pure.MISSING_DEFINITION, root_id,
            (work.WorkInputBindingV01('value', work.WorkOutputBindingV01('baseline', 'source_code', 'INTEGER')),),
            (), ('baseline',), None, None),
        work.WorkItemV01('label', consumer.definition.definition_id, root_id,
            (work.WorkInputBindingV01('value', work.WorkOutputBindingV01('need', 'value', 'INTEGER')),),
            (), ('need',), None, None))
    common = dict(catalogue=catalogue, source_context=source, semantic_proposal=semantic)
    candidate = work.build_work_program_candidate_v01(task_id=task_id, previous_revision_id=None,
        intent_ref='intent:' + task_id, bsep_ref=source.bsep_packet['packet_id'], semantic_proposal_ref=semantic.artifact_id,
        catalogue_revision=0, budget=work.WorkBudgetV01(3, 0, 0, 3, 1), items=items, trigger_evidence_refs=(), **common)
    program = work.materialize_work_program_v01(candidate, **common)
    policy = work.build_work_task_policy_v01(candidate, **common, host_instance_ref=host_ref,
        definition_ids=tuple(sorted((pure.MISSING_DEFINITION, baseline.definition.definition_id, consumer.definition.definition_id))),
        resource_refs=())
    permission = work.build_pure_need_permission_v01(program, **common, work_id='need',
        memory_scope='memory:radik:stage07:archive_shelf')
    bridge = action.build_logical_time_bridge_v01(origin_utc_epoch_seconds=1000, seconds_per_tick=1,
        bridge_policy_version='radik.stage07.controlled_logical_u3.v01')
    snapshot = hosts.TrustedWorkSourceSnapshotV01((), bridge, logical_time,
        'radik:stage07:controlled_logical_u3', task_id, revision)
    def current():
        require(current_reader() == source_binding, 'stage07_current_source_changed')
        return source_binding
    class Source:
        def read_current_v01(self):
            current()
            return snapshot
    host = hosts.build_root_work_execution_host_v01(owning_root_id=root_id,
        registry=action.build_empty_action_commit_packet_registry_v02(), catalogue=catalogue, packet_bindings=(),
        current_dependency_observations=(), logical_time_bridge=bridge, trusted_source=Source(),
        task_policies=(policy,), pure_need_permissions=(permission,) if optional else ())
    context = work.enroll_work_program_v01(host, program, **common, expected_revision=host.state_revision)
    current()
    initial = work.advance_work_program_v01(program, **common, host_map={root_id: host}, continuation_context=context)
    require(initial.status == 'NEEDS_CAPABILITY', 'stage07_missing_need_not_observed')
    rows = {r.work_id: r for r in initial.results}
    require(rows['baseline'].status == 'COMPLETED' and rows['need'].invocation is None
        and rows['need'].result is None and rows['label'].status == 'BLOCKED_REQUIRED_OUTPUT', 'stage07_initial_work_shape')
    require(len(host.work_attempts) == 1 and next(v.value for v in rows['baseline'].result.output if v.parameter_name == 'source_code') == value,
        'stage07_baseline_actual_source')
    context = work.work_continuation_context_v01(host, task_id=task_id, expected_revision=host.state_revision)
    return dict(host=host, common=common, initial=initial, permission=permission, context=context,
        need=work.observe_missing_pure_need_v01(context) if optional else None,
        current=current, source_binding=source_binding, document=document)


def review(task, selected_id, predicate, material):
    task['current']()
    result = memory.review_pure_memory_v01(need=task['need'], transaction_id=task['need'].permission.task_id,
        selected_id=selected_id, subject='radik:archive_shelf', predicate=predicate,
        claim_value=material, validation=True)
    require(result[2].decision == 'ACCEPT', 'stage07_current_root_refused')
    return result


def continue_task(task, package):
    host, need = task['host'], task['need']
    task['current']()
    pure.validate_admitted_pure_package_v01(package, host=host, need=need)
    before_root = review(task, package.package_id, 'admit_current_archive_encoding',
        dict(source_binding=task['source_binding'], package_sha256=package.wasm_sha256, need_id=need.need_id))
    resolution = hosts.install_admitted_pure_capability_v01(host, package=package, need=need, expected_revision=host.state_revision)
    context = work.work_continuation_context_v01(host, task_id=need.permission.task_id, expected_revision=host.state_revision)
    trigger = work.build_pure_missing_trigger_v01(context, need=need, resolution=resolution)
    old = task['initial'].program.candidate
    historical = work.build_work_historical_output_v01(context, revision_id=old.revision_id,
        work_id='baseline', output_field='source_code')
    original = next(item for item in old.items if item.work_id == 'need')
    new = replace(original, definition_id=resolution.definition_id, depends_on=(), inputs=(
        literal('package_ref', 'REFERENCE', resolution.package_id), work.WorkInputBindingV01('value', historical)))
    items = tuple(new if item.work_id == 'need' else item for item in old.items if item.work_id != 'baseline')
    common = {**task['common'], 'catalogue': host.admitted_catalogue}
    revised = work.revise_work_program_v01(context, previous_revision_id=old.revision_id, trigger=trigger,
        items=items, budget=work.WorkBudgetV01(2, 0, 0, 2, 0), **common)
    require(revised.status == 'ACTIVE', 'stage07_revision_refused')
    task['current']()
    context = work.work_continuation_context_v01(host, task_id=need.permission.task_id, expected_revision=host.state_revision)
    final = work.advance_work_program_v01(revised.program, **common, host_map={host.owning_root_id: host},
        results=revised.results, continuation_context=context)
    context = work.work_continuation_context_v01(host, task_id=need.permission.task_id, expected_revision=host.state_revision)
    require(work.validate_work_continuation_outcome_v01(final, context=context, **common) == (True, ())
        and final.status == 'COMPLETED', 'stage07_continuation_failed')
    rows = {r.work_id: r for r in final.results}
    guest, consumer = rows['need'], rows['label']
    expected = (need.input_value * 3 + 7) % 256
    label = 'SHELF-%02d-BIN-%02d' % (expected // 16, expected % 16)
    require(guest.result.output[0].value == expected and consumer.invocation.inputs[0].value == expected
        and consumer.consumed_fields[0].source_artifact_id == guest.result.result_id
        and consumer.result.output[0].value == label, 'stage07_actual_consumer_binding')
    history = work.inspect_work_task_history_v01(context)
    require(len(history) == 2 and history[0][0] == task['initial'].program
        and history[0][1] == task['initial'].results and len(host.work_attempts) == 3,
        'stage07_no_predecessor_replay')
    require(len(host.pure_guest_evidence) == 1 and host.pure_guest_evidence[0].invocation is guest.invocation,
        'stage07_guest_evidence_identity')
    pure.validate_pure_guest_evidence_v01(host.pure_guest_evidence[0], host=host)
    for row in (next(r for r in task['initial'].results if r.work_id == 'baseline'), guest, consumer):
        require(row.invocation.candidate_id is None and row.invocation.packet_id is None, 'stage07_pure_effect_boundary')
    final_root = review(task, consumer.result.result_id, 'accept_current_archive_label',
        dict(source_binding=task['source_binding'], need_result_id=guest.result.result_id,
            consumed_fields=plain(consumer.consumed_fields), label=label))
    return dict(resolution=resolution, trigger=trigger, historical_baseline=historical, revision=revised,
        final=final, history=history, pre_install_root=before_root, final_root=final_root, expected_encoded=expected,
        label=label, source_binding=task['source_binding'], common=common)


def task_witness(task):
    host = task['host']
    return dict(initial=plain(task['initial']), need=plain(task['need']), permission=plain(task['permission']),
        source_context=plain(task['common']['source_context']), semantic_proposal=plain(task['common']['semantic_proposal']),
        source_binding=task['source_binding'], current_host_revision=host.state_revision,
        initial_admissions=[plain(firewall.snapshot_admitted_capability_v01(x)) for x in task['common']['catalogue']],
        actual_work_attempts=plain(host.work_attempts), completed_work=plain(host.completed_work),
        pure_guest_evidence=plain(host.pure_guest_evidence),
        generation_proposals=plain(host.pure_generation_proposals), admission_attempts=plain(host.pure_admission_attempts),
        current_admissions=[plain(firewall.snapshot_admitted_capability_v01(x)) for x in host.admitted_catalogue], resources=plain(hosts.inspect_pure_need_resources_v01(
            host, task_id=task['permission'].task_id)) if task['need'] is not None else None)
