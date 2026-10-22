"""Fresh UTC, locally reviewed PURE support-document Work for Stage06.

No transport, file read or provider call occurs inside a capability executor.
Each call owns a fresh admission and Host; retained JSON restores no authority.
"""
import hashlib
import json
import re
import time
from datetime import datetime, timezone

from hedgehog import action_commit_packet_v02 as action
from hedgehog import context_packets as packets, structured_rationale as rationale
from hedgehog import work_execution_host_v01 as hosts
from hedgehog.external_drs import gate5_contracts_v01 as c, gate5_native_v01 as n
from hedgehog.kernel import abi_v01 as abi, effect_firewall_v01 as firewall
from hedgehog.kernel import execution_mode_router_v01 as router, work_composition_v01 as work


def compute(operation, material):
    if operation == 'producer':
        c.shape(material, ('document', 'revision'))
        c.require(type(material['document']) is str and len(material['document']) <= 2048, 'stage06_document_bound')
        match = re.fullmatch(r'Service Rowan support terms\.\nRevision: ([1-9][0-9]*)\.\nSupport call price: ([0-9]+) USD\.\nApplies to informational cost clarification only\.\n', material['document'])
        c.require(match is not None, 'stage06_document_shape')
        revision, price = map(int, match.groups())
        c.require(revision == material['revision'] and 0 <= price <= 100, 'stage06_document_revision_or_price')
        return dict(service='Service Rowan', currency='USD', unit='support_call', unit_price=price,
            revision=revision, document_sha256=hashlib.sha256(material['document'].encode()).hexdigest())
    c.require(operation in ('baseline', 'consumer'), 'stage06_work_operation')
    c.shape(material, ('base_price', 'support_calls', 'terms', 'import_ref', 'body_sha256', 'local_acceptance_ref'))
    c.require(type(material['base_price']) is int and 0 <= material['base_price'] <= 1000
        and type(material['support_calls']) is int and 0 < material['support_calls'] <= 10, 'stage06_consumer_input')
    if operation == 'baseline':
        c.require(all(material[k] is None for k in ('terms', 'import_ref', 'body_sha256', 'local_acceptance_ref')), 'stage06_baseline_external_material')
        return dict(state='NEEDS_SUPPORT_PRICE', currency='USD', base_price=material['base_price'],
            support_calls=material['support_calls'], support_cost=None, total_price=None, source_revision=None)
    terms = material['terms']
    c.shape(terms, ('service', 'currency', 'unit', 'unit_price', 'revision', 'document_sha256'))
    c.require((terms['service'], terms['currency'], terms['unit']) == ('Service Rowan', 'USD', 'support_call'), 'stage06_terms_scope')
    c.require(type(terms['unit_price']) is int and 0 <= terms['unit_price'] <= 100
        and type(terms['revision']) is int and terms['revision'] > 0, 'stage06_terms_values')
    c.hash_value(terms['document_sha256']); c.hash_value(material['body_sha256'])
    c.ref(material['import_ref']); c.ref(material['local_acceptance_ref'])
    cost = c.mul(material['support_calls'], terms['unit_price'])
    return dict(state='COST_CLARIFIED', currency='USD', base_price=material['base_price'],
        support_calls=material['support_calls'], support_cost=cost,
        total_price=c.add(material['base_price'], cost), source_revision=terms['revision'])


def validate_inputs(definition, inputs):
    errors = firewall.validate_capability_values_v01(definition.input_fields, inputs)
    if not errors:
        values = {v.parameter_name: v.value for v in inputs}
        try:
            compute(values['operation'], c.decode(values['material'].encode()))
        except (ValueError, KeyError, TypeError):
            errors = ('stage06_invalid_work_input',)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=inputs,
        invocation_id=None, valid=not errors, reason_codes=errors)


def execute(invocation):
    values = {v.parameter_name: v.value for v in invocation.inputs}
    output = compute(values['operation'], c.decode(values['material'].encode()))
    return (action.build_action_effect_parameter_record_v01(parameter_name='result', value_type='TEXT',
        value=c.canonical(output).decode()),)


def validate_outputs(definition, invocation, output):
    errors = firewall.validate_capability_values_v01(definition.output_fields, output)
    if not errors:
        values = {v.parameter_name: v.value for v in invocation.inputs}
        expected = compute(values['operation'], c.decode(values['material'].encode()))
        if len(output) != 1 or output[0].value != c.canonical(expected).decode():
            errors = ('stage06_work_output_mismatch',)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=output,
        invocation_id=invocation.invocation_id, valid=not errors, reason_codes=errors)


def source_context(task_id, now):
    """Real owner-declared informational request; deterministic proposal is advisory."""
    suffix = c.sha(dict(task=task_id, now=now))
    route_id, proposal_id = 'stage06:route:' + suffix, 'stage06:proposal:' + suffix
    vectors, guards = ('stage06:bounded_support_cost',), ('stage06:current_local_root',)
    business = packets.build_business_request_context_packet(packet_id='stage06:business:' + suffix,
        created_by='radik:stage06:owned_intake', domain='RADIK_EXTERNAL_DRS', request_id=task_id,
        business_subject='Service Rowan support cost', requested_action='clarify_informational_cost',
        user_visible_summary='Clarify the cost of support calls from approved current evidence.')
    reference = dict(source='G2C_BUSINESS_REQUEST_CONTEXT_PACKET_V01', packet_id=business['packet_id'],
        request_id=task_id, domain_id=business['domain'])
    route = packets.build_orchestrator_route_context_packet(packet_id='stage06:route_context:' + suffix,
        created_by='radik:stage06:deterministic_route', source_refs=(reference,), domain=business['domain'],
        allowed_routes=(route_id,), required_guards=guards, selected_vector_ids=vectors,
        route_validation_expectations=dict(root_review_required=True, selected_only_allowed_vectors=True),
        orchestrator_is_root=False, creates_action_commit_packet=False, calls_connectors=False)
    proposal = dict(proposal_id=proposal_id, suggested_route=route_id, selected_vector_ids=vectors,
        required_guards=guards, reason='Bounded current support evidence requires local Root review.',
        confidence=1.0, needs_review=True, uncertainty_notes=('Foreign evidence creates no local permission.',),
        root_review_required=True, truth_claimed=False, authority_claimed=False, action_permission_claimed=False,
        final_output_claimed=False, connector_command_claimed=False, drs_write_claimed=False,
        plan_graph_claimed=False, bypass_root_claimed=False,
        semantic_observations=('The local task requests an informational support-cost calculation.',),
        route_reasoning=('Use approved source evidence and the current local Root.',),
        rejected_route_reasoning=('Direct effects are outside this task.',),
        guard_reasoning=('Current source, status and Root review are required.',),
        vector_reasoning=('Only the bounded support-cost task is relevant.',),
        authority_boundary_reasoning=('A foreign signature establishes integrity, not local authority.',))
    structured = rationale.build_orchestrator_structured_rationale(observed_semantics=proposal['semantic_observations'],
        route_selection_reason=proposal['route_reasoning'], rejected_routes=proposal['rejected_route_reasoning'],
        required_guards_reasoning=proposal['guard_reasoning'], selected_vector_reasoning=proposal['vector_reasoning'],
        uncertainty_notes=proposal['uncertainty_notes'], authority_boundary=proposal['authority_boundary_reasoning'],
        root_review_required=True)
    def item(text, kind):
        return packets.semantic_evidence_item(text, source='runtime_canonicalization', evidence_kind=kind, confidence_label='high')
    bsep = packets.build_bounded_semantic_evidence_packet(packet_id='stage06:bsep:' + suffix,
        source_refs=(reference,), domain=business['domain'], source_role='orchestrator', target_role='architect',
        source_route_id=route_id, source_proposal_id=proposal_id, source_context_packet_id=route['packet_id'],
        source_structured_rationale_ref='structured_rationale_v01:' + c.sha(structured),
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
        g2a_evaluation_time_source='radik:stage06:utc', g2a_evaluation_context_id=task_id,
        g2a_transition_registry_profile=None, g2b_resolution_report=None, g2b_compatibility_projections=(),
        g2b_use_time=None, g2b_root_kernel=None, g2b_root_decision_input=None, g2b_root_decision_result=None,
        g2b_writeback_evidence=None)


def perform(root_id, task_id, operation, material, current_reader, evidence_dir):
    """One actual PURE item with fresh current checks and independent local Root."""
    started = time.monotonic_ns()
    baseline = current_reader()
    now = int(time.time())
    source = source_context(task_id, now)
    c.require(router.validate_execution_mode_source_context_v01(source).validation_status == 'PASS', 'stage06_source_context')
    callbacks = (validate_inputs, validate_outputs, execute)
    code = tuple(hosts.observe_local_capability_code_v01(fn) for fn in callbacks)
    fields = tuple(firewall.build_capability_field_v01(name=name, value_type='TEXT', required=True,
        consequential=False) for name in ('operation', 'material'))
    definition = firewall.build_capability_definition_v01(operation_id='radik.stage06.support.' + operation,
        version='v01', effect_kind='PURE', business_semantics=None, input_fields=fields,
        output_fields=(firewall.build_capability_field_v01(name='result', value_type='TEXT', required=True,
            consequential=False),), resource_refs=(), input_validator_ref=code[0].public_symbol,
        output_validator_ref=code[1].public_symbol, executor_ref=code[2].public_symbol,
        code_sha256s=tuple((x.public_symbol, x.source_sha256) for x in code))
    admitted = hosts.admit_local_capability_v01(definition=definition, input_validator=validate_inputs,
        output_validator=validate_outputs, executor=execute, catalogue_revision=0, host_instance_ref='host:' + task_id)
    bridge = action.build_logical_time_bridge_v01(origin_utc_epoch_seconds=now, seconds_per_tick=1,
        bridge_policy_version='radik.stage06.actual_utc.v01')
    snapshot = hosts.TrustedWorkSourceSnapshotV01((), bridge, now, 'radik:stage06:utc', task_id, 0)
    def current_snapshot():
        c.require(now <= int(time.time()) < now + 60, 'stage06_work_snapshot_expired')
        current = current_reader()
        c.require(current == baseline, 'stage06_current_source_changed')
        return current
    class Source:
        def read_current_v01(self):
            current_snapshot()
            return snapshot
    host = hosts.build_root_work_execution_host_v01(owning_root_id=root_id,
        registry=action.build_empty_action_commit_packet_registry_v02(), catalogue=(admitted,), packet_bindings=(),
        current_dependency_observations=(), logical_time_bridge=bridge, trusted_source=Source())
    stamp = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()
    proposal = abi.build_kernel_artifact_v01(abi_version='v1.0', artifact_id='stage06:semantic:' + c.sha(material),
        artifact_type='SemanticArchitectProposal', schema_version='v1', transaction_id='transaction:' + task_id,
        owner_root_id=root_id, source_component='radik:stage06:deterministic', authority_class='ADVISORY',
        lifecycle_state='PROPOSED', payload=dict(operation=operation, material=material, source_binding=baseline),
        trace_refs=(task_id, 'intent:' + task_id), parent_refs=(source.bsep_packet['packet_id'],),
        time_envelope=dict(pt_created_at=stamp(now), kt_asof=stamp(now), et_observed_at=None,
            ct_session_anchor=task_id, ttl_seconds=60, freshness_class='static', valid_from=stamp(now), valid_to=stamp(now+60)))
    literals = tuple(work.WorkInputBindingV01(k, work.WorkLiteralV01(action.build_action_effect_parameter_record_v01(
        parameter_name=k, value_type='TEXT', value=v))) for k, v in (('operation', operation), ('material', c.canonical(material).decode())))
    item = work.WorkItemV01('support', definition.definition_id, root_id, literals, (), (), None, None)
    common = dict(catalogue=(admitted,), source_context=source, semantic_proposal=proposal)
    candidate = work.build_work_program_candidate_v01(task_id=task_id, previous_revision_id=None,
        intent_ref='intent:' + task_id, bsep_ref=source.bsep_packet['packet_id'], semantic_proposal_ref=proposal.artifact_id,
        catalogue_revision=0, budget=work.WorkBudgetV01(1, 0, 0, 1, 0), items=(item,), trigger_evidence_refs=(), **common)
    program = work.materialize_work_program_v01(candidate, **common)
    initial = n.root_review(root_id, 'transaction:' + task_id, candidate.revision_id, task_id,
        dict(current_source=current_snapshot() == baseline, finite_pure=True), dict(material=material, source_binding=baseline), int(time.time()), window=(now, now+60))
    c.require(initial[2].decision == 'ACCEPT', 'stage06_pre_work_root_refused')
    current_snapshot()
    results = work.advance_work_program_v01(program, **common, host_map={root_id:host})
    valid, reasons = work.validate_work_program_result_v01(program, results, **common, host_map={root_id:host})
    c.require(valid and not reasons and len(results) == 1 and results[0].status == 'COMPLETED', 'stage06_native_work_failed')
    artifact = work.work_program_result_to_artifact_v01(program, results, **common, host_map={root_id:host})
    invocation, result = results[0].invocation, results[0].result
    admission_snapshot = firewall.snapshot_admitted_capability_v01(admitted)
    c.require(invocation.candidate_id is None and invocation.packet_id is None
        and not firewall.validate_capability_execution_result_v01(result, invocation, admission_snapshot), 'stage06_pure_boundary')
    output = c.decode(result.output[0].value.encode())
    current = current_snapshot()
    final = n.root_review(root_id, 'transaction:' + task_id, artifact.artifact_id, task_id,
        dict(current_source=current == baseline, exact_output=output == compute(operation, material), one_work=len(host.work_attempts) == 1),
        dict(output=output, input_sha256=c.sha(material), work_artifact=artifact.artifact_id, source_binding=current), int(time.time()), window=(now, now+60))
    c.require(final[2].decision == 'ACCEPT', 'stage06_final_root_refused')
    report = dict(operation=operation, root=root_id, task=task_id, inputs=material, output=output,
        source_context=n.plain(source), proposal=abi.kernel_artifact_to_plain_dict_v01(proposal), program=n.plain(program),
        native_evidence=dict(admission=n.plain(admission_snapshot), invocation=n.plain(invocation), result=n.plain(result)),
        results=n.plain(results), artifact=abi.kernel_artifact_to_plain_dict_v01(artifact),
        initial_review=n.root_plain(initial), final_review=n.root_plain(final), source_binding=current,
        current_clock='ACTUAL_INTEGER_UTC', provider_calls=0, attempts=len(host.work_attempts),
        elapsed_ns=time.monotonic_ns()-started)
    from hedgehog.external_drs.gate5_exchange_v01 import immutable
    immutable(evidence_dir / 'native_work.json', report)
    return report
