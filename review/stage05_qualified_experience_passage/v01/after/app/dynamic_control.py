"""Public G2C/G2D control for exact finite Work review commitments.

The builder can describe deterministic or nested control when required. Actual
short business Work bypasses D. A declared nested route selects full_fractal
and its two native child cells. Native policy is unchanged.
"""
from dataclasses import fields

from hedgehog.kernel import execution_mode_router_v01 as router
from hedgehog.kernel import fractal_runtime_v02 as fractal
from hedgehog.kernel import transition_registry_v01 as transitions
from hedgehog.kernel import work_composition_v01 as work
from hedgehog.kernel import abi_v01 as abi

from . import native_authority as authority
from .contracts import require
from .dynamic_semantics import DOMAIN
from .dynamic_temporal import informational_valid_to, utc_epoch_seconds


def build_control_source(program, common, *, route, now):
    candidate = program.candidate
    item = candidate.items[-1]
    scope = work.build_work_review_scope_ref_v01(candidate=candidate, item=item,
        source_context=common['source_context'], semantic_proposal=common['semantic_proposal'])
    mode_selected = 'full_fractal' if route == 'nested' else 'deterministic'
    ids = dict(request_id=candidate.task_id, transaction_id=common['semantic_proposal'].transaction_id,
        owning_root_id=item.owning_root_id, domain_id=DOMAIN)
    semantic_time = abi.kernel_artifact_to_plain_dict_v01(common['semantic_proposal'])['time_envelope']
    valid_to = informational_valid_to(now, utc_epoch_seconds(semantic_time['valid_to']),
        utc_epoch_seconds(semantic_time['pt_created_at']) + semantic_time['ttl_seconds'])
    profiles = tuple(router.build_execution_mode_local_mode_profile_v01(**ids, mode=mode,
        policy_snapshot_id='radik:dynamic:control_policy', capability_snapshot_id='radik:dynamic:loaded_control',
        cost_model_id='radik:dynamic:finite_cost', policy_allowed=mode == mode_selected,
        scope_allowed=True, risk_allowed=True, privacy_allowed=True,
        capability_state='NOT_REQUIRED' if mode in ('sealed_replay', 'direct_informational_reuse') else 'AVAILABLE',
        capability_id=None if mode in ('sealed_replay', 'direct_informational_reuse') else 'radik:dynamic:control:' + mode,
        cost_units=index + 1) for index, mode in enumerate(router.EXECUTABLE_EXECUTION_MODES_V01))
    snapshot = router.build_execution_mode_local_routing_snapshot_v01(**ids,
        request_class='BOUNDED_REVIEW', action_class='NON_ACTION', action_packet_relation='NOT_APPLICABLE',
        scope_class='BOUNDED', scope_ref=scope, permitted_narrower_scope_refs=(), risk_class='LOW',
        policy_snapshot_id='radik:dynamic:control_policy', capability_snapshot_id='radik:dynamic:loaded_control',
        cost_model_id='radik:dynamic:finite_cost', required_user_input_state='COMPLETE', hard_block_state='CLEAR',
        evaluation_time_epoch_seconds=now, pt_created_at_utc=authority.stamp(now), et_observed_at_utc=authority.stamp(now),
        ct_session_anchor=candidate.task_id, ttl_seconds=valid_to - now, freshness_class='static',
        valid_from_utc=authority.stamp(now), valid_to_utc=authority.stamp(valid_to), mode_profiles=profiles)
    old = common['source_context']
    source = router.build_execution_mode_source_context_v01(**dict(
        {field.name: getattr(old, field.name) for field in fields(old)},
        g2a_evaluation_time=now, g2a_evaluation_time_source=snapshot.created_by,
        g2a_evaluation_context_id=snapshot.local_routing_snapshot_id))
    routing = router.build_execution_mode_router_input_v01(request_id=candidate.task_id,
        transaction_id=ids['transaction_id'], owning_root_id=item.owning_root_id,
        bsep_binding=router.build_execution_mode_bsep_binding_v01(**ids, source_context=source),
        local_routing_snapshot=snapshot,
        replay_binding=router.build_execution_mode_replay_not_applicable_binding_v01(**ids),
        g2a_binding=router.build_execution_mode_g2a_no_packet_binding_v01(**ids, evaluation_time=now,
            evaluation_time_source=snapshot.created_by, evaluation_context_id=snapshot.local_routing_snapshot_id),
        g2b_binding=router.build_execution_mode_g2b_not_applicable_binding_v01(**ids))
    proposal, validation = router.route_execution_mode_v01(router_input=routing, source_context=source)
    require(validation.validation_status == 'PASS' and proposal.selected_mode == mode_selected, 'dynamic_native_control_route')
    artifact = router.project_execution_mode_proposal_kernel_artifact_v01(proposal=proposal, router_input=routing, source_context=source)
    registry = transitions.build_execution_mode_transition_registry_profile_v01()
    before = router.evaluate_execution_mode_proposal_to_root_transition_v01(registry=registry,
        proposal=proposal, router_input=routing, source_context=source, proposal_artifact=artifact)
    review = router.build_root_execution_mode_review_input_v01(proposal=proposal, router_input=routing,
        source_context=source, proposal_artifact=artifact, proposal_transition_decision=before,
        review_action='ACCEPT', accepted_scope_ref=scope, narrowing_basis_refs=())
    decision, kernel, root_input, result, validated = router.review_execution_mode_proposal_v01(
        review_input=review, proposal=proposal, router_input=routing, source_context=source,
        proposal_artifact=artifact, proposal_transition_decision=before)
    require(validated.validation_status == 'PASS' and decision.outcome == 'ACCEPT', 'dynamic_native_control_root')
    args = dict(review_input=review, decision=decision, proposal=proposal, router_input=routing,
        source_context=source, proposal_artifact=artifact, proposal_transition_decision=before,
        root_kernel=kernel, root_decision_input=root_input, root_decision_result=result)
    decision_artifact = router.project_root_execution_mode_decision_kernel_artifact_v01(**args)
    after = router.evaluate_execution_mode_root_route_transition_v01(registry=registry, **args, decision_artifact=decision_artifact)
    eligibility = router.project_execution_mode_route_eligibility_kernel_artifact_v01(**args,
        decision_artifact=decision_artifact, root_route_transition_decision=after)
    args['g2c_source_context'] = args.pop('source_context')
    native = fractal.build_fractal_runtime_source_context_v02(**args, transition_registry=registry,
        decision_artifact=decision_artifact, root_route_transition_decision=after, route_eligibility_artifact=eligibility,
        runtime_policy=fractal.build_fractal_runtime_policy_v02(
            required_downstream_capability_ids=proposal.required_downstream_capability_ids, permitted_child_scope_refs=()))
    return native, dict(common, source_context=source)


