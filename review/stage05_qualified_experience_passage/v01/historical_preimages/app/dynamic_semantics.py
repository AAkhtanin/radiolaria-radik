"""Current native Root/AVF/BSEP families for finite informational tasks.

No import-time I/O or provider call occurs here. A transport receipt is checked
by DynamicRoleRun before it supplies a product to this adapter.
"""
from dataclasses import dataclass, fields, replace
import json

from hedgehog import avf_v02 as avf
from hedgehog import context_packets as packets, structured_rationale as rationale
from hedgehog import drs_semantic_address_v01 as address, drs_memory_resolution_v01 as resolution
from hedgehog.kernel import execution_mode_router_v01 as router

from . import native_authority as authority
from .contracts import canonical, digest, require
from .dynamic_temporal import INFORMATION_HORIZON_SECONDS, TEMPORAL_POLICY_VERSION, informational_valid_to
from .task_spec import TaskSpec, meaning_key

DOMAIN = 'RADIK_DYNAMIC_INFORMATION'
FAMILY_VERSION = 'radik.dynamic.source_family.v01'
FAMILY_TTL = INFORMATION_HORIZON_SECONDS
_SEAL = object()


def _copy(value):
    return json.loads(canonical(value))


@dataclass(frozen=True)
class NativeSourceFamily:
    """Live objects retain native nominal types; projections are copied data."""
    source_context: object
    binding: object
    route_review: tuple
    native_sha: str
    _scope: bytes
    _product: bytes
    _provenance: bytes
    _evidence: bytes
    _projection: bytes
    _seal: object

    @property
    def family_ref(self):
        return 'radik:dynamic_family:' + self.native_sha

    @property
    def projection(self):
        return json.loads(self._projection)

    @property
    def scope(self):
        return json.loads(self._scope)

    @property
    def product(self):
        return json.loads(self._product)

    @property
    def provenance(self):
        return json.loads(self._provenance)

    @property
    def evidence(self):
        return json.loads(self._evidence)


def _native_digest(family):
    return digest(dict(scope=family.scope, product=family.product, provenance=family.provenance,
        source=authority.plain(family.source_context), binding=authority.plain(family.binding),
        review=authority.root_plain(family.route_review), evidence=family.evidence))


def _consumer_projection(family):
    """Only current selection data and exact producer commitments cross to A."""
    scope, product, evidence = family.scope, family.product, family.evidence
    avf_report = evidence['avf']
    root = family.route_review[2]
    return dict(version=FAMILY_VERSION, family_ref=family.family_ref,
        task_id=scope['task']['task_id'], profile=scope['task']['profile'], route=product['route'],
        source_scope_sha256=digest(scope['source_descriptors']), approved_evidence=_copy(product['evidence_requests']),
        bsep_binding=authority.plain(family.binding), created_at=scope['created_at'], valid_to=scope['valid_to'],
        policy_sha256=digest(scope['policy']),
        worldstate_sha256=digest(scope['worldstate']), temporal_query_id=scope['temporal_query']['query_id'],
        temporal_query_sha256=digest(scope['temporal_query']),
        avf=dict(report_id=avf_report['report_id'], evaluation_id=avf_report['evaluation_id'],
            selected_candidate_id=avf_report['top_candidate_id'], hard_masked_count=avf_report['hard_masked_count'],
            candidate_count=avf_report['candidates_evaluated_count'], report_sha256=digest(avf_report),
            hard_mask_table_sha256=digest(avf_report['hard_mask_table']),
            soft_mask_table_sha256=digest(avf_report['soft_mask_table'])),
        root_route=dict(decision_id=root.decision_id, decision=root.decision,
            selected_candidate_id=root.selected_candidate_id, decision_input_id=family.route_review[1].decision_input_id,
            owning_root_id=scope['root_id'], review_sha256=digest(authority.root_plain(family.route_review)),
            permission_created=root.permission_created, final_output_created=root.final_output_created,
            effect_requested=root.effect_requested),
        structured_rationale_validation=dict(accepted=evidence['structured_rationale_validation']['accepted'],
            validation_sha256=digest(evidence['structured_rationale_validation'])),
        relational_bsep_validation=dict(accepted=evidence['relational_bsep_validation']['accepted'],
            validation_sha256=digest(evidence['relational_bsep_validation'])))


def source_family_witness(family):
    """Full current producer evidence; never substitute it for consumer input."""
    require(type(family) is NativeSourceFamily and family._seal is _SEAL
        and _native_digest(family) == family.native_sha
        and family.projection == _consumer_projection(family), 'dynamic_family_native_binding')
    return dict(version='radik.dynamic.source_family_witness.v01', family_ref=family.family_ref,
        native_sha256=family.native_sha, scope=family.scope, orchestrator_product=family.product,
        orchestrator_provenance=family.provenance, source_context=authority.plain(family.source_context),
        bsep_binding=authority.plain(family.binding), route_review=authority.root_plain(family.route_review),
        producer_evidence=family.evidence, consumer_projection=family.projection)


def build_source_family(spec, orchestrator_product, provenance, sources, *, policy, now, root_id):
    """Root selects a hard-masked route and creates BSEP before Architect."""
    from .dynamic_roles import source_scope
    require(type(spec) is TaskSpec and type(now) is int and now >= spec.created_at,
        'dynamic_family_task_time')
    descriptors = source_scope(sources)
    require({row['source_ref'] for row in descriptors} == set(spec.source_ids), 'dynamic_family_sources')
    product = _copy(orchestrator_product)
    require(product.get('task_id') == spec.task_id and product.get('profile') == spec.profile
        and product.get('criterion') == spec.criterion and product.get('source_scope_sha256') == digest(descriptors)
        and product.get('route') in ('short', 'decomposed', 'nested'), 'dynamic_family_product')
    require(type(product.get('uncertainty')) is str and bool(product['uncertainty'].strip())
        and len(product['uncertainty']) <= 280 and len(product['uncertainty'].encode('utf-8')) <= 512,
        'dynamic_family_uncertainty')
    require(type(provenance) is dict and provenance.get('task_id') == spec.task_id
        and provenance.get('role') == 'orchestrator' and provenance.get('product_sha256') == digest(product)
        and provenance.get('producer_kind') in ('DIRECT_PLAN_ORCHESTRATOR_EMITTED', 'DETERMINISTIC_MEMORY_ROUTE'),
        'dynamic_family_producer')
    require(type(policy) is dict and policy.get('save_allowed') is False and now < policy.get('valid_to', 0),
        'dynamic_family_no_effect_policy')
    transaction_id = 'radik:dynamic_transaction:' + digest(spec.plain())
    scope = dict(version=FAMILY_VERSION, task=spec.plain(), root_id=root_id, transaction_id=transaction_id,
        source_descriptors=descriptors, meaning_key=meaning_key(spec, sources), policy=_copy(policy),
        created_at=now, valid_to=informational_valid_to(now, policy['valid_to']))
    semantic_address = address.build_semantic_address_v01(namespace='radik', domain=DOMAIN,
        subject_class='bounded_informational_task', intent_class=spec.profile,
        meaning_schema_id='radik.dynamic.current', meaning_schema_version='v01')
    temporal_query = resolution.build_drs_temporal_query_v01(query_mode='CURRENT_DECISION',
        semantic_address_id=semantic_address.semantic_address_id,
        scope_fingerprint=digest(dict(meaning=scope['meaning_key'], sources=descriptors, policy=policy)),
        as_of=now, evaluation_time=now, evaluation_time_source='INJECTED_CURRENT_DECISION_TIME',
        time_range_start=now, time_range_end=now + 1, required_time_axes=('PT', 'KT', 'ET', 'CT', 'TTL', 'VALIDITY'),
        freshness_policy_id='radik:dynamic_current', max_age_seconds=scope['valid_to'] - now, domain=DOMAIN, risk_class='LOW',
        reuse_intent='CONTEXT', requested_reuse_classes=('CONTEXT_ONLY',),
        required_evidence_classes=('SOURCE_IDENTITY', 'SOURCE_INTEGRITY', 'PROVENANCE_CHAIN', 'TIME_FITNESS',
            'POLICY_COMPATIBILITY', 'SCHEMA_COMPATIBILITY', 'CONFLICT_CLEARANCE', 'ROOT_DECISION', 'SOURCE_HISTORY'),
        forbidden_changes=('POLICY_CHANGED', 'SCHEMA_CHANGED'), policy_version='radik.dynamic.current.v01',
        schema_versions=('radik.dynamic.current.v01',), owning_local_root_id=root_id)
    scope['worldstate'] = dict(source_descriptors=descriptors, policy_sha256=digest(policy), observed_at=now,
        valid_to=scope['valid_to'], temporal_policy_version=TEMPORAL_POLICY_VERSION, meaning_key=scope['meaning_key'])
    scope['temporal_query'] = resolution.drs_temporal_query_to_plain_data_v01(temporal_query)
    material = dict(scope=scope, product=product, provenance=provenance)
    ref = digest(material)
    routes = ('short', 'decomposed', 'nested')
    candidates = tuple(avf.AVFCandidateV02('dynamic_' + route, 'Bounded informational ' + route,
        base_viability_score=0.9 if route == product['route'] else 0.7) for route in routes) + (
        avf.AVFCandidateV02('expired_reuse', 'Expired material', base_viability_score=1.0, ttl_valid=False),)
    evaluated = avf.evaluate_avf_candidates_v02(avf.AVFEvaluationInputV02(spec.task_id, candidates))
    require(evaluated.top_candidate_id == 'dynamic_' + product['route'] and evaluated.hard_masked_count == 1,
        'dynamic_family_avf')
    review = authority.root_review('dynamic_route:' + ref,
        dict(material=material, avf=authority.plain(evaluated)),
        dict(current_sources=True, bounded_sources=1 <= len(descriptors) <= 4, no_effect=True,
            source_bound_producer=True, hard_masked_expired=True), now,
        transaction_id=transaction_id, owning_root_id=root_id, task_id=spec.task_id)
    require(review[2].decision == 'ACCEPT', 'dynamic_family_root_route')
    business = packets.build_business_request_context_packet(packet_id='dynamic:business:' + ref,
        created_by='radik:owned_intake', domain=DOMAIN, request_id=spec.task_id,
        business_subject='bounded_approved_information', requested_action=spec.profile + '_approved_sources',
        user_visible_summary='Use current approved source spans for the selected informational task.')
    business_ref = dict(source='G2C_BUSINESS_REQUEST_CONTEXT_PACKET_V01', packet_id=business['packet_id'],
        request_id=spec.task_id, domain_id=DOMAIN)
    route_id, vectors, guards = 'dynamic:route:' + product['route'], ('dynamic:vector:' + ref,), ('dynamic:guard:current_root',)
    route = packets.build_orchestrator_route_context_packet(packet_id='dynamic:route_context:' + ref,
        created_by='radik:runtime_canonicalization', source_refs=(business_ref,), domain=DOMAIN,
        allowed_routes=(route_id,), required_guards=guards, selected_vector_ids=vectors,
        route_validation_expectations=dict(root_review_required=True, selected_only_allowed_vectors=True),
        orchestrator_is_root=False, creates_action_commit_packet=False, calls_connectors=False)
    proposal = dict(proposal_id='dynamic:orchestrator:' + ref, suggested_route=route_id,
        selected_vector_ids=vectors, required_guards=guards, reason='Current checked source needs select ' + product['route'],
        confidence=0.75, needs_review=True, uncertainty_notes=(product['uncertainty'],), root_review_required=True,
        truth_claimed=False, authority_claimed=False, action_permission_claimed=False, final_output_claimed=False,
        connector_command_claimed=False, drs_write_claimed=False, plan_graph_claimed=False, bypass_root_claimed=False,
        semantic_observations=('Current approved bytes constrain the finite informational program.',
            'Profile: ' + spec.profile + '; source count: ' + str(len(descriptors)) + '.'),
        route_reasoning=('The checked producer chooses bounded source spans and route.',),
        rejected_route_reasoning=('Expired and foreign material cannot be current evidence.',),
        guard_reasoning=('Current local Root reviews scope and hard masks.',),
        vector_reasoning=('The profile selects a distinct typed business operation.',),
        authority_boundary_reasoning=('Evidence creates no permission or effect.',))
    structured = rationale.build_orchestrator_structured_rationale(observed_semantics=proposal['semantic_observations'],
        route_selection_reason=proposal['route_reasoning'], rejected_routes=proposal['rejected_route_reasoning'],
        required_guards_reasoning=proposal['guard_reasoning'], selected_vector_reasoning=proposal['vector_reasoning'],
        uncertainty_notes=proposal['uncertainty_notes'], authority_boundary=proposal['authority_boundary_reasoning'], root_review_required=True)
    structured_validation = rationale.validate_orchestrator_structured_rationale(structured)
    require(structured_validation['accepted'], 'dynamic_family_rationale')
    def evidence(text, kind):
        return packets.semantic_evidence_item(text, source='runtime_canonicalization', evidence_kind=kind, confidence_label='medium')
    bsep = packets.build_bounded_semantic_evidence_packet(packet_id='dynamic:bsep:' + ref, source_refs=(business_ref,),
        domain=DOMAIN, source_role='orchestrator', target_role='architect', source_route_id=route_id,
        source_proposal_id=proposal['proposal_id'], source_context_packet_id=route['packet_id'],
        source_structured_rationale_ref='structured_rationale_v01:' + digest(structured),
        observed_semantic_facts=tuple(evidence(text, 'observed_fact') for text in proposal['semantic_observations']),
        missing_evidence=(evidence('External truth and entailment are not certified.', 'missing_evidence'),),
        uncertainty_notes=(evidence(product['uncertainty'], 'uncertainty'),),
        risk_boundary_notes=(evidence('This task has no effect authority.', 'risk_boundary'),),
        rejected_action_routes=(evidence('Actions and arbitrary paths are forbidden.', 'rejected_route'),),
        required_approvals_or_conditions=(evidence('Independent current local Root validation.', 'approval_condition'),),
        authority_boundary_notes=(evidence('Historical material restores no permission.', 'authority_boundary'),),
        selected_vector_ids=vectors, required_guards=guards)
    relational = packets.validate_bounded_semantic_evidence_packet(bsep, route_context_packet=route,
        orchestrator_proposal=proposal, structured_rationale_validation=structured_validation)
    require(relational['accepted'], 'dynamic_family_relational_bsep')
    args = {field.name: (() if field.name.endswith(('file_contents', 'observations', 'projections')) else None)
        for field in fields(router.ExecutionModeSourceContextV01)}
    args.update(business_request_context_packet=business, bsep_packet=bsep, bsep_route_context_packet=route,
        bsep_orchestrator_proposal=proposal, bsep_structured_rationale=structured, g2a_evaluation_time=now,
        g2a_evaluation_time_source='radik:trusted_clock', g2a_evaluation_context_id=spec.task_id)
    source = router.build_execution_mode_source_context_v01(**args)
    binding = router.build_execution_mode_bsep_binding_v01(request_id=spec.task_id, transaction_id=transaction_id,
        owning_root_id=root_id, domain_id=DOMAIN, source_context=source)
    require(router.validate_execution_mode_source_context_v01(source).validation_status == 'PASS', 'dynamic_family_native_source')
    evidence = dict(avf=authority.plain(evaluated), structured_rationale_validation=structured_validation,
        relational_bsep_validation=relational)
    provisional = NativeSourceFamily(source, binding, review, '', canonical(scope), canonical(product),
        canonical(provenance), canonical(evidence), b'{}', _SEAL)
    native_sha = _native_digest(provisional)
    provisional = replace(provisional, native_sha=native_sha)
    projection = _consumer_projection(provisional)
    require(len(canonical(projection)) <= 32768, 'dynamic_family_projection_budget')
    return replace(provisional, _projection=canonical(projection))


def validate_current_family(family, sources, *, policy, now):
    from .dynamic_roles import source_scope
    require(type(family) is NativeSourceFamily and family._seal is _SEAL, 'dynamic_family_origin')
    scope = family.scope
    require(type(now) is int and scope['created_at'] <= now < scope['valid_to'], 'dynamic_family_expired')
    require(source_scope(sources) == scope['source_descriptors'] and policy == scope['policy'],
        'dynamic_family_current_binding')
    require(_native_digest(family) == family.native_sha and family.projection == _consumer_projection(family),
        'dynamic_family_native_binding')
    require(router.validate_execution_mode_source_context_v01(family.source_context).validation_status == 'PASS'
        and family.route_review[2].decision == 'ACCEPT', 'dynamic_family_current_root')
    authority.root_plain(family.route_review)
    return family
