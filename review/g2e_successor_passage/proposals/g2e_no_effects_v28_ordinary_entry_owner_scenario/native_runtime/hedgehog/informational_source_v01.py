"""Candidate public NO_EFFECTS dependency authority; never action permission.

Value validation is separate from actual Host enrollment and retained capture.
Every local Root review is recomputed from the supplied causal material. A
parent Root, serialized ACCEPT string or equal capture cannot enroll a source.
"""
from hedgehog.kernel.diagnostic_telemetry_v01 import diagnostic_span_v01 as _diagnostic_span_v01
from dataclasses import dataclass, fields, is_dataclass, replace
import hashlib
import sys as _sys
from contextlib import contextmanager as _contextmanager
from contextvars import ContextVar as _ContextVar
from threading import get_ident as _get_ident
from time import perf_counter_ns as _wall_ns, thread_time_ns as _thread_ns, process_time_ns as _process_ns
from datetime import datetime
from hedgehog import action_commit_packet_v02 as dependency
from hedgehog.kernel import abi_v01 as abi
from hedgehog.kernel import root_decision_v01 as root
from hedgehog.kernel import semantic_work_v01 as semantic
from hedgehog.kernel import trust_model_v01 as trust
from hedgehog.kernel.integrity_replay_v01 import canonical_json_bytes_v01


@dataclass(frozen=True)
class InformationalReviewProfileV01:
    profile_id: str
    domain_id: str
    review_subject: str
    purpose: str


@dataclass(frozen=True)
class InformationalSourceCarrierV01:
    carrier_id: str
    version: str
    authority_kind: str
    task_id: str
    transaction_id: str
    owning_root_id: str
    domain_id: str
    review_profile: InformationalReviewProfileV01
    bsep_sha256: str
    baseline_report_id: str
    baseline_sha256: str
    policy_identity: str
    dependency_candidate: object
    source_artifacts: tuple
    origin_observations: tuple
    origin_invocation_id: str
    origin_result_id: str
    origin_source_sha256: str
    issued_at: int
    valid_from: int
    valid_to: int
    root_kernel: object
    root_input: object
    root_result: object
    effect_access: str = 'NONE'
    permission_ref: None = None
    effect_budget: int = 0


@dataclass(frozen=True)
class InformationalCurrentRootReviewV01:
    carrier_id: str
    source_revision: int
    evaluation_time: int
    evaluation_time_source: str
    evaluation_context_id: str
    observation_ids: tuple[str, ...]
    root_kernel: object
    root_input: object
    root_result: object


@dataclass(frozen=True)
class InformationalInvalidationV01:
    invalidation_id: str
    carrier_id: str
    dependency_id: str
    baseline_artifact_id: str
    observed_artifact: object
    observation_id: str
    source_revision: int
    host_revision: int
    capture_ordinal: int
    evaluation_time: int
    evaluation_time_source: str
    evaluation_context_id: str
    current_root_decision_id: str


def _require(value, code):
    if not value:
        raise ValueError(code)


def _plain(value):
    if value is None or type(value) in (str, int, bool, float):
        return value
    if type(value) is abi.KernelArtifactV01:
        return abi.kernel_artifact_to_plain_dict_v01(value)
    if type(value) is root.RootDecisionInputV01:
        return root.root_decision_input_to_plain_dict_v01(value)
    if type(value) is root.RootDecisionResultV01:
        return root.root_decision_result_to_plain_dict_v01(value)
    if type(value) is root.RootDecisionKernelV01:
        return root.root_decision_kernel_to_plain_dict_v01(value)
    if is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if type(value) in (tuple, list):
        return [_plain(item) for item in value]
    if type(value) is dict:
        return {key: _plain(item) for key, item in value.items()}
    raise ValueError('informational_source_plain_type')


def _digest(value):
    return hashlib.sha256(canonical_json_bytes_v01(_plain(value))).hexdigest()


def build_informational_review_profile_v01(*, domain_id, review_subject):
    _require(all(type(item) is str and 0 < len(item.encode('utf-8')) <= 160
        for item in (domain_id, review_subject)), 'informational_source_review_profile')
    material = dict(domain_id=domain_id, review_subject=review_subject, purpose='BOUNDED_DOCUMENT_SOURCE_REVIEW')
    return InformationalReviewProfileV01('informational_review_profile:' + _digest(material), **material)


def _root_review(material, *, task_id, transaction_id, owning_root_id, evidence_refs,
    topology_ref, policy_id, time_ref, kernel, review_subject):
    candidate_id = 'informational_source_candidate:' + _digest(material)
    bindings = tuple(semantic.build_evidence_binding_v01(evidence_id='informational_evidence:' + _digest(ref),
        evidence_ref=ref, evidence_class='INFORMATIONAL_SOURCE', source_component_id='deterministic_runtime',
        provenance_ref=time_ref, evidence_state='PRESENT') for ref in evidence_refs)
    request = semantic.build_semantic_work_request_v01(request_id=task_id,
        transaction_id=transaction_id, target_root_id=owning_root_id, runtime_topology_ref=topology_ref,
        bounded_context_refs=evidence_refs, permitted_actor_ids=('deterministic_runtime',),
        permitted_contribution_modes=('DETERMINISTIC',), requested_subjects=(review_subject,),
        required_evidence_classes=('INFORMATIONAL_SOURCE',), forbidden_claims=('AUTHORITY', 'PERMISSION',
            'ACTION_COMMIT_PACKET', 'RECEIPT', 'FINAL_OUTPUT', 'DRS_WRITE', 'REAL_WORLD_EFFECT'))
    claim = semantic.build_normalized_claim_v01(claim_id=candidate_id,
        subject=review_subject, predicate='informational_dependency_source', object_or_value=material,
        time_envelope_ref=time_ref, provenance_refs=(time_ref,), evidence_refs=tuple(b.evidence_id for b in bindings),
        confidence_micros=1000000, source_role='deterministic_runtime', source_mode='DETERMINISTIC')
    contribution = semantic.build_actor_contribution_v01(contribution_id='informational_contribution:' + _digest(material),
        request_id=task_id, actor_id='deterministic_runtime', actor_role='deterministic_runtime',
        contribution_mode='DETERMINISTIC', bsep_projection_ref=candidate_id, scope=topology_ref,
        bounded_context_refs=evidence_refs, claims=(claim,), evidence_bindings=bindings,
        constraint_bindings=(), uncertainty_bindings=(), requested_validators=('informational_source_v01',),
        forbidden_claims_observed=())
    profiles = trust.build_default_component_trust_profiles_v01()
    packet = semantic.build_root_review_packet_from_contributions_v01(request=request,
        contributions=(contribution,), trust_profiles=profiles)
    _require(not semantic.validate_root_review_packet_v01(request=request, contributions=(contribution,),
        packet=packet, trust_profiles=profiles), 'informational_source_root_semantics')
    decision_input = root.build_root_decision_input_v01(transaction_id=transaction_id,
        target_root_id=owning_root_id, root_review_packet=packet,
        post_vv_bundle=dict(bundle_id='informational_validation:' + _digest(material), hard_failure_reasons=[],
            post_vv_passed=True, provided_evidence_refs=list(evidence_refs), rejected_candidate_ids=[],
            required_evidence_refs=list(evidence_refs), validated_candidate_ids=[candidate_id]),
        gt_advisory=dict(actor_role='gt', advisory_id='informational_advisory:' + _digest(material),
            advisory_only=True, attempted_effect='CREATE_ROOT_DECISION', candidate_ids=[candidate_id],
            creates_final_output=False, requests_effect=False, score_micros_by_candidate={candidate_id:1000000},
            selected_candidate_id=candidate_id, source_artifact_type='GTAdvisoryReport',
            source_lifecycle_state='VALIDATED', target_artifact_type='RootDecision'),
        policy_state=dict(allow_accept=True, conflict_policy='REJECT', hard_policy_passed=True,
            identity_passed=True, no_candidate_policy='REJECT', policy_id=policy_id, scope_passed=True),
        permission_state=dict(permission_ref=None, permission_required=False,
            permission_scope_valid=True, user_permission_present=False),
        temporal_state=dict(expired=False, not_before_satisfied=True, temporal_valid=True, time_envelope_ref=time_ref),
        conflict_state=dict(conflict_set_ids=[], material_unresolved_conflict=False),
        prior_root_state=dict(prior_decision=None, prior_decision_id=None, prior_selected_candidate_id=None))
    _require(not root.validate_root_decision_input_v01(kernel=kernel, decision_input=decision_input),
        'informational_source_root_input')
    decision = root.decide_root_v01(kernel=kernel, decision_input=decision_input)
    _require(not root.validate_root_decision_result_v01(kernel=kernel, decision_input=decision_input, result=decision)
        and decision.decision == 'ACCEPT' and not decision.permission_created and not decision.final_output_created
        and not decision.effect_requested, 'informational_source_root_result')
    return decision_input, decision


def _material(value):
    return {field.name: _plain(getattr(value, field.name)) for field in fields(value)
        if field.name not in ('carrier_id', 'root_kernel', 'root_input', 'root_result')}


def _baseline_material(baseline):
    with _diagnostic_span_v01('INFO_BASELINE',baseline):
        from hedgehog.kernel import fractal_runtime_v02 as fractal
        _require(type(baseline) is fractal.FractalRuntimeExecutionBundleV02
            and fractal.validate_fractal_runtime_execution_bundle_v02(baseline).status == 'PASS',
            'informational_source_native_baseline')
        source = baseline.source_context
        snapshot = source.router_input.local_routing_snapshot
        _require(snapshot.action_class == 'NON_ACTION', 'informational_source_non_action')
        _require(not baseline.source_binding.downstream_action_packet_required
            and source.root_decision_result.decision == 'ACCEPT', 'informational_source_route')
        return source, snapshot, _digest(fractal.fractal_runtime_execution_bundle_to_plain_data_v02(baseline))


def validate_informational_artifact_time_v01(artifact, *, evaluation_time, valid_from=None, valid_to=None):
    """Bounded document use preserves original artifact validity and PT TTL."""
    _require(not abi.validate_kernel_artifact_v01(artifact) and type(evaluation_time) is int,
        'informational_source_artifact_time')
    envelope = abi.kernel_artifact_to_plain_dict_v01(artifact)['time_envelope']
    def epoch(key):
        return datetime.fromisoformat(envelope[key].replace('Z', '+00:00')).timestamp()
    start, end = epoch('valid_from'), min(epoch('valid_to'), epoch('pt_created_at') + envelope['ttl_seconds'])
    _require(start <= evaluation_time < end and epoch('pt_created_at') <= evaluation_time
        and epoch('kt_asof') <= evaluation_time
        and (envelope['et_observed_at'] is None or epoch('et_observed_at') <= evaluation_time)
        and (valid_from is None or type(valid_from) is int and start <= valid_from)
        and (valid_to is None or type(valid_to) is int and valid_to <= end),
        'informational_source_artifact_time')
    return True


def _validate_informational_source_legacy_v01(value, *, baseline_bundle):
    with _diagnostic_span_v01('INFO_CARRIER',value):
        _require(type(value) is InformationalSourceCarrierV01 and value.version == 'v01'
            and value.authority_kind == 'INFORMATIONAL' and value.effect_access == 'NONE'
            and value.permission_ref is None and type(value.effect_budget) is int and value.effect_budget == 0,
            'informational_source_type_or_effect')
        source, snapshot, baseline_sha = _baseline_material(baseline_bundle)
        _require(type(value.review_profile) is InformationalReviewProfileV01
            and value.review_profile == build_informational_review_profile_v01(domain_id=value.domain_id,
                review_subject=value.review_profile.review_subject), 'informational_source_review_profile')
        _require((value.task_id, value.transaction_id, value.owning_root_id, value.domain_id) ==
            (source.router_input.request_id, source.router_input.transaction_id, source.router_input.owning_root_id,
                snapshot.domain_id) and value.baseline_report_id == baseline_bundle.runtime_report.report_id
            and value.baseline_sha256 == baseline_sha and value.root_kernel == source.root_kernel
            and value.bsep_sha256 == _digest(source.g2c_source_context.bsep_packet)
            and value.policy_identity == snapshot.policy_snapshot_id, 'informational_source_baseline_binding')
        _require(all(type(clock) is int for clock in (value.issued_at, value.valid_from, value.valid_to))
            and value.valid_from <= value.issued_at < value.valid_to
            and snapshot.evaluation_time_epoch_seconds <= value.issued_at
            and value.valid_to <= snapshot.evaluation_time_epoch_seconds + snapshot.ttl_seconds,
            'informational_source_time')
        envelope = abi.kernel_artifact_to_plain_dict_v01(source.route_eligibility_artifact)['time_envelope']
        _require(datetime.fromisoformat(envelope['valid_from'].replace('Z', '+00:00')).timestamp() <= value.valid_from
            and value.valid_to <= datetime.fromisoformat(envelope['valid_to'].replace('Z', '+00:00')).timestamp(),
            'informational_source_route_expiry')
        _require(dependency.validate_dependency_set_candidate_v01(value.dependency_candidate) == (True, ())
            and 1 <= len(value.source_artifacts) <= 4 and type(value.source_artifacts) is tuple,
            'informational_source_dependencies')
        records = value.dependency_candidate.dependency_records
        artifacts = {artifact.artifact_id: artifact for artifact in value.source_artifacts}
        _require(len(artifacts) == len(value.source_artifacts) == len(records), 'informational_source_dependency_inventory')
        origins = {item.dependency_id: item for item in value.origin_observations}
        _require(type(value.origin_observations) is tuple and len(origins) == len(value.origin_observations)
            and set(origins) == set(artifacts), 'informational_source_origin_observation_inventory')
        for record in records:
            artifact = artifacts.get(record.dependency_id)
            _require(artifact is not None and not abi.validate_kernel_artifact_v01(artifact)
                and (artifact.owner_root_id, artifact.transaction_id) == (value.owning_root_id, value.transaction_id)
                and record.evidence_ref == artifact.artifact_id
                and record.content_sha256 == _digest(abi.kernel_artifact_to_plain_dict_v01(artifact)['payload'])
                and record.expected_accepting_local_root_id == value.owning_root_id
                and record.source_provenance_refs == (artifact.artifact_id,), 'informational_source_dependency_binding')
            validate_informational_artifact_time_v01(artifact, evaluation_time=value.issued_at,
                valid_from=value.valid_from, valid_to=value.valid_to)
            observation = origins[record.dependency_id]
            _require(dependency.validate_action_dependency_current_observation_v01(observation) == (True, ())
                and (observation.evidence_ref, observation.observed_content_sha256, observation.time_envelope_id,
                    observation.freshness_policy_id, observation.source_provenance_refs) ==
                    (record.evidence_ref, record.content_sha256, record.time_envelope_id,
                        record.freshness_policy_id, record.source_provenance_refs)
                and observation.valid_from_utc <= value.issued_at < observation.valid_to_utc
                and observation.observed_at_utc <= value.issued_at and value.valid_to <= observation.valid_to_utc,
                'informational_source_origin_observation')
        material = _material(value)
        root_input, root_result = _root_review(material, task_id=value.task_id, transaction_id=value.transaction_id,
            owning_root_id=value.owning_root_id, evidence_refs=(value.origin_result_id, value.baseline_report_id,
                *(artifact.artifact_id for artifact in value.source_artifacts)), topology_ref=baseline_bundle.topology.topology_id,
            policy_id=value.policy_identity, time_ref=source.route_eligibility_artifact.artifact_id,
            kernel=value.root_kernel, review_subject=value.review_profile.review_subject)
        _require(value.root_input == root_input and value.root_result == root_result
            and value.carrier_id == 'informational_source:' + _digest(dict(material=material,
                root_input=root_input, root_result=root_result)), 'informational_source_root_binding')
        return True


def validate_informational_origin_v01(value, *, baseline_bundle, host, invocation, result):
    with _historical_baseline_validation_failure_guard_v20():
        return _validate_informational_origin_with_source_v20(value, baseline_bundle=baseline_bundle,
            host=host, invocation=invocation, result=result, source_validator=validate_informational_source_v01)


def _validate_informational_origin_in_pure_scope_v20(value, *, baseline_bundle, host, invocation, result):
    with _historical_baseline_validation_failure_guard_v20():
        return _validate_informational_origin_with_source_v20(value, baseline_bundle=baseline_bundle,
            host=host, invocation=invocation, result=result, source_validator=_validate_informational_source_in_pure_scope_v20)


def _validate_informational_origin_with_source_v20(value, *, baseline_bundle, host, invocation, result,
    source_validator):
    with _diagnostic_span_v01('INFO_ORIGIN',value):
        source_validator(value, baseline_bundle=baseline_bundle)
        from hedgehog.work_execution_host_v01 import RootWorkExecutionHostV01
        from hedgehog.kernel import effect_firewall_v01 as firewall
        _require(type(host) is RootWorkExecutionHostV01 and host.owning_root_id == value.owning_root_id
            and any(invocation is old_invocation and result is old_result for old_invocation, old_result in host.completed_work),
            'informational_source_origin_not_retained')
        admissions = [item for item in host.admitted_catalogue if item.admission_id == invocation.admission_id]
        _require(len(admissions) == 1 and admissions[0].definition.effect_kind == 'PURE',
            'informational_source_origin_capability')
        admitted = firewall.snapshot_admitted_capability_v01(admissions[0])
        _require(not firewall.validate_capability_execution_result_v01(result, invocation, admitted)
            and result.outcome == 'SUCCEEDED', 'informational_source_origin_execution')
        source_material = canonical_json_bytes_v01([abi.kernel_artifact_to_plain_dict_v01(artifact)['payload']
            for artifact in value.source_artifacts]).decode('utf-8')
        _require(invocation.task_id == value.task_id and invocation.owning_root_id == value.owning_root_id
            and invocation.candidate_id is None and invocation.packet_id is None
            and (invocation.invocation_id, result.result_id) == (value.origin_invocation_id, value.origin_result_id)
            and len(invocation.inputs) == 1 and invocation.inputs[0].parameter_name == 'source_material'
            and invocation.inputs[0].value_type == 'TEXT' and invocation.inputs[0].value == source_material
            and len(result.output) == 1 and result.output[0].parameter_name == 'source_sha256'
            and result.output[0].value_type == 'TEXT' and result.output[0].value == value.origin_source_sha256
            == hashlib.sha256(source_material.encode()).hexdigest(), 'informational_source_origin_binding')
        return True


def _build_informational_source_legacy_v01(*, baseline_bundle, dependency_candidate, source_artifacts,
    origin_host, origin_invocation, origin_result, valid_from, valid_to, review_profile):
    source, snapshot, baseline_sha = _baseline_material(baseline_bundle)
    value = InformationalSourceCarrierV01('', 'v01', 'INFORMATIONAL', source.router_input.request_id,
        source.router_input.transaction_id, source.router_input.owning_root_id, snapshot.domain_id, review_profile,
        _digest(source.g2c_source_context.bsep_packet), baseline_bundle.runtime_report.report_id, baseline_sha,
        snapshot.policy_snapshot_id, dependency_candidate, source_artifacts, origin_host.current_sources.observations,
        origin_invocation.invocation_id,
        origin_result.result_id, origin_result.output[0].value, origin_host.current_sources.evaluation_time,
        valid_from, valid_to, source.root_kernel, None, None)
    material = _material(value)
    root_input, root_result = _root_review(material, task_id=value.task_id, transaction_id=value.transaction_id,
        owning_root_id=value.owning_root_id, evidence_refs=(value.origin_result_id, value.baseline_report_id,
            *(artifact.artifact_id for artifact in value.source_artifacts)), topology_ref=baseline_bundle.topology.topology_id,
        policy_id=value.policy_identity, time_ref=source.route_eligibility_artifact.artifact_id, kernel=value.root_kernel,
        review_subject=value.review_profile.review_subject)
    value = replace(value, carrier_id='informational_source:' + _digest(dict(material=material,
        root_input=root_input, root_result=root_result)), root_input=root_input, root_result=root_result)
    validate_informational_origin_v01(value, baseline_bundle=baseline_bundle, host=origin_host,
        invocation=origin_invocation, result=origin_result)
    return value


def build_informational_current_root_review_v01(carrier, *, baseline_bundle, snapshot):
    with _diagnostic_span_v01('INFO_CURRENT_ROOT',carrier):
        validate_informational_source_v01(carrier, baseline_bundle=baseline_bundle)
        return _build_informational_current_root_from_validated_carrier_v02(carrier,
            baseline_bundle=baseline_bundle,snapshot=snapshot)


def _build_informational_current_root_from_validated_carrier_v02(carrier, *, baseline_bundle, snapshot):
    """Private construction immediately after genuine source validation.

    Only the Host's same-lock enrollment-validation path may call this directly.
    It carries no reusable proof/token and skips no current snapshot or Root check.
    Public callers use the validate-first builder above on every invocation.
    """
    _require(carrier.valid_from <= snapshot.evaluation_time < carrier.valid_to
        and carrier.issued_at <= snapshot.evaluation_time, 'informational_source_current_time')
    records = {record.dependency_id: record for record in carrier.dependency_candidate.dependency_records}
    observations = {observation.dependency_id: observation for observation in snapshot.observations}
    origins = {observation.dependency_id: observation for observation in carrier.origin_observations}
    _require(len(observations) == len(snapshot.observations) and set(records) == set(observations),
        'informational_source_current_inventory')
    for key, observation in observations.items():
        record = records[key]
        _require(dependency.validate_action_dependency_current_observation_v01(observation) == (True, ())
            and (observation.evidence_ref, observation.freshness_policy_id,
                observation.source_provenance_refs, observation.valid_from_utc, observation.valid_to_utc,
                observation.observation_context_id) ==
                (record.evidence_ref, record.freshness_policy_id, record.source_provenance_refs,
                    origins[key].valid_from_utc, origins[key].valid_to_utc,origins[key].observation_context_id)
            and observation.valid_from_utc <= snapshot.evaluation_time < observation.valid_to_utc
            and observation.observed_at_utc <= snapshot.evaluation_time, 'informational_source_current_observation')
    # The public observation validator above authenticates the current content-
    # bound ID. Original identity/history remain committed by the carrier.
    commitment_bindings = tuple(dict(dependency_id=key,
        original_content_sha256=records[key].content_sha256,
        original_time_envelope_id=records[key].time_envelope_id,
        original_observation_id=origins[key].observation_id,
        original_observation_context_id=origins[key].observation_context_id,
        current_content_sha256=observations[key].observed_content_sha256,
        current_time_envelope_id=observations[key].time_envelope_id,
        current_observation_id=observations[key].observation_id,
        current_observation_context_id=observations[key].observation_context_id,
        evidence_ref=records[key].evidence_ref,
        freshness_policy_id=records[key].freshness_policy_id,
        source_provenance_refs=records[key].source_provenance_refs,
        valid_from_utc=origins[key].valid_from_utc,valid_to_utc=origins[key].valid_to_utc)
        for key in sorted(records))
    material = dict(carrier_id=carrier.carrier_id, source_revision=snapshot.source_revision,
        task_id=carrier.task_id,transaction_id=carrier.transaction_id,owning_root_id=carrier.owning_root_id,
        commitment_binding_profile='informational_original_current_commitment_v02',
        original_current_commitments=commitment_bindings,
        review_profile=_plain(carrier.review_profile),
        evaluation_time=snapshot.evaluation_time, evaluation_time_source=snapshot.evaluation_time_source,
        evaluation_context_id=snapshot.evaluation_context_id, observations=_plain(snapshot.observations),
        logical_time_bridge=_plain(snapshot.logical_time_bridge))
    root_input, root_result = _root_review(material, task_id=carrier.task_id, transaction_id=carrier.transaction_id,
        owning_root_id=carrier.owning_root_id, evidence_refs=(carrier.carrier_id,
            *(observation.observation_id for observation in snapshot.observations)),
        topology_ref=baseline_bundle.topology.topology_id, policy_id=carrier.policy_identity,
        time_ref=baseline_bundle.source_context.route_eligibility_artifact.artifact_id, kernel=carrier.root_kernel,
        review_subject=carrier.review_profile.review_subject)
    return InformationalCurrentRootReviewV01(carrier.carrier_id, snapshot.source_revision, snapshot.evaluation_time,
        snapshot.evaluation_time_source, snapshot.evaluation_context_id,
        tuple(observation.observation_id for observation in snapshot.observations), carrier.root_kernel, root_input, root_result)

def build_informational_invalidation_v01(*, host, capture, observed_artifact, require_current=True):
    from hedgehog.work_execution_host_v01 import validate_retained_informational_source_capture_v01
    _require(type(require_current) is bool, 'informational_invalidation_mode')
    validate_retained_informational_source_capture_v01(host, capture, require_current=require_current)
    _require(not abi.validate_kernel_artifact_v01(observed_artifact), 'informational_invalidation_artifact')
    carrier = capture.carrier
    validate_informational_artifact_time_v01(observed_artifact, evaluation_time=capture.evaluation_time,
        valid_to=carrier.valid_to)
    originals = [artifact for artifact in carrier.source_artifacts if artifact.artifact_id in observed_artifact.parent_refs]
    _require(len(originals) == 1, 'informational_invalidation_predecessor')
    original = originals[0]
    observation = next(item for item in capture.observations if item.dependency_id == original.artifact_id)
    _require((observed_artifact.owner_root_id, observed_artifact.transaction_id, observed_artifact.artifact_type) ==
        (original.owner_root_id, original.transaction_id, original.artifact_type)
        and observation.observed_content_sha256 == _digest(abi.kernel_artifact_to_plain_dict_v01(observed_artifact)['payload'])
        and observation.observed_content_sha256 != _digest(abi.kernel_artifact_to_plain_dict_v01(original)['payload']),
        'informational_invalidation_current_binding')
    value = InformationalInvalidationV01('', carrier.carrier_id, original.artifact_id, original.artifact_id,
        observed_artifact, observation.observation_id, capture.source_revision, capture.host_revision,
        capture.capture_ordinal, capture.evaluation_time, capture.evaluation_time_source,
        capture.evaluation_context_id, capture.current_root_review.root_result.decision_id)
    return replace(value, invalidation_id='informational_invalidation:' + _digest(
        {field.name: _plain(getattr(value, field.name)) for field in fields(value) if field.name != 'invalidation_id'}))


def validate_informational_invalidation_v01(value, *, host, capture):
    _require(type(value) is InformationalInvalidationV01
        and value == build_informational_invalidation_v01(host=host, capture=capture,
            observed_artifact=value.observed_artifact, require_current=False), 'informational_invalidation_binding')
    return True


def informational_source_to_plain_data_v01(value):
    _require(type(value) in (InformationalSourceCarrierV01, InformationalCurrentRootReviewV01,
        InformationalInvalidationV01), 'informational_source_plain_type')
    return _plain(value)


# This source profile is selected only by a separately admitted isolated entry.
# Its label commits an algorithm; it is not ownership, permission or a PASS.
OWNED_HISTORICAL_ACQUISITION_PURPOSE_V02 = (
    'BOUNDED_DOCUMENT_SOURCE_REVIEW_OWNED_HISTORICAL_FORMATTER_V02')


def build_informational_review_profile_v02(*, domain_id, review_subject):
    """Build the distinct canonical profile; callers supply no validation proof."""
    _require(all(type(item) is str and 0 < len(item.encode('utf-8')) <= 160
        for item in (domain_id, review_subject)), 'informational_source_review_profile')
    material = dict(domain_id=domain_id, review_subject=review_subject,
        purpose=OWNED_HISTORICAL_ACQUISITION_PURPOSE_V02)
    return InformationalReviewProfileV01('informational_review_profile:' + _digest(material), **material)


def _canonical_owned_profile_v02(profile):
    return (type(profile) is InformationalReviewProfileV01
        and profile.purpose == OWNED_HISTORICAL_ACQUISITION_PURPOSE_V02
        and profile == build_informational_review_profile_v02(domain_id=profile.domain_id,
            review_subject=profile.review_subject))


def _owned_historical_shape_v02(baseline):
    from hedgehog.kernel import fractal_runtime_v02 as fractal
    if type(baseline) is not fractal.FractalRuntimeExecutionBundleV02 \
            or baseline.observed_work_context is not None:
        return False
    source = baseline.source_context
    if type(source) is not fractal.FractalRuntimeSourceContextV02:
        return False
    # Inspect only these three public constructor-backed attributes. Class
    # defaults cannot establish their actual instance presence or ownership.
    attributes = vars(source)
    return all(name in attributes and attributes[name] is None for name in (
        'current_temporal_binding', 'current_temporal_verification',
        'current_observed_work_context'))


def _baseline_material_owned_historical_v02(baseline):
    """Acquire under the admitted no-competing-writer historical entry contract.

    Shape is not an ownership test. Unknown callers must use the legacy entry.
    Every supported call executes the genuine validating formatter. This profile
    explicitly has formatter-first errors and no post-formatter legacy retry.
    """
    if not _owned_historical_shape_v02(baseline):
        return _baseline_material(baseline)
    with _diagnostic_span_v01('INFO_BASELINE', baseline):
        from hedgehog.kernel import fractal_runtime_v02 as fractal
        material = fractal.fractal_runtime_execution_bundle_to_plain_data_v02(baseline)
        source = baseline.source_context
        snapshot = source.router_input.local_routing_snapshot
        _require(snapshot.action_class == 'NON_ACTION', 'informational_source_non_action')
        _require(not baseline.source_binding.downstream_action_packet_required
            and source.root_decision_result.decision == 'ACCEPT', 'informational_source_route')
        return source, snapshot, _digest(material)


_HISTORICAL_BASELINE_CLASSES_V20 = {'hedgehog.kernel.fractal_runtime_v02': ('FractalRuntimePolicyV02', 'FractalRuntimeBudgetV02', 'RuntimeTopologySourceBindingV02', 'RuntimeTopologySeedV02', 'RuntimeTopologyNodeV02', 'RuntimeTopologyEdgeV02', 'RuntimeAssignmentV02', 'RuntimeExecutionTopologyV02', 'ParentChildScopeProjectionV02', 'FractalCellInputV02', 'FractalCellQueueEntryV02', 'FractalReviseObservationV02', 'FractalPartialFailureRecordV02', 'FractalBackpressureStateV02', 'FractalCellResultV02', 'FractalRuntimeTraceV02', 'FractalRuntimeReportV02', 'FractalRuntimeValidationReportV02', 'FractalRuntimeSourceContextV02', 'FractalRuntimeExecutionBundleV02'), 'hedgehog.kernel.execution_mode_router_v01': ('ExecutionModeBSEPBindingV01', 'ExecutionModeReplayBindingV01', 'ExecutionModeG2ABindingV01', 'ExecutionModeG2BBindingV01', 'ExecutionModeLocalModeProfileV01', 'ExecutionModeLocalRoutingSnapshotV01', 'ExecutionModeRouterInputV01', 'ExecutionModeFeasibilityRowV01', 'ExecutionModeProposalV01', 'RootExecutionModeReviewInputV01', 'RootExecutionModeDecisionV01', 'ExecutionModeValidationReportV01', 'ExecutionModeSourceContextV01'), 'hedgehog.kernel.abi_v01': ('_FrozenJSONObject', 'KernelArtifactV01', 'CausalConsumptionRefV01'), 'hedgehog.kernel.root_decision_v01': ('_FrozenJSONObject', 'RootDecisionInputV01', 'RootDecisionResultV01', 'RootDecisionKernelV01'), 'hedgehog.kernel.semantic_work_v01': ('_FrozenJSONObject', 'SemanticWorkRequestV01', 'EvidenceBindingV01', 'ConstraintBindingV01', 'UncertaintyBindingV01', 'NormalizedClaimV01', 'ActorContributionV01', 'ConflictSetV01', 'SynthesisProposalV01', 'RootReviewPacketV01'), 'hedgehog.kernel.transition_registry_v01': ('TransitionRuleV01', 'TransitionDecisionV01', 'TransitionRegistryV01'), 'hedgehog.kernel.trust_model_v01': ('ComponentTrustProfileV01',), 'hedgehog.drs_memory_resolution_v01': ('DRSTemporalQueryV01', 'QueryEvaluationStateV01', 'ResolutionCandidateV01', 'RetrievalPlanV01', 'MemoryDescentBudgetV01', 'MemoryDescentRequestV01', 'MemoryDescentResultV01', 'DRSResolutionReportV01'), 'hedgehog.drs_g2b_compatibility_v01': ('LegacyDRSProjectionV01',), 'hedgehog.drs_semantic_address_v01': ('SemanticAddressV01', 'MemoryPointerV01', 'ArtifactPointerV01', 'LineageEdgeV01', 'DRSAuthorityEnvelopeV01', 'DRSTimeEnvelopeV01', 'MeaningRecordV01'), 'hedgehog.local_drs_resolver': ('SemanticDRSRecordInput', 'SemanticResolveQuery', 'ResolvedDRSCandidate', 'ResolvedDRSReport'), 'hedgehog.local_drs_v02': ('DRSLineageRef', 'DRSFreshnessEnvelope', 'TemporalQueryV02', 'DRSRecordV02', 'DRSReuseDecision', 'DRSResolveReport', 'LocalDRSResolveInputV02', 'DRSResolveTableRowV02', 'DRSReuseDecisionReportV02'), 'hedgehog.reuse_certificate_v01': ('RootShortcutAuthorizationProjectionV01', 'ReuseCertificateV01', 'G2AActionHistoryBindingV01')}
_HISTORICAL_BASELINE_SCOPE_V20 = _ContextVar('historical_baseline_validation_scope_v20', default=None)
_HISTORICAL_BASELINE_MAX_ROWS_V20 = 65536
_HISTORICAL_BASELINE_MAX_EDGES_V20 = 524288


class _HistoricalBaselineEdgesV20:
    """Exact strong graph edges for the finite admitted historical class profile."""
    def __init__(self, baseline):
        self.rows, self.classes = [], []
        self.supported = False
        allowed = set()
        for module_name, names in _HISTORICAL_BASELINE_CLASSES_V20.items():
            module = _sys.modules.get(module_name)
            if module is not None:
                for name in names:
                    cls = vars(module).get(name)
                    if type(cls) is type and cls.__module__ == module_name and cls.__name__ == name:
                        allowed.add(cls)
        active, seen, class_seen = set(), set(), set()
        edge_count = 0

        def visit(value):
            nonlocal edge_count
            cls = type(value)
            if value is None or cls in (str, int, bool, float, bytes):
                return True
            identity = id(value)
            if identity in active:
                return False
            if identity in seen:
                return True
            if len(self.rows) >= _HISTORICAL_BASELINE_MAX_ROWS_V20:
                return False
            active.add(identity)
            if cls in (tuple, list):
                owner, keys, edges = None, None, tuple(value)
            elif cls is dict:
                owner, keys, edges = value, tuple(value), tuple(value.values())
                if any(type(key) is not str for key in keys):
                    return False
            elif cls in allowed and is_dataclass(cls) and cls.__dataclass_params__.frozen \
                    and cls.__getattribute__ is object.__getattribute__ and '__slots__' not in vars(cls):
                owner = object.__getattribute__(value, '__dict__')
                if type(owner) is not dict or any(type(key) is not str for key in owner):
                    return False
                keys, edges = tuple(owner), tuple(owner.values())
                # Include every actual attribute, notably the historical InitVar sidecars.
                if not all(field.name in owner for field in fields(value)):
                    return False
                if cls not in class_seen:
                    class_values = vars(cls)
                    annotations = class_values.get('__annotations__')
                    if '__annotations__' in class_values and type(annotations) is not dict:
                        return False
                    annotation_keys = None if annotations is None else tuple(annotations)
                    annotation_edges = None if annotations is None else tuple(annotations.values())
                    field_rows = tuple((field, field.name, field._field_type) for field in fields(cls))
                    self.classes.append((cls, tuple(class_values), tuple(class_values.values()),
                        annotations, annotation_keys, annotation_edges, field_rows))
                    class_seen.add(cls)
            else:
                return False
            edge_count += len(edges)
            if edge_count > _HISTORICAL_BASELINE_MAX_EDGES_V20:
                return False
            self.rows.append((value, cls, owner, keys, edges))
            if not all(visit(edge) for edge in edges):
                return False
            active.remove(identity)
            seen.add(identity)
            return True

        try:
            self.supported = _owned_historical_shape_v02(baseline) and visit(baseline)
        except (AttributeError, TypeError, RecursionError):
            self.supported = False
        if not self.supported:
            self.rows.clear()
            self.classes.clear()

    @staticmethod
    def _same_edges(current, retained):
        return len(current) == len(retained) and all(a is b for a, b in zip(current, retained))

    def unchanged(self):
        if not self.supported:
            return False
        try:
            for cls, keys, edges, annotations, annotation_keys, annotation_edges, field_rows in self.classes:
                current = vars(cls)
                if not self._same_edges(tuple(current), keys) or not self._same_edges(tuple(current.values()), edges):
                    return False
                if annotations is None:
                    if '__annotations__' in current:
                        return False
                elif current.get('__annotations__') is not annotations \
                        or not self._same_edges(tuple(annotations), annotation_keys) \
                        or not self._same_edges(tuple(annotations.values()), annotation_edges):
                    return False
                current_fields = fields(cls)
                if len(current_fields) != len(field_rows) or any(field is not old or field.name is not name
                        or field._field_type is not kind for field, (old, name, kind) in zip(current_fields, field_rows)):
                    return False
            for value, cls, owner, keys, edges in self.rows:
                if type(value) is not cls:
                    return False
                if keys is None:
                    current = value
                else:
                    current = value if cls is dict else object.__getattribute__(value, '__dict__')
                    if current is not owner or not self._same_edges(tuple(current), keys):
                        return False
                    current = tuple(current.values())
                if not self._same_edges(current, edges):
                    return False
            return True
        except (AttributeError, TypeError):
            return False


class _HistoricalBaselineScopeV20:
    def __init__(self, enabled):
        self.thread, self.enabled, self.busy = _get_ident(), enabled, False
        self.entries = []
        self.stats = {name: 0 for name in ('genuine_baseline_traversals', 'guard_checks', 'guard_hits',
            'guard_wall_ns', 'guard_cpu_ns', 'guard_process_cpu_ns', 'snapshot_wall_ns', 'snapshot_cpu_ns',
            'snapshot_process_cpu_ns', 'fresh_fallbacks', 'unsupported_graphs', 'invalidations')}

    def _guard(self, graph):
        wall, cpu, process = _wall_ns(), _thread_ns(), _process_ns()
        try:
            self.stats['guard_checks'] += 1
            return graph.unchanged()
        finally:
            self.stats['guard_wall_ns'] += _wall_ns() - wall
            self.stats['guard_cpu_ns'] += _thread_ns() - cpu
            self.stats['guard_process_cpu_ns'] += _process_ns() - process

    def material(self, baseline):
        if not self.enabled or self.thread != _get_ident() or self.busy:
            self.entries.clear()
            self.stats['fresh_fallbacks'] += 1
            self.stats['genuine_baseline_traversals'] += 1
            return _baseline_material_owned_historical_v02(baseline)
        self.busy = True
        try:
            for retained, graph, material in self.entries:
                if retained is baseline:
                    if self._guard(graph):
                        self.stats['guard_hits'] += 1
                        return material
                    self.stats['invalidations'] += 1
            self.entries = [(retained, graph, material) for retained, graph, material in self.entries
                if retained is not baseline]
            wall, cpu, process = _wall_ns(), _thread_ns(), _process_ns()
            try:
                graph = _HistoricalBaselineEdgesV20(baseline)
            finally:
                self.stats['snapshot_wall_ns'] += _wall_ns() - wall
                self.stats['snapshot_cpu_ns'] += _thread_ns() - cpu
                self.stats['snapshot_process_cpu_ns'] += _process_ns() - process
            self.stats['genuine_baseline_traversals'] += 1
            material = _baseline_material_owned_historical_v02(baseline)
            if self._guard(graph):
                # A scope may retain at most one baseline; another identity starts cold.
                self.entries[:] = [(baseline, graph, material)]
            else:
                self.stats['unsupported_graphs'] += 1
                self.stats['fresh_fallbacks'] += 1
            return material
        except BaseException:
            self.entries.clear()
            raise
        finally:
            self.busy = False


def _historical_baseline_scope_active_v20():
    scope = _HISTORICAL_BASELINE_SCOPE_V20.get()
    return scope is not None and scope.enabled and not scope.busy and scope.thread == _get_ident()


@_contextmanager
def _historical_baseline_validation_scope_v20(*, enabled=True):
    """Private synchronous structural reuse only; disabled scopes force genuine calls."""
    previous = _HISTORICAL_BASELINE_SCOPE_V20.get()
    if previous is not None and previous.thread == _get_ident() and not previous.busy \
            and (previous.enabled is False or enabled is True):
        try:
            yield previous
        except BaseException:
            previous.entries.clear()
            raise
        return
    scope = _HistoricalBaselineScopeV20(enabled)
    token = _HISTORICAL_BASELINE_SCOPE_V20.set(scope)
    try:
        yield scope
    finally:
        scope.entries.clear()
        _HISTORICAL_BASELINE_SCOPE_V20.reset(token)


@_contextmanager
def _historical_baseline_validation_failure_guard_v20():
    try:
        yield
    except BaseException:
        scope = _HISTORICAL_BASELINE_SCOPE_V20.get()
        if scope is not None:
            scope.entries.clear()
        raise


def _baseline_material_for_pure_scope_v20(baseline):
    scope = _HISTORICAL_BASELINE_SCOPE_V20.get()
    if scope is None:
        return _baseline_material_owned_historical_v02(baseline)
    return scope.material(baseline)


def validate_informational_source_v01(value, *, baseline_bundle):
    """Dispatch only the new exact-purpose contract; legacy inputs keep v01."""
    if (type(value) is InformationalSourceCarrierV01
            and type(value.review_profile) is InformationalReviewProfileV01
            and value.review_profile.purpose == OWNED_HISTORICAL_ACQUISITION_PURPOSE_V02):
        return validate_informational_source_v02(value, baseline_bundle=baseline_bundle)
    return _validate_informational_source_legacy_v01(value, baseline_bundle=baseline_bundle)


def build_informational_source_v01(*, baseline_bundle, dependency_candidate, source_artifacts,
    origin_host, origin_invocation, origin_result, valid_from, valid_to, review_profile):
    """Keep the legacy builder separate from the owned-profile entry."""
    _require(not (type(review_profile) is InformationalReviewProfileV01
        and review_profile.purpose == OWNED_HISTORICAL_ACQUISITION_PURPOSE_V02),
        'informational_source_profile_builder_mismatch')
    return _build_informational_source_legacy_v01(baseline_bundle=baseline_bundle,
        dependency_candidate=dependency_candidate, source_artifacts=source_artifacts,
        origin_host=origin_host, origin_invocation=origin_invocation, origin_result=origin_result,
        valid_from=valid_from, valid_to=valid_to, review_profile=review_profile)


def validate_informational_source_v02(value, *, baseline_bundle):
    with _historical_baseline_validation_failure_guard_v20():
        return _validate_informational_source_with_baseline_v20(value, baseline_bundle=baseline_bundle,
            baseline_material=_baseline_material_owned_historical_v02)


def _validate_informational_source_in_pure_scope_v20(value, *, baseline_bundle):
    # The Host selects this private entry only after exact profile and scope checks.
    with _historical_baseline_validation_failure_guard_v20():
        return _validate_informational_source_with_baseline_v20(value, baseline_bundle=baseline_bundle,
            baseline_material=_baseline_material_for_pure_scope_v20)


def _validate_informational_source_with_baseline_v20(value, *, baseline_bundle, baseline_material):
    with _diagnostic_span_v01('INFO_CARRIER',value):
        _require(type(value) is InformationalSourceCarrierV01 and value.version == 'v01'
            and value.authority_kind == 'INFORMATIONAL' and value.effect_access == 'NONE'
            and value.permission_ref is None and type(value.effect_budget) is int and value.effect_budget == 0,
            'informational_source_type_or_effect')
        _require(_canonical_owned_profile_v02(value.review_profile)
            and value.review_profile.domain_id == value.domain_id, 'informational_source_review_profile')
        source, snapshot, baseline_sha = baseline_material(baseline_bundle)
        _require((value.task_id, value.transaction_id, value.owning_root_id, value.domain_id) ==
            (source.router_input.request_id, source.router_input.transaction_id, source.router_input.owning_root_id,
                snapshot.domain_id) and value.baseline_report_id == baseline_bundle.runtime_report.report_id
            and value.baseline_sha256 == baseline_sha and value.root_kernel == source.root_kernel
            and value.bsep_sha256 == _digest(source.g2c_source_context.bsep_packet)
            and value.policy_identity == snapshot.policy_snapshot_id, 'informational_source_baseline_binding')
        _require(all(type(clock) is int for clock in (value.issued_at, value.valid_from, value.valid_to))
            and value.valid_from <= value.issued_at < value.valid_to
            and snapshot.evaluation_time_epoch_seconds <= value.issued_at
            and value.valid_to <= snapshot.evaluation_time_epoch_seconds + snapshot.ttl_seconds,
            'informational_source_time')
        envelope = abi.kernel_artifact_to_plain_dict_v01(source.route_eligibility_artifact)['time_envelope']
        _require(datetime.fromisoformat(envelope['valid_from'].replace('Z', '+00:00')).timestamp() <= value.valid_from
            and value.valid_to <= datetime.fromisoformat(envelope['valid_to'].replace('Z', '+00:00')).timestamp(),
            'informational_source_route_expiry')
        _require(dependency.validate_dependency_set_candidate_v01(value.dependency_candidate) == (True, ())
            and 1 <= len(value.source_artifacts) <= 4 and type(value.source_artifacts) is tuple,
            'informational_source_dependencies')
        records = value.dependency_candidate.dependency_records
        artifacts = {artifact.artifact_id: artifact for artifact in value.source_artifacts}
        _require(len(artifacts) == len(value.source_artifacts) == len(records), 'informational_source_dependency_inventory')
        origins = {item.dependency_id: item for item in value.origin_observations}
        _require(type(value.origin_observations) is tuple and len(origins) == len(value.origin_observations)
            and set(origins) == set(artifacts), 'informational_source_origin_observation_inventory')
        for record in records:
            artifact = artifacts.get(record.dependency_id)
            _require(artifact is not None and not abi.validate_kernel_artifact_v01(artifact)
                and (artifact.owner_root_id, artifact.transaction_id) == (value.owning_root_id, value.transaction_id)
                and record.evidence_ref == artifact.artifact_id
                and record.content_sha256 == _digest(abi.kernel_artifact_to_plain_dict_v01(artifact)['payload'])
                and record.expected_accepting_local_root_id == value.owning_root_id
                and record.source_provenance_refs == (artifact.artifact_id,), 'informational_source_dependency_binding')
            validate_informational_artifact_time_v01(artifact, evaluation_time=value.issued_at,
                valid_from=value.valid_from, valid_to=value.valid_to)
            observation = origins[record.dependency_id]
            _require(dependency.validate_action_dependency_current_observation_v01(observation) == (True, ())
                and (observation.evidence_ref, observation.observed_content_sha256, observation.time_envelope_id,
                    observation.freshness_policy_id, observation.source_provenance_refs) ==
                    (record.evidence_ref, record.content_sha256, record.time_envelope_id,
                        record.freshness_policy_id, record.source_provenance_refs)
                and observation.valid_from_utc <= value.issued_at < observation.valid_to_utc
                and observation.observed_at_utc <= value.issued_at and value.valid_to <= observation.valid_to_utc,
                'informational_source_origin_observation')
        material = _material(value)
        root_input, root_result = _root_review(material, task_id=value.task_id, transaction_id=value.transaction_id,
            owning_root_id=value.owning_root_id, evidence_refs=(value.origin_result_id, value.baseline_report_id,
                *(artifact.artifact_id for artifact in value.source_artifacts)), topology_ref=baseline_bundle.topology.topology_id,
            policy_id=value.policy_identity, time_ref=source.route_eligibility_artifact.artifact_id,
            kernel=value.root_kernel, review_subject=value.review_profile.review_subject)
        _require(value.root_input == root_input and value.root_result == root_result
            and value.carrier_id == 'informational_source:' + _digest(dict(material=material,
                root_input=root_input, root_result=root_result)), 'informational_source_root_binding')
        return True

def build_informational_source_v02(*, baseline_bundle, dependency_candidate, source_artifacts,
    origin_host, origin_invocation, origin_result, valid_from, valid_to, review_profile):
    _require(_canonical_owned_profile_v02(review_profile), 'informational_source_review_profile')
    source, snapshot, baseline_sha = _baseline_material_owned_historical_v02(baseline_bundle)
    value = InformationalSourceCarrierV01('', 'v01', 'INFORMATIONAL', source.router_input.request_id,
        source.router_input.transaction_id, source.router_input.owning_root_id, snapshot.domain_id, review_profile,
        _digest(source.g2c_source_context.bsep_packet), baseline_bundle.runtime_report.report_id, baseline_sha,
        snapshot.policy_snapshot_id, dependency_candidate, source_artifacts, origin_host.current_sources.observations,
        origin_invocation.invocation_id,
        origin_result.result_id, origin_result.output[0].value, origin_host.current_sources.evaluation_time,
        valid_from, valid_to, source.root_kernel, None, None)
    material = _material(value)
    root_input, root_result = _root_review(material, task_id=value.task_id, transaction_id=value.transaction_id,
        owning_root_id=value.owning_root_id, evidence_refs=(value.origin_result_id, value.baseline_report_id,
            *(artifact.artifact_id for artifact in value.source_artifacts)), topology_ref=baseline_bundle.topology.topology_id,
        policy_id=value.policy_identity, time_ref=source.route_eligibility_artifact.artifact_id, kernel=value.root_kernel,
        review_subject=value.review_profile.review_subject)
    value = replace(value, carrier_id='informational_source:' + _digest(dict(material=material,
        root_input=root_input, root_result=root_result)), root_input=root_input, root_result=root_result)
    validate_informational_origin_v01(value, baseline_bundle=baseline_bundle, host=origin_host,
        invocation=origin_invocation, result=origin_result)
    return value
