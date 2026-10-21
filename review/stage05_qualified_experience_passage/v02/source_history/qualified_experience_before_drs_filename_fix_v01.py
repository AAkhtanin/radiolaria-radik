"""Application custody for native G3 qualified experience and current Work.

This adapter supplies independently retained live sources to the public G3
boundaries. Stored JSON is evidence and never reconstructs a live capability,
source owner, Root decision or permission. The bounded predicate concerns raw
source markers, not provider transport, AUTH, answer quality or external truth.
"""
from dataclasses import dataclass, fields, replace
from datetime import datetime
import json
import os
from pathlib import Path
import time

from hedgehog import action_commit_packet_v02 as actions, avf_v02 as avf, context_packets as packets
from hedgehog import outcome_feedback_v01 as feedback, outcome_calibration_v01 as calibration
from hedgehog import outcome_feedback_history_v01 as history, outcome_feedback_consumer_v01 as consumer
from hedgehog import work_execution_host_v01 as hosts
from hedgehog import drs_semantic_address_v01 as address, drs_memory_resolution_v01 as memory
from hedgehog.kernel import abi_v01 as abi, effect_firewall_v01 as firewall
from hedgehog.kernel import work_composition_v01 as work, execution_mode_router_v01 as router
from hedgehog.kernel import root_decision_v01 as roots

from . import native_authority as authority
from . import qualified_experience_work as pure
from .dynamic_roles import source_scope
from .task_spec import normalized_text

canonical, digest, require = authority.canonical, authority.digest, authority.require
POLICY = 'radik.qualified_experience.v01'
REUSE_SECONDS = 300
_SEAL = object()


def _copy(value):
    return json.loads(canonical(value))


def _envelope(now, valid_to, anchor):
    require(type(now) is int and type(valid_to) is int and now < valid_to, 'experience_expired')
    return dict(pt_created_at=authority.stamp(now), kt_asof=authority.stamp(now), et_observed_at=None,
        ct_session_anchor=anchor, ttl_seconds=valid_to-now, freshness_class='static',
        valid_from=authority.stamp(now), valid_to=authority.stamp(valid_to))


def _artifact(identity, kind, payload, *, root, transaction, envelope, parents=(), component='radik_experience', traces=()):
    return abi.build_kernel_artifact_v01(abi_version='v1.0', artifact_id=identity, artifact_type=kind,
        schema_version='v1', transaction_id=transaction, owner_root_id=root, source_component=component,
        authority_class='ADVISORY' if kind == 'SemanticArchitectProposal' else 'EVIDENCE_ONLY',
        lifecycle_state='PROPOSED' if kind == 'SemanticArchitectProposal' else 'VALIDATED',
        payload=payload, trace_refs=(identity,) + traces, parent_refs=parents, time_envelope=envelope)


def _request_source(source, request_id):
    """Build an independently identified pure check request from retained BSEP."""
    if source.business_request_context_packet['request_id'] == request_id:
        return source
    suffix = digest(dict(request_id=request_id, parent=source.business_request_context_packet['packet_id']))
    business = packets.build_business_request_context_packet(packet_id='radik:experience_business:' + suffix,
        created_by='radik:current_source_qualification', domain=source.business_request_context_packet['domain'],
        request_id=request_id, business_subject='approved_source_integrity', requested_action='verify_source_conditions',
        user_visible_summary='Perform a bounded informational source check under a fresh Root.')
    reference = dict(source='G2C_BUSINESS_REQUEST_CONTEXT_PACKET_V01', packet_id=business['packet_id'],
        request_id=request_id, domain_id=business['domain'])
    prior_route = source.bsep_route_context_packet
    route = packets.build_orchestrator_route_context_packet(packet_id='radik:experience_route:' + suffix,
        created_by='radik:current_source_qualification', source_refs=(reference,), domain=business['domain'],
        allowed_routes=prior_route['allowed_routes'], required_guards=prior_route['required_guards'],
        selected_vector_ids=prior_route['selected_vector_ids'], route_validation_expectations=prior_route['route_validation_expectations'])
    prior = source.bsep_packet
    fields_to_copy = ('source_role', 'target_role', 'source_route_id', 'source_proposal_id',
        'source_structured_rationale_ref', 'observed_semantic_facts', 'missing_evidence', 'uncertainty_notes',
        'risk_boundary_notes', 'rejected_action_routes', 'required_approvals_or_conditions',
        'authority_boundary_notes', 'selected_vector_ids', 'required_guards')
    bsep = packets.build_bounded_semantic_evidence_packet(packet_id='radik:experience_bsep:' + suffix,
        source_refs=(reference,), domain=business['domain'], source_context_packet_id=route['packet_id'],
        **{key:prior[key] for key in fields_to_copy})
    result = replace(source, business_request_context_packet=business, bsep_route_context_packet=route, bsep_packet=bsep)
    require(router.validate_execution_mode_source_context_v01(result).validation_status == 'PASS', 'experience_check_request_source')
    return result


def _closure():
    return {name: digest((Path(__file__).parent / name).read_bytes())
        for name in ('qualified_experience.py', 'qualified_experience_work.py', 'dynamic_roles.py', 'native_authority.py')}


def _scope(controller):
    spec = controller.spec
    return dict(profile=spec.profile, topic=normalized_text(spec.topic), goal=normalized_text(spec.goal),
        criterion=normalized_text(spec.criterion), supplied_candidate_sha256=None if spec.supplied_candidate is None
        else digest(spec.supplied_candidate.encode()), predicate='ABSENCE_OF_EXPLICIT_UNRESOLVED_SOURCE_MARKERS')


def _current(controller):
    sources = _copy(controller.current())
    require(controller.accepted is not None and controller.accepted.controller is controller,
        'experience_requires_actual_accepted_controller')
    controller.validate_native()
    source_scope(sources)
    require(controller.accepted.plain['task'] == controller.spec.plain(), 'experience_accepted_task')
    return sources


def _admit(root, operation, executor):
    callbacks = pure.validate_inputs, pure.validate_outputs, executor
    snapshots = tuple(hosts.observe_local_capability_code_v01(callback) for callback in callbacks)
    definition = firewall.build_capability_definition_v01(operation_id=operation, version='v01', effect_kind='PURE',
        business_semantics=None, input_fields=(firewall.build_capability_field_v01(name='material', value_type='TEXT',
            required=True, consequential=False),), output_fields=(firewall.build_capability_field_v01(name='material',
            value_type='TEXT', required=True, consequential=False),), resource_refs=(),
        input_validator_ref=snapshots[0].public_symbol, output_validator_ref=snapshots[1].public_symbol,
        executor_ref=snapshots[2].public_symbol,
        code_sha256s=tuple((snapshot.public_symbol, snapshot.source_sha256) for snapshot in snapshots))
    return hosts.admit_local_capability_v01(definition=definition, input_validator=callbacks[0],
        output_validator=callbacks[1], executor=callbacks[2], catalogue_revision=0, host_instance_ref=root)


@dataclass(frozen=True)
class ExperienceBinding:
    _owner: object
    _controller: object
    _seal: object
    _context: dict
    _opened: object
    _custody_review: tuple
    _source_scope: tuple
    _work: dict
    report: dict


def validate_strategy_history(controller, selection):
    """Revalidate live custody and history at an explicit G4 boundary."""
    require(type(selection) is ExperienceBinding and selection._seal is _SEAL
        and selection._controller is controller, 'experience_binding_origin')
    context = selection._context
    sources = _current(controller)
    require(tuple(source_scope(sources)) == selection._source_scope
        and digest(_scope(controller)) == context['scope_sha256']
        and _closure() == context['adapter_closure'], 'experience_binding_current_scope')
    now = controller.now()
    require(context['now'] <= now < context['valid_to'], 'experience_binding_expired')
    review = selection._custody_review
    require(not roots.validate_root_decision_result_v01(kernel=review[0], decision_input=review[1], result=review[2])
        and review[2].decision == 'ACCEPT' and review[2].target_root_id == context['root'], 'experience_custody_root')
    opened = selection._opened
    if opened is not None:
        gate = selection._owner._descriptor_gate(context, opened['store'], evaluated_at=now)
        require(gate['eligible'], 'experience_current_history_ineligible')
        opened['store'].validate_opened_v01(opened, bridge=opened['bridge'], evaluation_time=context['now'])
        require(now < selection.report['history_valid_to'], 'experience_history_expired')
    require(selection._owner._bindings.get(selection.report['binding_id']) is selection, 'experience_retained_binding')
    require(selection._owner._binding_reports.get(selection.report['binding_id']) == canonical(selection.report),
        'experience_binding_report_changed')
    return dict(prior_fp=opened['prior']['prior_fp'] if opened else 0,
        disposition='QUALIFIED_CURRENT_HISTORY' if opened else 'COLD_OR_NONMATCHING',
        history_ref=opened['snapshot_id'] if opened else None, custody_root_id=context['root'],
        custody_review=review, source_scope_sha256=digest(source_scope(sources)),
        valid_to=min(context['valid_to'], selection.report['history_valid_to']),
        selected_operation=selection.report['selected_operation'], consumed_work_ref=selection.report['work_result_ref'])


class QualifiedExperience:
    """One finite owner operation; retained source authority is never reloaded."""
    def __init__(self, directory, *, on_event=None):
        self.directory = Path(directory)
        require(not self.directory.is_symlink(), 'experience_directory_symlink')
        self.directory.mkdir(parents=True, exist_ok=True)
        self.on_event = on_event
        self._events, self._stores, self._captures, self._bindings = {}, {}, [], {}
        self._binding_reports = {}
        self._restrictions = {}
        self._origin = object()
        self._ordinal = 0

    def _persist(self, label, value):
        raw = canonical(value)
        path = self.directory / (label + '_' + digest(raw) + '.json')
        if path.exists():
            require(not path.is_symlink() and path.read_bytes() == raw, 'experience_evidence_collision')
        else:
            with path.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            descriptor = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        require(not path.is_symlink() and path.read_bytes() == raw, 'experience_evidence_readback')
        return dict(path=str(path), sha256=digest(raw), bytes=len(raw))

    def _emit(self, stage, **details):
        event = dict(kind='STATUS', phase='NATIVE', stage=stage, semantic_progress=True, **details)
        self._persist('progress', event)
        if self.on_event is not None:
            self.on_event(_copy(event))

    def _context(self, controller, *, ttl_seconds=900):
        sources = _current(controller)
        require(type(ttl_seconds) is int and 1 <= ttl_seconds <= 3600, 'experience_ttl_bound')
        now = controller.now()
        scope_sha = digest(_scope(controller))
        root = 'root:radik:experience:' + scope_sha[:24]
        valid_to = min(now + ttl_seconds, controller.family.scope['valid_to'], controller.initial_policy['valid_to'])
        source = replace(controller.family.source_context, g2a_evaluation_time=now,
            g2a_evaluation_time_source='radik:trusted_clock', g2a_evaluation_context_id=controller.spec.task_id)
        require(router.validate_execution_mode_source_context_v01(source).validation_status == 'PASS', 'experience_current_source')
        transaction = 'transaction:' + source.business_request_context_packet['request_id']
        domain = source.business_request_context_packet['domain']
        revision = digest(dict(adapter=_closure(), source_scope=source_scope(sources)))
        subject = dict(local_root_scope_id=root, domain_scope_id=domain, pack_family_id='RADIK_INFORMATIONAL',
            advisory_source_class='CONTROLLED_RAW_SOURCE_PREDICATE', advisory_source_revision=revision,
            advice_claim_profile_id=feedback.PREDICTIVE_SOURCE_PROFILE_ID, route_family_id='PURE_SOURCE_VERIFICATION',
            task_risk_class='INFORMATIONAL', validation_profile_id='G34_TYPED_BOOLEAN_COMPLETED_WORK_V01',
            policy_semantics_version=POLICY, history_key_profile_id='G3_TYPED_HISTORY_KEY_V01')
        key = {name: subject[name] for name in ('local_root_scope_id', 'domain_scope_id', 'pack_family_id',
            'route_family_id', 'task_risk_class', 'policy_semantics_version', 'advisory_source_revision', 'history_key_profile_id')}
        key.update(task_class_id='SOURCE_MARKERS:' + scope_sha[:24], capability_contract_version='capability:' + digest(_closure()),
            evidence_validation_profile_id=subject['validation_profile_id'])
        context = dict(root=root, now=now, valid_to=valid_to, source=source, transaction=transaction, domain=domain,
            scope_sha256=scope_sha, sources=sources, subject=subject, key=key, controller=controller, adapter_closure=_closure())
        return context

    def _material(self, context):
        semantic_ref = 'radik:experience_semantic:' + digest(dict(scope=context['scope_sha256'],
            sources=source_scope(context['sources']), accepted=context['controller'].accepted.plain['result_id']))
        return dict(version='radik.qualified_material.v01', scope_sha256=context['scope_sha256'],
            accepted_result_sha256=digest(context['controller'].accepted.plain), checks=[dict(semantic_ref=semantic_ref,
                observations=[dict(observation_id='radik:observation:' + digest(row), source=source)
                    for row, source in zip(source_scope(context['sources']), sorted(context['sources'], key=lambda value:value['source_ref']))])])

    def _host(self, context):
        catalogue = (_admit(context['root'], pure.VERIFY, pure.execute_verify),
            _admit(context['root'], pure.AUDIT, pure.execute_audit))
        snapshot = hosts.TrustedWorkSourceSnapshotV01((), actions.build_logical_time_bridge_v01(
            origin_utc_epoch_seconds=context['now'], seconds_per_tick=1, bridge_policy_version=POLICY),
            context['now'], 'radik:trusted_clock', context['controller'].spec.task_id, 0)
        class Source:
            def read_current_v01(inner):
                current = _current(context['controller'])
                require(source_scope(current) == source_scope(context['sources'])
                    and context['controller'].now() < context['valid_to'], 'experience_dispatch_current')
                return snapshot
        host = hosts.build_root_work_execution_host_v01(owning_root_id=context['root'],
            registry=actions.build_empty_action_commit_packet_registry_v02(), catalogue=catalogue, packet_bindings=(),
            current_dependency_observations=(), logical_time_bridge=snapshot.logical_time_bridge, trusted_source=Source())
        return catalogue, host

    def _plain_work(self, context, operation, material, *, check_request=None, task_id=None):
        task_id = task_id or context['controller'].spec.task_id
        context = dict(context, source=_request_source(context['source'], task_id), transaction='transaction:' + task_id)
        catalogue, host = self._host(context)
        definition = next(row.definition.definition_id for row in catalogue if row.definition.operation_id == operation)
        payload = dict(material=material, operation=operation, check_request=check_request)
        proposal = _artifact('radik:experience_proposal:' + digest(payload), 'SemanticArchitectProposal', payload,
            root=context['root'], transaction=context['transaction'], envelope=_envelope(context['now'], context['valid_to'], task_id),
            parents=(context['source'].bsep_packet['packet_id'],), traces=('radik:experience:' + task_id,),
            component='semantic_architect')
        common = dict(catalogue=catalogue, source_context=context['source'], semantic_proposal=proposal)
        item = work.WorkItemV01('source_check', definition, context['root'], (work.WorkInputBindingV01('material',
            work.WorkLiteralV01(authority.records(dict(material=('TEXT', canonical(material).decode())))[0])),), (), (), None, None)
        candidate = work.build_work_program_candidate_v01(task_id=task_id, previous_revision_id=None,
            intent_ref='radik:experience:' + task_id, bsep_ref=context['source'].bsep_packet['packet_id'],
            semantic_proposal_ref=proposal.artifact_id, catalogue_revision=0, budget=work.WorkBudgetV01(1, 0, 0, 1, 0),
            items=(item,), trigger_evidence_refs=(), **common)
        program = work.materialize_work_program_v01(candidate, **common)
        review = authority.root_review(candidate.revision_id, dict(operation=operation, material=material),
            dict(current_sources=True, finite_pure_work=True), context['now'], transaction_id=context['transaction'],
            owning_root_id=context['root'], topology_ref=program.topology_artifact.artifact_id)
        require(review[2].decision == 'ACCEPT', 'experience_pre_work_root')
        results = work.advance_work_program_v01(program, host_map={context['root']:host}, **common)
        require(len(results) == 1 and results[0].status == 'COMPLETED', 'experience_work_incomplete')
        valid, reasons = work.validate_work_program_result_v01(program, results, host_map={context['root']:host}, **common)
        require(valid and not reasons, 'experience_native_work_result')
        artifact = work.work_program_result_to_artifact_v01(program, results, host_map={context['root']:host}, **common)
        output = json.loads(authority.values(results[0].result.output)['material'])
        require(output == pure.compute(material, operation), 'experience_independent_output')
        final = authority.root_review(artifact.artifact_id, output, dict(current_sources=True, actual_work_output=True),
            context['now'], transaction_id=context['transaction'], owning_root_id=context['root'],
            topology_ref=program.topology_artifact.artifact_id)
        require(final[2].decision == 'ACCEPT', 'experience_result_root')
        return dict(program=program, results=results, artifact=artifact, common=common, host=host,
            catalogue=catalogue, item=item, material=material, output=output, review=final, initial_review=review)

    def _retain_report(self, execution):
        return dict(program=authority.plain(execution['program']), results=authority.plain(execution['results']),
            artifact=authority.plain(execution['artifact']), output=execution['output'],
            review=authority.root_plain(execution['review']))

    def observe(self, controller, *, predicted=True, expected_fp=500000000, ttl_seconds=900):
        """Persist an expectation before actual native verification; then qualify."""
        require(len(self._captures) < 8 and type(predicted) is bool
            and (expected_fp is None or type(expected_fp) is int and 0 <= expected_fp <= calibration.Q), 'experience_capture_bound')
        self._ordinal += 1
        context = self._context(controller, ttl_seconds=ttl_seconds)
        material = self._material(context)
        claim_ns = time.time_ns()
        claim_now = claim_ns // 10**9
        require(context['now'] <= claim_now < context['valid_to'], 'experience_claim_clock')
        context['now'] = claim_now
        context['source'] = replace(context['source'], g2a_evaluation_time=claim_now)
        semantic_ref = material['checks'][0]['semantic_ref']
        payload = dict(profile=feedback.PREDICTIVE_SOURCE_PROFILE_ID, predicted=predicted, expected_fp=expected_fp,
            claim_wall_ns=str(claim_ns), dependencies_sha256=digest(dict(scope=context['scope_sha256'], closure=_closure(),
                sources=source_scope(context['sources']))), semantic_ref=semantic_ref, operation=pure.VERIFY,
            source_observation_refs=sorted(row['observation_id'] for row in material['checks'][0]['observations']),
            policy_ref=POLICY, valid_from=claim_now, valid_to=context['valid_to'], sequence=self._ordinal)
        claim = _artifact('g34:prediction:' + digest(payload), 'SemanticEvidence', payload, root=context['root'],
            transaction=context['transaction'], envelope=_envelope(claim_now, context['valid_to'], controller.spec.task_id))
        prospective = self._persist('prospective', authority.plain(claim))
        self._emit('EXPERIENCE_PROSPECTIVE_PERSISTED', claim_ref=claim.artifact_id, evidence=prospective)
        started = time.monotonic_ns()
        execution = self._plain_work(context, pure.VERIFY, material)
        event_ns = time.time_ns()
        event_now = event_ns // 10**9
        capture_ns = time.time_ns()
        require(event_now < context['valid_to'], 'experience_outcome_expired')
        operation = dict(operation=pure.VERIFY, object_id='scope:' + context['scope_sha256'], recipient=context['root'])
        capture_id = 'radik:experience_capture:' + digest(dict(claim=claim.artifact_id,
            artifact=execution['artifact'].artifact_id, event_wall_ns=str(event_ns)))
        origin = 'radik:experience_origin:' + digest(dict(claim=claim.artifact_id, sequence=self._ordinal))
        ctx = dict(context['subject'])
        ctx.pop('domain_scope_id')
        ctx.update(source_id='radik:experience_context:' + digest(payload), domain=context['domain'],
            task_class_id=context['key']['task_class_id'], capability_contract_version=context['key']['capability_contract_version'],
            transaction_id=context['transaction'], run_id=controller.spec.task_id, episode_id=controller.spec.task_id,
            scenario_id='ORDINARY_SOURCE_MARKER_QUALIFICATION')
        native = dict(source_profile_id=feedback.NATIVE_SOURCE_PROFILE_ID, evidence_class='NATIVE_CONTROLLED_OBSERVATION',
            context=ctx, policy=dict(source_id=POLICY, revision=POLICY, **operation),
            origin=dict(source_id=origin, occurrence_id=origin),
            proposal=dict(source_id=semantic_ref, origin_ref=origin, created_at=claim_now, recommendation='PROCEED', **operation),
            expectation=dict(source_id=claim.artifact_id, created_at=claim_now, expected_fp=expected_fp),
            observation=dict(source_id=capture_id, proposal_ref=semantic_ref, occurrence_ref=origin, **operation,
                result_revision=context['key']['capability_contract_version'], event_time=event_now,
                boundary_disposition='PERMITTED', effect_count=0, result_state='PRESENT', failure='NONE'),
            closure=dict(source_id='radik:experience_closure:' + digest(_closure()), sources=_closure()),
            native=dict(claim_wall_ns=str(claim_ns), event_wall_ns=str(event_ns), capture_wall_ns=str(capture_ns),
                elapsed_ns=time.monotonic_ns()-started, sequence=self._ordinal, root_decision_ref=execution['review'][2].decision_id,
                plan_artifact_ref=execution['program'].topology_artifact.artifact_id,
                result_artifact_ref=execution['artifact'].artifact_id, material_sha256=digest(material),
                output_sha256=digest(execution['output']), work_count=1, reached_boundary='WORK_ROOT', reason=None,
                time_envelope=authority.plain(execution['artifact'])['time_envelope'], capture_ref=capture_id,
                semantic_ref=semantic_ref, dependencies_sha256=payload['dependencies_sha256']))
        source = feedback.PredictiveOutcomeSourceContextV01(canonical(dict(profile=feedback.PREDICTIVE_SOURCE_PROFILE_ID,
            native_source=native, claim_artifact=authority.plain(claim), result_artifact=authority.plain(execution['artifact']))))
        # Only the independently retained live execution supplies this source.
        valid, reasons = work.validate_work_program_result_v01(execution['program'], execution['results'],
            host_map={context['root']:execution['host']}, **execution['common'])
        require(valid and not reasons and self._retain_report(execution)['output'] == pure.compute(material, pure.VERIFY),
            'experience_capture_native_origin')
        arrived = time.time_ns() // 10**9
        observation = feedback.build_outcome_observation_v01(source_bundle=source, profile=feedback.PREDICTIVE_SOURCE_PROFILE_ID,
            explicit_times=dict(ingested_time=arrived, evaluated_at=arrived, timestamp=arrived))
        value = feedback.build_outcome_feedback_v01(observation=observation, source_bundle=source, profile=feedback.PREDICTIVE_SOURCE_PROFILE_ID)
        require(not feedback.validate_outcome_feedback_against_sources_v01(value, source_bundle=source,
            profile=feedback.PREDICTIVE_SOURCE_PROFILE_ID), 'experience_feedback_source_binding')
        event = calibration.bind_outcome_feedback_event_v01(value, source_bundle=source, profile=feedback.PREDICTIVE_SOURCE_PROFILE_ID)
        body = feedback.outcome_feedback_to_plain_data_v01(value)
        store_key = digest(context['key'])
        require(body['avf_history_key'] == context['key'] and body['advisory_subject_key'] == context['subject'],
            'experience_feedback_key_binding')
        self._events.setdefault(store_key, []).append(event)
        store = history.OutcomeHistoryV01(self.directory / 'history' / store_key, trusted_events=tuple(self._events[store_key]))
        old = store.head_v01()
        snapshot, review = store.prepare_v01((body['feedback_id'],), expected_head=old, evaluated_at=arrived)
        head = store.commit_v01(snapshot, review, expected_head=old)
        self._stores[store_key] = store
        report = dict(version='radik.qualified_observation.v01', prospective=prospective, claim=authority.plain(claim),
            actual=self._retain_report(execution), feedback=body, source_sha256=digest(source.canonical),
            snapshot=snapshot.to_plain_data(), head=head, recording_root=authority.root_plain(review),
            clocks=dict(claim_wall_ns=str(claim_ns), event_wall_ns=str(event_ns), capture_wall_ns=str(capture_ns),
                ingested_utc_seconds=arrived, monotonic_elapsed_ns=native['native']['elapsed_ns']),
            provider_calls=0, effect_calls=0, interpretation='Scoped source predicate; not task or model failure.')
        self._captures.append((self._origin, source, event, execution, canonical(report)))
        evidence = self._persist('qualified_observation', report)
        self._emit('EXPERIENCE_HISTORY_RECORDED', feedback_ref=body['feedback_id'], eligibility=body['update_eligibility'],
            history_ref=head['snapshot_id'], evidence=evidence)
        return report

    def audit_unscorable(self, controller, reason):
        """Unscorable provider/transport boundaries do not become G3 events."""
        require(reason in ('TRANSPORT_FAILURE', 'AUTH_FAILURE', 'UNSCORABLE_MODEL_RESPONSE', 'NON_EVALUABLE_MODEL_OUTPUT'),
            'experience_unscorable_reason')
        before = {key: store.head_v01() for key, store in self._stores.items()}
        report = dict(version='radik.unscorable_observation.v01', task_id=controller.spec.task_id,
            reason=reason, update_eligibility='NO_UPDATE', qualified_history_before=before,
            qualified_history_after={key: store.head_v01() for key, store in self._stores.items()},
            observed_result=None, task_outcome='UNKNOWN', fabricated_native_execution=False)
        require(report['qualified_history_before'] == report['qualified_history_after'], 'experience_unscorable_mutation')
        self._persist('unscorable', report)
        return report

    def history_snapshot(self):
        """Hash the finite files installed by this instance's live observations.

        These byte identities support immutability comparisons. No historical
        payload is opened as current advice and no live authority is rebuilt.
        """
        retained = {}
        for origin, _source, _event, _execution, raw in self._captures:
            require(origin is self._origin, 'experience_history_capture_origin')
            report = json.loads(raw)
            key = digest(report['feedback']['avf_history_key'])
            retained.setdefault(key, {})[report['head']['snapshot_id']] = report['head']
        result = {}
        for key, store in sorted(self._stores.items()):
            heads = retained.get(key, {})
            head = store.head_v01()
            require(head is not None and heads.get(head['snapshot_id']) == head,
                'experience_history_snapshot_origin')
            paths = {'HEAD.json', 'writer.lock'}
            for prior in heads.values():
                paths.update('epochs/' + prior['snapshot_id'] + suffix
                    for suffix in ('.json', '.payload.json', '.descriptor.json'))
                paths.add('drs/work/' + prior['record_id'] + '.json')
            files = {}
            for relative in sorted(paths):
                path = store.directory / relative
                require(path.is_file() and path.stat().st_size <= 1048576 and not path.is_symlink()
                    and not any(parent.is_symlink() for parent in path.parents
                        if parent == store.directory or store.directory in parent.parents),
                    'experience_history_snapshot_file')
                raw = path.read_bytes()
                files[relative] = dict(sha256=digest(raw), bytes=len(raw))
            result[key] = dict(head=_copy(head), retained_heads=_copy(heads), files=files)
        return result

    def _descriptor_gate(self, context, store, *, evaluated_at=None):
        """The same native eligibility gate precedes every numeric history open."""
        now = context['now'] if evaluated_at is None else evaluated_at
        head = store.head_v01()
        _descriptor, record = store.current_descriptor_v01(head, history_key=context['key'])
        original = record
        restriction = self._restrictions.get(digest(context['key']))
        if restriction is not None:
            args = {field.name:getattr(record, field.name) for field in fields(record)
                if field.name not in ('meaning_record_id', 'meaning_record_version',
                    'local_reference_kernel_scope', 'creates_authority', 'creates_permission')}
            # A restriction can only remove eligibility. It never rewrites the
            # original record, history, source observations or authority grant.
            if restriction['kind'] == 'CONFLICT':
                args['conflict_hints'] = record.conflict_hints + ('CURRENT_UNRESOLVED_CONFLICT',)
            else:
                require(restriction['kind'] == 'QUARANTINE', 'experience_restriction_kind')
                args['persistent_lifecycle_state'] = 'QUARANTINED'
            record = address.build_meaning_record_v01(**args)
        query = memory.build_drs_temporal_query_v01(query_mode='CURRENT_DECISION',
            semantic_address_id=record.semantic_address.semantic_address_id,
            scope_fingerprint=consumer.identity('history_key', context['key']), as_of=now, evaluation_time=now,
            evaluation_time_source='INJECTED_CURRENT_DECISION_TIME', time_range_start=now, time_range_end=now+1,
            required_time_axes=('PT', 'KT', 'ET', 'CT', 'TTL', 'VALIDITY'),
            freshness_policy_id=record.time_envelope.freshness_policy_id,
            max_age_seconds=min(REUSE_SECONDS, record.time_envelope.ttl_seconds), domain=context['domain'],
            risk_class='LOW', reuse_intent='CONTEXT', requested_reuse_classes=('CONTEXT_ONLY',),
            required_evidence_classes=('SOURCE_IDENTITY', 'SOURCE_INTEGRITY', 'PROVENANCE_CHAIN', 'TIME_FITNESS',
                'POLICY_COMPATIBILITY', 'SCHEMA_COMPATIBILITY', 'CONFLICT_CLEARANCE', 'ROOT_DECISION', 'SOURCE_HISTORY'),
            forbidden_changes=('POLICY_CHANGED',), policy_version=POLICY,
            schema_versions=(history.HISTORY_PROFILE_G34,), owning_local_root_id=context['root'])
        evaluation = memory.evaluate_drs_candidate_v01(semantic_address=record.semantic_address, query=query, meaning_record=record)
        return dict(query=memory.drs_temporal_query_to_plain_data_v01(query),
            evaluation=memory.query_evaluation_state_to_plain_data_v01(evaluation), eligible=evaluation.eligible_for_ranking,
            original_record_id=original.meaning_record_id, evaluated_record_id=record.meaning_record_id,
            original_time_envelope=address.drs_time_envelope_to_plain_data_v01(original.time_envelope),
            current_restriction=_copy(restriction), changes_history=False, creates_permission=False)

    @staticmethod
    def _aged_but_unexpired(gate):
        """Recognize only the native max-age refusal, never broader refusal."""
        query, evaluation, envelope = gate['query'], gate['evaluation'], gate['original_time_envelope']
        now = query['evaluation_time']
        non_temporal = ('scope_passed', 'lifecycle_passed', 'policy_compatible', 'schema_compatible',
            'provenance_passed', 'authority_envelope_passed',
            'forbidden_changes_passed', 'conflict_passed', 'quarantine_passed', 'deadend_passed',
            'action_intent_passed', 'g2a_action_history_passed', 'permission_boundary_passed')
        return (gate['eligible'] is False and gate['current_restriction'] is None
            and gate['original_record_id'] == gate['evaluated_record_id']
            and evaluation['reason_codes'] == ['drs_temporal_hard_gate_failed', 'drs_required_evidence_missing']
            and evaluation['query_state'] == 'BLOCKED_BY_TIME'
            and evaluation['validity_interval_passed'] is True
            # TIME_FITNESS is required by this query and is derived from the
            # temporal gate. Its absence is the same age refusal, not a waiver.
            and evaluation['required_evidence_passed'] is False
            and all(evaluation[field] is True for field in non_temporal)
            and envelope['valid_from'] <= now < envelope['valid_to']
            and envelope['pt_created_at'] + query['max_age_seconds'] <= now
            < envelope['pt_created_at'] + envelope['ttl_seconds']
            and query['max_age_seconds'] == min(REUSE_SECONDS, envelope['ttl_seconds'])
            and query['freshness_policy_id'] == envelope['freshness_policy_id'])

    def aged_consumer_control(self, controller):
        """Run the real consumer with an explicit future history-only clock.

        Current source checks, Root decisions and Work use the actual current
        controller clock. The future eligibility time is a labelled control;
        it neither asserts elapsed wall time nor dates new evidence in future.
        """
        context = self._context(controller)
        store = self._stores.get(digest(context['key']))
        require(store is not None, 'experience_controls_require_history')
        before = self.history_snapshot()
        descriptor, record = store.current_descriptor_v01(store.head_v01(), history_key=context['key'])
        aged_time = max(context['now'], record.time_envelope.pt_created_at
            + min(REUSE_SECONDS, record.time_envelope.ttl_seconds))
        gate = self._descriptor_gate(context, store, evaluated_at=aged_time)
        require(self._aged_but_unexpired(gate), 'experience_aged_control_requires_unexpired_history')
        binding = self.consume(controller, history_evaluated_at=aged_time)
        consumed = binding.report
        require(consumed['history_disposition'] == 'AGED_HISTORY_REQUIRES_CURRENT_CHECK'
            and consumed['history_ref'] is None and consumed['prior_fp'] == 0
            and consumed['mandatory_check'] is not None and consumed['outcome_to_history_refs'] == [],
            'experience_aged_control_consumption')
        after = self.history_snapshot()
        require(before == after, 'experience_controls_changed_history')
        report = dict(version='radik.aged_consumer_control.v02',
            evaluation_clock_lane='EXPLICIT_OFFLINE_CONTROL_TIME_NOT_WALL_TIME_PASSAGE',
            history_evaluated_at=aged_time, actual_work_evaluated_at=consumed['evaluated_at'],
            original_descriptor=descriptor, original_record=address.meaning_record_to_plain_data_v01(record),
            aged_gate=gate, history_before=before, history_after=after, binding_report=_copy(consumed),
            old_history_opened=False, prior_fp=0, ttl_extension=False, history_deleted=False,
            permission_restored=False, new_observation_recorded=False, provider_calls=0, effect_calls=0)
        self._persist('aged_consumer_control', report)
        return report

    def eligibility_controls(self, controller):
        """Bounded explicit-clock and restrictive-state controls on retained data.

        Future evaluation clocks and injected conflict/quarantine are labelled
        controls, not claims that wall time elapsed or an external event occurred.
        They enter the ordinary pre-open gate and cannot qualify new evidence.
        """
        context = self._context(controller)
        key = digest(context['key'])
        store = self._stores.get(key)
        require(store is not None, 'experience_controls_require_history')
        before = store.head_v01()
        descriptor, record = store.current_descriptor_v01(before, history_key=context['key'])
        now = context['now']
        fresh = self._descriptor_gate(context, store)
        aged_time = record.time_envelope.pt_created_at + min(REUSE_SECONDS, record.time_envelope.ttl_seconds)
        aged = self._descriptor_gate(context, store, evaluated_at=aged_time)
        expired_time = record.time_envelope.valid_to
        expired = self._descriptor_gate(context, store, evaluated_at=expired_time)
        expired_open, expired_discovery = store.current_v01(history_key=context['key'], root=context['root'],
            transaction=context['transaction'] + ':expired_control', evaluation_time=expired_time)
        require(fresh['eligible'] and not aged['eligible'] and not expired['eligible'] and expired_open is None,
            'experience_temporal_control_failed')
        query_controls = {}
        for label, field in (('source_revision_changed', 'advisory_source_revision'), ('unrelated_task', 'task_class_id')):
            changed = dict(context['key'], **{field:'controlled_different:' + digest(dict(key=key, label=label))[:24]})
            opened, evidence = store.current_v01(history_key=changed, root=context['root'],
                transaction=context['transaction'] + ':' + label, evaluation_time=now)
            require(opened is None, 'experience_scope_transfer_control_failed')
            query_controls[label] = dict(query_key=changed, opened=False, discovery=evidence,
                lane='CONTROLLED_MISMATCH_QUERY_NOT_AN_ACTUAL_SOURCE_REVISION')
        restrictions = {}
        previous = self._restrictions.get(key)
        try:
            for kind in ('CONFLICT', 'QUARANTINE'):
                self._restrictions[key] = dict(kind=kind, evidence_ref='controlled:' + kind.lower(),
                    lane='CONTROLLED_CURRENT_RESTRICTION_NO_EXTERNAL_EVENT_CLAIM', observed_at=now)
                gate = self._descriptor_gate(context, store)
                require(not gate['eligible'], 'experience_restriction_control_failed')
                # Exercise the same ordinary consumption entry, which must stop
                # before history payload descent, numerical advice or Work.
                count = len(self._bindings)
                try:
                    self.consume(controller)
                except ValueError as error:
                    require(str(error) == 'experience_current_history_ineligible', 'experience_wrong_restriction_refusal')
                    refusal = str(error)
                else:
                    raise ValueError('experience_restriction_consumed')
                require(len(self._bindings) == count, 'experience_restriction_created_work_binding')
                restrictions[kind.lower()] = dict(gate=gate, ordinary_consumer_refusal=refusal, consumed=False)
        finally:
            if previous is None:
                self._restrictions.pop(key, None)
            else:
                self._restrictions[key] = previous
        require(store.head_v01() == before, 'experience_controls_changed_history')
        after_descriptor, after_record = store.current_descriptor_v01(before, history_key=context['key'])
        require(descriptor == after_descriptor and record == after_record, 'experience_controls_extended_ttl')
        report = dict(version='radik.qualified_eligibility_controls.v01', history_ref=before['snapshot_id'],
            actual_observation_time=now, original_record=address.meaning_record_to_plain_data_v01(record),
            fresh=fresh, aged=aged, expired=expired, expired_discovery=expired_discovery,
            queries=query_controls, restrictions=restrictions, history_head_before=before, history_head_after=store.head_v01(),
            evaluation_clock_lane='EXPLICIT_OFFLINE_CONTROL_TIMES_NOT_WALL_TIME_PASSAGE',
            ttl_extension=False, history_deleted=False, permission_restored=False)
        self._persist('eligibility_controls', report)
        return report

    def consume(self, controller, *, cold=False, history_evaluated_at=None):
        """A history-dependent decision is consumed by actual ordinary PURE Work."""
        require(type(cold) is bool and len(self._bindings) < 16, 'experience_consumer_bound')
        self._ordinal += 1
        context = self._context(controller)
        require(history_evaluated_at is None or (not cold and type(history_evaluated_at) is int
            and context['now'] <= history_evaluated_at <= 253402300798), 'experience_history_control_clock')
        material = self._material(context)
        store = self._stores.get(digest(context['key']))
        opened, discovery = (None, dict(reason='EXPLICIT_COLD_COMPARATOR' if cold else 'NO_MATCHING_RETAINED_HISTORY'))
        aged_gate = None
        if store is not None and not cold:
            gate = self._descriptor_gate(context, store, evaluated_at=history_evaluated_at)
            if gate['eligible']:
                # A control clock can remove eligibility only. It cannot open
                # history or change the time on actual current advice.
                require(history_evaluated_at is None, 'experience_history_control_requires_refusal')
                opened, discovery = store.current_v01(history_key=context['key'], root=context['root'],
                    transaction=context['transaction'], evaluation_time=context['now'])
            else:
                require(self._aged_but_unexpired(gate), 'experience_current_history_ineligible')
                aged_gate = gate
                discovery = dict(reason='AGED_HISTORY_REQUIRES_CURRENT_CHECK', history_opened=False,
                    history_head=store.head_v01(), current_prior_applied=False,
                    evaluation_clock_lane='ACTUAL_CURRENT_CONTROLLER_TIME' if history_evaluated_at is None
                    else 'EXPLICIT_OFFLINE_CONTROL_TIME_NOT_WALL_TIME_PASSAGE')
            discovery['application_current_gate'] = gate
        else:
            require(history_evaluated_at is None, 'experience_history_control_requires_history')
        envelope = _envelope(context['now'], context['valid_to'], controller.spec.task_id)
        bridge = opened['bridge'] if opened else _artifact('radik:experience_cold:' + digest(dict(
            scope=context['scope_sha256'], now=context['now'], ordinal=self._ordinal)), 'SemanticEvidence',
            dict(profile='G34_COLD_HISTORY_V01', prior_fp=0), root=context['root'], transaction=context['transaction'], envelope=envelope)
        catalogue, host = self._host(context)
        descriptions, keys, checks = {}, {}, {}
        operations = {'verify':pure.VERIFY, 'audit':pure.AUDIT, 'expired_high_score':pure.VERIFY}
        candidates = tuple(avf.AVFCandidateV02(candidate_id=identity, candidate_label=operation,
            base_viability_score={'verify':0.90, 'audit':0.89, 'expired_high_score':1.0}[identity],
            ttl_valid=identity != 'expired_high_score') for identity, operation in operations.items())
        for identity, operation in operations.items():
            subject = dict(context['subject'])
            key = dict(context['key'])
            if identity != 'verify':
                subject.update(route_family_id='PURE_SOURCE_CONDITION_AUDIT', advisory_source_class='CONTROLLED_SOURCE_AUDIT')
                key.update(route_family_id=subject['route_family_id'], task_class_id='SOURCE_AUDIT:' + context['scope_sha256'][:24])
            description = dict(operation=operation, definition_id=next(row.definition.definition_id for row in catalogue
                if row.definition.operation_id == operation), material_sha256=digest(material),
                observation_refs=sorted(row['observation_id'] for row in material['checks'][0]['observations']), subject=subject, history_key=key)
            description['claim_id'] = consumer.identity('current_claim', description)
            descriptions[identity], keys[identity] = description, key
            check = dict(profile='G34_BOUNDED_CURRENT_ADEQUACY_V01', root=context['root'],
                target_claim_id=description['claim_id'], target_subject=subject, observation_refs=description['observation_refs'],
                task_inputs_sha256=digest(material), epoch=opened['head'] if opened else None,
                evaluated_at=context['now'], policy_ref=POLICY, operation=pure.VERIFY,
                definition_id=next(row.definition.definition_id for row in catalogue if row.definition.operation_id == pure.VERIFY),
                material=material, result_facts=pure.compute(material, pure.VERIFY))
            check['check_id'] = consumer.identity('bounded_check', check)
            checks[identity] = check
        contract = consumer.build_current_review_contract_v01(source_context=context['source'], root=context['root'],
            transaction=context['transaction'], policy_ref=POLICY, claims=descriptions, checks=checks)
        trusted = dict(candidates=candidates, history_keys=keys, opened_history=opened, bridge=bridge,
            evaluated_at=context['now'], contract=contract, source_context=context['source'])
        projection, avf_reports = consumer.build_current_advisory_v01(**trusted)
        projected = projection.to_plain_data()
        if aged_gate is not None:
            require(opened is None and projected['history_ref'] is None
                and projected['trust']['review_recommended'] is True
                and all(row['prior_fp'] == 0 and row['prior_ref'] is None for row in projected['rows']),
                'experience_aged_history_not_current_prior')
        selected = projected['selected']
        check = checks[selected]
        extra = receipt = receipt_bridge = None
        if projected['trust']['review_recommended']:
            extra = self._plain_work(context, pure.VERIFY, material, check_request=check,
                task_id='g34:check:' + check['check_id'])
            receipt = extra['program'], extra['results'], extra['common'], {context['root']:extra['host']}
        review = consumer.review_current_advisory_v01(projection=projection, trusted_inputs=trusted, root=context['root'],
            transaction=context['transaction'], candidate_materials=descriptions, additional_receipt=receipt)
        require(review[2].decision == 'ACCEPT', 'experience_current_root_refused')
        if aged_gate is not None:
            require(extra is not None and receipt is not None, 'experience_aged_check_required')
        if receipt is not None:
            receipt_bridge = consumer.current_check_receipt_bridge_v01(check=check, receipt=receipt, current_bridge=bridge)
        advisory = _artifact('g34:advisory:' + projected['projection_id'], 'SemanticEvidence', dict(advisory=projected),
            root=context['root'], transaction=context['transaction'], envelope=envelope, parents=(bridge.artifact_id,))
        payload = dict(material=material, advisory_ref=projected['projection_id'], bridge_ref=bridge.artifact_id,
            root_decision_ref=review[2].decision_id, operation=operations[selected],
            check_receipt_ref=receipt_bridge.artifact_id if receipt_bridge else None)
        proposal = _artifact('radik:experience_current:' + digest(payload), 'SemanticArchitectProposal', payload,
            root=context['root'], transaction=context['transaction'], envelope=envelope,
            parents=(context['source'].bsep_packet['packet_id'], bridge.artifact_id, advisory.artifact_id)
                + ((receipt_bridge.artifact_id,) if receipt_bridge else ()),
            component='semantic_architect', traces=('g34:intent:' + controller.spec.task_id,))
        item = work.WorkItemV01('consume_experience', descriptions[selected]['definition_id'], context['root'],
            (work.WorkInputBindingV01('material', work.WorkLiteralV01(authority.records(
                dict(material=('TEXT', canonical(material).decode())))[0])),), (), (), None, None)
        program, results, artifact, common = consumer.execute_reviewed_pure_work_v01(review=review, projection=projection,
            source_context=context['source'], semantic_proposal=proposal, catalogue=catalogue, host=host, item=item,
            material=material, budget=work.WorkBudgetV01(1, 0, 0, 1, 0), task_id=controller.spec.task_id,
            trusted_inputs=trusted, additional_receipt=receipt)
        output = json.loads(authority.values(results[0].result.output)['material'])
        require(output == pure.compute(material, operations[selected]), 'experience_selected_consumption')
        bsep = _artifact(context['source'].bsep_packet['packet_id'], 'SemanticEvidence',
            dict(bsep=context['source'].bsep_packet), root=context['root'], transaction=context['transaction'], envelope=envelope)
        work_proposal = work.work_program_candidate_to_artifact_v01(program.candidate, **common)
        artifacts = (bridge, advisory, bsep, proposal, work_proposal, program.topology_artifact, artifact)
        if receipt_bridge is not None:
            artifacts += (receipt_bridge,)
        def edge(producer, downstream, field):
            return abi.build_causal_consumption_ref_v01(producer_actor_id=producer.source_component,
                source_artifact_id=producer.artifact_id, output_field=field, consumer_component=downstream.source_component,
                downstream_artifact_id=downstream.artifact_id, decision_effect='CURRENT_WORK_SELECTION',
                disposition='USED', reason_code='used:actual_current_value', trace_refs=(controller.spec.task_id,))
        causal = [edge(advisory, proposal, '/advisory/selected'), edge(proposal, work_proposal, '/material'),
            edge(work_proposal, program.topology_artifact, '/work_program/items'),
            edge(program.topology_artifact, artifact, '/ordered_work_ids')]
        if receipt_bridge is not None:
            causal.append(edge(receipt_bridge, proposal, '/result_facts'))
        if opened is not None:
            causal.insert(0, edge(bridge, advisory, '/prior/prior_fp'))
        causal.extend(program.source_bindings)
        causal_errors = consumer.validate_current_causal_proof_v01(projection=projection, trusted_inputs=trusted,
            artifacts=artifacts, causal_refs=tuple(causal), program=program, common=common)
        require(not causal_errors, 'experience_native_causal_proof')
        custody_material = dict(source_scope=source_scope(context['sources']), accepted_result_sha256=digest(controller.accepted.plain),
            actual_check_ref=artifact.artifact_id, actual_check_output=output, scoped_history_ref=opened['snapshot_id'] if opened else None)
        custody = authority.root_review('radik:source_custody:' + digest(custody_material), custody_material,
            dict(actual_current_source_bytes=source_scope(_current(controller)) == source_scope(context['sources']),
                actual_selected_work=output == pure.compute(material, operations[selected]), pure_no_effect=True),
            context['now'], transaction_id=context['transaction'], owning_root_id=context['root'],
            predicate='qualify_current_source_custody', topology_ref=program.topology_artifact.artifact_id)
        require(custody[2].decision == 'ACCEPT', 'experience_custody_refused')
        history_valid_to = int(datetime.fromisoformat(authority.plain(bridge)['time_envelope']['valid_to']).timestamp())
        report = dict(version='radik.qualified_consumer.v01', scope=_scope(controller), source_scope=source_scope(context['sources']),
            current_root=context['root'], current_transaction=context['transaction'], evaluated_at=context['now'],
            history_valid_to=history_valid_to, history_ref=opened['snapshot_id'] if opened else None,
            current_work_valid_to=context['valid_to'], rejected_history_valid_to=None if aged_gate is None
                else aged_gate['original_time_envelope']['valid_to'],
            history_disposition='AGED_HISTORY_REQUIRES_CURRENT_CHECK' if aged_gate is not None
                else 'QUALIFIED_CURRENT_HISTORY' if opened else 'COLD_OR_NONMATCHING',
            prior_fp=opened['prior']['prior_fp'] if opened else 0, discovery=discovery,
            contract=contract.to_plain_data(), projection=projected, avf=authority.plain(avf_reports),
            current_review=consumer.review_to_plain_v01(review), source_custody_review=authority.root_plain(custody),
            mandatory_check=self._retain_report(extra) if extra else None,
            selected_operation=operations[selected], work_result_ref=artifact.artifact_id,
            work=dict(program=authority.plain(program), results=authority.plain(results), artifact=authority.plain(artifact), output=output),
            causal_validation='PASS', causal_refs=authority.plain(causal),
            causal_artifacts=[authority.plain(value) for value in artifacts],
            outcome_to_history_refs=[row['feedback_id'] for row in [feedback.outcome_feedback_to_plain_data_v01(
                feedback.OutcomeFeedbackEnvelopeV01(event.feedback_canonical)) for event in self._events.get(digest(context['key']), [])]]
                if opened is not None else [],
            effect_calls=0, provider_calls=0, history_creates_permission=False)
        report['binding_id'] = 'radik:experience_binding:' + digest(report)
        binding = ExperienceBinding(self, controller, _SEAL, context, opened, custody, tuple(source_scope(context['sources'])),
            dict(program=program, results=results, common=common, host=host), report)
        self._bindings[report['binding_id']] = binding
        self._binding_reports[report['binding_id']] = canonical(report)
        validate_strategy_history(controller, binding)
        evidence = self._persist('qualified_consumer', report)
        self._emit('EXPERIENCE_CURRENT_WORK_CONSUMED', selected_operation=operations[selected],
            history_ref=report['history_ref'], result_ref=artifact.artifact_id, evidence=evidence)
        return binding
