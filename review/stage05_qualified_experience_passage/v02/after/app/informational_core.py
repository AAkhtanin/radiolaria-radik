"""Document-source informational adapter over the accepted public native APIs.

The digest origin has its own bounded Work policy and Host. That Host owns the
origin, enrollment and captures. A nonportable app link binds it to the actual
business Host, task, common semantic origin and trusted intake object. No Host
history, admission or permission is imported from serialized evidence.
"""
from dataclasses import dataclass, replace
import json

from hedgehog import action_commit_packet_v02 as action, informational_source_v01 as info
from hedgehog import work_execution_host_v01 as hosts
from hedgehog.kernel import abi_v01 as abi, effect_firewall_v01 as firewall
from hedgehog.kernel import work_composition_v01 as work, integrity_replay_v01 as integrity
from hedgehog.kernel import continuous_delta_runtime_v01 as delta_runtime
from . import native_authority as authority
from . import informational_material as material
from . import document_temporal as temporal
from .evidence import persist

require,canonical,digest,plain=authority.require,authority.canonical,authority.digest,authority.plain
OPERATION='radik.material.source_digest.v26'
_LINK_ORIGIN=object()


def validate_source_inputs_v26(definition,inputs):
    errors=firewall.validate_capability_values_v01(definition.input_fields,inputs)
    if not errors:
        try:
            values=authority.values(inputs)
            require(set(values)=={'source_material'},'informational_digest_input_shape')
            material=json.loads(values['source_material'])
            require(type(material)is list and 1<=len(material)<=4 and
                values['source_material']==canonical(material).decode(),'informational_digest_canonical_material')
        except (ValueError,TypeError,KeyError):errors=('informational_digest_input_shape',)
    return firewall.build_capability_validation_evidence_v01(definition=definition,values=inputs,
        invocation_id=None,valid=not errors,reason_codes=errors)


def execute_source_digest_v26(invocation):
    require(invocation.candidate_id is None and invocation.packet_id is None,'informational_digest_must_be_pure')
    material=authority.values(invocation.inputs)['source_material']
    return authority.records(dict(source_sha256=('TEXT',digest(material.encode()))))


def validate_source_outputs_v26(definition,invocation,output):
    errors=firewall.validate_capability_values_v01(definition.output_fields,output)
    if not errors:
        expected=digest(authority.values(invocation.inputs)['source_material'].encode())
        if authority.values(output)!={'source_sha256':expected}:errors=('informational_digest_output_binding',)
    return firewall.build_capability_validation_evidence_v01(definition=definition,values=output,
        invocation_id=invocation.invocation_id,valid=not errors,reason_codes=errors)


def admit_source_digest(host_ref):
    callbacks=(validate_source_inputs_v26,validate_source_outputs_v26,execute_source_digest_v26)
    code=tuple(hosts.observe_local_capability_code_v01(cb)for cb in callbacks)
    definition=firewall.build_capability_definition_v01(operation_id=OPERATION,version='v26',effect_kind='PURE',business_semantics=None,
        input_fields=(firewall.build_capability_field_v01(name='source_material',value_type='TEXT',required=True,consequential=False),),
        output_fields=(firewall.build_capability_field_v01(name='source_sha256',value_type='TEXT',required=True,consequential=False),),
        resource_refs=(),input_validator_ref=code[0].public_symbol,output_validator_ref=code[1].public_symbol,
        executor_ref=code[2].public_symbol,code_sha256s=tuple((v.public_symbol,v.source_sha256)for v in code))
    return hosts.admit_local_capability_v01(definition=definition,input_validator=callbacks[0],output_validator=callbacks[1],
        executor=callbacks[2],catalogue_revision=0,host_instance_ref=host_ref)


def source_payload(source):
    return dict(source_ref=source['source_ref'],source_revision=source['revision'],content_sha256=source['sha256'],text=source['text'])


class InformationalDocumentSource(material.CurrentInformationalSource):
    """Dependency identity is stable; payload hash and content-bound envelope are current."""
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.informational_dependencies={}

    def install_document_dependencies(self,records,sources,start,end):
        require(not self.dependencies and not self.informational_dependencies,'informational_dependency_install_once')
        self.informational_dependencies={record.dependency_id:(record,source['source_ref'],start,end)
            for record,source in zip(records,sources,strict=True)}
        self.sample()

    def read_current_v01(self):
        if not self.informational_dependencies:return super().read_current_v01()
        current=self.current();by_ref={v['source_ref']:v for v in current['full_sources']};observations=[]
        for record,logical,start,end in self.informational_dependencies.values():
            require(logical in by_ref,'informational_dependency_source_missing')
            content=digest(source_payload(by_ref[logical]))
            envelope=action.build_action_dependency_time_envelope_id_v01(dependency_id=record.dependency_id,
                evidence_ref=record.evidence_ref,content_sha256=content,freshness_policy_id=record.freshness_policy_id,
                source_provenance_refs=record.source_provenance_refs,valid_from_utc=start,valid_to_utc=end)
            observations.append(action.build_action_dependency_current_observation_v01(dependency_id=record.dependency_id,
                evidence_ref=record.evidence_ref,observed_content_sha256=content,time_envelope_id=envelope,
                freshness_policy_id=record.freshness_policy_id,source_provenance_refs=record.source_provenance_refs,
                valid_from_utc=start,valid_to_utc=end,observed_at_utc=self.evaluation_time,observation_context_id=self.task_id))
        values=tuple(sorted(observations,key=lambda v:v.dependency_id))
        changed=values!=self.snapshot.observations or self.evaluation_time!=self.snapshot.evaluation_time
        self.snapshot=replace(self.snapshot,observations=values,evaluation_time=self.evaluation_time,
            source_revision=self.snapshot.source_revision+int(changed))
        return self.snapshot


@dataclass(frozen=True)
class InformationalOriginLink:
    task: object
    business_host: object
    trusted_source: object
    host: object
    program: object
    outcome: object
    carrier: object
    enrollment: object
    documents: tuple
    initial_sources: tuple
    valid_to: int
    ownership_review: tuple
    _origin: object


def caps_for_task(task):
    material=dict(policy=task.source.current()['policy'],semantic=plain(task.common['semantic_proposal']),
        baseline=plain(task.d_baseline),information=plain(task.information[0]))
    if task.semantic_family is not None and hasattr(task.semantic_family,'scope'):
        material['semantic_family']=task.semantic_family.scope
    if task.accepted is not None:
        material['accepted_result']=task.accepted.plain
    material['current_d_source']=plain(task.d_source)
    rows=temporal.collect_caps(material)
    require(rows,'informational_temporal_caps_missing')
    return min(row['valid_to']for row in rows),rows


def _artifact(task,payload,*,created_at,valid_to,parents=()):
    envelope=dict(pt_created_at=authority.stamp(created_at),kt_asof=authority.stamp(created_at),
        et_observed_at=authority.stamp(created_at),ct_session_anchor=task.task_id,ttl_seconds=valid_to-created_at,
        freshness_class='static',valid_from=authority.stamp(created_at),valid_to=authority.stamp(valid_to))
    ref='radik:document_source:'+digest(dict(payload=payload,parents=parents,time=envelope))
    return abi.build_kernel_artifact_v01(abi_version='v1.0',artifact_id=ref,artifact_type='SemanticEvidence',schema_version='v1',
        transaction_id=task.d_baseline.topology.transaction_id,owner_root_id=task.root_id,
        source_component='radik:trusted_document_intake',authority_class='EVIDENCE_ONLY',lifecycle_state='VALIDATED',
        payload=payload,trace_refs=(task.task_id,),parent_refs=parents,time_envelope=envelope)


def prepare_origin(task):
    """Called only after the actual D baseline and before any source successor."""
    require(task.informational_profile and task.informational_origin is None and task.d_baseline is not None,
        'informational_origin_phase')
    require(type(task.source)is InformationalDocumentSource and task.pending is None,'informational_source_profile')
    from .informational_control import baseline_semantic_domain
    domain=baseline_semantic_domain(task)
    require_no_effects(task.source)
    current=task.source.current();require(current['full_sources']==task.sources,'informational_origin_sources_changed')
    now=current['now'];valid_to,caps=caps_for_task(task)
    temporal.require_remaining(valid_to,now,temporal.NATIVE_SECONDS+temporal.CONSUMER_SECONDS)
    documents=tuple(_artifact(task,source_payload(v),created_at=now,valid_to=valid_to)for v in task.sources)
    records=[]
    for artifact in documents:
        content=digest(abi.kernel_artifact_to_plain_dict_v01(artifact)['payload'])
        envelope=action.build_action_dependency_time_envelope_id_v01(dependency_id=artifact.artifact_id,evidence_ref=artifact.artifact_id,
            content_sha256=content,freshness_policy_id=temporal.PROFILE,source_provenance_refs=(artifact.artifact_id,),
            valid_from_utc=now,valid_to_utc=valid_to)
        records.append(action.build_dependency_set_candidate_record_v01(dependency_id=artifact.artifact_id,
            dependency_class='DOCUMENT_SOURCE',evidence_ref=artifact.artifact_id,content_sha256=content,requirement_class='MANDATORY',
            time_envelope_id=envelope,freshness_policy_id=temporal.PROFILE,source_provenance_refs=(artifact.artifact_id,),
            expected_accepting_local_root_id=task.root_id))
    task.source.install_document_dependencies(tuple(records),task.sources,now,valid_to)
    admitted=admit_source_digest('host:'+task.root_id+':source_origin:'+digest(task.task_id)[:16]);catalogue=(admitted,)
    common=dict(task.common,catalogue=catalogue)
    item=work.WorkItemV01('document_source_digest',admitted.definition.definition_id,task.root_id,
        (material.literal('source_material',[abi.kernel_artifact_to_plain_dict_v01(v)['payload']for v in documents]),),(),(),None,None)
    candidate=work.build_work_program_candidate_v01(task_id=task.task_id,previous_revision_id=None,
        intent_ref=task.program.candidate.intent_ref,bsep_ref=task.program.candidate.bsep_ref,
        semantic_proposal_ref=task.program.candidate.semantic_proposal_ref,catalogue_revision=0,
        budget=work.WorkBudgetV01(1,0,0,1,0),items=(item,),trigger_evidence_refs=(),**common)
    program=work.materialize_work_program_v01(candidate,**common)
    policy=work.build_work_task_policy_v01(candidate,**common,host_instance_ref=admitted.host_instance_ref,
        definition_ids=(admitted.definition.definition_id,),resource_refs=())
    clock=task.source.sample()
    host=hosts.build_root_work_execution_host_v01(owning_root_id=task.root_id,
        registry=action.build_empty_action_commit_packet_registry_v02(),catalogue=catalogue,packet_bindings=(),
        current_dependency_observations=clock.observations,logical_time_bridge=clock.logical_time_bridge,
        trusted_source=task.source,task_policies=(policy,))
    work.enroll_work_program_v01(host,program,**common,expected_revision=host.state_revision)
    context=work.work_continuation_context_v01(host,task_id=task.task_id,expected_revision=host.state_revision)
    outcome=work.advance_work_program_v01(program,**common,host_map={task.root_id:host},continuation_context=context)
    final_context=work.work_continuation_context_v01(host,task_id=task.task_id,expected_revision=host.state_revision)
    require(work.validate_work_continuation_outcome_v01(outcome,context=final_context,**common)==(True,()),
        'informational_origin_work_outcome_invalid')
    require(outcome.status=='COMPLETED'and len(outcome.results)==1,'informational_origin_work_not_completed')
    result=outcome.results[0];invocation,output=result.invocation,result.result
    require(invocation.packet_id is None and invocation.candidate_id is None and output.outcome=='SUCCEEDED',
        'informational_origin_pure_boundary')
    dependency=action.build_dependency_set_candidate_v01(dependency_records=tuple(records))
    profile=info.build_informational_review_profile_v02(domain_id=domain,review_subject='radik:documents')
    carrier=info.build_informational_source_v02(baseline_bundle=task.d_baseline,dependency_candidate=dependency,
        source_artifacts=documents,origin_host=host,origin_invocation=invocation,origin_result=output,
        valid_from=now,valid_to=valid_to,review_profile=profile)
    enrollment=hosts.enroll_informational_source_v01(host,carrier=carrier,baseline_bundle=task.d_baseline,
        origin_invocation=invocation,origin_result=output,expected_revision=host.revision)
    business=work.inspect_work_task_v01(task.host,task_id=task.task_id)
    review=authority.root_review('radik:informational_host_link:'+carrier.carrier_id,
        dict(task_id=task.task_id,root_id=task.root_id,carrier_id=carrier.carrier_id,
            business_policy_sha256=digest(plain(business.policy)),origin_policy_sha256=digest(plain(policy)),
            intent_ref=candidate.intent_ref,bsep_ref=candidate.bsep_ref,semantic_proposal_ref=candidate.semantic_proposal_ref,
            source_descriptors=material.descriptors(task.sources)),
        dict(same_task=candidate.task_id==task.program.candidate.task_id,
            same_root=host.owning_root_id==task.host.owning_root_id==task.root_id,
            same_intent=candidate.intent_ref==task.program.candidate.intent_ref,
            same_source_policy=business.policy.source_ref==policy.source_ref,
            same_bsep=candidate.bsep_ref==task.program.candidate.bsep_ref,
            same_semantic=candidate.semantic_proposal_ref==task.common['semantic_proposal'].artifact_id,
            current_sources=task.source.current()['full_sources']==task.sources),task.source.clock(),
        transaction_id=task.d_baseline.topology.transaction_id,owning_root_id=task.root_id,task_id=task.task_id)
    require(review[2].decision=='ACCEPT','informational_host_link_refused')
    state=InformationalOriginLink(task,task.host,task.source,host,program,outcome,carrier,enrollment,documents,
        task.sources,valid_to,review,_LINK_ORIGIN)
    task.informational_origin=state
    task.evidence_refs.append(persist(task.evidence_directory,'informational_origin',dict(
        temporal_profile=temporal.PROFILE,effective_valid_to=valid_to,temporal_caps=caps,program=program,outcome=outcome,
        carrier=carrier,enrollment=enrollment,ownership_review=authority.root_plain(review),
        original_SOURCE_before_origin_unchanged=True,source_material_contract='CANONICAL_SOURCE_ARTIFACT_PAYLOADS',
        direct_pure_dispatch_bypassed=False,synthetic_offline_roles=task.semantic_family.kind!="ACTUAL_ORCHESTRATOR_OBSERVATION")))
    return state


def validate_link(task):
    require_no_effects(task.source)
    state=task.informational_origin
    require(type(state)is InformationalOriginLink and state._origin is _LINK_ORIGIN and state.task is task
        and state.business_host is task.host and state.trusted_source is task.source,
        'informational_business_host_link')
    require(state.program.candidate.task_id==task.program.candidate.task_id==task.task_id
        and state.program.candidate.intent_ref==task.program.candidate.intent_ref
        and state.program.candidate.bsep_ref==task.program.candidate.bsep_ref
        and state.program.candidate.semantic_proposal_ref==task.program.candidate.semantic_proposal_ref,
        'informational_business_origin_changed')
    business=work.inspect_work_task_v01(task.host,task_id=task.task_id)
    origin=work.inspect_work_task_v01(state.host,task_id=task.task_id)
    require(business.policy.source_ref==origin.policy.source_ref
        and business.policy.intent_ref==origin.policy.intent_ref==task.program.candidate.intent_ref
        and business.policy.owning_root_id==origin.policy.owning_root_id==task.root_id,
        'informational_current_task_policy_link')
    info.validate_informational_origin_v01(state.carrier,baseline_bundle=task.d_baseline,host=state.host,
        invocation=state.outcome.results[0].invocation,result=state.outcome.results[0].result)
    return state


def validate_update_sources(task,updated,changed_index):
    state=validate_link(task);updated=material.normalize_sources(updated)
    require(task.source.current()['full_sources']==updated,'informational_intake_snapshot_changed')
    require(changed_index in range(len(updated)) and len(updated)==len(state.initial_sources)
        and all(updated[i]==state.initial_sources[i]for i in range(len(updated))if i!=changed_index),
        'informational_retained_source_changed')
    old,new=state.initial_sources[changed_index],updated[changed_index]
    require(new['source_ref']==old['source_ref']and new['revision']>old['revision']and new['sha256']!=old['sha256'],
        'informational_source_successor_required')
    temporal.require_remaining(state.valid_to,task.source.clock())
    return state,updated


def capture_current(task):
    state=validate_link(task);before=require_no_effects(task.source);clock=task.source.sample()
    temporal.require_remaining(state.valid_to,clock.evaluation_time)
    capture=hosts.capture_current_informational_source_v01(state.host,carrier_id=state.carrier.carrier_id,
        expected_revision=state.host.revision,evaluation_time=clock.evaluation_time,
        evaluation_time_source=clock.evaluation_time_source,evaluation_context_id=clock.evaluation_context_id)
    require(hosts.validate_retained_informational_source_capture_v01(state.host,capture,require_current=True)is True,
        'informational_current_capture_refused')
    after=require_no_effects(task.source)
    require(after['full_sources']==before['full_sources'], 'informational_capture_sources_changed')
    temporal.require_remaining(state.valid_to,after['now'])
    return capture


def prepare_delta_components(task,updated,changed_index):
    state,updated=validate_update_sources(task,updated,changed_index)
    effective,caps=caps_for_task(task)
    effective=min(state.valid_to,effective)
    temporal.require_remaining(effective,task.source.clock(),temporal.NATIVE_SECONDS+temporal.CONSUMER_SECONDS)
    task.evidence_refs.append(persist(task.evidence_directory,'informational_pre_e_temporal_intersection',
        dict(valid_to=effective,required_seconds=temporal.NATIVE_SECONDS+temporal.CONSUMER_SECONDS,caps=caps)))
    capture=capture_current(task)
    observed=_artifact(task,source_payload(updated[changed_index]),created_at=capture.evaluation_time,
        valid_to=state.valid_to,parents=(state.documents[changed_index].artifact_id,))
    invalidation=info.build_informational_invalidation_v01(host=state.host,capture=capture,observed_artifact=observed)
    return state,updated,capture,observed,invalidation


def validate_consumption_boundary(task,context):
    state=validate_link(task)
    require(context.source_authority_kind=='INFORMATIONAL'and context.current_source_host is state.host
        and context.informational_carrier is state.carrier,'informational_return_origin')
    require(hosts.validate_retained_informational_source_capture_v01(state.host,context.current_source_capture,require_current=False)is True,
        'informational_historical_capture_refused')
    expected=task.delta_expected
    validate_update_sources(task,expected['updated'],expected['changed_index'])
    current=capture_current(task)
    require(current.carrier is state.carrier,'informational_current_carrier_changed')
    task.evidence_refs.append(persist(task.evidence_directory,'informational_current_consumption_boundary',dict(
        historical_operation_capture=context.current_source_capture,current_consumption_capture=current,
        historical_capture_claimed_current=False,current_checked_with_require_current=True,
        current_UTC=task.source.clock(),source_descriptors=material.descriptors(expected['updated']))))
    return current


def require_no_effects(source):
    current=source.current();policy=current['policy']
    require(policy['save_allowed'] is False and policy['consent_ref'] is None
        and current['now'] < policy['valid_to'], 'informational_current_no_effects_policy')
    return current


def require_publication(task):
    state=validate_link(task);current=require_no_effects(task.source)
    require(current['full_sources']==task.sources,'informational_publication_sources_changed')
    temporal.require_remaining(state.valid_to,current['now'])
    capture=capture_current(task)
    publication_readback(task)
    return capture


def publication_readback(task):
    current=require_no_effects(task.source)
    require(current['full_sources']==task.sources,'informational_publication_sources_changed')
    effective,_caps=caps_for_task(task)
    temporal.require_remaining(min(task.informational_origin.valid_to,effective),current['now'])
    return current['now']


def require_family_profile(family, informational_profile):
    from . import semantic_membrane as membrane
    expected=temporal.FAMILY_VERSION if informational_profile else membrane.FAMILY_VERSION
    require(family.scope['version']==expected, 'informational_semantic_profile_mismatch')
