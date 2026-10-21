"""Informational source continuation for the ordinary dynamic controller.

The native control return and the business Work revision have separate consumer
witnesses. E never supplies a nominal D Work-review receipt. No JSON restores a
Host, origin, request, Root or source-transition token.
"""
from dataclasses import dataclass
import json
from pathlib import Path
import time

from hedgehog.kernel import work_composition_v01 as work, fractal_runtime_v02 as fractal
from hedgehog.kernel import continuous_delta_runtime_v01 as delta
from . import native_authority as authority, informational_core as core, informational_control as control
from . import informational_material as material, dynamic_delta_graph as graphs
from .dynamic_delta_source import build_arguments
from .contracts import canonical, digest, require
from .dynamic_work import _candidate
from .dynamic_semantics import validate_current_family, source_family_witness


@dataclass(frozen=True)
class _FamilyEvidence:
    family: object

    @property
    def kind(self):
        return 'ACTUAL_ORCHESTRATOR_OBSERVATION'

    @property
    def scope(self):
        return self.family.scope


def _cold_mapping(controller):
    sources,candidate=controller.initial_sources,controller.candidate
    route=candidate['program']['route']
    groups=([list(range(len(sources)))]*3 if route=='short' or len(sources)==1 else
        [list(range(0,len(sources),2)),list(range(1,len(sources),2))])
    leaves=[]
    for index,source in enumerate(sources):
        slot=controller.results[-1].work_id if route=='short' else 'extract'+str(index)
        field='result' if route=='short' else 'material'
        historical=work.build_work_historical_output_v01(controller._context(),
            revision_id=controller.program.candidate.revision_id,work_id=slot,output_field=field)
        require(work.validate_work_historical_output_v01(historical,context=controller._context())==(True,()),
            'dynamic_delta_cold_historical_output')
        actual=next(r for r in controller.results if r.work_id==slot)
        inputs=authority.values(actual.invocation.inputs)
        consumed=json.loads(inputs['material'])
        if route!='short':
            require(consumed['source']==source and consumed['claims']==[c for c in candidate['claims']
                if c['source_ref']==source['source_ref']],'dynamic_delta_cold_actual_work_source')
        else:
            require(consumed['sources']==sources,'dynamic_delta_cold_actual_short_sources')
        leaves.append(dict(source={k:source[k] for k in ('source_ref','revision','sha256')},
            claims_sha256=digest([c for c in candidate['claims'] if c['source_ref']==source['source_ref']]),
            work_id=slot,invocation_sha256=digest(authority.plain(actual.invocation)),
            output=authority.plain(historical),input_sha256=digest(inputs['material'].encode())))
    declaration=dict(schema='radik.dynamic.native_business_bridge.v01',task_spec_sha256=digest(controller.spec.plain()),
        program_revision=controller.program.candidate.revision_id,business_artifact_ref=controller.artifact.artifact_id,
        accepted_root_sha256=digest(controller.accepted.plain['root']),route=route,source_groups=groups,
        leaves=leaves,native_role='CONTROL_WORK_NOT_BUSINESS_EXTRACTION')
    review=authority.root_review('dynamic:cold_dependency_declaration:'+digest(declaration),declaration,
        dict(actual_completed_inputs=True,all_approved_sources=True,before_source_successor=True,
            no_effect=True,independent_native_and_business_consumers_required=True),controller.now(),
        transaction_id=controller.family.scope['transaction_id'],owning_root_id=controller.root_id,
        task_id=controller.spec.task_id)
    require(review[2].decision=='ACCEPT','dynamic_delta_cold_dependency_root_refused')
    controller._persist('dynamic_cold_dependency_declaration',dict(declaration=declaration,root=authority.root_plain(review)))
    return declaration,review


def prepare_shared_information(task, material, accepted_review):
    """The common pre-D preparation used by the ordinary Context constructor.

    A source-admitted local control may call this seam with fresh native Work
    and Root objects. It does not supply the constructor's actual role proof.
    """
    task.information = control.build_information(task, material, accepted_review)
    task.d_source = control.build_d_source(task, task.information)
    return task


class DynamicInformationalContext:
    def __init__(self, controller):
        from .dynamic_roles import DynamicRoleRun
        require(controller.accepted is not None and controller.memory_origin is None
            and type(controller.role_run) is DynamicRoleRun and controller.role_run.stage == 3
            and controller.family is controller.role_run.family and controller.final_root is not None,
            'dynamic_delta_actual_cold_origin_required')
        controller.current()
        validate_current_family(controller.family, controller.initial_sources,
            policy=controller.current_policy(), now=controller.now())
        self.native_declaration,self.native_declaration_root=_cold_mapping(controller)
        self.native_bridge=None
        self.controller = controller
        self.task_id, self.root_id = controller.spec.task_id, controller.root_id
        self.program, self.common, self.host = controller.program, controller.common, controller.host
        self.review_bindings = controller.review_bindings
        self.sources = material.normalize_sources(controller.initial_sources)
        self.semantic_family = _FamilyEvidence(controller.family)
        self.accepted, self.pending, self.informational_profile = controller.accepted, None, True
        self.evidence_directory, self.evidence_refs = controller.evidence_directory, controller.evidence_refs
        self.source = core.InformationalDocumentSource(self.task_id, controller.current,
            controller.current_policy, controller.now)
        self.informational_origin = self.d_baseline = self.delta_expected = None
        prepare_shared_information(self, dict(
            actual_work=controller.artifact.artifact_id, accepted_result=controller.accepted.plain['result_id'],
            actual_work_receipt_sha256=digest(controller.accepted.plain['actual_work']),
            dependency_declaration=self.native_declaration,
            dependency_declaration_root=authority.root_plain(self.native_declaration_root)), controller.final_root)


def prepare(controller):
    require(controller.informational_context is None and controller.native_revision == 0,
        'dynamic_delta_origin_once_before_successor')
    context = DynamicInformationalContext(controller)
    core.require_no_effects(context.source)
    controller.emit('DYNAMIC_INFORMATIONAL_BASELINE_START')
    started = time.monotonic()
    with controller._pulse('INFORMATIONAL_CONTROL_BASELINE'):
        context.d_baseline, validation = fractal.run_fractal_runtime_v02(context.d_source)
    require(context.d_baseline is not None and validation.status == 'PASS'
        and fractal.validate_fractal_runtime_execution_bundle_v02(context.d_baseline).status == 'PASS',
        'dynamic_delta_baseline_invalid')
    controller._persist('dynamic_informational_baseline', context.d_baseline)
    root_input=next(c for c in context.d_baseline.cell_inputs if c.parent_cell_id is None)
    cell_ids=(root_input.cell_id,*root_input.ordered_planned_child_cell_ids) if len(context.native_declaration['source_groups'])==3 else root_input.ordered_planned_child_cell_ids
    bindings=[]
    for cell_id,indices in zip(cell_ids,context.native_declaration['source_groups'],strict=True):
        cell=next(c for c in context.d_baseline.cell_inputs if c.cell_id==cell_id)
        seed=next(a for q,a in zip(context.d_baseline.queue_entries,context.d_baseline.queue_artifacts,strict=True)
            if q.queue_entry_id==cell.ordered_initial_queue_entry_ids[0])
        bindings.append(dict(cell_id=cell_id,seed_artifact=authority.plain(seed),source_indices=indices,
            business_leaves=[context.native_declaration['leaves'][i] for i in indices]))
    context.native_bridge=dict(declaration_sha256=digest(context.native_declaration),
        baseline_report=context.d_baseline.runtime_report.report_id,bindings=bindings)
    context._frozen_declaration=canonical(context.native_declaration)
    context._frozen_bridge=canonical(context.native_bridge)
    controller._persist('dynamic_cold_native_business_bridge',context.native_bridge)
    core.prepare_origin(context)
    capture = core.capture_current(context)
    controller._persist('dynamic_informational_cold_capture', capture)
    controller.informational_context = context
    controller.emit('DYNAMIC_INFORMATIONAL_BASELINE_READY', wall_seconds=time.monotonic()-started,
        baseline_report_ref=context.d_baseline.runtime_report.report_id, origin_carrier=context.informational_origin.carrier.carrier_id)
    return context


def initial_plan(controller, sources):
    require(controller.informational_context is not None and controller.accepted is not None
        and controller.source_transition is None and controller.native_revision == 0,
        'dynamic_delta_current_origin_required')
    result=graphs.plan(controller.initial_sources,sources,controller.candidate,spec=controller.spec)
    require(result['native_source_groups']==controller.informational_context.native_declaration['source_groups'],
        'dynamic_delta_cold_dependency_mapping_changed')
    return result


def _validate_native_return(context, arguments, bundle, validation, plan):
    require(type(bundle) is delta.ContinuousDeltaExecutionBundleV01 and validation.status == 'PASS'
        and delta.validate_continuous_delta_execution_bundle_v01(bundle).status == 'PASS',
        'dynamic_delta_native_return_invalid')
    require(bundle.source_context is arguments['source_context']
        and bundle.source_context.baseline_g2d_execution_bundle is context.d_baseline
        and bundle.delta == arguments['delta'], 'dynamic_delta_native_source_identity')
    core.validate_consumption_boundary(context, bundle.source_context)
    current, baseline = bundle.recomputed_g2d_execution_bundle, context.d_baseline
    root = next(c for c in baseline.cell_inputs if c.parent_cell_id is None)
    if plan['native_scope'] == 'STRICT_SUBSET_ONE_NATIVE_CHILD':
        group = next(i for i, indices in enumerate(plan['native_source_groups']) if plan['changed_index'] in indices)
        affected, retained = root.ordered_planned_child_cell_ids[group], root.ordered_planned_child_cell_ids[1-group]
        require(bundle.recomputation_plan.ordered_affected_cell_ids == (affected,)
            and type(current) is fractal.FractalRetainedWorkExecutionBundleV01
            and fractal.validate_fractal_retained_work_execution_bundle_v01(current).status == 'PASS',
            'dynamic_delta_native_affected_closure')
        historical = next(r for r in baseline.cell_results if r.cell_id == retained)
        require(len(current.retained_consumptions) == 1 and current.retained_consumptions[0].consumed_result == historical
            and not any(q.cell_id == retained for q in current.queue_entries), 'dynamic_delta_native_retained_consumption')
        fresh = next(r for r in current.cell_results if r.cell_id == affected)
        parent = next(r for r in current.cell_results if r.parent_cell_id is None)
        results = {affected:fresh.result_id, retained:historical.result_id}
        require(parent.ordered_child_result_ids == tuple(results[cell] for cell in root.ordered_planned_child_cell_ids),
            'dynamic_delta_native_parent_consumption')
        return dict(native_E='PASS', native_retained_consumer='PASS',
            affected_cell=affected, retained_cell=retained, retained_result_sha256=digest(authority.plain(historical)),
            parent_result_id=parent.result_id, retained_consumption_ref=current.retained_consumptions[0].consumption_id)
    require(arguments['retained_profile'] is None and type(current) is fractal.FractalRuntimeExecutionBundleV02
        and fractal.validate_fractal_runtime_execution_bundle_v02(current).status == 'PASS'
        and set(bundle.recomputation_plan.ordered_affected_cell_ids) == {c.cell_id for c in baseline.cell_inputs},
        'dynamic_delta_full_closure_required')
    return dict(native_E='PASS', native_retained_consumer='NOT_APPLICABLE_FULL_CLOSURE',
        selective_acceptance=False, execution='WHOLE_RUN_ESCALATION')


def _revise_business(controller, plan):
    from dataclasses import replace
    from .dynamic_native import literal, MAX_ITEMS, MAX_REVISIONS, MAX_COMPUTE_UNITS, MAX_NATIVE_CHILD_BUDGET
    from .dynamic_control import build_control_source
    context, previous = controller._context(), controller.program.candidate.revision_id
    changed, route = plan['changed_index'], plan['route']
    retained = {}
    if route != 'short':
        for i, source in enumerate(controller.initial_sources):
            if i != changed:
                value = work.build_work_historical_output_v01(context, revision_id=previous,
                    work_id='extract'+str(i), output_field='material')
                require(work.validate_work_historical_output_v01(value, context=context) == (True, ()),
                    'dynamic_delta_historical_output_invalid')
                retained[i] = value
    trigger_slot = next(iter(retained), None)
    trigger = work.build_work_revision_trigger_v01(context,
        work_id='extract'+str(trigger_slot) if trigger_slot is not None else controller.results[-1].work_id,
        output_field='material' if trigger_slot is not None else 'result')
    number = controller.native_revision + 1
    require(number <= MAX_REVISIONS, 'dynamic_delta_revision_budget_exhausted')
    if not retained:
        previous_output=trigger.output
        old_business=json.loads(previous_output.value.value)
        items=(controller._item('delta_full'+str(number),'source_delta',
            (literal('material',dict(controller._material('source_delta'),sources=controller.initial_sources,
                prior_business_sha256=digest(old_business))),work.WorkInputBindingV01('previous',previous_output))),)
    else:
        source = controller.initial_sources[changed]
        changed_id, gate_id, audit_id = 'delta_extract'+str(number), 'delta_gate'+str(number), 'delta_audit'+str(number)
        branch = controller._item(changed_id, 'extract', (literal('material', dict(source=source,
            claims=[c for c in controller.candidate['claims'] if c['source_ref']==source['source_ref']])),))
        gate = controller._item(gate_id, 'gate', (literal('material', controller.candidate),))
        branches = [work.WorkOutputBindingV01(changed_id,'material','TEXT') if i==changed else retained[i]
            for i in range(len(controller.initial_sources))]
        exception_source = next((c['source_ref'] for c in controller.candidate['claims'] if c['kind']=='exception'),
            controller.initial_sources[0]['source_ref'])
        audit_index = next(i for i,s in enumerate(controller.initial_sources) if s['source_ref']==exception_source)
        audit = controller._item(audit_id,'audit',(work.WorkInputBindingV01('material',branches[audit_index]),),
            depends=(gate_id,changed_id) if audit_index==changed else (gate_id,),
            guard=work.WorkOutputBindingV01(gate_id,'enabled','BOOLEAN'))
        inputs = [literal('material',controller._material('aggregate'))]
        inputs.extend(work.WorkInputBindingV01('branch'+str(i),value) for i,value in enumerate(branches))
        enabled = controller.candidate['program']['optional_exceptions'] and any(c['kind']=='exception' for c in controller.candidate['claims'])
        if enabled:
            inputs.append(work.WorkInputBindingV01('audit',work.WorkOutputBindingV01(audit_id,'material','TEXT')))
        parent = controller._item('delta_result'+str(number),'aggregate_audit' if enabled else 'aggregate_plain',inputs,
            depends=(changed_id,audit_id) if enabled else (changed_id,))
        items = (branch,gate,audit,parent)
    usage = context.snapshot.usage
    budget = work.WorkBudgetV01(MAX_ITEMS, MAX_NATIVE_CHILD_BUDGET-usage.children-usage.reserved_children,
        0, MAX_COMPUTE_UNITS-usage.compute_units, MAX_REVISIONS-number)
    obligation, control_source = None, None
    if route == 'nested':
        item = replace(items[-1],review_obligation_id='review:pending_source')
        contextual = replace(context,trigger=trigger)
        def proposed(final):
            return work.build_work_program_candidate_v01(task_id=controller.spec.task_id,previous_revision_id=previous,
                intent_ref=controller.intent_ref,bsep_ref=controller.program.candidate.bsep_ref,
                semantic_proposal_ref=controller.program.candidate.semantic_proposal_ref,catalogue_revision=0,
                budget=budget,items=(*items[:-1],final),trigger_evidence_refs=(trigger.trigger_id,),
                continuation_context=contextual,**controller.common)
        candidate = proposed(item)
        program = work.materialize_work_program_v01(candidate,continuation_context=contextual,**controller.common)
        control_source, _unchanged_common = build_control_source(program,controller.common,route='nested',now=controller.now())
        # Build the exact public obligation with original immutable Work origin.
        obligation = work.build_work_review_obligation_v01(candidate=candidate,item=item,source_context=control_source)
        item = replace(item,review_obligation_id=obligation.obligation_id)
        candidate = proposed(item)
        obligation = work.build_work_review_obligation_v01(candidate=candidate,item=item,source_context=control_source)
        items = (*items[:-1],item)
    revised = work.revise_work_program_v01(context,previous_revision_id=previous,trigger=trigger,items=items,budget=budget,**controller.common)
    require(revised.status != 'EXHAUSTED','dynamic_delta_revision_budget_exhausted')
    controller.native_revision = number
    if obligation is not None:
        observed = work.execute_work_task_review_v01(controller._context(),obligation=obligation,
            source_context=control_source,semantic_proposal=controller.semantic)
        require(type(observed) is tuple and len(observed)==3,'dynamic_delta_exact_nested_review_required')
        controller.control_source,controller.control_bundle,controller.review_bindings = control_source,observed[2],(observed,)
        controller._persist('dynamic_delta_exact_nested_review',observed)
    controller._advance(revised.program)
    final = controller.results[-1]
    inputs = authority.values(final.invocation.inputs)
    for i, historical in retained.items():
        require(inputs['branch'+str(i)] == historical.value.value,'dynamic_delta_business_retained_not_consumed')
    witness = dict(status='PASS',historical_bindings=retained,trigger=trigger,
        actual_parent_invocation=final.invocation,actual_parent_result=final.result,
        unchanged_business_outputs_consumed=len(retained),full_recompute=not retained)
    controller._persist('dynamic_delta_business_consumer',witness)
    return witness


def continue_sources(controller, sources, *, store, source_transition):
    from . import source_successor
    from .dynamic_roles import DynamicRoleRun
    require(controller.informational_context is not None and controller.native_revision==0,
        'dynamic_delta_current_origin_required')
    context = controller.informational_context
    old_sources,old_candidate,old_common = controller.initial_sources,controller.candidate,controller.common
    _ref,row = source_successor.validate(store,source_transition,sources,statuses=('STARTED',))
    require(row['task_id']==controller.spec.task_id and row['base']['prior_root_sha256']==digest(controller.accepted.plain['root']),
        'dynamic_delta_prior_root_changed')
    # Stage the typed current-source snapshot only after its durable TaskStore start.
    controller.source_transition,controller.source_transition_store = source_transition,store
    controller.initial_sources = json.loads(canonical(sources))
    controller.family = None
    controller.intake_review = None
    controller.admit_intake()
    controller.role_run = DynamicRoleRun(controller,controller.spec,controller.initial_sources)
    for role in ('orchestrator','architect'):
        request=controller.role_run.issue(role)
        observation=controller.client.propose(role=role,context=request.context,output_schema=json.loads(request.schema_bytes),role_request=request)
        controller.role_run.consume(request,observation)
        if role=='orchestrator':
            controller._persist('dynamic_delta_pre_architect_family',source_family_witness(controller.role_run.family))
    family,candidate=controller.role_run.family,controller.role_run.candidate
    candidate=_candidate(controller.spec,candidate,controller.initial_sources,family.projection)
    plan=graphs.plan(old_sources,controller.initial_sources,old_candidate,candidate,spec=controller.spec)
    require(canonical(context.native_declaration)==context._frozen_declaration
        and canonical(context.native_bridge)==context._frozen_bridge
        and context.native_bridge['declaration_sha256']==digest(context.native_declaration)
        and context.native_bridge['baseline_report']==context.d_baseline.runtime_report.report_id,
        'dynamic_delta_cold_bridge_changed')
    require(plan['native_source_groups']==context.native_declaration['source_groups'],
        'dynamic_delta_cold_dependency_mapping_changed')
    controller._persist('dynamic_delta_current_dependency_plan',dict(plan=plan,cold_bridge=context.native_bridge))
    usage=controller._context().snapshot.usage
    require(usage.revisions < 2 and usage.compute_units+4 <= 32
        and (plan['route']!='nested' or usage.children+usage.reserved_children+20<=24),
        'dynamic_delta_pre_e_work_budget_exhausted')
    source_successor.advance(store,source_transition,'PLANNED',plan=plan)
    controller.family,controller.candidate=family,candidate
    require(controller.common is old_common,'dynamic_delta_immutable_work_origin_changed')
    context.delta_expected=dict(old=context.sources,updated=material.normalize_sources(sources),changed_index=plan['changed_index'])
    components=core.prepare_delta_components(context,sources,plan['changed_index'])
    arguments=build_arguments(context,components[1],plan['changed_index'],components[0],*components[2:],plan)
    capture_ref=controller._persist('dynamic_delta_current_capture',dict(capture=components[2],
        observed_artifact=components[3],invalidation=components[4]))
    input_ref=controller._persist('dynamic_delta_native_input',dict(graph=plan,arguments=arguments))
    guard=getattr(controller,'owner_scenario_guard',None)
    if guard is not None:
        from .owner_scenario import SelectiveScenarioGuard
        require(type(guard)is SelectiveScenarioGuard,'dynamic_delta_owner_guard_type')
        guard.before_e(controller,plan,context,arguments,capture_ref,input_ref)
    from .native_report_observer import observe_e
    event_sink=getattr(controller.client,'owner_event_sink',None)
    require(callable(event_sink),'dynamic_delta_owner_observer_required')
    profile=getattr(controller.client,'_ordinary_profile_manifest',None)
    e_call_id='owner_E_'+digest(dict(task=controller.spec.task_id,source_scope=sources))[:32]
    report_workspace=controller.evidence_directory/('native_e_'+e_call_id)
    report_workspace.mkdir(mode=0o700)
    def report_event(kind,phase,**details):return event_sink(dict(kind=kind,phase=phase,**details))
    observer_refs=tuple(dict(path=str(Path(ref['path']).relative_to(controller.client.project)),
        sha256=ref['sha256'],size_bytes=ref['bytes'])for ref in (capture_ref,input_ref))
    native_entrypoint=delta.run_continuous_delta_runtime_v01
    with observe_e(controller,report_event,report_workspace,native_entrypoint=native_entrypoint,
            profile=profile,e_call_id=e_call_id,
            input_refs=observer_refs) as observer:
        controller.emit('DYNAMIC_NATIVE_E_START',native_scope=plan['native_scope'],e_call_id=e_call_id,
            capture_ref=capture_ref,input_ref=input_ref)
        with controller._pulse('INFORMATIONAL_NATIVE_E'):
            bundle,validation=native_entrypoint(**arguments)
        observer.native_return(validation)
        native=_validate_native_return(context,arguments,bundle,validation,plan)
        native_ref=controller._persist('dynamic_delta_native_return',dict(bundle=bundle,consumer=native))
    controller.emit('DYNAMIC_NATIVE_E_RETURN',e_call_id=e_call_id,native_return_ref=native_ref)
    business=_revise_business(controller,plan)
    projection=controller.projection()
    controller.role_run.bind_native_work(projection)
    request=controller.role_run.issue('critic')
    observation=controller.client.propose(role='critic',context=request.context,output_schema=json.loads(request.schema_bytes),role_request=request)
    controller.role_run.consume(request,observation)
    context.sources=material.normalize_sources(sources)
    context.accepted=controller.accepted
    core.require_publication(context)
    outcome=controller._accept(projection,critic=controller.role_run.critic,provenance=controller.role_run.provenance)
    controller._persist('dynamic_delta_final_consumers',dict(native=native,business=business,
        source_successor_id=source_transition.successor_id,final_root=authority.root_plain(controller.final_root)))
    return controller._remember(outcome)
