"""Prepared native scenario through the existing task runner and public Work APIs.

The owner entry authorizes this finite scenario. Model products remain evidence:
actual short routes and missing claim kinds are reported, never rewritten.
"""
from .contracts import canonical, digest, require


SCHEMA = 'radik.stage04.native_scenario_result.v01'
PLAN = (
    dict(name='conditions_and_exceptions', profile='compare',
        goal='Compare the approved documents and distinguish source-backed conditions, exceptions and unresolved information.',
        criterion='Cite exact source spans, keep qualifications explicit, and choose the warranted native execution route.',
        updates=('focus_exceptions', 'focus_conditions')),
    dict(name='nested_and_unknowns', profile='explain',
        goal='Explain the approved documents as a coherent hierarchy of obligations, conditions, exceptions and unknowns where supported.',
        criterion='Cite exact source spans and use nested native decomposition only when warranted by the task.',
        updates=('review_unknowns',)),
)
KINDS = dict(focus_conditions=('condition',), focus_exceptions=('exception',),
    review_unknowns=('unknown', 'contradiction'))


def _copy(value):
    import json
    return json.loads(canonical(value))


def _origin(controller):
    candidate = controller.program.candidate
    return dict(task_id=candidate.task_id, intent_ref=candidate.intent_ref, bsep_ref=candidate.bsep_ref,
        semantic_proposal_ref=candidate.semantic_proposal_ref, candidate_sha256=digest(controller.candidate),
        family_ref=controller.family.family_ref, source_ref=controller._context().snapshot.policy.source_ref)


def _native(controller):
    from hedgehog.kernel import work_composition_v01 as work
    from . import native_authority as authority
    context = controller._context()
    history = work.inspect_work_task_history_v01(context)
    rows = []
    for program, results, artifact, trigger in history:
        candidate = program.candidate
        rows.append(dict(revision_id=candidate.revision_id, previous_revision_id=candidate.previous_revision_id,
            task_id=candidate.task_id, intent_ref=candidate.intent_ref, bsep_ref=candidate.bsep_ref,
            semantic_proposal_ref=candidate.semantic_proposal_ref, budget=authority.plain(candidate.budget),
            trigger=authority.plain(trigger), artifact_ref=None if artifact is None else artifact.artifact_id,
            items=[dict(work_id=result.work_id, status=result.status,
                invocation_id=None if result.invocation is None else result.invocation.invocation_id,
                result_id=None if result.result is None else result.result.result_id,
                consumed_fields=authority.plain(result.consumed_fields)) for result in results]))
        for result in results:
            if result.invocation is not None:
                require(result.invocation.candidate_id is None and result.invocation.packet_id is None,
                    'native_scenario_pure_invocation')
    require(context.snapshot.policy.max_model_calls == 0 and context.snapshot.policy.max_revisions <= 2
        and context.snapshot.usage.model_calls == 0, 'native_scenario_native_budget')
    return dict(policy=authority.plain(context.snapshot.policy), usage=authority.plain(context.snapshot.usage),
        outcome=context.snapshot.outcome, history=rows, provider_calls=0, effects=0)


def _accepted(controller, outcome):
    from .dynamic_native import DynamicAcceptedResult
    require(type(outcome) is DynamicAcceptedResult and outcome.controller is controller
        and outcome is controller.accepted, 'native_scenario_accepted_origin')
    outcome.projection.validate(controller.spec, controller.candidate, controller.family)
    plain = outcome.plain
    provenance = plain['semantic_pipeline']['provenance']
    receipts = [value['reservation_id'] for value in provenance.values()
        if type(value) is dict and 'reservation_id' in value]
    return dict(result_id=plain['result_id'], result_sha256=plain['result_sha256'],
        task_id=plain['task_id'], accepted_at=plain['accepted_at'], valid_to=plain['valid_to'],
        root_decision=plain['root']['result']['decision'],
        root_decision_id=plain['root']['result']['decision_id'],
        actual_route=controller.candidate['program']['route'],
        memory_origin=_copy(plain['semantic_pipeline']['memory_origin']),
        native_revision=plain['work']['native_revision'], work=_copy(plain['work']),
        role_reservation_ids=receipts, evidence_refs=_copy(controller.evidence_refs), native=_native(controller))


def run_native_scenario(*, store, run_task, controllers, source_ids, owner_operation_id, run_id, client, report_sink=None):
    """Run two independently declared baselines using the existing runtime callback.

    run_task(task_id, condition=None) returns its genuine DynamicAcceptedResult or
    native EXHAUSTED outcome. It owns durable normal-round/history/budget writes.
    Conditions use zero-attempt NATIVE_CONTINUE rounds on the same live controller.
    report_sink, if supplied, receives JSON-safe snapshots; it grants no authority.
    """
    require(callable(run_task) and type(controllers) is dict and type(source_ids) in (tuple, list)
        and 1 <= len(source_ids) <= 4 and len(set(source_ids)) == len(source_ids)
        and set(source_ids) <= set(store.state['sources']) and store.state['active_task_id'] is None
        and type(owner_operation_id) is str and bool(owner_operation_id)
        and type(run_id) is str and bool(run_id) and (report_sink is None or callable(report_sink))
        and client.budget._normal_operation is not None
        and client.budget._console_operation == dict(owner_operation_id=owner_operation_id, run_id=run_id),
        'native_scenario_entry_scope')
    report = dict(schema=SCHEMA, status='STARTED', owner_operation_id=owner_operation_id, run_id=run_id,
        source_ids=list(source_ids), task_ids={}, steps=[], boundary_observations=[],
        ledger_before=client.budget.snapshot(), ledger_after=None, current_phase='TASK_EXECUTION', current_step='NATIVE_SCENARIO_PREPARE',
        baseline_plan=[dict(name=item['name'], profile=item['profile'],
            updates=list(item['updates'])) for item in PLAN], baselines=[],
        model_routes_forced=False, model_products_rewritten=False, native_max_revisions=2,
        native_provider_calls=0, external_effects=0, native_E_status='BLOCKED_INFORMATIONAL_ACTION_PACKET_UNAVAILABLE',
        selective_delta_accepted=False, actual_acceptance=False)
    def publish():
        report['ledger_after'] = client.budget.snapshot()
        if report_sink is not None:
            try:
                report_sink(_copy(report))
            except BaseException as error:
                from .stage04_diagnostics import observe_failure
                observe_failure(error, phase='CONNECTED_REPORT_WRITE', step=report['current_step'])
                raise
    publish()
    try:
        # Both independent intents exist before either chain can exhaust. The
        # second baseline is not created to resume or evade the first one's cap.
        planned = []
        for item in PLAN:
            task_id = store.create(goal=item['goal'], source_ids=tuple(source_ids), profile=item['profile'],
                criterion=item['criterion'], topic='stage04_native_' + item['name'])
            planned.append((item, task_id))
        report['planned_task_ids'] = [task_id for _, task_id in planned]
        report['task_ids'] = dict(decomposed=planned[0][1], nested=planned[1][1])
        publish()
        for item, task_id in planned:
            prefix = 'D' if item['profile'] == 'compare' else 'N'
            report['current_step'] = prefix + '_COLD'
            before_cold = len(client.budget.snapshot()['attempts'])
            row = dict(name=item['name'], task_id=task_id, status='BASELINE_STARTED', updates=[])
            report['baselines'].append(row); publish()
            outcome = run_task(task_id)
            require(task_id in controllers, 'native_scenario_controller_missing')
            controller = controllers[task_id]
            row['baseline'] = _accepted(controller, outcome)
            report['steps'].append(dict(step=report['current_step'], task_id=task_id,
                new_turn_attempts=len(client.budget.snapshot()['attempts']) - before_cold,
                accepted_result=_copy(outcome.plain), native_snapshot=controller.snapshot()))
            row['status'] = 'BASELINE_ACCEPTED'; publish()
            if controller.memory_origin is not None:
                row['status'] = 'QUALIFIED_MEMORY_OBSERVED_NO_LIVE_U2_BASELINE'
                publish(); continue
            origin, host = _origin(controller), controller.host
            policy = controller._context().snapshot.policy
            row['origin'] = origin
            completed = 0
            for kind in item['updates']:
                indexes = [index for index, claim in enumerate(controller.candidate['claims']) if claim['kind'] in KINDS[kind]]
                if not indexes:
                    row['updates'].append(dict(kind=kind, status='CLAIM_KIND_NOT_OBSERVED',
                        provider_reservations=0, native_dispatches=0))
                    continue
                before = controller.client.budget.snapshot()
                native_before = controller._context().snapshot
                update = dict(kind=kind, claim_indexes=indexes)
                report['current_step'] = prefix + '_' + {'focus_exceptions': 'EXCEPTIONS',
                    'focus_conditions': 'CONDITIONS', 'review_unknowns': 'UNKNOWNS'}[kind]
                publish()
                result = run_task(task_id, update)
                after = controller.client.budget.snapshot()
                require(controllers[task_id] is controller and controller.host is host
                    and _origin(controller) == origin and controller._context().snapshot.policy == policy,
                    'native_scenario_u2_origin_changed')
                require(after['attempts'] == before['attempts'] and after['active_attempt_id'] is None,
                    'native_scenario_u2_provider_reservation')
                if getattr(result, 'status', None) == 'EXHAUSTED':
                    row['updates'].append(dict(kind=kind, status='EXHAUSTED', reason=result.reason,
                        provider_reservations=0, native=_native(controller)))
                    break
                observed = _accepted(controller, result)
                require(controller._context().snapshot.usage.revisions == native_before.usage.revisions + 1,
                    'native_scenario_revision_count')
                row['updates'].append(dict(kind=kind, status='ACCEPTED', update=update, observation=observed,
                    provider_reservations=0))
                report['steps'].append(dict(step=report['current_step'], task_id=task_id, new_turn_attempts=0,
                    accepted_result=_copy(result.plain), native_snapshot=controller.snapshot()))
                completed += 1; publish()
            if completed == 2:
                # This explicit finite boundary probe never starts a fresh host,
                # baseline or provider turn. The immutable policy must exhaust.
                last = next(value['update'] for value in reversed(row['updates']) if value['status'] == 'ACCEPTED')
                before = controller.client.budget.snapshot()
                results_before = tuple(controller.results)
                report['current_step'] = prefix + '_REVISION_BOUNDARY'; publish()
                boundary = run_task(task_id, _copy(last))
                require(getattr(boundary, 'status', None) == 'EXHAUSTED'
                    and boundary.reason == 'work_task_revision_exhausted'
                    and controller.client.budget.snapshot()['attempts'] == before['attempts']
                    and controller.results == results_before and controller.host is host,
                    'native_scenario_revision_boundary')
                row['boundary'] = dict(status=boundary.status, reason=boundary.reason,
                    provider_reservations=0, native_dispatches=0, native=_native(controller))
                report['boundary_observations'].append(dict(task_id=task_id, **row['boundary']))
            row['status'] = 'BOUNDED_OBSERVATIONS_COMPLETE'
            row['actual_route'] = controller.candidate['program']['route']
            publish()
        accepted_updates = [update for row in report['baselines'] for update in row['updates'] if update['status'] == 'ACCEPTED']
        kinds = {update['kind'] for update in accepted_updates}
        nested = [row for row in report['baselines'] if row['baseline']['work']['control'] is not None]
        expansion = next((update for update in accepted_updates if update['kind'] == 'focus_exceptions'), None)
        contraction = next((update for update in accepted_updates if update['kind'] == 'focus_conditions'), None)
        report['coverage'] = dict(accepted_update_kinds=sorted(kinds),
            nested_baseline_count=len(nested),
            nested_child_return_refs=[ref for row in nested for ref in row['baseline']['work']['control']['parent_return_refs']],
            exception_expansion_observed=expansion is not None and any(value['work_id'].startswith('revision_audit')
                and value['status'] == 'COMPLETED' for value in expansion['observation']['work']['actual_results']),
            condition_contraction_observed=contraction is not None and any(value['work_id'].startswith('revision_audit')
                and value['status'] == 'SKIPPED_GUARD_FALSE' for value in contraction['observation']['work']['actual_results']),
            zero_provider_native_continuations=True,
            source_routes=[row['baseline']['actual_route'] for row in report['baselines']])
        full = kinds == set(KINDS) and bool(nested) and report['coverage']['exception_expansion_observed'] \
            and report['coverage']['condition_contraction_observed']
        report['status'] = ('NATIVE_SCENARIO_OBSERVATIONS_COMPLETE_E_BLOCKED' if full
            else 'NATIVE_SCENARIO_PARTIAL_OBSERVATIONS_E_BLOCKED')
        report['current_phase'], report['current_step'] = 'REPORT', 'NATIVE_SCENARIO_COMPLETE'
        report['qualification'] = ('Native cells/child returns are G2D control evidence consumed by the exact business Work obligation; '
            'U1 extraction/audit outputs are separately consumed by the business aggregate. Short routes and missing kinds remain observations.')
        publish()
        return _copy(report)
    except BaseException as primary:
        from .stage04_diagnostics import observe_failure, project_error, record_secondary
        report['status'] = 'STOPPED_REVIEW_REQUIRED'
        observe_failure(primary, phase=report['current_phase'], step=report['current_step'])
        report['error'] = project_error(primary)
        report['current_phase'], report['current_step'] = report['error']['phase'], report['error']['step']
        try:
            report['partial_snapshots'] = [controllers[task_id].snapshot()
                for task_id in report.get('planned_task_ids', ()) if task_id in controllers]
        except Exception as secondary:
            record_secondary(primary, secondary, phase='TASK_HISTORY_WRITE', step=report['current_step'])
        if report_sink is not None:
            try:
                publish()
            except Exception as secondary:
                record_secondary(primary, secondary, phase='CONNECTED_REPORT_WRITE', step=report['current_step'])
        raise
