"""Owned-copy entry rehearsal; inert external responses, real internal guards.

This helper is admitted only through a typed SOURCE-only rehearsal context. It
does not run D or E and cannot award a selective owner-scenario result. Its six
responses come from the explicitly inert transport supplied by ordinary entry.
"""
import json
from pathlib import Path
import time


class _RehearsalClock:
    """Explicit test-time input; the live owner driver never constructs it."""
    def __init__(self, deadline):
        self.deadline, self.expired = deadline, False

    def __call__(self):
        return self.deadline if self.expired else int(time.time())


def _context(project, context):
    from config import application_profile_gate as gate
    from app.contracts import require
    require(type(context) is gate.RehearsalContext
        and gate.validate_rehearsal_context(project, context) is context,
        'scenario_rehearsal_typed_context_required')
    return context


def _export(export, name, value):
    from app.contracts import require
    from app.native_authority import plain
    require(callable(export), 'scenario_rehearsal_export_required')
    return export(name, plain(value))


def _refusal(call, expected):
    from app.contracts import require
    try:
        call()
    except (ValueError, TypeError, KeyError) as error:
        code = str(error)
        require(code == expected, 'scenario_rehearsal_unexpected_refusal:' + code)
        return dict(status='REFUSED', code=code)
    raise ValueError('scenario_rehearsal_missing_refusal:' + expected)


def structural_checks(project, context, export):
    """Pure topology and actual ordinary report writer, without native objects."""
    _context(project, context)
    from app.contracts import canonical, digest, require
    from app.owner_scenario import (check_selective_topology, ScenarioReportWriter,
        readback_reference, SCHEMA, MAX_REPORT_BYTES)
    sources = ['radik:source:' + '1'*32, 'radik:source:' + '2'*32]
    leaves = [dict(source=dict(source_ref=source), work_id='extract' + str(index))
        for index, source in enumerate(sources)]
    declaration = dict(schema='radik.dynamic.native_business_bridge.v01', route='decomposed',
        source_groups=[[0], [1]], leaves=leaves)
    bridge = dict(declaration_sha256=digest(declaration), bindings=[dict(cell_id='synthetic:cell:' + str(index),
        seed_artifact=dict(classification='SYNTHETIC_NO_AUTHORITY'), source_indices=[index],
        business_leaves=[leaf]) for index, leaf in enumerate(leaves)])
    result = dict(classification='SYNTHETIC_STRUCTURE_AND_WRITER_ONLY_NO_AUTHORITY',
        positive=check_selective_topology(declaration, bridge, sources, sources[0]))
    short = dict(declaration, route='short')
    result['short_refusal'] = _refusal(lambda: check_selective_topology(short, bridge, sources, sources[0]),
        'owner_scenario_cold_route_has_no_selective_topology')
    full = dict(declaration, source_groups=[[0, 1], [0, 1], [0, 1]])
    result['full_refusal'] = _refusal(lambda: check_selective_topology(full, bridge, sources, sources[0]),
        'owner_scenario_cold_full_closure_has_no_retained_proof')
    swapped = dict(bridge, bindings=list(reversed(bridge['bindings'])))
    result['swapped_refusal'] = _refusal(lambda: check_selective_topology(declaration, swapped, sources, sources[0]),
        'owner_scenario_cold_source_native_business_mapping')
    # A separate rehearsal run ID cannot overwrite the entry result's file.
    run_id = digest(dict(seal=context.seal_sha256, purpose='scenario_writer_probe'))[:12]
    writer = ScenarioReportWriter(project, run_id)
    value = dict(schema=SCHEMA, classification='SYNTHETIC_REPORT_WRITER_NO_AUTHORITY',
        status='WRITER_PREFLIGHT', unicode='UTF-8 \u03b1', values=[None, True, 1, {}, []])
    reference = writer.write(value)
    require(readback_reference(project, reference, cap=MAX_REPORT_BYTES) == value,
        'scenario_rehearsal_writer_readback')
    result['writer_readback'] = reference
    first_value=dict(value)
    value=dict(value,status='WRITER_SECOND_PUBLICATION')
    second_reference=writer.write(value)
    require(reference['path']!=second_reference['path']
        and readback_reference(project,reference,cap=MAX_REPORT_BYTES)==first_value
        and readback_reference(project,second_reference,cap=MAX_REPORT_BYTES)==value,
        'scenario_rehearsal_immutable_publications')
    result['second_writer_readback']=second_reference
    result['prior_snapshot_still_valid']=True
    oversize = dict(value, padding='x' * MAX_REPORT_BYTES)
    result['writer_size_refusal'] = _refusal(lambda: writer.write(oversize), 'owner_scenario_report_size')
    require(writer.path.read_bytes() == canonical(value), 'scenario_rehearsal_oversize_preserves_report')
    result['previous_run_refusal'] = _refusal(lambda: ScenarioReportWriter(project, run_id),
        'owner_scenario_no_uncertain_retry')
    _export(export, 'scenario_structure_and_writer', result)
    return result


def _issued_negatives(controller, run, request, client):
    """Real request validators refuse substitutions without a reservation."""
    from app.contracts import digest, require
    before = client.budget.snapshot()
    schema = json.loads(request.schema_bytes)
    def validate(**change):
        arguments = dict(sender=client, role=request.role, context=request.context,
            output_schema=schema, body=request.body)
        arguments.update(change)
        return request.validate(**arguments)
    decoded = json.loads(request.context)
    changed_source = json.loads(request.context)
    changed_source['sources'][0]['sha256'] = '0'*64
    changed_profile = json.loads(request.context)
    changed_profile['task']['profile'] = 'verify'
    foreign_task = json.loads(request.context)
    foreign_task['task_id'] = 'radik-task:' + '0'*32
    negatives = dict(
        sender=_refusal(lambda: validate(sender=object()), 'dynamic_role_request_origin'),
        role=_refusal(lambda: validate(role='critic' if request.role == 'orchestrator' else 'orchestrator'),
            'dynamic_role_stage_order'),
        source=_refusal(lambda: validate(context=json.dumps(changed_source)), 'dynamic_role_exact_context_schema'),
        profile=_refusal(lambda: validate(context=json.dumps(changed_profile)), 'dynamic_role_exact_context_schema'),
        task=_refusal(lambda: validate(context=json.dumps(foreign_task)), 'dynamic_role_exact_context_schema'),
        body=_refusal(lambda: validate(body=request.body + b' '), 'dynamic_role_exact_body'))
    valid_guard = validate()
    for key, changed in (('profile', 'verify'), ('dependencies_sha256', '0'*64),
            ('task_spec_sha256', '0'*64), ('task_id', 'radik-task:' + '0'*32)):
        tampered_guard = dict(valid_guard, **{key: changed})
        negatives['round_' + key] = _refusal(
            lambda guard=tampered_guard: client.budget.validate_task_request(guard),
            'budget_task_request_dependencies')
    require(type(controller.clock) is _RehearsalClock, 'scenario_rehearsal_clock_type')
    controller.clock.expired = True
    try:
        negatives['expired_before_reservation'] = _refusal(lambda: client.propose(role=request.role,
            context=request.context, output_schema=schema, role_request=request), 'dynamic_role_time')
    finally:
        controller.clock.expired = False
    require(client.budget.snapshot() == before, 'scenario_rehearsal_negative_reserved_attempt')
    negatives['unchanged_ledger_sha256'] = digest(before)
    negatives['scope'] = 'REAL_ISSUED_REQUEST_VALIDATOR_BEFORE_FIRST_RESERVATION'
    return negatives


def run(*, project, client, operation_ref, context, export, event_sink=None):
    """Six inert requests through fresh ordinary entry and real native Work.

    The second round deliberately stops at the business-only seam of the
    existing continuation. No fake informational origin or D/E result is made.
    """
    _context(project, context)
    from app.contracts import canonical, digest, require
    from app import normal_session, source_successor, dynamic_delta_graph
    from app.task_store import TaskStore
    from app.task_spec import meaning_key
    from app.dynamic_native import DynamicDocumentController
    from app.dynamic_roles import DynamicRoleRun
    from app.dynamic_work import _candidate
    from app.dynamic_delta import _revise_business
    from app import dynamic_semantics
    from hedgehog.kernel import work_composition_v01 as work
    from app.runtime import _information_policy_reader, _write_policy
    from app.dynamic_temporal import informational_valid_to
    from app.owner_scenario import DOCUMENT_A, DOCUMENT_B, DOCUMENT_A_UPDATED, GOAL, CRITERION
    project = Path(project).resolve(strict=True)
    require(project == Path(context.application_root).resolve(strict=True), 'scenario_rehearsal_owned_root')
    operation = normal_session.validate_operation(project, operation_ref)
    require(operation['schema'] == 'radik.normal_operation.v02'
        and client.budget._normal_operation == operation_ref and client.budget_scope == 'console',
        'scenario_rehearsal_normal_operation')
    workspace = project / 'workspace/owner_documents'
    store = TaskStore(workspace, require_existing=True)
    _write_policy(workspace)
    initial_state = json.loads(canonical(store.state))
    initial_ledger = client.budget.snapshot()
    source_a = store.register_source('p28:rehearsal:' + operation['run_id'] + ':a', 'rehearsal_alder.txt', DOCUMENT_A)
    source_b = store.register_source('p28:rehearsal:' + operation['run_id'] + ':b', 'rehearsal_birch.txt', DOCUMENT_B)
    task_id = store.create(goal=GOAL, source_ids=(source_a, source_b), profile='compare', criterion=CRITERION,
        topic='independent_support_conditions')
    spec = store.spec(task_id)
    controller = None
    result = dict(schema='radik.p28.ordinary_entry_rehearsal.v01',
        classification='SOURCE_ONLY_OWNED_COPY_INERT_EXTERNAL_TRANSPORT', task_id=task_id,
        source_only_scope=True, actual_D_calls=0, actual_E_calls=0, real_AUTH_calls=0,
        real_provider_calls=0, selective_owner_scenario_proven=False, rounds=[], negatives=[])

    def persist(name):
        result['task_state'] = json.loads(canonical(store.state))
        result['ledger'] = client.budget.snapshot()
        _export(export, name, result)

    def roles(run, names):
        for role in names:
            request = run.issue(role)
            if role == 'orchestrator':
                result['negatives'].append(_issued_negatives(controller, run, request, client))
            observation = client.propose(role=role, context=request.context,
                output_schema=json.loads(request.schema_bytes), role_request=request)
            run.consume(request, observation)

    def begin(*, successor=None):
        sources = store.prepare_round_sources(spec)
        store.check_dispatch_sources(task_id, sources, source_transition=successor)
        dependencies = dict(meaning_key=meaning_key(spec, sources),
            sources=[{key: row[key] for key in ('source_ref', 'revision', 'sha256')} for row in sources])
        binding = client.budget.begin_task_round(task_id=task_id, profile=spec.profile,
            task_spec_sha256=digest(spec.plain()), dependencies_sha256=digest(dependencies), max_attempts=3,
            mode='INFORMATIONAL_DELTA' if successor is not None else 'COLD',
            source_successor_ref=successor.staged_ref if successor is not None else None)
        if successor is not None:
            source_successor.advance(store, successor, 'ROUND_LINKED', round_binding=binding)
        # The durable grant is read before TaskStore start and any reservation.
        grant = normal_session.validate_round(project, binding, task_state=store.state,
            before_begin=True, current=True)
        _export(export, 'round_grant_before_start_' + str(len(result['rounds'])),
            dict(binding=binding, grant=grant, counted=len(client.budget.snapshot()['attempts'])))
        store.begin(task_id, sources, operation_round=binding, source_transition=successor)
        return sources, binding

    try:
        sources, binding = begin()
        try:
            controller = DynamicDocumentController(workspace, client, task_spec=spec,
                source_reader=store.source_reader(spec),
                clock=_RehearsalClock(operation['opened_at'] + 7800),
                policy_reader=_information_policy_reader(workspace, informational_valid_to(int(time.time())),
                    informational_delta=True), informational_delta=True,
                operation_deadline=operation['opened_at'] + 7800, on_event=event_sink)
            controller.admit_intake()
            run_roles = DynamicRoleRun(controller, spec, sources)
            controller.role_run = run_roles
            roles(run_roles, ('orchestrator', 'architect'))
            controller.family, controller.candidate = run_roles.family, run_roles.candidate
            require(controller.candidate['program']['route'] == 'short', 'scenario_rehearsal_inert_short_only')
            controller._start()
            projection = controller.projection()
            run_roles.bind_native_work(projection)
            roles(run_roles, ('critic',))
            cold = controller._remember(controller._accept(projection,
                critic=run_roles.critic, provenance=run_roles.provenance))
            store.complete(task_id, cold.plain)
            _export(export,'entry_cold_full_work_witness',dict(program=controller.program,artifact=controller.artifact,
                results=controller.results,history=work.inspect_work_task_history_v01(controller._context()),
                completed_work=controller.host.completed_work,source_family=dynamic_semantics.source_family_witness(controller.family),
                evidence_refs=list(controller.evidence_refs),accepted=cold.plain,actual_model_roles=False))
            result['rounds'].append(dict(mode='COLD', binding=binding, accepted=cold.plain,
                snapshot=controller.snapshot()))
        finally:
            client.budget.end_task_round()
        persist('entry_rehearsal_cold_actual')
        old_sources, old_candidate = controller.initial_sources, controller.candidate
        require(store.register_source('p28:rehearsal:' + operation['run_id'] + ':a',
            'rehearsal_alder.txt', DOCUMENT_A_UPDATED) == source_a, 'scenario_rehearsal_source_identity')
        updated = store.prepare_round_sources(spec)
        graph = dynamic_delta_graph.plan(old_sources, updated, old_candidate, spec=spec)
        successor = store.stage_source_successor(task_id, updated, affected_graph=graph)
        sources, binding = begin(successor=successor)
        try:
            source_successor.validate(store, successor, sources, statuses=('STARTED',))
            controller.source_transition, controller.source_transition_store = successor, store
            controller.initial_sources = json.loads(canonical(sources))
            controller.family = controller.intake_review = None
            controller.admit_intake()
            run_roles = DynamicRoleRun(controller, spec, sources)
            controller.role_run = run_roles
            roles(run_roles, ('orchestrator', 'architect'))
            candidate = _candidate(spec, run_roles.candidate, sources, run_roles.family.projection)
            plan = dynamic_delta_graph.plan(old_sources, sources, old_candidate, candidate, spec=spec)
            require(plan['route'] == 'short' and plan['native_scope'] == 'FULL_CLOSURE_NO_RETAINED_PROOF',
                'scenario_rehearsal_business_only_scope')
            source_successor.advance(store, successor, 'PLANNED', plan=plan)
            controller.family, controller.candidate = run_roles.family, candidate
            consumer = _revise_business(controller, plan)
            projection = controller.projection()
            run_roles.bind_native_work(projection)
            roles(run_roles, ('critic',))
            changed = controller._remember(controller._accept(projection,
                critic=run_roles.critic, provenance=run_roles.provenance))
            store.complete(task_id, changed.plain)
            _export(export,'entry_delta_business_full_work',dict(program=controller.program,artifact=controller.artifact,
                results=controller.results,history=work.inspect_work_task_history_v01(controller._context()),
                completed_work=controller.host.completed_work,source_family=dynamic_semantics.source_family_witness(controller.family),
                consumer=consumer,evidence_refs=list(controller.evidence_refs),accepted=changed.plain,
                actual_model_roles=False,actual_E_calls=0))
            result['rounds'].append(dict(mode='INFORMATIONAL_DELTA', binding=binding,
                plan=plan, business_consumer=consumer, accepted=changed.plain,
                snapshot=controller.snapshot(), explicit_omission='NO_INFORMATIONAL_PREPARATION_D_OR_E'))
        finally:
            client.budget.end_task_round()
        require(len(client.budget.snapshot()['attempts']) - len(initial_ledger['attempts']) == 6,
            'scenario_rehearsal_six_inert_requests')
        # Existing history and acknowledgement bytes are checked again by the
        # parent fresh-process reader; this check also keeps all old task rows.
        require(all(store.state['tasks'][key] == value for key, value in initial_state['tasks'].items()),
            'scenario_rehearsal_historical_tasks_changed')
        ledger = client.budget.snapshot()
        require(ledger['attempts'][:len(initial_ledger['attempts'])] == initial_ledger['attempts'],
            'scenario_rehearsal_historical_attempts_changed')
        result.update(status='PASS_ENTRY_INERT_REQUESTS_AND_BUSINESS_ONLY_ROUNDS',
            actual_request_count=6, information_native_E='NOT_RUN', owner_semantics='NOT_ESTABLISHED')
        persist('entry_rehearsal_actual')
        return result
    except BaseException as error:
        result.update(status='STOPPED_NO_AUTOMATIC_RETRY', primary_failure=dict(type=type(error).__name__,
            code=str(error)[:512]), snapshot=None if controller is None else controller.snapshot())
        try:
            persist('entry_rehearsal_partial')
        except BaseException as secondary:
            try:
                error.add_note('rehearsal_secondary_export_failure:' + type(secondary).__name__)
            except AttributeError:
                pass
        raise
