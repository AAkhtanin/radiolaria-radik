"""Fresh-process SOURCE-only ordinary history and discarded-grant controls.

No action in this module is available to a production owner console. All
imports and actions require the independently sealed owned rehearsal copy.
"""
import json
from pathlib import Path
import uuid


def _context(project, context):
    from config import application_profile_gate as gate
    from app.contracts import require
    require(type(context) is gate.RehearsalContext
        and gate.validate_rehearsal_context(project, context) is context,
        'lifecycle_rehearsal_context_required')
    return context


def _raw(project, relative):
    from app.normal_session import _read
    from app.contracts import digest
    raw = _read(project, relative, 32 * 1024 * 1024)
    return dict(path=relative, sha256=digest(raw), bytes=len(raw), value=json.loads(raw))


def _started(tasks):
    return {event['operation_round']['round_id']: event['operation_round']
        for row in tasks['tasks'].values() for event in row['history']
        if event['kind'] == 'ROUND_STARTED' and 'normal_round_scope' in event.get('operation_round', {})}


def _witness(project):
    from app import normal_session as normal, normal_profile, task_budget
    from app.task_store import TaskStore
    from app.contracts import require
    before_tasks = normal._read(project, normal.TASKS)
    before_ledger = normal._read(project, normal.LEDGER)
    state = task_budget.read_state(project)
    store = TaskStore(Path(project) / 'workspace/owner_documents', require_existing=True)
    ledger = json.loads(before_ledger)
    rounds = normal.validate_history(project, ledger, store.state)
    grants = normal_profile.index(project)
    reconciled = normal_profile.reconcile_index(project, ledger, store.state, _started(store.state))
    require(normal._read(project, normal.TASKS) == before_tasks
        and normal._read(project, normal.LEDGER) == before_ledger,
        'lifecycle_readonly_history_changed')
    result = dict(task_budget_state=state, ledger=_raw(project, normal.LEDGER),
        task_state=_raw(project, normal.TASKS), indexed_grants=grants,
        validated_rounds=rounds, reconciled=reconciled,
        no_live_controller_constructed=True, no_Host_Root_or_tokens_restored=True,
        provider_calls=0, native_D_E_calls=0)
    if normal._path(project, normal.ACTIVE).exists():
        result['active'] = _raw(project, normal.ACTIVE)
    if normal._path(project, normal_profile.INDEX).exists():
        result['grant_index'] = _raw(project, normal_profile.INDEX)
    return store, ledger, result


def _export(export, name, value):
    from app.native_authority import plain
    from app.contracts import require
    require(callable(export), 'lifecycle_export_required')
    return export(name, plain(value))


def _refusal(call, expected):
    from app.contracts import require
    try:
        call()
    except ValueError as error:
        require(str(error) == expected, 'lifecycle_unexpected_refusal:' + str(error))
        return dict(status='REFUSED', code=str(error))
    raise ValueError('lifecycle_expected_refusal_missing:' + expected)


def run(action, *, project, context, client, operation_ref, owner_lock_fd, export):
    """Perform one explicitly selected isolated fresh-entry lifecycle action."""
    _context(project, context)
    from app import normal_session as normal, normal_profile
    from app.contracts import canonical, digest, require
    from app.task_spec import meaning_key
    from app.owner_scenario import DOCUMENT_A, DOCUMENT_B, GOAL, CRITERION
    project = Path(project).resolve(strict=True)
    require(action in ('restart_read', 'grant_stage', 'grant_review'), 'lifecycle_action_scope')
    store, ledger, before = _witness(project)
    result = dict(schema='radik.p28.rehearsal_lifecycle.v01', action=action,
        classification='SOURCE_ONLY_OWNED_COPY_NO_EXTERNAL_ACTION', before=before,
        model_reservations=0, provider_calls=0, native_D_E_calls=0, automatic_retry=False)
    if action == 'restart_read':
        require(operation_ref is None, 'lifecycle_restart_new_operation_refused')
        result.update(status='PASS_FRESH_PROCESS_COMPATIBLE_HISTORY_READ',
            authority_restored=False, task_round_started=False)
        _export(export, 'restart_read', result)
        return result
    require(client is not None and client.budget._normal_operation == operation_ref,
        'lifecycle_current_operation_required')
    operation = normal.validate_operation(project, operation_ref)
    require(operation['schema'] == 'radik.normal_operation.v02', 'lifecycle_v02_operation_required')
    result['operation'] = _raw(project, operation_ref['path'])
    if action == 'grant_stage':
        require(client.budget._task_round is None, 'lifecycle_no_prior_round_required')
        source_ids = []
        for index, raw in enumerate((DOCUMENT_A, DOCUMENT_B)):
            source_ids.append(store.register_source('p28:discarded-grant:' + operation['run_id'] + ':' + str(index),
                'discarded_grant_' + str(index) + '.txt', raw))
        task_id = store.create(goal=GOAL, source_ids=tuple(source_ids), profile='compare', criterion=CRITERION,
            topic='discarded_grant_support_conditions')
        spec = store.spec(task_id)
        sources = store.prepare_round_sources(spec)
        dependencies = dict(meaning_key=meaning_key(spec, sources),
            sources=[{key: row[key] for key in ('source_ref', 'revision', 'sha256')} for row in sources])
        binding = client.budget.begin_task_round(task_id=task_id, profile=spec.profile,
            task_spec_sha256=digest(spec.plain()), dependencies_sha256=digest(dependencies),
            max_attempts=3, mode='COLD')
        grant = normal.validate_round(project, binding, task_state=store.state, before_begin=True, current=True)
        _store, after_ledger, after = _witness(project)
        require(after_ledger == ledger and not any(event['kind'] == 'ROUND_STARTED'
            for event in store.state['tasks'][task_id]['history'])
            and after['reconciled'][binding['round_id']]['disposition'] == 'GRANTED',
            'lifecycle_grant_before_start_required')
        result.update(status='PASS_DURABLE_GRANTED_BEFORE_FIRST_RESERVATION',
            leave_operation_open=True, leave_round_open=True, task_id=task_id,
            binding=binding, grant=grant, grant_ref=binding['normal_round_scope']['grant_ref'], after=after)
        _export(export, 'grant_stage', result)
        return result
    # The new process receives only operation history. It does not reconstruct
    # the previous budget object's round, pending request, controller or tokens.
    require(client.budget._task_round is None, 'lifecycle_round_authority_restored_from_json')
    active = json.loads(normal._read(project, normal.ACTIVE))
    candidates = [item for item in before['reconciled'].values()
        if item['disposition'] == 'GRANTED'
        and item['binding']['normal_round_scope']['operation_ref'] == operation_ref]
    require(len(candidates) == 1 and active['operation_ref'] == operation_ref,
        'lifecycle_one_discarded_grant_required')
    binding = candidates[0]['binding']
    require(active.get('round_ref') == binding['normal_round_scope']['grant_ref']
        and not any(event.get('operation_round', {}).get('round_id') == binding['round_id']
            for row in store.state['tasks'].values() for event in row['history'])
        and not any(row.get('round_binding', {}).get('round_id') == binding['round_id'] for row in ledger['attempts']),
        'lifecycle_discarded_grant_must_have_no_start_or_reservation')
    result['discovered_grant'] = _raw(project, binding['normal_round_scope']['grant_ref']['path'])
    discovered = result['discovered_grant']['value']
    require(len(ledger['attempts']) == discovered['counted']
        and ledger['ledger_sha256'] == discovered['ledger_head'],
        'lifecycle_discarded_grant_has_new_counted_requests')
    result['dispatch_refusal'] = _refusal(lambda: normal.validate_round(project, binding,
        task_state=store.state, current=True, for_dispatch=True), 'normal_round_history_binding')
    result['unrelated_operation_refusal'] = _refusal(lambda: normal.open_operation(project,
        owner_lock_fd=owner_lock_fd, owner_operation_id=str(uuid.uuid4()), run_id=uuid.uuid4().hex[:12],
        source_review_ref=operation['source_review_ref'], source_admission_ref=operation['source_admission_ref'],
        source_identity_sha256=operation['source_identity_sha256'],
        auth_source_identity_sha256=operation['auth_source_identity_sha256'],
        profile_ref=operation['profile_ref']), 'normal_profile_unrelated_active_operation')
    _store, unchanged_ledger, after_refusals = _witness(project)
    require(unchanged_ledger == ledger and after_refusals['task_state'] == before['task_state']
        and after_refusals['indexed_grants'] == before['indexed_grants'],
        'lifecycle_refusal_changed_history')
    result['after_refusals'] = after_refusals
    # This is a named explicit rehearsal cleanup action, not an entry retry or
    # automatic production grant recovery.
    aborted = normal_profile.abort_before_start(project, ledger, binding)
    closed = normal.close_operation(project, owner_lock_fd=owner_lock_fd,
        operation_ref=operation_ref, failed=True)
    _store, after_ledger, after = _witness(project)
    require(after_ledger == ledger and after['reconciled'][binding['round_id']]['disposition'] == 'ABORTED_BEFORE_START'
        and not normal._path(project, normal.ACTIVE).exists(), 'lifecycle_explicit_abort_not_closed')
    result.update(status='PASS_FRESH_PROCESS_DISCOVERY_AND_EXPLICIT_ABORT', after=after,
        abort_ref=aborted, abort=_raw(project, aborted['path']), operation_close_ref=closed,
        operation_close=_raw(project, closed['path']), operation_closed=True,
        authority_restored=False, automatic_retry=False)
    _export(export, 'grant_review', result)
    return result
