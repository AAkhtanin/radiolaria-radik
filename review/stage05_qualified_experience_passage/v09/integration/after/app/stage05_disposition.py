"""One explicit local UNKNOWN disposition and two fresh Stage05 task slots.

The original outcome, usage and counted attempts are immutable. An independently
reviewed proposal alone does not release occupancy. Only the explicit supervised
owner action may write its receipt; normal operation and round gates remain in
force and the historical ABC continuation validators are unchanged.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import time

from . import normal_session as normal

SELECTED = 'radik-call:c146081f7b9a4d649f3c7e916189271e'
RECEIPT = 'state/stage05_dispositions/c146081f7b9a4d649f3c7e916189271e.json'
SLOTS = ('ROWAN_COLD', 'ALDER_COLD')
require, digest, canonical = normal.require, normal.digest, normal.canonical


def _reference(project, reference):
    normal._ref(reference)
    require(reference['path'].startswith(('review/', 'state/stage05_dispositions/')),
        'stage05_disposition_reference')
    raw = normal._read(project, reference['path'])
    require(digest(raw) == reference['sha256'] and
        ('size_bytes' not in reference or len(raw) == reference['size_bytes']),
        'stage05_disposition_reference_pin')
    return raw, json.loads(raw)


def _approved(project, proposal_ref, review_ref, *, current=False):
    raw, proposal = _reference(project, proposal_ref)
    fields = {'schema', 'scope', 'selected_attempt_id', 'before_ledger_ref', 'before_task_state_ref',
        'transport_result_ref', 'owner_receipt_ref', 'child_receipt_ref', 'reservation_outcome_ref',
        'source_identity_sha256', 'auth_source_identity_sha256', 'profile_ref', 'operation_allowance',
        'receipt_path', 'automatic_retry', 'entry_authorizes_model_or_effect'}
    require(set(proposal) == fields and proposal['schema'] == 'radik.stage05.unknown_disposition_proposal.v01'
        and proposal['scope'] == 'SELECTED_LOCAL_OCCUPANCY_AND_FRESH_STAGE05_REMAINDER_ONLY'
        and proposal['selected_attempt_id'] == SELECTED and proposal['receipt_path'] == RECEIPT
        and proposal['automatic_retry'] is proposal['entry_authorizes_model_or_effect'] is False,
        'stage05_disposition_proposal')
    before_raw, before = _reference(project, proposal['before_ledger_ref'])
    tasks_raw, tasks = _reference(project, proposal['before_task_state_ref'])
    _raw, result = _reference(project, proposal['transport_result_ref'])
    _raw, owner = _reference(project, proposal['owner_receipt_ref'])
    _raw, child = _reference(project, proposal['child_receipt_ref'])
    _raw, closed = _reference(project, proposal['reservation_outcome_ref'])
    require(before_raw == canonical(before) and before['version'] == normal.VERSION
        and before['active_attempt_id'] == SELECTED and len(before['attempts']) == 50
        and before['ledger_sha256'] == digest({k:v for k,v in before.items() if k != 'ledger_sha256'})
        and tasks_raw == canonical(tasks) and tasks['active_task_id'] is None,
        'stage05_disposition_predecessor')
    rows = [row for row in before['attempts'] if row['attempt_id'] == SELECTED]
    require(len(rows) == 1 and rows[0] == before['attempts'][-1]
        and rows[0]['outcome'] == rows[0]['usage'] == 'UNKNOWN', 'stage05_disposition_selected_unknown')
    selected = rows[0]
    old_task = tasks['tasks'][selected['round_binding']['task_id']]
    require(old_task['status'] == 'FAILED' and not old_task['results']
        and result['reservation_id'] == SELECTED and result['outcome'] == result['usage'] == 'UNKNOWN'
        and result['context_sha256'] == selected['context_sha256']
        and digest(result['request_body']['input'][0]['content'][0]['text'].encode()) == selected['context_sha256']
        and digest(result['request_body']) == result['wire']['body_sha256'] == selected['telemetry']['wire_body_sha256']
        and result['response_id'] == selected['telemetry']['response_id']
        and result['terminal_observed'] is False and result['completed_output']['role_product_accepted'] is False
        and result['dispatch_may_have_started'] is True
        and result['client_http_closed'] is result['deadline_watchdog_finished'] is True,
        'stage05_disposition_transport_binding')
    require(owner['status'] == 'STOPPED_NO_RETRY' and closed['status'] == 'CHILD_CLOSED'
        and owner['child_reaped'] is child['child_reaped'] is closed['child_reaped'] is True
        and owner['child_pid'] == child['child_pid'] == closed['child_pid']
        and owner['child_exit_code'] == child['child_exit_code'] == closed['child_exit_code']
        and owner['automatic_retry'] is closed['automatic_retry'] is False,
        'stage05_disposition_local_closure')
    allowance = proposal['operation_allowance']
    require(type(allowance) is dict and set(allowance) == {'schema', 'scenario_ref', 'scenario_mode',
        'slots', 'max_provider_attempts', 'native_provider_calls', 'effects', 'automatic_retry'}
        and allowance['schema'] == 'radik.stage05.remaining_operation_allowance.v01'
        and allowance['scenario_mode'] == 'remaining_only'
        and allowance['slots'] == [{'slot': slot, 'mode': 'COLD', 'max_attempts': 3} for slot in SLOTS]
        and type(allowance['max_provider_attempts']) is int and allowance['max_provider_attempts'] == 6
        and type(allowance['native_provider_calls']) is int and allowance['native_provider_calls'] == 0
        and type(allowance['effects']) is int and allowance['effects'] == 0
        and allowance['automatic_retry'] is False, 'stage05_disposition_allowance')
    _raw, inputs = _reference(project, allowance['scenario_ref'])
    require(inputs['scenario_mode'] == 'remaining_only' and inputs['command'] == 'experience'
        and inputs['expected_role_calls'] == 6
        and inputs['expected_primary_role_calls'] == inputs['expected_unrelated_role_calls'] == 3
        and inputs['native_E_calls'] == inputs['effects'] == 0, 'stage05_disposition_scenario')
    _raw, profile = _reference(project, proposal['profile_ref'])
    require(digest(profile['pins']) == proposal['source_identity_sha256']
        and profile['auth_source_identity_sha256'] == proposal['auth_source_identity_sha256']
        and profile['pins'].get(allowance['scenario_ref']['path']) == allowance['scenario_ref']['sha256'],
        'stage05_disposition_source_binding')
    _raw, review = _reference(project, review_ref)
    require(set(review) == {'schema', 'reviewer', 'status', 'proposal_sha256',
        'source_identity_sha256', 'auth_source_identity_sha256', 'owner_action_required',
        'entry_authorizes_model_or_effect'}
        and review['schema'] == 'radik.stage05.unknown_disposition_review.v01'
        and review['reviewer'] == '/root/private_remote_controls'
        and review['status'] == 'SOURCE_ACCEPTED_FOR_EXPLICIT_OWNER_DISPOSITION_AND_FINITE_REMAINDER'
        and review['proposal_sha256'] == digest(raw)
        and all(review[k] == proposal[k] for k in ('source_identity_sha256','auth_source_identity_sha256'))
        and review['owner_action_required'] is True and review['entry_authorizes_model_or_effect'] is False,
        'stage05_disposition_independent_review')
    if current:
        from .normal_profile import current as selected_profile
        require(selected_profile(project)[0] == proposal['profile_ref'], 'stage05_disposition_current_profile')
        for path, pin in profile['pins'].items():
            require(digest(normal._read(project, path)) == pin, 'stage05_disposition_current_source')
    return proposal, before, tasks, selected, inputs


def prepare(project, proposal_ref, review_ref, *, source_identity_sha256,
            auth_source_identity_sha256, profile_ref):
    """Read the exact predecessor. Preparation never writes or acknowledges it."""
    proposal, before, tasks, selected, _inputs = _approved(project, proposal_ref, review_ref, current=True)
    require(proposal['profile_ref'] == profile_ref
        and proposal['source_identity_sha256'] == source_identity_sha256
        and proposal['auth_source_identity_sha256'] == auth_source_identity_sha256,
        'stage05_disposition_current_source')
    require(normal._read(project, normal.LEDGER) == canonical(before)
        and normal._read(project, normal.TASKS) == canonical(tasks)
        and not normal._path(project, normal.ACTIVE).exists()
        and not normal._path(project, RECEIPT).exists(), 'stage05_disposition_current_predecessor')
    require(not normal._path(project, normal.LEDGER + '.pending').exists(), 'stage05_disposition_partial')
    return dict(selected_attempt_id=SELECTED, counted=50, remote_outcome='UNKNOWN', usage='UNKNOWN',
        operation_allowance=proposal['operation_allowance'], owner_action_required=True,
        old_owner_operation_id=selected['owner_operation_id'], old_run_id=selected['run_id'])


def apply(project, proposal_ref, review_ref, *, owner_lock_fd, owner_operation_id, run_id,
          source_identity_sha256, auth_source_identity_sha256, profile_ref,
          owner_confirmed, owner_launch_ref, owner_run_binding):
    """Only the explicit future supervised owner action may release local occupancy."""
    require(owner_confirmed is True, 'stage05_disposition_owner_confirmation_required')
    normal._owner_lock(project, owner_lock_fd)
    normal._identity(owner_operation_id, run_id)
    _raw, launch = _reference(project, owner_launch_ref)
    consent = dict(selected_attempt_id=SELECTED, proposal_ref=proposal_ref, review_ref=review_ref)
    require(launch.get('selected_unknown_acknowledgement') == consent
        and digest(launch) == owner_run_binding and normal._hash(owner_run_binding)
        and launch.get('schema') == 'radik.p28.owner_terminal_launch.v01'
        and launch.get('process_index') == 1 and launch.get('prior_child_receipt_ref') is None
        and launch.get('source_review_ref') == normal._reference(project, profile_ref)['source_review_ref'],
        'stage05_disposition_owner_launch_binding')
    prepare(project, proposal_ref, review_ref, source_identity_sha256=source_identity_sha256,
        auth_source_identity_sha256=auth_source_identity_sha256, profile_ref=profile_ref)
    proposal, before, tasks, _selected, _inputs = _approved(project, proposal_ref, review_ref)
    require(all(owner_operation_id != row['owner_operation_id'] and run_id != row['run_id']
        for row in before['attempts']), 'stage05_disposition_new_operation')
    lock_path = normal._path(project, 'state/console_model_turns.lock')
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'a+b') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(),
            'stage05_disposition_ledger_lock')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        from .task_budget import read_state
        state = read_state(project)
        require(state['active_attempt_id'] == SELECTED and state['counted'] == 50
            and state['source_identity_sha256'] == source_identity_sha256
            and normal._read(project, normal.LEDGER) == canonical(before)
            and normal._read(project, normal.TASKS) == canonical(tasks),
            'stage05_disposition_current_predecessor')
        receipt = dict(schema='radik.stage05.unknown_disposition_receipt.v01', proposal_ref=proposal_ref,
            review_ref=review_ref, selected_attempt_id=SELECTED, owner_operation_id=owner_operation_id,
            run_id=run_id, source_identity_sha256=source_identity_sha256,
            auth_source_identity_sha256=auth_source_identity_sha256, profile_ref=profile_ref,
            owner_launch_ref=owner_launch_ref, owner_run_binding=owner_run_binding,
            owner_confirmed=True, counted=50, historical_prefix_sha256=digest(before['attempts']),
            allowance_sha256=digest(proposal['operation_allowance']), recorded_at=int(time.time()),
            remote_outcome='UNKNOWN', usage='UNKNOWN', server_cancellation_observed=False,
            automatic_retry=False, new_request_started=False)
        reference = normal._exclusive(project, RECEIPT, receipt)
        after = dict(before, active_attempt_id=None)
        after['ledger_sha256'] = digest({k:v for k,v in after.items() if k != 'ledger_sha256'})
        # A partial receipt/ledger pair refuses future entry; it is never auto-repaired.
        normal._replace(project, normal.LEDGER, after)
        checked = read_state(project)
        require(checked['active_attempt_id'] is None and checked['counted'] == 50
            and SELECTED in checked['acknowledged_remote_unknown_attempt_ids']
            and normal._read(project, normal.LEDGER) == canonical(after), 'stage05_disposition_readback')
        return dict(receipt_ref=reference, selected_attempt_id=SELECTED, counted=50,
            owner_operation_id=owner_operation_id, run_id=run_id, remote_outcome='UNKNOWN',
            usage='UNKNOWN', new_request_started=False)


def _context(project):
    if not normal._path(project, RECEIPT).exists():
        return None
    raw, receipt = normal._json(project, RECEIPT)
    require(raw == canonical(receipt) and set(receipt) == {'schema', 'proposal_ref', 'review_ref',
        'selected_attempt_id', 'owner_operation_id', 'run_id', 'source_identity_sha256',
        'auth_source_identity_sha256', 'profile_ref', 'owner_launch_ref', 'owner_run_binding',
        'owner_confirmed', 'counted', 'historical_prefix_sha256', 'allowance_sha256', 'recorded_at',
        'remote_outcome', 'usage', 'server_cancellation_observed', 'automatic_retry', 'new_request_started'}
        and receipt['schema'] == 'radik.stage05.unknown_disposition_receipt.v01',
        'stage05_disposition_receipt')
    proposal, before, tasks, selected, inputs = _approved(project, receipt['proposal_ref'], receipt['review_ref'])
    require(receipt['selected_attempt_id'] == SELECTED and receipt['owner_confirmed'] is True
        and receipt['counted'] == 50 and receipt['historical_prefix_sha256'] == digest(before['attempts'])
        and receipt['allowance_sha256'] == digest(proposal['operation_allowance'])
        and type(receipt['recorded_at']) is int and receipt['recorded_at'] >= selected['finished_at']
        and receipt['profile_ref'] == proposal['profile_ref']
        and all(receipt[k] == proposal[k] for k in ('source_identity_sha256','auth_source_identity_sha256'))
        and receipt['remote_outcome'] == receipt['usage'] == 'UNKNOWN'
        and receipt['server_cancellation_observed'] is receipt['automatic_retry'] is receipt['new_request_started'] is False,
        'stage05_disposition_receipt_binding')
    normal._identity(receipt['owner_operation_id'], receipt['run_id'])
    require(all(receipt['owner_operation_id'] != row['owner_operation_id'] and receipt['run_id'] != row['run_id']
        for row in before['attempts']), 'stage05_disposition_new_operation')
    _raw, launch = _reference(project, receipt['owner_launch_ref'])
    require(digest(launch) == receipt['owner_run_binding']
        and launch.get('schema') == 'radik.p28.owner_terminal_launch.v01'
        and launch.get('process_index') == 1 and launch.get('prior_child_receipt_ref') is None
        and launch.get('source_review_ref') == normal._reference(project, receipt['profile_ref'])['source_review_ref']
        and launch.get('selected_unknown_acknowledgement') == dict(selected_attempt_id=SELECTED,
            proposal_ref=receipt['proposal_ref'], review_ref=receipt['review_ref']),
        'stage05_disposition_owner_launch_binding')
    return dict(receipt=receipt, receipt_ref=dict(path=RECEIPT, sha256=digest(raw)),
        proposal=proposal, before=before, tasks=tasks, inputs=inputs)


def extend_status(project, ledger, previous):
    """Recognize only the exact new receipt; unacknowledged UNKNOWN still fails."""
    context = _context(project)
    if context is None or len(ledger['attempts']) < 50:
        return previous
    receipt, before = context['receipt'], context['before']
    require(ledger['attempts'][:50] == before['attempts']
        and ledger['active_attempt_id'] != SELECTED, 'stage05_disposition_ledger_prefix')
    admitted = [row for row in ledger['attempts'][50:]
        if row['owner_operation_id'] == receipt['owner_operation_id'] or row['run_id'] == receipt['run_id']]
    require(len(admitted) <= 6 and all(row['owner_operation_id'] == receipt['owner_operation_id']
        and row['run_id'] == receipt['run_id'] for row in admitted), 'stage05_disposition_six_attempt_cap')
    for row in admitted:
        slot = _slot_record(project, context, row['round_binding']['round_id'])
        require(slot['binding'] == {k:v for k,v in row['round_binding'].items() if k != 'normal_round_scope'},
            'stage05_disposition_counted_slot')
    acknowledged = list(previous['acknowledged_remote_unknown_attempt_ids'])
    require(SELECTED not in acknowledged, 'stage05_disposition_duplicate')
    return dict(previous, acknowledged_remote_unknown_attempt_ids=acknowledged+[SELECTED],
        stage05_disposition_ref=context['receipt_ref'], stage05_operation_allowance=context['proposal']['operation_allowance'],
        stage05_owner_operation_id=receipt['owner_operation_id'], stage05_run_id=receipt['run_id'])


def require_operation(project, ledger, *, owner_operation_id, run_id, source_identity_sha256,
                      auth_source_identity_sha256, profile_ref):
    context = _context(project)
    if context is None:
        return
    receipt = context['receipt']
    target_closed = normal._path(project, normal._operation_path(receipt['owner_operation_id'])+'.closed').exists()
    if target_closed:
        require(owner_operation_id != receipt['owner_operation_id'] and run_id != receipt['run_id'],
            'stage05_disposition_operation_replay')
        return
    require(owner_operation_id == receipt['owner_operation_id'] and run_id == receipt['run_id']
        and source_identity_sha256 == receipt['source_identity_sha256']
        and auth_source_identity_sha256 == receipt['auth_source_identity_sha256']
        and profile_ref == receipt['profile_ref'] and ledger['attempts'] == context['before']['attempts']
        and ledger['active_attempt_id'] is None, 'stage05_disposition_operation_binding')


def _slot_path(round_id):
    require(type(round_id) is str and re.fullmatch('task-round:[0-9a-f]{32}', round_id),
        'stage05_disposition_round_id')
    return 'state/stage05_dispositions/'+SELECTED.split(':')[-1]+'/'+round_id.split(':')[-1]+'.json'


def _slot_record(project, context, round_id):
    _raw, record = normal._json(project, _slot_path(round_id))
    require(set(record) == {'schema', 'receipt_ref', 'slot', 'binding', 'before_count',
        'source_identity_sha256', 'task_spec_sha256'}
        and record['schema'] == 'radik.stage05.remaining_round_allowance.v01'
        and record['receipt_ref'] == context['receipt_ref'] and record['slot'] in SLOTS
        and record['binding']['round_id'] == round_id
        and record['before_count'] == (50 if record['slot'] == SLOTS[0] else 53), 'stage05_disposition_round_allowance')
    return record


def _task_slot(project, context, operation, binding, tasks, *, before_begin):
    receipt, inputs = context['receipt'], context['inputs']
    require(operation['owner_operation_id'] == receipt['owner_operation_id']
        and operation['run_id'] == receipt['run_id'] and operation.get('profile_ref') == receipt['profile_ref'],
        'stage05_disposition_operation_binding')
    tid = binding['task_id']
    require(tid not in context['tasks']['tasks'] and tid in tasks['tasks'] and binding['max_attempts'] == 3,
        'stage05_disposition_fresh_task')
    row = tasks['tasks'][tid]; spec = row['spec']; candidates=[]
    for index, name in enumerate(('rowan','alder')):
        selected = inputs if index == 0 else inputs['unrelated']
        sid = 'radik:source:'+digest(('stage05:'+receipt['run_id']+':'+name).encode())[:32]
        if spec['source_ids'] == [sid]: candidates.append((index, selected, sid))
    require(len(candidates) == 1, 'stage05_disposition_fresh_source')
    index, selected, sid = candidates[0]
    require(sid not in context['tasks']['sources'] and spec['resource_scope'] == [sid]
        and all(spec[key] == selected['ordinary_profile' if key=='profile' else key]
            for key in ('profile','goal','criterion','topic'))
        and spec['predecessor_task_id'] is spec['supplied_candidate'] is None
        and spec['task_id'] == tid and digest(spec) == binding['task_spec_sha256']
        and type(spec['created_at']) is int and spec['created_at'] >= receipt['recorded_at']
        and tasks['sources'][sid]['filename'] == sid.split(':')[-1]+'.txt'
        and normal._read(project, 'workspace/owner_documents/input/'+tasks['sources'][sid]['filename'])
            == selected['source_text'].encode(), 'stage05_disposition_task_source_binding')
    starts=[e for e in row['history'] if e['kind']=='ROUND_STARTED']
    require(len(starts) == (0 if before_begin else 1)
        and (not before_begin or row['status']=='QUEUED' and not row['results']),
        'stage05_disposition_one_round_per_task')
    return SLOTS[index]


def prepare_round(project, ledger, binding, *, operation, mode):
    context = _context(project)
    if context is None or operation['owner_operation_id'] != context['receipt']['owner_operation_id']:
        return
    require(mode == 'COLD' and len(ledger['attempts']) in (50,53), 'stage05_disposition_round_mode')
    _raw, tasks = normal._json(project, normal.TASKS)
    slot = _task_slot(project, context, operation, binding, tasks, before_begin=True)
    expected = SLOTS[(len(ledger['attempts'])-50)//3]
    require(slot == expected and all(row['outcome']=='COMPLETED' and row['owner_operation_id']==operation['owner_operation_id']
        for row in ledger['attempts'][50:]), 'stage05_disposition_slot_order')
    # Each slot has a separate immutable name as well as its exact normal round.
    slot_path='state/stage05_dispositions/'+SELECTED.split(':')[-1]+'/'+slot.lower()+'.json'
    require(not normal._path(project, slot_path).exists(), 'stage05_disposition_slot_reuse')
    record=dict(schema='radik.stage05.remaining_round_allowance.v01', receipt_ref=context['receipt_ref'],
        slot=slot, binding=dict(binding), before_count=len(ledger['attempts']),
        source_identity_sha256=operation['source_identity_sha256'], task_spec_sha256=digest(tasks['tasks'][binding['task_id']]['spec']))
    reference=normal._exclusive(project, _slot_path(binding['round_id']), record)
    normal._exclusive(project, slot_path, reference)


def validate_round(project, binding, *, operation, task_state, before_begin=False, current=False):
    context = _context(project)
    if context is None or operation['owner_operation_id'] != context['receipt']['owner_operation_id']:
        return
    record=_slot_record(project, context, binding['round_id'])
    require(record['binding'] == {k:v for k,v in binding.items() if k != 'normal_round_scope'}
        and record['source_identity_sha256'] == operation['source_identity_sha256']
        and record['task_spec_sha256'] == binding['task_spec_sha256'], 'stage05_disposition_round_binding')
    slot_path='state/stage05_dispositions/'+SELECTED.split(':')[-1]+'/'+record['slot'].lower()+'.json'
    _raw, reference=normal._json(project, slot_path)
    raw=normal._read(project, _slot_path(binding['round_id']))
    require(reference == dict(path=_slot_path(binding['round_id']), sha256=digest(raw)),
        'stage05_disposition_slot_binding')
    # Historical acceptance remains valid after the final deliberate source revision.
    # Every live/before-begin gate re-reads the actual source bytes and current spec.
    if before_begin or current:
        require(_task_slot(project, context, operation, binding, task_state, before_begin=before_begin)==record['slot'],
            'stage05_disposition_current_slot')
