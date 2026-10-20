"""Finite application profile registry and compatible normal-history extension.

Historical source identities are validated against their immutable reviews. Only
the active profile additionally checks installed bytes. No read activates it.
"""
import json

from . import normal_session as normal

PROFILE = 'stage04_dynamic_informational_delta_v28'
MANIFEST = ('review/g2e_successor_passage/proposals/'
    'g2e_no_effects_v28_ordinary_entry_owner_scenario/ordinary_profile_manifest.json')
ACTIVATION = 'state/application_profile.json'
INDEX = 'state/normal_grant_index.json'
MODES = dict(normal.MODES, INFORMATIONAL_DELTA=3)
ROUND_VERSION = 'radik.normal_round_binding.v02'
require, digest = normal.require, normal.digest


def profile(project, reference):
    from config.application_profile_gate import load_profile
    return load_profile(project,reference)['manifest']


def current(project):
    from config.application_profile_gate import select
    selected=select(project)
    return None if selected is None else (selected['profile_ref'],selected['manifest'])


def validate_operation(project, reference, value):
    require(set(value) == {'schema', 'profile_ref', 'owner_operation_id', 'run_id',
        'transition_ref', 'source_review_ref', 'source_admission_ref', 'source_identity_sha256',
        'auth_source_identity_sha256', 'settings_sha256', 'ledger_head', 'counted', 'task_state_sha256',
        'opened_at'} and value['schema'] == 'radik.normal_operation.v02', 'normal_profile_operation_shape')
    selected = profile(project, value['profile_ref'])
    normal._identity(value['owner_operation_id'], value['run_id'])
    require(reference['path'] == normal._operation_path(value['owner_operation_id'])
        and value['source_identity_sha256'] == digest(selected['pins'])
        and all(value[key] == selected[key] for key in ('source_review_ref', 'source_admission_ref',
            'auth_source_identity_sha256'))
        and value['transition_ref'] == normal._initial(project)[0]
        and all(normal._hash(value[key]) for key in ('settings_sha256', 'ledger_head', 'task_state_sha256'))
        and type(value['counted']) is int and value['counted'] >= 3
        and type(value['opened_at']) is int and value['opened_at'] >= 0, 'normal_profile_operation_basis')
    return value


def index(project):
    require(not normal._path(project, INDEX + '.pending').exists(), 'normal_grant_partial_index')
    if not normal._path(project, INDEX).exists():
        return []
    value = json.loads(normal._read(project, INDEX, 262144))
    require(type(value) is dict and set(value) == {'schema', 'grants'}
        and value['schema'] == 'radik.normal_grant_index.v01'
        and type(value['grants']) is list and len(value['grants']) <= 1024,
        'normal_grant_index_shape')
    require(len({v['path'] for v in value['grants']}) == len(value['grants']), 'normal_grant_duplicate')
    for reference in value['grants']:
        normal._ref(reference)
        require(reference['path'].startswith('state/normal_rounds/') and reference['path'].endswith('.json'),
            'normal_grant_registered_path')
    return value['grants']


def register_grant(project, relative, value):
    rows = index(project)
    reference = dict(path=relative, sha256=digest(value))
    require(reference['path'] not in {r['path'] for r in rows} and len(rows) < 1024, 'normal_grant_duplicate')
    updated = dict(schema='radik.normal_grant_index.v01', grants=rows + [reference])
    # An indexed partial grant must be discovered after a crash, never reissued.
    if normal._path(project, INDEX).exists():
        normal._replace(project, INDEX, updated)
    else:
        normal._exclusive(project, INDEX, updated)
    normal._exclusive(project, relative, value)
    return reference


def validate_round_shape(binding):
    proof = binding['normal_round_scope']
    require(type(proof) is dict and set(proof) == {'schema', 'grant_ref', 'operation_ref', 'mode',
        'owner_operation_id', 'run_id', 'history_ordinal', 'profile_ref', 'source_successor_ref'}
        and proof['schema'] == ROUND_VERSION and proof['mode'] in MODES
        and type(binding['max_attempts']) is int and binding['max_attempts'] == MODES[proof['mode']]
        and type(proof['history_ordinal']) is int and proof['history_ordinal'] >= 1,
        'normal_profile_round_shape')
    normal._identity(proof['owner_operation_id'], proof['run_id'])
    for key in ('grant_ref', 'operation_ref', 'profile_ref'):
        normal._ref(proof[key])
    require(proof['grant_ref']['path'] == normal._round_path(binding['round_id']), 'normal_profile_round_shape')
    require((proof['source_successor_ref'] is not None) == (proof['mode'] == 'INFORMATIONAL_DELTA'),
        'normal_profile_delta_successor_required')
    if proof['source_successor_ref'] is not None:
        normal._ref(proof['source_successor_ref'])
    return proof


def reconcile_index(project, ledger, task_state, started_rounds):
    """Include never-started durable grants without inventing TaskStore events."""
    result, round_ids = {}, set()
    for reference in index(project):
        grant = normal._reference(project, reference)
        binding = grant['round_binding']
        require(grant['schema'] == 'radik.normal_round_grant.v02', 'normal_index_grant_type')
        operation = normal.validate_operation(project, grant['operation_ref'])
        proof = dict(schema=ROUND_VERSION, grant_ref=reference, operation_ref=grant['operation_ref'],
            mode=grant['mode'], owner_operation_id=grant['owner_operation_id'], run_id=grant['run_id'],
            history_ordinal=grant['history_ordinal'], profile_ref=grant['profile_ref'],
            source_successor_ref=grant['source_successor_ref'])
        full = dict(binding, normal_round_scope=proof)
        validate_round_shape(full)
        require(binding['round_id'] not in round_ids and operation['profile_ref'] == grant['profile_ref'],
            'normal_index_duplicate_round')
        round_ids.add(binding['round_id'])
        require(binding['task_id'] in task_state['tasks'] and grant['counted'] <= len(ledger['attempts'])
            and binding['task_spec_sha256'] == digest(task_state['tasks'][binding['task_id']]['spec']),
            'normal_index_task_binding')
        prefix = dict(ledger, attempts=ledger['attempts'][:grant['counted']], active_attempt_id=None)
        require(grant['ledger_head'] == digest({k:v for k,v in prefix.items() if k != 'ledger_sha256'}),
            'normal_index_ledger_prefix')
        requests = [r for r in ledger['attempts'] if r.get('round_binding', {}).get('round_id') == binding['round_id']]
        if binding['round_id'] in started_rounds:
            require(started_rounds[binding['round_id']] == full, 'normal_index_started_binding')
            disposition = 'STARTED'
        else:
            require(not requests, 'normal_index_request_without_start')
            disposition = 'GRANTED'
            if normal._path(project, normal._closed(reference)).exists():
                close = json.loads(normal._read(project, normal._closed(reference)))
                require(close == dict(schema='radik.normal_round_abort.v01', grant_ref=reference,
                    disposition='ABORTED_BEFORE_START', final_head=grant['ledger_head'], counted=grant['counted'],
                    active_attempt_id=None, automatic_retry=False), 'normal_index_abort_binding')
                disposition = 'ABORTED_BEFORE_START'
        result[binding['round_id']] = dict(binding=full, disposition=disposition)
    require(all(b['normal_round_scope']['schema'] != ROUND_VERSION or rid in result
        for rid,b in started_rounds.items()), 'normal_profile_unindexed_start')
    return result


def abort_before_start(project, ledger, binding):
    proof = validate_round_shape(binding)
    grant = normal._reference(project, proof['grant_ref'])
    _raw, tasks = normal._json(project, normal.TASKS)
    require(not any(e.get('operation_round', {}).get('round_id') == binding['round_id']
        for row in tasks['tasks'].values() for e in row['history'])
        and not any(r.get('round_binding', {}).get('round_id') == binding['round_id'] for r in ledger['attempts'])
        and ledger['active_attempt_id'] is None and ledger['ledger_sha256'] == grant['ledger_head']
        and len(ledger['attempts']) == grant['counted'], 'normal_abort_before_start_binding')
    normal.validate_round(project, binding, task_state=tasks, before_begin=True, current=True)
    result = normal._exclusive(project, normal._closed(proof['grant_ref']), dict(
        schema='radik.normal_round_abort.v01', grant_ref=proof['grant_ref'], disposition='ABORTED_BEFORE_START',
        final_head=ledger['ledger_sha256'], counted=len(ledger['attempts']), active_attempt_id=None, automatic_retry=False))
    normal._replace(project, normal.ACTIVE, dict(schema='radik.normal_active_operation.v01',
        operation_ref=proof['operation_ref']))
    return result
