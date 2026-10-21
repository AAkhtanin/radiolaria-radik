"""Closed Stage04 console carryforward and read-only task-ledger predicates.

This extends the finite selector and existing TurnBudget engine. It performs no
provider/native/effect work. Migration is a separate reviewed owner-lock action;
missing or interrupted state refuses reservations until that action reconciles it.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import stat

from review.transport import model_scope as base

POLICY='config/task_model_policy.json'
TRANSITION='state/console_stage04_transition.json'
COMMITTED='state/console_stage04_committed.json'
SETTINGS='state/task_model_settings.json'
PROPOSAL='review/stage04_dynamic_passage/migration_proposal.json'
REVIEW='review/stage04_dynamic_passage/migration_review.json'
ACTUAL='review/stage04_dynamic_passage/actual_console_review.json'
BASELINE='review/stage04_dynamic_passage/baseline.json'
BEFORE='review/stage04_dynamic_passage/actual_basis/state/console_model_turns.json'
RUNTIME_REVIEW='review/stage04_dynamic_passage/runtime_source_review.json'
VERSION='radik.console_turn_ledger.v02'
require,canonical,digest,is_hash=base.require,base.canonical,base.digest,base.is_hash


def read_json(project,path,cap=1024*1024):
    raw=base.read_public(project,path,cap=cap);value=json.loads(raw)
    require(raw==canonical(value),'task_scope_canonical_bytes')
    return raw,value


def policy(project):
    raw=base.read_public(project,POLICY);value=json.loads(raw)
    fields={'schema','scope','profile','max_new_turn_attempts','max_active_requests','max_attempts_per_round',
        'max_rounds_per_task','max_sources','max_native_items','max_native_children','max_native_depth',
        'max_native_revisions','max_native_child_budget','max_native_child_reservations','automatic_model_retries','automatic_effect_retries','native_work_max_model_calls',
        'native_e_max_provider_calls','supported_models','initial_settings','settings_change','auth_route',
        'request_deadline_seconds','settings_documentation','model_resolution'}
    require(type(value)is dict and set(value)==fields and value['schema']=='radik.task_model_policy.v01'
        and value['scope']=='console' and value['profile']=='stage04_dynamic_information_v01',
        'task_scope_policy_shape')
    exact={'max_new_turn_attempts':1000000,'max_active_requests':1,'max_attempts_per_round':3,
        'max_rounds_per_task':3,'max_sources':4,'max_native_items':12,'max_native_children':2,
        'max_native_depth':2,'max_native_revisions':2,'max_native_child_reservations':20,'max_native_child_budget':24,'automatic_model_retries':0,'automatic_effect_retries':0,
        'native_work_max_model_calls':0,'native_e_max_provider_calls':0,'request_deadline_seconds':600}
    require(all(type(value[key])is int and value[key]==expected for key,expected in exact.items()),
        'task_scope_policy_budget')
    require(value['supported_models']=={'gpt-6.1-sol':['low','medium','high','xhigh','max']}
        and value['initial_settings']=={'model':'gpt-6.1-sol','effort':'high','service_tier':'default'}
        and value['auth_route']=='EXISTING_RADIK_CHATGPT_PLAN_ONLY', 'task_scope_model_policy')
    return raw,value


def validate_settings(value,transition_sha):
    require(type(value)is dict and set(value)=={'schema','transition_sha256','entries','current_sha256'}
        and value['schema']=='radik.task_model_settings.v01' and value['transition_sha256']==transition_sha
        and type(value['entries'])is list and 1<=len(value['entries'])<=10000,'task_scope_settings')
    previous=None
    for index,row in enumerate(value['entries']):
        require(type(row)is dict and set(row)=={'sequence','model','effort','service_tier','previous_sha256',
            'owner_operation_id','run_id','entry_sha256'} and row['sequence']==index
            and row['model']=='gpt-6.1-sol' and row['effort'] in ('low','medium','high','xhigh','max')
            and row['service_tier']=='default' and row['previous_sha256']==previous
            and type(row['owner_operation_id'])is str and re.fullmatch('[0-9a-f-]{36}',row['owner_operation_id'])
            and type(row['run_id'])is str and re.fullmatch('[0-9a-f]{12}',row['run_id'])
            and row['entry_sha256']==digest({key:item for key,item in row.items() if key!='entry_sha256'}),
            'task_scope_settings_entry')
        previous=row['entry_sha256']
    require(value['current_sha256']==previous,'task_scope_settings_head')
    return value


def _references(project,record):
    for field in ('before_ledger','activation','exam_ledger','quota','actual_review','source_review','migration_review','task_policy'):
        ref=record[field]
        require(type(ref)is dict and set(ref)=={'path','sha256'} and is_hash(ref['sha256']),
            'task_scope_transition_reference')
        require(digest(base.read_public(project,ref['path']))==ref['sha256'],'task_scope_transition_basis_changed')
    expected={'before_ledger':BEFORE,'activation':base.SCOPE_PATHS['console']['activation'],
        'exam_ledger':base.SCOPE_PATHS['exam']['ledger'],'quota':base.QUOTA_PATH,'actual_review':ACTUAL,
        'source_review':RUNTIME_REVIEW,'migration_review':REVIEW,'task_policy':POLICY}
    require(all(record[key]['path']==path for key,path in expected.items()),'task_scope_transition_fixed_paths')


def validate_transition(project,record):
    require(type(record)is dict and set(record)=={'schema','profile','previous_source_identity_sha256',
        'source_identity_sha256','before_count','before_ledger','activation','activation_identity_sha256',
        'exam_ledger','quota','actual_review','source_review','migration_review','task_policy','owner_operation_id',
        'run_id','transition_sha256'} and record['schema']=='radik.console_source_transition.v01'
        and record['profile']=='stage04_dynamic_information_v01' and record['before_count']==3
        and record['previous_source_identity_sha256']=='85646b688d293dc587b0c448830a0e17b5ce09aaba2a427dc3304633cf1a8530'
        and is_hash(record['source_identity_sha256']) and is_hash(record['activation_identity_sha256'])
        and record['transition_sha256']==digest({key:value for key,value in record.items() if key!='transition_sha256'}),
        'task_scope_transition')
    _references(project,record)
    source=json.loads(base.read_public(project,RUNTIME_REVIEW))
    review=json.loads(base.read_public(project,REVIEW))
    require(source.get('reviewer')=='/root/semantic_continuation_reviewer'
        and source.get('status')=='SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION'
        and digest(source['pins'])==record['source_identity_sha256']
        and review.get('reviewer')=='/root/semantic_continuation_reviewer'
        and review.get('status')=='ACCEPTED_FOR_PRESERVING_STAGE04_CONSOLE_SOURCE_TRANSITION'
        and review.get('source_identity_sha256')==record['source_identity_sha256']
        and review.get('proposal_sha256')==digest(base.read_public(project,PROPOSAL)),
        'task_scope_independent_migration_review')
    activation=json.loads(base.read_public(project,record['activation']['path']))
    require(activation['activation_sha256']==record['activation_identity_sha256'],
        'task_scope_old_activation_changed')
    return record


def validate_ledger(project,ledger,record,settings):
    from . import console_continuation
    original_ledger=ledger
    if ledger.get('version')=='radik.console_turn_ledger.v05':
        from .normal_session import historical_ledger
        ledger=historical_ledger(project,ledger)
    fields={'version','scope','policy_sha256','activation_sha256',
        'transition_sha256','task_policy_sha256','attempts','active_attempt_id','ledger_sha256'}
    continued=type(ledger)is dict and ledger.get('version') in (console_continuation.VERSION,console_continuation.CHAIN_VERSION)
    chained=type(ledger)is dict and ledger.get('version')==console_continuation.CHAIN_VERSION
    require(type(ledger)is dict and set(ledger)==fields|({'console_continuation_ref'} if continued else set())|({'console_continuation_chain'} if chained else set())
        and ledger['version'] in (VERSION,console_continuation.VERSION,console_continuation.CHAIN_VERSION) and ledger['scope']=='console'
        and ledger['transition_sha256']==record['transition_sha256']
        and ledger['activation_sha256']==record['activation_identity_sha256']
        and ledger['task_policy_sha256']==record['task_policy']['sha256']
        and type(ledger['attempts'])is list and 3<=len(ledger['attempts'])<=1000000
        and ledger['ledger_sha256']==digest({key:value for key,value in ledger.items() if key!='ledger_sha256'}),
        'task_scope_ledger')
    before=json.loads(base.read_public(project,BEFORE))
    base.validate_console_ledger(before,policy_sha256=ledger['policy_sha256'],activation_sha256=ledger['activation_sha256'])
    require(len(before['attempts'])==3 and before['active_attempt_id'] is None
        and ledger['attempts'][:3]==before['attempts'],'task_scope_original_three_rows_changed')
    entries={row['entry_sha256']:row for row in settings['entries']};ids={row['attempt_id'] for row in before['attempts']}
    previous=digest(before['attempts'][-1]);pending=[];rounds={};tasks={};last_rid=None
    required={'attempt_id','role','context_sha256','purpose','started_at','requested_model','requested_effort',
        'requested_service_tier','outcome','usage','served_model','owner_operation_id','run_id','round_binding',
        'round_index','previous_attempt_sha256','settings_sha256'}
    for row in ledger['attempts'][3:]:
        terminal={'finished_at','telemetry'} if row.get('outcome')!='PENDING' else set()
        require(type(row)is dict and set(row)==required|terminal and type(row['attempt_id'])is str
            and re.fullmatch('radik-call:[0-9a-f]{32}',row['attempt_id']) and row['attempt_id'] not in ids
            and row['role'] in ('orchestrator','architect','critic') and is_hash(row['context_sha256'])
            and type(row['purpose'])is str and 0<len(row['purpose'])<=256
            and type(row['started_at'])is int and row['started_at']>=0
            and row['previous_attempt_sha256']==previous and row['served_model']=='UNKNOWN'
            and row['outcome'] in ('PENDING','UNKNOWN',*base.TERMINAL_OUTCOMES)
            and type(row['owner_operation_id'])is str and re.fullmatch('[0-9a-f-]{36}',row['owner_operation_id'])
            and type(row['run_id'])is str and re.fullmatch('[0-9a-f]{12}',row['run_id']), 'task_scope_attempt')
        binding=validate_round_binding(row['round_binding']);rid=binding['round_id'];tid=binding['task_id']
        require(rid not in rounds or rid==last_rid,'task_scope_interleaved_round')
        prior=rounds.setdefault(rid,[])
        require((not prior or prior[0]['round_binding']==binding)
            and type(row['round_index'])is int and row['round_index']==len(prior)<binding['max_attempts']
            and (not prior or all(row[key]==prior[0][key] for key in ('owner_operation_id','run_id','settings_sha256')))
            and row['role']==('orchestrator','architect','critic')[len(prior)]
            and (not prior or prior[-1]['outcome']=='COMPLETED'), 'task_scope_round_dependencies')
        tasks.setdefault(tid,set()).add(rid)
        require(len(tasks[tid])<=3 or binding.get('operation_allowance') is not None
            or binding.get('normal_round_scope') is not None,'task_scope_task_round_budget')
        chosen=entries.get(row['settings_sha256'])
        require(chosen is not None and row['requested_model']==chosen['model']
            and row['requested_effort']==chosen['effort'] and row['requested_service_tier'] is None,
            'task_scope_attempt_settings')
        if terminal:
            require(type(row['finished_at'])is int and row['finished_at']>=row['started_at']
                and type(row['telemetry'])is dict,'task_scope_attempt_terminal')
            if row['outcome']!='UNKNOWN':
                require(row['telemetry'].get('terminal_observed')is True or
                    row['telemetry'].get('own_process_finished')is True and row['telemetry'].get('turn_not_started')is True,
                    'budget_terminal_evidence')
        if row['outcome'] in ('PENDING','UNKNOWN'):pending.append(row['attempt_id'])
        prior.append(row);ids.add(row['attempt_id']);previous=digest(row);last_rid=rid
    acknowledged=console_continuation.validate(project,ledger)['acknowledged_remote_unknown_attempt_ids']
    pending=[attempt_id for attempt_id in pending if attempt_id not in acknowledged]
    require(pending==([] if ledger['active_attempt_id']is None else [ledger['active_attempt_id']]),
        'task_scope_active_or_unknown')
    console_continuation.validate_allowance_history(project,original_ledger)
    return original_ledger


def validate_round_binding(value):
    from .console_continuation import validate_round_binding as shared
    return shared(value)


def initial_material(project, record):
    """Reconstruct the exact committed initial bytes from the accepted preimage."""
    before = json.loads(base.read_public(project, BEFORE))
    entry = dict(sequence=0, model='gpt-6.1-sol', effort='high', service_tier='default',
        previous_sha256=None, owner_operation_id=record['owner_operation_id'], run_id=record['run_id'])
    entry['entry_sha256'] = digest(entry)
    settings = dict(schema='radik.task_model_settings.v01', transition_sha256=record['transition_sha256'],
        entries=[entry], current_sha256=entry['entry_sha256'])
    ledger = dict(before, version=VERSION, transition_sha256=record['transition_sha256'],
        task_policy_sha256=record['task_policy']['sha256'])
    ledger['ledger_sha256'] = digest({key:value for key,value in ledger.items() if key!='ledger_sha256'})
    return ledger, settings


def read_state(project):
    raw,record=read_json(project,TRANSITION);validate_transition(project,record)
    require(base.owned(project,COMMITTED).exists(),'task_scope_migration_incomplete')
    _commit_raw,commit=read_json(project,COMMITTED)
    require(type(commit)is dict and set(commit)=={'schema','transition_sha256','initial_ledger_sha256',
        'initial_settings_sha256'} and commit['schema']=='radik.console_source_transition_commit.v01'
        and commit['transition_sha256']==record['transition_sha256']
        and is_hash(commit['initial_ledger_sha256']) and is_hash(commit['initial_settings_sha256']),
        'task_scope_migration_incomplete')
    initial_ledger, initial_settings = initial_material(project, record)
    require(commit['initial_ledger_sha256']==digest(canonical(initial_ledger))
        and commit['initial_settings_sha256']==digest(canonical(initial_settings)), 'task_scope_commit_initial_binding')
    settings_raw,settings=read_json(project,SETTINGS);validate_settings(settings,record['transition_sha256'])
    require(settings['entries'][0]==initial_settings['entries'][0], 'task_scope_initial_settings_changed')
    ledger_raw,ledger=read_json(project,base.SCOPE_PATHS['console']['ledger'],cap=base.MAX_CONSOLE_LEDGER_BYTES)
    validate_ledger(project,ledger,record,settings)
    from . import console_continuation
    continuation=console_continuation.validate(project,ledger)
    from .normal_session import status as normal_status
    normal=normal_status(project,ledger)
    from .source_admission import current
    admitted = current(project, transition=record, commit=commit, ledger=ledger, settings=settings)
    return dict(scope='console',state='IDLE' if ledger['active_attempt_id']is None else 'ACTIVE_OR_UNKNOWN',
        counted=len(ledger['attempts']),maximum=1000000,remaining_attempts=1000000-len(ledger['attempts']),
        active_attempt_id=ledger['active_attempt_id'],unknown_attempt_ids=[row['attempt_id'] for row in ledger['attempts'] if row['outcome']=='UNKNOWN'],
        unacknowledged_unknown_attempt_ids=[row['attempt_id'] for row in ledger['attempts']
            if row['outcome']=='UNKNOWN' and row['attempt_id'] not in continuation['acknowledged_remote_unknown_attempt_ids']],
        ledger_path=base.SCOPE_PATHS['console']['ledger'],ledger_sha256=digest(ledger_raw),
        ledger_canonical_sha256=ledger['ledger_sha256'],policy_path=POLICY,policy_sha256=record['task_policy']['sha256'],
        activation_path=base.SCOPE_PATHS['console']['activation'],activation_sha256=record['activation_identity_sha256'],
        transition_path=TRANSITION,
        transition_sha256=record['transition_sha256'],legacy_console_counted=3,legacy_exam_counted=16,
        cumulative_counted=16+len(ledger['attempts']),model_settings=dict(settings['entries'][-1]),
        original_activation_preserved=True,original_console_rows_preserved=True, **continuation, **normal, **admitted)


def _sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def _write_exact(project,relative,raw):
    """Complete only a known partial prefix of this reviewed deterministic write."""
    path=base.owned(project,relative)
    if path.exists():
        present=base.read_public(project,relative,cap=base.MAX_CONSOLE_LEDGER_BYTES)
        if present==raw:return
        require(len(present)<len(raw) and raw.startswith(present),'task_scope_partial_write_not_owned_prefix')
        repair=path.with_suffix(path.suffix+'.repair')
        require(not repair.exists() and not repair.is_symlink(),'task_scope_repair_pending')
        fd=os.open(repair,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(repair,path);_sync_directory(path.parent);return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    _sync_directory(path.parent)


def apply_transition(project,*,owner_lock_fd):
    """Apply/reconcile exactly one independently reviewed preserving transition.

    Three writes become visible in order: immutable transition, exact migrated
    ledger/settings, commit marker. Reservations refuse any incomplete prefix.
    The original ledger preimage is independently captured immutable evidence.
    A deleted activated ledger is never reconstructed as a fresh counter.
    """
    project=Path(project).resolve(strict=True)
    require(type(owner_lock_fd)is int and owner_lock_fd>=0,'task_scope_owner_lock')
    info=os.fstat(owner_lock_fd);owned_lock=base.owned(project,base.OWNER_LOCK_PATH).stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
        and info.st_uid==os.getuid() and (info.st_dev,info.st_ino)==(owned_lock.st_dev,owned_lock.st_ino),
        'task_scope_owner_lock')
    fcntl.flock(owner_lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    proposal_raw=base.read_public(project,PROPOSAL);proposal=json.loads(proposal_raw)
    review_raw=base.read_public(project,REVIEW);review=json.loads(review_raw)
    expected={'schema','before_ledger_sha256','activation_raw_sha256','activation_identity_sha256',
        'exam_ledger_sha256','quota_sha256','actual_review_sha256','source_review_sha256',
        'source_identity_sha256','task_policy_sha256','owner_operation_id','run_id'}
    require(type(proposal)is dict and set(proposal)==expected
        and proposal['schema']=='radik.console_source_transition_proposal.v01'
        and all(is_hash(proposal[key]) for key in expected-{'schema','owner_operation_id','run_id'})
        and type(proposal['owner_operation_id'])is str and re.fullmatch('[0-9a-f-]{36}',proposal['owner_operation_id'])
        and type(proposal['run_id'])is str and re.fullmatch('[0-9a-f]{12}',proposal['run_id']),
        'task_scope_migration_proposal')
    require(review.get('reviewer')=='/root/semantic_continuation_reviewer'
        and review.get('status')=='ACCEPTED_FOR_PRESERVING_STAGE04_CONSOLE_SOURCE_TRANSITION'
        and review.get('proposal_sha256')==digest(proposal_raw)
        and review.get('source_identity_sha256')==proposal['source_identity_sha256'],
        'task_scope_independent_migration_review')
    before_raw,before=read_json(project,BEFORE)
    activation_raw,activation=read_json(project,base.SCOPE_PATHS['console']['activation'])
    old_policy_raw=base.read_public(project,base.SCOPE_PATHS['console']['policy'])
    base.validate_console_policy(json.loads(old_policy_raw))
    base.validate_console_activation(activation,policy_sha256=digest(old_policy_raw))
    base.validate_console_ledger(before,policy_sha256=digest(old_policy_raw),activation_sha256=activation['activation_sha256'])
    require(len(before['attempts'])==3 and before['active_attempt_id']is None
        and all(row['outcome']=='COMPLETED' for row in before['attempts'])
        and digest(before_raw)==proposal['before_ledger_sha256']
        and digest(activation_raw)==proposal['activation_raw_sha256']
        and activation['activation_sha256']==proposal['activation_identity_sha256'],
        'task_scope_three_row_predecessor')
    # All original activation receipts and immutable exam/quota still bind this
    # source transition, including historical acknowledged UNKNOWN outcomes.
    for ref in (activation['exam_ledger'],activation['actual_acceptance'],activation['consumed_save_quota'],*activation['exam_receipts']):
        require(digest(base.read_public(project,ref['path']))==ref['sha256'],'task_scope_activation_basis_changed')
    require(digest(base.read_public(project,base.SCOPE_PATHS['exam']['ledger']))==proposal['exam_ledger_sha256']
        and digest(base.read_public(project,base.QUOTA_PATH))==proposal['quota_sha256'],
        'task_scope_exam_or_quota_changed')
    base.validate_closed_quota(base.read_public(project,base.QUOTA_PATH))
    task_policy_raw,_task_policy=policy(project)
    record={'schema':'radik.console_source_transition.v01','profile':'stage04_dynamic_information_v01',
        'previous_source_identity_sha256':activation['source_identity_sha256'],
        'source_identity_sha256':proposal['source_identity_sha256'],'before_count':3,
        'activation_identity_sha256':activation['activation_sha256'],
        'owner_operation_id':proposal['owner_operation_id'],'run_id':proposal['run_id']}
    for field,path,pin in (('before_ledger',BEFORE,proposal['before_ledger_sha256']),
        ('activation',base.SCOPE_PATHS['console']['activation'],proposal['activation_raw_sha256']),
        ('exam_ledger',base.SCOPE_PATHS['exam']['ledger'],proposal['exam_ledger_sha256']),
        ('quota',base.QUOTA_PATH,proposal['quota_sha256']),('actual_review',ACTUAL,proposal['actual_review_sha256']),
        ('source_review',RUNTIME_REVIEW,proposal['source_review_sha256']),('migration_review',REVIEW,digest(review_raw)),
        ('task_policy',POLICY,proposal['task_policy_sha256'])):
        record[field]={'path':path,'sha256':pin}
    require(digest(task_policy_raw)==proposal['task_policy_sha256'],'task_scope_policy_changed')
    record['transition_sha256']=digest(record);validate_transition(project,record)
    initial,settings=initial_material(project,record)
    validate_settings(settings,record['transition_sha256']);validate_ledger(project,initial,record,settings)
    ledger_path=base.owned(project,base.SCOPE_PATHS['console']['ledger'])
    require(ledger_path.exists(),'budget_console_activated_ledger_missing')
    current_raw=base.read_public(project,base.SCOPE_PATHS['console']['ledger'],cap=base.MAX_CONSOLE_LEDGER_BYTES)
    transition_path=base.owned(project,TRANSITION);commit_path=base.owned(project,COMMITTED)
    commit={'schema':'radik.console_source_transition_commit.v01','transition_sha256':record['transition_sha256'],
        'initial_ledger_sha256':digest(canonical(initial)),'initial_settings_sha256':digest(canonical(settings))}
    if commit_path.exists() and base.read_public(project,COMMITTED)==canonical(commit):
        require(transition_path.exists() and base.read_public(project,TRANSITION)==canonical(record),
            'task_scope_committed_transition_changed')
        return dict(status='ALREADY_COMMITTED_NO_NEW_BUDGET',**read_state(project))
    require(current_raw in (before_raw,canonical(initial)), 'task_scope_partial_transition_ledger_changed')
    _write_exact(project,TRANSITION,canonical(record))
    _write_exact(project,SETTINGS,canonical(settings))
    if current_raw==before_raw:
        pending=base.SCOPE_PATHS['console']['ledger']+'.stage04.pending'
        _write_exact(project,pending,canonical(initial))
        os.replace(base.owned(project,pending),ledger_path);_sync_directory(ledger_path.parent)
    _write_exact(project,COMMITTED,canonical(commit))
    return dict(status='COMMITTED_PRESERVING_THREE_ROWS',**read_state(project))
