"""Owned normal-operation journals; historical recovery authority is never renewed.

Readers are bounded and do not call source admission, construct a store, or reserve
a model turn. Only the trusted owner entry mutates the preserving transition and
operation pointer. A command grant is durable before TaskStore and provider use.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

VERSION = 'radik.console_turn_ledger.v05'
POLICY = 'config/normal_session_policy.json'
PASSAGE = 'review/normal_session_g2e_passage'
PROPOSAL = PASSAGE + '/normal_transition_proposal.json'
REVIEW = PASSAGE + '/normal_transition_review.json'
TRANSITION = 'state/normal_session_transition.json'
COMMITTED = 'state/normal_session_committed.json'
ACTIVE = 'state/normal_session_active.json'
LEDGER = 'state/console_model_turns.json'
TASKS = 'workspace/owner_documents/state/dynamic_tasks.json'
SETTINGS = 'state/task_model_settings.json'
ROUND_VERSION = 'radik.normal_round_binding.v01'
MODES = {'COLD': 3, 'MEMORY_ONLY': 0, 'NATIVE_CONTINUE': 0}
UUID = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if type(value) is bytes else canonical(value)).hexdigest()


def _hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _identity(operation, run):
    require(type(operation) is str and UUID.fullmatch(operation) is not None
        and type(run) is str and re.fullmatch('[0-9a-f]{12}', run), 'normal_operation_identity')


def _path(project, relative):
    require(type(relative) is str and relative and '\\' not in relative
        and not relative.startswith('/') and all(p not in ('', '.', '..') for p in relative.split('/')),
        'normal_owned_path')
    root = Path(project).resolve(strict=True)
    path = root
    for part in relative.split('/'):
        path = path / part
        require(not path.is_symlink(), 'normal_owned_symlink')
    require(path.resolve().is_relative_to(root), 'normal_owned_path')
    return path


def _read(project, relative, cap=32 * 1024 * 1024):
    path = _path(project, relative)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= cap,
            'normal_regular_bound')
        raw = stream.read(cap + 1)
    require(len(raw) <= cap, 'normal_regular_bound')
    return raw


def _json(project, relative):
    raw = _read(project, relative)
    value = json.loads(raw)
    return raw, value


def _ref(reference):
    require(type(reference) is dict and set(reference) in ({'path','sha256'},{'path','sha256','size_bytes'})
        and ('size_bytes'not in reference or type(reference['size_bytes'])is int and 0<=reference['size_bytes']<=32*1024*1024)
        and _hash(reference['sha256']) and type(reference['path']) is str,
        'normal_reference')
    return reference


def _reference(project, reference):
    _ref(reference)
    raw = _read(project, reference['path'])
    require(digest(raw) == reference['sha256']and('size_bytes'not in reference or len(raw)==reference['size_bytes']), 'normal_reference_changed')
    value = json.loads(raw)
    return value


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _exclusive(project, relative, value):
    path = _path(project, relative)
    parent_existed=path.parent.exists()
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not parent_existed:_sync(path.parent.parent)
    # A visible partial or prior receipt is a refusal, never a repair/regrant.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    raw = canonical(value)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    _sync(path.parent)
    require(_read(project, relative) == raw, 'normal_write_readback')
    return {'path': relative, 'sha256': digest(raw)}


def _replace(project, relative, value):
    path = _path(project, relative)
    pending = relative + '.pending'
    _exclusive(project, pending, value)
    os.replace(_path(project, pending), path)
    _sync(path.parent)
    require(_read(project, relative) == canonical(value), 'normal_write_readback')


def _owner_lock(project, fd):
    from review.transport.model_scope import OWNER_LOCK_PATH
    require(type(fd) is int and fd >= 0, 'normal_owner_lock')
    info, target = os.fstat(fd), _path(project, OWNER_LOCK_PATH).stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino), 'normal_owner_lock')
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def policy(project):
    raw, value = _json(project, POLICY)
    expected = dict(schema='radik.normal_session_policy.v01', scope='console',
        authority='EXPLICIT_OWNER_OPERATION_AND_USER_COMMAND', lifetime_task_quota=None,
        modes=MODES, max_active_requests=1, max_console_attempts=1000000,
        automatic_retries=0, native_u2_max_revisions=2, native_work_max_model_calls=0,
        native_e_max_provider_calls=0, request_deadline_seconds=600,
        reuse_window_seconds=7200, informational_horizon_seconds=10800,
        historical_task_policy='IMMUTABLE_LEGACY_MEANINGS_ONLY')
    require(type(value) is dict and value == expected
        and all(type(value[key]) is int for key in ('max_active_requests', 'max_console_attempts',
            'automatic_retries', 'native_u2_max_revisions', 'native_work_max_model_calls',
            'native_e_max_provider_calls', 'request_deadline_seconds', 'reuse_window_seconds',
            'informational_horizon_seconds')) and all(type(n) is int for n in value['modes'].values()),
        'normal_policy_shape')
    return raw, value


def approval(project):
    raw, proposal = _json(project, PROPOSAL)
    review_raw, review = _json(project, REVIEW)
    require(type(proposal) is dict and set(proposal) == {'schema', 'before_ledger_ref',
        'task_state_ref', 'normal_policy_ref', 'source_review_ref', 'source_identity_sha256',
        'auth_source_identity_sha256', 'source_admission_ref'}
        and proposal['schema'] == 'radik.normal_session_transition_proposal.v01'
        and all(_hash(proposal[key]) for key in ('source_identity_sha256', 'auth_source_identity_sha256')),
        'normal_transition_proposal')
    require(review.get('reviewer') == '/root/semantic_continuation_reviewer'
        and review.get('status') == 'ACCEPTED_FOR_FUTURE_NORMAL_SESSION_TRANSITION'
        and review.get('proposal_sha256') == digest(raw)
        and all(review.get(key) == proposal[key] for key in
            ('source_identity_sha256', 'auth_source_identity_sha256')), 'normal_transition_review')
    before = _reference(project, proposal['before_ledger_ref'])
    tasks = _reference(project, proposal['task_state_ref'])
    source = _reference(project, proposal['source_review_ref'])
    _reference(project, proposal['source_admission_ref'])
    policy_raw, _ = policy(project)
    require(proposal['normal_policy_ref'] == {'path': POLICY, 'sha256': digest(policy_raw)}
        and all(proposal[key]['path'].startswith(PASSAGE+'/') for key in
            ('before_ledger_ref','task_state_ref','source_review_ref','source_admission_ref'))
        and source.get('reviewer') == '/root/semantic_continuation_reviewer'
        and digest(source['pins']) == proposal['source_identity_sha256']
        and source.get('auth_source_identity_sha256') == proposal['auth_source_identity_sha256']
        and before.get('version') == 'radik.console_turn_ledger.v04'
        and before.get('active_attempt_id') is None and tasks.get('active_task_id') is None,
        'normal_transition_basis')
    return raw, proposal, review_raw, before, tasks


def _initial(project):
    proposal_raw, proposal, review_raw, before, _tasks = approval(project)
    raw, transition = _json(project, TRANSITION)
    require(type(transition) is dict and set(transition) == {'schema', 'proposal_ref', 'review_ref'}
        and transition['schema'] == 'radik.normal_session_transition.v01'
        and transition['proposal_ref'] == {'path': PROPOSAL, 'sha256': digest(proposal_raw)}
        and transition['review_ref'] == {'path': REVIEW, 'sha256': digest(review_raw)},
        'normal_transition_binding')
    reference = {'path': TRANSITION, 'sha256': digest(raw)}
    initial = dict(before, version=VERSION, normal_policy_transition_ref=reference)
    initial['ledger_sha256'] = digest({k: v for k, v in initial.items() if k != 'ledger_sha256'})
    return reference, initial, before, proposal


def historical_ledger(project, ledger):
    """Validate the v05 transition and project old headers, without recursive I/O."""
    require(type(ledger) is dict and ledger.get('version') == VERSION, 'normal_ledger_version')
    reference, initial, before, _proposal = _initial(project)
    _raw, commit = _json(project, COMMITTED)
    require(commit == dict(schema='radik.normal_session_commit.v01', transition_ref=reference,
        before_ledger_sha256=digest(canonical(before)), before_head=before['ledger_sha256'],
        initial_ledger_sha256=digest(canonical(initial)), initial_head=initial['ledger_sha256']),
        'normal_transition_commit')
    require(set(ledger) == set(initial) and ledger['normal_policy_transition_ref'] == reference
        and ledger['ledger_sha256'] == digest({k: v for k, v in ledger.items() if k != 'ledger_sha256'})
        and ledger['attempts'][:len(before['attempts'])] == before['attempts']
        and all(ledger[k] == initial[k] for k in initial
            if k not in ('attempts', 'active_attempt_id', 'ledger_sha256')), 'normal_historical_prefix')
    view = {k: v for k, v in ledger.items() if k != 'normal_policy_transition_ref'}
    view['version'] = before['version']
    view['ledger_sha256'] = digest({k: v for k, v in view.items() if k != 'ledger_sha256'})
    return view


def apply_transition(project, *, owner_lock_fd, source_identity_sha256, auth_source_identity_sha256):
    """Future source/result-admitted owner entry only; no ledger reset or ACK."""
    _owner_lock(project, owner_lock_fd)
    raw, ledger = _json(project, LEDGER)
    if ledger.get('version') == VERSION:
        historical_ledger(project, ledger)
        return ledger['normal_policy_transition_ref']
    proposal_raw, proposal, review_raw, before, tasks = approval(project)
    require(proposal['source_identity_sha256'] == source_identity_sha256
        and proposal['auth_source_identity_sha256'] == auth_source_identity_sha256
        and raw == canonical(before) and _read(project, TASKS) == canonical(tasks),
        'normal_transition_current_predecessor')
    require(not _path(project, COMMITTED).exists() and not _path(project, TRANSITION).exists(),
        'normal_transition_incomplete_or_repeated')
    transition = dict(schema='radik.normal_session_transition.v01',
        proposal_ref={'path': PROPOSAL, 'sha256': digest(proposal_raw)},
        review_ref={'path': REVIEW, 'sha256': digest(review_raw)})
    reference = _exclusive(project, TRANSITION, transition)
    initial = dict(before, version=VERSION, normal_policy_transition_ref=reference)
    initial['ledger_sha256'] = digest({k: v for k, v in initial.items() if k != 'ledger_sha256'})
    _replace(project, LEDGER, initial)
    _exclusive(project, COMMITTED, dict(schema='radik.normal_session_commit.v01', transition_ref=reference,
        before_ledger_sha256=digest(raw), before_head=before['ledger_sha256'],
        initial_ledger_sha256=digest(canonical(initial)), initial_head=initial['ledger_sha256']))
    historical_ledger(project, initial)
    return reference


def _operation_path(operation):
    return 'state/normal_operations/' + operation.replace('-', '') + '.json'


def _round_path(round_id):
    return 'state/normal_rounds/' + round_id.split(':')[-1] + '.json'


def _closed(reference):
    return reference['path'] + '.closed'


def validate_operation(project, reference):
    value = _reference(project, reference)
    if type(value) is dict and value.get('schema') == 'radik.normal_operation.v02':
        from .normal_profile import validate_operation as validate_profile_operation
        return validate_profile_operation(project, reference, value)
    require(type(value) is dict and set(value) == {'schema', 'owner_operation_id', 'run_id',
        'transition_ref', 'source_review_ref', 'source_admission_ref', 'source_identity_sha256',
        'auth_source_identity_sha256', 'settings_sha256', 'ledger_head', 'counted', 'task_state_sha256',
        'opened_at'} and value['schema'] == 'radik.normal_operation.v01', 'normal_operation_shape')
    _identity(value['owner_operation_id'], value['run_id'])
    require(reference['path'] == _operation_path(value['owner_operation_id'])
        and all(_hash(value[key]) for key in ('source_identity_sha256', 'auth_source_identity_sha256',
            'settings_sha256', 'ledger_head', 'task_state_sha256'))
        and type(value['counted']) is int and value['counted'] >= 3
        and type(value['opened_at']) is int and value['opened_at'] >= 0, 'normal_operation_shape')
    _ref(value['transition_ref'])
    transition_ref, _initial_ledger, _before, _proposal = _initial(project)
    source = _reference(project, value['source_review_ref'])
    _reference(project, value['source_admission_ref'])
    require(value['transition_ref']==transition_ref
        and value['source_review_ref']['path'].startswith('review/')
        and value['source_review_ref']['path'].endswith('/runtime_source_review.json')
        and value['source_admission_ref']['path'].startswith('review/')
        and value['source_admission_ref']['path'].endswith('/current_source_admission.json')
        and source.get('reviewer') == '/root/semantic_continuation_reviewer'
        and source.get('status')=='SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION'
        and digest(source['pins']) == value['source_identity_sha256']
        and source.get('auth_source_identity_sha256') == value['auth_source_identity_sha256'],
        'normal_operation_source_basis')
    return value


def _close_operation(project, reference, ledger, disposition):
    value = validate_operation(project, reference)
    require(disposition in ('EXITED', 'FAILED_OR_UNKNOWN', 'RESTART_ABANDONED'), 'normal_operation_close')
    return _exclusive(project, _closed(reference), dict(schema='radik.normal_operation_close.v01',
        operation_ref=reference, owner_operation_id=value['owner_operation_id'], run_id=value['run_id'],
        disposition=disposition, final_head=ledger['ledger_sha256'], counted=len(ledger['attempts']),
        active_attempt_id=ledger['active_attempt_id']))


def open_operation(project, *, owner_lock_fd, owner_operation_id, run_id, source_review_ref,
                   source_admission_ref, source_identity_sha256, auth_source_identity_sha256, profile_ref=None, opened_at=None):
    _owner_lock(project, owner_lock_fd)
    _identity(owner_operation_id, run_id)
    _raw, ledger = _json(project, LEDGER)
    historical_ledger(project, ledger)
    require(ledger['active_attempt_id'] is None, 'normal_active_or_unknown')
    from .stage05_disposition import require_operation
    require_operation(project, ledger, owner_operation_id=owner_operation_id, run_id=run_id,
        source_identity_sha256=source_identity_sha256, auth_source_identity_sha256=auth_source_identity_sha256,
        profile_ref=profile_ref)
    require(all(row.get('owner_operation_id') != owner_operation_id and row.get('run_id') != run_id
        for row in ledger['attempts']), 'normal_operation_replay')
    if _path(project, ACTIVE).exists():
        require(profile_ref is None, 'normal_profile_unrelated_active_operation')
        _raw, active = _json(project, ACTIVE)
        old = validate_operation(project, active['operation_ref'])
        require(old['owner_operation_id'] != owner_operation_id and old['run_id'] != run_id,
            'normal_operation_replay')
        require(not _path(project, _closed(active['operation_ref'])).exists(), 'normal_operation_incomplete')
        _close_operation(project, active['operation_ref'], ledger, 'RESTART_ABANDONED')
        _path(project, ACTIVE).unlink()
        _sync(_path(project, ACTIVE).parent)
    _raw, settings = _json(project, SETTINGS)
    tasks_raw, tasks = _json(project, TASKS)
    require(tasks['active_task_id'] is None or tasks['tasks'][tasks['active_task_id']]['status'] == 'RUNNING',
        'normal_task_state')
    value = dict(schema='radik.normal_operation.v01', owner_operation_id=owner_operation_id, run_id=run_id,
        transition_ref=ledger['normal_policy_transition_ref'], source_review_ref=_ref(source_review_ref),
        source_admission_ref=_ref(source_admission_ref), source_identity_sha256=source_identity_sha256,
        auth_source_identity_sha256=auth_source_identity_sha256, settings_sha256=settings['current_sha256'],
        ledger_head=ledger['ledger_sha256'], counted=len(ledger['attempts']), task_state_sha256=digest(tasks_raw),
        opened_at=int(time.time()) if opened_at is None else opened_at)
    require(type(value['opened_at'])is int and 0<=int(time.time())-value['opened_at']<7800,
        'normal_operation_original_clock')
    if profile_ref is not None:
        from .normal_profile import current
        selected = current(project)
        require(selected is not None and selected[0] == profile_ref, 'normal_profile_not_active')
        value.update(schema='radik.normal_operation.v02', profile_ref=profile_ref)
    reference = _exclusive(project, _operation_path(owner_operation_id), value)
    validate_operation(project, reference)
    _exclusive(project, ACTIVE, dict(schema='radik.normal_active_operation.v01', operation_ref=reference))
    return reference


def close_operation(project, *, owner_lock_fd, operation_ref, failed=False):
    _owner_lock(project, owner_lock_fd)
    _raw, active = _json(project, ACTIVE)
    require(type(active) is dict and active.get('operation_ref') == operation_ref
        and active.get('schema') == 'radik.normal_active_operation.v01'
        and set(active) in ({'schema','operation_ref'},{'schema','operation_ref','round_ref'}),
        'normal_operation_not_current')
    _raw, ledger = _json(project, LEDGER)
    historical_ledger(project, ledger)
    reference = _close_operation(project, operation_ref, ledger,
        'FAILED_OR_UNKNOWN' if failed or ledger['active_attempt_id'] is not None else 'EXITED')
    _path(project, ACTIVE).unlink()
    _sync(_path(project, ACTIVE).parent)
    return reference


def _active_operation(project, reference):
    value = validate_operation(project, reference)
    _raw, active = _json(project, ACTIVE)
    require(type(active) is dict and active.get('schema') == 'radik.normal_active_operation.v01'
        and active.get('operation_ref') == reference
        and set(active) in ({'schema', 'operation_ref'}, {'schema', 'operation_ref', 'round_ref'})
        and not _path(project, _closed(reference)).exists(), 'normal_operation_not_current')
    return value


def validate_round_shape(binding):
    proof = binding.get('normal_round_scope')
    if type(proof) is dict and proof.get('schema') == 'radik.normal_round_binding.v02':
        from .normal_profile import validate_round_shape as validate_profile_round
        return validate_profile_round(binding)
    require(type(proof) is dict and set(proof) == {'schema', 'grant_ref', 'operation_ref', 'mode',
        'owner_operation_id', 'run_id', 'history_ordinal'} and proof['schema'] == ROUND_VERSION
        and proof['mode'] in MODES and binding['max_attempts'] == MODES[proof['mode']]
        and type(proof['history_ordinal']) is int and proof['history_ordinal'] >= 1,
        'normal_round_shape')
    _identity(proof['owner_operation_id'], proof['run_id'])
    _ref(proof['grant_ref'])
    _ref(proof['operation_ref'])
    require(proof['grant_ref']['path'] == _round_path(binding['round_id']), 'normal_round_shape')
    return proof


def prepare_round(project, ledger, binding, *, operation_ref, mode, source_successor_ref=None):
    """Persist a new command grant; never reuse or repair an old round ID."""
    historical_ledger(project, ledger)
    operation = _active_operation(project, operation_ref)
    from . import normal_profile
    profile = operation.get('profile_ref')
    modes = normal_profile.MODES if profile is not None else MODES
    require(mode in modes and type(binding['max_attempts']) is int
        and binding['max_attempts'] == modes[mode] and ledger['active_attempt_id'] is None,
        'normal_round_mode')
    _raw, tasks = _json(project, TASKS)
    require(tasks['active_task_id'] is None and binding['task_id'] in tasks['tasks'], 'normal_round_task')
    row = tasks['tasks'][binding['task_id']]
    ordinal = sum(event['kind'] == 'ROUND_STARTED' for event in row['history']) + 1
    require(binding['task_spec_sha256'] == digest(row['spec']), 'normal_round_task')
    from .stage05_disposition import prepare_round as prepare_stage05_round
    prepare_stage05_round(project, ledger, binding, operation=operation, mode=mode)
    # The active journal contains one grant at a time, including a zero-call grant.
    active_raw, active = _json(project, ACTIVE)
    require(set(active) == {'schema', 'operation_ref'}, 'normal_round_already_active')
    _raw, settings = _json(project, SETTINGS)
    value = dict(schema='radik.normal_round_grant.v01', operation_ref=operation_ref,
        owner_operation_id=operation['owner_operation_id'], run_id=operation['run_id'], mode=mode,
        round_binding=dict(binding), history_ordinal=ordinal, before_history_sha256=digest(row['history']),
        before_task_sequence=tasks['sequence'], ledger_head=ledger['ledger_sha256'], counted=len(ledger['attempts']),
        settings_sha256=settings['current_sha256'], issued_at=int(time.time()))
    if profile is not None:
        require(normal_profile.current(project)[0] == profile, 'normal_profile_not_active')
        value.update(schema='radik.normal_round_grant.v02', profile_ref=profile,
            source_successor_ref=source_successor_ref)
        require((source_successor_ref is not None) == (mode == 'INFORMATIONAL_DELTA'),
            'normal_profile_delta_successor_required')
    else:
        require(source_successor_ref is None, 'normal_legacy_successor_forbidden')
    grant_ref = (normal_profile.register_grant(project, _round_path(binding['round_id']), value)
        if profile is not None else _exclusive(project, _round_path(binding['round_id']), value))
    proof = dict(schema=ROUND_VERSION, grant_ref=grant_ref, operation_ref=operation_ref, mode=mode,
        owner_operation_id=operation['owner_operation_id'], run_id=operation['run_id'], history_ordinal=ordinal)
    if profile is not None:
        proof.update(schema=normal_profile.ROUND_VERSION, profile_ref=profile,
            source_successor_ref=source_successor_ref)
    result = dict(binding, normal_round_scope=proof)
    validate_round_shape(result)
    _replace(project, ACTIVE, dict(active, round_ref=grant_ref))
    return result


def validate_round(project, binding, *, task_state=None, before_begin=False, current=False,
                   for_dispatch=False):
    proof = validate_round_shape(binding)
    grant = _reference(project, proof['grant_ref'])
    operation = validate_operation(project, proof['operation_ref'])
    typed = proof['schema'] == 'radik.normal_round_binding.v02'
    extra = {'profile_ref', 'source_successor_ref'} if typed else set()
    require(type(grant) is dict and set(grant) == extra | {'schema', 'operation_ref', 'owner_operation_id', 'run_id',
        'mode', 'round_binding', 'history_ordinal', 'before_history_sha256', 'before_task_sequence',
        'ledger_head', 'counted', 'settings_sha256', 'issued_at'}
        and grant['schema'] == ('radik.normal_round_grant.v02' if typed else 'radik.normal_round_grant.v01')
        and grant['round_binding'] == {k: v for k, v in binding.items() if k != 'normal_round_scope'}
        and all(grant[key] == proof[key] for key in
            ('operation_ref', 'owner_operation_id', 'run_id', 'mode', 'history_ordinal'))
        and all(operation[key] == proof[key] for key in ('owner_operation_id', 'run_id'))
        and all(_hash(grant[key]) for key in ('before_history_sha256', 'ledger_head', 'settings_sha256'))
        and type(grant['before_task_sequence']) is int and grant['before_task_sequence'] >= 0
        and type(grant['counted']) is int and grant['counted'] >= operation['counted']
        and type(grant['issued_at']) is int and grant['issued_at'] >= operation['opened_at'],
        'normal_round_grant_binding')
    if typed:
        require(operation.get('profile_ref') == proof['profile_ref'] == grant['profile_ref']
            and proof['source_successor_ref'] == grant['source_successor_ref'], 'normal_profile_round_basis')
        from .normal_profile import index
        require(proof['grant_ref'] in index(project), 'normal_profile_unindexed_grant')
        if proof['source_successor_ref'] is not None:
            successor = _reference(project, proof['source_successor_ref'])
            require(successor['status'] == 'STAGED' and successor['task_id'] == binding['task_id']
                and successor['task_spec_sha256'] == binding['task_spec_sha256']
                and digest(successor['base']['new_dependencies']) == binding['dependencies_sha256'],
                'normal_profile_source_successor_binding')
    if task_state is None:
        _raw, task_state = _json(project, TASKS)
    row = task_state['tasks'][binding['task_id']]
    starts = [e for e in row['history'] if e['kind'] == 'ROUND_STARTED']
    if before_begin:
        require(len(starts) + 1 == proof['history_ordinal']
            and digest(row['history']) == grant['before_history_sha256']
            and task_state['sequence'] == grant['before_task_sequence'], 'normal_round_history_binding')
    else:
        matches = [e for e in starts if e.get('operation_round') == binding]
        require(len(matches) == 1 and starts.index(matches[0]) + 1 == proof['history_ordinal']
            and matches[0]['sequence'] == grant['before_task_sequence'] + 1
            and digest([e for e in row['history'] if e['sequence'] < matches[0]['sequence']])
                == grant['before_history_sha256'], 'normal_round_history_binding')
    require(digest(row['spec']) == binding['task_spec_sha256'], 'normal_round_task')
    if current:
        if typed:
            from .normal_profile import current as selected_profile
            require(selected_profile(project)[0] == proof['profile_ref'], 'normal_profile_not_active')
        active = _active_operation(project, proof['operation_ref'])
        _raw, pointer = _json(project, ACTIVE)
        require(pointer == dict(schema='radik.normal_active_operation.v01', operation_ref=proof['operation_ref'],
            round_ref=proof['grant_ref']) and not _path(project, _closed(proof['grant_ref'])).exists(),
            'normal_round_not_current')
        _raw, settings = _json(project, SETTINGS)
        require(settings['current_sha256'] == grant['settings_sha256'], 'normal_round_settings_changed')
    if for_dispatch:
        require(current and not before_begin and task_state['active_task_id']==binding['task_id']
            and row['status']=='RUNNING'
            and not any(e['kind'] in ('ROUND_ACCEPTED','ROUND_STOPPED_WITHOUT_RETRY',
                'PROCESS_RESTART_INTERRUPTED','ACCEPTED_RESULT_RETAINED_WITH_LATE_FAILURE','CANCELLED')
                for e in row['history'] if e['sequence']>matches[0]['sequence']),
            'normal_round_dispatch_closed')
    from .stage05_disposition import validate_round as validate_stage05_round
    validate_stage05_round(project, binding, operation=operation, task_state=task_state,
        before_begin=before_begin, current=current)
    return grant


def validate_history(project, ledger, task_state):
    """Reconcile every normal durable slot with counted requests, including zero-call slots."""
    if ledger.get('version') != VERSION:
        require(not any('normal_round_scope' in e.get('operation_round', {})
            for row in task_state['tasks'].values() for e in row['history']), 'normal_round_requires_transition')
        return {}
    historical_ledger(project, ledger)
    _transition_ref,_initial_ledger,before,_proposal=_initial(project)
    rounds = {}
    for task_id, row in task_state['tasks'].items():
        for event in row['history']:
            binding = event.get('operation_round', {})
            if 'normal_round_scope' not in binding:
                continue
            require(event['kind'] == 'ROUND_STARTED' and binding['task_id'] == task_id
                and binding['round_id'] not in rounds, 'normal_round_history_binding')
            grant = validate_round(project, binding, task_state=task_state)
            require(grant['operation_ref'] == binding['normal_round_scope']['operation_ref'], 'normal_round_history_binding')
            rounds[binding['round_id']] = binding
            operation=validate_operation(project,grant['operation_ref'])
            operation_prefix=dict(ledger,attempts=ledger['attempts'][:operation['counted']],active_attempt_id=None)
            require(operation['counted']<=len(ledger['attempts']) and operation['ledger_head']==digest(
                {k:v for k,v in operation_prefix.items() if k!='ledger_sha256'}), 'normal_operation_start_binding')
    for index,row in enumerate(ledger['attempts'][3:],3):
        binding = row['round_binding']
        require(index<len(before['attempts']) or 'normal_round_scope' in binding,
            'normal_request_scope_required')
        if 'normal_round_scope' in binding:
            proof = binding['normal_round_scope']
            require(rounds.get(binding['round_id']) == binding
                and row['owner_operation_id'] == proof['owner_operation_id'] and row['run_id'] == proof['run_id']
                and binding['max_attempts'] == 3, 'normal_request_history_binding')
            grant=_reference(project,proof['grant_ref'])
            first=next(i for i,item in enumerate(ledger['attempts'])
                if item.get('round_binding',{}).get('round_id')==binding['round_id'])
            require(first==grant['counted'] and grant['settings_sha256']==row['settings_sha256'],
                'normal_request_start_binding')
            prefix=dict(ledger,attempts=ledger['attempts'][:first],active_attempt_id=None)
            require(grant['ledger_head']==digest({k:v for k,v in prefix.items() if k!='ledger_sha256'}),
                'normal_request_start_binding')
    from .normal_profile import reconcile_index
    indexed = reconcile_index(project, ledger, task_state, rounds)
    # Return all durable slots; nonstarted slots have no synthetic TaskStore start.
    for round_id, item in indexed.items():
        rounds.setdefault(round_id, item['binding'])
    return rounds


def finish_round(project, ledger, binding):
    grant = validate_round(project, binding, current=True)
    proof = binding['normal_round_scope']
    reference = _exclusive(project, _closed(proof['grant_ref']), dict(schema='radik.normal_round_close.v01',
        grant_ref=proof['grant_ref'], final_head=ledger['ledger_sha256'], counted=len(ledger['attempts']),
        active_attempt_id=ledger['active_attempt_id'], automatic_retry=False))
    _replace(project, ACTIVE, dict(schema='radik.normal_active_operation.v01', operation_ref=grant['operation_ref']))
    return reference


def status(project, ledger):
    if ledger.get('version') != VERSION:
        require(not _path(project,TRANSITION).exists() and not _path(project,COMMITTED).exists()
            and not _path(project,ACTIVE).exists(),'normal_transition_incomplete_or_repeated')
        return dict(normal_session_state='NOT_ACTIVATED')
    historical_ledger(project, ledger)
    if not _path(project, ACTIVE).exists():
        return dict(normal_session_state='IDLE', normal_policy_path=POLICY,
            normal_policy_transition_ref=ledger['normal_policy_transition_ref'])
    _raw, active = _json(project, ACTIVE)
    operation = validate_operation(project, active['operation_ref'])
    require(active.get('schema') == 'radik.normal_active_operation.v01'
        and set(active) in ({'schema', 'operation_ref'}, {'schema', 'operation_ref', 'round_ref'}),
        'normal_operation_not_current')
    require(not _path(project,_closed(active['operation_ref'])).exists(),'normal_operation_incomplete')
    return dict(normal_session_state='ROUND_ACTIVE' if 'round_ref' in active else 'OPERATION_ACTIVE',
        normal_policy_path=POLICY, normal_policy_transition_ref=ledger['normal_policy_transition_ref'],
        normal_operation_ref=active['operation_ref'], normal_owner_operation_id=operation['owner_operation_id'],
        normal_run_id=operation['run_id'], normal_round_ref=active.get('round_ref'))


def public_evidence_paths(project, ledger, owner_operation_id, run_id):
    """Select only the requested operation's finite journal and historical anchors."""
    _identity(owner_operation_id,run_id)
    if ledger.get('version')!=VERSION:return []
    historical_ledger(project,ledger)
    _raw,tasks=_json(project,TASKS)
    validate_history(project,ledger,tasks)
    operation_path=_operation_path(owner_operation_id)
    raw=_read(project,operation_path)
    reference={'path':operation_path,'sha256':digest(raw)}
    value=validate_operation(project,reference)
    require(value['run_id']==run_id,'normal_operation_identity')
    paths={POLICY,PROPOSAL,REVIEW,TRANSITION,COMMITTED,LEDGER,TASKS,SETTINGS,operation_path}
    for field in ('before_ledger_ref','task_state_ref','source_review_ref','source_admission_ref'):
        paths.add(_initial(project)[3][field]['path'])
    paths.update((value['source_review_ref']['path'],value['source_admission_ref']['path']))
    if value.get('profile_ref') is not None:
        from .normal_profile import INDEX, index, profile
        paths.add(value['profile_ref']['path'])
        selected=profile(project,value['profile_ref'])
        paths.add(selected['historical_source_inventory_ref']['path'])
        paths.add(INDEX)
        successor_ids=set()
        for grant_ref in index(project):
            grant=_reference(project,grant_ref)
            if grant['operation_ref'].get('path')!=operation_path:continue
            paths.add(grant_ref['path'])
            if _path(project,_closed(grant_ref)).exists():paths.add(_closed(grant_ref))
            staged=grant.get('source_successor_ref')
            if staged is not None:
                successor_ids.add(_reference(project,staged)['successor_id'])
        if successor_ids:
            from types import SimpleNamespace
            from .source_successor import INDEX as successor_index,read as read_successors
            records,_latest=read_successors(SimpleNamespace(project=_path(project,TASKS).parent.parent,state=tasks))
            paths.add(successor_index)
            for successor_ref in records:
                if _reference(project,successor_ref)['successor_id'] in successor_ids:paths.add(successor_ref['path'])
    if _path(project,_closed(reference)).exists():paths.add(_closed(reference))
    if _path(project,ACTIVE).exists():paths.add(ACTIVE)
    for row in tasks['tasks'].values():
        for event in row['history']:
            proof=event.get('operation_round',{}).get('normal_round_scope')
            if proof is None or proof['owner_operation_id']!=owner_operation_id or proof['run_id']!=run_id:continue
            paths.add(proof['grant_ref']['path'])
            if _path(project,_closed(proof['grant_ref'])).exists():paths.add(_closed(proof['grant_ref']))
    return sorted(paths)
