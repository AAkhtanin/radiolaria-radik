"""Finite model-budget paths and read-only public scope observations.

Import only after the source inventory is checked. This stdlib-only selector
creates no ledger, activation, owner operation or provider request.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType

SCOPE_PATHS = {
    'exam': {'policy': 'config/model_policy.json', 'ledger': 'state/model_turns.json'},
    'console': {'policy': 'config/console_model_policy.json', 'ledger': 'state/console_model_turns.json',
        'activation': 'state/console_budget_activation.json'},
}
CONSOLE_POLICY_VERSION = 'radik.console_model_policy.v01'
CONSOLE_LEDGER_VERSION = 'radik.console_turn_ledger.v01'
CONSOLE_CONTINUED_LEDGER_VERSION = 'radik.console_turn_ledger.v03'
CONSOLE_CHAIN_LEDGER_VERSION = 'radik.console_turn_ledger.v04'
CONSOLE_ACTIVATION_VERSION = 'radik.console_budget_activation.v01'
ACCEPTANCE_PATH = 'review/actual_save_console_passage/actual_acceptance_review.json'
QUOTA_PATH = 'state/live_save_quota/single_save.jsonl'
OWNER_LOCK_PATH = 'review/direct_plan_passage/owner_start.lock'
MAX_CONSOLE_ATTEMPTS = 1000000
MAX_CONSOLE_LEDGER_BYTES = 16 * 1024 * 1024 * 1024
TERMINAL_OUTCOMES = ('COMPLETED', 'FAILED', 'DENIED', 'CANCELLED', 'TIMED_OUT')
CONSOLE_POLICY_FIELDS = {'schema', 'active', 'scope', 'activation_basis', 'max_new_turn_attempts',
    'max_active_requests', 'max_attempts_per_compare', 'automatic_model_retries', 'automatic_effect_retries',
    'model', 'effort', 'service_tier', 'service_tier_meaning', 'native_work_max_model_calls',
    'native_e_max_provider_calls', 'runtime_inference_gate'}
ACTIVATION_FIELDS = {'schema', 'scope', 'policy_sha256', 'creator_owner_operation_id', 'creator_run_id',
    'source_identity_sha256', 'activated_at', 'exam_ledger', 'exam_recovery_history_sha256',
    'exam_receipts', 'actual_acceptance', 'consumed_save_quota', 'activation_sha256'}


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if type(value) is bytes else canonical(value)).hexdigest()


def is_hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def scope_profile(scope):
    require(type(scope) is str and scope in SCOPE_PATHS, 'budget_scope_unknown')
    return MappingProxyType(dict(scope=scope, **SCOPE_PATHS[scope]))


def owned(project, relative):
    project = Path(project)
    require(project.is_dir() and not project.is_symlink() and project.absolute() == project.resolve(strict=True),
        'budget_scope_project_identity')
    require(type(relative) is str and relative and not Path(relative).is_absolute()
        and not set(Path(relative).parts).intersection(('.', '..', 'private', 'Arena', 'arena', '.codex', '.aws')),
        'budget_scope_owned_path')
    path = project
    for part in Path(relative).parts:
        path = path / part
        require(not path.is_symlink(), 'budget_scope_symlink')
    require(path.parent.resolve(strict=True).is_relative_to(project), 'budget_scope_owned_path')
    return path


def read_public(project, relative, *, cap=1024 * 1024):
    path = owned(project, relative)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= cap,
            'budget_scope_regular_bound')
        raw = stream.read(info.st_size + 1)
    require(len(raw) == info.st_size and len(raw) <= cap, 'budget_scope_regular_bound')
    return raw


def validate_console_policy(policy):
    require(type(policy) is dict and set(policy) == CONSOLE_POLICY_FIELDS
        and policy['schema'] == CONSOLE_POLICY_VERSION and policy['scope'] == 'console' and policy['active'] is True
        and type(policy['max_new_turn_attempts']) is int and policy['max_new_turn_attempts'] == MAX_CONSOLE_ATTEMPTS
        and type(policy['max_active_requests']) is int and policy['max_active_requests'] == 1
        and type(policy['max_attempts_per_compare']) is int and policy['max_attempts_per_compare'] == 3
        and policy['automatic_model_retries'] == policy['automatic_effect_retries'] == 0
        and policy['native_work_max_model_calls'] == policy['native_e_max_provider_calls'] == 0
        and policy['model'] == 'gpt-6.1-sol' and policy['effort'] == 'high' and policy['service_tier'] is None
        and all(type(policy[key]) is str and policy[key] for key in
            ('activation_basis', 'service_tier_meaning', 'runtime_inference_gate')), 'budget_console_policy')
    return policy


def validate_console_activation(value, *, policy_sha256):
    require(type(value) is dict and set(value) == ACTIVATION_FIELDS
        and value['schema'] == CONSOLE_ACTIVATION_VERSION and value['scope'] == 'console'
        and value['policy_sha256'] == policy_sha256 and is_hash(value['source_identity_sha256'])
        and type(value['activated_at']) is int and value['activated_at'] >= 0
        and type(value['creator_owner_operation_id']) is str
        and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value['creator_owner_operation_id'])
        and type(value['creator_run_id']) is str and re.fullmatch('[0-9a-f]{12}', value['creator_run_id'])
        and value['activation_sha256'] == digest({key: item for key, item in value.items() if key != 'activation_sha256'}),
        'budget_console_activation')
    exam = value['exam_ledger']
    require(type(exam) is dict and set(exam) == {'path', 'sha256', 'canonical_sha256', 'counted', 'active_attempt_id'}
        and exam['path'] == SCOPE_PATHS['exam']['ledger'] and is_hash(exam['sha256']) and is_hash(exam['canonical_sha256'])
        and exam['counted'] == 16 and exam['active_attempt_id'] is None
        and is_hash(value['exam_recovery_history_sha256']), 'budget_console_exam_basis')
    require(type(value['exam_receipts']) is list and len(value['exam_receipts']) == 5
        and all(type(row) is dict and set(row) == {'path', 'sha256'} and is_hash(row['sha256'])
            and type(row['path']) is str and re.fullmatch(
                r'review/direct_plan_passage/local_unknown_recovery_[0-9a-f-]{36}\.json', row['path'])
            for row in value['exam_receipts']), 'budget_console_recovery_basis')
    acceptance, quota = value['actual_acceptance'], value['consumed_save_quota']
    require(type(acceptance) is dict and set(acceptance) == {'path', 'sha256'}
        and acceptance['path'] == ACCEPTANCE_PATH and is_hash(acceptance['sha256']), 'budget_console_acceptance_basis')
    require(type(quota) is dict and set(quota) == {'path', 'sha256', 'head_sha256', 'state'}
        and quota['path'] == QUOTA_PATH and is_hash(quota['sha256']) and is_hash(quota['head_sha256'])
        and quota['state'] == 'CLOSED', 'budget_console_quota_basis')
    return value


def validate_closed_quota(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 65536 and raw.endswith(b'\n'), 'budget_console_quota_basis')
    rows = [json.loads(line) for line in raw.splitlines()]
    require(len(rows) == 3 and [row.get('state') for row in rows] == ['GRANTED', 'RESERVED', 'CLOSED'],
        'budget_console_quota_not_consumed')
    previous = None
    for index, row in enumerate(rows):
        require(type(row) is dict and set(row) == {'version', 'sequence', 'previous_sha256', 'state', 'at', 'details', 'record_sha256'}
            and row['version'] == 'radik.single_save_quota.v01' and row['sequence'] == index
            and row['previous_sha256'] == previous and type(row['at']) is int and type(row['details']) is dict
            and row['record_sha256'] == digest({key: item for key, item in row.items() if key != 'record_sha256'})
            and canonical(row) == raw.splitlines()[index], 'budget_console_quota_basis')
        previous = row['record_sha256']
    require(rows[-1]['details'].get('grant_revoked') is True and rows[-1]['details'].get('retry_allowed') is False
        and rows[-1]['details'].get('receipt', {}).get('executor_starts') == 1,
        'budget_console_quota_not_consumed')
    return rows


def validate_console_ledger(ledger, *, policy_sha256, activation_sha256):
    require(type(ledger) is dict and set(ledger) == {'version', 'scope', 'policy_sha256', 'activation_sha256',
        'attempts', 'active_attempt_id', 'ledger_sha256'} and ledger['version'] == CONSOLE_LEDGER_VERSION
        and ledger['scope'] == 'console' and ledger['policy_sha256'] == policy_sha256
        and ledger['activation_sha256'] == activation_sha256 and type(ledger['attempts']) is list
        and len(ledger['attempts']) <= MAX_CONSOLE_ATTEMPTS
        and ledger['ledger_sha256'] == digest({key: item for key, item in ledger.items() if key != 'ledger_sha256'}),
        'budget_console_ledger')
    ids, compare_ids, outstanding = set(), set(), []
    previous = None
    current_compare, role_index = None, 0
    for row in ledger['attempts']:
        require(type(row) is dict, 'budget_console_attempt')
        required = {'attempt_id', 'role', 'context_sha256', 'purpose', 'started_at', 'requested_model',
            'requested_effort', 'requested_service_tier', 'outcome', 'usage', 'served_model', 'owner_operation_id',
            'run_id', 'compare_id', 'compare_index', 'previous_attempt_sha256'}
        terminal = {'finished_at', 'telemetry'} if row.get('outcome') != 'PENDING' else set()
        require(type(row) is dict and set(row) == required | terminal
            and type(row['attempt_id']) is str and re.fullmatch('radik-call:[0-9a-f]{32}', row['attempt_id'])
            and row['attempt_id'] not in ids and is_hash(row['context_sha256'])
            and type(row['purpose']) is str and 0 < len(row['purpose']) <= 256
            and type(row['started_at']) is int and row['started_at'] >= 0
            and row['requested_model'] == 'gpt-6.1-sol' and row['requested_effort'] == 'high'
            and row['requested_service_tier'] is None and row['served_model'] == 'UNKNOWN'
            and type(row['owner_operation_id']) is str
            and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', row['owner_operation_id'])
            and type(row['run_id']) is str and re.fullmatch('[0-9a-f]{12}', row['run_id'])
            and type(row['compare_id']) is str and re.fullmatch('console-compare:[0-9a-f]{32}', row['compare_id'])
            and row['previous_attempt_sha256'] == previous
            and row['outcome'] in ('PENDING', 'UNKNOWN', *TERMINAL_OUTCOMES), 'budget_console_attempt')
        if row['compare_id'] != current_compare:
            require(row['compare_id'] not in compare_ids, 'budget_console_compare_replay')
            compare_ids.add(row['compare_id']); current_compare, role_index = row['compare_id'], 0
        require(type(row['compare_index']) is int and row['compare_index'] == role_index < 3
            and row['role'] == ('orchestrator', 'architect', 'critic')[role_index], 'budget_console_compare_limit')
        if role_index:
            require(prior_row['outcome'] == 'COMPLETED' and (row['owner_operation_id'], row['run_id']) ==
                (prior_row['owner_operation_id'], prior_row['run_id']), 'budget_console_compare_failed')
        if terminal:
            require(type(row['finished_at']) is int and row['finished_at'] >= row['started_at']
                and type(row['telemetry']) is dict, 'budget_console_attempt')
            if row['outcome'] != 'UNKNOWN':
                require(row['telemetry'].get('terminal_observed') is True or
                    row['telemetry'].get('own_process_finished') is True and row['telemetry'].get('turn_not_started') is True,
                    'budget_terminal_evidence')
        if row['outcome'] in ('PENDING', 'UNKNOWN'):
            outstanding.append(row['attempt_id'])
        ids.add(row['attempt_id']); role_index += 1; previous = digest(row); prior_row = row
    require(outstanding == ([] if ledger['active_attempt_id'] is None else [ledger['active_attempt_id']]),
        'budget_console_active_or_unknown')
    return ledger


def read_scope_state(project, scope):
    """Observe exact scopes without opening locks or creating missing state."""
    profile = scope_profile(scope)
    policy_raw = read_public(project, profile['policy'])
    policy = json.loads(policy_raw)
    path = owned(project, profile['ledger'])
    if scope == 'exam':
        if not path.exists():
            return dict(scope=scope, state='NOT_CREATED', counted=0, maximum=policy['max_new_turn_attempts'],
                remaining_attempts=policy['max_new_turn_attempts'], active_attempt_id=None, unknown_attempt_ids=[],
                policy_path=profile['policy'], policy_sha256=digest(policy_raw), ledger_path=profile['ledger'])
        raw = read_public(project, profile['ledger'])
        ledger = json.loads(raw)
        require(type(ledger.get('attempts')) is list and ledger.get('policy_sha256') == digest(policy_raw), 'budget_scope_exam_state')
        history = ledger.get('recovery_history', [ledger['local_recovery']] if 'local_recovery' in ledger else [])
        acknowledged = {row['attempt_id'] for row in history}
        unknown = [row['attempt_id'] for row in ledger['attempts'] if row['outcome'] == 'UNKNOWN']
        return dict(scope=scope, state='ACTIVE_OR_UNKNOWN' if ledger.get('active_attempt_id') is not None else 'IDLE',
            counted=len(ledger['attempts']), maximum=policy['max_new_turn_attempts'], active_attempt_id=ledger.get('active_attempt_id'),
            remaining_attempts=policy['max_new_turn_attempts'] - len(ledger['attempts']),
            unknown_attempt_ids=[attempt for attempt in unknown if attempt not in acknowledged],
            historical_unknown_attempt_ids=unknown, acknowledged_remote_unknown_attempt_ids=sorted(acknowledged),
            policy_path=profile['policy'], policy_sha256=digest(policy_raw), ledger_path=profile['ledger'],
            ledger_sha256=digest(raw), ledger_canonical_sha256=digest(ledger))
    validate_console_policy(policy)
    activation_path = owned(project, profile['activation'])
    require(activation_path.exists(), 'budget_console_prior_activation_required')
    require(path.exists(), 'budget_console_activated_ledger_missing')
    activation_raw = read_public(project, profile['activation'])
    activation = validate_console_activation(json.loads(activation_raw), policy_sha256=digest(policy_raw))
    require(activation_raw == canonical(activation), 'budget_console_activation')
    for reference in (activation['exam_ledger'], activation['actual_acceptance'],
            activation['consumed_save_quota'], *activation['exam_receipts']):
        require(digest(read_public(project, reference['path'])) == reference['sha256'], 'budget_console_basis_changed')
    quota_rows = validate_closed_quota(read_public(project, QUOTA_PATH))
    require(quota_rows[-1]['record_sha256'] == activation['consumed_save_quota']['head_sha256'], 'budget_console_basis_changed')
    from app import task_budget as task_scope
    require(owned(project,task_scope.TRANSITION).exists()
        and owned(project,task_scope.COMMITTED).exists(), 'budget_console_prior_transition_required')
    return task_scope.read_state(project)
