"""One reviewed current-source admission over the committed Stage04 history.

This reader writes no state and grants no model or effect authority. Historical
transition validation and all ledger/settings predicates run before this layer.
The independent admission fixes an immutable baseline prefix, not a moving head.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PASSAGE = 'review/normal_session_g2e_passage'
OPAQUE_PASSAGE = 'review/opaque_metadata_passage'
ANCHOR_PASSAGE = 'review/metadata_continuation_passage'
STREAM = 'review/stream_console_continuation_passage'
PRELIVE = 'review/stage04_prelive_passage'
PRELIVE_SOURCE = 'd7398e45cc8e5da4969c839b95cc282cf9bb4f3fe42495dfa8db7f11c0449cef'
BASE_ATTEMPT = 'radik-call:0adde1226bdd47f18eb14ca89a1e93ea'
ADMISSION = PASSAGE + '/current_source_admission.json'
RUNTIME_REVIEW = PASSAGE + '/runtime_source_review.json'
OWNER_REVIEW = PASSAGE + '/owner_source_review.json'
PRIOR_RUNTIME = 'review/stage04_dynamic_passage/runtime_source_review.json'
PRIOR_SOURCE = 'cfb430a3fc863049eb2503ebc02026b0fc7b1a2d4350f397da7d8bb860a0c343'
TRANSITION_ID = 'b96bade072a08a3964a458cb43637968b37e39448f3653e0c6f53b676c1b7120'
BASE_LEDGER = ANCHOR_PASSAGE + '/actual_basis/state/console_model_turns.json'
BASE_SETTINGS = ANCHOR_PASSAGE + '/actual_basis/state/task_model_settings.json'
FIXED_BASIS = frozenset({
    'state/console_stage04_transition.json', 'state/console_stage04_committed.json',
    'state/console_budget_activation.json', 'state/model_turns.json',
    'state/live_save_quota/single_save.jsonl', 'config/model_policy.json',
    'config/console_model_policy.json', 'config/task_model_policy.json',
    PRIOR_RUNTIME, 'review/stage04_dynamic_passage/owner_source_review.json',
    'review/stage04_dynamic_passage/migration_proposal.json',
    'review/stage04_dynamic_passage/migration_review.json',
    PRELIVE + '/runtime_source_review.json', PRELIVE + '/owner_source_review.json',
    PRELIVE + '/current_source_admission.json', PRELIVE + '/console_source_review.json',
    PRELIVE + '/mechanical_result_review.json', PRELIVE + '/real_execution_review.json',
    'review/returns/RADIK_RETURN_20261016T073219.831363Z.tar.gz',
    'review/returns/RADIK_RETURN_20261016T090929.041606Z.tar.gz',
    'state/console_continuation_073219.json',
    STREAM + '/runtime_source_review.json', STREAM + '/owner_source_review.json',
    STREAM + '/current_source_admission.json', STREAM + '/console_source_review.json',
    STREAM + '/mechanical_result_review.json', STREAM + '/real_execution_review.json',
    STREAM + '/continuation_review.json', STREAM + '/continuation_proposal.json',
    ANCHOR_PASSAGE + '/runtime_source_review.json', ANCHOR_PASSAGE + '/owner_source_review.json',
    ANCHOR_PASSAGE + '/current_source_admission.json', ANCHOR_PASSAGE + '/console_source_review.json',
    ANCHOR_PASSAGE + '/mechanical_result_review.json', ANCHOR_PASSAGE + '/real_execution_review.json',
    ANCHOR_PASSAGE + '/continuation_review.json', ANCHOR_PASSAGE + '/continuation_proposal.json',
    'state/console_continuations/0adde1226bdd47f18eb14ca89a1e93ea.json',
    OPAQUE_PASSAGE + '/runtime_source_review.json', OPAQUE_PASSAGE + '/owner_source_review.json',
    OPAQUE_PASSAGE + '/current_source_admission.json', OPAQUE_PASSAGE + '/console_source_review.json',
    OPAQUE_PASSAGE + '/mechanical_result_review.json', OPAQUE_PASSAGE + '/real_execution_review.json',
    OPAQUE_PASSAGE + '/continuation_review.json', OPAQUE_PASSAGE + '/continuation_proposal.json',
    'state/console_continuations/72ff1b3723314961b6d5a067d24f9a50.json',
})


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'),
        allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value if type(value) is bytes else canonical(value)).hexdigest()


def read(project, relative, cap=64 * 1024 * 1024):
    project = Path(project)
    require(project.is_absolute() and project.resolve(strict=True) == project
        and type(relative) is str and relative and not Path(relative).is_absolute()
        and not set(Path(relative).parts).intersection(('.', '..', 'private', '.codex',
            '.aws', 'Arena', 'arena', 'codex-home')), 'source_carryforward_owned_path')
    path = project / relative
    for node in (path, *path.parents):
        require(not node.is_symlink(), 'source_carryforward_symlink')
        if node == project:
            break
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= cap,
            'source_carryforward_regular_bound')
        raw = stream.read(cap + 1)
    require(len(raw) == info.st_size, 'source_carryforward_regular_bound')
    return raw


def current(project, *, transition, commit, ledger, settings):
    """Check exact source plus valid append-only successors of the sealed basis."""
    from .normal_profile import current as selected_profile
    selected=selected_profile(project)
    historical={} if selected is None else json.loads(read(project,selected[1]['historical_source_inventory_ref']['path']))['files']
    def source_bytes(relative):
        if selected is None:return read(project,relative)
        require(relative in historical,'source_profile_historical_preimage_missing')
        ref=historical[relative]
        raw=read(project,ref['path'])
        require(digest(raw)==ref['sha256'],'source_profile_historical_preimage_changed')
        return raw
    admission_raw = read(project, ADMISSION)
    admission = json.loads(admission_raw)
    fields = {'schema', 'reviewer', 'status', 'scope', 'source_identity_sha256',
        'auth_source_identity_sha256', 'runtime_review_sha256', 'owner_review_sha256',
        'historical_source_identity_sha256', 'transition_sha256', 'unchanged_basis_pins',
        'baseline_ledger_sha256', 'baseline_settings_sha256', 'baseline_count',
        'baseline_settings_count', 'baseline_active_attempt_id',
        'prelive_source_identity_sha256', 'entry_authorizes_model_or_effect'}
    require(type(admission) is dict and set(admission) == fields
        and admission['schema'] == 'radik.independent.normal_session_current_source_admission.v01'
        and admission['reviewer'] == '/root/semantic_continuation_reviewer'
        and admission['status'] == 'SOURCE_ACCEPTED_FOR_NORMAL_SESSION_CARRYFORWARD'
        and admission['scope'] == 'CURRENT_SOURCE_WITH_PRESERVED_FIVE_ROW_ANCHOR_AND_VALIDATED_RECEIPT_CHAIN_NO_ACKNOWLEDGEMENT'
        and admission['entry_authorizes_model_or_effect'] is False
        and admission['historical_source_identity_sha256'] == PRIOR_SOURCE
        and admission['prelive_source_identity_sha256'] == PRELIVE_SOURCE
        and admission['baseline_active_attempt_id'] == BASE_ATTEMPT
        and admission['transition_sha256'] == TRANSITION_ID
        and transition['source_identity_sha256'] == PRIOR_SOURCE
        and transition['transition_sha256'] == TRANSITION_ID
        and commit['transition_sha256'] == TRANSITION_ID, 'source_carryforward_review')
    for field in ('source_identity_sha256', 'auth_source_identity_sha256',
            'runtime_review_sha256', 'owner_review_sha256', 'baseline_ledger_sha256',
            'baseline_settings_sha256'):
        require(type(admission[field]) is str and re.fullmatch('[0-9a-f]{64}', admission[field]),
            'source_carryforward_hash')
    runtime_raw, owner_raw = read(project, RUNTIME_REVIEW), read(project, OWNER_REVIEW)
    runtime, owner = json.loads(runtime_raw), json.loads(owner_raw)
    require(digest(runtime_raw) == admission['runtime_review_sha256']
        and digest(owner_raw) == admission['owner_review_sha256']
        and runtime.get('reviewer') == owner.get('reviewer') == '/root/semantic_continuation_reviewer'
        and runtime.get('status') == 'SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION'
        and owner.get('status') == 'SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT'
        and runtime.get('scope') == owner.get('scope') == 'DIRECT_CHATGPT_PLAN_SOURCE_ONLY'
        and digest(runtime['pins']) == admission['source_identity_sha256']
        and digest(owner['pins']) == admission['auth_source_identity_sha256']
        and set(owner['pins']) <= set(runtime['pins'])
        and all(runtime['pins'][name] == pin for name, pin in owner['pins'].items()),
        'source_carryforward_current_review')
    for relative, pin in runtime['pins'].items():
        require(type(relative) is str and relative.startswith(('app/', 'config/', 'review/',
            'source/reference/')) or relative == 'radik', 'source_carryforward_source_path')
        require(digest(source_bytes(relative)) == pin, 'source_carryforward_source_changed')
    basis = admission['unchanged_basis_pins']
    require(type(basis) is dict and set(basis) == FIXED_BASIS,
        'source_carryforward_fixed_basis')
    for relative, pin in basis.items():
        require(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin)
            and digest(source_bytes(relative)) == pin, 'source_carryforward_basis_changed')
    before_raw, before_settings_raw = read(project, BASE_LEDGER), read(project, BASE_SETTINGS)
    before, before_settings = json.loads(before_raw), json.loads(before_settings_raw)
    count, setting_count = admission['baseline_count'], admission['baseline_settings_count']
    require(digest(before_raw) == admission['baseline_ledger_sha256']
        and digest(before_settings_raw) == admission['baseline_settings_sha256']
        and type(count) is int and count == len(before['attempts']) == 5
        and before['active_attempt_id'] == BASE_ATTEMPT
        and before['attempts'][4]['attempt_id'] == BASE_ATTEMPT
        and before['attempts'][4]['outcome'] == 'UNKNOWN'
        and type(setting_count) is int and setting_count == len(before_settings['entries']) >= 1,
        'source_carryforward_baseline')
    if ledger.get('version') == 'radik.console_turn_ledger.v05':
        from .normal_session import historical_ledger
        ledger = historical_ledger(project, ledger)
    current_headers = {k: v for k, v in ledger.items()
        if k not in ('attempts', 'active_attempt_id', 'ledger_sha256')}
    original_headers = {k: v for k, v in before.items()
        if k not in ('attempts', 'active_attempt_id', 'ledger_sha256')}
    if ledger.get('version') == 'radik.console_turn_ledger.v04':
        from .console_continuation import validate
        acknowledged = validate(project, ledger)
        require(BASE_ATTEMPT in acknowledged['acknowledged_remote_unknown_attempt_ids']
            and acknowledged['local_occupancy_released'] is True
            and current_headers.get('console_continuation_ref') == original_headers.get('console_continuation_ref')
            and 'console_continuation_chain' in current_headers,
            'source_carryforward_console_acknowledgement_binding')
        # Validate the entire immutable chain before normalizing its one new
        # header. All five historical rows and the old receipt stay exact.
        current_headers.pop('console_continuation_chain')
        current_headers['version'] = 'radik.console_turn_ledger.v03'
    require(ledger['attempts'][:count] == before['attempts']
        and current_headers == original_headers
        and settings['entries'][:setting_count] == before_settings['entries']
        and settings['schema'] == before_settings['schema']
        and settings['transition_sha256'] == before_settings['transition_sha256'],
        'source_carryforward_prefix_changed')
    result=dict(source_identity_sha256=admission['source_identity_sha256'],
        auth_source_identity_sha256=admission['auth_source_identity_sha256'],
        historical_source_identity_sha256=PRIOR_SOURCE,
        prelive_source_identity_sha256=PRELIVE_SOURCE,
        current_source_admission_path=ADMISSION, current_source_admission_sha256=digest(admission_raw),
        current_source_admission_scope=admission['scope'], baseline_console_counted=count,
        baseline_settings_count=setting_count, historical_transition_preserved=True,
        source_admission_acknowledges_UNKNOWN=False)
    if selected is not None:
        value=selected[1]
        result.update(source_identity_sha256=digest(value['pins']),
            auth_source_identity_sha256=value['auth_source_identity_sha256'],
            previous_normal_source_identity_sha256=admission['source_identity_sha256'],
            current_source_admission_path=value['source_admission_ref']['path'],
            current_source_admission_sha256=value['source_admission_ref']['sha256'],
            application_profile_ref=selected[0],application_profile=value['profile_id'])
    return result
