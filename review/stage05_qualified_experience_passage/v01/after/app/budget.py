"""Persistent finite turn-attempt ledger; unknown calls are never free retries."""
import fcntl
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path

from .contracts import canonical, digest, require
from review.transport import model_scope


RECOVERY_VERSION = 'radik.local_request_recovery_contract.v01'
RECOVERY_HISTORY_VERSION = 'radik.local_request_recovery_contract.v02'
RECOVERY_RESPONSE_VERSION = 'radik.local_request_recovery_contract.v03'
OCCUPANCY_CONTRACT = 'ONE_MANAGED_LOCAL_REQUEST_WITH_ACKNOWLEDGED_REMOTE_UNKNOWN'
RECOVERY_DISPOSITION = 'LOCAL_CLOSED_REMOTE_OUTCOME_UNKNOWN'
RECOVERY_FIELDS = frozenset({
    'version', 'disposition', 'occupancy_contract', 'owner_acceptance', 'attempt_id',
    'policy_sha256', 'ledger_before_file_sha256', 'ledger_before_canonical_sha256',
    'attempt_before_sha256', 'counted_attempts', 'old_context_sha256',
    'old_request_body_sha256', 'old_owner_operation_id', 'old_run_id',
    'old_source_identity_sha256', 'current_source_identity_sha256', 'evidence_refs',
    'local_cleanup', 'no_effect', 'prepared_at', 'contract_id',
})
APPLICATION_FIELDS = frozenset({
    'version', 'disposition', 'occupancy_contract', 'contract_sha256', 'contract_id',
    'attempt_id', 'attempt_before_sha256', 'old_context_sha256', 'old_run_id',
    'ledger_before_file_sha256', 'ledger_before_canonical_sha256', 'counted_attempts',
    'current_source_identity_sha256', 'owner_operation_id', 'applied_at',
})
HISTORY_CONTRACT_FIELDS = RECOVERY_FIELDS | {'prior_recovery_history_sha256', 'prior_recovery_receipts'}
HISTORY_APPLICATION_FIELDS = APPLICATION_FIELDS | {
    'prior_ledger_version', 'prior_recovery_history_sha256', 'prior_recovery_receipts'}
RESPONSE_APPLICATION_FIELDS = HISTORY_APPLICATION_FIELDS | {'response_id', 'transport_observation_ref'}


def _response_id(value):
    # This is the exact bounded identifier profile used by the Responses parser.
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,160}', value) is not None


def _transport_identity(raw, reference, row, cleanup):
    require(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024
            and digest(raw) == reference['sha256'], 'budget_recovery_transport_pin')
    observation = json.loads(raw)
    response_id = row.get('telemetry', {}).get('response_id')
    require(_response_id(response_id) and type(observation) is dict
            and observation.get('response_id') == response_id == cleanup['response_id']
            and observation.get('reservation_id') == row['attempt_id']
            and observation.get('context_sha256') == row['context_sha256']
            and type(observation.get('wire')) is dict
            and observation['wire'].get('body_sha256') == row['telemetry']['wire_body_sha256']
            and observation.get('outcome') == 'UNKNOWN'
            and observation.get('terminal_observed') is False,
            'budget_recovery_response_identity_mismatch')


def _receipt_reference(reference, *, annotated=False):
    fields = {'path', 'sha256'} | ({'application_sha256', 'contract_sha256'} if annotated else set())
    require(type(reference) is dict and set(reference) == fields
            and type(reference['path']) is str and re.fullmatch(
                r'review/direct_plan_passage/local_unknown_recovery_[0-9a-f-]{36}\.json',
                reference['path']) is not None
            and all(_hash(reference[key]) for key in fields - {'path'}), 'budget_recovery_receipt_reference')


def _history(ledger):
    if ledger['version'] == 'radik.turn_ledger.v01':
        return []
    if ledger['version'] == 'radik.turn_ledger.v02':
        return [ledger['local_recovery']]
    return ledger['recovery_history']


def _ledger_prefix(ledger, history, count, active, version):
    value = {'version': version, 'policy_sha256': ledger['policy_sha256'],
             'attempts': ledger['attempts'][:count], 'active_attempt_id': active}
    if version != 'radik.turn_ledger.v01':
        value.update(local_occupancy_contract=OCCUPANCY_CONTRACT, local_recovery=history[0])
    if version == 'radik.turn_ledger.v03':
        value['recovery_history'] = history
    return value


def _validate_ledger_material(ledger, *, policy_sha256, max_attempts):
    require(type(ledger) is dict and ledger.get('version') in (
        'radik.turn_ledger.v01', 'radik.turn_ledger.v02', 'radik.turn_ledger.v03'), 'budget_ledger_shape')
    require(ledger.get('policy_sha256') == policy_sha256, 'budget_policy_changed')
    require(type(ledger.get('attempts')) is list and len(ledger['attempts']) <= max_attempts,
            'budget_ledger_shape')
    expected = {'version', 'policy_sha256', 'attempts', 'active_attempt_id'}
    if ledger['version'] != 'radik.turn_ledger.v01':
        expected |= {'local_occupancy_contract', 'local_recovery'}
        require(ledger.get('local_occupancy_contract') == OCCUPANCY_CONTRACT, 'budget_local_occupancy_contract')
    if ledger['version'] == 'radik.turn_ledger.v03':
        expected.add('recovery_history')
        require(type(ledger.get('recovery_history')) is list
                and 1 <= len(ledger['recovery_history']) <= min(16, len(ledger['attempts']))
                and (len(ledger['recovery_history']) >= 2
                     or type(ledger['recovery_history'][0]) is dict
                     and ledger['recovery_history'][0].get('version') == 'radik.local_request_recovery_application.v03')
                and ledger['local_recovery'] == ledger['recovery_history'][0], 'budget_recovery_history_shape')
    require(set(ledger) == expected, 'budget_ledger_shape')
    require(all(type(row) is dict and row.get('outcome') in (
        'PENDING', 'UNKNOWN', 'COMPLETED', 'FAILED', 'DENIED', 'CANCELLED', 'TIMED_OUT')
        and type(row.get('attempt_id')) is str for row in ledger['attempts']), 'budget_attempt_shape')
    ids = [row['attempt_id'] for row in ledger['attempts']]
    require(len(set(ids)) == len(ids) and (ledger['active_attempt_id'] is None or ledger['active_attempt_id'] in ids),
            'budget_ledger_identity')
    history = _history(ledger)
    recovered_ids, operations, contracts = [], [], []
    previous_count = 0
    for index, application in enumerate(history):
        response_bound = application.get('version') == 'radik.local_request_recovery_application.v03'
        fields = RESPONSE_APPLICATION_FIELDS if response_bound else (
            APPLICATION_FIELDS if index == 0 else HISTORY_APPLICATION_FIELDS)
        require(type(application) is dict and set(application) == fields
                and (response_bound or application['version'] == (
                    'radik.local_request_recovery_application.v01' if index == 0
                    else 'radik.local_request_recovery_application.v02'))
                and application['disposition'] == RECOVERY_DISPOSITION
                and application['occupancy_contract'] == OCCUPANCY_CONTRACT
                and _operation(application['owner_operation_id']) and _run(application['old_run_id'])
                and type(application['counted_attempts']) is int
                and previous_count < application['counted_attempts'] <= len(ledger['attempts'])
                and type(application['applied_at']) is int and application['applied_at'] >= 0,
                'budget_recovery_application_shape')
        require(all(_hash(application[key]) for key in ('contract_sha256', 'attempt_before_sha256',
            'old_context_sha256', 'ledger_before_file_sha256', 'ledger_before_canonical_sha256',
            'current_source_identity_sha256')), 'budget_recovery_application_hash')
        require(application['attempt_id'] not in recovered_ids
                and application['owner_operation_id'] not in operations
                and application['contract_sha256'] not in contracts, 'budget_recovery_history_duplicate')
        count = application['counted_attempts']
        found = [row for row in ledger['attempts'][:count] if row['attempt_id'] == application['attempt_id']]
        require(len(found) == 1 and found[0]['outcome'] == 'UNKNOWN'
                and digest(found[0]) == application['attempt_before_sha256'], 'budget_recovered_unknown_row_changed')
        if response_bound:
            require(_response_id(application['response_id'])
                    and application['response_id'] == found[0].get('telemetry', {}).get('response_id')
                    and type(application['transport_observation_ref']) is dict
                    and set(application['transport_observation_ref']) == {'path', 'sha256'},
                    'budget_recovery_response_identity_mismatch')
        prior_version = ('radik.turn_ledger.v01' if index == 0 else
                         'radik.turn_ledger.v02' if index == 1
                         and history[0]['version'] == 'radik.local_request_recovery_application.v01'
                         else 'radik.turn_ledger.v03')
        if index or response_bound:
            require(application['prior_ledger_version'] == prior_version
                    and application['prior_recovery_history_sha256'] == digest(history[:index])
                    and type(application['prior_recovery_receipts']) is list
                    and len(application['prior_recovery_receipts']) == index,
                    'budget_recovery_history_predecessor')
            for prior_index, reference in enumerate(application['prior_recovery_receipts']):
                _receipt_reference(reference, annotated=True)
                require(reference['application_sha256'] == digest(history[prior_index])
                        and reference['contract_sha256'] == history[prior_index]['contract_sha256'],
                        'budget_recovery_history_receipt_binding')
            if index > 1:
                require(application['prior_recovery_receipts'][:-1] == history[index - 1]['prior_recovery_receipts'],
                        'budget_recovery_history_receipt_substitution')
        before = _ledger_prefix(ledger, history[:index], count, application['attempt_id'], prior_version)
        require(digest(before) == application['ledger_before_canonical_sha256'],
                'budget_recovered_original_history_changed')
        end = history[index + 1]['counted_attempts'] if index + 1 < len(history) else len(ledger['attempts'])
        for row in ledger['attempts'][count:end]:
            require(row.get('owner_operation_id') == application['owner_operation_id']
                    and _run(row.get('run_id')) and row['run_id'] != application['old_run_id']
                    and row.get('recovery_contract_sha256') == application['contract_sha256']
                    and row.get('context_sha256') not in [prior['old_context_sha256'] for prior in history[:index + 1]],
                    'budget_recovered_new_reservation_binding')
            if index:
                _receipt_reference(row.get('owner_receipt_ref'))
                if index + 1 < len(history):
                    expected_ref = history[index + 1]['prior_recovery_receipts'][index]
                    require(row['owner_receipt_ref'] == {key: expected_ref[key] for key in ('path', 'sha256')},
                            'budget_recovery_history_receipt_substitution')
        recovered_ids.append(application['attempt_id'])
        operations.append(application['owner_operation_id'])
        contracts.append(application['contract_sha256'])
        previous_count = count
    outstanding = [row['attempt_id'] for row in ledger['attempts']
                   if row['outcome'] in ('PENDING', 'UNKNOWN') and row['attempt_id'] not in recovered_ids]
    require(outstanding == ([] if ledger['active_attempt_id'] is None else [ledger['active_attempt_id']]),
            'budget_ledger_active_consistency')


def _verify_receipt(raw, reference, ledger, history, index):
    _receipt_reference(reference)
    require(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024 and digest(raw) == reference['sha256'],
            'budget_recovery_receipt_pin')
    receipt = json.loads(raw)
    application = history[index]
    require(reference['path'] == 'review/direct_plan_passage/local_unknown_recovery_' +
            application['owner_operation_id'] + '.json', 'budget_recovery_receipt_reference')
    require(type(receipt) is dict and receipt.get('schema') == 'radik.owner_local_unknown_recovery.v01'
            and receipt.get('owner_operation_id') == application['owner_operation_id']
            and receipt.get('contract_sha256') == application['contract_sha256']
            and type(receipt.get('budget_receipt')) is dict
            and receipt['budget_receipt'].get('application') == application,
            'budget_recovery_receipt_application')
    version = ('radik.turn_ledger.v02' if index == 0
               and application['version'] == 'radik.local_request_recovery_application.v01'
               else 'radik.turn_ledger.v03')
    after = _ledger_prefix(ledger, history[:index + 1], application['counted_attempts'], None, version)
    budget_receipt = receipt['budget_receipt']
    old_row = next(row for row in ledger['attempts'] if row['attempt_id'] == application['attempt_id'])
    require(budget_receipt.get('ledger_after_sha256') == digest(after)
            and budget_receipt.get('old_outcome') == 'UNKNOWN'
            and budget_receipt.get('old_usage') == old_row['usage']
            and budget_receipt.get('counted_attempts') == application['counted_attempts']
            and budget_receipt.get('remote_completion_or_cancellation') == 'NOT_OBSERVED_NOT_CLAIMED',
            'budget_recovery_receipt_ledger')
    return {**reference, 'application_sha256': digest(application), 'contract_sha256': application['contract_sha256']}


def _hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _operation(value):
    return type(value) is str and re.fullmatch(
        '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value) is not None


def _run(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{12}', value) is not None


def validate_local_closed_recovery_contract(contract):
    """Validate a proposed limited amendment; this creates no permission."""
    require(type(contract) is dict and contract.get('version') in (
                RECOVERY_VERSION, RECOVERY_HISTORY_VERSION, RECOVERY_RESPONSE_VERSION)
            and set(contract) == (RECOVERY_FIELDS if contract['version'] == RECOVERY_VERSION else HISTORY_CONTRACT_FIELDS),
            'budget_recovery_contract_fields')
    require(contract['version'] in (RECOVERY_VERSION, RECOVERY_HISTORY_VERSION, RECOVERY_RESPONSE_VERSION)
            and contract['disposition'] == RECOVERY_DISPOSITION
            and contract['occupancy_contract'] == OCCUPANCY_CONTRACT
            and contract['owner_acceptance'] == 'EXPLICIT_ACCEPT_REMOTE_UNKNOWN_REQUIRED',
            'budget_recovery_contract_scope')
    hashes = ('policy_sha256', 'ledger_before_file_sha256', 'ledger_before_canonical_sha256',
              'attempt_before_sha256', 'old_context_sha256', 'old_request_body_sha256',
              'old_source_identity_sha256', 'current_source_identity_sha256')
    require(all(_hash(contract[key]) for key in hashes), 'budget_recovery_contract_hash')
    require(type(contract['attempt_id']) is str
            and re.fullmatch('radik-call:[0-9a-f]{32}', contract['attempt_id']) is not None
            and _operation(contract['old_owner_operation_id']) and _run(contract['old_run_id'])
            and type(contract['counted_attempts']) is int and 1 <= contract['counted_attempts'] <= 16
            and type(contract['prepared_at']) is int and contract['prepared_at'] >= 0,
            'budget_recovery_contract_identity')
    refs = contract['evidence_refs']
    require(type(refs) is dict and set(refs) == {
        'result', 'transport_observation', 'ledger_after_snapshot', 'run_start_basis'},
        'budget_recovery_evidence_fields')
    for reference in refs.values():
        require(type(reference) is dict and set(reference) == {'path', 'sha256'}
                and type(reference['path']) is str and reference['path'].startswith('review/')
                and reference['path'].endswith('.json') and not Path(reference['path']).is_absolute()
                and not set(Path(reference['path']).parts).intersection(
                    ('.', '..', 'private', 'Arena', 'arena', 'codex-home', '.venv-plan'))
                and _hash(reference['sha256']), 'budget_recovery_evidence_reference')
    cleanup = contract['local_cleanup']
    require(type(cleanup) is dict and set(cleanup) == {
        'client_http_closed', 'watchdog_finished', 'terminal_observed',
        'response_id', 'dispatch_may_have_started'}
        and cleanup['client_http_closed'] is True and cleanup['watchdog_finished'] is True
        and cleanup['terminal_observed'] is False and _response_id(cleanup['response_id'])
        and cleanup['dispatch_may_have_started'] is True, 'budget_recovery_local_cleanup')
    require(cleanup['response_id'] == 'UNKNOWN' or contract['version'] == RECOVERY_RESPONSE_VERSION,
            'budget_recovery_transport_observation_required')
    no_effect = contract['no_effect']
    require(type(no_effect) is dict and set(no_effect) == {
        'native_business_work_count', 'effect_writer_count', 'action_policy_closed', 'quota_state'}
        and type(no_effect['native_business_work_count']) is int and no_effect['native_business_work_count'] == 0
        and type(no_effect['effect_writer_count']) is int and no_effect['effect_writer_count'] == 0
        and no_effect['action_policy_closed'] is True
        and type(no_effect['quota_state']) is dict and set(no_effect['quota_state']) == {'state'}
        and no_effect['quota_state']['state'] in ('NOT_STARTED', 'KNOWN_EMPTY'),
        'budget_recovery_effect_scope')
    if contract['version'] in (RECOVERY_HISTORY_VERSION, RECOVERY_RESPONSE_VERSION):
        prior_refs = contract['prior_recovery_receipts']
        require(_hash(contract['prior_recovery_history_sha256']) and type(prior_refs) is list
                and (0 if contract['version'] == RECOVERY_RESPONSE_VERSION else 1)
                    <= len(prior_refs) < contract['counted_attempts'], 'budget_recovery_prior_receipts')
        for reference in prior_refs:
            _receipt_reference(reference, annotated=True)
    require(contract['contract_id'] == 'radik-local-recovery:' + digest({key: value
        for key, value in contract.items() if key != 'contract_id'}), 'budget_recovery_contract_identity_hash')
    return json.loads(canonical(contract))


def build_local_closed_recovery_contract(ledger_bytes, *, attempt_id, basis,
                                       current_source_identity_sha256, prepared_at, prior_receipts=None,
                                       transport_observation=None):
    """Pure preparation from exact public evidence already checked by a reviewer.

    The original max-one promise has no local/server qualifier. This proposed
    amendment requires a separate explicit owner acceptance. It neither changes
    the ledger nor treats disconnect as remote completion or cancellation.
    Evidence references bind independently checked observations; the owner gate
    rechecks those exact bytes and provenance before any future application.
    """
    require(type(ledger_bytes) is bytes and 0 < len(ledger_bytes) <= 1024 * 1024,
            'budget_recovery_ledger_bytes')
    ledger = json.loads(ledger_bytes)
    _validate_ledger_material(ledger, policy_sha256=ledger.get('policy_sha256'), max_attempts=16)
    require(1 <= len(ledger['attempts']) <= 16, 'budget_recovery_original_ledger')
    history = _history(ledger)
    require(ledger['active_attempt_id'] == attempt_id, 'budget_recovery_active_identity')
    found = [row for row in ledger['attempts'] if row.get('attempt_id') == attempt_id]
    require(len(found) == 1 and found[0].get('outcome') == 'UNKNOWN', 'budget_recovery_requires_unknown')
    row = found[0]
    require(attempt_id not in [application['attempt_id'] for application in history],
            'budget_recovery_already_applied')
    telemetry = row.get('telemetry', {})
    require(telemetry.get('terminal_observed') is False
            and _response_id(telemetry.get('response_id'))
            and telemetry.get('dispatch_may_have_started') is True
            and _hash(telemetry.get('wire_body_sha256')), 'budget_recovery_unknown_telemetry')
    require(type(basis) is dict and set(basis) == {'old_owner_operation_id', 'old_run_id',
        'old_source_identity_sha256', 'evidence_refs', 'local_cleanup', 'no_effect'},
        'budget_recovery_basis_fields')
    require(basis['local_cleanup'].get('response_id') == telemetry['response_id'],
            'budget_recovery_response_identity_mismatch')
    response_bound = transport_observation is not None
    if response_bound:
        require(type(transport_observation) is dict and set(transport_observation) == {'reference', 'raw'}
                and transport_observation['reference'] == basis['evidence_refs']['transport_observation'],
                'budget_recovery_transport_reference')
        _transport_identity(transport_observation['raw'], transport_observation['reference'], row, basis['local_cleanup'])
    else:
        require(telemetry['response_id'] == 'UNKNOWN', 'budget_recovery_transport_observation_required')
    contract = {
        'version': (RECOVERY_RESPONSE_VERSION if response_bound else
                    RECOVERY_HISTORY_VERSION if history else RECOVERY_VERSION), 'disposition': RECOVERY_DISPOSITION,
        'occupancy_contract': OCCUPANCY_CONTRACT,
        'owner_acceptance': 'EXPLICIT_ACCEPT_REMOTE_UNKNOWN_REQUIRED',
        'attempt_id': attempt_id, 'policy_sha256': ledger['policy_sha256'],
        'ledger_before_file_sha256': digest(ledger_bytes),
        'ledger_before_canonical_sha256': digest(ledger), 'attempt_before_sha256': digest(row),
        'counted_attempts': len(ledger['attempts']), 'old_context_sha256': row['context_sha256'],
        'old_request_body_sha256': telemetry['wire_body_sha256'],
        'current_source_identity_sha256': current_source_identity_sha256, 'prepared_at': prepared_at,
        **json.loads(canonical(basis)),
    }
    if history:
        require(row.get('owner_operation_id') == basis['old_owner_operation_id']
                and row.get('run_id') == basis['old_run_id'], 'budget_recovery_old_operation_binding')
        require(type(prior_receipts) is list and len(prior_receipts) == len(history),
                'budget_recovery_prior_receipts')
        references = []
        for index, supplied in enumerate(prior_receipts):
            require(type(supplied) is dict and set(supplied) == {'reference', 'raw'}, 'budget_recovery_prior_receipts')
            references.append(_verify_receipt(supplied['raw'], supplied['reference'], ledger, history, index))
        if len(history) > 1:
            require(references[:-1] == history[-1]['prior_recovery_receipts'],
                    'budget_recovery_history_receipt_substitution')
        contract.update(prior_recovery_history_sha256=digest(history), prior_recovery_receipts=references)
    else:
        require(prior_receipts in (None, []), 'budget_recovery_unexpected_prior_receipt')
        if response_bound:
            contract.update(prior_recovery_history_sha256=digest([]), prior_recovery_receipts=[])
    contract['contract_id'] = 'radik-local-recovery:' + digest(contract)
    return validate_local_closed_recovery_contract(contract)


class TurnBudget:
    def __init__(self, path, policy_path):
        self.path = Path(path)
        self.policy_path = Path(policy_path)
        policy_bytes = self.policy_path.read_bytes()
        self.policy = json.loads(policy_bytes)
        console_profile = model_scope.scope_profile('console')
        selected_console_path = self.path.name == Path(console_profile['ledger']).name \
            or self.policy_path.name == Path(console_profile['policy']).name
        self.scope = 'console' if selected_console_path or self.policy.get('schema') == model_scope.CONSOLE_POLICY_VERSION else 'exam'
        self._console_operation, self._compare, self._task_round = None, None, None
        self._normal_operation = None
        self._task_transition = None
        self._activation = None
        if self.scope == 'console':
            project = self.path.parent.parent
            profile = model_scope.scope_profile('console')
            require(self.path.is_absolute() and self.policy_path.is_absolute()
                and self.path == project / profile['ledger'] and self.policy_path == project / profile['policy'],
                'budget_console_fixed_paths')
            model_scope.validate_console_policy(self.policy)
            state = model_scope.read_scope_state(project, 'console')
            require(state['state'] != 'NOT_ACTIVATED', 'budget_console_not_activated')
            self._activation = json.loads(model_scope.read_public(project, profile['activation']))
            if state.get('transition_sha256'):
                from . import task_budget as task_scope
                self._task_transition = json.loads(model_scope.read_public(project, task_scope.TRANSITION))
                task_scope.policy(project)
        else:
            require(self.policy.get('active') is True
                and type(self.policy['max_new_turn_attempts']) is int
                and 1 <= self.policy['max_new_turn_attempts'] <= 16
                and type(self.policy['max_active_requests']) is int
                and self.policy['max_active_requests'] == 1
                and self.policy['model'] == 'gpt-6.1-sol' and self.policy['effort'] == 'high'
                and self.policy['service_tier'] is None, 'model_policy_inactive_or_invalid')
        self.policy_sha256 = digest(policy_bytes)
        self._operation_binding = None

    @classmethod
    def for_scope(cls, project, scope, *, activation_binding=None, activate=False, owner_lock_fd=None):
        profile = model_scope.scope_profile(scope)
        project = Path(project).resolve(strict=True)
        if activate:
            require(scope == 'console' and type(activation_binding) is dict, 'budget_console_activation_intent')
            activate_console_scope(project, owner_lock_fd=owner_lock_fd, **activation_binding)
        else:
            require(activation_binding is None, 'budget_console_activation_intent')
        selected = cls(project / profile['ledger'], project / profile['policy'])
        require(selected.scope == scope, 'budget_scope_substitution')
        return selected

    def set_console_operation(self, owner_operation_id, run_id):
        """Bind one explicit interactive invocation; no state or request is made."""
        require(self.scope == 'console' and _operation(owner_operation_id) and _run(run_id),
            'budget_console_operation_binding')
        binding = dict(owner_operation_id=owner_operation_id, run_id=run_id)
        require(self._console_operation is None or self._console_operation == binding, 'budget_console_operation_binding')
        self._console_operation = binding

    def set_normal_operation(self, operation_ref):
        """Select the already durable fresh owner operation, never a recovery slot."""
        from . import normal_session
        require(self.scope=='console' and self._console_operation is not None
            and self._normal_operation is None and self._task_round is None,
            'budget_normal_operation_binding')
        value=normal_session._active_operation(self.path.parent.parent,operation_ref)
        require(all(value[key]==self._console_operation[key] for key in ('owner_operation_id','run_id')),
            'budget_normal_operation_binding')
        self._normal_operation=dict(operation_ref)

    def begin_compare(self, compare_id=None):
        """Open a manual zero-to-three O/A/C boundary, without reserving a turn."""
        require(self.scope == 'console' and self._console_operation is not None and self._compare is None,
            'budget_console_compare_not_explicit')
        require(self._task_transition is None, 'budget_legacy_compare_requires_task_intake')
        ledger = self.snapshot()
        require(ledger['active_attempt_id'] is None, 'budget_active_or_unknown_call')
        compare_id = compare_id or 'console-compare:' + uuid.uuid4().hex
        require(type(compare_id) is str and re.fullmatch('console-compare:[0-9a-f]{32}', compare_id)
            and all(row['compare_id'] != compare_id for row in ledger['attempts']), 'budget_console_compare_replay')
        self._compare = compare_id
        return compare_id

    def end_compare(self):
        require(self.scope == 'console' and self._compare is not None, 'budget_console_compare_not_explicit')
        compare_id, self._compare = self._compare, None
        return dict(compare_id=compare_id, **self.scope_status())

    def scope_status(self):
        return model_scope.read_scope_state(self.path.parent.parent, self.scope)

    def current_model_settings(self):
        """Read the current explicit setting; no request or state change occurs."""
        if self._task_transition is None:
            return dict(model=self.policy['model'], effort=self.policy['effort'],
                service_tier='default', settings_sha256=digest(self.policy))
        from . import task_budget as task_scope
        task_scope.read_state(self.path.parent.parent)
        _raw, value = task_scope.read_json(self.path.parent.parent, task_scope.SETTINGS)
        task_scope.validate_settings(value, self._task_transition['transition_sha256'])
        row = value['entries'][-1]
        return {key: row[key] for key in ('model', 'effort', 'service_tier')} | {
            'settings_sha256': row['entry_sha256']}

    def begin_task_round(self, *, task_id, profile, task_spec_sha256,
                         dependencies_sha256, round_id=None, max_attempts=3, operation_action=None,
                         mode=None, source_successor_ref=None):
        """Bind one explicit task round to its accepted finite dependencies."""
        from . import task_budget as task_scope
        require(self.scope == 'console' and self._task_transition is not None
            and self._console_operation is not None and self._task_round is None
            and self._compare is None, 'budget_task_round_not_explicit')
        binding = dict(task_id=task_id, round_id=round_id or 'task-round:' + uuid.uuid4().hex,
            profile=profile, task_spec_sha256=task_spec_sha256,
            dependencies_sha256=dependencies_sha256, max_attempts=max_attempts)
        ledger = self.snapshot()
        from . import console_continuation
        require(ledger['active_attempt_id'] is None, 'budget_active_or_unknown_call')
        existing = [row['round_binding'] for row in ledger['attempts'][3:]]
        require(all(row['round_id'] != binding['round_id'] for row in existing), 'budget_task_round_replay')
        if self._normal_operation is not None:
            from . import normal_session
            require(operation_action is None,'budget_normal_recovery_action_forbidden')
            # Validate the base before any durable command grant is created.
            check=dict(binding,max_attempts=3)
            console_continuation.validate_round_binding(check)
            binding=normal_session.prepare_round(self.path.parent.parent,ledger,binding,
                operation_ref=self._normal_operation,mode=mode or 'COLD',source_successor_ref=source_successor_ref)
        else:
            require(mode is None,'budget_normal_operation_required')
            require(ledger.get('version')!='radik.console_turn_ledger.v05','budget_normal_operation_required')
            binding = console_continuation.prepare_round(self.path.parent.parent, ledger, binding,
                **self._console_operation, operation_action=operation_action)
        require(binding.get('operation_allowance') is not None or binding.get('normal_round_scope') is not None or
            len({row['round_id'] for row in existing if row['task_id'] == task_id}) < 3,
            'budget_task_round_exhausted')
        self._task_round = binding
        return dict(binding)

    def validate_task_request(self, guard):
        """Bind exact emitted task meaning and sources to the active round."""
        require(self._task_round is not None and type(guard) is dict,
            'budget_task_round_not_explicit')
        require(all(guard.get(key) == self._task_round[key] for key in
            ('task_id', 'profile', 'task_spec_sha256', 'dependencies_sha256')),
            'budget_task_request_dependencies')
        if 'normal_round_scope' in self._task_round:
            from .normal_session import validate_round
            validate_round(self.path.parent.parent,self._task_round,current=True,for_dispatch=True)
        return True

    def abort_task_round_before_start(self):
        require(self._task_round is not None, 'budget_task_round_not_explicit')
        from .normal_profile import abort_before_start
        result=abort_before_start(self.path.parent.parent,self.snapshot(),self._task_round)
        self._task_round=None
        return result

    def end_task_round(self):
        require(self._task_round is not None, 'budget_task_round_not_explicit')
        if 'normal_round_scope' in self._task_round:
            from . import normal_session
            normal_session.finish_round(self.path.parent.parent,self.snapshot(),self._task_round)
        value, self._task_round = dict(self._task_round), None
        return dict(round_binding=value, **self.scope_status())

    def configure_console(self, *, model, effort):
        """Explicit configuration between completed rounds; no budget reset."""
        from . import task_budget as task_scope
        require(self._task_transition is not None and self._console_operation is not None
            and self._task_round is None and self._compare is None, 'budget_settings_round_active')
        require(model == 'gpt-6.1-sol' and effort in ('low', 'medium', 'high', 'xhigh', 'max'),
            'budget_settings_unsupported')
        def change(ledger):
            require(ledger['active_attempt_id'] is None, 'budget_active_or_unknown_call')
            project = self.path.parent.parent
            _raw, value = task_scope.read_json(project, task_scope.SETTINGS)
            task_scope.validate_settings(value, self._task_transition['transition_sha256'])
            previous = value['entries'][-1]
            if (previous['model'], previous['effort']) == (model, effort):
                return dict(previous)
            row = dict(sequence=len(value['entries']), model=model, effort=effort,
                service_tier='default', previous_sha256=previous['entry_sha256'], **self._console_operation)
            row['entry_sha256'] = digest(row)
            value['entries'].append(row); value['current_sha256'] = row['entry_sha256']
            task_scope.validate_settings(value, self._task_transition['transition_sha256'])
            path = model_scope.owned(project, task_scope.SETTINGS)
            pending = path.with_suffix('.pending')
            require(not pending.exists() and not pending.is_symlink(), 'budget_pending_write')
            fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
            os.replace(pending, path); task_scope._sync_directory(path.parent)
            return dict(row)
        return self._transaction(change)

    def _validate_ledger(self, ledger):
        if self.scope == 'console':
            if self._task_transition is not None:
                from . import task_budget as task_scope
                _raw, settings = task_scope.read_json(self.path.parent.parent, task_scope.SETTINGS)
                task_scope.validate_settings(settings, self._task_transition['transition_sha256'])
                task_scope.validate_ledger(self.path.parent.parent, ledger, self._task_transition, settings)
                return
            model_scope.validate_console_ledger(ledger, policy_sha256=self.policy_sha256,
                activation_sha256=self._activation['activation_sha256'])
            return
        _validate_ledger_material(ledger, policy_sha256=self.policy_sha256,
                                  max_attempts=self.policy['max_new_turn_attempts'])

    def _read_receipt(self, reference):
        """Read only a bounded owned public recovery receipt, never auth state."""
        _receipt_reference(reference)
        return self._read_public_reference(reference)

    def _read_public_reference(self, reference):
        require(type(reference) is dict and set(reference) == {'path', 'sha256'}
                and type(reference['path']) is str and reference['path'].startswith('review/')
                and reference['path'].endswith('.json') and not Path(reference['path']).is_absolute()
                and not set(Path(reference['path']).parts).intersection(
                    ('.', '..', 'private', 'Arena', 'arena', 'codex-home', '.venv-plan'))
                and _hash(reference['sha256']), 'budget_recovery_evidence_reference')
        project = self.path.parent.parent
        path = project / reference['path']
        for node in (path, *path.parents):
            require(not node.is_symlink(), 'budget_recovery_receipt_symlink')
            if node == project:
                break
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'budget_recovery_receipt_regular')
            raw = stream.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'budget_recovery_receipt_bound')
        return raw

    def _recheck_prior_receipts(self, ledger):
        history = _history(ledger)
        if len(history) < 2:
            return
        for index, reference in enumerate(history[-1]['prior_recovery_receipts']):
            plain_ref = {key: reference[key] for key in ('path', 'sha256')}
            checked = _verify_receipt(self._read_receipt(plain_ref), plain_ref, ledger, history, index)
            require(checked == reference, 'budget_recovery_history_receipt_substitution')

    def _transaction(self, change, *, expected_file_sha256=None, recovery_contract_sha256=None):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        require(not self.path.is_symlink() and not self.path.parent.is_symlink(), 'budget_symlink')
        lock_path = self.path.with_suffix('.lock')
        require(not lock_path.is_symlink(), 'budget_lock_symlink')
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock_fd, 'a+b') as lock:
            lock_info = os.fstat(lock.fileno())
            require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_nlink == 1, 'budget_lock_regular')
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if self.scope == 'console':
                model_scope.read_scope_state(self.path.parent.parent, 'console')
            raw = (model_scope.read_public(self.path.parent.parent, model_scope.scope_profile('console')['ledger'],
                cap=model_scope.MAX_CONSOLE_LEDGER_BYTES) if self.scope == 'console' else self.path.read_bytes()) if self.path.exists() else None
            require(self.scope != 'console' or raw is not None, 'budget_console_activated_ledger_missing')
            ledger = json.loads(raw) if raw is not None else {
                'version': 'radik.turn_ledger.v01', 'policy_sha256': self.policy_sha256,
                'attempts': [], 'active_attempt_id': None}
            self._validate_ledger(ledger)
            if recovery_contract_sha256 is not None:
                require(recovery_contract_sha256 not in [application['contract_sha256'] for application in _history(ledger)],
                        'budget_recovery_already_applied')
            if expected_file_sha256 is not None:
                require(raw is not None and digest(raw) == expected_file_sha256, 'budget_recovery_ledger_changed')
            result = change(ledger)
            if self.scope == 'console':
                ledger['ledger_sha256'] = digest({key: value for key, value in ledger.items() if key != 'ledger_sha256'})
            self._validate_ledger(ledger)
            temporary = self.path.with_suffix('.pending')
            require(not temporary.exists(), 'budget_pending_write')
            with temporary.open('xb') as stream:
                stream.write(canonical(ledger)); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            # Make the renamed reservation durable before a caller may dispatch.
            # A directory-fsync failure keeps the visible reservation and refuses
            # the call; it never refunds an ID or opens an automatic retry.
            parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            return result

    def reserve(self, *, role, context_sha256, purpose):
        require(role in ('boundary_probe', 'orchestrator', 'architect', 'critic',
                         'source_author', 'examiner'), 'budget_role')
        require(type(context_sha256) is str and len(context_sha256) == 64, 'budget_context_hash')
        require(self._task_round is None or self._task_round['max_attempts'] != 0,
            'budget_memory_only_provider_forbidden')
        def change(ledger):
            binding = {}
            if self.scope == 'console' and self._task_transition is not None:
                require(self._console_operation is not None and self._task_round is not None,
                    'budget_task_round_not_explicit')
                from . import console_continuation
                if 'normal_round_scope' in self._task_round:
                    from . import normal_session
                    grant=normal_session.validate_round(self.path.parent.parent,self._task_round,current=True,for_dispatch=True)
                    require(all(grant[key]==self._console_operation[key] for key in ('owner_operation_id','run_id')),
                        'budget_normal_operation_binding')
                else:
                    console_continuation.assert_reservation(self.path.parent.parent, ledger,
                        **self._console_operation, round_id=self._task_round['round_id'])
                current = [row for row in ledger['attempts'][3:]
                    if row['round_binding']['round_id'] == self._task_round['round_id']]
                require(len(current) < self._task_round['max_attempts']
                    and role == ('orchestrator', 'architect', 'critic')[len(current)]
                    and all(row['outcome'] == 'COMPLETED' for row in current), 'budget_task_round_dependencies')
                settings = self.current_model_settings()
                binding = dict(self._console_operation, round_binding=dict(self._task_round), round_index=len(current),
                    previous_attempt_sha256=digest(ledger['attempts'][-1]),
                    settings_sha256=settings['settings_sha256'])
            elif self.scope == 'console':
                require(self._console_operation is not None and self._compare is not None,
                    'budget_console_compare_not_explicit')
                current = [row for row in ledger['attempts'] if row['compare_id'] == self._compare]
                require(len(current) < 3 and role == ('orchestrator', 'architect', 'critic')[len(current)]
                    and all(row['outcome'] == 'COMPLETED' for row in current), 'budget_console_compare_limit')
                binding = dict(self._console_operation, compare_id=self._compare, compare_index=len(current),
                    previous_attempt_sha256=digest(ledger['attempts'][-1]) if ledger['attempts'] else None)
            elif ledger['version'] != 'radik.turn_ledger.v01':
                history = _history(ledger)
                recovered = history[-1]
                require(self._operation_binding is not None
                        and self._operation_binding['owner_operation_id'] == recovered['owner_operation_id']
                        and self._operation_binding['recovery_contract_sha256'] == recovered['contract_sha256']
                        and self._operation_binding['run_id'] != recovered['old_run_id'],
                        'budget_recovered_operation_binding_required')
                require(context_sha256 not in [application['old_context_sha256'] for application in history],
                        'budget_recovered_old_request_replay')
                if ledger['version'] == 'radik.turn_ledger.v03':
                    self._recheck_prior_receipts(ledger)
                    current_ref = self._operation_binding.get('owner_receipt_ref')
                    _verify_receipt(self._read_receipt(current_ref), current_ref, ledger, history, len(history) - 1)
                binding = dict(self._operation_binding)
            require(ledger['active_attempt_id'] is None, 'budget_active_or_unknown_call')
            require(len(ledger['attempts']) < self.policy['max_new_turn_attempts'], 'budget_exhausted')
            attempt = 'radik-call:' + uuid.uuid4().hex
            selected = self.current_model_settings()
            ledger['attempts'].append({'attempt_id': attempt, 'role': role,
                'context_sha256': context_sha256, 'purpose': purpose, 'started_at': int(time.time()),
                'requested_model': selected['model'], 'requested_effort': selected['effort'],
                'requested_service_tier': self.policy['service_tier'], 'outcome': 'PENDING',
                'usage': 'UNKNOWN', 'served_model': 'UNKNOWN', **binding})
            ledger['active_attempt_id'] = attempt
            return attempt
        return self._transaction(change)

    def set_operation_binding(self, owner_operation_id, run_id, contract_sha256, *, receipt_ref=None):
        """Bind one fresh owner run in memory; no ledger or network operation."""
        require(self.scope == 'exam' and _operation(owner_operation_id) and _run(run_id) and _hash(contract_sha256),
                'budget_operation_binding_shape')
        binding = {'owner_operation_id': owner_operation_id, 'run_id': run_id,
                   'recovery_contract_sha256': contract_sha256}
        if receipt_ref is not None:
            _receipt_reference(receipt_ref)
            binding['owner_receipt_ref'] = json.loads(canonical(receipt_ref))
        require(self._operation_binding is None or self._operation_binding == binding,
                'budget_operation_binding_already_set')
        self._operation_binding = binding

    def apply_local_closed_recovery(self, contract_bytes, *, expected_contract_sha256,
                                    current_source_identity_sha256, owner_operation_id, applied_at):
        """Explicit reviewed owner action; never called by preparation or retry.

        The owner entrypoint first verifies independent approval, exact evidence,
        no-effect/current quota and the qualified permission under its own lock.
        This transaction rechecks the exact ledger and preserves every old row.
        No server completion/cancellation, refund, new grant or reset is claimed.
        """
        require(self.scope == 'exam', 'budget_console_recovery_not_admitted')
        require(type(contract_bytes) is bytes and len(contract_bytes) <= 65536
                and _hash(expected_contract_sha256) and digest(contract_bytes) == expected_contract_sha256,
                'budget_recovery_contract_pin')
        contract = validate_local_closed_recovery_contract(json.loads(contract_bytes))
        require(contract_bytes == canonical(contract) + b'\n', 'budget_recovery_canonical_contract')
        require(current_source_identity_sha256 == contract['current_source_identity_sha256']
                and contract['policy_sha256'] == self.policy_sha256, 'budget_recovery_current_source_or_policy')
        require(_operation(owner_operation_id) and owner_operation_id != contract['old_owner_operation_id']
                and type(applied_at) is int and applied_at >= contract['prepared_at'], 'budget_recovery_new_operation')
        def change(ledger):
            history = _history(ledger)
            require(contract['attempt_id'] not in [application['attempt_id'] for application in history]
                    and owner_operation_id not in [application['owner_operation_id'] for application in history],
                    'budget_recovery_history_duplicate')
            require(digest(ledger) == contract['ledger_before_canonical_sha256']
                    and len(ledger['attempts']) == contract['counted_attempts']
                    and ledger['active_attempt_id'] == contract['attempt_id'], 'budget_recovery_current_ledger')
            row = next(item for item in ledger['attempts'] if item['attempt_id'] == contract['attempt_id'])
            require(row['outcome'] == 'UNKNOWN' and digest(row) == contract['attempt_before_sha256']
                    and row['context_sha256'] == contract['old_context_sha256']
                    and row.get('telemetry', {}).get('wire_body_sha256') == contract['old_request_body_sha256'],
                    'budget_recovery_current_attempt')
            require(row.get('telemetry', {}).get('response_id') == contract['local_cleanup']['response_id'],
                    'budget_recovery_response_identity_mismatch')
            response_bound = contract['version'] == RECOVERY_RESPONSE_VERSION
            if response_bound:
                reference = contract['evidence_refs']['transport_observation']
                _transport_identity(self._read_public_reference(reference), reference, row, contract['local_cleanup'])
            if history:
                require(contract['version'] in (RECOVERY_HISTORY_VERSION, RECOVERY_RESPONSE_VERSION)
                        and contract['prior_recovery_history_sha256'] == digest(history)
                        and len(contract['prior_recovery_receipts']) == len(history),
                        'budget_recovery_history_predecessor')
                self._recheck_prior_receipts(ledger)
                for index, reference in enumerate(contract['prior_recovery_receipts']):
                    plain_ref = {key: reference[key] for key in ('path', 'sha256')}
                    checked = _verify_receipt(self._read_receipt(plain_ref), plain_ref, ledger, history, index)
                    require(checked == reference, 'budget_recovery_history_receipt_substitution')
                require(row.get('owner_operation_id') == contract['old_owner_operation_id']
                        and row.get('run_id') == contract['old_run_id'], 'budget_recovery_old_operation_binding')
            else:
                require(contract['version'] in (RECOVERY_VERSION, RECOVERY_RESPONSE_VERSION),
                        'budget_recovery_history_predecessor')
            application = {'version': ('radik.local_request_recovery_application.v03' if response_bound else
                                      'radik.local_request_recovery_application.v02' if history
                                      else 'radik.local_request_recovery_application.v01'),
                'disposition': RECOVERY_DISPOSITION, 'occupancy_contract': OCCUPANCY_CONTRACT,
                'contract_sha256': expected_contract_sha256, 'contract_id': contract['contract_id'],
                'owner_operation_id': owner_operation_id, 'applied_at': applied_at,
                **{key: contract[key] for key in ('attempt_id', 'attempt_before_sha256', 'old_context_sha256',
                    'old_run_id', 'ledger_before_file_sha256', 'ledger_before_canonical_sha256',
                    'counted_attempts', 'current_source_identity_sha256')}}
            if history or response_bound:
                application.update(prior_ledger_version=ledger['version'],
                    prior_recovery_history_sha256=contract['prior_recovery_history_sha256'],
                    prior_recovery_receipts=json.loads(canonical(contract['prior_recovery_receipts'])))
                if response_bound:
                    application.update(response_id=contract['local_cleanup']['response_id'],
                        transport_observation_ref=dict(contract['evidence_refs']['transport_observation']))
                ledger.update(version='radik.turn_ledger.v03', recovery_history=[*history, application],
                              active_attempt_id=None, local_occupancy_contract=OCCUPANCY_CONTRACT,
                              local_recovery=ledger['local_recovery'] if history else application)
            else:
                ledger.update(version='radik.turn_ledger.v02', local_occupancy_contract=OCCUPANCY_CONTRACT,
                              local_recovery=application, active_attempt_id=None)
            return {'version': ('radik.local_request_recovery_receipt.v03' if response_bound else
                                'radik.local_request_recovery_receipt.v02' if history
                                else 'radik.local_request_recovery_receipt.v01'), 'application': dict(application),
                'ledger_after_sha256': digest(ledger), 'old_outcome': 'UNKNOWN',
                'old_usage': row['usage'], 'counted_attempts': len(ledger['attempts']),
                'remote_completion_or_cancellation': 'NOT_OBSERVED_NOT_CLAIMED'}
        return self._transaction(change, expected_file_sha256=contract['ledger_before_file_sha256'],
                                 recovery_contract_sha256=expected_contract_sha256)

    def finish(self, attempt_id, *, outcome, usage, telemetry=None):
        require(outcome in ('COMPLETED', 'FAILED', 'DENIED', 'CANCELLED', 'TIMED_OUT', 'UNKNOWN'),
                'budget_terminal_outcome')
        def change(ledger):
            require(ledger['active_attempt_id'] == attempt_id, 'budget_finish_identity')
            row = next(x for x in ledger['attempts'] if x['attempt_id'] == attempt_id)
            row.update(outcome=outcome, usage=usage if usage is not None else 'UNKNOWN',
                       finished_at=int(time.time()), telemetry=telemetry or {})
            if outcome != 'UNKNOWN':
                require((telemetry or {}).get('terminal_observed') is True
                        or ((telemetry or {}).get('own_process_finished') is True
                            and (telemetry or {}).get('turn_not_started') is True),
                        'budget_terminal_evidence')
                ledger['active_attempt_id'] = None
            return dict(row)
        return self._transaction(change)

    def snapshot(self):
        if self.scope == 'console':
            model_scope.read_scope_state(self.path.parent.parent, 'console')
            value = json.loads(model_scope.read_public(self.path.parent.parent, model_scope.scope_profile('console')['ledger'],
                cap=model_scope.MAX_CONSOLE_LEDGER_BYTES))
            self._validate_ledger(value)
            return value
        return self._transaction(lambda ledger: json.loads(canonical(ledger)))


def activate_console_scope(project, *, owner_lock_fd, owner_operation_id, run_id,
                           source_identity_sha256, actual_acceptance_ref, exam_ledger_sha256, quota_sha256):
    """One explicit future owner activation; existing state is never reset.

    The owner source/admission flow supplies the reviewed intent and keeps its
    existing lock across this call and the interactive session. This function
    performs no AUTH, catalog, provider, native Work or effect operation.
    """
    project = Path(project).resolve(strict=True)
    require(all(model_scope.owned(project, name).exists() for name in (
        'state/console_budget_activation.json', 'state/console_model_turns.json',
        'state/console_stage04_transition.json', 'state/console_stage04_committed.json')),
        'budget_console_prior_state_required')
    require(_operation(owner_operation_id) and _run(run_id) and _hash(source_identity_sha256)
        and _hash(exam_ledger_sha256) and _hash(quota_sha256), 'budget_console_activation_binding')
    require(type(owner_lock_fd) is int and owner_lock_fd >= 0, 'budget_console_owner_lock')
    lock_path = model_scope.owned(project, model_scope.OWNER_LOCK_PATH)
    lock_info, path_info = os.fstat(owner_lock_fd), lock_path.stat()
    require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_nlink == 1
        and stat.S_IMODE(lock_info.st_mode) == 0o600 and lock_info.st_uid == os.getuid()
        and (lock_info.st_dev, lock_info.st_ino) == (path_info.st_dev, path_info.st_ino), 'budget_console_owner_lock')
    fcntl.flock(owner_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    require(type(actual_acceptance_ref) is dict and set(actual_acceptance_ref) == {'path', 'sha256'}
        and actual_acceptance_ref['path'] == model_scope.ACCEPTANCE_PATH and _hash(actual_acceptance_ref['sha256']),
        'budget_console_acceptance_basis')
    exam = TurnBudget.for_scope(project, 'exam')
    exam_raw = model_scope.read_public(project, model_scope.scope_profile('exam')['ledger'])
    ledger = json.loads(exam_raw)
    exam._validate_ledger(ledger)
    require(digest(exam_raw) == exam_ledger_sha256 and len(ledger['attempts']) == 16
        and ledger['active_attempt_id'] is None and len(_history(ledger)) == 5, 'budget_console_exam_basis')
    receipts = []
    for index, application in enumerate(_history(ledger)):
        path = 'review/direct_plan_passage/local_unknown_recovery_' + application['owner_operation_id'] + '.json'
        raw = model_scope.read_public(project, path)
        reference = dict(path=path, sha256=digest(raw))
        if index + 1 < len(_history(ledger)):
            expected = {key: _history(ledger)[index + 1]['prior_recovery_receipts'][index][key] for key in ('path', 'sha256')}
        else:
            latest_rows = ledger['attempts'][application['counted_attempts']:]
            require(latest_rows and all(row.get('owner_receipt_ref') == latest_rows[0].get('owner_receipt_ref')
                for row in latest_rows), 'budget_console_recovery_basis')
            expected = latest_rows[0]['owner_receipt_ref']
        require(reference == expected, 'budget_console_recovery_basis')
        _verify_receipt(raw, reference, ledger, _history(ledger), index)
        receipts.append(reference)
    quota_raw = model_scope.read_public(project, model_scope.QUOTA_PATH, cap=65536)
    quota = model_scope.validate_closed_quota(quota_raw)
    require(digest(quota_raw) == quota_sha256, 'budget_console_quota_basis')
    acceptance_raw = model_scope.read_public(project, model_scope.ACCEPTANCE_PATH)
    acceptance = json.loads(acceptance_raw)
    require(digest(acceptance_raw) == actual_acceptance_ref['sha256']
        and acceptance.get('schema') == 'radik.independent.actual_business_chain_acceptance.v01'
        and acceptance.get('reviewer') == '/root/semantic_continuation_reviewer'
        and acceptance.get('status') == 'ACTUAL_BUSINESS_CHAIN_ACCEPTED_WITH_LATE_NEGATIVE_FAILURE'
        and acceptance.get('scope') == 'ACTUAL_F2902C1EF6C5_FIXED_TWO_DOCUMENT_OWNED_REFERENCE_SAVE_ONLY'
        and acceptance['consumed_permission']['actual_effect_policy'] == 'CLOSED_REVISION2'
        and acceptance['consumed_permission']['repeat_or_new_SAVE_authority'] is False
        and acceptance['observed_business_results']['SAVE']['raw_quota_state'] == 'CLOSED'
        and acceptance['evidence_pins'][model_scope.scope_profile('exam')['ledger']] == exam_ledger_sha256
        and acceptance['evidence_pins'][model_scope.QUOTA_PATH] == quota_sha256
        and acceptance['ledger']['canonical_after_sha256'] == digest(ledger)
        and quota[0]['details']['grant']['target'] == 'accepted_live_' + acceptance['run_id'] + '.txt'
        and quota[0]['details']['grant']['result_id'] == acceptance['observed_business_results']['delta']['result_id']
        and quota[-1]['details']['receipt']['receipt_id'] == acceptance['observed_business_results']['SAVE']['receipt_id']
        and quota[-1]['details']['receipt']['readback_sha256'] == acceptance['observed_business_results']['SAVE']['readback_sha256'],
        'budget_console_acceptance_basis')
    profile = model_scope.scope_profile('console')
    policy_raw = model_scope.read_public(project, profile['policy'])
    model_scope.validate_console_policy(json.loads(policy_raw))
    activation_path, ledger_path = model_scope.owned(project, profile['activation']), model_scope.owned(project, profile['ledger'])
    if activation_path.exists():
        state = model_scope.read_scope_state(project, 'console')
        existing = json.loads(model_scope.read_public(project, profile['activation']))
        require(existing['source_identity_sha256'] == source_identity_sha256
            and existing['actual_acceptance'] == actual_acceptance_ref
            and existing['exam_ledger']['sha256'] == exam_ledger_sha256
            and existing['consumed_save_quota']['sha256'] == quota_sha256, 'budget_console_activation_changed')
        require(state['active_attempt_id'] is None, 'budget_active_or_unknown_call')
        return existing
    require(not ledger_path.exists() and not ledger_path.with_suffix('.lock').exists()
        and not ledger_path.with_suffix('.pending').exists(), 'budget_console_existing_state_no_reset')
    activation = dict(schema=model_scope.CONSOLE_ACTIVATION_VERSION, scope='console', policy_sha256=digest(policy_raw),
        creator_owner_operation_id=owner_operation_id, creator_run_id=run_id, source_identity_sha256=source_identity_sha256,
        activated_at=int(time.time()), exam_ledger=dict(path=model_scope.scope_profile('exam')['ledger'], sha256=exam_ledger_sha256,
            canonical_sha256=digest(ledger), counted=16, active_attempt_id=None), exam_recovery_history_sha256=digest(_history(ledger)),
        exam_receipts=receipts, actual_acceptance=dict(actual_acceptance_ref),
        consumed_save_quota=dict(path=model_scope.QUOTA_PATH, sha256=quota_sha256,
            head_sha256=quota[-1]['record_sha256'], state='CLOSED'))
    activation['activation_sha256'] = digest(activation)
    model_scope.validate_console_activation(activation, policy_sha256=digest(policy_raw))
    new_ledger = dict(version=model_scope.CONSOLE_LEDGER_VERSION, scope='console', policy_sha256=digest(policy_raw),
        activation_sha256=activation['activation_sha256'], attempts=[], active_attempt_id=None)
    new_ledger['ledger_sha256'] = digest(new_ledger)
    model_scope.validate_console_ledger(new_ledger, policy_sha256=digest(policy_raw), activation_sha256=activation['activation_sha256'])
    for path, value in ((activation_path, activation), (ledger_path, new_ledger)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    model_scope.read_scope_state(project, 'console')
    return activation
