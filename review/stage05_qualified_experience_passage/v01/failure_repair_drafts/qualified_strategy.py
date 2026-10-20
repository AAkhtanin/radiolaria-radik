"""Bounded document checks allocated by the public G4 numeric profile.

This is an application adapter, not the Airline G42 consumer or a strategic
equilibrium claim. Two actual local Roots review their separate responsibilities.
The native Host accounts for one source gate, seven checks and one consumer.
No provider, action packet, model training, external truth or speedup is implied.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import time

from hedgehog import action_commit_packet_v02 as action
from hedgehog import work_execution_host_v01 as hosts
from hedgehog.gate4_reference_contracts_v01 import (
    G4_REFERENCE_NUMERIC_V01, G4_REFERENCE_SCOPE_V01, NUMERIC_HASH, UTILITY_HASH,
    Q, checked, digest as g4_digest,
)
from hedgehog.gate4_pressure_budget_v01 import (
    evaluate_reference_pressure_v01, allocate_reference_work_budget_v01,
    validate_reference_allocation_v01,
)
from hedgehog.kernel import abi_v01 as abi, effect_firewall_v01 as firewall
from hedgehog.kernel import work_composition_v01 as work

from . import native_authority as authority
from .contracts import canonical, digest, require

PROFILE = 'radik.qualified.document_allocation.v01'
TOTAL_UNITS = 9
DISCRETIONARY_UNITS = 7
BRANCHES = ('quotation', 'qualification')
QUANTA = {
    'quotation': ('source_hash', 'claim_byte_bounds', 'claim_utf8_bytes',
                  'source_coverage', 'duplicate_spans', 'claim_budget'),
    'qualification': ('uncertainty_text', 'unknown_markers', 'exception_markers',
                      'absolute_word_audit', 'condition_markers', 'claim_kind_inventory'),
}
SOURCE_OPERATION = 'radik.qualified.source_gate.v01'
CHECK_OPERATION = 'radik.qualified.check.v01'
FINAL_OPERATION = 'radik.qualified.consume.v01'

NATIVE_STAGES = (
    'G4_BOOTSTRAP_ADVANCE', 'G4_BOOTSTRAP_ARTIFACT', 'G4_HISTORY',
    'G4_ALLOCATION', 'G4_TASK_ROOT', 'G4_REVISION', 'G4_PRE_DISPATCH_PERSISTENCE',
    'G4_ALLOCATED_ADVANCE', 'G4_ALLOCATED_ARTIFACT', 'G4_FINAL_CHECKS', 'G4_CUSTODY',
)


@contextmanager
def _native_stage(stage):
    """Attach the first bounded native boundary without replacing the error."""
    try:
        yield
    except BaseException as error:
        if getattr(error, '_radik_stage05_native_stage', None) not in NATIVE_STAGES:
            error._radik_stage05_native_stage = stage
        raise


def _lid(kind, value):
    return 'g4_reference:' + kind + ':' + digest(value)


def _copy(value):
    return json.loads(canonical(value))


def _history(controller, selection):
    from .qualified_experience import validate_strategy_history
    value = validate_strategy_history(controller, selection)
    require(value['disposition'] in ('QUALIFIED_CURRENT_HISTORY', 'COLD_OR_NONMATCHING'),
            'qualified_g3_history_disposition')
    return dict(prior_fp=value['prior_fp'], disposition='USABLE' if value['disposition'] ==
        'QUALIFIED_CURRENT_HISTORY' else 'ABSENT', history_ref=value['history_ref'],
        custody_root_id=value['custody_root_id'], custody_review=authority.root_plain(value['custody_review']),
        source_scope_sha256=value['source_scope_sha256'], valid_to=value['valid_to'],
        selected_operation=value['selected_operation'], consumed_work_ref=value['consumed_work_ref'])


def _source_material(controller):
    sources = controller.current()
    require(controller.accepted is not None and controller.accepted.controller is controller,
            'qualified_accepted_live_controller_required')
    controller.validate_native()
    require(controller.accepted.plain['proposal'] == controller.candidate,
            'qualified_accepted_proposal_changed')
    return dict(task=controller.spec.plain(), sources=_copy(sources),
                candidate=_copy(controller.candidate),
                accepted_result_id=controller.accepted.plain['result_id'],
                accepted_result_sha256=controller.accepted.plain['result_sha256'])


def _source_gate(material):
    require(type(material) is dict and set(material) == {'task', 'sources', 'candidate',
        'accepted_result_id', 'accepted_result_sha256'}, 'qualified_source_material')
    sources, candidate = material['sources'], material['candidate']
    require(type(sources) is list and 1 <= len(sources) <= 4 and type(candidate) is dict,
            'qualified_source_bound')
    require(candidate['task_id'] == material['task']['task_id'], 'qualified_source_task')
    refs = [row['source_ref'] for row in sources]
    require(len(set(refs)) == len(refs) and set(refs) == set(material['task']['source_ids']),
            'qualified_source_scope')
    for row in sources:
        require(type(row['text']) is str and 0 < len(row['text'].encode('utf-8')) <= 16384
                and digest(row['text'].encode('utf-8')) == row['sha256'], 'qualified_source_bytes')
    claims = candidate['claims']
    require(type(claims) is list and 1 <= len(claims) <= 8, 'qualified_claim_bound')
    for claim in claims:
        source = next((row for row in sources if row['source_ref'] == claim['source_ref']), None)
        require(source is not None and all(claim[key] == source[key]
            for key in ('source_ref', 'revision', 'sha256')), 'qualified_claim_source')
    return dict(profile=PROFILE, material_sha256=digest(material),
                source_scope_sha256=digest(sorted([{key: row[key] for key in ('source_ref', 'revision', 'sha256')}
                    for row in sources], key=lambda row: row['source_ref'])), source_count=len(sources), claim_count=len(claims))


def _check(material):
    require(type(material) is dict and set(material) == {'source', 'branch', 'ordinal'},
            'qualified_quantum_shape')
    source = material['source']
    _source_gate(source)
    branch, ordinal = material['branch'], material['ordinal']
    require(branch in BRANCHES and type(ordinal) is int and 1 <= ordinal <= 6,
            'qualified_quantum_scope')
    name = QUANTA[branch][ordinal - 1]
    sources, candidate = source['sources'], source['candidate']
    claims = candidate['claims']
    by_ref = {row['source_ref']: row for row in sources}
    if name == 'source_hash':
        finding = [{'source_ref': row['source_ref'], 'sha256': digest(row['text'].encode('utf-8'))}
                   for row in sources]
    elif name == 'claim_byte_bounds':
        finding = [{'claim': index, 'valid': type(row['start']) is type(row['end']) is int
            and 0 <= row['start'] < row['end'] <= len(by_ref[row['source_ref']]['text'].encode('utf-8'))}
            for index, row in enumerate(claims)]
        require(all(row['valid'] for row in finding), 'qualified_claim_span')
    elif name == 'claim_utf8_bytes':
        finding = [{'claim': index, 'exact': by_ref[row['source_ref']]['text'].encode('utf-8')
                    [row['start']:row['end']].decode('utf-8') == row['quote']}
                   for index, row in enumerate(claims)]
        require(all(row['exact'] for row in finding), 'qualified_claim_quote')
    elif name == 'source_coverage':
        finding = [{'source_ref': row['source_ref'], 'cited': any(
            claim['source_ref'] == row['source_ref'] for claim in claims)} for row in sources]
        require(all(row['cited'] for row in finding), 'qualified_claim_coverage')
    elif name == 'duplicate_spans':
        keys = [(row['source_ref'], row['start'], row['end'], row['kind']) for row in claims]
        finding = dict(distinct=len(set(keys)), total=len(keys))
        require(finding['distinct'] == finding['total'], 'qualified_duplicate_span')
    elif name == 'claim_budget':
        finding = dict(claim_count=len(claims), quote_bytes=sum(len(row['quote'].encode('utf-8')) for row in claims))
        require(all(len(row['quote'].encode('utf-8')) <= 2048 for row in claims), 'qualified_quote_budget')
    elif name == 'uncertainty_text':
        finding = dict(nonempty=bool(candidate['uncertainty'].strip()),
                       sha256=digest(candidate['uncertainty'].encode('utf-8')))
        require(finding['nonempty'], 'qualified_uncertainty_missing')
    elif name in ('unknown_markers', 'exception_markers', 'condition_markers'):
        markers = {'unknown_markers': ('unknown', 'uncertain', 'unverified', 'not established'),
                   'exception_markers': ('except', 'unless', 'exception'),
                   'condition_markers': ('if ', 'only when', 'provided that')}[name]
        finding = [{'source_ref': row['source_ref'], 'markers': [marker for marker in markers
                    if marker in row['text'].lower()]} for row in sources]
    elif name == 'absolute_word_audit':
        markers = ('always', 'never', 'guaranteed', 'certainly', 'proven')
        finding = dict(statement_markers=[marker for marker in markers if marker in candidate['statement'].lower()],
            source_qualifications=[row['source_ref'] for row in sources
                if any(marker in row['text'].lower() for marker in ('unknown', 'uncertain', 'except', 'unless'))],
            disposition='ADDITIONAL_REVIEW_IF_ABSOLUTE_STATEMENT_AND_SOURCE_QUALIFICATION')
        finding['additional_review_required'] = bool(finding['statement_markers'] and finding['source_qualifications'])
    else:
        require(name == 'claim_kind_inventory', 'qualified_unknown_check')
        finding = {kind: sum(row['kind'] == kind for row in claims)
                   for kind in ('support', 'contradiction', 'condition', 'exception', 'unknown')}
    return dict(profile=PROFILE, branch=branch, ordinal=ordinal, check=name,
                material_sha256=digest(material), finding=finding)


def derive_budget(basis):
    """Project original enrolled policy and usage; never accept a caller score."""
    require(type(basis) is dict and set(basis) == {'profile', 'source', 'history', 'policy',
        'usage', 'envelope', 'source_context', 'owner_root', 'custody_root', 'task_id',
        'transaction_id', 'evaluation_time', 'definitions'}, 'qualified_budget_basis')
    require(basis['profile'] == PROFILE and basis['owner_root'] != basis['custody_root'],
            'qualified_actual_distinct_roots')
    policy, usage, history = basis['policy'], basis['usage'], basis['history']
    require(policy['task_id'] == basis['task_id'] and policy['owning_root_id'] == basis['owner_root']
            and policy['max_compute_units'] == TOTAL_UNITS and policy['max_model_calls'] == 0
            and policy['max_children'] == 0, 'qualified_original_native_policy')
    require(usage['policy'] == policy and usage['usage']['compute_units'] == 1,
            'qualified_original_native_usage')
    require(history['custody_root_id'] == basis['custody_root'] and history['disposition'] in
            ('USABLE', 'ABSENT', 'EXPIRED', 'NONMATCHING'), 'qualified_history_disposition')
    require(type(history['prior_fp']) is int and -Q <= history['prior_fp'] <= Q
            and (history['disposition'] == 'USABLE' or history['prior_fp'] == 0), 'qualified_raw_prior')
    source_gate = _source_gate(basis['source'])
    require(history['source_scope_sha256'] == source_gate['source_scope_sha256'], 'qualified_history_scope')
    owners = sorted(_lid('root', root) for root in (basis['owner_root'], basis['custody_root']))
    ctx = dict(profile=G4_REFERENCE_NUMERIC_V01, scope=G4_REFERENCE_SCOPE_V01, schema='g4_reference:v01',
        evaluation_id=_lid('evaluation', basis), domain_id='g4_reference:radik:document_checks',
        owner_root_id=_lid('root', basis['owner_root']), task_id=_lid('task', basis['task_id']),
        transaction_id=_lid('transaction', basis['transaction_id']), intent_ref=_lid('intent', policy['intent_ref']),
        bsep_ref=_lid('bsep', basis['source_context']['bsep_packet']['packet_id']), participants=owners,
        evaluation_time=basis['evaluation_time'], time_envelope_ref=_lid('time', basis['envelope']),
        source_snapshot_ref=_lid('original', basis['source']), source_snapshot_hash='0' * 64,
        candidate_set_ref=_lid('inventory', QUANTA), candidate_set_hash='0' * 64,
        policy_ref=_lid('policy', policy), policy_hash='0' * 64,
        utility_profile_ref='g4_reference:utility:v01', utility_profile_hash=UTILITY_HASH,
        numeric_profile_ref='g4_reference:numeric:v01', numeric_profile_hash=NUMERIC_HASH,
        dependencies=[_lid('source', basis['source']), _lid('history', history)],
        catalogue_revision='g4_reference:catalogue:0', origin='NATIVE_SOURCE_BOUND_G42_V01',
        dispositions=[dict(id='g4_reference:current', state='KNOWN', source_ref=_lid('basis', basis))],
        native_binding=dict(profile='G42_ORIGINAL_AND_PROJECTION_BINDING_V01', basis_sha256=digest(basis),
            original_snapshot_sha256=digest(basis['source']), original_policy_sha256=digest(policy),
            original_usage_sha256=digest(usage), original_envelope_sha256=digest(basis['envelope']),
            id_mapping_sha256=digest(dict(owner=basis['owner_root'], custody=basis['custody_root'], task=basis['task_id']))))
    ctx['policy_hash'] = g4_digest(dict(total=policy['max_compute_units'], policy_ref=ctx['policy_ref'],
        owner_root_id=ctx['owner_root_id'], task_id=ctx['task_id']))
    branches = []
    for branch in (*BRANCHES, 'external_unapproved'):
        excluded = branch == 'external_unapproved'
        row = dict(id=_lid('branch', branch), material_ref=_lid('material', dict(branch=branch, source=basis['source'])),
            catalogue_revision=ctx['catalogue_revision'], eligible='FALSE' if excluded else 'TRUE', available='TRUE',
            lower=0 if excluded else 2, upper=6,
            hard=[dict(id='g4_reference:hard:approved_source', state='FALSE' if excluded else 'TRUE',
                       evidence_ref=_lid('current_intake', basis['source']))])
        for key, value in dict(relevance=800000000, lineage=800000000, uncertainty=500000000,
                              cost=400000000 if branch == 'quotation' else 430000000).items():
            row[key] = dict(value=(0 if key in ('uncertainty', 'cost') else Q) if excluded else value,
                source_ref=_lid('configured', (branch, key, value)), normalization='FIXED_Q_0_1',
                interpretation='Prospectively fixed inspection relevance, lineage, uncertainty and dispatch cost; not probabilities.')
        used = branch == 'quotation' and history['disposition'] == 'USABLE'
        row['prior'] = dict(value=history['prior_fp'] if used else 0,
            source_ref=_lid('prior', history if used else branch), disposition='USABLE' if used else 'ABSENT',
            normalization='FIXED_Q_SIGNED', interpretation='Raw current G3 prior once; excluded branch has maximal configured features and no invented history.')
        branches.append(row)
    pressure = checked('pressure_input', dict(context=ctx, branches=branches))
    pressure['context']['source_snapshot_hash'] = g4_digest(pressure['branches'])
    pressure['context']['candidate_set_hash'] = g4_digest([row['id'] for row in pressure['branches']])
    ctx = pressure['context']
    return checked('budget', dict(context=ctx, id=_lid('budget', basis), original_policy_ref=ctx['policy_ref'],
        original_policy_hash=ctx['policy_hash'], total=policy['max_compute_units'], spent=usage['usage']['compute_units'],
        host_revision=usage['host_revision'], spending_snapshot_ref=_lid('spending', usage),
        spending_snapshot_hash=g4_digest(dict(spent=usage['usage']['compute_units'], host_revision=usage['host_revision'],
            owner_root_id=ctx['owner_root_id'], task_id=ctx['task_id'], transaction_id=ctx['transaction_id'])),
        mandatory=[dict(id='g4_reference:mandatory:consumer', count=1, kind='FINAL_CONSUMER',
            definition_ref=_lid('definition', basis['definitions']['consumer']), material_ref=_lid('basis', basis),
            material_sha256=digest(basis), source_ref=_lid('proposal', basis['source']), catalogue_revision=ctx['catalogue_revision'])],
        pressure_inputs=pressure))


def _allocation(basis):
    budget = derive_budget(basis)
    pressure = evaluate_reference_pressure_v01(budget['pressure_inputs'], profile=G4_REFERENCE_NUMERIC_V01)
    allocation = allocate_reference_work_budget_v01(pressure, current_budget_context=budget).plain()
    require(allocation['status'] == 'ALLOCATED' and allocation['target'] == DISCRETIONARY_UNITS,
            'qualified_allocation_not_ready')
    return budget, allocation


def _selected(allocation):
    counts = {row['id']: row['allocation'] for row in allocation['rows']}
    return [(branch, ordinal) for branch in BRANCHES for ordinal in range(1, counts.get(_lid('branch', branch), 0) + 1)]


def _consume(data):
    basis, proof = data['material'], data['allocation_proof']
    require(type(proof) is dict and set(proof) == {'budget', 'allocation'}, 'qualified_consumer_material')
    expected = derive_budget(basis)
    require(proof['budget'] == expected, 'qualified_consumer_original_budget')
    allocation = validate_reference_allocation_v01(proof['allocation'], inputs=expected['pressure_inputs'],
        current_budget_context=expected).plain()
    require(allocation['status'] == 'ALLOCATED', 'qualified_consumer_allocation_status')
    selected = _selected(allocation)
    require(len(selected) == DISCRETIONARY_UNITS and set(data) == {'material', 'allocation_proof', 'previous', *('q' + str(i) for i in range(len(selected)))},
            'qualified_consumer_exact_inputs')
    require(data['previous'] == _source_gate(basis['source']), 'qualified_consumer_source_gate')
    consumed = []
    for index, (branch, ordinal) in enumerate(selected):
        result = data['q' + str(index)]
        require(result == _check(dict(source=basis['source'], branch=branch, ordinal=ordinal)),
                'qualified_consumer_actual_quantum')
        consumed.append(result)
    extra = [row['finding'] for row in consumed if row['check'] == 'absolute_word_audit']
    return dict(profile=PROFILE, basis_sha256=digest(basis), allocation_sha256=digest(allocation),
        consumed_checks=consumed, consumed_units=len(consumed),
        additional_review_required=any(row['additional_review_required'] for row in extra),
        disposition='SOURCE_BOUND_INSPECTION_ONLY', provider_calls=0, effects=0)


def _compute(operation, data):
    if operation == SOURCE_OPERATION:
        require(set(data) == {'material'}, 'qualified_source_fields')
        return _source_gate(data['material'])
    if operation == CHECK_OPERATION:
        require(set(data) == {'material'}, 'qualified_check_fields')
        return _check(data['material'])
    require(operation == FINAL_OPERATION, 'qualified_operation')
    return _consume(data)


def _decode(inputs):
    require(all(type(row.value) is str and len(row.value.encode('utf-8')) <= 262144 for row in inputs),
            'qualified_input_budget')
    return {key: json.loads(value) for key, value in authority.values(inputs).items()}


def validate_inputs(definition, inputs):
    errors = firewall.validate_capability_values_v01(definition.input_fields, inputs)
    try:
        if not errors:
            _compute(definition.operation_id, _decode(inputs))
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        errors = (str(error),)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=inputs,
        invocation_id=None, valid=not errors, reason_codes=errors)


def _execute(invocation, operation):
    require(invocation.candidate_id is None and invocation.packet_id is None, 'qualified_pure_invocation')
    output = _compute(operation, _decode(invocation.inputs))
    return authority.records(dict(material=('TEXT', canonical(output).decode('utf-8'))))


def execute_source(invocation):
    return _execute(invocation, SOURCE_OPERATION)


def execute_check(invocation):
    return _execute(invocation, CHECK_OPERATION)


def execute_consumer(invocation):
    return _execute(invocation, FINAL_OPERATION)


def validate_outputs(definition, invocation, output):
    errors = firewall.validate_capability_values_v01(definition.output_fields, output)
    try:
        if not errors:
            require(authority.values(output) == {'material': canonical(_compute(definition.operation_id,
                _decode(invocation.inputs))).decode('utf-8')}, 'qualified_actual_output')
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        errors = (str(error),)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=output,
        invocation_id=invocation.invocation_id, valid=not errors, reason_codes=errors)


def _admit(operation, names, host_ref):
    executor = {SOURCE_OPERATION: execute_source, CHECK_OPERATION: execute_check,
                FINAL_OPERATION: execute_consumer}[operation]
    callbacks = (validate_inputs, validate_outputs, executor)
    snapshots = tuple(hosts.observe_local_capability_code_v01(callback) for callback in callbacks)
    definition = firewall.build_capability_definition_v01(operation_id=operation, version='v01', effect_kind='PURE',
        business_semantics=None, input_fields=tuple(firewall.build_capability_field_v01(name=name,
            value_type='TEXT', required=True, consequential=False) for name in names),
        output_fields=(firewall.build_capability_field_v01(name='material', value_type='TEXT', required=True, consequential=False),),
        resource_refs=(), input_validator_ref=snapshots[0].public_symbol, output_validator_ref=snapshots[1].public_symbol,
        executor_ref=snapshots[2].public_symbol, code_sha256s=tuple((row.public_symbol, row.source_sha256) for row in snapshots))
    return hosts.admit_local_capability_v01(definition=definition, input_validator=validate_inputs,
        output_validator=validate_outputs, executor=executor, catalogue_revision=0, host_instance_ref=host_ref)


def _literal(name, value):
    return work.WorkInputBindingV01(name, work.WorkLiteralV01(action.build_action_effect_parameter_record_v01(
        parameter_name=name, value_type='TEXT', value=canonical(value).decode('utf-8'))))


class _CurrentSource:
    def __init__(self, controller, task_id, selection):
        self.controller, self.task_id, self.selection = controller, task_id, selection
        now = controller.now()
        self.snapshot = hosts.TrustedWorkSourceSnapshotV01((), action.build_logical_time_bridge_v01(
            origin_utc_epoch_seconds=now, seconds_per_tick=1, bridge_policy_version=PROFILE),
            now, 'radik:trusted_clock', task_id, 0)

    def read_current_v01(self):
        self.controller.current()
        _history(self.controller, self.selection)
        now = self.controller.now()
        require(now >= self.snapshot.evaluation_time, 'qualified_clock_rollback')
        self.snapshot = replace(self.snapshot, evaluation_time=now,
            source_revision=self.snapshot.source_revision + int(now != self.snapshot.evaluation_time))
        return self.snapshot


def run(controller, experience_binding=None, *, label='cold'):
    """Execute through an owned native Host using a sealed G3 current selection."""
    from .qualified_experience import _request_source
    require(label in ('cold', 'qualified', 'unrelated'), 'qualified_run_label')
    require(experience_binding is not None, 'qualified_sealed_current_history_required')
    history = _history(controller, experience_binding)
    source = _source_material(controller)
    start = time.monotonic()
    task_id = controller.spec.task_id + ':qualified:' + label
    source_context = replace(_request_source(controller.family.source_context, task_id),
        g2a_evaluation_time=controller.now(), g2a_evaluation_time_source='radik:trusted_clock',
        g2a_evaluation_context_id=task_id)
    host_ref = 'radik:qualified_host:' + digest(task_id)
    catalogue = (_admit(SOURCE_OPERATION, ('material',), host_ref),
        _admit(CHECK_OPERATION, ('material',), host_ref),
        _admit(FINAL_OPERATION, ('material', 'allocation_proof', 'previous', *('q' + str(i) for i in range(DISCRETIONARY_UNITS))), host_ref))
    definitions = dict(source=catalogue[0].definition.definition_id, check=catalogue[1].definition.definition_id,
                       consumer=catalogue[2].definition.definition_id)
    now = controller.now()
    intent = 'radik:qualified_intent:' + digest(dict(task=task_id, source=source, history=history))
    semantic = abi.build_kernel_artifact_v01(abi_version='v1.0', artifact_id='radik:qualified_proposal:' + digest(intent),
        artifact_type='SemanticArchitectProposal', schema_version='v1', transaction_id='transaction:' + task_id,
        owner_root_id=controller.root_id, source_component='radik:qualified_adapter', authority_class='ADVISORY', lifecycle_state='PROPOSED',
        payload=dict(profile=PROFILE, source=source, history=history, inventory=QUANTA, total_units=TOTAL_UNITS),
        trace_refs=(intent, controller.spec.task_id), parent_refs=(source_context.bsep_packet['packet_id'],),
        time_envelope=dict(pt_created_at=authority.stamp(now), kt_asof=authority.stamp(now), et_observed_at=None,
            ct_session_anchor=task_id, ttl_seconds=min(controller.family.scope['valid_to'], history['valid_to']) - now,
            freshness_class='static', valid_from=authority.stamp(now),
            valid_to=authority.stamp(min(controller.family.scope['valid_to'], history['valid_to']))))
    common = dict(catalogue=catalogue, source_context=source_context, semantic_proposal=semantic)
    initial = work.WorkItemV01('source_gate', definitions['source'], controller.root_id,
        (_literal('material', source),), (), (), None, None)
    candidate = work.build_work_program_candidate_v01(task_id=task_id, previous_revision_id=None, intent_ref=intent,
        bsep_ref=source_context.bsep_packet['packet_id'], semantic_proposal_ref=semantic.artifact_id,
        catalogue_revision=0, budget=work.WorkBudgetV01(16, 0, 0, TOTAL_UNITS, 2), items=(initial,),
        trigger_evidence_refs=(), **common)
    program = work.materialize_work_program_v01(candidate, **common)
    policy = work.build_work_task_policy_v01(candidate, **common, host_instance_ref=host_ref,
        definition_ids=tuple(sorted(definitions.values())), resource_refs=())
    current_source = _CurrentSource(controller, task_id, experience_binding)
    clock = current_source.read_current_v01()
    host = hosts.build_root_work_execution_host_v01(owning_root_id=controller.root_id,
        registry=action.build_empty_action_commit_packet_registry_v02(), catalogue=catalogue, packet_bindings=(),
        current_dependency_observations=(), logical_time_bridge=clock.logical_time_bridge,
        trusted_source=current_source, task_policies=(policy,))
    work.enroll_work_program_v01(host, program, **common, expected_revision=host.state_revision)

    def context():
        return work.work_continuation_context_v01(host, task_id=task_id, expected_revision=host.state_revision)

    def advance(value, *, bootstrap=False):
        with _native_stage('G4_BOOTSTRAP_ADVANCE' if bootstrap else 'G4_ALLOCATED_ADVANCE'):
            outcome = work.advance_work_program_v01(value, **common, host_map={controller.root_id: host}, continuation_context=context())
            require(work.validate_work_continuation_outcome_v01(outcome, context=context(), **common) == (True, ())
                    and outcome.status == 'COMPLETED' and all(row.status == 'COMPLETED' for row in outcome.results),
                    'qualified_native_work_return')
        with _native_stage('G4_BOOTSTRAP_ARTIFACT' if bootstrap else 'G4_ALLOCATED_ARTIFACT'):
            artifact = work.work_program_result_to_artifact_v01(value, outcome.results, **common,
                host_map={controller.root_id: host}, continuation_context=context())
        return outcome, artifact

    controller.emit('QUALIFIED_ALLOCATION_START', label=label, total_native_units=TOTAL_UNITS)
    bootstrap, bootstrap_artifact = advance(program, bootstrap=True)
    with _native_stage('G4_HISTORY'):
        snapshot = work.inspect_work_task_v01(host, task_id=task_id)
        require(_history(controller, experience_binding) == history, 'qualified_current_history_changed')
        basis = dict(profile=PROFILE, source=source, history=history, policy=authority.plain(policy),
            usage=authority.plain(snapshot), envelope=abi.kernel_artifact_to_plain_dict_v01(semantic)['time_envelope'],
            source_context=dict(bsep_packet=dict(packet_id=source_context.bsep_packet['packet_id']),
                original_sha256=digest(authority.plain(source_context)),
                parent_original_sha256=digest(authority.plain(controller.family.source_context))), owner_root=controller.root_id,
            custody_root=history['custody_root_id'], task_id=task_id, transaction_id=semantic.transaction_id,
            evaluation_time=host.current_sources.evaluation_time, definitions=definitions)
    with _native_stage('G4_ALLOCATION'):
        budget, allocation = _allocation(basis)
        selected = _selected(allocation)
        material = dict(basis=basis, budget=budget, allocation=allocation)
    with _native_stage('G4_TASK_ROOT'):
        review_material = dict(profile=PROFILE, material_sha256=digest(material), selected=selected,
                               source_scope_sha256=history['source_scope_sha256'])
        review = authority.root_review('radik:qualified_choice:' + digest(review_material), review_material,
            dict(original_cap=budget['total'] == policy.max_compute_units, fixed_cost=len(selected) + 2 == TOTAL_UNITS,
                current_source=source == _source_material(controller), no_effect_policy=controller.current_policy()['save_allowed'] is False),
            controller.now(), transaction_id=semantic.transaction_id, owning_root_id=controller.root_id, task_id=task_id)
        require(review[2].decision == 'ACCEPT', 'qualified_allocation_root_refused')
    with _native_stage('G4_REVISION'):
        items = []
        for branch, ordinal in selected:
            items.append(work.WorkItemV01(branch + '_' + str(ordinal), definitions['check'], controller.root_id,
                (_literal('material', dict(source=source, branch=branch, ordinal=ordinal)),), (), (), None, None))
        trigger = work.build_work_revision_trigger_v01(context(), work_id='source_gate', output_field='material')
        inputs = [_literal('material', basis), _literal('allocation_proof', dict(budget=budget, allocation=allocation)),
                  work.WorkInputBindingV01('previous', trigger.output)]
        inputs.extend(work.WorkInputBindingV01('q' + str(index), work.WorkOutputBindingV01(item.work_id, 'material', 'TEXT'))
                      for index, item in enumerate(items))
        items.append(work.WorkItemV01('final_consumer', definitions['consumer'], controller.root_id,
            tuple(inputs), (), tuple(item.work_id for item in items), None, None))
        revision = work.revise_work_program_v01(context(), previous_revision_id=program.candidate.revision_id,
            trigger=trigger, items=tuple(items), budget=work.WorkBudgetV01(16, 0, 0, TOTAL_UNITS - snapshot.usage.compute_units, 1), **common)
        require(type(revision) is work.WorkContinuationOutcomeV01 and revision.status == 'ACTIVE',
                'qualified_native_revision_not_active')
        revised = revision.program
    with _native_stage('G4_PRE_DISPATCH_PERSISTENCE'):
        controller._persist('qualified_allocation_pre_dispatch', dict(basis=basis, budget=budget, allocation=allocation,
            decision=authority.root_plain(review), program=revised, bootstrap=bootstrap_artifact))
    outcome, artifact = advance(revised)
    with _native_stage('G4_FINAL_CHECKS'):
        final = next(row for row in outcome.results if row.work_id == 'final_consumer')
        output = json.loads(authority.values(final.result.output)['material'])
        require(output['consumed_units'] == DISCRETIONARY_UNITS, 'qualified_consumed_units')
        actual = work.inspect_work_task_v01(host, task_id=task_id)
        require(actual.usage.compute_units == TOTAL_UNITS and host.registry.action_packet_lifecycle_entries == ()
            and all(row.invocation.packet_id is None and row.invocation.candidate_id is None
                    for row in outcome.results), 'qualified_native_accounting')
        require(source == _source_material(controller) and _history(controller, experience_binding) == history,
                'qualified_final_current_basis')
        final_material = dict(output=output, artifact=authority.plain(artifact), usage=authority.plain(actual),
                              original_basis_sha256=digest(basis))
    with _native_stage('G4_CUSTODY'):
        custody = authority.root_review('radik:qualified_custody:' + digest(final_material), final_material,
            dict(raw_source_hashes=all(digest(row['text'].encode('utf-8')) == row['sha256'] for row in controller.current()),
                source_scope_current=history['source_scope_sha256'] == _source_gate(source)['source_scope_sha256'],
                current_history=_history(controller, experience_binding) == history,
                no_external_sources=all(row['branch'] in BRANCHES for row in output['consumed_checks'])),
            controller.now(), transaction_id=semantic.transaction_id, owning_root_id=history['custody_root_id'], task_id=task_id)
        require(custody[2].decision == 'ACCEPT' and custody[1].target_root_id != review[1].target_root_id,
                'qualified_independent_custody_refused')
    receipt = dict(profile=PROFILE, label=label, task_id=task_id, source_task_id=controller.spec.task_id,
        budget_total=TOTAL_UNITS, consumed_units=actual.usage.compute_units, allocation=allocation,
        actual_checks=output['consumed_checks'], final_consumer=output, history=history,
        task_root=authority.root_plain(review), custody_root=authority.root_plain(custody),
        bootstrap=bootstrap_artifact, artifact=artifact, program=revised, results=outcome.results,
        host_history=work.inspect_work_task_history_v01(context()), usage=actual,
        seconds=time.monotonic() - start, provider_calls=0, effects=0,
        claim='FINITE_REAL_WORK_REDISTRIBUTION_NOT_SPEEDUP')
    reference = controller._persist('qualified_allocation_actual', receipt)
    controller.emit('QUALIFIED_ALLOCATION_RETURN', label=label, native_units=actual.usage.compute_units,
                    selected_checks=[row['check'] for row in output['consumed_checks']], seconds=receipt['seconds'])
    return dict(profile=PROFILE, label=label, budget_total=TOTAL_UNITS, consumed_units=actual.usage.compute_units,
        allocation_counts={branch: sum(row['branch'] == branch for row in output['consumed_checks']) for branch in BRANCHES},
        selected_checks=[row['check'] for row in output['consumed_checks']], final_consumer=output,
        task_root_decision_id=review[2].decision_id, custody_root_decision_id=custody[2].decision_id,
        history=history, artifact_id=artifact.artifact_id, evidence=reference, seconds=receipt['seconds'],
        provider_calls=0, effects=0, claim=receipt['claim'])
