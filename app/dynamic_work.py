"""Pure finite dynamic business capabilities: no I/O, provider or effect operation.

Trusted current intake and native scheduling are outside this module. Every
executor recomputes bounded business data from exact supplied values.
"""
import json

from hedgehog.kernel import effect_firewall_v01 as firewall

from . import native_authority as authority
from .contracts import canonical, digest, require
from .task_spec import TaskSpec, meaning_key
from .memory import validate_memory_origin

MAX_RESULT_BYTES = 32768


def _copy(value):
    return json.loads(canonical(value))


def descriptors(sources):
    from .dynamic_roles import source_scope
    return source_scope(sources)


def _candidate(spec, candidate, sources, family_projection=None):
    require(type(spec) is TaskSpec and type(candidate) is dict and candidate.get('task_id') == spec.task_id
        and candidate.get('profile') == spec.profile and candidate.get('criterion') == spec.criterion
        and candidate.get('source_scope_sha256') == digest(descriptors(sources)), 'dynamic_work_candidate_binding')
    require(type(candidate.get('claims')) is list and 1 <= len(candidate['claims']) <= 8,
        'dynamic_work_claim_budget')
    by_ref = {source['source_ref']: source for source in sources}
    seen, identities = set(), set()
    for claim in candidate['claims']:
        require(type(claim) is dict and set(claim) == {'source_ref', 'revision', 'sha256', 'start', 'end', 'quote', 'kind'},
            'dynamic_work_claim_shape')
        source = by_ref.get(claim['source_ref'])
        require(source is not None and all(claim[key] == source[key] for key in ('source_ref', 'revision', 'sha256')),
            'dynamic_work_claim_source')
        raw = source['text'].encode('utf-8')
        start, end = claim['start'], claim['end']
        require(type(start) is type(end) is int and 0 <= start < end <= len(raw), 'dynamic_work_span')
        try:
            quote = raw[start:end].decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('dynamic_work_utf8_boundary') from None
        require(type(claim['quote']) is str and claim['quote'] == quote and len(quote.encode('utf-8')) <= 2048
            and claim['kind'] in ('support', 'contradiction', 'condition', 'exception', 'unknown'), 'dynamic_work_quote')
        identity = claim['source_ref'], start, end, claim['kind']
        require(identity not in identities, 'dynamic_work_duplicate_claim')
        identities.add(identity)
        seen.add(claim['source_ref'])
    require(seen == set(spec.source_ids), 'dynamic_work_each_source')
    for key, maximum in (('statement', 2048), ('uncertainty', 512)):
        require(type(candidate.get(key)) is str and bool(candidate[key].strip())
            and len(candidate[key].encode('utf-8')) <= maximum, 'dynamic_work_text_budget')
    require(len(candidate['uncertainty']) <= 280 and type(candidate.get('program')) is dict
        and set(candidate['program']) == {'route', 'optional_exceptions'}
        and candidate['program']['route'] in ('short', 'decomposed', 'nested')
        and type(candidate['program']['optional_exceptions']) is bool, 'dynamic_work_program')
    if family_projection is not None:
        require(candidate['program']['route'] == family_projection['route']
            and candidate['source_scope_sha256'] == family_projection['source_scope_sha256'], 'dynamic_work_family')
        requests = family_projection['approved_evidence']
        require(all(any(all(claim[key] == request[key] for key in ('source_ref', 'revision', 'sha256'))
            and request['start'] <= claim['start'] < claim['end'] <= request['end'] for request in requests)
            for claim in candidate['claims']), 'dynamic_work_bsep_selection')
    return _copy(candidate)


def extract(material):
    require(type(material) is dict and set(material) == {'source', 'claims'}, 'dynamic_extract_material')
    source, claims = material['source'], material['claims']
    descriptors([source])
    require(type(claims) is list and 1 <= len(claims) <= 8, 'dynamic_extract_claims')
    raw = source['text'].encode('utf-8')
    for claim in claims:
        require(all(claim[key] == source[key] for key in ('source_ref', 'revision', 'sha256'))
            and type(claim['start']) is type(claim['end']) is int
            and 0 <= claim['start'] < claim['end'] <= len(raw), 'dynamic_extract_source_span')
        try:
            quote = raw[claim['start']:claim['end']].decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('dynamic_extract_utf8_boundary') from None
        require(quote == claim['quote'] and len(quote.encode('utf-8')) <= 2048, 'dynamic_extract_quote')
    return dict(source={key: source[key] for key in ('source_ref', 'revision', 'sha256')}, selected=_copy(claims))


def business_result(spec, candidate, branches):
    """Profile-specific outputs preserve the distinction between citation and truth."""
    require(type(spec) is TaskSpec and type(branches) in (list, tuple)
        and len(branches) == len(spec.source_ids), 'dynamic_business_branches')
    selected = [claim for branch in branches for claim in branch['selected']]
    require(sorted(canonical(claim) for claim in selected) == sorted(canonical(claim) for claim in candidate['claims'])
        and {branch['source']['source_ref'] for branch in branches} == set(spec.source_ids), 'dynamic_business_actual_predecessors')
    common = dict(version='radik.dynamic.business.v01', profile=spec.profile, criterion=spec.criterion,
        statement=candidate['statement'], uncertainty=candidate['uncertainty'],
        verified_scope='Exact UTF-8 byte spans and current source identities; external truth and entailment are not certified.')
    if spec.profile == 'compare':
        pairs = []
        for index, left in enumerate(branches):
            for right in branches[index + 1:]:
                lq, rq = {claim['quote'] for claim in left['selected']}, {claim['quote'] for claim in right['selected']}
                pairs.append(dict(left=left['source']['source_ref'], right=right['source']['source_ref'],
                    identical_citations=sorted(lq & rq), left_only=sorted(lq - rq), right_only=sorted(rq - lq)))
        result = dict(common, sources=_copy(branches), comparisons=pairs, conclusion_status='UNCERTAIN_COMPARISON')
    elif spec.profile == 'explain':
        result = dict(common, obligations=[claim for claim in selected if claim['kind'] == 'support'],
            conditions=[claim for claim in selected if claim['kind'] == 'condition'],
            exceptions=[claim for claim in selected if claim['kind'] == 'exception'],
            unknowns=[claim for claim in selected if claim['kind'] in ('unknown', 'contradiction')],
            conclusion_status='SOURCE_BOUND_EXPLANATION')
    else:
        require(spec.profile == 'verify' and type(spec.supplied_candidate) is str, 'dynamic_business_profile')
        result = dict(common, supplied_candidate=spec.supplied_candidate,
            supporting_evidence=[claim for claim in selected if claim['kind'] == 'support'],
            contradicting_evidence=[claim for claim in selected if claim['kind'] == 'contradiction'],
            qualifications=[claim for claim in selected if claim['kind'] in ('condition', 'exception', 'unknown')],
            conclusion_status='ENTAILMENT_REQUIRES_REVIEW')
    audit = exception_audit(candidate, branches)
    if audit is not None:
        result['exception_audit'] = audit
    require(len(canonical(result)) <= MAX_RESULT_BYTES, 'dynamic_business_result_budget')
    return result


def exception_audit(candidate, branches):
    """The enabled audit's exact typed output, recomputed for validators."""
    if not candidate['program']['optional_exceptions'] or not any(
            claim['kind'] == 'exception' for claim in candidate['claims']):
        return None
    source_ref = next(claim['source_ref'] for claim in candidate['claims'] if claim['kind'] == 'exception')
    branch = next(branch for branch in branches if branch['source']['source_ref'] == source_ref)
    return dict(source=branch['source'], exceptions=[claim for claim in branch['selected'] if claim['kind'] == 'exception'])


def _decode(inputs):
    return {key: json.loads(value) for key, value in authority.values(inputs).items()}


def _compute(operation, data):
    if operation in ('radik.dynamic.revision_gate.v01', 'radik.dynamic.revision_audit.v01'):
        audit = revision_audit(data['material'], data['previous'])
        return {'enabled': audit is not None} if operation.endswith('revision_gate.v01') else {
            'material': canonical(audit).decode('utf-8')}
    if operation == 'radik.dynamic.extract.v01':
        return {'material': canonical(extract(data['material'])).decode('utf-8')}
    if operation == 'radik.dynamic.exception_gate.v01':
        candidate = data['material']
        require(type(candidate['program']['optional_exceptions']) is bool, 'dynamic_gate_boolean')
        return {'enabled': candidate['program']['optional_exceptions'] and any(
            claim['kind'] == 'exception' for claim in candidate['claims'])}
    if operation == 'radik.dynamic.exception_audit.v01':
        branch = data['material']
        require(type(branch) is dict and set(branch) == {'source', 'selected'}, 'dynamic_audit_actual_predecessor')
        return {'material': canonical(dict(source=branch['source'], exceptions=[claim for claim in branch['selected']
            if claim['kind'] == 'exception'])).decode('utf-8')}
    material = data['material']
    spec = TaskSpec.from_plain(material['task'])
    intake = material['intake']
    require(type(intake) is dict and set(intake) == {'intake_root_ref', 'intake_root_sha256',
        'task_spec_sha256', 'current_source_scope_sha256'}
        and intake['task_spec_sha256'] == digest(spec.plain())
        and intake['current_source_scope_sha256'] == material['candidate']['source_scope_sha256'],
        'dynamic_work_intake_binding')
    mode = material['mode']
    require(operation == 'radik.dynamic.' + spec.profile + '.' + mode + '.v01'
        and mode in ('short', 'aggregate', 'revision', 'memory'), 'dynamic_operation_profile')
    if mode in ('short', 'memory'):
        sources = material['sources']
        candidate = _candidate(spec, material['candidate'], sources, material['family'])
        branches = [extract(dict(source=source, claims=[claim for claim in candidate['claims']
            if claim['source_ref'] == source['source_ref']])) for source in sources]
        result = business_result(spec, candidate, branches)
        if mode == 'memory':
            origin = material['memory_origin']
            prior = material['prior']
            require(type(origin) is dict and set(origin) == {'record_id', 'payload_sha256', 'descent_id',
                'root_decision_id', 'prior_task_id', 'result_id', 'accepted_at', 'valid_to', 'meaning_key',
                'historical_route', 'historical_valid_to', 'selection_origin'}
                and type(origin['accepted_at']) is type(origin['valid_to']) is int
                and origin['accepted_at'] <= material['evaluated_at'] < origin['valid_to']
                and origin['meaning_key'] == meaning_key(spec, sources), 'dynamic_memory_origin')
            eligibility = validate_memory_origin(origin['selection_origin'], now=material['evaluated_at'])
            require(eligibility['record_id'] == origin['record_id'] and eligibility['payload_sha256'] == origin['payload_sha256']
                and eligibility['descent_id'] == origin['descent_id']
                and eligibility['descent_root_decision_id'] == origin['root_decision_id']
                and eligibility['result_id'] == prior['result_id'] and eligibility['result_sha256'] == prior['result_sha256']
                and eligibility['candidate_sha256'] == digest(prior['proposal'])
                and eligibility['source_scope_sha256'] == digest(descriptors(sources))
                and eligibility['historical_accepted_at'] == origin['accepted_at']
                and eligibility['historical_valid_to'] == origin['historical_valid_to']
                and origin['valid_to'] == min(origin['historical_valid_to'], eligibility['record_clocks']['valid_to']),
                'dynamic_memory_selection_origin')
            if 'revision_focus' in prior['business']:
                require(all(prior['business'].get(key) == item for key, item in result.items()),
                    'dynamic_memory_prior_revision')
                result = dict(result, revision_focus=prior['business']['revision_focus'])
            require(candidate['program']['route'] == 'short'
                and prior['proposal']['program']['route'] == origin['historical_route']
                and prior['business'] == result
                and prior['proposal'] == dict(candidate, task_id=origin['prior_task_id'],
                    program=dict(candidate['program'], route=origin['historical_route']))
                and prior['result_id'] == origin['result_id'] and prior['accepted_at'] == origin['accepted_at']
                and prior['valid_to'] == origin['historical_valid_to'], 'dynamic_memory_prior_business')
    elif mode == 'aggregate':
        candidate = material['candidate']
        branches = [data['branch' + str(index)] for index in range(len(spec.source_ids))]
        require(candidate['profile'] == spec.profile and candidate['task_id'] == spec.task_id,
            'dynamic_aggregate_candidate')
        result = business_result(spec, candidate, branches)
        audit = exception_audit(candidate, branches)
        require((audit is None and 'audit' not in data) or (audit is not None and data.get('audit') == audit),
            'dynamic_aggregate_actual_audit_output')
    else:
        previous = data['previous']
        require(previous['profile'] == spec.profile and previous['criterion'] == spec.criterion,
            'dynamic_revision_actual_previous')
        update = material['condition_update']
        require(type(update) is dict and set(update) == {'kind', 'claim_indexes'}
            and update['kind'] in ('focus_conditions', 'focus_exceptions', 'review_unknowns')
            and type(update['claim_indexes']) is list and 1 <= len(update['claim_indexes']) <= 8
            and len(set(update['claim_indexes'])) == len(update['claim_indexes']), 'dynamic_revision_update')
        claims = material['candidate']['claims']
        require(all(type(index) is int and 0 <= index < len(claims) for index in update['claim_indexes']),
            'dynamic_revision_indexes')
        kinds = {'focus_conditions': ('condition',), 'focus_exceptions': ('exception',),
            'review_unknowns': ('unknown', 'contradiction')}[update['kind']]
        require(all(claims[index]['kind'] in kinds for index in update['claim_indexes']),
            'dynamic_revision_condition_scope')
        audit = revision_audit(material, previous)
        require((audit is None and 'audit' not in data) or (audit is not None and data.get('audit') == audit),
            'dynamic_revision_actual_audit_output')
        focus = dict(kind=update['kind'], selected_claims=[claims[index] for index in update['claim_indexes']],
            previous_result_sha256=digest(previous))
        if audit is not None:
            focus['actual_exception_audit'] = audit
        result = dict(previous, revision_focus=focus)
        require(len(canonical(result)) <= MAX_RESULT_BYTES, 'dynamic_business_result_budget')
    return {'result': canonical(result).decode('utf-8')}


def revision_audit(material, previous):
    """Read the actual prior business output; a finite condition controls expansion."""
    candidate, update = material['candidate'], material['condition_update']
    require(previous['profile'] == material['task']['profile'] and previous['criterion'] == material['task']['criterion'],
        'dynamic_revision_actual_previous')
    require(type(update) is dict and set(update) == {'kind', 'claim_indexes'}
        and update['kind'] in ('focus_conditions', 'focus_exceptions', 'review_unknowns')
        and type(update['claim_indexes']) is list and 1 <= len(update['claim_indexes']) <= 8
        and len(set(update['claim_indexes'])) == len(update['claim_indexes'])
        and all(type(index) is int and 0 <= index < len(candidate['claims']) for index in update['claim_indexes']),
        'dynamic_revision_update')
    selected = [candidate['claims'][index] for index in update['claim_indexes']]
    if previous['profile'] == 'compare':
        actual = [claim for branch in previous['sources'] for claim in branch['selected']]
    elif previous['profile'] == 'explain':
        actual = [claim for key in ('obligations', 'conditions', 'exceptions', 'unknowns') for claim in previous[key]]
    else:
        actual = [claim for key in ('supporting_evidence', 'contradicting_evidence', 'qualifications') for claim in previous[key]]
    require(all(claim in actual for claim in selected), 'dynamic_revision_actual_claim_read')
    permitted = {'focus_conditions': ('condition',), 'focus_exceptions': ('exception',),
        'review_unknowns': ('unknown', 'contradiction')}[update['kind']]
    require(all(claim['kind'] in permitted for claim in selected), 'dynamic_revision_condition_scope')
    if update['kind'] != 'focus_exceptions':
        return None
    return dict(kind='focused_actual_exceptions', selected_claims=selected, previous_result_sha256=digest(previous))


def validate_inputs(definition, inputs):
    errors = firewall.validate_capability_values_v01(definition.input_fields, inputs)
    if not errors:
        try:
            require(definition.version == 'v01' and definition.effect_kind == 'PURE'
                and all(type(value.value) is str and len(value.value.encode('utf-8')) <= 131072 for value in inputs),
                'dynamic_capability_input_budget')
            _compute(definition.operation_id, _decode(inputs))
        except (ValueError, KeyError, TypeError, UnicodeError):
            errors = ('dynamic_capability_input_invalid',)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=inputs,
        invocation_id=None, valid=not errors, reason_codes=errors)


def validate_outputs(definition, invocation, output):
    errors = firewall.validate_capability_values_v01(definition.output_fields, output)
    if not errors:
        try:
            require(authority.values(output) == _compute(definition.operation_id, _decode(invocation.inputs)),
                'dynamic_capability_actual_output')
        except (ValueError, KeyError, TypeError, UnicodeError):
            errors = ('dynamic_capability_output_invalid',)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=output,
        invocation_id=invocation.invocation_id, valid=not errors, reason_codes=errors)


def execute_extract(invocation):
    return authority.records({key: ('TEXT', value) for key, value in _compute('radik.dynamic.extract.v01', _decode(invocation.inputs)).items()})


def execute_gate(invocation):
    output = _compute('radik.dynamic.exception_gate.v01', _decode(invocation.inputs))
    return authority.records({'enabled': ('BOOLEAN', output['enabled'])})


def execute_revision_gate(invocation):
    output = _compute('radik.dynamic.revision_gate.v01', _decode(invocation.inputs))
    return authority.records({'enabled': ('BOOLEAN', output['enabled'])})


def execute_revision_audit(invocation):
    output = _compute('radik.dynamic.revision_audit.v01', _decode(invocation.inputs))
    return authority.records({'material': ('TEXT', output['material'])})


def execute_audit(invocation):
    return authority.records({key: ('TEXT', value) for key, value in _compute('radik.dynamic.exception_audit.v01', _decode(invocation.inputs)).items()})


def execute_business(invocation):
    data = _decode(invocation.inputs)
    material = data['material']
    operation = 'radik.dynamic.' + material['task']['profile'] + '.' + material['mode'] + '.v01'
    return authority.records({key: ('TEXT', value) for key, value in _compute(operation, data).items()})

