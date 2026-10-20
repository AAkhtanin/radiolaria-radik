"""Typed O/A/Work/C proposal chain for finite informational task profiles.

Only the configured transport can emit receipts. Native Work is bound between
Architect and Critic, and no proposal restores permission or performs an effect.
"""
from dataclasses import asdict, dataclass
import json
import re

from .contracts import canonical, digest, require
from .proposal import ProposalObservation
from .task_spec import TaskSpec

CONTEXT_VERSION = 'radik.dynamic.role_context.v01'
PIPELINE_VERSION = 'radik.dynamic.pipeline.v01'
ROLE_VERSIONS = {role: 'radik.dynamic.role.' + role + '.v01'
    for role in ('orchestrator', 'architect', 'critic')}
CRITIC_CHECKS = ('source_binding', 'candidate_binding', 'profile_contract',
    'native_work_binding', 'uncertainty')
CLAIM_KINDS = ('support', 'contradiction', 'condition', 'exception', 'unknown')
ROUTES = ('short', 'decomposed', 'nested')
MAX_PRODUCT_BYTES = 16384
PRODUCT_LIMITS = {'max_serialized_utf8_bytes': MAX_PRODUCT_BYTES,
    'max_canonical_utf8_bytes': MAX_PRODUCT_BYTES, 'max_claims': 8,
    'max_uncertainty_chars': 280, 'max_uncertainty_utf8_bytes': 512,
    'max_statement_chars': 2048, 'max_statement_utf8_bytes': 2048,
    'max_quote_utf8_bytes': 2048,
    'instruction': 'Fit the entire JSON response, including keys, escaping and whitespace, within 16384 UTF-8 bytes. '
        'Individual field ceilings do not increase this joint limit. Select shorter exact spans when needed.'}


def available_exact_spans(sources):
    """Offer a finite partition into UTF-8 aligned byte ranges of at most 2KiB."""
    result = []
    for source in sources:
        raw = source['text'].encode('utf-8')
        start = 0
        while start < len(raw):
            end = min(start + 2048, len(raw))
            while end > start:
                try:
                    raw[start:end].decode('utf-8', errors='strict')
                    break
                except UnicodeDecodeError:
                    end -= 1
            require(start < end, 'dynamic_role_span_boundary')
            result.append(dict(source_ref=source['source_ref'], revision=source['revision'],
                sha256=source['sha256'], start=start, end=end))
            start = end
    return result


def _copy(value):
    return json.loads(canonical(value))


def source_scope(sources):
    require(type(sources) in (list, tuple) and 1 <= len(sources) <= 4, 'dynamic_role_sources')
    result = []
    for row in sources:
        require(type(row) is dict and set(row) == {'source_ref', 'revision', 'sha256', 'text', 'observed_at'},
            'dynamic_role_source_shape')
        require(type(row['source_ref']) is str and type(row['revision']) is int and row['revision'] >= 1
            and type(row['text']) is str and 0 < len(row['text'].encode('utf-8')) <= 16384
            and '\x00' not in row['text'] and type(row['observed_at']) is int and row['observed_at'] >= 0
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']) is not None
            and digest(row['text'].encode('utf-8')) == row['sha256'], 'dynamic_role_source_binding')
        result.append({key: row[key] for key in ('source_ref', 'revision', 'sha256')})
    require(len({row['source_ref'] for row in result}) == len(result), 'dynamic_role_source_duplicate')
    return sorted(result, key=lambda row: row['source_ref'])


def _object(properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties),
        'additionalProperties': False}


def _string(maximum):
    return {'type': 'string', 'minLength': 1, 'maxLength': maximum}


def _context(value, role):
    if type(value) is str:
        value = json.loads(value)
    typed = type(value) is dict and value.get('version') == 'radik.dynamic.role_context.v02'
    extra = {'source_successor'} if typed else set()
    require(type(value) is dict and set(value) == extra | {'version', 'role', 'task_id', 'topic', 'task',
        'sources', 'policy', 'source_scope_sha256', 'available_exact_spans', 'span_unit', 'product_limits', 'intake',
        'predecessor', 'candidate', 'work'}
        and value['version'] == ('radik.dynamic.role_context.v02' if typed else CONTEXT_VERSION) and value['role'] == role, 'dynamic_role_context')
    spec = TaskSpec.from_plain(value['task'])
    require(value['task_id'] == spec.task_id and value['topic'] == spec.topic
        and {row['source_ref'] for row in source_scope(value['sources'])} == set(spec.source_ids)
        and value['source_scope_sha256'] == digest(source_scope(value['sources'])),
        'dynamic_role_context_binding')
    require(value['span_unit'] == 'UTF8_BYTE_OFFSETS' and value['available_exact_spans']
        == available_exact_spans(value['sources']) and value['product_limits'] == PRODUCT_LIMITS,
        'dynamic_role_available_spans')
    intake = value['intake']
    require(type(intake) is dict and set(intake) == {'intake_root_ref', 'intake_root_sha256',
        'task_spec_sha256', 'current_source_scope_sha256'} and type(intake['intake_root_ref']) is str
        and 0 < len(intake['intake_root_ref']) <= 256
        and all(type(intake[key]) is str and re.fullmatch('[0-9a-f]{64}',intake[key]) is not None
            for key in ('intake_root_sha256','task_spec_sha256','current_source_scope_sha256'))
        and intake['task_spec_sha256'] == digest(spec.plain())
        and intake['current_source_scope_sha256'] == value['source_scope_sha256'], 'dynamic_role_intake_context')
    policy = value['policy']
    require(type(policy) is dict and set(policy) == {'save_allowed', 'consent_ref', 'valid_to',
        'revision', 'workspace_ref'} and policy['save_allowed'] is False
        and (policy['consent_ref'] is None if typed else type(policy['consent_ref']) is str) and type(policy['valid_to']) is int
        and type(policy['revision']) is int and policy['revision'] >= 1
        and type(policy['workspace_ref']) is str, 'dynamic_role_no_effect_policy')
    if typed and value['source_successor'] is not None:
        transition=value['source_successor']
        require(type(transition) is dict and set(transition)=={'staged_ref','prior_result_id','prior_root_sha256',
            'route','retained_claims','changed_sources','contract'}
            and transition['route'] in ROUTES and type(transition['retained_claims']) is list
            and transition['contract']=='PRESERVE_EXACT_UNCHANGED_BRANCH_CLAIMS_OR_REQUIRE_NEW_INTAKE',
            'dynamic_role_source_successor_context')
    if role == 'orchestrator':
        require(value['predecessor'] is None and value['candidate'] is None and value['work'] is None,
            'dynamic_role_initial_context')
    else:
        prior = value['predecessor']
        require(type(prior) is dict and set(prior) == {'family_ref', 'projection', 'orchestrator_sha256', 'orchestrator'}
            and type(prior['family_ref']) is str and type(prior['projection']) is dict
            and type(prior['orchestrator']) is dict and digest(prior['orchestrator']) == prior['orchestrator_sha256']
            and type(prior['orchestrator_sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', prior['orchestrator_sha256']) is not None,
            'dynamic_role_family_context')
        require((value['candidate'] is None and value['work'] is None) if role == 'architect'
            else type(value['candidate']) is dict and type(value['work']) is dict,
            'dynamic_role_downstream_context')
    return value, spec


def closed_role_schema(role, context):
    """Rebuild the only permitted dynamic schema from the exact bounded context."""
    require(role in ROLE_VERSIONS, 'dynamic_role_name')
    material, spec = _context(context, role)
    common = {'version': {'const': ROLE_VERSIONS[role]}, 'task_id': {'const': spec.task_id},
        'profile': {'const': spec.profile}, 'criterion': {'const': spec.criterion}}
    if role in ('orchestrator', 'architect'):
        common['source_scope_sha256'] = {'const': material['source_scope_sha256']}
        span = {'source_ref': {'enum': list(spec.source_ids)}, 'revision': {'type': 'integer', 'minimum': 1},
            'sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
            'start': {'type': 'integer', 'minimum': 0, 'maximum': 16384},
            'end': {'type': 'integer', 'minimum': 1, 'maximum': 16384}}
        if role == 'orchestrator':
            common.update(route={'enum': list(ROUTES)}, evidence_requests={'type': 'array',
                'minItems': len(spec.source_ids), 'maxItems': 8,
                'items': {'enum': material['available_exact_spans']}}, uncertainty=_string(280))
        else:
            span.update(quote=_string(2048), kind={'enum': list(CLAIM_KINDS)})
            common.update(claims={'type': 'array', 'minItems': 1, 'maxItems': 8, 'items': _object(span)},
                statement=_string(2048), uncertainty=_string(280),
                program=_object({'route': {'enum': list(ROUTES)}, 'optional_exceptions': {'type': 'boolean'}}))
    else:
        common.update(candidate_sha256={'const': digest(material['candidate'])},
            work_sha256={'const': digest(material['work'])}, verdict={'enum': ['ACCEPT', 'REVISE']},
            checks={'type': 'array', 'minItems': len(CRITIC_CHECKS), 'maxItems': len(CRITIC_CHECKS),
                'items': _object({'name': {'enum': list(CRITIC_CHECKS)}, 'passed': {'type': 'boolean'}})},
            supporting_claims={'type': 'array', 'minItems': 0, 'maxItems': 8,
                'uniqueItems': True, 'items': {'type': 'integer', 'minimum': 0, 'maximum': 7}},
            uncertainty=_string(280))
    transition=material.get('source_successor')
    if transition is not None:
        if role=='orchestrator':common['route']={'const':transition['route']}
        elif role=='architect':common['program']['properties']['route']={'const':transition['route']}
    return _object(common)


def validate_product(role, value, context):
    """Validate source spans and predecessor reads beyond JSON schema shape."""
    from jsonschema import Draft202012Validator
    material, spec = _context(context, role)
    schema = closed_role_schema(role, material)
    require(type(value) is dict and len(canonical(value)) <= MAX_PRODUCT_BYTES,
        'dynamic_role_product_total_byte_budget')
    require(not list(Draft202012Validator(schema).iter_errors(value)), 'dynamic_role_product_schema')
    text_keys = ('uncertainty',) + (('statement',) if role == 'architect' else ())
    for key in text_keys:
        require(len(value[key].encode('utf-8')) <= (2048 if key == 'statement' else 512)
            and bool(value[key].strip()) and '\x00' not in value[key], 'dynamic_role_product_text_budget')
    if role in ('orchestrator', 'architect'):
        sources = {row['source_ref']: row for row in material['sources']}
        spans = value['evidence_requests' if role == 'orchestrator' else 'claims']
        require(len({canonical(row) for row in spans}) == len(spans), 'dynamic_role_duplicate_span')
        for span in spans:
            row = sources[span['source_ref']]
            raw = row['text'].encode('utf-8')
            require(span['revision'] == row['revision'] and span['sha256'] == row['sha256']
                and 0 <= span['start'] < span['end'] <= len(raw), 'dynamic_role_exact_source_span')
            try:
                quote = raw[span['start']:span['end']].decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                raise ValueError('dynamic_role_span_boundary') from None
            if role == 'architect':
                require(span['quote'] == quote
                    and len(span['quote'].encode('utf-8')) <= 2048, 'dynamic_role_exact_quote')
                require(any(prior['source_ref'] == span['source_ref'] and prior['start'] <= span['start']
                    and span['end'] <= prior['end'] for prior in material['predecessor']['orchestrator']['evidence_requests']),
                    'dynamic_role_architect_projected_span')
        require({span['source_ref'] for span in spans} == set(spec.source_ids),
            'dynamic_role_all_sources_read')
        if role == 'architect':
            require(value['program']['route'] == material['predecessor']['projection']['route'],
                'dynamic_role_route_binding')
    else:
        require(tuple(check['name'] for check in value['checks']) == CRITIC_CHECKS
            and all(index < len(material['candidate']['claims']) for index in value['supporting_claims']),
            'dynamic_role_critic_reads')
        require(value['verdict'] != 'ACCEPT' or all(check['passed'] for check in value['checks']),
            'dynamic_role_critic_acceptance')
    transition=material.get('source_successor')
    if transition is not None and role=='architect':
        changed=set(transition['changed_sources'])
        require([claim for claim in value['claims'] if claim['source_ref'] not in changed]==transition['retained_claims'],
            'dynamic_role_retained_claims_changed')
    return _copy(value)


@dataclass(frozen=True)
class DynamicRoleRequest:
    _run: object
    role: str
    context: str
    schema_bytes: bytes
    body: bytes
    _issue_key: object

    def validate(self, *, sender, role, context, output_schema, body):
        return self._run.validate_request(self, sender=sender, role=role, context=context,
            output_schema=output_schema, body=body)

    def emit(self, *, sender, observation, body):
        return self._run.emit(self, sender=sender, observation=observation, body=body)


class DynamicRoleRun:
    """One source-bound proposal round; native execution remains in its controller."""
    def __init__(self, controller, spec, sources):
        from .openai_plan_transport import OpenAIPlanTransport
        from .dynamic_native import DynamicDocumentController
        require(type(controller) is DynamicDocumentController and type(spec) is TaskSpec
            and isinstance(controller.client, OpenAIPlanTransport),
            'dynamic_role_owned_transport')
        self.controller, self.spec, self.sender = controller, spec, controller.client
        self._wire_profile = canonical(self.sender.request_profile())
        self._intake = canonical(controller.intake_context())
        self.sources, self.policy = _copy(sources), _copy(controller.current_policy())
        require({row['source_ref'] for row in source_scope(self.sources)} == set(spec.source_ids),
            'dynamic_role_task_sources')
        self.started_at = self.last_time = controller.now()
        self.stage, self.pending, self.family = 0, None, None
        self._family_identity, self._work, self._work_plain = None, None, None
        self._products, self._receipts, self._requests, self._provenance = {}, {}, {}, {}
        self._issue_key = object()

    @property
    def candidate(self):
        require('architect' in self._products, 'dynamic_role_candidate_missing')
        return json.loads(self._products['architect'])

    @property
    def critic(self):
        require(self.stage == 3, 'dynamic_role_critic_missing')
        return json.loads(self._products['critic'])

    @property
    def provenance(self):
        return _copy(dict(version=PIPELINE_VERSION, **self._provenance))

    def current(self):
        now = self.controller.now()
        require(type(now) is int and self.last_time <= now < self.controller.role_deadline(self.started_at),
            'dynamic_role_time')
        self.last_time = now
        require(canonical(self.controller.intake_context()) == self._intake,'dynamic_role_intake_changed')
        require(canonical(self.sender.request_profile()) == self._wire_profile,
            'dynamic_role_model_settings_changed')
        current = self.controller.source_reader()
        require(source_scope(current) == source_scope(self.sources)
            and {row['source_ref']: row['text'] for row in current}
                == {row['source_ref']: row['text'] for row in self.sources}, 'dynamic_role_current_sources')
        require(self.controller.current_policy() == self.policy, 'dynamic_role_current_policy')
        for role, (observation, frozen) in self._receipts.items():
            require(canonical(asdict(observation)) == frozen
                and self.sender._emitted_for(self._requests[role], observation, self._requests[role].body),
                'dynamic_role_receipt_origin')
            if role in self._products:
                require(canonical(observation.value) == self._products[role], 'dynamic_role_product_mutated')
        if self.stage > 0:
            from .dynamic_semantics import validate_current_family
            require(self.family is self._family_identity and self.family is not None,
                'dynamic_role_family_identity')
            validate_current_family(self.family, current, policy=self.policy, now=now)
            require(self.family.scope['task'] == self.spec.plain()
                and self.family.scope['root_id'] == self.controller.root_id
                and self.family.product == json.loads(self._products['orchestrator'])
                and self.family.provenance == self._provenance['orchestrator'],
                'dynamic_role_family_predecessor')
        if self._work is not None:
            self._work.validate(self.spec, self.candidate, self.family)
            require(canonical(self._work.plain()) == self._work_plain, 'dynamic_role_work_mutated')
        return now

    def expected(self, role):
        require(self.stage < 3 and role == ('orchestrator', 'architect', 'critic')[self.stage],
            'dynamic_role_stage_order')
        predecessor = None if role == 'orchestrator' else dict(family_ref=self.family.family_ref,
            projection=_copy(self.family.projection), orchestrator_sha256=digest(self._products['orchestrator']),
            orchestrator=json.loads(self._products['orchestrator']))
        if role == 'critic':
            require(self._work is not None and self._work_plain is not None, 'dynamic_role_actual_work_required')
        context = dict(version=CONTEXT_VERSION, role=role, task_id=self.spec.task_id, topic=self.spec.topic,
            task=self.spec.plain(), sources=self.sources, policy=self.policy,
            source_scope_sha256=digest(source_scope(self.sources)),
            available_exact_spans=available_exact_spans(self.sources), span_unit='UTF8_BYTE_OFFSETS',
            product_limits=PRODUCT_LIMITS, intake=json.loads(self._intake), predecessor=predecessor,
            candidate=self.candidate if role == 'critic' else None,
            work=json.loads(self._work_plain) if role == 'critic' else None)
        if self.controller.informational_delta:
            context.update(version='radik.dynamic.role_context.v02',source_successor=self.controller.source_successor_context())
        require(len(canonical(context)) <= 131072, 'dynamic_role_context_budget')
        return canonical(context).decode('utf-8'), closed_role_schema(role, context)

    def issue(self, role):
        from .openai_plan_transport import build_request_body
        require(self.pending is None, 'dynamic_role_pending')
        self.current()
        context, schema = self.expected(role)
        request = DynamicRoleRequest(self, role, context, canonical(schema),
            build_request_body(role=role, context=context, output_schema=schema,
                profile=json.loads(self._wire_profile)), self._issue_key)
        self.pending = request
        return request

    def validate_request(self, request, *, sender, role, context, output_schema, body):
        from .openai_plan_transport import build_request_body
        from .task_spec import meaning_key
        require(type(request) is DynamicRoleRequest and request is self.pending
            and request._run is self and request._issue_key is self._issue_key and sender is self.sender,
            'dynamic_role_request_origin')
        self.current()
        expected_context, expected_schema = self.expected(role)
        require(request.role == role and request.context == context == expected_context
            and canonical(output_schema) == request.schema_bytes == canonical(expected_schema),
            'dynamic_role_exact_context_schema')
        require(type(body) is bytes and body == request.body == build_request_body(role=role,
            context=expected_context, output_schema=expected_schema,
            profile=json.loads(self._wire_profile)), 'dynamic_role_exact_body')
        guard = {'pipeline_version': PIPELINE_VERSION, 'stage': self.stage, 'role': role,
            'task_id': self.spec.task_id, 'profile': self.spec.profile,
            'task_spec_sha256': digest(self.spec.plain()),
            'dependencies_sha256': digest(dict(meaning_key=meaning_key(self.spec,self.sources),
                sources=source_scope(self.sources))),
            'predecessor_origin': 'NONE_INITIAL' if self.stage == 0 else 'TRANSPORT_EMITTED',
            'family_ref': None if self.family is None else self.family.family_ref,
            'body_sha256': digest(body)}
        # Called by the issued request at reservation, POST and emission.
        self.sender.budget.validate_task_request(guard)
        self.controller.validate_source_transition_dispatch()
        return guard

    def emit(self, request, *, sender, observation, body):
        self.validate_request(request, sender=sender, role=request.role, context=request.context,
            output_schema=json.loads(request.schema_bytes), body=body)
        require(sender._emitted_for(request, observation, body) and type(observation) is ProposalObservation
            and observation.outcome == 'COMPLETED' and request.role not in self._receipts
            and observation.context_sha256 == digest(request.context.encode('utf-8'))
            and observation.wire_body_sha256 == digest(body), 'dynamic_role_transport_emission')
        self._receipts[request.role] = (observation, canonical(asdict(observation)))
        self._requests[request.role] = request

    def consume(self, request, observation):
        require(request is self.pending and request.role in self._receipts, 'dynamic_role_receipt_missing')
        actual, frozen = self._receipts[request.role]
        require(observation is actual and canonical(asdict(observation)) == frozen,
            'dynamic_role_observation_replaced')
        self.current()
        product = validate_product(request.role, observation.value, request.context)
        provenance = dict(producer_kind='DIRECT_PLAN_' + request.role.upper() + '_EMITTED',
            role=request.role, task_id=self.spec.task_id, context_sha256=observation.context_sha256,
            response_id=observation.response_id, reservation_id=observation.reservation_id,
            wire_body_sha256=observation.wire_body_sha256, observation_sha256=digest(frozen),
            product_sha256=digest(product))
        if request.role == 'orchestrator':
            from .dynamic_semantics import build_source_family
            self.family = build_source_family(self.spec, product, provenance, self.sources,
                policy=self.policy, now=self.controller.now(), root_id=self.controller.root_id)
            self._family_identity = self.family
            self.controller.events.append({'stage': 'PRE_ARCHITECT_BSEP',
                'family_ref': self.family.family_ref, 'native_sha256': self.family.native_sha})
        self._products[request.role], self._provenance[request.role] = canonical(product), provenance
        self.controller.events.append({'stage': 'DYNAMIC_SEMANTIC_ROLE', 'role': request.role,
            'task_id': self.spec.task_id, 'product_sha256': digest(product), 'observation': asdict(observation)})
        self.pending, self.stage = None, self.stage + 1
        return product

    def bind_native_work(self, projection):
        from .dynamic_native import NativeWorkProjection
        require(self.stage == 2 and self.pending is None and self._work is None
            and type(projection) is NativeWorkProjection, 'dynamic_role_native_work_origin')
        self.current()
        projection.validate(self.spec, self.candidate, self.family)
        plain = projection.plain()
        require(type(plain) is dict and len(canonical(plain)) <= 49152, 'dynamic_role_native_work_budget')
        self._work, self._work_plain = projection, canonical(plain)
