"""Connected document console candidate; semantic inference has explicit gates."""
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import time
import uuid

from .contracts import (canonical, digest, require, role_schema, orchestrator_context,
    downstream_context, validate_orchestrator, validate_architect, validate_critic,
    ORCHESTRATOR_VERSION, CRITIC_VERSION, CRITIC_CHECKS, build_continuation_projection,
    SemanticProductRefusal, SEMANTIC_CONTRACT_ERROR_CODES, semantic_refusal_projection)
from .intake import ApprovedSourceStore
from .memory import DocumentMemory, memory_origin_from_selection
from .native_authority import (root_review, source_context, validate_source_family,
    document_transaction_id, source_family_witness)
from .semantic_membrane import PIPELINE_VERSION, ACTUAL_KINDS, MEMORY_KINDS
from .proposal import ProposalObservation
from .native_document import (build_task, run_task, consume_memory, continue_task, save_output,
                              validate_outcome, validate_persisted_outcome)

ROOT_ID = 'root:radik:document_console:v01'
TOPIC = 'service_conditions'
GOAL = 'Сопоставь условия двух служб поддержки: часы приёма, срок ответа и канал для срочных заявок. Укажи точные основания и неопределённость.'
CRITERION = 'Compare two permitted documents with exact source-bound excerpts and explicit uncertainty.'


def owned_directory(project, relative):
    project = Path(project).resolve(strict=True)
    path = project
    for part in Path(relative).parts:
        require(part not in ('', '.', '..') and not Path(relative).is_absolute(), 'controller_owned_relative')
        path = path / part
        require(not path.is_symlink(), 'controller_directory_symlink')
    path.mkdir(parents=True, exist_ok=True)
    require(path.resolve().is_relative_to(project), 'controller_owned_directory')
    return path


@dataclass(frozen=True)
class RoleRequest:
    """An issued runtime stage, never a caller-authored approval flag or hash."""
    _run: object
    role: str
    context: str
    schema_bytes: bytes
    body: bytes
    _issue_key: object

    def validate(self, *, sender, role, context, output_schema, body):
        return self._run.validate_request(self, sender=sender, role=role,
            context=context, output_schema=output_schema, body=body)

    def emit(self, *, sender, observation, body):
        self._run.emit(self, sender=sender, observation=observation, body=body)


@dataclass(frozen=True)
class SemanticSelection:
    candidate: dict
    family: object
    critic: dict
    provenance: dict


class SemanticRun:
    """Controller-owned predecessor chain and immutable provider receipts.

    The configured transport creates the receipt at its completion boundary.
    Source/policy/time and all native relationships are rechecked at reservation
    and immediately before POST. Persisted JSON cannot enter this live chain.
    """
    def __init__(self, console, sources, task_id, continuation):
        from .openai_plan_transport import OpenAIPlanTransport
        sender = console.semantic_receiver or getattr(console.semantic_provider, '__self__', None)
        require(isinstance(sender, OpenAIPlanTransport),
            'semantic_owned_transport_required')
        self.console, self.sender, self.task_id = console, sender, task_id
        self.sources = json.loads(canonical(sources))
        self.continuation = json.loads(canonical(continuation))
        self.policy = console.current_policy()
        self.started_at = self.last_time = console.now()
        self.stage, self.pending, self.family = 0, None, None
        self._family_identity = None
        self._issue_key = object()
        self._products, self._receipts, self._provenance, self._requests = {}, {}, {}, {}

    def current(self):
        now = self.console.now()
        require(type(now) is int and now >= self.last_time, 'semantic_time_reversal')
        self.last_time = now
        require(self.started_at <= now < self.started_at + 3600, 'semantic_run_time')
        for role, (observation, frozen) in self._receipts.items():
            require(canonical(asdict(observation)) == frozen, 'semantic_predecessor_mutated')
            request = self._requests[role]
            require(self.sender._emitted_for(request, observation, request.body), 'semantic_predecessor_origin_changed')
            if role in self._products:
                require(self._products[role] == canonical(observation.value)
                    and self._provenance[role] == self.provenance(role, observation, frozen),
                    'semantic_accepted_product_or_provenance_changed')
        sources = self.console.intake.read()
        keys = ('source_ref', 'revision', 'sha256', 'text')
        require([{key: row[key] for key in keys} for row in sources] ==
            [{key: row[key] for key in keys} for row in self.sources], 'semantic_source_changed')
        require(self.console.current_policy() == self.policy, 'semantic_policy_changed')
        if self.stage > 0:
            require(self.family is self._family_identity and self.family is not None,
                'semantic_current_family_missing_or_foreign')
            validate_source_family(self.family, sources, task_id=self.task_id, topic=TOPIC,
                goal=GOAL, criterion=CRITERION, root_id=ROOT_ID, now=now, policy=self.policy)
            require(self.family.product == json.loads(self._products['orchestrator'])
                and self.family.provenance == self._provenance['orchestrator']
                and self.family.scope['continuation'] == self.continuation,
                'semantic_family_actual_predecessor')
        return now

    def expected(self, role):
        require(role == ('orchestrator', 'architect', 'critic')[self.stage], 'semantic_stage_order')
        if role == 'orchestrator':
            context = orchestrator_context(self.sources, task_id=self.task_id, topic=TOPIC,
                goal=GOAL, root_id=ROOT_ID, continuation=self.continuation)
            schema = role_schema(role, task_id=self.task_id, topic=TOPIC, continuation=self.continuation)
        else:
            require('orchestrator' in self._receipts and self.family is not None, 'semantic_actual_predecessor_missing')
            candidate = None if role == 'architect' else json.loads(self._products['architect'])
            if role == 'critic':
                require('architect' in self._receipts, 'semantic_actual_architect_missing')
                validate_architect(candidate, self.sources, self.family.projection,
                    task_id=self.task_id, topic=TOPIC, continuation=self.continuation)
            context = downstream_context(role, self.family.projection, goal=GOAL, candidate=candidate)
            schema = role_schema(role, task_id=self.task_id, topic=TOPIC,
                projection=self.family.projection, candidate=candidate, continuation=self.continuation)
        return canonical(context).decode('utf-8'), schema

    def issue(self, role):
        from .openai_plan_transport import build_request_body
        require(self.pending is None and self.stage < 3, 'semantic_pending_request')
        self.current()
        context, schema = self.expected(role)
        request = RoleRequest(self, role, context, canonical(schema),
            build_request_body(role=role, context=context, output_schema=schema), self._issue_key)
        self.pending = request
        return request

    def validate_request(self, request, *, sender, role, context, output_schema, body):
        from .openai_plan_transport import build_request_body
        require(type(request) is RoleRequest and request is self.pending
            and request._run is self and request._issue_key is self._issue_key
            and sender is self.sender, 'semantic_runtime_request_origin')
        self.current()
        expected_context, expected_schema = self.expected(role)
        require(request.role == role and context == request.context == expected_context
            and canonical(output_schema) == request.schema_bytes == canonical(expected_schema),
            'semantic_exact_context_schema')
        require(type(body) is bytes and body == request.body == build_request_body(
            role=role, context=expected_context, output_schema=expected_schema), 'semantic_exact_wire_body')
        return {'pipeline_version': PIPELINE_VERSION, 'stage': self.stage, 'role': role,
            'predecessor_origin': 'NONE_INITIAL' if self.stage == 0 else 'TRANSPORT_EMITTED',
            'family_ref': None if self.family is None else self.family.family_ref,
            'body_sha256': digest(body)}

    def emit(self, request, *, sender, observation, body):
        self.validate_request(request, sender=sender, role=request.role, context=request.context,
            output_schema=json.loads(request.schema_bytes), body=body)
        require(sender._emitted_for(request, observation, body), 'semantic_transport_emission_origin')
        require(type(observation) is ProposalObservation and observation.outcome == 'COMPLETED'
            and observation.context_sha256 == digest(request.context.encode('utf-8'))
            and observation.wire_body_sha256 == digest(body)
            and request.role not in self._receipts, 'semantic_transport_observation_binding')
        self._receipts[request.role] = (observation, canonical(asdict(observation)))
        self._requests[request.role] = request

    def provenance(self, role, observation, frozen):
        return dict(producer_kind=ACTUAL_KINDS[role], role=role, task_id=self.task_id,
            root_id=ROOT_ID, context_sha256=observation.context_sha256,
            response_id=observation.response_id, reservation_id=observation.reservation_id,
            wire_body_sha256=observation.wire_body_sha256, observation_sha256=digest(frozen),
            product_sha256=digest(observation.value))

    def consume(self, request, observation):
        require(request is self.pending and request.role in self._receipts, 'semantic_transport_receipt_missing')
        actual, frozen = self._receipts[request.role]
        require(observation is actual and canonical(asdict(observation)) == frozen,
            'semantic_observation_replaced_or_mutated')
        self.current()
        role = request.role
        try:
            if role == 'orchestrator':
                product = validate_orchestrator(observation.value, self.sources, task_id=self.task_id,
                    topic=TOPIC, continuation=self.continuation)
            elif role == 'architect':
                product = validate_architect(observation.value, self.sources, self.family.projection,
                    task_id=self.task_id, topic=TOPIC, continuation=self.continuation)
            else:
                product = validate_critic(observation.value, json.loads(self._products['architect']),
                    task_id=self.task_id, topic=TOPIC)
        except ValueError as error:
            if type(error) is SemanticProductRefusal:
                refusal = SemanticProductRefusal(error.code, role=role,
                    text_budget=error.text_budget, completed_transport=True)
            elif type(error) is ValueError and len(error.args) == 1 \
                    and type(error.args[0]) is str and error.args[0] in SEMANTIC_CONTRACT_ERROR_CODES:
                refusal = SemanticProductRefusal(error.args[0], role=role, completed_transport=True)
            else:
                raise
            diagnostic = semantic_refusal_projection(refusal)
            require(diagnostic is not None and diagnostic['role'] == role, 'semantic_refusal_projection_shape')
            self.console.events.append({'stage': 'SEMANTIC_PRODUCT_REFUSED', **diagnostic})
            raise refusal from None
        provenance = self.provenance(role, observation, frozen)
        self._products[role], self._provenance[role] = canonical(product), provenance
        if role == 'orchestrator':
            self.family = source_context(product, provenance, self.sources, task_id=self.task_id,
                topic=TOPIC, goal=GOAL, criterion=CRITERION, root_id=ROOT_ID,
                transaction_id=document_transaction_id(self.task_id, TOPIC), now=self.console.now(),
                policy=self.policy, continuation=self.continuation,
                informational_profile=self.console.informational_profile)
            self._family_identity = self.family
            self.console.events.append({'stage': 'PRE_ARCHITECT_BSEP', 'family': source_family_witness(self.family)})
        self.console.events.append({'stage': 'SEMANTIC_ROLE', 'role': role,
            'context_sha256': digest(request.context.encode('utf-8')), 'product_sha256': digest(product),
            'observation': asdict(observation), 'producer_origin': 'CONFIGURED_TRANSPORT_EMITTED'})
        self.pending = None
        self.stage += 1

    def selection(self):
        require(self.stage == 3 and self.pending is None, 'semantic_complete_pipeline_required')
        self.current()
        for observation, frozen in self._receipts.values():
            require(canonical(asdict(observation)) == frozen, 'semantic_predecessor_mutated')
        candidate, critic = json.loads(self._products['architect']), json.loads(self._products['critic'])
        validate_critic(critic, candidate, task_id=self.task_id, topic=TOPIC)
        return SemanticSelection(candidate, self.family, critic,
            dict(pipeline_version=PIPELINE_VERSION, **self._provenance,
                candidate_sha256=digest(candidate), memory_origin=None))


class DocumentConsole:
    def __init__(self, project, *, semantic_provider=None, runtime_admitted=False, clock=None, semantic_receiver=None, continuation_enabled=False, informational_profile=False):
        self.clock = clock or time.time
        self.project = Path(project).resolve(strict=True)
        self.output = owned_directory(self.project, 'output')
        self.evidence = owned_directory(self.project, 'review/task_evidence')
        self.state = owned_directory(self.project, 'state')
        self.intake = ApprovedSourceStore(self.project)
        self.semantic_provider = semantic_provider
        self.semantic_receiver = semantic_receiver
        self.runtime_admitted = runtime_admitted
        require(type(continuation_enabled) is bool, 'controller_continuation_mode')
        self.continuation_enabled = continuation_enabled
        require(type(informational_profile) is bool and (not informational_profile or continuation_enabled),
            "informational_profile_requires_baseline")
        self.informational_profile = informational_profile
        self.task = None
        self.outcome = None
        self.events = []
        self.model_calls = 0
        self.memory = DocumentMemory(owned_directory(self.project, 'drs'), owning_root_id=ROOT_ID,
            root_review=root_review, validate_outcome=validate_outcome,
            validate_persisted_outcome=validate_persisted_outcome)

    def now(self):
        return int(self.clock())

    def current_policy(self):
        path = self.state / 'owned_effect_policy.json'
        require(not path.is_symlink(), 'effect_policy_symlink')
        value = json.loads(path.read_bytes())
        require(type(value) is dict and set(value) == {
            'save_allowed', 'consent_ref', 'valid_to', 'revision', 'workspace_ref'}, 'effect_policy_closed_fields')
        require(type(value['save_allowed']) is bool and type(value['valid_to']) is int
                and type(value['revision']) is int and value['revision'] >= 1
                and ((type(value['consent_ref']) is str and value['consent_ref'].startswith('permission:'))
                     or (self.informational_profile and value['consent_ref'] is None))
                and value['workspace_ref'] == 'radik:owned:output', 'effect_policy_shape')
        if self.informational_profile:
            require(value['save_allowed'] is False and value['consent_ref'] is None,
                'informational_current_no_effects_policy')
        return value

    def _checkpoint(self):
        value = {'schema': 'radik.checkpoint.v01', 'saved_at': self.now(),
            'task_id': None if self.task is None else self.task.task_id,
            'goal': GOAL, 'topic': TOPIC, 'criterion': CRITERION,
            'outcome': None if self.outcome is None else self.outcome.plain,
            'events': self.events, 'model_calls': self.model_calls,
            'authority_on_restart': 'NOT_RESTORED',
            'uncertain_save_policy': 'Read actual receipts/output before any retry; no automatic effect retry.'}
        target = self.state / 'checkpoint.json'
        require(not target.is_symlink(), 'checkpoint_symlink')
        temporary = target.with_suffix('.pending')
        require(not temporary.exists(), 'checkpoint_pending')
        with temporary.open('xb') as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, target)

    def _proposal(self, sources, task_id, supplied=None, *, continuation=None):
        require(supplied is None, 'direct_proposal_has_no_causal_role_chain')
        require(self.runtime_admitted and self.semantic_provider is not None, 'live_semantic_stage_not_admitted')
        run = SemanticRun(self, sources, task_id, continuation)
        for role in ('orchestrator', 'architect', 'critic'):
            request = run.issue(role)
            observation = self.semantic_provider(role=role, context=request.context,
                output_schema=json.loads(request.schema_bytes), role_request=request)
            self.model_calls += 1
            run.consume(request, observation)
        return run.selection()

    def _memory_selection(self, selected, sources, task_id):
        historical = selected.material['outcome']
        require(historical.get('version') == 'radik.document.result.v02'
            and historical.get('semantic_pipeline', {}).get('version') == PIPELINE_VERSION,
            'memory_requires_causal_v02_history')
        prior = historical['proposal']
        route = dict(version=ORCHESTRATOR_VERSION, task_id=task_id, topic=TOPIC,
            strategy=prior['strategy'], evidence_requests=[{key: claim[key] for key in
                ('source_ref', 'revision', 'sha256', 'start', 'end')} for claim in prior['claims']],
            uncertainty=prior['uncertainty'])
        route = validate_orchestrator(route, sources, task_id=task_id, topic=TOPIC)
        origin = memory_origin_from_selection(selected, evaluated_at=self.now())
        def provenance(role, product, context):
            return dict(producer_kind=MEMORY_KINDS[role], role=role, task_id=task_id, root_id=ROOT_ID,
                context_sha256=digest(context), response_id='NOT_CALLED:MEMORY',
                reservation_id='NOT_CALLED:MEMORY', wire_body_sha256='NOT_CALLED:MEMORY',
                observation_sha256=digest(historical), product_sha256=digest(product))
        orch_provenance = provenance('orchestrator', route, dict(memory_origin=origin, route=route))
        family = source_context(route, orch_provenance, sources, task_id=task_id, topic=TOPIC,
            goal=GOAL, criterion=CRITERION, root_id=ROOT_ID, transaction_id=document_transaction_id(task_id, TOPIC),
            now=self.now(), policy=self.current_policy())
        candidate = validate_architect(dict(prior, task_id=task_id), sources, family.projection,
            task_id=task_id, topic=TOPIC)
        critic = dict(version=CRITIC_VERSION, task_id=task_id, topic=TOPIC,
            candidate_sha256=digest(candidate), accepted=True, checks={key: True for key in CRITIC_CHECKS},
            uncertainty='Deterministic memory revalidation; no new provider observation or external truth.')
        critic = validate_critic(critic, candidate, task_id=task_id, topic=TOPIC)
        bundle = dict(pipeline_version=PIPELINE_VERSION, orchestrator=orch_provenance,
            architect=provenance('architect', candidate, dict(projection=family.projection, memory_origin=origin)),
            critic=provenance('critic', critic, dict(candidate=candidate, memory_origin=origin)),
            candidate_sha256=digest(candidate), memory_origin=origin)
        validate_source_family(family, self.intake.read(), task_id=task_id, topic=TOPIC,
            goal=GOAL, criterion=CRITERION, root_id=ROOT_ID, now=self.now(), policy=self.current_policy())
        self.events.append({'stage': 'DETERMINISTIC_MEMORY_SEMANTIC_SELECTION',
            'producer_kind': MEMORY_KINDS['orchestrator'], 'family': source_family_witness(family),
            'memory_origin': origin, 'model_calls': 0})
        return SemanticSelection(candidate, family, critic, bundle)

    def compare(self, *, research_proposal=None, task_id=None):
        require(self.task is None, 'controller_task_already_active')
        sources = self.intake.read()
        task_id = task_id or 'radik-task:' + uuid.uuid4().hex
        selected = None if self.informational_profile else self.memory.select(sources=sources, task_id=task_id, topic_id=TOPIC,
            intent=GOAL, criterion=CRITERION, now=self.now())
        selection = self._memory_selection(selected, sources, task_id) if selected is not None else \
            self._proposal(sources, task_id, research_proposal)
        task_dir = owned_directory(self.project, 'review/task_evidence/' + digest(task_id))
        self.task = build_task(task_id, TOPIC, GOAL, sources, selection.candidate, criterion=CRITERION,
            semantic_family=selection.family, critic_assessment=selection.critic, semantic_provenance=selection.provenance,
            continuation_enabled=self.continuation_enabled, informational_profile=self.informational_profile, root_id=ROOT_ID, clock=self.now, source_reader=self.intake.read,
            policy_reader=self.current_policy, workspace=self.output, evidence_directory=task_dir,
            on_event=self.events.append)
        self.outcome = consume_memory(self.task, selected) if selected is not None else run_task(self.task)
        record_id = self.memory.remember(outcome=self.outcome, sources=self.intake.read(), task_id=task_id,
            topic_id=TOPIC, intent=GOAL, criterion=CRITERION, now=self.now())
        completion = {'stage': 'WARM_WRITEBACK_READY' if selected is not None else 'COLD',
            'record_id': record_id, 'memory_selection': None if selected is None else asdict(selected),
            'model_calls': self.model_calls}
        self.events.append(completion)
        self._checkpoint()
        if selected is not None:
            self.events.append(dict(completion, stage='WARM', checkpoint_completed=True))
        return self.outcome

    def update(self, *, research_proposal=None):
        require(self.task is not None, 'controller_no_current_task')
        require(self.continuation_enabled and self.task.d_baseline is not None,
            'continuation_control_baseline_not_admitted_before_provider')
        policy = self.current_policy()
        if self.informational_profile:
            from .informational_document import require_no_effects
            require_no_effects(self.task.source)
        else:
            require(policy['save_allowed'] and self.now() < policy['valid_to'],
                    'continuation_requires_pending_save_policy_before_provider')
        require(self.task.delta_count == 0, 'one_delta_per_task')
        require(self.outcome is not None and self.task.accepted is self.outcome, 'continuation_actual_prior_result')
        sources = self.intake.read()
        # Verify the actual previously accepted result as historical data against
        # its original source bytes. This does not renew its Root or permission.
        prior = validate_persisted_outcome(self.outcome.plain, self.task.sources)
        continuation = build_continuation_projection(prior, self.task.sources, sources)
        self.events.append({'stage': 'CONTINUATION_DEPENDENCY', 'projection': continuation,
                            'projection_sha256': digest(continuation)})
        selection = self._proposal(sources, self.task.task_id, research_proposal, continuation=continuation)
        self.outcome = continue_task(self.task, sources, selection.candidate,
            semantic_family=selection.family, critic_assessment=selection.critic, semantic_provenance=selection.provenance)
        if self.informational_profile:
            from .informational_document import require_publication
            require_publication(self.task)
            record_id = self.memory.remember(outcome=self.outcome, sources=self.intake.read(),
                task_id=self.task.task_id, topic_id=TOPIC, intent=GOAL, criterion=CRITERION, now=self.now())
            self.events.append({'stage': 'INFORMATIONAL_DELTA_MEMORY_WRITEBACK', 'record_id': record_id})
        self.events.append({'stage': 'SOURCE_DELTA', 'model_calls': self.model_calls})
        self._checkpoint()
        return self.outcome

    def save(self, target):
        require(not self.informational_profile, "informational_profile_save_closed")
        require(self.task is not None and self.outcome is not None, 'controller_no_accepted_result')
        policy = self.current_policy()
        receipt = save_output(self.task, target, consent_ref=policy['consent_ref'])
        self.events.append({'stage': 'SAVE_OUTPUT', 'receipt': receipt})
        self._checkpoint()
        return receipt
