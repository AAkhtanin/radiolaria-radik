"""Finite native informational programs; no provider or effect executor.

The owned controller composes the public U1/U2 and G2C/G2D APIs. It does not
replace the kernel scheduler, nominal contracts, guards or Root decisions.
"""
from dataclasses import dataclass, replace
import json
from pathlib import Path
from contextlib import contextmanager
from threading import Event, Thread
import time

from hedgehog import action_commit_packet_v02 as action
from hedgehog import work_execution_host_v01 as hosts
from hedgehog.kernel import abi_v01 as abi, effect_firewall_v01 as firewall
from hedgehog.kernel import work_composition_v01 as work

from . import native_authority as authority
from .contracts import canonical, digest, require
from .dynamic_semantics import build_source_family, validate_current_family, source_family_witness
from .dynamic_control import build_control_source
from .dynamic_temporal import TEMPORAL_POLICY_VERSION, informational_valid_to, reuse_valid_to, utc_epoch_seconds
from .evidence import persist
from .task_spec import TaskSpec, meaning_key
from .dynamic_work import (_candidate, _decode, _compute, extract, business_result, exception_audit,
    revision_audit, validate_inputs, validate_outputs, execute_extract, execute_gate, execute_audit,
    execute_revision_gate, execute_revision_audit, execute_business)

MAX_ITEMS, MAX_CHILDREN, MAX_REVISIONS = 12, 2, 2
# Public U2 reserves the unchanged D policy's whole 21-cell ceiling before
# dispatch, then releases unused capacity. Actual application children stay 2.
MAX_NATIVE_CHILD_RESERVATIONS, MAX_NATIVE_CHILD_BUDGET, MAX_COMPUTE_UNITS = 20, 24, 32
MAX_RESULT_BYTES = 32768
E_INFORMATION_BLOCKER = 'dynamic_g2e_information_packet_unavailable'
_PROJECTION_SEAL = object()


def _copy(value):
    return json.loads(canonical(value))


def descriptors(sources):
    from .dynamic_roles import source_scope
    return source_scope(sources)
























def admit(operation, input_names, output_names, executor, host_ref, *, callbacks=None, version="v01"):
    callbacks = callbacks or (validate_inputs, validate_outputs, executor)
    snapshots = tuple(hosts.observe_local_capability_code_v01(callback) for callback in callbacks)
    definition = firewall.build_capability_definition_v01(operation_id=operation, version=version, effect_kind='PURE',
        business_semantics=None, input_fields=tuple(firewall.build_capability_field_v01(name=name, value_type='TEXT',
            required=True, consequential=False) for name in input_names),
        output_fields=tuple(firewall.build_capability_field_v01(name=name, value_type=value_type, required=True,
            consequential=False) for name, value_type in output_names), resource_refs=(),
        input_validator_ref=snapshots[0].public_symbol, output_validator_ref=snapshots[1].public_symbol,
        executor_ref=snapshots[2].public_symbol, code_sha256s=tuple((snap.public_symbol, snap.source_sha256) for snap in snapshots))
    return hosts.admit_local_capability_v01(definition=definition, input_validator=callbacks[0], output_validator=callbacks[1],
        executor=executor, catalogue_revision=0, host_instance_ref=host_ref)


class CurrentDynamicSource:
    """Trusted source read occurs outside PURE and before every native dispatch."""
    def __init__(self, controller):
        self.controller = controller
        now = controller.now()
        self.snapshot = hosts.TrustedWorkSourceSnapshotV01((), action.build_logical_time_bridge_v01(
            origin_utc_epoch_seconds=now, seconds_per_tick=1, bridge_policy_version='radik.dynamic.clock.v01'),
            now, 'radik:trusted_clock', controller.spec.task_id, 0)

    def read_current_v01(self):
        self.controller.current()
        now = self.controller.now()
        require(now >= self.snapshot.evaluation_time, 'dynamic_clock_regression')
        self.snapshot = replace(self.snapshot, evaluation_time=now,
            source_revision=self.snapshot.source_revision + int(now != self.snapshot.evaluation_time))
        return self.snapshot


def literal(name, value):
    return work.WorkInputBindingV01(name, work.WorkLiteralV01(action.build_action_effect_parameter_record_v01(
        parameter_name=name, value_type='TEXT', value=canonical(value).decode('utf-8'))))


@dataclass(frozen=True)
class NativeWorkProjection:
    _owner: object
    _plain: bytes
    _seal: object

    def plain(self):
        return json.loads(self._plain)

    def validate(self, spec, candidate, family):
        require(self._seal is _PROJECTION_SEAL and type(self._owner) is DynamicDocumentController
            and self._owner.spec == spec and self._owner.candidate == candidate and self._owner.family is family,
            'dynamic_work_projection_origin')
        self._owner.validate_native()
        require(self._plain == canonical(self._owner.projection_plain()), 'dynamic_work_projection_binding')
        return self


@dataclass(frozen=True)
class DynamicAcceptedResult:
    plain: dict
    controller: object
    projection: NativeWorkProjection


class DynamicDocumentController:
    """One selected task; all scheduling and revisions use the native host."""
    def __init__(self, project, client, *, task_spec, source_reader, policy_reader=None, clock=None,
                 on_event=None, memory=None, informational_delta=False, operation_deadline=None):
        require(type(task_spec) is TaskSpec and callable(source_reader), 'dynamic_controller_task')
        require(type(informational_delta) is bool, 'dynamic_informational_profile_type')
        self.informational_delta = informational_delta
        self.operation_deadline = operation_deadline
        self.informational_context = self.source_transition = self.source_transition_store = self.final_root = None
        self.project, self.client, self.spec = Path(project), client, task_spec
        self.source_reader = source_reader
        self.clock = clock or (lambda: int(time.time()))
        self._policy_reader = policy_reader
        self._default_policy = dict(save_allowed=False, consent_ref='radik:information_only',
            valid_to=informational_valid_to(self.now()), revision=1, workspace_ref='radik:owned:output')
        if informational_delta:
            from .normal_session import validate_operation
            operation = validate_operation(client.project, client.budget._normal_operation)
            require(operation['schema']=='radik.normal_operation.v02'
                and type(operation_deadline) is int
                and operation['opened_at'] < operation_deadline <= operation['opened_at']+7800,
                'dynamic_informational_operation_deadline')
            self._default_policy['consent_ref']=None
        self.on_event, self.events = on_event, []
        root_digest = digest(task_spec.task_id)[:24]
        self.root_id = 'root:radik:dynamic:' + ':'.join(root_digest[index:index + 8] for index in range(0, 24, 8))
        self.initial_sources, self.initial_policy = _copy(source_reader()), _copy(self.current_policy())
        require({row['source_ref'] for row in descriptors(self.initial_sources)} == set(task_spec.source_ids),
            'dynamic_controller_source_scope')
        self.family = self.candidate = self.role_run = self.program = self.host = None
        self.results, self.review_bindings, self.evidence_refs = (), (), []
        self.accepted, self.control_source, self.control_bundle, self.artifact = None, None, None, None
        self.intake_review = None
        self.memory_origin, self.memory_saved, self.native_revision = None, None, 0
        self.evidence_directory = self.project / 'review' / 'task_evidence' / digest(task_spec.task_id)
        self.evidence_directory.mkdir(parents=True, exist_ok=True)
        if memory is None:
            from .memory import DocumentMemory
            self.memory = DocumentMemory(self.project / 'state' / 'document_memory', owning_root_id='root:radik:dynamic_memory',
                root_review=authority.root_review, validate_outcome=validate_dynamic_outcome,
                validate_persisted_outcome=validate_persisted_dynamic_result, task_spec=task_spec)
        else:
            self.memory = memory

    def now(self):
        now = self.clock()
        require(type(now) is int and now >= self.spec.created_at, 'dynamic_controller_time')
        return now

    def current_policy(self):
        return _copy(self._policy_reader() if self._policy_reader is not None else self._default_policy)

    def emit(self, stage, **details):
        event = dict(stage=stage, task_id=self.spec.task_id, **details)
        self.events.append(event)
        if self.on_event is not None:
            self.on_event(_copy(event))

    def role_deadline(self, started_at):
        if not self.informational_delta:
            return started_at + 3600
        return min(self.operation_deadline,self.initial_policy['valid_to'])

    def source_successor_context(self):
        if self.source_transition is None:
            return None
        from .source_successor import validate
        _ref,row=validate(self.source_transition_store,self.source_transition,self.source_reader(),statuses=('STARTED','PLANNED'))
        require(type(self.accepted) is DynamicAcceptedResult and self.accepted.controller is self,
            'dynamic_source_successor_live_predecessor')
        prior=self.accepted.plain
        require(prior==self.source_transition_store.result(self.spec.task_id)
            and digest(prior['root'])==row['base']['prior_root_sha256']
            and prior['task']==self.spec.plain(), 'dynamic_source_successor_prior_root')
        changed=row['base']['changed_sources']
        return dict(staged_ref=self.source_transition.staged_ref,prior_result_id=prior['result_id'],
            prior_root_sha256=digest(prior['root']),route=prior['proposal']['program']['route'],
            retained_claims=[c for c in prior['proposal']['claims'] if c['source_ref'] not in changed],
            changed_sources=changed,contract='PRESERVE_EXACT_UNCHANGED_BRANCH_CLAIMS_OR_REQUIRE_NEW_INTAKE')

    def validate_source_transition_dispatch(self):
        if self.source_transition is not None:
            from .source_successor import validate
            validate(self.source_transition_store,self.source_transition,self.source_reader(),statuses=('STARTED','PLANNED'))
        return True

    def current(self):
        sources, policy, now = self.source_reader(), self.current_policy(), self.now()
        if self.informational_delta:
            require(now < self.operation_deadline,'dynamic_owner_operation_deadline')
        if self.source_transition is not None:
            from .source_successor import validate
            validate(self.source_transition_store,self.source_transition,sources,statuses=('STARTED','PLANNED','ACCEPTED'))

        require(descriptors(sources) == descriptors(self.initial_sources)
            and {row['source_ref']: row['text'] for row in sources} == {row['source_ref']: row['text'] for row in self.initial_sources},
            'dynamic_current_sources_changed')
        require(policy == self.initial_policy and policy['save_allowed'] is False and now < policy['valid_to'],
            'dynamic_current_policy_changed_or_expired')
        if self.family is not None:
            validate_current_family(self.family, sources, policy=policy, now=now)
        return sources

    def _persist(self, label, value):
        reference = persist(self.evidence_directory, label, value)
        self.evidence_refs.append(reference)
        return reference

    def admit_intake(self):
        """A genuine no-effect local Root boundary precedes O and DRS use."""
        self.current()
        if self.intake_review is None:
            material = dict(version='radik.dynamic.intake.v01', task=self.spec.plain(),
                sources=descriptors(self.initial_sources), policy=self.current_policy(),
                meaning_key=meaning_key(self.spec, self.initial_sources))
            review = authority.root_review('dynamic:intake:' + digest(material), material,
                dict(typed_intent=True, approved_current_sources=True, bounded_resources=True, no_effect_policy=True),
                self.now(), transaction_id='radik:dynamic_transaction:' + digest(self.spec.plain()),
                owning_root_id=self.root_id, task_id=self.spec.task_id)
            require(review[2].decision == 'ACCEPT' and not review[2].permission_created
                and not review[2].effect_requested, 'dynamic_intake_root_refused')
            self.intake_review = review
            self._persist('dynamic_intake_root', authority.root_plain(review))
            self.emit('DYNAMIC_INTAKE_ROOT_ACCEPTED', decision_id=review[2].decision_id)
        return self.intake_context()

    def intake_context(self):
        require(self.intake_review is not None, 'dynamic_intake_root_required')
        review = authority.root_plain(self.intake_review)
        require(self.intake_review[2].decision == 'ACCEPT', 'dynamic_intake_root_refused')
        return dict(intake_root_ref=self.intake_review[2].decision_id, intake_root_sha256=digest(review),
            task_spec_sha256=digest(self.spec.plain()), current_source_scope_sha256=digest(descriptors(self.initial_sources)))

    def _catalogue(self):
        host_ref = 'radik:dynamic_host:' + digest(self.spec.task_id)
        n = len(self.spec.source_ids)
        audit_enabled = self.candidate['program']['optional_exceptions'] and any(
            claim['kind'] == 'exception' for claim in self.candidate['claims'])
        prefix = 'radik.dynamic.' + self.spec.profile + '.'
        self.capabilities = dict(
            extract=admit('radik.dynamic.extract.v01', ('material',), (('material', 'TEXT'),), execute_extract, host_ref),
            gate=admit('radik.dynamic.exception_gate.v01', ('material',), (('enabled', 'BOOLEAN'),), execute_gate, host_ref),
            audit=admit('radik.dynamic.exception_audit.v01', ('material',), (('material', 'TEXT'),), execute_audit, host_ref),
            short=admit(prefix + 'short.v01', ('material',), (('result', 'TEXT'),), execute_business, host_ref),
            aggregate_plain=admit(prefix + 'aggregate.v01', ('material',) + tuple('branch' + str(index) for index in range(n)),
                (('result', 'TEXT'),), execute_business, host_ref),
            aggregate_audit=admit(prefix + 'aggregate.v01', ('material',) + tuple('branch' + str(index) for index in range(n)) + ('audit',),
                (('result', 'TEXT'),), execute_business, host_ref),
            revision=admit(prefix + 'revision.v01', ('material', 'previous'), (('result', 'TEXT'),), execute_business, host_ref),
            revision_audit_result=admit(prefix + 'revision.v01', ('material', 'previous', 'audit'),
                (('result', 'TEXT'),), execute_business, host_ref),
            revision_gate=admit('radik.dynamic.revision_gate.v01', ('material', 'previous'),
                (('enabled', 'BOOLEAN'),), execute_revision_gate, host_ref),
            revision_audit=admit('radik.dynamic.revision_audit.v01', ('material', 'previous'),
                (('material', 'TEXT'),), execute_revision_audit, host_ref),
            memory=admit(prefix + 'memory.v01', ('material',), (('result', 'TEXT'),), execute_business, host_ref))
        from . import dynamic_delta_work as full_delta
        self.capabilities['source_delta']=admit(prefix+'source_delta.v27',('material','previous'),(('result','TEXT'),),
            full_delta.execute,host_ref,callbacks=(full_delta.validate_inputs,full_delta.validate_outputs,full_delta.execute),version='v27')
        catalogue=tuple(self.capabilities.values())
        self.capabilities['aggregate']=self.capabilities['aggregate_audit' if audit_enabled else 'aggregate_plain']
        return catalogue

    def _material(self, mode):
        projection = self.family.projection
        finite = {key: projection[key] for key in ('route', 'source_scope_sha256', 'approved_evidence', 'family_ref')}
        return dict(mode=mode, task=self.spec.plain(), candidate=_copy(self.candidate), family=finite,
            intake=self.intake_context())

    def _item(self, name, capability, inputs, *, depends=(), guard=None):
        return work.WorkItemV01(name, self.capabilities[capability].definition.definition_id, self.root_id,
            tuple(inputs), (), tuple(depends), guard, None)

    def _initial_items(self, *, memory_material=None):
        if memory_material is not None:
            return (self._item('memory0', 'memory', (literal('material', memory_material),)),)
        route = self.candidate['program']['route']
        if route == 'short':
            return (self._item('short0', 'short', (literal('material', dict(self._material('short'), sources=self.initial_sources)),)),)
        items = []
        for index, source in enumerate(self.initial_sources):
            items.append(self._item('extract' + str(index), 'extract', (literal('material', dict(source=source,
                claims=[claim for claim in self.candidate['claims'] if claim['source_ref'] == source['source_ref']])),)))
        items.append(self._item('gate0', 'gate', (literal('material', self.candidate),)))
        exception_source = next((claim['source_ref'] for claim in self.candidate['claims'] if claim['kind'] == 'exception'),
            self.initial_sources[0]['source_ref'])
        index = next(index for index, source in enumerate(self.initial_sources) if source['source_ref'] == exception_source)
        items.append(self._item('audit0', 'audit', (work.WorkInputBindingV01('material',
            work.WorkOutputBindingV01('extract' + str(index), 'material', 'TEXT')),),
            depends=('extract' + str(index), 'gate0'), guard=work.WorkOutputBindingV01('gate0', 'enabled', 'BOOLEAN')))
        inputs = [literal('material', self._material('aggregate'))]
        branches = tuple('extract' + str(index) for index in range(len(self.initial_sources)))
        inputs.extend(work.WorkInputBindingV01('branch' + str(index), work.WorkOutputBindingV01(name, 'material', 'TEXT'))
            for index, name in enumerate(branches))
        if self.candidate['program']['optional_exceptions'] and any(claim['kind'] == 'exception' for claim in self.candidate['claims']):
            inputs.append(work.WorkInputBindingV01('audit', work.WorkOutputBindingV01('audit0', 'material', 'TEXT')))
            branches += ('audit0',)
        items.append(self._item('result0', 'aggregate', inputs, depends=branches))
        return tuple(items)

    def _candidate_program(self, items):
        return work.build_work_program_candidate_v01(task_id=self.spec.task_id, previous_revision_id=None,
            intent_ref=self.intent_ref, bsep_ref=self.family.source_context.bsep_packet['packet_id'],
            semantic_proposal_ref=self.semantic.artifact_id, catalogue_revision=0,
            budget=work.WorkBudgetV01(MAX_ITEMS, MAX_NATIVE_CHILD_BUDGET, 0, MAX_COMPUTE_UNITS, MAX_REVISIONS),
            items=tuple(items), trigger_evidence_refs=(), **self.common)

    def _start(self, *, memory_material=None):
        self.current()
        self.candidate = _candidate(self.spec, self.candidate, self.initial_sources, self.family.projection)
        catalogue = self._catalogue()
        self.intent_ref = 'radik:dynamic_intent:' + digest(self.spec.plain())
        now = self.now()
        self.semantic = abi.build_kernel_artifact_v01(abi_version='v1.0', artifact_id='dynamic:architect:' + digest(self.candidate),
            artifact_type='SemanticArchitectProposal', schema_version='v1', transaction_id=self.family.scope['transaction_id'],
            owner_root_id=self.root_id, source_component='semantic_architect', authority_class='ADVISORY', lifecycle_state='PROPOSED',
            payload=dict(task=self.spec.plain(), candidate=self.candidate, family_ref=self.family.family_ref),
            trace_refs=(self.intent_ref,), parent_refs=(self.family.source_context.bsep_packet['packet_id'],),
            time_envelope=dict(pt_created_at=authority.stamp(now), kt_asof=authority.stamp(now), et_observed_at=None,
                ct_session_anchor=self.spec.task_id, ttl_seconds=self.family.scope['valid_to'] - now, freshness_class='static',
                valid_from=authority.stamp(now), valid_to=authority.stamp(self.family.scope['valid_to'])))
        self.common = dict(catalogue=catalogue, source_context=self.family.source_context, semantic_proposal=self.semantic)
        candidate = self._candidate_program(self._initial_items(memory_material=memory_material))
        program = work.materialize_work_program_v01(candidate, **self.common)
        obligation = None
        if self.candidate['program']['route'] == 'nested':
            self.control_source, self.common = build_control_source(program, self.common,
                route='nested', now=self.now())
            candidate = self._candidate_program(candidate.items)
            item = candidate.items[-1]
            obligation = work.build_work_review_obligation_v01(candidate=candidate, item=item, source_context=self.control_source)
            item = replace(item, review_obligation_id=obligation.obligation_id)
            candidate = self._candidate_program((*candidate.items[:-1], item))
            obligation = work.build_work_review_obligation_v01(candidate=candidate, item=item, source_context=self.control_source)
        self.program = work.materialize_work_program_v01(candidate, **self.common)
        policy = work.build_work_task_policy_v01(candidate, **self.common, host_instance_ref=catalogue[0].host_instance_ref,
            definition_ids=tuple(sorted(cap.definition.definition_id for cap in catalogue)), resource_refs=())
        if obligation is not None:
            # Install a stricter requirement for both finite revision result
            # contracts as well as the initial reviewed business definition.
            policy = replace(policy, review_definition_ids=tuple(sorted(set(policy.review_definition_ids) | {
                self.capabilities['revision'].definition.definition_id,
                self.capabilities['revision_audit_result'].definition.definition_id,
                self.capabilities['aggregate_plain'].definition.definition_id,
                self.capabilities['aggregate_audit'].definition.definition_id,
                self.capabilities['source_delta'].definition.definition_id})))
            work.validate_installed_work_task_policy_v01(policy, owning_root_id=self.root_id, catalogue=catalogue)
        self.source = CurrentDynamicSource(self)
        snapshot = self.source.read_current_v01()
        self.host = hosts.build_root_work_execution_host_v01(owning_root_id=self.root_id,
            registry=action.build_empty_action_commit_packet_registry_v02(), catalogue=catalogue, packet_bindings=(),
            current_dependency_observations=(), logical_time_bridge=snapshot.logical_time_bridge,
            trusted_source=self.source, task_policies=(policy,))
        work.enroll_work_program_v01(self.host, self.program, **self.common, expected_revision=self.host.state_revision)
        if obligation is not None:
            self.emit('DYNAMIC_NATIVE_REVIEW_START', route='nested', native_child_reservation=MAX_NATIVE_CHILD_RESERVATIONS)
            with self._pulse('NATIVE_NESTED_REVIEW'):
                observed = work.execute_work_task_review_v01(self._context(), obligation=obligation,
                    source_context=self.control_source, semantic_proposal=self.semantic)
            require(type(observed) is tuple and len(observed) == 3, 'dynamic_required_control_not_observed')
            self.review_bindings = (observed,)
            self.control_bundle = observed[2]
            require(len(self.control_bundle.cell_results) == 3
                and max(result.cell_depth for result in self.control_bundle.cell_results) <= 1
                and self.control_bundle.runtime_report.parent_return_refs, 'dynamic_actual_child_bound')
            self._persist('dynamic_native_control', self.control_bundle)
            require(work.validate_work_review_binding_v01(obligation, candidate=candidate, item=candidate.items[-1],
                source_context=self.control_source, execution_bundle=self.control_bundle, semantic_proposal=self.semantic) == (True, ()),
                'dynamic_exact_work_control_binding')
        self._advance(self.program)

    @contextmanager
    def _pulse(self, stage):
        """Report actual elapsed activity without percentages or deadline changes."""
        done, started = Event(), time.monotonic()
        def report():
            while not done.wait(15):
                elapsed = int(time.monotonic() - started)
                self.emit('DYNAMIC_NATIVE_ACTIVITY', native_stage=stage, elapsed_seconds=elapsed)
                if self.on_event is None:
                    print('Нативная обработка: ' + stage + ', прошло ' + str(elapsed) + ' с.', flush=True)
        thread = Thread(target=report, name='radik-native-progress', daemon=True)
        thread.start()
        try:
            yield
        finally:
            done.set()
            thread.join()

    def _context(self):
        return work.work_continuation_context_v01(self.host, task_id=self.spec.task_id, expected_revision=self.host.state_revision)

    def _advance(self, program):
        self.current()
        self.emit('DYNAMIC_NATIVE_WORK_START', revision_id=program.candidate.revision_id)
        with self._pulse('NATIVE_WORK_REVISION' if self.native_revision else 'NATIVE_WORK'):
            outcome = work.advance_work_program_v01(program, **self.common, host_map={self.root_id: self.host},
                review_bindings=self.review_bindings, continuation_context=self._context())
        require(work.validate_work_continuation_outcome_v01(outcome, context=self._context(),
            review_bindings=self.review_bindings, **self.common) == (True, ()), 'dynamic_native_outcome_validation')
        require(outcome.status == 'COMPLETED' and all(result.status in ('COMPLETED', 'SKIPPED_GUARD_FALSE')
            for result in outcome.results), 'dynamic_native_work_not_completed')
        self.program, self.results = program, outcome.results
        self.artifact = work.work_program_result_to_artifact_v01(program, self.results, **self.common,
            host_map={self.root_id: self.host}, review_bindings=self.review_bindings, continuation_context=self._context())
        self._persist('dynamic_native_work', dict(program=program, results=self.results, artifact=self.artifact,
            admissions=tuple(firewall.snapshot_admitted_capability_v01(cap) for cap in self.common['catalogue']),
            history=work.inspect_work_task_history_v01(self._context()),
            host_events=self.host.events, completed_work=self.host.completed_work, reviews=self.review_bindings))
        self.emit('DYNAMIC_NATIVE_WORK_RETURN', revision_id=program.candidate.revision_id,
            result_artifact_ref=self.artifact.artifact_id, completed=sum(result.status == 'COMPLETED' for result in self.results),
            skipped=sum(result.status == 'SKIPPED_GUARD_FALSE' for result in self.results), provider_calls=0, effects=0)

    def validate_native(self):
        self.current()
        require(self.host is not None and self.artifact is not None and work.validate_work_program_result_v01(
            self.program, self.results, **self.common, host_map={self.root_id: self.host},
            review_bindings=self.review_bindings, continuation_context=self._context()) == (True, ()),
            'dynamic_native_actual_work_validation')
        require(self.host.registry.action_packet_lifecycle_entries == ()
            and self.host.registry.action_packet_fulfillment_attempt_contexts == (), 'dynamic_no_action_packet')
        return True

    def projection_plain(self):
        final = self.results[-1]
        require(final.status == 'COMPLETED', 'dynamic_actual_final_result')
        result = json.loads(authority.values(final.result.output)['result'])
        return dict(version='radik.dynamic.work_projection.v01', task_id=self.spec.task_id, profile=self.spec.profile,
            candidate_sha256=digest(self.candidate), source_scope_sha256=digest(descriptors(self.initial_sources)),
            family_ref=self.family.family_ref, business=result, native_revision=self.native_revision,
            revision_id=self.program.candidate.revision_id, result_artifact_ref=self.artifact.artifact_id,
            result_artifact_sha256=digest(authority.plain(self.artifact)), program_sha256=digest(authority.plain(self.program.candidate)),
            actual_results=[dict(work_id=value.work_id, status=value.status,
                invocation_id=value.invocation.invocation_id if value.invocation is not None else None,
                result_id=value.result.result_id if value.result is not None else None,
                invocation_sha256=digest(authority.plain(value.invocation)), result_sha256=digest(authority.plain(value.result)))
                for value in self.results], control=None if self.control_bundle is None else dict(mode=self.control_source.decision.accepted_mode,
                runtime_report_ref=self.control_bundle.runtime_report.report_id,
                parent_return_refs=list(self.control_bundle.runtime_report.parent_return_refs),
                cell_count=len(self.control_bundle.cell_results), actual_children_per_revision=MAX_CHILDREN,
                native_reservation_per_review=MAX_NATIVE_CHILD_RESERVATIONS,
                native_cumulative_child_budget=MAX_NATIVE_CHILD_BUDGET), provider_calls=0, effects=0)

    def _work_receipt(self):
        """Keep finite reconstruction data instead of copying source text or ancestry."""
        final = self.results[-1]
        invocation = authority.plain(final.invocation)
        data = _decode(final.invocation.inputs)
        material = dict(data['material'])
        for key in ('task', 'candidate', 'sources'):
            material.pop(key, None)
        if 'sources' in data['material']:
            material['source_observed_at'] = {source['source_ref']: source['observed_at']
                for source in data['material']['sources']}
        snapshot = firewall.snapshot_admitted_capability_v01(next(cap for cap in self.common['catalogue']
            if cap.admission_id == final.invocation.admission_id))
        snapshot_plain = authority.plain(snapshot)
        snapshot_plain.pop('code_sources')
        invocation.pop('inputs')
        return dict(version='radik.dynamic.actual_work_receipt.v01', snapshot=snapshot_plain,
            invocation=invocation, result=authority.plain(final.result), material_context=material,
            previous=data.get('previous'), inputs_sha256=firewall.capability_value_subject_sha256_v01(final.invocation.inputs))

    def projection(self):
        self.validate_native()
        result = canonical(self.projection_plain())
        require(len(result) <= 49152, 'dynamic_work_projection_budget')
        return NativeWorkProjection(self, result, _PROJECTION_SEAL)

    def _accept(self, projection, *, critic=None, provenance=None):
        projection.validate(self.spec, self.candidate, self.family)
        work_plain = projection.plain()
        now = self.now()
        if critic is not None:
            require(critic['verdict'] == 'ACCEPT' and all(check['passed'] for check in critic['checks'])
                and critic['candidate_sha256'] == digest(self.candidate)
                and critic['work_sha256'] == digest(work_plain), 'dynamic_critic_refused')
        checks = dict(actual_native_work=True, current_sources=True, no_effect=True,
            current_semantic_family=True, critic_checked=critic is not None or self.memory_origin is not None or self.native_revision > 0)
        accepted_at = self.memory_origin['accepted_at'] if self.memory_origin is not None else now
        semantic_time = abi.kernel_artifact_to_plain_dict_v01(self.semantic)['time_envelope']
        caps = dict(family=self.family.scope['valid_to'], policy=self.current_policy()['valid_to'],
            semantic_validity=utc_epoch_seconds(semantic_time['valid_to']),
            semantic_ttl=utc_epoch_seconds(semantic_time['pt_created_at']) + semantic_time['ttl_seconds'])
        if self.informational_delta:
            caps['owner_operation']=self.operation_deadline
        if self.control_source is not None:
            routing_time = self.control_source.router_input.local_routing_snapshot
            caps.update(routing_validity=utc_epoch_seconds(routing_time.valid_to_utc),
                routing_ttl=routing_time.evaluation_time_epoch_seconds + routing_time.ttl_seconds)
        if self.memory_origin is not None:
            caps['memory_origin'] = self.memory_origin['valid_to']
        valid_to = reuse_valid_to(accepted_at, *caps.values())
        require(accepted_at <= now < valid_to, 'dynamic_accepted_time')
        temporal = dict(version=TEMPORAL_POLICY_VERSION, accepted_at=accepted_at, valid_to=valid_to, caps=caps)
        receipt = self._work_receipt()
        compact_work = {key: value for key, value in work_plain.items() if key != 'business'}
        material = dict(task=self.spec.plain(), proposal_sha256=digest(self.candidate), work=compact_work,
            business_sha256=digest(work_plain['business']), actual_work_sha256=digest(receipt),
            critic=critic, memory_origin=self.memory_origin, native_revision=self.native_revision,
            intake=self.intake_context(), temporal_binding=temporal)
        root = authority.root_review('dynamic:result_candidate:' + digest(material), material, checks, now,
            transaction_id=self.family.scope['transaction_id'], owning_root_id=self.root_id, task_id=self.spec.task_id,
            bsep_ref=self.family.source_context.bsep_packet['packet_id'], topology_ref=self.program.topology_artifact.artifact_id)
        require(root[2].decision == 'ACCEPT', 'dynamic_final_root_refused')
        body = dict(version='radik.dynamic.result.v01', task_id=self.spec.task_id, task=self.spec.plain(),
            topic=self.spec.topic, goal=self.spec.goal, criterion=self.spec.criterion,
            sources=descriptors(self.initial_sources), proposal=_copy(self.candidate), proposal_sha256=digest(self.candidate),
            business=work_plain['business'], content=render_result(work_plain['business']), work=compact_work,
            actual_work=receipt,
            root=authority.root_plain(root), root_material_sha256=digest(material),
            root_context=dict(reviewed_at=now, transaction_id=self.family.scope['transaction_id'], root_id=self.root_id,
                bsep_ref=self.family.source_context.bsep_packet['packet_id'], topology_ref=self.program.topology_artifact.artifact_id),
            semantic_pipeline=dict(version='radik.dynamic.pipeline.v01', family_ref=self.family.family_ref,
                native_sha256=self.family.native_sha, provenance=provenance or {}, critic=critic,
                memory_origin=self.memory_origin, native_revision=self.native_revision, intake=self.intake_context()),
            accepted_at=accepted_at, valid_to=valid_to, temporal_binding=temporal, evidence_refs=list(self.evidence_refs))
        body['result_id'] = 'radik:dynamic_result:' + digest(dict(task=self.spec.task_id,
            artifact=self.artifact.artifact_id, root=root[2].decision_id))
        body['result_sha256'] = digest(body)
        require(len(canonical(body)) <= 131072, 'dynamic_accepted_result_budget')
        from .memory import memory_payload_bytes
        memory_payload_bytes(body, self.initial_sources, task_id=self.spec.task_id, topic_id=self.spec.topic,
            intent=self.spec.goal, criterion=self.spec.criterion, task_spec=self.spec,
            stage='ACCEPTED_RESULT_PREPUBLICATION')
        self.final_root = root
        self.accepted = DynamicAcceptedResult(body, self, projection)
        self._persist('accepted_dynamic_result', body)
        self.emit('DYNAMIC_RESULT_ACCEPTED', result_id=body['result_id'], profile=self.spec.profile)
        return self.accepted

    def _remember(self, outcome):
        record = self.memory.remember(outcome=outcome, sources=self.initial_sources, task_id=self.spec.task_id,
            topic_id=self.spec.topic, intent=self.spec.goal, criterion=self.spec.criterion, now=self.now())
        self.emit('DYNAMIC_MEMORY_WRITEBACK', record_id=record, checked_readback=True)
        return outcome

    def run(self, *, require_memory=False):
        require(type(require_memory) is bool, 'dynamic_memory_requirement_type')
        require(self.host is None, 'dynamic_task_already_started')
        self.current()
        self.admit_intake()
        selection = self.memory.select(sources=self.initial_sources, task_id=self.spec.task_id,
            topic_id=self.spec.topic, intent=self.spec.goal, criterion=self.spec.criterion, now=self.now())
        if selection is not None:
            return self.warm(selection)
        require(not require_memory, 'dynamic_qualified_memory_required')
        from .dynamic_roles import DynamicRoleRun
        self.role_run = DynamicRoleRun(self, self.spec, self.initial_sources)
        try:
            for role in ('orchestrator', 'architect'):
                request = self.role_run.issue(role)
                observation = self.client.propose(role=role, context=request.context, output_schema=json.loads(request.schema_bytes), role_request=request)
                self.role_run.consume(request, observation)
                if role == 'orchestrator':
                    self._persist('dynamic_source_family', source_family_witness(self.role_run.family))
            self.family, self.candidate = self.role_run.family, self.role_run.candidate
            self._start()
            projection = self.projection()
            self.role_run.bind_native_work(projection)
            request = self.role_run.issue('critic')
            observation = self.client.propose(role='critic', context=request.context, output_schema=json.loads(request.schema_bytes), role_request=request)
            self.role_run.consume(request, observation)
            outcome = self._accept(projection, critic=self.role_run.critic, provenance=self.role_run.provenance)
        except BaseException:
            self.emit('DYNAMIC_TASK_STOPPED', accepted=False)
            raise
        return self._remember(outcome)

    def warm(self, selection):
        from .memory import MemorySelection, memory_origin_from_selection
        require(self.host is None and type(selection) is MemorySelection, 'dynamic_memory_selection_type')
        self.current()
        self.admit_intake()
        saved = validate_persisted_dynamic_result(selection.material['outcome'], self.initial_sources, now=self.now())
        require(selection.material['meaning_key'] == meaning_key(self.spec, self.initial_sources)
            and digest(selection.material) == selection.payload_sha256
            and selection.descent['opened_record_ids'] == [selection.record_id]
            and selection.descent['opened_payload_fingerprints'] == [selection.payload_sha256]
            and selection.descent['bytes_opened'] == len(canonical(selection.material))
            and selection.descent['executed_descent_class'] == 'OPEN_ONE_ARTIFACT'
            and selection.descent['limits_respected'] and not selection.descent['reason_codes']
            and selection.root_decision_id != selection.historical_root_decision_id, 'dynamic_memory_actual_descent')
        prior_spec = TaskSpec.from_plain(saved['task'])
        require(meaning_key(prior_spec, self.initial_sources) == meaning_key(self.spec, self.initial_sources), 'dynamic_memory_meaning')
        selection_origin = memory_origin_from_selection(selection, evaluated_at=self.now())
        self.candidate = dict(saved['proposal'], task_id=self.spec.task_id,
            program=dict(saved['proposal']['program'], route='short'))
        self.native_revision = saved['work']['native_revision']
        self.memory_origin = dict(record_id=selection.record_id, payload_sha256=selection.payload_sha256,
            descent_id=selection.descent['memory_descent_result_id'], root_decision_id=selection.root_decision_id,
            prior_task_id=saved['task_id'], result_id=saved['result_id'], accepted_at=saved['accepted_at'],
            valid_to=min(saved['valid_to'], selection_origin['record_clocks']['valid_to']),
            meaning_key=meaning_key(self.spec, self.initial_sources), historical_valid_to=saved['valid_to'],
            historical_route=saved['proposal']['program']['route'], selection_origin=selection_origin)
        product = dict(version='radik.dynamic.role.orchestrator.v01', task_id=self.spec.task_id,
            profile=self.spec.profile, criterion=self.spec.criterion, source_scope_sha256=digest(descriptors(self.initial_sources)),
            route=self.candidate['program']['route'], evidence_requests=[{key: claim[key]
                for key in ('source_ref', 'revision', 'sha256', 'start', 'end')} for claim in self.candidate['claims']],
            uncertainty=self.candidate['uncertainty'])
        provenance = dict(producer_kind='DETERMINISTIC_MEMORY_ROUTE', role='orchestrator', task_id=self.spec.task_id,
            product_sha256=digest(product), memory_origin=_copy(self.memory_origin))
        self.family = build_source_family(self.spec, product, provenance, self.initial_sources,
            policy=self.current_policy(), now=self.now(), root_id=self.root_id)
        self._persist('dynamic_source_family', source_family_witness(self.family))
        material = dict(self._material('memory'), sources=self.initial_sources, evaluated_at=self.now(),
            memory_origin=_copy(self.memory_origin), prior={key: saved[key] for key in
                ('proposal', 'business', 'result_id', 'result_sha256', 'accepted_at', 'valid_to')})
        self._persist('dynamic_memory_selection', selection)
        self._start(memory_material=material)
        outcome = self._accept(self.projection(), provenance=provenance)
        self._remember(outcome)
        self.emit('DYNAMIC_WARM_COMPLETE', record_id=selection.record_id, provider_calls=0,
            original_accepted_at=saved['accepted_at'], original_valid_to=saved['valid_to'])
        return outcome

    def revise(self, condition_update):
        """Consume the exact latest native output under the original U2 policy."""
        require(self.accepted is not None and self.memory_origin is None, 'dynamic_revision_requires_live_task')
        self.current()
        previous_revision = self.program.candidate.revision_id
        prior = self.results[-1]
        historical = work.build_work_historical_output_v01(self._context(), revision_id=previous_revision,
            work_id=prior.work_id, output_field='result')
        trigger = work.build_work_revision_trigger_v01(self._context(), work_id=prior.work_id, output_field='result')
        material = dict(self._material('revision'), condition_update=_copy(condition_update))
        number = self.native_revision + 1
        previous = json.loads(historical.value.value)
        enabled = revision_audit(material, previous) is not None
        gate_id, audit_id = 'revision_gate' + str(number), 'revision_audit' + str(number)
        gate = self._item(gate_id, 'revision_gate', (literal('material', material),
            work.WorkInputBindingV01('previous', historical)))
        audit = self._item(audit_id, 'revision_audit', (literal('material', material),
            work.WorkInputBindingV01('previous', historical)), depends=(gate_id,),
            guard=work.WorkOutputBindingV01(gate_id, 'enabled', 'BOOLEAN'))
        inputs = [literal('material', material), work.WorkInputBindingV01('previous', historical)]
        dependencies = (gate_id,)
        if enabled:
            inputs.append(work.WorkInputBindingV01('audit', work.WorkOutputBindingV01(audit_id, 'material', 'TEXT')))
            dependencies += (audit_id,)
        item = self._item('revision_result' + str(number), 'revision_audit_result' if enabled else 'revision',
            inputs, depends=dependencies)
        revision_items = (gate, audit, item)
        snapshot = self._context().snapshot
        remaining = MAX_COMPUTE_UNITS - snapshot.usage.compute_units
        remaining_children = MAX_NATIVE_CHILD_BUDGET - snapshot.usage.children - snapshot.usage.reserved_children
        revised_budget = work.WorkBudgetV01(MAX_ITEMS, remaining_children, 0, max(1, remaining), max(0, MAX_REVISIONS - number))
        obligation = None
        if self.candidate['program']['route'] == 'nested' and number <= MAX_REVISIONS:
            # The installed policy requires a declared review even for the
            # preview. Replace this marker with the exact fresh obligation
            # before enrollment; it is never an observed review receipt.
            item = replace(item, review_obligation_id='review:pending_source')
            contextual = replace(self._context(), trigger=trigger)
            def proposed_candidate(current_item):
                return work.build_work_program_candidate_v01(task_id=self.spec.task_id,
                    previous_revision_id=previous_revision, intent_ref=self.intent_ref,
                    bsep_ref=self.program.candidate.bsep_ref, semantic_proposal_ref=self.semantic.artifact_id,
                    catalogue_revision=0, budget=revised_budget, items=(*revision_items[:-1], current_item), trigger_evidence_refs=(trigger.trigger_id,),
                    continuation_context=contextual, **self.common)
            candidate = proposed_candidate(item)
            program = work.materialize_work_program_v01(candidate, continuation_context=contextual, **self.common)
            control_source, revised_common = build_control_source(program, self.common, route='nested', now=self.now())
            self.common = revised_common
            candidate = proposed_candidate(item)
            obligation = work.build_work_review_obligation_v01(candidate=candidate, item=item, source_context=control_source)
            item = replace(item, review_obligation_id=obligation.obligation_id)
            candidate = proposed_candidate(item)
            obligation = work.build_work_review_obligation_v01(candidate=candidate, item=item, source_context=control_source)
        proposed = work.revise_work_program_v01(self._context(), previous_revision_id=previous_revision,
            trigger=trigger, items=(*revision_items[:-1], item), budget=revised_budget, **self.common)
        if proposed.status == 'EXHAUSTED':
            self.emit('DYNAMIC_REVISION_EXHAUSTED', reason=proposed.reason)
            return proposed
        self.native_revision = number
        if obligation is not None:
            self.control_source = control_source
            self.emit('DYNAMIC_NATIVE_REVIEW_START', route='nested', native_child_reservation=MAX_NATIVE_CHILD_RESERVATIONS)
            with self._pulse('NATIVE_NESTED_REVISION_REVIEW'):
                observed = work.execute_work_task_review_v01(self._context(), obligation=obligation,
                    source_context=control_source, semantic_proposal=self.semantic)
            require(type(observed) is tuple and len(observed) == 3 and len(observed[2].cell_results) == 3
                and max(result.cell_depth for result in observed[2].cell_results) <= 1,
                'dynamic_revision_control_not_observed')
            self.review_bindings = (observed,)
            self.control_bundle = observed[2]
            self._persist('dynamic_native_control', self.control_bundle)
        self._advance(proposed.program)
        outcome = self._accept(self.projection(), provenance=dict(producer_kind='NATIVE_U2_ZERO_CALL_ONLY',
            trigger=authority.plain(trigger)))
        return self._remember(outcome)

    def prepare_source_continuation(self):
        require(self.informational_delta, 'dynamic_informational_profile_required')
        from .dynamic_delta import prepare
        return prepare(self)

    def plan_source_successor(self, sources):
        require(self.informational_delta, 'dynamic_informational_profile_required')
        from .dynamic_delta import initial_plan
        return initial_plan(self,sources)

    def update_sources(self, sources=None, *, store=None, source_transition=None):
        require(self.informational_delta and sources is not None and store is not None and source_transition is not None,
            'dynamic_explicit_source_successor_required')
        from .dynamic_delta import continue_sources
        return continue_sources(self,sources,store=store,source_transition=source_transition)

    def snapshot(self):
        return dict(task=self.spec.plain(), started=self.host is not None,
            native_revision=self.native_revision, events=_copy(self.events), memory_events=_copy(self.memory.events),
            result=None if self.accepted is None else _copy(self.accepted.plain), evidence_refs=_copy(self.evidence_refs),
            g2e_information_status='CURRENT_TYPED_ORIGIN_READY' if self.informational_context is not None else 'NO_CURRENT_ORIGIN')


def render_result(result):
    lines = [result['statement'], '', 'Основания и границы:']
    if result['profile'] == 'compare':
        claims = [claim for branch in result['sources'] for claim in branch['selected']]
    elif result['profile'] == 'explain':
        claims = [claim for key in ('obligations', 'conditions', 'exceptions', 'unknowns') for claim in result[key]]
    else:
        lines.append('Проверяемое утверждение: ' + result['supplied_candidate'])
        claims = [claim for key in ('supporting_evidence', 'contradicting_evidence', 'qualifications') for claim in result[key]]
    for claim in claims:
        lines.append(claim['source_ref'] + ' [' + str(claim['start']) + ':' + str(claim['end']) + '] ' + claim['quote'])
    if 'revision_focus' in result:
        lines.append('Уточнение: ' + result['revision_focus']['kind'])
    lines.extend(('', 'Неопределённость: ' + result['uncertainty'],
        'Проверены точные байты цитат и источники. Внешняя истинность и смысловое следование не удостоверены.'))
    content = '\n'.join(lines) + '\n'
    require(len(content.encode('utf-8')) <= 49152, 'dynamic_render_budget')
    return content


def validate_dynamic_outcome(outcome, sources):
    require(type(outcome) is DynamicAcceptedResult and outcome.controller.accepted is outcome,
        'dynamic_live_outcome_origin')
    controller = outcome.controller
    outcome.projection.validate(controller.spec, controller.candidate, controller.family)
    require(descriptors(sources) == descriptors(controller.initial_sources), 'dynamic_live_outcome_sources')
    value = validate_persisted_dynamic_result(outcome.plain, sources)
    require(value['work'] == {key: item for key, item in outcome.projection.plain().items() if key != 'business'},
        'dynamic_live_outcome_work')
    return value


def _historical_work(value, spec, candidate, sources):
    """Reconstruct exact inputs, then use native identity/contract validators.

    Current reviewed callback code must equal the recorded admission. This
    creates no admission or execution and never installs a historical Host.
    """
    receipt = value['actual_work']
    require(type(receipt) is dict and set(receipt) == {'version', 'snapshot', 'invocation', 'result',
        'material_context', 'previous', 'inputs_sha256'} and receipt['version'] == 'radik.dynamic.actual_work_receipt.v01',
        'dynamic_saved_actual_work_shape')
    context = _copy(receipt['material_context'])
    mode = context['mode']
    require(mode in ('short', 'aggregate', 'revision', 'memory', 'source_delta'), 'dynamic_saved_operation')
    material = dict(context, task=spec.plain(), candidate=candidate)
    if mode in ('short', 'memory', 'source_delta'):
        observed = material.pop('source_observed_at')
        require(set(observed) == set(spec.source_ids) and all(type(item) is int and item >= 0
            for item in observed.values()), 'dynamic_saved_observation_clocks')
        material['sources'] = [dict(source, observed_at=observed[source['source_ref']]) for source in sources]
    data = dict(material=material)
    if mode == 'source_delta':
        data['previous']=receipt['previous']
    elif mode == 'aggregate':
        for index, source in enumerate(sources):
            data['branch' + str(index)] = extract(dict(source=source, claims=[claim for claim in candidate['claims']
                if claim['source_ref'] == source['source_ref']]))
        audit = exception_audit(candidate, [data['branch' + str(index)] for index in range(len(sources))])
        if audit is not None:
            data['audit'] = audit
    elif mode == 'revision':
        data['previous'] = receipt['previous']
        audit = revision_audit(material, data['previous'])
        if audit is not None:
            data['audit'] = audit
    else:
        require(receipt['previous'] is None, 'dynamic_saved_no_previous')
    inputs = authority.records({name: ('TEXT', canonical(item).decode('utf-8')) for name, item in data.items()})
    require(receipt['inputs_sha256'] == firewall.capability_value_subject_sha256_v01(inputs), 'dynamic_saved_actual_inputs')
    snapshot_data = receipt['snapshot']
    definition_data = snapshot_data['definition']
    operation = 'radik.dynamic.' + spec.profile + '.' + mode + ('.v27' if mode=='source_delta' else '.v01')
    version='v27' if mode=='source_delta' else 'v01'
    require(definition_data['operation_id'] == operation and definition_data['version'] == version
        and definition_data['effect_kind'] == 'PURE' and definition_data['business_semantics'] is None,
        'dynamic_saved_capability_profile')
    def field(item):
        return firewall.CapabilityFieldV01(**dict(item, allowed_values=tuple(item['allowed_values'])))
    definition = firewall.build_capability_definition_v01(operation_id=operation, version=version, effect_kind='PURE',
        business_semantics=None, input_fields=tuple(field(item) for item in definition_data['input_fields']),
        output_fields=tuple(field(item) for item in definition_data['output_fields']), resource_refs=(),
        input_validator_ref=definition_data['input_validator_ref'], output_validator_ref=definition_data['output_validator_ref'],
        executor_ref=definition_data['executor_ref'], code_sha256s=tuple(tuple(pair) for pair in definition_data['code_sha256s']))
    require(authority.plain(definition) == definition_data
        and tuple(item.name for item in definition.input_fields) == tuple(sorted(data))
        and tuple((item.name, item.value_type) for item in definition.output_fields) == (('result', 'TEXT'),),
        'dynamic_saved_capability_contract')
    from . import dynamic_delta_work as full_delta
    callbacks=(full_delta.validate_inputs,full_delta.validate_outputs,full_delta.execute) if mode=='source_delta' else (validate_inputs,validate_outputs,execute_business)
    compute=(lambda _operation,data:full_delta.compute(data)) if mode=='source_delta' else _compute
    codes = tuple(hosts.observe_local_capability_code_v01(callback) for callback in callbacks)
    require(tuple(sorted((code.public_symbol, code.source_sha256) for code in codes)) == definition.code_sha256s,
        'dynamic_saved_reviewed_callback_identity')
    snapshot = firewall.CapabilityAdmissionSnapshotV01(**dict(snapshot_data, definition=definition,
        code_sources=tuple(sorted(codes, key=lambda code: code.public_symbol))))
    require(not firewall.validate_capability_admission_snapshot_v01(snapshot), 'dynamic_saved_admission_identity')
    def evidence(item):
        return firewall.CapabilityValidationEvidenceV01(**dict(item, reason_codes=tuple(item['reason_codes'])))
    invocation_data = receipt['invocation']
    invocation = firewall.BoundCapabilityInvocationV01(**dict(invocation_data, inputs=inputs,
        resource_refs=tuple(invocation_data['resource_refs']), input_validation=evidence(invocation_data['input_validation'])))
    result_data = receipt['result']
    outputs = tuple(action.build_action_effect_parameter_record_v01(**item) for item in result_data['output'])
    result = firewall.CapabilityExecutionResultV01(**dict(result_data, output=outputs,
        output_validation=evidence(result_data['output_validation'])))
    require(invocation.task_id == spec.task_id and invocation.candidate_id is invocation.packet_id is None
        and invocation.owning_root_id == value['root_context']['root_id']
        and not firewall.validate_capability_execution_result_v01(result, invocation, snapshot)
        and result.outcome == 'SUCCEEDED', 'dynamic_saved_native_result_identity')
    require(authority.plain(callbacks[0](definition, inputs)) == invocation_data['input_validation']
        and authority.plain(callbacks[1](definition, invocation, outputs)) == result_data['output_validation']
        and authority.values(outputs) == compute(operation, data)
        and json.loads(authority.values(outputs)['result']) == value['business'], 'dynamic_saved_actual_output')
    last = value['work']['actual_results'][-1]
    require(last['invocation_id'] == invocation.invocation_id and last['result_id'] == result.result_id
        and last['invocation_sha256'] == digest(authority.plain(invocation))
        and last['result_sha256'] == digest(authority.plain(result)), 'dynamic_saved_receipt_projection')
    return receipt


def _validate_saved_time_binding(value):
    """Check historical time evidence without restoring policy or authority."""
    accepted_at, valid_to = value['accepted_at'], value['valid_to']
    reviewed_at = value['root_context']['reviewed_at']
    origin = value['semantic_pipeline']['memory_origin']
    require(type(reviewed_at) is int and accepted_at <= reviewed_at < valid_to, 'dynamic_saved_time_binding')
    if origin is None:
        require(accepted_at == reviewed_at, 'dynamic_saved_time_binding')
    else:
        require(accepted_at == origin['accepted_at'] and valid_to <= origin['valid_to']
            and origin['valid_to'] <= min(origin['historical_valid_to'],
                origin['selection_origin']['record_clocks']['valid_to']), 'dynamic_saved_time_binding')
    if 'temporal_binding' not in value:
        # Before this policy, fresh results used a 600-second maximum. Actual
        # historical record envelopes remain independently checked by DRS.
        require(origin is not None or valid_to <= reviewed_at + 600, 'dynamic_saved_time_binding')
        return
    temporal = value['temporal_binding']
    require(type(temporal) is dict and set(temporal) == {'version', 'accepted_at', 'valid_to', 'caps'}
        and temporal['version'] == TEMPORAL_POLICY_VERSION
        and temporal['accepted_at'] == accepted_at and temporal['valid_to'] == valid_to,
        'dynamic_saved_time_binding')
    caps = temporal['caps']
    required = {'family', 'policy', 'semantic_validity', 'semantic_ttl'}
    optional = {'routing_validity', 'routing_ttl'}
    expected = required | (optional if type(caps) is dict and optional & set(caps) else set()) \
        | ({'memory_origin'} if origin is not None else set()) \
        | ({'owner_operation'} if type(caps) is dict and 'owner_operation' in caps else set())
    require(type(caps) is dict and set(caps) == expected
        and all(type(cap) is int and reviewed_at < cap for cap in caps.values())
        and caps['family'] <= caps['policy']
        and caps['semantic_validity'] <= caps['family'] and caps['semantic_ttl'] <= caps['family'],
        'dynamic_saved_time_binding')
    if optional <= set(caps):
        require(caps['routing_validity'] <= caps['semantic_validity']
            and caps['routing_ttl'] <= caps['semantic_ttl'], 'dynamic_saved_time_binding')
    require((origin is None or caps['memory_origin'] == origin['valid_to'])
        and valid_to == reuse_valid_to(accepted_at, *caps.values()), 'dynamic_saved_time_binding')


def validate_persisted_dynamic_result(value, sources, now=None):
    """Historical data validation restores no callback, Host, Root or permission."""
    require(type(value) is dict and value.get('version') == 'radik.dynamic.result.v01'
        and len(canonical(value)) <= 131072, 'dynamic_saved_shape_budget')
    spec = TaskSpec.from_plain(value['task'])
    require(value['task_id'] == spec.task_id and value['topic'] == spec.topic and value['goal'] == spec.goal
        and value['criterion'] == spec.criterion and value['sources'] == descriptors(sources), 'dynamic_saved_scope')
    candidate = _candidate(spec, value['proposal'], sources)
    branches = [extract(dict(source=source, claims=[claim for claim in candidate['claims']
        if claim['source_ref'] == source['source_ref']])) for source in sources]
    result = business_result(spec, candidate, branches)
    stored = value['business']
    if 'revision_focus' in stored:
        require(value['work']['native_revision'] > 0 and all(stored[key] == expected for key, expected in result.items()),
            'dynamic_saved_revision_business')
        focus = stored['revision_focus']
        require(focus['kind'] in ('focus_conditions', 'focus_exceptions', 'review_unknowns')
            and type(focus['selected_claims']) is list and all(claim in candidate['claims'] for claim in focus['selected_claims']),
            'dynamic_saved_revision_focus')
    else:
        require(stored == result, 'dynamic_saved_business')
    projection = value['work']
    require(projection['version'] == 'radik.dynamic.work_projection.v01' and projection['task_id'] == spec.task_id
        and projection['profile'] == spec.profile and projection['candidate_sha256'] == digest(candidate)
        and projection['source_scope_sha256'] == digest(descriptors(sources))
        and projection['provider_calls'] == projection['effects'] == 0 and projection['actual_results']
        and projection['actual_results'][-1]['status'] == 'COMPLETED', 'dynamic_saved_work_binding')
    require(value['proposal_sha256'] == digest(candidate) and value['semantic_pipeline']['version'] == 'radik.dynamic.pipeline.v01'
        and value['semantic_pipeline']['family_ref'] == projection['family_ref'], 'dynamic_saved_pipeline')
    require(type(value['accepted_at']) is type(value['valid_to']) is int and value['accepted_at'] < value['valid_to']
        and (now is None or value['accepted_at'] <= now < value['valid_to']), 'dynamic_saved_expired')
    _validate_saved_time_binding(value)
    require(value['root']['result']['decision'] == 'ACCEPT'
        and value['root']['input']['permission_state']['permission_required'] is False
        and value['content'] == render_result(stored), 'dynamic_saved_root_content')
    receipt = _historical_work(value, spec, candidate, sources)
    pipeline = value['semantic_pipeline']
    material = dict(task=spec.plain(), proposal_sha256=digest(candidate), work=projection,
        business_sha256=digest(stored), actual_work_sha256=digest(receipt), critic=pipeline['critic'],
        memory_origin=pipeline['memory_origin'], native_revision=pipeline['native_revision'], intake=pipeline['intake'])
    if 'temporal_binding' in value:
        material['temporal_binding'] = value['temporal_binding']
    require(value['root_material_sha256'] == digest(material), 'dynamic_saved_root_material')
    context = value['root_context']
    checks = dict(actual_native_work=True, current_sources=True, no_effect=True,
        current_semantic_family=True, critic_checked=pipeline['critic'] is not None
            or pipeline['memory_origin'] is not None or pipeline['native_revision'] > 0)
    historical = authority.root_review('dynamic:result_candidate:' + digest(material), material, checks,
        context['reviewed_at'], transaction_id=context['transaction_id'], owning_root_id=context['root_id'],
        task_id=spec.task_id, bsep_ref=context['bsep_ref'], topology_ref=context['topology_ref'])
    require(authority.root_plain(historical) == value['root'], 'dynamic_saved_root_public_identity')
    require(value['result_id'] == 'radik:dynamic_result:' + digest(dict(task=spec.task_id,
        artifact=projection['result_artifact_ref'], root=value['root']['result']['decision_id'])), 'dynamic_saved_result_id')
    original = dict(value)
    result_sha = original.pop('result_sha256')
    require(result_sha == digest(original), 'dynamic_saved_result_identity')
    return _copy(value)
