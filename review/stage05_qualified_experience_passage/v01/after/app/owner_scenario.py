"""Finite owner scenario over the ordinary dispatcher and canonical TaskStore.

This module supplies no role products, transport, native executor or authority.
Its guard narrows a future owner operation to one selective source successor.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat

from .contracts import canonical, digest, require
from . import native_authority as authority
from .evidence import MAX_EVIDENCE_BYTES, persist


SCHEMA = 'radik.ordinary.owner_scenario.v01'
MAX_REPORT_BYTES = 4 * 1024 * 1024
GOAL = ('Compare the independently administered support conditions of the two fictional services. '
    'Keep the factual basis for each service separate, then explain the combined comparison.')
CRITERION = ('Compare response times, support windows, urgency channels, exceptions and unknown charges. '
    'Preserve the independent evidence of each service and distinguish factual uncertainty.')
DOCUMENT_A = (b'Fictional Service Alder is administered independently from Service Birch. '
    b'Alder replies within one working day. Alder support is available 08:00-16:00 Monday to Friday. '
    b'Urgent Alder requests use telephone except on public holidays. Alder telephone charges are not specified.\n')
DOCUMENT_B = (b'Fictional Service Birch is administered independently from Service Alder. '
    b'Birch replies within two working days. Birch support is available 09:00-17:00 Monday to Saturday. '
    b'Urgent Birch requests use chat except when maintenance closes the chat service. Birch chat charges are not specified.\n')
DOCUMENT_A_UPDATED = DOCUMENT_A.replace(b'one working day', b'three working days')
STAGE04_REMAINDER = [
    'contraction and conditions/review_unknowns with their own consumer witnesses',
    'revision and resource exhaustion',
    'cancel',
    'true process restart followed by fresh current acceptance/preparation; JSON restores no E authority',
    'current memory after process restart under the selected profile',
    'remaining admissible profile/source-count routes with branch-specific evidence',
    'SAVE, external DRS and U3/U4 are later stages']


def _owned(root, path):
    root = Path(root).resolve(strict=True)
    path = Path(path)
    path = path if path.is_absolute() else root / path
    require(path.is_relative_to(root), 'owner_scenario_owned_path')
    current = root
    for part in path.relative_to(root).parts:
        require(part not in ('', '.', '..'), 'owner_scenario_owned_path')
        current = current / part
        require(not current.is_symlink(), 'owner_scenario_symlink')
    require(path.resolve().is_relative_to(root), 'owner_scenario_owned_path')
    return path


def _read(root, path, cap):
    path = _owned(root, path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= cap,
            'owner_scenario_regular_bound')
        raw = stream.read(cap + 1)
    require(len(raw) <= cap, 'owner_scenario_regular_bound')
    return raw


def readback_reference(root, reference, *, cap=MAX_EVIDENCE_BYTES):
    require(type(reference) is dict and {'path', 'sha256', 'bytes'} <= set(reference)
        and type(reference['bytes']) is int and 0 <= reference['bytes'] <= cap
        and type(reference['sha256']) is str
        and re.fullmatch('[0-9a-f]{64}', reference['sha256']) is not None,
        'owner_scenario_reference_shape')
    raw = _read(root, reference['path'], cap)
    require(len(raw) == reference['bytes'] and digest(raw) == reference['sha256'],
        'owner_scenario_reference_readback')
    return json.loads(raw)


class ScenarioReportWriter:
    """Immutable ordinal publications plus a checked latest-report alias."""
    def __init__(self, project, run_id):
        require(type(run_id) is str and re.fullmatch('[0-9a-f]{12}', run_id) is not None,
            'owner_scenario_run_id')
        self.project = Path(project).resolve(strict=True)
        self.relative = 'workspace/owner_documents/review/stage04_actual_runs/' + run_id + '.json'
        self.path = _owned(self.project, self.relative)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot_relative = self.relative[:-5] + '.snapshots'
        self.snapshot_directory = _owned(self.project, self.snapshot_relative)
        require(not self.path.exists() and not self.path.with_suffix('.pending').exists()
            and not self.snapshot_directory.exists(),
            'owner_scenario_no_uncertain_retry')
        self.snapshot_directory.mkdir(mode=0o700)
        self.previous, self.ordinal = None, 0

    def write(self, value):
        require(type(value) is dict and value.get('schema') == SCHEMA,
            'owner_scenario_report_shape')
        raw = canonical(value)
        require(len(raw) <= MAX_REPORT_BYTES, 'owner_scenario_report_size')
        require(self.ordinal < 256, 'owner_scenario_report_publication_budget')
        path = _owned(self.project, self.path)
        require((not path.exists()) if self.previous is None else
            _read(self.project, path, MAX_REPORT_BYTES) == self.previous,
            'owner_scenario_report_changed')
        # Acknowledgements bind this immutable file. Updating the convenient
        # latest alias below can never stale a previously acknowledged hash.
        snapshot_relative = self.snapshot_relative + '/' + str(self.ordinal).zfill(6) + '.json'
        snapshot = _owned(self.project, snapshot_relative)
        fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(snapshot.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        reference = dict(path=snapshot_relative, sha256=digest(raw), bytes=len(raw))
        require(readback_reference(self.project, reference, cap=MAX_REPORT_BYTES) == value,
            'owner_scenario_snapshot_readback')
        pending = _owned(self.project, path.with_suffix('.pending'))
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        latest = dict(path=self.relative, sha256=digest(raw), bytes=len(raw))
        require(readback_reference(self.project, latest, cap=MAX_REPORT_BYTES) == value,
            'owner_scenario_report_readback')
        self.previous = raw
        self.ordinal += 1
        return reference


def check_selective_topology(declaration, bridge, source_refs, changed_source_ref):
    """Pure structural restriction; success grants no runtime authority."""
    require(type(source_refs) in (tuple, list) and len(source_refs) == 2
        and len(set(source_refs)) == 2 and changed_source_ref in source_refs,
        'owner_scenario_two_source_scope')
    require(type(declaration) is dict and declaration.get('schema') == 'radik.dynamic.native_business_bridge.v01'
        and declaration.get('route') in ('decomposed', 'nested'),
        'owner_scenario_cold_route_has_no_selective_topology')
    require(declaration.get('source_groups') == [[0], [1]]
        and type(declaration.get('leaves')) is list and len(declaration['leaves']) == 2,
        'owner_scenario_cold_full_closure_has_no_retained_proof')
    require(type(bridge) is dict and bridge.get('declaration_sha256') == digest(declaration)
        and type(bridge.get('bindings')) is list and len(bridge['bindings']) == 2,
        'owner_scenario_cold_bridge_binding')
    for index, (leaf, binding) in enumerate(zip(declaration['leaves'], bridge['bindings'], strict=True)):
        require(leaf['source']['source_ref'] == source_refs[index]
            and leaf['work_id'] == 'extract' + str(index)
            and binding['source_indices'] == [index] and binding['business_leaves'] == [leaf]
            and type(binding.get('cell_id')) is str and type(binding.get('seed_artifact')) is dict,
            'owner_scenario_cold_source_native_business_mapping')
    require(bridge['bindings'][0]['cell_id'] != bridge['bindings'][1]['cell_id'],
        'owner_scenario_cold_distinct_children_required')
    changed = list(source_refs).index(changed_source_ref)
    return dict(changed_index=changed, retained_index=1-changed,
        changed_cell=bridge['bindings'][changed]['cell_id'],
        retained_cell=bridge['bindings'][1-changed]['cell_id'],
        retained_work='extract' + str(1-changed), route=declaration['route'])


@dataclass
class SelectiveScenarioGuard:
    """Live object restriction used by the same ordinary continuation function."""
    controller: object
    changed_source_ref: str
    expected_changed_sha256: str
    before_e_calls: int = 0
    pre_e_receipt: object = None

    def __post_init__(self):
        from .dynamic_native import DynamicDocumentController
        c = self.controller
        require(type(self.expected_changed_sha256) is str
            and re.fullmatch('[0-9a-f]{64}', self.expected_changed_sha256) is not None,
            'owner_scenario_declared_change_hash')
        require(type(c) is DynamicDocumentController and c.informational_delta
            and c.native_revision == 0 and c.memory_origin is None and c.accepted is not None
            and c.informational_context is not None and c.source_transition is None,
            'owner_scenario_actual_live_cold_required')
        c.current()
        context = c.informational_context
        require(context.controller is c and context.accepted is c.accepted
            and context.native_declaration_root[2].decision == 'ACCEPT'
            and canonical(context.native_declaration) == context._frozen_declaration
            and canonical(context.native_bridge) == context._frozen_bridge,
            'owner_scenario_actual_cold_declaration_required')
        self.source_refs = tuple(s['source_ref'] for s in c.initial_sources)
        self.cold_sources = json.loads(canonical(c.initial_sources))
        self.cold_result_id = c.accepted.plain['result_id']
        self.topology = check_selective_topology(context.native_declaration, context.native_bridge,
            self.source_refs, self.changed_source_ref)
        self.declaration_sha256, self.bridge_sha256 = digest(context.native_declaration), digest(context.native_bridge)

    def before_e(self, controller, plan, context, arguments, capture_ref, input_ref):
        require(controller is self.controller and context is controller.informational_context
            and controller.native_revision == 0 and self.before_e_calls == 0,
            'owner_scenario_one_live_E_only')
        require(controller.accepted is context.accepted
            and context.accepted.plain['result_id'] == self.cold_result_id,
            'owner_scenario_cold_predecessor_changed')
        require(digest(context.native_declaration) == self.declaration_sha256
            and digest(context.native_bridge) == self.bridge_sha256
            and tuple(s['source_ref'] for s in controller.initial_sources) == self.source_refs,
            'owner_scenario_cold_identity_changed')
        require(plan['native_scope'] == 'STRICT_SUBSET_ONE_NATIVE_CHILD'
            and plan['route'] == self.topology['route'] and plan['changed_sources'] == [self.changed_source_ref]
            and plan['changed_index'] == self.topology['changed_index']
            and plan['retained_work'] == [self.topology['retained_work']]
            and plan['retained_business_claims_checked'] is True
            and arguments['retained_profile'] == 'fractal_retained_work_v01',
            'owner_scenario_current_plan_not_selective')
        changed = self.topology['changed_index']
        for index, (old, new) in enumerate(zip(self.cold_sources, controller.initial_sources, strict=True)):
            require(new['source_ref'] == old['source_ref'] and
                (new['revision'] == old['revision'] + 1 and new['sha256'] == self.expected_changed_sha256
                    and new['sha256'] != old['sha256'] if index == changed else
                 all(new[key] == old[key] for key in ('source_ref', 'revision', 'sha256', 'text'))),
                'owner_scenario_exact_one_source_revision')
            require(digest(new['text'].encode('utf-8')) == new['sha256'],
                'owner_scenario_current_raw_source_bytes')
        root = controller.project.parent.parent
        capture = readback_reference(root, capture_ref)
        inputs = readback_reference(root, input_ref)
        require(capture.get('classification') == 'PORTABLE_EVIDENCE_NOT_LIVE_AUTHORITY'
            and capture['body']['capture'] == authority.plain(arguments['source_context'].current_source_capture)
            and inputs.get('classification') == 'PORTABLE_EVIDENCE_NOT_LIVE_AUTHORITY'
            and inputs['body'] == authority.plain(dict(graph=plan, arguments=arguments)),
            'owner_scenario_full_current_capture_before_E')
        require(arguments['source_context'].current_source_host is context.informational_origin.host
            and arguments['source_context'].informational_carrier is context.informational_origin.carrier,
            'owner_scenario_current_host_carrier_identity')
        self.before_e_calls = 1
        self.pre_e_receipt = dict(capture_ref=capture_ref, input_ref=input_ref,
            cold_result_id=self.cold_result_id, changed_source_ref=self.changed_source_ref,
            current_source_bytes=[dict(source_ref=s['source_ref'], sha256=s['sha256'],
                bytes=len(s['text'].encode('utf-8'))) for s in controller.initial_sources],
            declaration_sha256=self.declaration_sha256, bridge_sha256=self.bridge_sha256,
            topology=self.topology)
        return self.pre_e_receipt


def writer_preflight(controller):
    """Exercise existing serialization with actual cold types before any E call."""
    c, context = controller, controller.informational_context
    require(context is not None and c.native_revision == 0, 'owner_scenario_preflight_cold_required')
    actual = dict(baseline=context.d_baseline, source_context=context.d_source,
        cold_declaration=context.native_declaration, cold_bridge=context.native_bridge,
        accepted=c.accepted.plain, program=c.program, results=c.results,
        root=authority.root_plain(c.final_root), current_sources=c.initial_sources)
    portable = authority.plain(actual)
    require(len(canonical(dict(classification='PORTABLE_EVIDENCE_NOT_LIVE_AUTHORITY',
        type='builtins.dict', body=portable))) <= MAX_EVIDENCE_BYTES,
        'owner_scenario_actual_cold_evidence_size')
    reference = persist(c.evidence_directory, 'owner_scenario_writer_preflight', actual)
    require(readback_reference(c.project.parent.parent, reference)['body'] == portable,
        'owner_scenario_actual_cold_writer_readback')
    # This probe tests primitive support only; it is not native or Root evidence.
    probe = dict(classification='SYNTHETIC_SERIALIZER_PROBE_NO_AUTHORITY',
        text='UTF-8 \u03b1', integer=1, boolean=True, absent=None, sequence=[{}, [], ''],
        tuple_value=(1, 2), raw_bytes=b'\x00\xff', integer_key={1: 'retained slot'})
    probe_ref = persist(c.evidence_directory, 'owner_scenario_portability_probe', probe)
    require(readback_reference(c.project.parent.parent, probe_ref)['body'] == authority.plain(probe),
        'owner_scenario_portability_probe_readback')
    return dict(status='PASS_ACTUAL_COLD_TYPES_AND_BOUNDED_SERIALIZATION', actual_ref=reference,
        primitive_probe_ref=probe_ref, per_evidence_byte_cap=MAX_EVIDENCE_BYTES,
        report_byte_cap=MAX_REPORT_BYTES, future_values_still_checked_at_each_write=True)


def _latest(controller, label):
    matches = [r for r in controller.evidence_refs if Path(r['path']).name.startswith(label + '_')]
    require(bool(matches), 'owner_scenario_required_witness_missing:' + label)
    reference = matches[-1]
    return reference, readback_reference(controller.project.parent.parent, reference)['body']


def _checked_result(store, task_id, controller):
    result = store.result(task_id)
    require(type(result) is dict and controller.accepted is not None
        and result == controller.accepted.plain and result['task'] == store.spec(task_id).plain()
        and result['root']['result']['decision'] == 'ACCEPT', 'owner_scenario_current_result_binding')
    return result


def _document(project, relative, raw, *, previous=None):
    path = _owned(project, relative)
    require(type(raw) is bytes and 0 < len(raw) <= 16384 and b'\0' not in raw,
        'owner_scenario_document_bound')
    raw.decode('utf-8', errors='strict')
    require(not path.exists() if previous is None else _read(project, path, 16384) == previous,
        'owner_scenario_document_no_uncertain_retry')
    pending = _owned(project, path.with_suffix('.pending'))
    with pending.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.replace(pending, path)
    require(_read(project, path, 16384) == raw, 'owner_scenario_document_readback')
    return path


def run_owner_scenario(*, store, run_task, controllers, client, operation, report_sink, event_sink=None):
    """Future cold3 -> one source successor/delta3 -> actual memory readback.

    The caller is runtime.main and supplies its existing run_task closure. No
    diagnostic runtime, copied role product, retry or route override exists here.
    """
    from .task_store import TaskStore
    from .normal_session import validate_operation
    project = store.project.parent.parent
    require(type(store) is TaskStore and store.project == project / 'workspace/owner_documents'
        and callable(run_task) and type(controllers) is dict and callable(report_sink),
        'owner_scenario_canonical_dispatcher')
    current = validate_operation(project, client.budget._normal_operation)
    require(current == operation and operation['schema'] == 'radik.normal_operation.v02'
        and getattr(client, 'budget_scope', None) == 'console', 'owner_scenario_v02_operation_required')
    report = dict(schema=SCHEMA, status='STARTED', owner_operation_id=operation['owner_operation_id'],
        run_id=operation['run_id'], profile_ref=operation['profile_ref'], current_phase='SETUP',
        native_E_status='NOT_STARTED', business_consumer_status='NOT_STARTED',
        root_memory_status='NOT_STARTED', whole_scenario_status='NOT_COMPLETED',
        model_request_plan=6, model_request_plan_scope='THIS_FIRST_OWNER_SCENARIO_ONLY',
        automatic_retry=False, external_effects=0, steps=[],
        limits=dict(changed_sources=1, same_source_set=True, same_route=True,
            same_live_controller=True, initial_native_revision=0, E_authority_on_restart='NOT_RESTORED'),
        Stage04_remaining=STAGE04_REMAINDER)
    task_id = None
    controller = guard = None

    def publish():
        reference = report_sink(json.loads(canonical(report)))
        require(readback_reference(project, reference, cap=MAX_REPORT_BYTES) == report,
            'owner_scenario_report_sink_readback')
        if event_sink is not None:
            event_sink(dict(kind='REPORT_READBACK_ACK', phase=report['current_phase'],
                useful=False, readback_ref=reference, milestone=report['status']))
        return reference

    try:
        publish()
        run_id = operation['run_id']
        documents = []
        for name, raw in (('alder', DOCUMENT_A), ('birch', DOCUMENT_B)):
            path = _document(project, 'workspace/owner_documents/input/owner_' + run_id + '_' + name + '.txt', raw)
            source_id = store.register_source(str(path), path.name, _read(project, path, 16384))
            documents.append(dict(path=str(path), source_ref=source_id, initial_sha256=digest(raw), bytes=len(raw)))
        task_id = store.create(goal=GOAL, source_ids=tuple(d['source_ref'] for d in documents),
            profile='compare', criterion=CRITERION, topic='independent_support_conditions')
        report.update(task_id=task_id, task_spec=store.spec(task_id).plain(), documents=documents,
            task_profile_criterion_acceptance='EXPLICIT_OWNER_SCENARIO_CONTRACT', current_phase='NATIVE')
        publish()
        before = len(client.budget.snapshot()['attempts'])
        run_task(task_id)
        controller = controllers[task_id]
        cold = _checked_result(store, task_id, controller)
        after = len(client.budget.snapshot()['attempts'])
        require(after-before == 3 and controller.memory_origin is None,
            'owner_scenario_requires_three_actual_cold_roles')
        report['steps'].append(dict(step='COLD_O_BSEP_A_WORK_C_ROOT', new_turn_attempts=after-before,
            accepted_result=cold, snapshot=controller.snapshot()))
        report.update(status='COLD_ACCEPTED', current_phase='PERSISTENCE')
        publish()
        # A legal short/full-closure cold result remains useful but cannot prove
        # this scenario. Refusal happens before editing or E, without new roles.
        guard = SelectiveScenarioGuard(controller, documents[0]['source_ref'], digest(DOCUMENT_A_UPDATED))
        controller.owner_scenario_guard = guard
        report['writer_preflight'] = writer_preflight(controller)
        report['cold_selective_topology'] = guard.topology
        report.update(status='COLD_TOPOLOGY_AND_WRITER_READY', current_phase='SETUP')
        publish()
        path = _document(project, documents[0]['path'], DOCUMENT_A_UPDATED, previous=DOCUMENT_A)
        require(store.register_source(str(path), path.name, _read(project, path, 16384)) == documents[0]['source_ref'],
            'owner_scenario_logical_source_identity')
        report['declared_source_change'] = dict(source_ref=documents[0]['source_ref'],
            old_sha256=digest(DOCUMENT_A), new_sha256=digest(DOCUMENT_A_UPDATED),
            edit='Alder response time: one working day -> three working days', bytes=len(DOCUMENT_A_UPDATED))
        report.update(status='ONE_SOURCE_EDIT_REGISTERED', current_phase='NATIVE')
        publish()
        before = len(client.budget.snapshot()['attempts'])
        run_task(task_id, source_update=True)
        require(controllers[task_id] is controller and guard.before_e_calls == 1,
            'owner_scenario_live_single_E_path')
        after = len(client.budget.snapshot()['attempts'])
        require(after-before == 3, 'owner_scenario_requires_three_actual_delta_roles')
        current_result = _checked_result(store, task_id, controller)
        require(current_result['result_id'] != cold['result_id'] and controller.native_revision == 1,
            'owner_scenario_fresh_changed_result')
        native_ref, native = _latest(controller, 'dynamic_delta_native_return')
        business_ref, business = _latest(controller, 'dynamic_delta_business_consumer')
        final_ref, final = _latest(controller, 'dynamic_delta_final_consumers')
        require(native['consumer']['native_E'] == 'PASS'
            and native['consumer']['native_retained_consumer'] == 'PASS'
            and native['consumer']['retained_cell'] == guard.topology['retained_cell']
            and business['status'] == 'PASS' and business['unchanged_business_outputs_consumed'] == 1
            and business['full_recompute'] is False and final['native'] == native['consumer']
            and final['business'] == business and final['final_root'] == current_result['root'],
            'owner_scenario_distinct_native_business_parent_witnesses')
        retained_index = guard.topology['retained_index']
        historical = business['historical_bindings'][str(retained_index)]
        parent = controller.results[-1]
        parent_inputs = authority.values(parent.invocation.inputs)
        require(parent_inputs['branch' + str(retained_index)] == historical['value']['value']
            and business['actual_parent_invocation'] == authority.plain(parent.invocation)
            and business['actual_parent_result'] == authority.plain(parent.result)
            and parent.invocation.candidate_id is None and parent.invocation.packet_id is None,
            'owner_scenario_retained_bytes_bound_to_actual_parent')
        report.update(native_E_status='PASS_ACTUAL_SINGLE_E_WITH_RETAINED_CONTROL',
            business_consumer_status='PASS_ACTUAL_RETAINED_BUSINESS_BYTES_IN_NEW_PARENT',
            pre_e=guard.pre_e_receipt, native_return_ref=native_ref,
            business_consumer_ref=business_ref, final_consumers_ref=final_ref,
            status='DELTA_ROOT_ACCEPTED', current_phase='PERSISTENCE')
        report['source_to_consumers'] = dict(
            source=guard.pre_e_receipt['current_source_bytes'][guard.topology['changed_index']],
            cold_declaration_sha256=guard.declaration_sha256,
            cold_native_bridge_sha256=guard.bridge_sha256,
            native_changed_cell=guard.topology['changed_cell'],
            native_retained_cell=guard.topology['retained_cell'],
            native_parent_result_id=native['consumer']['parent_result_id'],
            native_retained_consumption_ref=native['consumer']['retained_consumption_ref'],
            retained_business_work=guard.topology['retained_work'],
            retained_business_value_sha256=digest(historical['value']['value'].encode('utf-8')),
            business_parent_invocation_sha256=digest(business['actual_parent_invocation']),
            business_parent_result_sha256=digest(business['actual_parent_result']),
            native_control_is_business_extraction=False)
        report['steps'].append(dict(step='SOURCE_SUCCESSOR_O_A_CAPTURE_E_BUSINESS_C_ROOT',
            new_turn_attempts=after-before, accepted_result=current_result, snapshot=controller.snapshot()))
        publish()
        # The memory API performs fresh typed eligibility and current Root
        # descent over persisted bytes. It restores no Host or E authority.
        before = len(client.budget.snapshot()['attempts'])
        selection = controller.memory.select(sources=controller.initial_sources, task_id=task_id,
            topic_id=controller.spec.topic, intent=controller.spec.goal, criterion=controller.spec.criterion,
            now=controller.now())
        require(selection is not None and selection.material['outcome'] == current_result
            and selection.root_decision_id != selection.historical_root_decision_id
            and selection.descent['limits_respected'] and not selection.descent['reason_codes']
            and selection.descent['opened_payload_fingerprints'] == [selection.payload_sha256]
            and len(client.budget.snapshot()['attempts']) == before,
            'owner_scenario_actual_current_memory_readback')
        memory_ref = controller._persist('owner_scenario_final_memory_readback',
            dict(selection=selection, events=controller.memory.events, actual_result_id=current_result['result_id']))
        readback_reference(project, memory_ref)
        report.update(root_memory_status='PASS_FRESH_ROOT_AND_ACTUAL_MEMORY_WRITEBACK_READBACK',
            memory_readback_ref=memory_ref, whole_scenario_status='PASS_FIRST_SELECTIVE_OWNER_SCENARIO',
            status='COMPLETED', current_phase='PERSISTENCE',
            operation_close_owner='ORDINARY_ENTRY_FINALIZER_AFTER_DRIVER_RETURN')
        reference = publish()
        return dict(report=report, report_ref=reference)
    except BaseException as error:
        if controller is None and task_id is not None:
            controller = controllers.get(task_id)
        if controller is not None:
            report['partial_snapshot'] = controller.snapshot()
            report['E_entry_observed'] = any(e['stage'] == 'DYNAMIC_NATIVE_E_START' for e in controller.events)
            if report['E_entry_observed'] and report['native_E_status'] == 'NOT_STARTED':
                report['native_E_status'] = 'STARTED_NOT_PROVEN_COMPLETE'
            if guard is not None:
                report['pre_e'] = guard.pre_e_receipt
            # Completed lower consumers retain their own status when a later
            # consumer, Critic, Root, memory or report stops the whole scenario.
            for label, field, predicate, status in (
                ('dynamic_delta_native_return', 'native_E_status',
                    lambda value: value['consumer']['native_E'] == 'PASS',
                    'PASS_ACTUAL_NATIVE_RETURN_WHOLE_SCENARIO_INCOMPLETE'),
                ('dynamic_delta_business_consumer', 'business_consumer_status',
                    lambda value: value['status'] == 'PASS' and value['unchanged_business_outputs_consumed'] == 1,
                    'PASS_ACTUAL_BUSINESS_CONSUMER_WHOLE_SCENARIO_INCOMPLETE')):
                try:
                    reference, value = _latest(controller, label)
                    if predicate(value):
                        report[field] = status
                        report[field + '_partial_ref'] = reference
                except (ValueError, OSError, KeyError, TypeError):
                    pass
        report.update(status='STOPPED_NO_AUTOMATIC_RETRY', whole_scenario_status='NOT_COMPLETED',
            primary_failure=dict(type=type(error).__name__, code=str(error)[:512]),
            current_phase='PERSISTENCE', operation_close_owner='ORDINARY_ENTRY_FAILURE_FINALIZER')
        try:
            publish()
        except BaseException as secondary:
            # Never turn a secondary report failure into the scenario's cause.
            try:
                error.add_note('owner_scenario_secondary_report_failure:' + type(secondary).__name__)
            except AttributeError:
                pass
        raise
