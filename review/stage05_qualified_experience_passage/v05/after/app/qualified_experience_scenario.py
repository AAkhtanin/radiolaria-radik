"""Finite owner experience sequence through the ordinary TaskStore and Work.

This driver provides fictional source bytes and requests, never model products,
Root acceptance, feedback outcomes or Work results. Every checkpoint is retained
before the next step; completion still requires independent actual acceptance.
"""
from contextlib import contextmanager
import json
import re
from pathlib import Path
import time

from .contracts import digest, require
from .evidence import persist
from .native_authority import plain
from .stage04_diagnostics import observe_failure, project_error, project_transport_failure, record_secondary

PREFIX = 'review/stage05_qualified_experience_passage/v05'


STAGE05_SCENARIO_STAGES = frozenset((
    'UNKNOWN', 'ORDINARY_TASK', 'COLD_DECISION', 'PROSPECTIVE_FEEDBACK',
    'SUBSEQUENT_WORK', 'CAUSAL_CHECKS', 'UNSCORABLE_CONTROL',
    'ELIGIBILITY_CONTROLS', 'AGED_CURRENT_CHECK', 'UNRELATED_TASK',
    'UNRELATED_CONSUMER', 'SOURCE_REVISION_REFUSAL', 'FINALIZATION',
))
STAGE05_NATIVE_STAGES = frozenset((
    'UNKNOWN', 'G4_BOOTSTRAP_ADVANCE', 'G4_BOOTSTRAP_ARTIFACT', 'G4_HISTORY',
    'G4_ALLOCATION', 'G4_TASK_ROOT', 'G4_REVISION', 'G4_PRE_DISPATCH_PERSISTENCE',
    'G4_ALLOCATED_ADVANCE', 'G4_ALLOCATED_ARTIFACT', 'G4_FINAL_CHECKS', 'G4_CUSTODY',
))
STAGE05_FRAME_FUNCTIONS = frozenset(('<module>', '<lambda>', '<genexpr>',
    '<listcomp>', '<dictcomp>', '<setcomp>'))


def diagnostic_source_pins(manifest):
    """Use only the finite independently admitted application and native paths."""
    result = {path: value for path, value in manifest['pins'].items() if path.endswith('.py')}
    for item in manifest['native_files'].values():
        path, value = item['path'], item['sha256']
        if path.endswith('.py'):
            require(path not in result or result[path] == value, 'stage05_failure_source_identity')
            result[path] = value
    require(len(result) <= 4096 and all(type(path) is str and path == Path(path).as_posix()
        and not Path(path).is_absolute() and not any(part in ('.', '..', 'private', '.git')
        for part in Path(path).parts) and len(path) <= 1024 and type(value) is str
        and re.fullmatch('[0-9a-f]{64}', value) for path, value in result.items()),
        'stage05_failure_source_identity')
    return result


def _failure_context(project, manifest, error, scenario_stage):
    """Retain bounded admitted frame coordinates, never error text or frame locals."""
    pins = diagnostic_source_pins(manifest)
    frames = []
    skipped = 0
    visited = 0
    cursor = error.__traceback__
    while cursor is not None and visited < 128:
        visited += 1
        try:
            relative = Path(cursor.tb_frame.f_code.co_filename).absolute().relative_to(project.absolute()).as_posix()
        except (ValueError, OSError):
            relative = None
        if relative in pins:
            function = cursor.tb_frame.f_code.co_name
            if (type(function) is not str or len(function) > 96 or not
                    (re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', function)
                     or function in STAGE05_FRAME_FUNCTIONS)):
                function = 'UNKNOWN'
            line = cursor.tb_lineno
            if type(line) is int and 1 <= line <= 1000000:
                frames.append(dict(path=relative, sha256=pins[relative], line=line, function=function))
            else:
                skipped += 1
        else:
            skipped += 1
        cursor = cursor.tb_next
    try:
        native = getattr(error, '_radik_stage05_native_stage', None)
    except BaseException:
        native = None
    result = dict(schema='radik.stage05.failure_context.v01',
        scenario_stage=scenario_stage if scenario_stage in STAGE05_SCENARIO_STAGES else 'UNKNOWN',
        native_stage=native if type(native) is str and native in STAGE05_NATIVE_STAGES else 'UNKNOWN',
        source_frames=frames[-32:], omitted_frames=max(0, len(frames)-32),
        unadmitted_frames=skipped, traceback_truncated=cursor is not None,
        raw_error_recorded=False, locals_recorded=False)
    transport = project_transport_failure(getattr(error, 'transport_failure', None), source_pins=pins)
    if transport is not None:
        result['transport_failure'] = transport
    return result


def run(*, store, run_task, controllers, client, operation, event_sink):
    from config.application_profile_gate import _read
    from .qualified_experience import QualifiedExperience
    from . import qualified_strategy

    project = Path(client.project)
    manifest = client._ordinary_profile_manifest
    relative = PREFIX+'/inputs/scenario.json'
    raw = _read(project, relative)
    require(digest(raw) == manifest['pins'].get(relative), 'stage05_scenario_input_pin')
    inputs = json.loads(raw)
    require(inputs['schema'] == 'radik.stage05.qualified_experience_inputs.v01'
        and inputs['command'] == 'experience' and inputs['expected_role_calls'] == 6
        and inputs['expected_primary_role_calls'] == inputs['expected_unrelated_role_calls'] == 3
        and inputs['native_E_calls'] == inputs['effects'] == 0, 'stage05_scenario_input_contract')
    require(inputs.get('scenario_mode') in ('full', 'remaining_only'), 'stage05_scenario_input_contract')
    remaining_only = inputs['scenario_mode'] == 'remaining_only'
    # Pinned prior refs document completed evidence; they restore no live object.
    require(type(inputs.get('prior_actual_evidence')) is dict
        and inputs['prior_actual_evidence'].get('authority_restored') is False,
        'stage05_scenario_input_contract')
    require(operation is not None and operation['schema'] == 'radik.normal_operation.v02',
        'stage05_current_operation_required')
    output = project/'workspace/owner_documents/review/stage05'/operation['run_id']
    require(not output.exists() and not output.is_symlink(), 'stage05_uncertain_retry_refused')
    output.mkdir(parents=True, mode=0o700)
    before = client.budget.snapshot()
    observations = []
    report = dict(schema='radik.stage05.qualified_experience_result.v01', status='STARTED',
        owner_operation_id=operation['owner_operation_id'], run_id=operation['run_id'],
        scenario_input_sha256=digest(raw), scenario_mode=inputs['scenario_mode'],
        prior_actual_evidence=inputs['prior_actual_evidence'],
        observations=observations, actual_model_calls=None,
        native_E_calls=0, effects=0, automatic_retry=False, Stage05_acceptance='NOT_INFERRED')

    def checkpoint(step, value):
        ref = persist(output, step, plain(value))
        observations.append(dict(step=step, reference=ref))
        persist(output, 'partial_result', report)
        if event_sink is not None:
            event_sink(dict(kind='STATUS', phase='PERSISTENCE', stage='STAGE05_CHECKPOINT',
                step=step, readback_ref=ref, semantic_progress=True))
        print('Stage 5 checkpoint: '+step+'; evidence='+ref['path'], flush=True)
        return ref

    scenario_stage = 'ORDINARY_TASK'

    @contextmanager
    def phase(name):
        nonlocal scenario_stage
        scenario_stage = name.upper()
        primary = None
        started = time.monotonic_ns()
        if event_sink is not None:
            event_sink(dict(kind='PHASE_ENTER', phase='NATIVE', span_id='stage05_'+name, native=True))
        try:
            yield
        except BaseException as error:
            primary = error
            observe_failure(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
            raise
        finally:
            try:
                report.setdefault('native_phase_measurements', []).append(
                    dict(phase=name, elapsed_wall_ns=time.monotonic_ns()-started))
                if event_sink is not None:
                    event_sink(dict(kind='PHASE_EXIT', phase='NATIVE', span_id='stage05_'+name, native=True))
            except BaseException as secondary:
                if primary is None:
                    raise
                record_secondary(primary, secondary, phase='TERMINAL_OUTPUT', step='STAGE05_EXPERIENCE')

    try:
        source_key = 'stage05:'+operation['run_id']+':rowan'
        source = store.register_source(source_key,
            'Fictional Rowan support terms', inputs['source_text'].encode('utf-8'))
        task = store.create(goal=inputs['goal'], source_ids=(source,), profile=inputs['ordinary_profile'],
            criterion=inputs['criterion'], topic=inputs['topic'])
        report['task_id'] = task
        checkpoint('prospective_scenario', dict(inputs=inputs, task=store.spec(task).plain(),
            ledger_before_sha256=digest(before), source_id=source))
        # This operation consumes current accepted Work and requests no G2-E continuation.
        run_task(task, prepare_continuation=False)
        controller = controllers[task]
        require(controller.accepted is not None and controller.memory_origin is None,
            'stage05_actual_cold_result_required')
        after_cold = client.budget.snapshot()
        report['actual_model_calls'] = len(after_cold['attempts'])-len(before['attempts'])
        require(report['actual_model_calls'] == inputs['expected_primary_role_calls'], 'stage05_cold_role_budget')
        checkpoint('ordinary_accepted_result', dict(result=store.result(task),
            source_scope=controller.initial_sources, model_calls=report['actual_model_calls']))

        experience = QualifiedExperience(project/'workspace/owner_documents/state/qualified_experience',
            on_event=event_sink)
        with phase('cold_decision'):
            cold_binding = experience.consume(controller, cold=True)
            if not remaining_only:
                baseline = qualified_strategy.run(controller, cold_binding, label='cold')
        # A fresh cold G3 consumer supplies the later unrelated-operation comparator.
        checkpoint('cold_current_consumer' if remaining_only else 'cold_allocated_work',
            cold_binding.report if remaining_only else baseline)
        with phase('prospective_feedback'):
            feedback = experience.observe(controller, predicted=True)
        checkpoint('qualified_feedback', feedback)
        with phase('subsequent_work'):
            qualified = experience.consume(controller)
            if not remaining_only:
                subsequent = qualified_strategy.run(controller, qualified, label='qualified')
        checkpoint('qualified_current_consumer' if remaining_only else 'qualified_allocated_work',
            qualified.report if remaining_only else subsequent)
        scenario_stage = 'CAUSAL_CHECKS'
        require(feedback['feedback']['update_eligibility'] == 'ELIGIBLE'
            and feedback['feedback']['observed_result']['value'] == 0
            and int(feedback['clocks']['claim_wall_ns']) < int(feedback['clocks']['event_wall_ns'])
            <= int(feedback['clocks']['capture_wall_ns']), 'stage05_prospective_negative_required')
        require(cold_binding.report['history_ref'] is None
            and qualified.report['history_ref'] == feedback['head']['snapshot_id']
            and feedback['feedback']['feedback_id'] in qualified.report['outcome_to_history_refs']
            and qualified.report['prior_fp'] < 0
            and cold_binding.report['selected_operation'] != qualified.report['selected_operation']
            and cold_binding.report['work_result_ref'] != qualified.report['work_result_ref']
            and cold_binding.report['source_scope'] == qualified.report['source_scope'],
            'stage05_actual_scoped_consumer_change_required')
        if not remaining_only:
            require(baseline['budget_total'] == subsequent['budget_total']
                == baseline['consumed_units'] == subsequent['consumed_units'] == 9
                and baseline['history']['disposition'] == 'ABSENT'
                and subsequent['history']['disposition'] == 'USABLE'
                and baseline['allocation_counts'] == dict(quotation=4, qualification=3)
                and subsequent['allocation_counts'] == dict(quotation=3, qualification=4)
                and 'absolute_word_audit' not in baseline['selected_checks']
                and 'absolute_word_audit' in subsequent['selected_checks']
                and subsequent['history']['consumed_work_ref'] == qualified.report['work_result_ref']
                and subsequent['history']['history_ref'] == feedback['head']['snapshot_id']
                and all(value['provider_calls'] == value['effects'] == 0 for value in (baseline, subsequent)),
                'stage05_actual_equal_budget_redistribution_required')
        checkpoint('causal_chain_verified', dict(prospective_ref=feedback['claim']['artifact_id'],
            outcome_ref=feedback['feedback']['feedback_id'], history_ref=qualified.report['history_ref'],
            current_work_ref=qualified.report['work_result_ref'],
            allocated_work_ref=None if remaining_only else subsequent['artifact_id'],
            cold_binding_id=cold_binding.report['binding_id'], qualified_binding_id=qualified.report['binding_id'],
            statement=('A fresh scoped negative predicate changed the current G3 consumer; prior G4 credit remains historical.'
                if remaining_only else 'Scoped negative predicate changed actual Work and redistributed the same budget.')))
        if not remaining_only:
            with phase('unscorable_control'):
                unscorable = experience.audit_unscorable(controller, reason='UNSCORABLE_MODEL_RESPONSE')
            checkpoint('unscorable_audit_control', dict(controlled_failure_category=True,
                actual_transport_failure_claimed=False, observation=unscorable))
            require(unscorable['update_eligibility'] == 'NO_UPDATE'
                and unscorable['qualified_history_before'] == unscorable['qualified_history_after'],
                'stage05_unscorable_history_preserved')
            with phase('eligibility_controls'):
                eligibility = experience.eligibility_controls(controller)
            checkpoint('current_eligibility_controls', eligibility)
            with phase('aged_current_check'):
                aged = experience.aged_consumer_control(controller)
            require(aged['old_history_opened'] is False and aged['prior_fp'] == 0
                and aged['binding_report']['mandatory_check'] is not None
                and aged['binding_report']['history_ref'] is None
                and aged['binding_report']['outcome_to_history_refs'] == []
                and aged['history_before'] == aged['history_after'],
                'stage05_aged_additional_work_required')
            checkpoint('aged_current_check', aged)
        after_primary_native = client.budget.snapshot()
        require(after_primary_native['attempts'] == after_cold['attempts']
            and after_primary_native['active_attempt_id'] is None,
            'stage05_native_provider_calls_forbidden')

        # A real independent cold task supplies its own current Root and Work.
        # Its three role attempts are explicitly additional owner budget.
        scenario_stage = 'UNRELATED_TASK'
        unrelated_inputs = inputs['unrelated']
        unrelated_source = store.register_source('stage05:'+operation['run_id']+':alder',
            'Fictional Alder museum terms', unrelated_inputs['source_text'].encode('utf-8'))
        unrelated_task = store.create(goal=unrelated_inputs['goal'], source_ids=(unrelated_source,),
            profile=unrelated_inputs['ordinary_profile'], criterion=unrelated_inputs['criterion'],
            topic=unrelated_inputs['topic'])
        report['unrelated_task_id'] = unrelated_task
        history_before_unrelated = experience.history_snapshot()
        checkpoint('unrelated_prospective_task', dict(task=store.spec(unrelated_task).plain(),
            source_id=unrelated_source, expected_additional_role_calls=inputs['expected_unrelated_role_calls'],
            retained_history=history_before_unrelated))
        report['actual_model_calls'] = None
        run_task(unrelated_task, prepare_continuation=False)
        unrelated_controller = controllers[unrelated_task]
        require(unrelated_controller is not controller and unrelated_controller.accepted is not None
            and unrelated_controller.memory_origin is None
            and unrelated_controller.spec.task_id != controller.spec.task_id
            and unrelated_controller.root_id != controller.root_id,
            'stage05_unrelated_actual_controller_required')
        after_unrelated_cold = client.budget.snapshot()
        unrelated_calls = len(after_unrelated_cold['attempts'])-len(after_cold['attempts'])
        report['actual_model_calls'] = len(after_unrelated_cold['attempts'])-len(before['attempts'])
        require(unrelated_calls == inputs['expected_unrelated_role_calls'],
            'stage05_unrelated_role_budget')
        checkpoint('unrelated_accepted_result', dict(result=store.result(unrelated_task),
            source_scope=unrelated_controller.initial_sources, model_calls=unrelated_calls))
        with phase('unrelated_consumer'):
            unrelated = experience.consume(unrelated_controller)
        history_after_unrelated = experience.history_snapshot()
        require(unrelated.report['history_ref'] is None and unrelated.report['prior_fp'] == 0
            and unrelated.report['outcome_to_history_refs'] == []
            and unrelated.report['selected_operation'] == cold_binding.report['selected_operation']
            and unrelated.report['work_result_ref'] != qualified.report['work_result_ref']
            and unrelated.report['current_root'] != qualified.report['current_root']
            and unrelated.report['source_scope'] != qualified.report['source_scope']
            and unrelated.report['scope'] != qualified.report['scope']
            and unrelated.report['provider_calls'] == unrelated.report['effect_calls'] == 0
            and history_before_unrelated == history_after_unrelated,
            'stage05_unrelated_native_consumer_scope')
        checkpoint('unrelated_current_consumer', dict(actual_task_id=unrelated_task,
            accepted_result_id=unrelated_controller.accepted.plain['result_id'],
            task_root=unrelated_controller.root_id, consumer=unrelated.report,
            history_before=history_before_unrelated, history_after=history_after_unrelated,
            foreign_prior_applied=False, foreign_lesson_applied=False, foreign_prohibition_applied=False))

        # Change only this scenario document after all dependent consumers.
        # The ordinary approved-source reader derives and commits its revision.
        with phase('source_revision_refusal'):
            before_sources = store.source_reader(store.spec(task))()
            require(len(before_sources) == 1 and before_sources[0]['source_ref'] == source
                and before_sources[0]['text'].encode('utf-8') == inputs['source_text'].encode('utf-8'),
                'stage05_source_revision_preimage')
            history_before_revision = experience.history_snapshot()
            native_before_revision = dict(results=plain(controller.results),
                events=plain(controller.events), evidence_refs=plain(controller.evidence_refs))
            checkpoint('source_revision_before', dict(source_id=source,
                approved_sources=before_sources, raw_utf8_hex=before_sources[0]['text'].encode('utf-8').hex(),
                history=history_before_revision, native=native_before_revision,
                old_binding_id=qualified.report['binding_id']))
            changed_bytes = inputs['source_revision_text'].encode('utf-8')
            require(changed_bytes != before_sources[0]['text'].encode('utf-8'),
                'stage05_source_revision_requires_change')
            require(store.register_source(source_key, 'Fictional Rowan support terms', changed_bytes) == source,
                'stage05_source_revision_logical_identity')
            after_sources = store.source_reader(store.spec(task))()
            require(len(after_sources) == 1 and after_sources[0]['source_ref'] == source
                and after_sources[0]['revision'] == before_sources[0]['revision'] + 1
                and after_sources[0]['sha256'] == digest(changed_bytes)
                and after_sources[0]['sha256'] != before_sources[0]['sha256']
                and after_sources[0]['text'].encode('utf-8') == changed_bytes,
                'stage05_source_revision_actual_reader')
            checkpoint('source_revision_after', dict(source_id=source,
                approved_sources=after_sources, raw_utf8_hex=changed_bytes.hex(),
                old_revision=before_sources[0]['revision'], new_revision=after_sources[0]['revision']))
            try:
                qualified_strategy.run(controller, qualified, label='qualified')
            except ValueError as error:
                require(error.args == ('dynamic_current_sources_changed',),
                    'stage05_source_revision_wrong_refusal')
                refusal = error.args[0]
            else:
                raise ValueError('stage05_source_revision_stale_binding_consumed')
            native_after_revision = dict(results=plain(controller.results),
                events=plain(controller.events), evidence_refs=plain(controller.evidence_refs))
            history_after_revision = experience.history_snapshot()
            require(native_after_revision == native_before_revision
                and history_after_revision == history_before_revision,
                'stage05_source_revision_mutated_prior_work_or_history')
        checkpoint('source_revision_stale_binding_refused', dict(refusal_code=refusal,
            consumer='qualified_strategy.run', old_binding_id=qualified.report['binding_id'],
            source_id=source, before_sources=before_sources, after_sources=after_sources,
            history_before=history_before_revision, history_after=history_after_revision,
            native_before=native_before_revision, native_after=native_after_revision,
            stale_prior_reapplied=False, native_dispatch_reached=False))
        scenario_stage = 'FINALIZATION'
        final = client.budget.snapshot()
        require(final['attempts'] == after_unrelated_cold['attempts'] and final['active_attempt_id'] is None,
            'stage05_native_provider_calls_forbidden')
        report['actual_model_calls'] = len(final['attempts'])-len(before['attempts'])
        require(report['actual_model_calls'] == inputs['expected_role_calls'], 'stage05_total_role_budget')
        report['role_calls_by_task'] = {task:inputs['expected_primary_role_calls'], unrelated_task:unrelated_calls}
        report['status'] = 'OWNER_SCENARIO_COMPLETED_REQUIRES_REVIEW'
        report['completed_scope'] = 'FRESH_REMAINING_ONLY' if remaining_only else 'FULL_SCENARIO'
        report['repeated_G4_allocations'] = 0 if remaining_only else 2
        report['repeated_aged_consumers'] = 0 if remaining_only else 1
        report['prior_closed_process_authority_restored'] = False
        report['ledger_after_sha256'] = digest(final)
        report['result_ref'] = persist(output, 'completed_result', report)
        return report
    except BaseException as error:
        observe_failure(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        report['status'] = 'STOPPED_NO_RETRY'
        detail = dict(schema='radik.stage05.failure_context.v01', scenario_stage='UNKNOWN',
            native_stage='UNKNOWN', source_frames=[], omitted_frames=0, unadmitted_frames=0,
            traceback_truncated=False, raw_error_recorded=False, locals_recorded=False)
        try:
            detail = _failure_context(project, manifest, error, scenario_stage)
        except BaseException as secondary:
            record_secondary(error, secondary, phase='NATIVE_SNAPSHOT', step='STAGE05_EXPERIENCE')
        report['failure_context'] = detail
        report['primary_failure'] = project_error(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        ref = None
        try:
            ref = persist(output, 'stopped_result', report)
        except BaseException as secondary:
            record_secondary(error, secondary, phase='CONNECTED_REPORT_WRITE', step='STAGE05_EXPERIENCE')
        projected = project_error(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        try:
            if event_sink is not None:
                attachment = dict(readback_ref=ref) if ref is not None else {}
                event_sink(dict(kind='PRIMARY_FAILURE', phase='FINALIZATION', stage='STAGE05_FAILURE',
                    failure=dict(phase='STAGE05_EXPERIENCE', error_class=projected['type'], code=projected['code']),
                    failure_context=detail, **attachment))
        except BaseException as secondary:
            record_secondary(error, secondary, phase='TERMINAL_OUTPUT', step='STAGE05_EXPERIENCE')
        raise
