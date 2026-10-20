"""Finite owner experience sequence through the ordinary TaskStore and Work.

This driver provides fictional source bytes and requests, never model products,
Root acceptance, feedback outcomes or Work results. Every checkpoint is retained
before the next step; completion still requires independent actual acceptance.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import time

from .contracts import digest, require
from .evidence import persist
from .native_authority import plain

PREFIX = 'review/stage05_qualified_experience_passage/v01'


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
        and inputs['command'] == 'experience' and inputs['expected_role_calls'] == 3
        and inputs['native_E_calls'] == inputs['effects'] == 0, 'stage05_scenario_input_contract')
    require(operation is not None and operation['schema'] == 'radik.normal_operation.v02',
        'stage05_current_operation_required')
    output = project/'workspace/owner_documents/review/stage05'/operation['run_id']
    require(not output.exists() and not output.is_symlink(), 'stage05_uncertain_retry_refused')
    output.mkdir(parents=True, mode=0o700)
    before = client.budget.snapshot()
    observations = []
    report = dict(schema='radik.stage05.qualified_experience_result.v01', status='STARTED',
        owner_operation_id=operation['owner_operation_id'], run_id=operation['run_id'],
        scenario_input_sha256=digest(raw), observations=observations, actual_model_calls=None,
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

    @contextmanager
    def phase(name):
        started = time.monotonic_ns()
        if event_sink is not None:
            event_sink(dict(kind='PHASE_ENTER', phase='NATIVE', span_id='stage05_'+name, native=True))
        try:
            yield
        finally:
            if event_sink is not None:
                event_sink(dict(kind='PHASE_EXIT', phase='NATIVE', span_id='stage05_'+name, native=True))
            report.setdefault('native_phase_measurements', []).append(
                dict(phase=name, elapsed_wall_ns=time.monotonic_ns()-started))

    try:
        source = store.register_source('stage05:'+operation['run_id']+':rowan',
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
        require(report['actual_model_calls'] == inputs['expected_role_calls'], 'stage05_cold_role_budget')
        checkpoint('ordinary_accepted_result', dict(result=store.result(task),
            source_scope=controller.initial_sources, model_calls=report['actual_model_calls']))

        experience = QualifiedExperience(project/'workspace/owner_documents/state/qualified_experience',
            on_event=event_sink)
        with phase('cold_decision'):
            cold_binding = experience.consume(controller, cold=True)
            baseline = qualified_strategy.run(controller, cold_binding, label='cold')
        checkpoint('cold_allocated_work', baseline)
        with phase('prospective_feedback'):
            feedback = experience.observe(controller, predicted=True)
        checkpoint('qualified_feedback', feedback)
        with phase('subsequent_work'):
            qualified = experience.consume(controller)
            subsequent = qualified_strategy.run(controller, qualified, label='qualified')
        checkpoint('qualified_allocated_work', subsequent)
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
            current_work_ref=qualified.report['work_result_ref'], allocated_work_ref=subsequent['artifact_id'],
            cold_binding_id=cold_binding.report['binding_id'], qualified_binding_id=qualified.report['binding_id'],
            statement='Scoped negative predicate changed actual Work and redistributed the same budget.'))
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
        final = client.budget.snapshot()
        require(final['attempts'] == after_cold['attempts'] and final['active_attempt_id'] is None,
            'stage05_native_provider_calls_forbidden')
        report['status'] = 'OWNER_SCENARIO_COMPLETED_REQUIRES_REVIEW'
        report['ledger_after_sha256'] = digest(final)
        report['result_ref'] = persist(output, 'completed_result', report)
        return report
    except BaseException as error:
        from .stage04_diagnostics import project_error, observe_failure
        observe_failure(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        report['status'] = 'STOPPED_NO_RETRY'
        report['primary_failure'] = project_error(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        try:
            persist(output, 'stopped_result', report)
        except Exception:
            pass
        raise
