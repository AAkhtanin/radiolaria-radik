"""Direct-plan runtime; source and current transition gates precede imports here."""
from pathlib import Path
import json
import os
import stat
import time

from .budget import TurnBudget
from .contracts import canonical, digest, require
from .controller import GOAL, CRITERION, owned_directory
from .task_spec import classify_intent, meaning_key
from .task_store import TaskStore
from .dynamic_temporal import informational_valid_to
from .stage04_diagnostics import (project_error, observe_failure, record_secondary,
    mark_primary_persisted, failure_line, print_primary, PHASES, STEPS)
from .openai_plan_transport import OpenAIPlanTransport
from .plan_auth import PlanAuth
from review.transport.direct_plan_gate import (source_identity, live_transition,
                                              console_transition, PROJECT)


def make_client(auth, *, scope="exam"):
    from .ordinary_rehearsal import RehearsalAuth
    from config.application_profile_gate import validate_rehearsal_context
    require(type(auth) in (PlanAuth,RehearsalAuth),'direct_runtime_own_auth_required')
    if type(auth) is RehearsalAuth:validate_rehearsal_context(PROJECT,auth.context)
    relative='review/direct_plan_passage/transport_observations/'+str(time.time_ns())
    client=OpenAIPlanTransport(project=PROJECT,auth=auth,
        budget=TurnBudget.for_scope(PROJECT,scope),
        observation_directory=relative,
        source_validator=lambda:source_identity(PROJECT,scope=scope),
        admission_validator=lambda **kw:live_transition(project=PROJECT,scope=scope,**kw))
    client.budget_scope=scope
    client.last_live_result_path=None
    return client


def bounded_live_exam(client):
    """First paid operation is the existing actual orchestrator, not a probe."""
    from review.live_exam_document import run
    return run(client)


def _write_policy(workspace):
    path=workspace/'state/owned_effect_policy.json'
    value={'save_allowed':False,'consent_ref':'permission:owner-console-no-effects:v01',
           'valid_to':0,'revision':1,'workspace_ref':'radik:owned:output'}
    if path.exists():
        require(not path.is_symlink() and json.loads(path.read_bytes())==value,
                'console_effect_policy_must_remain_closed')
    else:
        with path.open('xb') as stream:
            stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())


def _document_bytes(name):
    path=Path(name).expanduser().absolute()
    forbidden={'.codex','.aws','codex-home','private','private_native_log','private_native_sqlite',
               'auth.json','credentials.json','tokens.json','.env'}
    require(not set(path.parts).intersection(forbidden), 'console_private_source_refused')
    for node in (path,*path.parents):require(not node.is_symlink(),'console_source_symlink')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),'console_source_not_regular')
        raw=stream.read(16385)
    require(0<len(raw)<=16384 and b'\0' not in raw,'console_source_byte_limit')
    raw.decode('utf-8',errors='strict')
    return raw


def _legacy_material(workspace):
    """Expose the original checkpoint as historical material, never admission."""
    path=workspace/'state/checkpoint.json'
    if not path.exists():return None
    require(not path.is_symlink() and path.stat().st_size<=1048576,'console_legacy_checkpoint_boundary')
    value=json.loads(path.read_bytes())
    require(type(value) is dict and value.get('schema')=='radik.checkpoint.v01'
        and value.get('authority_on_restart')=='NOT_RESTORED'
        and type(value.get('outcome')) is dict,'console_legacy_checkpoint_shape')
    outcome=value['outcome']
    require(outcome.get('version')=='radik.document.result.v02'
        and type(outcome.get('content')) is str and type(outcome.get('valid_to')) is int
        and type(outcome.get('accepted_at')) is int,'console_legacy_result_shape')
    return outcome


def _information_policy_reader(workspace, valid_to, *, informational_delta=False):
    """Bind a finite no-effect decision window to each reread owned policy."""
    def read():
        path=workspace/'state/owned_effect_policy.json'
        require(not path.is_symlink() and path.stat().st_size<=16384,'console_information_policy_boundary')
        raw=path.read_bytes()
        value=json.loads(raw)
        require(type(value) is dict and set(value)=={'save_allowed','consent_ref','valid_to','revision','workspace_ref'}
            and value['save_allowed'] is False and type(value['consent_ref']) is str
            and type(value['valid_to']) is int and type(value['revision']) is int and value['revision']>=1
            and value['workspace_ref']=='radik:owned:output','console_information_policy_closed')
        return {'save_allowed':False,'consent_ref':None if informational_delta else 'radik:information_only:source-policy-sha256:'+digest(raw),
            'valid_to':valid_to,'revision':value['revision'],'workspace_ref':value['workspace_ref']}
    return read


def _record_connected_failure(report, error, *, phase, step, budget, controllers, write_report):
    """Keep the primary refusal even if later evidence recording also fails."""
    observe_failure(error,phase=phase,step=step)
    if report.get('status') not in ('CONNECTED_INFORMATIONAL_OBSERVATIONS_COMPLETE_E_BLOCKED',
            'NATIVE_SCENARIO_OBSERVATIONS_COMPLETE_E_BLOCKED','NATIVE_SCENARIO_PARTIAL_OBSERVATIONS_E_BLOCKED'):
        report['status']='STOPPED_NO_AUTOMATIC_RETRY'
    report.update(raw_error_recorded=False,primary_observed=True,primary_preserved=True,
        primary_preservation_basis='RECORDED_IN_THIS_DOCUMENT_IF_READBACK_VERIFIED',
        partial_snapshots=[],current_phase=phase,current_step=step)
    try:
        if report.get('schema')=='radik.stage04.native_scenario_result.v01':
            report['ledger_after']=budget.snapshot()
            report['ledger_status_after']=budget.scope_status()
        else:report['ledger_after']=budget.scope_status()
    except Exception as status_error:
        record_secondary(error,status_error,phase='BUDGET_OBSERVATION',step=step)
    for controller in controllers.values():
        try:report['partial_snapshots'].append(controller.snapshot())
        except Exception as snapshot_error:
            record_secondary(error,snapshot_error,phase='NATIVE_SNAPSHOT',step=step)
    report['error']=project_error(error,phase=phase,step=step)
    report['error'].pop('primary_persistence',None)
    report['secondary_recording_failures']=report['error'].get('secondary_failures',[])
    report['secondary_failures_scope']='OBSERVED_BEFORE_THIS_DOCUMENT_WRITE'
    try:
        write_report()
        mark_primary_persisted(error)
    except Exception as recording_error:
        record_secondary(error,recording_error,phase='CONNECTED_REPORT_WRITE',step=step)
    report['error']=project_error(error)
    report['secondary_recording_failures']=report['error'].get('secondary_failures',[])
    print_primary(error)


def main(*, client, save_target=None, interactive=True, stage04_acceptance=False,
         console_continuation=None, native_scenario=False, owner_scenario=False,
         command_observer=None):
    """Persistent sequential informational tasks through the admitted native path."""
    require(type(owner_scenario)is bool and(not owner_scenario or not stage04_acceptance and not native_scenario and console_continuation is None),'console_owner_scenario_scope')
    require(command_observer is None or callable(command_observer),'console_command_observer')
    require(save_target is None,'console_save_not_admitted')
    require(type(stage04_acceptance) is bool,'console_stage04_explicit_flag')
    require(type(native_scenario) is bool and (not native_scenario
        or not stage04_acceptance and console_continuation is None), 'console_native_scenario_explicit_flag')
    require(console_continuation is None or type(console_continuation) is dict
        and stage04_acceptance is False, 'console_continuation_explicit_flag')
    console_transition(PROJECT)
    require(getattr(client,'budget_scope',None)=='console','console_explicit_budget_scope_required')
    from review.transport.model_scope import read_scope_state
    workspace=owned_directory(PROJECT,'workspace/owner_documents')
    require(not workspace.is_relative_to(PROJECT/'review'),'console_exam_workspace_refused')
    for name in ('input','state','output','drs','review'):owned_directory(workspace,name)
    _write_policy(workspace)
    store=TaskStore(workspace,require_existing=console_continuation is not None
        or client.budget._normal_operation is not None)
    controllers={}
    from .normal_session import validate_operation
    operation = validate_operation(PROJECT, client.budget._normal_operation) if client.budget._normal_operation is not None else None
    informational_delta = operation is not None and operation['schema']=='radik.normal_operation.v02'
    operation_deadline = getattr(client, '_ordinary_operation_deadline_utc', None) if informational_delta else None
    require(not informational_delta or type(operation_deadline) is int
        and operation['opened_at'] < operation_deadline <= operation['opened_at']+7800,
        'console_current_operation_deadline')
    legacy=_legacy_material(workspace)
    active_step='INTERACTIVE_TASK'
    command_sequence=0
    last_round_observation=None
    qualified_experience_result=None

    def read_console(prompt_id, prompt, **details):
        """The human and supervised driver consume the same ordinary input."""
        if command_observer is not None and client.owner_event_sink is not None:
            client.owner_event_sink(dict(kind='STATUS',phase='PERSISTENCE',
                stage='CONSOLE_INPUT_REQUIRED',prompt_id=prompt_id,
                command_sequence=command_sequence+(prompt_id=='command'),
                semantic_progress=False,**details))
        # Keep machine event rows on their own lines even when stdin is a pipe.
        print(prompt,flush=True)
        return input()

    def observe_command(command, status, before, started_wall, started_cpu, error=None):
        """Persist historical evidence before exposing command completion."""
        if command_observer is None:return
        selected_id=store.state['selected_task_id']
        state=store.snapshot()
        snapshots={}
        for task_id,controller in controllers.items():
            snapshots[task_id]=dict(controller.snapshot(),candidate=controller.candidate,
                initial_sources=controller.initial_sources,memory_origin=controller.memory_origin)
        after=client.budget.snapshot()
        value=dict(schema='radik.ordinary.command_observation.v01',
            command_sequence=command_sequence,command=command,status=status,
            process_id=os.getpid(),task_id=selected_id,
            store_state=state,controller_snapshots=snapshots,
            selected_result=store.result(selected_id) if selected_id is not None else None,
            normal_operation_ref=client.budget._normal_operation,
            round_observation=last_round_observation,
            qualified_experience_result=qualified_experience_result,
            ledger_before=before,ledger_after=after,
            ledger_before_sha256=digest(before),ledger_after_sha256=digest(after),
            attempt_delta=len(after['attempts'])-len(before['attempts']),
            error=None if error is None else project_error(error,phase='TASK_EXECUTION',step='INTERACTIVE_TASK'),
            elapsed_wall_ns=time.monotonic_ns()-started_wall,
            elapsed_process_cpu_ns=time.process_time_ns()-started_cpu,
            authority_on_restart='NOT_RESTORED',automatic_retry=False)
        command_observer(value)

    def progress(event):
        if client.owner_event_sink is not None:client.owner_event_sink(event)
        messages={
            'DYNAMIC_INTAKE_ROOT_ACCEPTED':'Приём задачи подтверждён; проверяю текущую память.',
            'PRE_ARCHITECT_BSEP':'Источники и BSEP проверены; следующий шаг — Architect.',
            'DYNAMIC_NATIVE_REVIEW_START':'Проверяю вложенные native Work и их связи.',
            'DYNAMIC_NATIVE_WORK_START':'Выполняю допущенный native Work.',
            'DYNAMIC_NATIVE_WORK_RETURN':'Native Work завершён; проверяю фактический результат.',
            'DYNAMIC_RESULT_ACCEPTED':'Локальный Root принял результат; сохраняю память.',
            'DYNAMIC_MEMORY_WRITEBACK':'Запись памяти проверена чтением.',
            'DYNAMIC_WARM_COMPLETE':'Текущая память потреблена; новых вызовов модели нет.'}
        message=messages.get(event.get('stage'))
        if message is not None:print(message,flush=True)
        elif event.get('stage')=='DYNAMIC_NATIVE_ACTIVITY':
            print('Проверка native Work продолжается.',flush=True)

    def legacy_summary():
        if legacy is None:return None
        return {'selection':'legacy','profile':'HISTORICAL_TWO_DOCUMENT_COMPARE',
            'accepted_at':legacy['accepted_at'],'valid_to':legacy['valid_to'],
            'time_state':'EXPIRED' if int(time.time())>=legacy['valid_to'] else 'HISTORICAL_REQUIRES_FRESH_VALIDATION',
            'reuse_state':'DISTINCT_PROFILE_CRITERION_POLICY_NOT_ADAPTED',
            'authority_on_restart':'NOT_RESTORED'}
    print('Radik: задачи сравнения, объяснения условий и проверки предложенного ответа по 1–4 разрешённым UTF-8 документам. task <текст>, queue, select <id>, clarify, run, run-memory, continue, cancel, result, memory, status, settings и exit. run — один новый конечный раунд; run-memory — только текущая пригодная память без модели. compare сохраняет прежний ввод двух документов. SAVE не допущен.',flush=True)

    def selected(argument=''):
        task_id=argument or store.state['selected_task_id']
        require(task_id in store.state['tasks'],'console_task_selection_required')
        return task_id

    def read_sources(count):
        require(type(count) is int and 1<=count<=4,'console_source_count')
        source_ids=[]
        for index in range(count):
            name=read_console('source_path','Путь к документу '+str(index+1)+': ',source_index=index+1).strip()
            raw=_document_bytes(name)
            key=str(Path(name).expanduser().absolute())
            source_ids.append(store.register_source(key,Path(key).name,raw))
        require(len(set(source_ids))==len(source_ids),'console_duplicate_source')
        return tuple(source_ids)

    def show_result(task_id):
        if task_id=='legacy':
            require(legacy is not None,'console_legacy_result_unavailable')
            print(legacy['content'],flush=True)
            print('Исторический результат прежнего профиля; срок и разрешения не продлевались. Для новой задачи требуется свежая проверка источников и памяти.',flush=True)
            return
        accepted=store.result(task_id)
        if accepted is None:print('У этой задачи ещё нет принятого результата.',flush=True)
        else:
            print(accepted['content'],flush=True)
            print('Сохранённый материал результата; свежесть, источники и локальный Root проверяются заново при использовании. SAVE не разрешён.',flush=True)

    def run_task(task_id, condition=None, *, require_memory=False, operation_action=None, source_update=False,
            prepare_continuation=True):
        nonlocal active_step,last_round_observation
        require(type(prepare_continuation) is bool, 'console_continuation_preparation_flag')
        if native_scenario:active_step=report.get('current_step','INTERACTIVE_TASK')
        from .dynamic_native import DynamicDocumentController, DynamicAcceptedResult
        spec=store.spec(task_id)
        reader=store.source_reader(spec)
        require(type(source_update) is bool and (not source_update or informational_delta and condition is None
            and not require_memory and task_id in controllers), 'console_source_successor_live_controller_required')
        sources=store.prepare_round_sources(spec) if condition is None and client.budget._normal_operation is not None else reader()
        transition=None
        if source_update:
            graph=controllers[task_id].plan_source_successor(sources)
            transition=store.stage_source_successor(task_id,sources,affected_graph=graph)
        store.check_dispatch_sources(task_id,sources,source_transition=transition)
        dependencies={'meaning_key':meaning_key(spec,sources),
            'sources':[{key:row[key] for key in ('source_ref','revision','sha256')} for row in sources]}
        if condition is not None:
            require(task_id in controllers,'console_continuation_requires_current_native_result')
        operation_round=client.budget.begin_task_round(task_id=task_id,profile=spec.profile,
            task_spec_sha256=digest(spec.plain()),dependencies_sha256=digest(dependencies),
            max_attempts=0 if require_memory or condition is not None else 3,
            operation_action=operation_action,
            mode=('INFORMATIONAL_DELTA' if source_update else 'NATIVE_CONTINUE' if condition is not None else 'MEMORY_ONLY' if require_memory else 'COLD')
                if client.budget._normal_operation is not None else None,
            source_successor_ref=transition.staged_ref if transition is not None else None)
        last_round_observation=dict(task_id=task_id,binding=operation_round,
            started=False,outcome_status=None,closure=None)
        started=False;primary_error=None;previous_result=None
        try:
            if transition is not None:
                from .source_successor import advance
                advance(store,transition,'ROUND_LINKED',round_binding=operation_round)
            previous_result=store.result(task_id)
            store.begin(task_id,sources,operation_round=operation_round,source_transition=transition);started=True
            last_round_observation['started']=True
            print('Шаг '+active_step+': проверяю источники и память; при необходимости вызываю Orchestrator. Затем — native Work и локальный Root.',flush=True)
            if source_update:
                controller=controllers[task_id]
                outcome=controller.update_sources(sources,store=store,source_transition=transition)
            elif condition is None:
                controller=DynamicDocumentController(workspace,client,task_spec=spec,source_reader=reader,
                    policy_reader=_information_policy_reader(workspace,informational_valid_to(int(time.time())),informational_delta=informational_delta),
                    on_event=progress,informational_delta=informational_delta,operation_deadline=operation_deadline)
                controllers[task_id]=controller
                outcome=controller.run(require_memory=require_memory)
            else:
                outcome=controllers[task_id].revise(condition)
            if getattr(outcome,'status',None)=='EXHAUSTED':
                from .native_authority import plain
                last_round_observation['native_refusal']=plain(outcome)
                last_round_observation['native_refusal_type']=type(outcome).__module__+'.'+type(outcome).__name__
                store.fail(task_id)
                last_round_observation['outcome_status']='EXHAUSTED'
                print('Исчерпан исходный бюджет продолжения; прежний результат сохранён в истории.',flush=True)
                return outcome
            accepted=outcome.plain
            store.complete(task_id,accepted)
            if prepare_continuation and informational_delta and not source_update and condition is None and controller.memory_origin is None:
                controller.prepare_source_continuation()
            show_result(task_id)
            last_round_observation['outcome_status']='COMPLETED'
            return outcome
        except BaseException as error:
            primary_error=error
            observe_failure(error,phase='TASK_EXECUTION',step=active_step)
            if started and store.state['active_task_id']==task_id:
                controller=controllers.get(task_id)
                accepted=getattr(controller,'accepted',None)
                try:
                    if type(accepted) is DynamicAcceptedResult and accepted.plain != previous_result:
                        store.complete(task_id,accepted.plain,late_failure=True)
                    else:store.fail(task_id)
                except Exception as history_error:
                    record_secondary(error,history_error,phase='TASK_HISTORY_WRITE',step=active_step)
            raise
        finally:
            try:
                if not started and informational_delta:
                    closed=client.budget.abort_task_round_before_start()
                else:closed=client.budget.end_task_round()
                last_round_observation['closure']=closed
            except Exception as closing_error:
                if primary_error is None:
                    observe_failure(closing_error,phase='TASK_ROUND_CLOSE',step=active_step)
                    raise
                record_secondary(primary_error,closing_error,phase='TASK_ROUND_CLOSE',step=active_step)

    if owner_scenario:
        require(informational_delta,'console_owner_scenario_v02_required')
        from .owner_scenario import ScenarioReportWriter,run_owner_scenario
        writer=ScenarioReportWriter(PROJECT,operation['run_id'])
        client.last_stage04_result_path=writer.relative
        run_owner_scenario(store=store,run_task=run_task,controllers=controllers,client=client,
            operation=operation,report_sink=writer.write,event_sink=client.owner_event_sink)
        return 0

    if stage04_acceptance or console_continuation is not None:
        # Explicit owner action uses the same store, readers, task rounds and
        # native controller as manual tasks. These texts are fictional evidence.
        active_step='SETUP';active_phase='CONNECTED_SETUP'
        operation=client.budget._console_operation
        continuation_context=None
        if console_continuation is not None:
            continuation_context=store.console_continuation_context(PROJECT,console_continuation)
            require(all(continuation_context[key]==operation[key]
                for key in ('owner_operation_id','run_id')), 'console_continuation_operation_binding')
        report_relative='workspace/owner_documents/review/stage04_actual_runs/'+operation['run_id']+'.json'
        report_path=PROJECT/report_relative
        require(not report_path.exists() and not report_path.is_symlink(),'console_stage04_no_uncertain_retry')
        report_path.parent.mkdir(parents=True,exist_ok=True)
        report={'schema':'radik.stage04.actual_connected_result.v01',
            'owner_operation_id':operation['owner_operation_id'],'run_id':operation['run_id'],
            'status':'STARTED','fictional_domains':['support','delivery_returns'],
            'native_E_status':'BLOCKED_INFORMATIONAL_ACTION_PACKET_UNAVAILABLE',
            'selective_delta_accepted':False,'external_effects':0,'steps':[],
            'ledger_before':client.budget.scope_status(),
            'transport_directory':client.observation_directory,'current_phase':active_phase,
            'current_step':active_step,'automatic_retry':False}
        if continuation_context is not None:
            report['console_continuation']=continuation_context
            report['task_ids']=dict(continuation_context['task_ids'])
        def write_report():
            pending=report_path.with_suffix('.pending')
            try:
                require(not pending.exists() and not pending.is_symlink(),'console_stage04_report_pending')
                raw=canonical(report)
                with pending.open('xb') as stream:
                    stream.write(raw);stream.flush();os.fsync(stream.fileno())
                os.replace(pending,report_path)
                parent=os.open(report_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(parent)
                finally:os.close(parent)
                fd=os.open(report_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as stream:
                    require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode)
                        and stream.read(len(raw)+1)==raw,'console_stage04_report_readback')
                client.last_stage04_result_path=report_relative
            except BaseException as recording_error:
                observe_failure(recording_error,phase='CONNECTED_REPORT_WRITE',step=active_step)
                raise
        try:
            write_report()
            if continuation_context is not None:
                prepared=store.prepare_console_continuation(PROJECT,console_continuation)
                require(prepared==continuation_context,'console_continuation_task_binding')
                a,b,c=(prepared['task_ids'][key] for key in ('a','b','c'))
                report['console_continuation']['failed_first_action_requeued_once']=True
                report['console_continuation']['historical_rounds_preserved']=True
            else:
                source_a=store.register_source('stage04:fiction:support:a','fiction_support_a.txt',
                    b'Fictional Service A: replies within one day. Support is available 08:00-16:00. Urgent requests use telephone.\n')
                source_b=store.register_source('stage04:fiction:support:b','fiction_support_b.txt',
                    b'Fictional Service B: replies within two days. Support is available 09:00-17:00. Urgent requests use chat except on holidays.\n')
                source_c=store.register_source('stage04:fiction:delivery:terms','fiction_delivery_terms.txt',
                    b'Fictional Store C: delivery takes three working days. Returns are accepted within fourteen days unless the sealed item was opened. Return postage is not specified.\n')
                a=store.create(goal='Compare the support conditions of the two fictional services.',
                    source_ids=(source_a,source_b),profile='compare',criterion='Compare response times, hours, conditions and exceptions.',topic='support_conditions')
                b=store.create(goal='Explain the delivery and return conditions of the fictional store.',
                    source_ids=(source_c,),profile='explain',criterion='Explain delivery, return conditions, exceptions and unknown charges.',topic='delivery_returns',predecessor_task_id=a)
                c=store.create(goal='Verify the proposed answer about the fictional store.',source_ids=(source_c,),
                    profile='verify',criterion='Check each assertion against the source and preserve uncertainty.',
                    topic='delivery_returns',supplied_candidate='Returns are always accepted within fourteen days, including opened sealed items, and return postage is free.',predecessor_task_id=b)
            report['task_ids']={'a':a,'b':b,'c':c}
            task_actions={'A_COLD':a,'B_COLD':b,'A_CURRENT_MEMORY':a,'C_VERIFY':c}
            action_ids=['A_COLD','B_COLD','A_CURRENT_MEMORY','C_VERIFY']
            if continuation_context is not None and 'proposal_ref' in continuation_context:
                action_ids=continuation_context['operation_actions']
                require(type(action_ids)is list and 1<=len(action_ids)<=4
                    and len(action_ids)==len(set(action_ids)) and all(label in task_actions for label in action_ids),
                    'console_continuation_action_scope')
            for label in action_ids:
                task_id=task_actions[label]
                active_step=label;active_phase='TASK_EXECUTION'
                report.update(current_phase=active_phase,current_step=active_step)
                print('Связанный сценарий: '+label+'.',flush=True)
                store.select(task_id);before=len(client.budget.snapshot()['attempts'])
                run_task(task_id,require_memory=label=='A_CURRENT_MEMORY',
                    operation_action=label if continuation_context is not None and 'proposal_ref' in continuation_context else None)
                accepted=store.result(task_id)
                require(type(accepted) is dict,'console_stage04_actual_result_required')
                after=len(client.budget.snapshot()['attempts'])
                report['steps'].append({'step':label,'task_id':task_id,'new_turn_attempts':after-before,
                    'accepted_result':accepted,'native_snapshot':controllers[task_id].snapshot()})
                if label=='A_CURRENT_MEMORY':require(after==before,'console_stage04_current_memory_miss_no_retry')
                write_report()
            report.update(status='CONNECTED_INFORMATIONAL_OBSERVATIONS_COMPLETE_E_BLOCKED',
                ledger_after=client.budget.scope_status(),authority_on_restart='NOT_RESTORED')
            write_report()
        except BaseException as error:
            _record_connected_failure(report,error,phase=active_phase,step=active_step,
                budget=client.budget,controllers=controllers,write_report=write_report)
            raise
        active_phase='RETURN_PUBLICATION';active_step='REPORT'
        report.update(current_phase=active_phase,current_step=active_step)
        print('Информационные результаты сохранены; собираю и проверяю отчёт.',flush=True)
        try:
            from review.package_direct_plan_return import publish_stage04_owner_result
            delivery=publish_stage04_owner_result(PROJECT,report_relative,client.observation_directory)
        except BaseException as error:
            _record_connected_failure(report,error,phase=active_phase,step=active_step,
                budget=client.budget,controllers=controllers,write_report=write_report)
            raise
        client.last_stage04_return=delivery
        print('Связанный информационный сценарий завершён. Отчёт: '+delivery['report_status']+'. Конечный recovery scope закрыт; консоль завершает работу. Для обычной новой сессии используйте --console. Native G2-E остаётся заблокирован публичным NO_EFFECTS контрактом.',flush=True)
        return 0

    if native_scenario:
        from .stage04_native_scenario import run_native_scenario
        operation=client.budget._console_operation
        selected_id=store.state['selected_task_id']
        if selected_id not in store.state['tasks'] or len(store.spec(selected_id).source_ids)<2:
            candidates=[task_id for task_id in store.state['queue']
                if store.state['tasks'][task_id]['spec'] is not None
                and store.spec(task_id).profile=='compare' and len(store.spec(task_id).source_ids)>=2]
            selected_id=candidates[-1] if candidates else None
        require(selected_id in store.state['tasks'],'console_native_scenario_sources_required')
        source_ids=store.spec(selected_id).source_ids
        require(len(source_ids)>=2,'console_native_scenario_sources_required')
        active_step='SETUP';active_phase='CONNECTED_SETUP'
        report_relative='workspace/owner_documents/review/stage04_actual_runs/'+operation['run_id']+'.json'
        report_path=PROJECT/report_relative
        require(not report_path.exists() and not report_path.is_symlink(),'console_stage04_no_uncertain_retry')
        report_path.parent.mkdir(parents=True,exist_ok=True)
        report={'schema':'radik.stage04.native_scenario_result.v01','status':'STARTED',
            **operation,'steps':[],'external_effects':0,'automatic_retry':False,
            'transport_directory':client.observation_directory,'current_phase':active_phase,'current_step':active_step}
        def write_native_report(snapshot=None):
            nonlocal active_phase,active_step
            if snapshot is not None:report.update(snapshot)
            active_phase=report.get('current_phase') if report.get('current_phase') in PHASES else 'UNKNOWN'
            active_step=report.get('current_step') if report.get('current_step') in STEPS else 'UNKNOWN'
            report.update(owner_operation_id=operation['owner_operation_id'],run_id=operation['run_id'],
                transport_directory=client.observation_directory,automatic_retry=False)
            pending=report_path.with_suffix('.pending')
            require(not pending.exists() and not pending.is_symlink(),'console_stage04_report_pending')
            raw=canonical(report)
            with pending.open('xb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.replace(pending,report_path)
            parent=os.open(report_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(parent)
            finally:os.close(parent)
            require(report_path.read_bytes()==raw,'console_stage04_report_readback')
            client.last_stage04_result_path=report_relative
        try:
            write_native_report()
            active_step='INTERACTIVE_TASK';active_phase='TASK_EXECUTION'
            result=run_native_scenario(store=store,run_task=run_task,controllers=controllers,
                source_ids=source_ids,owner_operation_id=operation['owner_operation_id'],
                run_id=operation['run_id'],client=client,report_sink=write_native_report)
            write_native_report(result)
            active_phase='RETURN_PUBLICATION';active_step='REPORT'
            from review.package_direct_plan_return import publish_stage04_owner_result
            delivery=publish_stage04_owner_result(PROJECT,report_relative,client.observation_directory)
            client.last_stage04_return=delivery
            print('Наблюдения native сценария сохранены. Отчёт: '+delivery['report_status']+
                '. Обычная рабочая сессия продолжена; новые задачи автоматически не запускаются.',flush=True)
        except BaseException as error:
            if active_phase!='RETURN_PUBLICATION':
                safe=project_error(error,phase=report.get('current_phase',active_phase),
                    step=report.get('current_step',active_step))
                active_phase,active_step=safe['phase'],safe['step']
            _record_connected_failure(report,error,phase=active_phase,step=active_step,
                budget=client.budget,controllers=controllers,write_report=write_native_report)
            raise
        active_step='INTERACTIVE_TASK'
    if not interactive:return 0

    observe_command('ready','READY',client.budget.snapshot(),time.monotonic_ns(),time.process_time_ns())
    while True:
        try:
            line=read_console('command','Команда: ').strip()
            command,_,argument=line.partition(' ')
            command=command.lower();argument=argument.strip()
        except EOFError:return 0
        command_sequence+=1
        before=client.budget.snapshot();prior_count=len(before['attempts'])
        started_wall=time.monotonic_ns();started_cpu=time.process_time_ns()
        last_round_observation=None
        command_status='COMPLETED';command_error=None
        try:
            if command in ('exit','quit','выход'):
                command_status='EXIT'
                return 0
            if command=='compare':
                task_id=store.create(goal=GOAL,source_ids=read_sources(2),profile='compare',criterion=CRITERION,
                    topic='support_conditions')
                print('Задача '+task_id,flush=True)
                run_task(task_id)
            elif command in ('task','задача'):
                goal=argument or read_console('task_goal','Опишите информационную задачу: ').strip()
                profile=classify_intent(goal)
                source_ids=read_sources(int(read_console('source_count','Число разрешённых документов [1–4]: ').strip()))
                criterion=read_console('criterion','Критерий или условия ответа: ').strip() or None
                candidate=read_console('candidate','Предложенный ответ для проверки: ').strip() if profile=='verify' else None
                task_id=store.create(goal=goal,source_ids=source_ids,profile=profile,criterion=criterion,
                    supplied_candidate=candidate or None,predecessor_task_id=store.state['selected_task_id'])
                print('Задача '+task_id+'; '+store.state['tasks'][task_id]['status'],flush=True)
            elif command in ('queue','tasks'):
                print(json.dumps({'selected_task_id':store.state['selected_task_id'],
                    'historical_result':legacy_summary(),
                    'tasks':[{'task_id':task_id,'status':store.state['tasks'][task_id]['status'],
                        'profile':store.state['tasks'][task_id]['draft']['profile'],
                        'results':len(store.state['tasks'][task_id]['results'])}
                        for task_id in store.state['queue']]},ensure_ascii=False),flush=True)
            elif command=='select':
                store.select(selected(argument))
                print('Выбрана задача '+store.state['selected_task_id'],flush=True)
            elif command=='clarify':
                task_id=selected(argument)
                row=store.state['tasks'][task_id]
                require(row['status'] in ('CLARIFICATION_REQUIRED','QUEUED','INTERRUPTED'),
                    'console_completed_clarification_requires_continuation')
                profile=read_console('task_profile','Профиль [compare/explain/verify]: ').strip().lower()
                criterion=read_console('criterion','Критерий или условия ответа: ').strip()
                candidate=read_console('candidate','Предложенный ответ для проверки: ').strip() if profile=='verify' else None
                store.clarify(task_id,{'profile':profile,'criterion':criterion,'supplied_candidate':candidate})
                print('Уточнение сохранено; задача готова к run.',flush=True)
            elif command=='experience':
                require(not argument and informational_delta, 'qualified_experience_ordinary_scope')
                from .qualified_experience_scenario import run as run_experience
                prior_step=active_step
                active_step='STAGE05_EXPERIENCE'
                try:
                    qualified_experience_result=run_experience(store=store,run_task=run_task,
                        controllers=controllers,client=client,operation=operation,
                        event_sink=client.owner_event_sink)
                finally:
                    active_step=prior_step
                print('Stage 5 scenario completed; independent actual review is required.',flush=True)
            elif command=='run':run_task(selected(argument))
            elif command=='run-memory':run_task(selected(argument),require_memory=True)
            elif command=='continue':
                task_id=selected(argument)
                if task_id not in controllers:
                    command_status='REFUSED_NO_CURRENT_CONTROLLER'
                    print('Продолжение требует актуального native результата в этом процессе. Выберите задачу и выполните run для свежей проверки источников и памяти.',flush=True)
                else:
                    kinds={'conditions':'focus_conditions','exceptions':'focus_exceptions','unknowns':'review_unknowns'}
                    kind=read_console('continue_kind','Уточнение [conditions/exceptions/unknowns]: ').strip().lower()
                    require(kind in kinds,'console_continuation_condition')
                    indexes=read_console('continue_indexes','Номера оснований от 1 через запятую (Enter — все): ').strip()
                    claims=controllers[task_id].candidate['claims']
                    allowed={'conditions':('condition',),'exceptions':('exception',),'unknowns':('unknown','contradiction')}[kind]
                    count=len(claims)
                    chosen=[index for index,claim in enumerate(claims) if claim['kind'] in allowed] if not indexes \
                        else [int(value.strip())-1 for value in indexes.split(',')]
                    require(1<=len(chosen)<=8 and len(set(chosen))==len(chosen)
                        and all(0<=index<count and claims[index]['kind'] in allowed for index in chosen),
                        'console_continuation_claim_indexes')
                    run_task(task_id,{'kind':kinds[kind],'claim_indexes':chosen})
            elif command=='cancel':
                task_id=selected(argument);store.cancel(task_id)
                print('Задача отменена для следующих запусков. Отмена удалённого запроса не утверждается; сохранённые результаты оставлены в истории.',flush=True)
            elif command=='result':
                show_result('legacy' if argument=='legacy' or not argument
                    and store.state['selected_task_id'] is None and legacy is not None else selected(argument))
            elif command=='memory':
                task_id=selected(argument)
                controller=controllers.get(task_id)
                events=controller.memory.events if controller is not None else []
                print(json.dumps({'task_id':task_id,'memory_events':events,
                    'retained_results':len(store.state['tasks'][task_id]['results']),
                    'authority_on_restart':'NOT_RESTORED'},ensure_ascii=False),flush=True)
            elif command=='status':
                print(json.dumps({'profile':'DYNAMIC_INFORMATIONAL_TASKS_NO_EFFECTS',
                    'exam_budget':read_scope_state(PROJECT,'exam'),
                    'console_budget':read_scope_state(PROJECT,'console'),
                    'model_settings':client.budget.current_model_settings(),
                    'selected_task_id':store.state['selected_task_id'],
                    'active_task_id':store.state['active_task_id'],
                    'task_count':len(store.state['tasks']),
                    'historical_result':legacy_summary(),
                    'save_allowed':False,'workspace':'workspace/owner_documents'},ensure_ascii=False),flush=True)
            elif command=='settings':
                parts=argument.split()
                if not parts:print(json.dumps(client.budget.current_model_settings(),ensure_ascii=False),flush=True)
                else:
                    require(len(parts)==2,'console_settings_arguments')
                    print(json.dumps(client.budget.configure_console(model=parts[0],effort=parts[1]),ensure_ascii=False),flush=True)
            elif command=='update':
                task_id=selected(argument)
                require(informational_delta and task_id in controllers,'console_source_successor_live_controller_required')
                spec=store.spec(task_id)
                source_id=read_console('update_source','Approved source ID to update: ').strip()
                require(source_id in spec.source_ids,'console_source_successor_scope')
                source_path=read_console('update_path','Current UTF-8 source path: ').strip()
                raw=_document_bytes(source_path)
                registered=store.state['sources'][source_id]
                # Updating approved bytes preserves the logical identity. The
                # source-successor journal and fresh O/A/C authorize its use.
                logical=Path(source_path).expanduser().absolute()
                actual='radik:source:'+digest(str(logical).encode('utf-8'))[:32]
                require(actual==source_id,'console_source_successor_logical_identity')
                require(store.register_source(str(logical),registered['label'],raw)==source_id,
                    'console_source_successor_logical_identity')
                run_task(task_id,source_update=True)
            elif command=='save':
                command_status='REFUSED_SAVE'
                print('SAVE не допущен в информационном профиле.',flush=True)
            else:
                command_status='UNKNOWN_COMMAND'
                print('Неизвестная команда.',flush=True)
        except BaseException as error:
            command_error=error;command_status='REFUSED'
            observe_failure(error,phase='TASK_EXECUTION',step='INTERACTIVE_TASK')
            print_primary(error)
            if not isinstance(error,(ValueError,OSError,UnicodeError,EOFError)):raise
            # Failed/unknown inference cannot restart from the menu.
            ledger=client.budget.snapshot()
            if ledger['active_attempt_id'] is not None or len(ledger['attempts'])!=prior_count:return 2
        finally:
            if command_error is None and last_round_observation is not None:
                command_status=last_round_observation['outcome_status'] or command_status
            try:
                observe_command(command,command_status,before,started_wall,started_cpu,command_error)
                if command_error is not None and command_observer is not None:
                    mark_primary_persisted(command_error)
            except BaseException as recording_error:
                if command_error is None:raise
                record_secondary(command_error,recording_error,phase='CONNECTED_REPORT_WRITE',step='INTERACTIVE_TASK')
                raise command_error
