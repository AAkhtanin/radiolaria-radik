"""Focused SOURCE-only negative consumers in one separately sealed copied entry.

The ordinary stdin dispatcher and lexical run_task remain the consumers. Only a
named exception immediately before TaskStore.begin is injected, once, to examine
grant closure. No role product, controller result or native result is fabricated.
"""
import io
import json
from pathlib import Path
import sys
import time


def run(*, project, context, client, operation_ref, owner_lock_fd, export):
    from config.application_profile_gate import validate_rehearsal_context
    from app import runtime, normal_session as normal, normal_profile, source_successor
    from app.contracts import canonical, digest, require
    from app.task_store import TaskStore
    validate_rehearsal_context(project,context)
    project=Path(project)
    require(project==context.application_root and project!=context.environment_root
        and client.budget._normal_operation==operation_ref and callable(export),
        'ordinary_controls_isolated_scope')
    operation=normal.validate_operation(project,operation_ref)
    require(operation['schema']=='radik.normal_operation.v02','ordinary_controls_current_operation')
    workspace=project/'workspace/owner_documents'
    original_ledger=client.budget.snapshot()
    original_store=TaskStore(workspace,require_existing=True)
    original_state=original_store.snapshot()
    original_results={task_id:list(row['results']) for task_id,row in original_state['tasks'].items()}
    original_requests=json.loads(canonical(client.auth.requests))
    reports=[]

    def snapshot():
        current=TaskStore(workspace,require_existing=True)
        return dict(store=current.snapshot(),ledger=client.budget.snapshot(),
            grant_index=normal_profile.index(project),
            active=json.loads(normal._read(project,normal.ACTIVE)))

    def refuse(call,expected):
        try:call()
        except ValueError as error:
            require(error.args==(expected,),'ordinary_controls_wrong_refusal')
            return dict(status='REFUSED',code=expected)
        raise ValueError('ordinary_controls_refusal_missing')

    def scripted(label,lines):
        """Feed actual stdin; never duplicate the ordinary command dispatcher."""
        observations=[];references=[]
        def observe(value):
            references.append(export('control_'+label+'_command',value))
            observations.append(value)
        previous=sys.stdin
        try:
            sys.stdin=io.StringIO('\n'.join(lines)+'\n')
            code=runtime.main(client=client,interactive=True,command_observer=observe)
        finally:sys.stdin=previous
        require(code==0 and observations and observations[0]['status']=='READY'
            and observations[-1]['status']=='EXIT','ordinary_controls_script_exit')
        require(client.budget.snapshot()==original_ledger and client.budget._task_round is None,
            'ordinary_controls_no_model_or_open_round')
        return observations,references

    def only_command(observations,command):
        rows=[row for row in observations if row['command']==command]
        require(len(rows)==1,'ordinary_controls_command_identity')
        return rows[0]

    def no_work_refusal(row,expected):
        require(row['status']=='REFUSED' and row['error']['code']==expected
            and row['attempt_delta']==0 and row['ledger_after']==row['ledger_before'],
            'ordinary_controls_refusal_binding')
        if row['round_observation'] is not None:
            task=row['round_observation']['task_id']
            controller=row['controller_snapshots'].get(task)
            require(controller is None or controller['started'] is False
                and controller['result'] is None,'ordinary_controls_unexpected_work')

    # Create a unique task using genuine stdin/source intake; then cancel it.
    # The installed prepare_round_sources refusal happens before any round grant.
    control_input=project/'workspace/owner_documents/review/p31_control_input.txt'
    require(not control_input.exists(),'ordinary_controls_input_replay')
    raw=b'If a fictional support ticket includes a local reference, triage can begin.\n'
    with control_input.open('xb') as stream:stream.write(raw)
    before=snapshot()
    rows,refs=scripted('cancel',[
        'task Explain a unique copied cancellation control.',
        '1',str(control_input),'Preserve this task while rejecting later dispatch.',
        'cancel','run','result','exit'])
    refused_run=only_command(rows,'run')
    no_work_refusal(refused_run,'task_cancelled_before_dispatch')
    after=snapshot()
    require(refused_run['round_observation'] is None and before['grant_index']==after['grant_index']
        and after['store']['tasks'][refused_run['task_id']]['status']=='CANCELLED',
        'ordinary_controls_cancel_before_grant')
    reports.append(dict(case='CANCELLED_ORDINARY_RUN_PREGRANT',before=before,after=after,
        command_refs=refs,refusal=refused_run['error'],new_grants=0,new_work=0))

    # A missing memory row must refuse through the real controller after a real
    # zero-call round and intake Root. No controller method is replaced.
    before=snapshot()
    rows,refs=scripted('missing_memory',[
        'task Explain a unique missing-memory control.',
        '1',str(control_input),'Use only previously accepted material for this unique meaning.',
        'run-memory','exit'])
    missing=only_command(rows,'run-memory')
    no_work_refusal(missing,'dynamic_qualified_memory_required')
    require(missing['round_observation']['started'] is True
        and missing['round_observation']['binding']['normal_round_scope']['mode']=='MEMORY_ONLY'
        and missing['round_observation']['closure'] is not None,
        'ordinary_controls_missing_memory_round')
    reports.append(dict(case='MISSING_MEMORY_ORDINARY_NO_FALLBACK',before=before,after=snapshot(),
        command_refs=refs,refusal=missing['error'],new_work=0))

    # Use naturally expired preserved P30 bytes and the real current clock.
    # Neither the record, its payload, TTL nor any application clock is edited.
    current=TaskStore(workspace,require_existing=True)
    expired=[]
    for task_id,row in original_state['tasks'].items():
        if row['status']=='COMPLETED' and row['results']:
            value=current.result(task_id)
            if value['valid_to']<=int(time.time()):expired.append((task_id,value))
    require(bool(expired),'ordinary_controls_expired_original_required')
    expired_id,expired_result=max(expired,key=lambda item:item[1]['valid_to'])
    before=snapshot()
    rows,refs=scripted('expired_memory',['select '+expired_id,'run-memory','exit'])
    stale=only_command(rows,'run-memory')
    no_work_refusal(stale,'dynamic_qualified_memory_required')
    require(stale['round_observation']['started'] is True
        and stale['round_observation']['closure'] is not None,
        'ordinary_controls_expired_memory_round')
    reports.append(dict(case='EXPIRED_MEMORY_ORDINARY_REAL_CLOCK_NO_FALLBACK',
        before=before,after=snapshot(),command_refs=refs,refusal=stale['error'],
        task_id=expired_id,original_result=expired_result,observed_utc=int(time.time()),
        clock_replaced=False,ttl_changed=False,new_work=0))

    # Exactly one injected pre-begin exception follows a real durable grant.
    # The unchanged method is restored before any later command or consumer.
    original_begin=TaskStore.begin
    injected=[]
    def before_begin(store,task_id,sources,**kwargs):
        binding=kwargs['operation_round']
        normal.validate_round(project,binding,task_state=store.state,before_begin=True,current=True)
        require(not injected,'ordinary_controls_injection_once')
        injected.append(dict(task_id=task_id,binding=binding,state=store.snapshot()))
        raise ValueError('task_dispatch_state')
    before=snapshot()
    try:
        TaskStore.begin=before_begin
        rows,refs=scripted('prebegin',[
            'task Explain a unique pre-begin closure control.',
            '1',str(control_input),'Keep the grant closed after the named injected exception.',
            'run','exit'])
    finally:TaskStore.begin=original_begin
    failed=only_command(rows,'run')
    no_work_refusal(failed,'task_dispatch_state')
    after=snapshot()
    round_value=failed['round_observation']
    require(len(injected)==1 and round_value['started'] is False
        and round_value['binding']==injected[0]['binding'] and round_value['closure'] is not None
        and after['grant_index'][:-1]==before['grant_index']
        and len(after['grant_index'])==len(before['grant_index'])+1,
        'ordinary_controls_prebegin_grant_closed')
    closed=normal._reference(project,round_value['closure'])
    require(closed['disposition']=='ABORTED_BEFORE_START'
        and 'round_ref' not in after['active']
        and not any(row['kind']=='ROUND_STARTED' for row in
            after['store']['tasks'][injected[0]['task_id']]['history']),
        'ordinary_controls_prebegin_abort_receipt')
    reports.append(dict(case='LEXICAL_RUN_TASK_PREBEGIN_EXCEPTION_CLOSURE',
        classification='NAMED_ISOLATED_PREBEGIN_EXCEPTION_NOT_NATIVE_SEMANTIC_ACCEPTANCE',
        before=before,after=after,command_refs=refs,injection=injected,
        refusal=failed['error'],abort=closed,new_work=0))

    # TaskStore construction must interrupt a staged successor without
    # reconstructing a live token. This uses actual changed copied source bytes.
    store=TaskStore(workspace,require_existing=True)
    completed=[task_id for task_id,row in original_state['tasks'].items()
        if row['status']=='COMPLETED' and row['results']
        and store.state['tasks'][task_id]['status']=='COMPLETED']
    # The expired-memory refusal changed only one copied task to FAILED.
    # The independently reviewed P30 baseline retains other completed tasks.
    require(bool(completed),'ordinary_controls_completed_original_required')
    task_id=completed[-1];spec=store.spec(task_id)
    old=store.source_reader(spec)();stage_basis='PRESERVED_COMPLETED_P30_COPY'
    before_store=store.snapshot();before_result=store.result(task_id)
    source_id=old[0]['source_ref'];source_path=store.project/'input'/store.state['sources'][source_id]['filename']
    original_bytes=source_path.read_bytes();changed_bytes=original_bytes+b'\nChanged copied source for interruption only.\n'
    require(len(changed_bytes)<=16384,'ordinary_controls_changed_source_bound')
    source_path.write_bytes(changed_bytes)
    updated=store.source_reader(spec)()
    token=store.stage_source_successor(task_id,updated,affected_graph=dict(
        changed_sources=[source_id],classification='DURABILITY_ONLY_NO_E'))
    staged_ref,staged=source_successor.validate(store,token,updated)
    reopened=TaskStore(store.project,require_existing=True)
    records,latest=source_successor.read(reopened)
    interrupted_ref,interrupted=latest[token.successor_id]
    closed_token=refuse(lambda:source_successor.validate(store,token,updated),'source_successor_closed')
    foreign_token=refuse(lambda:source_successor.validate(reopened,token,updated),'source_successor_live_origin')
    require(interrupted['status']=='RESTART_INTERRUPTED'
        and reopened.state['tasks'][task_id]['origin_dependencies']==before_store['tasks'][task_id]['origin_dependencies']
        and reopened.state['tasks'][task_id]['results']==before_store['tasks'][task_id]['results']
        and reopened.result(task_id)==before_result,'ordinary_controls_successor_interruption')
    reports.append(dict(case='SOURCE_SUCCESSOR_INTERRUPTION_NO_AUTHORITY_RESTORATION',
        basis=stage_basis,task_id=task_id,before=before_store,after=reopened.snapshot(),
        original_source=dict(path=str(source_path),sha256=digest(original_bytes),text=original_bytes.decode()),
        changed_source=dict(path=str(source_path),sha256=digest(changed_bytes),text=changed_bytes.decode()),
        staged_ref=staged_ref,staged=staged,interrupted_ref=interrupted_ref,interrupted=interrupted,
        closed_token=closed_token,foreign_token=foreign_token,native_E_calls=0))
    final=TaskStore(workspace,require_existing=True).snapshot()
    require(client.budget.snapshot()==original_ledger and client.budget._task_round is None
        and client.auth.requests==original_requests
        and all(final['tasks'][task_id]['results'][:len(refs)]==refs
            for task_id,refs in original_results.items()),
        'ordinary_controls_original_results_or_accounting_changed')
    result=dict(schema='radik.p31.ordinary_controls.v01',status='PASS_FOCUSED_COPIED_CONSUMERS',
        classification='SOURCE_ONLY_NOT_OWNER_ACTUAL_SEMANTIC_ACCEPTANCE',
        reports=reports,original_state=original_state,final_state=final,
        ledger_before=original_ledger,ledger_after=client.budget.snapshot(),
        external_requests_before=original_requests,external_requests_after=client.auth.requests,
        model_calls=0,provider_calls=0,native_Work_calls=0,native_E_calls=0,
        exception_injection_restored=TaskStore.begin is original_begin,
        revision_exhaustion_scope='SEPARATE_FULL_ORDINARY_REHEARSAL_A4',
        unchanged_native_resource_and_provenance_negatives='CREDIT_ONLY_WITH_EXACT_SOURCE_BINDINGS',
        automatic_retry=False)
    export('ordinary_focused_controls',result)
    return result
