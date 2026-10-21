"""Finite isolated UNKNOWN/normal-operation link; no provider or native execution.

Exact new disposition and normal journal functions execute on copied state.
Historical admission/profile validation and six role outcomes are explicit inert
interfaces. The original task-budget pending/ack accounting function is real.
"""
import argparse
import ast
import builtins
import copy
from dataclasses import dataclass, asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import unicodedata
import uuid
from types import SimpleNamespace

PROJECT=Path('/Users/admin/Projects/RadiolariaRadik')
BASE='review/stage05_qualified_experience_passage/v04'
SELF=BASE+'/unknown_disposition_controls.py'
WORK=PROJECT/BASE/'offline_actual/UNKNOWN_LINK_V01/work'
ROOT=WORK/'isolated'
STARTED=time.monotonic()


def require(value, code):
    if not value: raise ValueError(code)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if type(value)is bytes else canonical(value)).hexdigest()


def exact(ref):
    path=PROJECT/ref['path'];require(path.is_relative_to(PROJECT) and '..' not in path.parts,'link_path')
    for p in (path,*path.parents):
        require(not p.is_symlink(),'link_symlink')
        if p==PROJECT:break
    raw=path.read_bytes();require(digest(raw)==ref['sha256'] and len(raw)==ref['size_bytes'],'link_pin')
    return raw


def save(relative,value):
    path=ROOT/relative;path.parent.mkdir(parents=True,exist_ok=True)
    raw=value if type(value)is bytes else canonical(value)
    with path.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    require(path.read_bytes()==raw,'link_readback')
    return dict(path=relative,sha256=digest(raw),size_bytes=len(raw))


def replace(relative,value):
    raw=value if type(value)is bytes else canonical(value)
    path=ROOT/relative
    with path.open('wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    require(path.read_bytes()==raw,'link_readback')


def fence(reads):
    stdlib=Path(sys.base_prefix).resolve()
    def audit(event,args):
        if event.startswith(('socket.','subprocess.')) or event in ('os.system','os.fork','os.forkpty',
                'os.posix_spawn','os.exec','ctypes.dlopen','ctypes.dlsym'):
            raise ValueError('link_external_action_denied')
        if event=='import' and args:
            require(str(args[0]).split('.')[0] not in ('app','hedgehog','config'),'link_whole_app_import_denied')
        if event=='open' and args and not isinstance(args[0],int):
            path=Path(os.fsdecode(args[0])).absolute();mode,flags=args[1:3]
            write=isinstance(mode,str) and any(c in mode for c in 'wax+') or isinstance(flags,int) and bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            require(path.is_relative_to(WORK) if write else path in reads or path.is_relative_to(WORK)
                or path.resolve().is_relative_to(stdlib),'link_io_scope')
        if event in ('os.mkdir','os.remove','os.unlink','os.rmdir','os.rename','os.chmod','os.chown','os.link','os.symlink'):
            for value in args[:2] if event in ('os.rename','os.link','os.symlink') else args[:1]:
                if isinstance(value,(str,bytes,Path)):
                    require(Path(os.fsdecode(value)).absolute().is_relative_to(WORK),'link_mutation_scope')
    sys.addaudithook(audit)


def extract(raw,path,*,constants=(),functions=(),classes=(),extra=None,all_definitions=False):
    nodes=[];found=set()
    for n in ast.parse(raw,filename=path).body:
        if isinstance(n,ast.Assign) and (all_definitions or len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in constants):
            nodes.append(n)
            if len(n.targets)==1 and isinstance(n.targets[0],ast.Name):found.add(n.targets[0].id)
        elif isinstance(n,ast.FunctionDef) and (all_definitions or n.name in functions):nodes.append(n);found.add(n.name)
        elif isinstance(n,ast.ClassDef) and (all_definitions or n.name in classes):nodes.append(n);found.add(n.name)
    if not all_definitions:require(set(constants)|set(functions)|set(classes)<=found,'link_extract_inventory')
    ns=dict(__name__='__main__',__package__='link_boundary',__builtins__=vars(builtins));ns.update(extra or {})
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(ROOT/path),'exec'),ns)
    return ns


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--grant',required=True);parser.add_argument('--sha256',required=True);args=parser.parse_args()
    require(args.grant==BASE+'/unknown_disposition_controls_grant.json','link_grant_path')
    grant_raw=(PROJECT/args.grant).read_bytes();require(digest(grant_raw)==args.sha256,'link_grant_pin');grant=json.loads(grant_raw)
    require(grant['reviewer']=='/root/private_remote_controls' and grant['approved_executor']=='/root'
        and grant['approved_invocation_count']==1 and grant['actual_id']=='UNKNOWN_LINK_V01'
        and grant['network']=='DENIED' and grant['production_writes_allowed'] is False
        and grant['real_AUTH_provider_native_E_SAVE_allowed'] is False,'link_independent_grant')
    exact(grant['runner_ref']);proposal=json.loads(exact(grant['proposal_ref']))
    refs=proposal['source_refs']+proposal['input_refs'];raws={r['path']:exact(r) for r in refs}
    require(not WORK.exists(),'link_no_retry');WORK.mkdir(parents=True,mode=0o700);ROOT.mkdir()
    fence({PROJECT/r['path'] for r in refs}|{PROJECT/SELF,PROJECT/args.grant,PROJECT/grant['proposal_ref']['path']})
    prepare=json.loads(raws[BASE+'/unknown_disposition_preparation.json']);actual=prepare['future_proposal'];before_refs=prepare['predecessor_refs']
    for ref in before_refs.values():save(ref['path'],raws[ref['path']])
    before=json.loads(raws[before_refs['before_ledger_ref']['path']]);tasks_before=json.loads(raws[before_refs['before_task_state_ref']['path']]);selected=actual['selected_attempt_id']
    save('state/console_model_turns.json',canonical(before));save('workspace/owner_documents/state/dynamic_tasks.json',canonical(tasks_before))
    settings=json.loads(raws['state/task_model_settings.json']);save('state/task_model_settings.json',canonical(settings))
    save('state/console_model_turns.lock',b'');lock_ref=save('review/direct_plan_passage/owner_start.lock',b'');os.chmod(ROOT/lock_ref['path'],0o600)
    lock_fd=os.open(ROOT/lock_ref['path'],os.O_RDWR|os.O_NOFOLLOW)
    save('review/stage04_dynamic_passage/actual_basis/state/console_model_turns.json',raws['review/stage04_dynamic_passage/actual_basis/state/console_model_turns.json'])
    source_names=('normal_session','console_continuation','stage05_disposition','ordinary_entry')
    for name in source_names:save('app/'+name+'.py',raws[BASE+'/after/app/'+name+'.py'])
    input_path=BASE+'/inputs/scenario.json';save(input_path,raws[input_path]);inputs=json.loads(raws[input_path])
    pins={'app/'+n+'.py':digest(raws[BASE+'/after/app/'+n+'.py']) for n in source_names};pins[input_path]=digest(raws[input_path]);source_sha=digest(pins);auth_sha='a'*64
    source_review_ref=save('review/link_fixture/runtime_source_review.json',dict(schema='EXPLICIT_SYNTHETIC_PROFILE_BOUNDARY',pins=pins))
    admission_ref=save('review/link_fixture/current_source_admission.json',dict(schema='EXPLICIT_SYNTHETIC_PROFILE_BOUNDARY'))
    profile=dict(pins=pins,auth_source_identity_sha256=auth_sha,source_review_ref=source_review_ref,source_admission_ref=admission_ref)
    profile_ref=save('review/link_fixture/profile.json',profile)
    actual=copy.deepcopy(actual);actual.update(source_identity_sha256=source_sha,auth_source_identity_sha256=auth_sha,profile_ref=profile_ref)
    actual['operation_allowance']['scenario_ref']=dict(path=input_path,sha256=digest(raws[input_path]),size_bytes=len(raws[input_path]))
    proposal_ref=save('review/link_fixture/unknown_proposal.json',actual)
    review_ref=save('review/link_fixture/unknown_review.json',dict(schema='radik.stage05.unknown_disposition_review.v01',reviewer='/root/private_remote_controls',status='SOURCE_ACCEPTED_FOR_EXPLICIT_OWNER_DISPOSITION_AND_FINITE_REMAINDER',proposal_sha256=proposal_ref['sha256'],source_identity_sha256=source_sha,auth_source_identity_sha256=auth_sha,owner_action_required=True,entry_authorizes_model_or_effect=False))
    # This fixture review is a synthetic external admission interface, not an owner grant.
    decision=dict(selected_attempt_id=selected,proposal_ref=proposal_ref,review_ref=review_ref)
    owner_admission_ref=save(BASE+'/owner_admission.json',dict(independent_reviewer='/root/private_remote_controls',
        status='OWNER_EXECUTION_ADMITTED_AFTER_SOURCE_AND_REHEARSAL',owner_execution_authorized=True,
        code_pins=pins,ordinary_profile_manifest_ref=profile_ref,source_review_ref=source_review_ref,
        selected_unknown_acknowledgement=decision,synthetic_control_metadata=True))
    launch=dict(schema='radik.p28.owner_terminal_launch.v01',process_index=1,prior_child_receipt_ref=None,
        source_review_ref=source_review_ref,ordinary_profile_manifest_ref=profile_ref,automatic_retry=False,
        inherited_lock_fd=lock_fd,admission_sha256=owner_admission_ref['sha256'],selected_unknown_acknowledgement=decision)
    launch_ref=save(BASE+'/owner_terminal_runs/LINK/process_1_launch.json',canonical(launch)+b'\n');binding=digest(launch)
    modules={};common=dict(Path=Path,json=json,hashlib=hashlib,os=os,re=re,stat=stat,time=time,fcntl=fcntl,
        uuid=uuid,unicodedata=unicodedata,dataclass=dataclass,asdict=asdict,require=require,canonical=canonical,digest=digest)
    def importer(name,globals=None,locals=None,fromlist=(),level=0):
        if level==1 and name=='':return SimpleNamespace(**modules)
        if level==0 and name=='app' and fromlist==('stage05_disposition',):return SimpleNamespace(stage05_disposition=modules['stage05_disposition'])
        require(name in modules and (level==1 or name=='review.transport.model_scope'),'link_import_scope')
        return modules[name]
    common['__builtins__']=dict(vars(builtins),__import__=importer)
    normal_functions=('_hash','_identity','_path','_read','_json','_ref','_reference','_sync','_exclusive','_replace',
        '_owner_lock','_operation_path','_round_path','_closed','validate_operation','open_operation','_close_operation',
        'close_operation','_active_operation','validate_round_shape','prepare_round','validate_round','finish_round')
    normal=extract(raws[BASE+'/after/app/normal_session.py'],'app/normal_session.py',
        constants=('VERSION','ACTIVE','LEDGER','TASKS','SETTINGS','ROUND_VERSION','MODES','UUID'),functions=normal_functions,extra=common)
    N=SimpleNamespace(**normal);modules['normal_session']=N
    def historical(project,ledger):
        require(ledger['version']==before['version'] and ledger['attempts'][:50]==before['attempts']
            and all(ledger[k]==before[k] for k in before if k not in ('attempts','active_attempt_id','ledger_sha256')),
            'link_historical_external_boundary')
        value={k:v for k,v in ledger.items() if k!='normal_policy_transition_ref'};value['version']='radik.console_turn_ledger.v04';value['ledger_sha256']=digest({k:v for k,v in value.items() if k!='ledger_sha256'});return value
    normal['historical_ledger']=N.historical_ledger=historical
    normal['_initial']=N._initial=lambda project:(before['normal_policy_transition_ref'],None,None,None)
    profile_ns=extract(raws['app/normal_profile.py'],'app/normal_profile.py',constants=('INDEX','ROUND_VERSION','MODES'),
        functions=('validate_operation','index','register_grant','validate_round_shape'),extra=dict(common,normal=N))
    profile_ns['profile']=lambda project,reference:profile if reference==profile_ref else (_ for _ in ()).throw(ValueError('link_profile_ref'))
    modules['normal_profile']=SimpleNamespace(**profile_ns,current=lambda project:(profile_ref,profile))
    modules['review.transport.model_scope']=SimpleNamespace(OWNER_LOCK_PATH=lock_ref['path'])
    disposition=extract(raws[BASE+'/after/app/stage05_disposition.py'],'app/stage05_disposition.py',all_definitions=True,extra=dict(common,normal=N))
    D=SimpleNamespace(**disposition);modules['stage05_disposition']=D
    ordinary=extract(raws[BASE+'/after/app/ordinary_entry.py'],'app/ordinary_entry.py',
        functions=('_stage05_owner_disposition',),extra=common)
    old_ack=[r['attempt_id'] for r in before['attempts'] if r['outcome']=='UNKNOWN' and r['attempt_id']!=selected]
    def legacy(project,ledger):
        require(ledger['attempts'][:min(50,len(ledger['attempts']))]==before['attempts'][:min(50,len(ledger['attempts']))], 'link_legacy_prefix')
        return dict(acknowledged_remote_unknown_attempt_ids=old_ack,local_occupancy_released=True)
    # Only the appended wrapper executes; exact historical validation is a bounded external interface.
    tree=ast.parse(raws[BASE+'/after/app/console_continuation.py']);wrapper=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='validate'][-1]
    console=dict(common,_validate_before_stage05_disposition=legacy,__name__='__main__',__package__='link_boundary')
    exec(compile(ast.Module(body=[wrapper],type_ignores=[]),str(ROOT/'app/console_continuation.py'),'exec'),console)
    round_ns=extract(raws[BASE+'/after/app/console_continuation.py'],'app/console_continuation.py',
        constants=('ROUND_FIELDS','PROOF_FIELDS','RELATIVE_PROOF_FIELDS','ROUND_ALLOWANCE_VERSION','RELATIVE_ROUND_ALLOWANCE_VERSION','ACTION_IDS'),
        functions=('validate_round_binding','_ref','_result_ref_shape'),extra=common)
    def allowance_history(project,ledger,task_state=None):
        if task_state is not None:require(all(task_state['tasks'].get(k)==v for k,v in tasks_before['tasks'].items()),'link_historical_tasks_changed')
        return {}
    C=SimpleNamespace(validate=console['validate'],validate_allowance_history=allowance_history,
        VERSION='radik.console_turn_ledger.v03',CHAIN_VERSION='radik.console_turn_ledger.v04',
        validate_round_binding=round_ns['validate_round_binding'],read=lambda project,path:N._read(project,path))
    modules['console_continuation']=C
    initial_three=json.loads(raws['review/stage04_dynamic_passage/actual_basis/state/console_model_turns.json'])
    base=SimpleNamespace(read_public=lambda project,path:(ROOT/path).read_bytes(),
        validate_console_ledger=lambda value,**k:require(value==initial_three,'link_initial_three_changed'),
        TERMINAL_OUTCOMES=('COMPLETED','FAILED','DENIED','CANCELLED'))
    budget=extract(raws['app/task_budget.py'],'app/task_budget.py',constants=('VERSION','BEFORE'),functions=('validate_ledger',),
        extra=dict(common,base=base,is_hash=lambda value:type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None,validate_round_binding=C.validate_round_binding))
    transition=dict(transition_sha256=before['transition_sha256'],activation_identity_sha256=before['activation_sha256'],task_policy={'sha256':before['task_policy_sha256']})
    def state(project):
        ledger=json.loads((ROOT/N.LEDGER).read_bytes());budget['validate_ledger'](ROOT,ledger,transition,settings)
        return dict(counted=len(ledger['attempts']),active_attempt_id=ledger['active_attempt_id'],source_identity_sha256=source_sha,**C.validate(ROOT,ledger))
    modules['task_budget']=SimpleNamespace(read_state=state)
    spec=extract(raws['app/task_spec.py'],'app/task_spec.py',all_definitions=True,extra=common);modules['task_spec']=SimpleNamespace(**spec)
    intake=extract(raws['app/intake.py'],'app/intake.py',classes=('ApprovedSourceStore',),extra=common)
    successor=extract(raws['app/source_successor.py'],'app/source_successor.py',functions=('dependencies',),extra=dict(common,TaskSpec=spec['TaskSpec'],meaning_key=spec['meaning_key'],meaning_scope=spec['meaning_scope']))
    modules['source_successor']=SimpleNamespace(dependencies=successor['dependencies'],
        current_dependencies=lambda store,tid:store.state['tasks'][tid]['origin_dependencies'],
        interrupt=lambda store:require(store.state['active_task_id']is None,'link_no_inherited_task_occupancy'))
    store_ns=extract(raws['app/task_store.py'],'app/task_store.py',constants=('STORE_VERSION','STATUSES','MAX_TASKS','MAX_STATE_BYTES','MAX_RESULT_BYTES'),functions=('_copy',),classes=('TaskStore',),
        extra=dict(common,TaskSpec=spec['TaskSpec'],TASK_VERSION=spec['TASK_VERSION'],TASK_ID=spec['TASK_ID'],SOURCE_ID=spec['SOURCE_ID'],ApprovedSourceStore=intake['ApprovedSourceStore']))
    # No provider, Root or Work methods are invoked by this structural control.
    operation_id='a152a521-1234-4abc-8abc-0123456789ab';run_id='a152a5211234'
    negatives=[]
    def refused(name,code,call):
        try:call()
        except ValueError as error:require(error.args==(code,),'link_wrong_refusal');negatives.append(dict(case=name,code=code))
        else:raise ValueError('link_missing_refusal')
    common_args=dict(source_identity_sha256=source_sha,auth_source_identity_sha256=auth_sha,profile_ref=profile_ref)
    apply_args=dict(owner_lock_fd=lock_fd,owner_operation_id=operation_id,run_id=run_id,
        owner_launch_ref=launch_ref,owner_run_binding=binding,**common_args)
    open_args=dict(owner_lock_fd=lock_fd,owner_operation_id=operation_id,run_id=run_id,
        source_review_ref=source_review_ref,source_admission_ref=admission_ref,**common_args)
    hook=ordinary['_stage05_owner_disposition'];gate=SimpleNamespace(_read=N._read,require=require)
    hook_selected=dict(manifest=profile,profile_ref=profile_ref)
    hook_args=dict(owner_lock_fd=lock_fd,owner_operation_id=operation_id,run_id=run_id,
        source_identity_sha256=source_sha,auth_source_identity_sha256=auth_sha)
    require(hook(ROOT,SimpleNamespace(owner_supervisor_launch=None),hook_selected,gate,**hook_args)is None,
        'link_ordinary_unsupervised_no_disposition')
    require(state(ROOT)['active_attempt_id']==selected,'link_original_unknown')
    refused('owner_consent_absent','stage05_disposition_owner_confirmation_required',lambda:D.apply(ROOT,proposal_ref,review_ref,owner_confirmed=False,**apply_args))
    refused('normal_open_before_release','normal_active_or_unknown',lambda:N.open_operation(ROOT,**open_args))
    forged=dict(before,active_attempt_id=None);forged['ledger_sha256']=digest({k:v for k,v in forged.items()if k!='ledger_sha256'})
    refused('header_clear_without_receipt','task_scope_active_or_unknown',lambda:budget['validate_ledger'](ROOT,forged,transition,settings))
    require((ROOT/N.LEDGER).read_bytes()==canonical(before) and not (ROOT/D.RECEIPT).exists(),'link_no_unauthorized_mutation')
    codepath='app/stage05_disposition.py';code_before=(ROOT/codepath).read_bytes();replace(codepath,code_before+b'\n')
    refused('changed_current_source','stage05_disposition_current_source',lambda:D.prepare(ROOT,proposal_ref,review_ref,**common_args));replace(codepath,code_before)
    prepared=D.prepare(ROOT,proposal_ref,review_ref,**common_args)
    released=hook(ROOT,SimpleNamespace(owner_supervisor_launch=launch_ref['path'],owner_run_binding=binding),
        hook_selected,gate,**hook_args)
    released_ledger=json.loads((ROOT/N.LEDGER).read_bytes());require(released_ledger['attempts']==before['attempts'] and state(ROOT)['counted']==50 and state(ROOT)['active_attempt_id']is None,'link_preserved_release')
    refused('wrong_fresh_operation','stage05_disposition_operation_binding',lambda:N.open_operation(ROOT,**dict(open_args,run_id='b152a5211234')))
    operation_ref=N.open_operation(ROOT,**open_args);operation=N.validate_operation(ROOT,operation_ref)
    store=store_ns['TaskStore'](ROOT/'workspace/owner_documents',require_existing=True)
    slots=[]
    for index,name in enumerate(('rowan','alder')):
        chosen=inputs if index==0 else inputs['unrelated'];sid=store.register_source('stage05:'+run_id+':'+name,'Inert '+name,chosen['source_text'].encode())
        tid=store.create(goal=chosen['goal'],source_ids=(sid,),profile=chosen['ordinary_profile'],criterion=chosen['criterion'],topic=chosen['topic'])
        material=store.source_reader(store.spec(tid))();dependencies=successor['dependencies'](store.spec(tid),material)
        request=dict(task_id=tid,round_id='task-round:'+uuid.uuid4().hex,profile=store.spec(tid).profile,
            task_spec_sha256=digest(store.spec(tid).plain()),dependencies_sha256=digest(dependencies),max_attempts=3)
        ledger=json.loads((ROOT/N.LEDGER).read_bytes())
        binding_round=N.prepare_round(ROOT,ledger,request,operation_ref=operation_ref,mode='COLD')
        store.begin(tid,material,operation_round=binding_round)
        N.validate_round(ROOT,binding_round,task_state=store.state,current=True,for_dispatch=True)
        rawpath='workspace/owner_documents/input/'+store.state['sources'][sid]['filename'];raw_before=(ROOT/rawpath).read_bytes();replace(rawpath,raw_before+b' changed')
        refused(name+'_changed_source_dispatch','stage05_disposition_task_source_binding',lambda:N.validate_round(ROOT,binding_round,task_state=store.state,current=True,for_dispatch=True));replace(rawpath,raw_before)
        # Explicit inert terminal producer: validates local accounting, never native/product acceptance.
        for role in ('orchestrator','architect','critic'):
            stamp=int(time.time());settings_row=settings['entries'][-1]
            row=dict(attempt_id='radik-call:'+uuid.uuid4().hex,role=role,context_sha256=digest((tid+role).encode()),
                purpose='ISOLATED_SYNTHETIC_ACCOUNTING_CONTROL',started_at=stamp,requested_model=settings_row['model'],requested_effort=settings_row['effort'],requested_service_tier=None,
                outcome='COMPLETED',usage={'synthetic':True},served_model='UNKNOWN',owner_operation_id=operation_id,run_id=run_id,
                round_binding=binding_round,round_index=('orchestrator','architect','critic').index(role),previous_attempt_sha256=digest(ledger['attempts'][-1]),settings_sha256=settings['current_sha256'],finished_at=stamp,telemetry={'terminal_observed':True,'synthetic':True})
            ledger['attempts'].append(row)
        ledger['ledger_sha256']=digest({k:v for k,v in ledger.items()if k!='ledger_sha256'});replace(N.LEDGER,ledger)
        require(state(ROOT)['counted']==53+3*index,'link_real_accounting_count')
        store.state['active_task_id']=None;store.state['tasks'][tid]['status']='COMPLETED';store._event(tid,'ROUND_ACCEPTED');store._save()
        close_ref=N.finish_round(ROOT,ledger,binding_round)
        slots.append(dict(slot=D.SLOTS[index],task_id=tid,source_id=sid,normal_round_binding=binding_round,close_ref=close_ref))
    final=json.loads((ROOT/N.LEDGER).read_bytes());extra=copy.deepcopy(final);extra['attempts'].append(copy.deepcopy(final['attempts'][-1]))
    refused('seventh_stage05_attempt','stage05_disposition_six_attempt_cap',lambda:D.extend_status(ROOT,extra,legacy(ROOT,extra)))
    require(final['attempts'][:50]==before['attempts'] and final['attempts'][49]['outcome']==final['attempts'][49]['usage']=='UNKNOWN'
        and len(final['attempts'])==56 and all(store.state['tasks'][k]==v for k,v in tasks_before['tasks'].items()),'link_final_prefix')
    close_ref=N.close_operation(ROOT,owner_lock_fd=lock_fd,operation_ref=operation_ref)
    os.close(lock_fd)
    result=dict(schema='radik.stage05.unknown_link_control.v01',status='PASS',prepared=prepared,release=released,
        before_ledger_sha256=digest(canonical(before)),after_release_ledger_sha256=digest(canonical(released_ledger)),
        original_attempts_sha256=digest(before['attempts']),after_release_attempts_sha256=digest(released_ledger['attempts']),
        final_original_prefix_sha256=digest(final['attempts'][:50]),original_count=50,after_release_count=50,
        synthetic_final_count=56,old_unknown_unchanged=True,negative_controls=negatives,operation_ref=operation_ref,
        separate_allowance=actual['operation_allowance'],fresh_slots=slots,normal_close_ref=close_ref,
        explicit_test_doubles=['Historical source/transition/profile admission','Existing old continuation validation against exact50-row prefix','No-op source-successor interruption for inactive copied store','Six synthetic terminal row/task outcomes'],
        actual_functions=['ordinary_entry._stage05_owner_disposition','stage05_disposition all runtime predicates and apply','appended console continuation validate wrapper','task_budget.validate_ledger including pending/ack accounting','normal_session operation/round I/O and guards','normal_profile operation/round/index functions','TaskStore register_source/create/source_reader/begin and immutable TaskSpec','ApprovedSourceStore raw reads/revisions'],
        production_ACK=False,synthetic_owner_consent=True,provider_calls=0,native_calls=0,effects=0,application_whole_modules_imported=False,
        owner_admission=False,elapsed_seconds=time.monotonic()-STARTED)
    for ref in refs:exact(ref)
    save('review/link_fixture/result.json',result)
    report=WORK/'result.json';raw=canonical(result)+b'\n'
    with report.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    require(report.read_bytes()==raw,'link_result_readback')
    print('UNKNOWN_LINK_RETURN '+json.dumps(dict(status='PASS',path=report.relative_to(PROJECT).as_posix(),sha256=digest(raw),size_bytes=len(raw))),flush=True)


if __name__=='__main__':main()
