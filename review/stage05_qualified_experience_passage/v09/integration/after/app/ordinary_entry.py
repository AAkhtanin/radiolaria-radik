"""Selected ordinary owner entry and its explicitly bounded copied rehearsal.

Installation precedes this fresh process. The same readers, task operation and
transport are used; only typed external fixtures replace real AUTH/HTTP in copy.
"""
import fcntl
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

PREFIX='review/g2e_successor_passage/proposals/g2e_no_effects_v28_ordinary_entry_owner_scenario'


def _helper(project,manifest,relative,name):
    from config.application_profile_gate import _read,require
    raw=_read(project,relative);require(hashlib.sha256(raw).hexdigest()==manifest['pins'].get(relative),'ordinary_helper_source_changed')
    spec=importlib.util.spec_from_file_location(name,Path(project)/relative);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    exec(compile(raw,str(Path(project)/relative),'exec'),module.__dict__)
    return module


def _reference(project,value):
    from config.application_profile_gate import require,_read
    path=Path(value['path']);path=path if path.is_absolute()else Path(project)/path
    require(path.is_relative_to(Path(project)),'ordinary_event_owned_reference')
    raw=_read(project,str(path.relative_to(project)))
    size=value.get('size_bytes',value.get('bytes'))
    require(type(size)is int and len(raw)==size and hashlib.sha256(raw).hexdigest()==value['sha256'],'ordinary_event_readback')
    return dict(path=str(path.relative_to(project)),sha256=value['sha256'],size_bytes=size)


def _sources(project,selected,export):
    from config.application_profile_gate import require,_read
    from hedgehog import work_execution_host_v01 as host
    from app import dynamic_delta_work,dynamic_work,informational_core,native_document
    from app import qualified_experience_work,qualified_strategy
    from hedgehog.kernel import diagnostic_telemetry_v01 as diagnostic
    manifest=selected['manifest'];native=manifest['native_files'];origins=[]
    for logical,ref in native.items():
        if logical.startswith(('hedgehog/','demo/'))and logical.endswith('.py'):
            name=logical[:-3].replace('/','.')
            if name.endswith('.__init__'):name=name[:-9]
            module=importlib.import_module(name);path=Path(module.__file__).resolve(strict=True)
            require(path==Path(project)/ref['path']and module.__spec__.origin==str(path)
                and hashlib.sha256(_read(project,ref['path'])).hexdigest()==ref['sha256'],'ordinary_native_module_origin')
            origins.append(dict(module=name,path=ref['path'],sha256=ref['sha256'],loader=type(module.__loader__).__module__+'.'+type(module.__loader__).__name__))
    from jsonschema import Draft202012Validator
    import jsonschema_specifications
    resources=[]
    for logical,ref in native.items():
        if logical.startswith('schemas/'):
            raw=_read(project,ref['path']);schema=json.loads(raw);Draft202012Validator.check_schema(schema)
            resources.append(dict(logical=logical,path=ref['path'],sha256=hashlib.sha256(raw).hexdigest(),schema_id=schema.get('$id'),draft=schema.get('$schema')))
    require(len(origins)==sum(logical.startswith(('hedgehog/','demo/')) and logical.endswith('.py') for logical in native)
        and len(resources)==sum(logical.startswith('schemas/') for logical in native)
        and 43<=len(origins)<=160 and 33<=len(resources)<=100
        and len(jsonschema_specifications.REGISTRY)>0,'ordinary_native_schema_closure')
    # Exercise the actual ordinary module's own __file__-relative schema reader.
    from hedgehog import capability_admission_v01 as capability
    require(Path(capability.__file__).resolve().parents[1]/'schemas/capability_admission_v01.schema.json'==Path(project)/native['schemas/capability_admission_v01.schema.json']['path'],
        'ordinary_required_schema_path')
    callbacks=[]
    for module,names in [(dynamic_work,('validate_inputs','validate_outputs','execute')),
            (dynamic_delta_work,('validate_inputs','validate_outputs','execute')),
            (informational_core,('validate_source_inputs_v26','validate_source_outputs_v26','execute_source_digest_v26')),
            (native_document,('validate_pure_inputs','validate_pure_outputs','execute_extraction','execute_comparison')),
            (qualified_experience_work,('validate_inputs','validate_outputs','execute_verify','execute_audit')),
            (qualified_strategy,('validate_inputs','validate_outputs','execute_source','execute_check','execute_consumer')),
            (host,('capture_current_informational_source_v01','validate_current_informational_source_capture_v01')),
            (diagnostic,('diagnostic_span_v01','diagnostic_phase_v01','diagnostic_consumer_v01','diagnostic_progress_v01'))]:
        for name in names:
            if not hasattr(module,name):continue
            callback=getattr(module,name);observation=host.observe_local_capability_code_v01(callback)
            path=Path(inspect.getsourcefile(callback)).resolve(strict=True);relative=str(path.relative_to(project))
            require(manifest['pins'].get(relative)==hashlib.sha256(_read(project,relative)).hexdigest()==observation.source_sha256,
                'ordinary_loaded_callback_source')
            callbacks.append(dict(symbol=module.__name__+'.'+name,observation=observation))
    from app.native_authority import plain
    export('ordinary_loader_schema_callback_origins',dict(status='PASS_REAL_ORDINARY_LOADER',native_origins=origins,
        schema_resources=resources,external_registry_ids=sorted(jsonschema_specifications.REGISTRY),
        actual_registry_count=len(jsonschema_specifications.REGISTRY),callbacks=plain(callbacks),
        application_root=str(project),environment_root=str(selected['rehearsal_context'].environment_root)if selected['rehearsal_context']else str(project)))


def _boundary_checks(project,context,export,owner_lock_fd,manifest):
    from config import application_profile_gate as gate
    from app.plan_auth import PlanAuth
    from dataclasses import replace
    import socket
    rows=[]
    def refused(name,call,expected):
        try:call()
        except ValueError as error:gate.require(error.args==(expected,),'ordinary_boundary_wrong_refusal')
        else:raise ValueError('ordinary_boundary_false_acceptance')
        rows.append(dict(case=name,status='REFUSED',code=expected))
    for action in ('AUTH','HTTP','MODEL','PRODUCTION_ACTIVATION'):
        refused('source_seal_'+action.lower(),lambda action=action:gate.require_external_owner(project,action),
            'rehearsal_external_action_refused')
    refused('real_auth_constructor',lambda:PlanAuth(project),'rehearsal_external_action_refused')
    refused('foreign_context',lambda:gate.validate_rehearsal_context(project,replace(context,application_root=project.parent)),
        'rehearsal_typed_context_required')
    refused('production_context',lambda:gate.validate_rehearsal_context(gate.REAL_PROJECT,context),'rehearsal_typed_context_required')
    refused('real_socket',lambda:socket.socket(),'rehearsal_external_process_or_network_refused')
    refused('production_write',lambda:(gate.REAL_PROJECT/'state/p28_forbidden_probe').open('x'),
        'rehearsal_production_write_refused')
    installer=_helper(project,manifest,PREFIX+'/activate_profile.py','radik_p28_rehearsal_install_probe')
    idempotent=installer.activate(project,rehearsal_context=context,owner_lock_fd=owner_lock_fd)
    return export('ordinary_external_boundary_refusals',dict(status='PASS',controls=rows,
        verified_idempotent_install=idempotent,production_authority=False,actual_external_calls=0))


def _failure_detail(project,environment,error,boundary):
    """Public source frames and owned missing paths, never exception payloads."""
    def owned_name(value):
        if not isinstance(value,(str,bytes)):return None
        try:
            path=Path(value).absolute()
            if set(path.parts).intersection(('private','.codex','.aws','Arena','arena','credentials.json','tokens.json')):return None
            for root,label in ((Path(project),'APPLICATION'),(Path(environment),'READ_ONLY_ENVIRONMENT')):
                if path.is_relative_to(root):return dict(root=label,path=str(path.relative_to(root)))
        except (ValueError,TypeError):pass
        return None
    frames=[];trace=error.__traceback__
    while trace is not None and len(frames)<32:
        frame=trace.tb_frame;name=owned_name(frame.f_code.co_filename)
        frames.append(dict(source=name or dict(root='EXTERNAL_STDLIB',path='NOT_EXPORTED'),
            line=trace.tb_lineno,function=frame.f_code.co_name))
        trace=trace.tb_next
    return dict(boundary=boundary,missing_owned_path=owned_name(getattr(error,'filename',None)),
        source_frames=frames,exception_payload_exported=False)


def _operation_timing_name(project, args, manifest, gate, *, inherited_clock):
    """Select the short clock only for an exactly bound Stage05 launch."""
    stage05='review/stage05_qualified_experience_passage/v09/integration'
    launch_name=getattr(args,'owner_supervisor_launch',None)
    selected=(inherited_clock and not args.owner_scenario and type(launch_name) is str
        and launch_name.startswith(stage05+'/owner_terminal_runs/'))
    if not selected:
        return PREFIX+'/supervisor_timing.py'
    launch=json.loads(gate._read(project,launch_name))
    raw=json.dumps(launch,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    gate.require(launch.get('schema') in ('radik.stage05.source_rehearsal_launch.v01',
        'radik.p28.owner_terminal_launch.v01')
        and hashlib.sha256(raw).hexdigest()==args.owner_run_binding
        and launch.get('source_review_ref')==manifest['source_review_ref']
        and launch.get('process_index')==1 and launch.get('prior_child_receipt_ref') is None
        and all(launch.get(key)==getattr(args,'owner_'+key) for key in
            ('operation_started_ns','operation_deadline_ns','operation_started_utc')),
        'ordinary_stage05_launch_binding')
    return stage05+'/supervisor_timing.py'


def _stage05_owner_disposition(project, args, selected, gate, *, owner_lock_fd,
        owner_operation_id, run_id, source_identity_sha256, auth_source_identity_sha256):
    """Consume only the explicit decision in the independently admitted launch."""
    stage05='review/stage05_qualified_experience_passage/v09/integration'
    launch_name=getattr(args,'owner_supervisor_launch',None)
    if not (type(launch_name) is str and launch_name.startswith(stage05+'/owner_terminal_runs/')):
        return None
    raw=gate._read(project,launch_name);launch=json.loads(raw)
    canonical=json.dumps(launch,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    manifest=selected['manifest']
    profile_identity={key:selected['profile_ref'][key] for key in ('path','sha256')}
    launch_profile=launch.get('ordinary_profile_manifest_ref')
    gate.require(launch.get('schema')=='radik.p28.owner_terminal_launch.v01'
        and hashlib.sha256(canonical).hexdigest()==args.owner_run_binding
        and launch.get('source_review_ref')==manifest['source_review_ref']
        and type(launch_profile) is dict and set(launch_profile)=={'path','sha256','size_bytes'}
        and {key:launch_profile[key] for key in ('path','sha256')}==profile_identity
        and launch.get('process_index')==1 and launch.get('prior_child_receipt_ref') is None
        and launch.get('automatic_retry') is False
        and launch.get('inherited_lock_fd')==owner_lock_fd,
        'ordinary_stage05_disposition_launch')
    admission_raw=gate._read(project,stage05+'/owner_admission.json');admission=json.loads(admission_raw)
    decision=launch.get('selected_unknown_acknowledgement')
    gate.require(hashlib.sha256(admission_raw).hexdigest()==launch.get('admission_sha256')
        and admission.get('independent_reviewer')=='/root/private_remote_controls'
        and admission.get('status')=='OWNER_EXECUTION_ADMITTED_AFTER_SOURCE_AND_REHEARSAL'
        and admission.get('owner_execution_authorized') is True
        and admission.get('code_pins')==manifest['pins']
        and admission.get('ordinary_profile_manifest_ref')==launch_profile
        and admission.get('source_review_ref')==manifest['source_review_ref']
        and type(decision) is dict and set(decision)=={'selected_attempt_id','proposal_ref','review_ref'}
        and decision==admission.get('selected_unknown_acknowledgement')
        and decision['selected_attempt_id']=='radik-call:3d5197d2edd747e8b4ec5dd56afcb16a',
        'ordinary_stage05_explicit_unknown_decision')
    from app import stage05_disposition_successor as stage05_disposition
    return stage05_disposition.apply(project,decision['proposal_ref'],decision['review_ref'],
        owner_lock_fd=owner_lock_fd,owner_operation_id=owner_operation_id,run_id=run_id,
        source_identity_sha256=source_identity_sha256,auth_source_identity_sha256=auth_source_identity_sha256,
        profile_ref=selected['profile_ref'],owner_confirmed=True,
        owner_launch_ref=dict(path=launch_name,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw)),
        owner_run_binding=args.owner_run_binding)


def run(project,args,selected):
    from config import application_profile_gate as gate
    from config.native_profile_loader import install
    project=Path(project);manifest=selected['manifest'];context=gate.rehearsal_context(project,args.rehearsal_seal_sha256)
    gate.require(not(args.rehearsal_action!='entry'and context is None),'ordinary_rehearsal_action_refused')
    environment=gate.environment_root(project)
    gate.require(Path(sys.prefix).absolute()==environment/'.venv-plan'and sys.dont_write_bytecode,'ordinary_selected_interpreter')
    site=environment/('.venv-plan/lib/python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)+'/site-packages')
    sys.path.insert(0,str(site))
    inherited_names=('owner_operation_started_ns','owner_operation_deadline_ns',
        'owner_operation_started_utc','owner_run_binding','owner_lock_fd')
    inherited_clock=any(getattr(args,name) is not None for name in inherited_names)
    timing=_helper(project,manifest,_operation_timing_name(project,args,manifest,gate,
        inherited_clock=inherited_clock),'radik_selected_operation_timing')
    supervised_console=inherited_clock and not args.owner_scenario
    gate.require(args.rehearsal_action not in ('ordinary_console','ordinary_controls') or supervised_console,
        'ordinary_supervised_owner_binding')
    if args.owner_scenario or inherited_clock:
        gate.require(all(getattr(args,name) is not None for name in inherited_names),
            'ordinary_supervised_owner_binding')
        clocks=timing.validate_operation_clock(started_ns=args.owner_operation_started_ns,
            deadline_ns=args.owner_operation_deadline_ns,started_utc=args.owner_operation_started_utc)
        gate.require(args.owner_lock_fd is not None and re.fullmatch('[0-9a-f]{64}',args.owner_run_binding or''),
            'ordinary_supervised_owner_binding')
        started=args.owner_operation_started_ns;deadline=args.owner_operation_deadline_ns;started_utc=args.owner_operation_started_utc
        binding=args.owner_run_binding
    else:
        started=time.monotonic_ns();deadline=started+timing.LIMITS['operation_seconds']*10**9;started_utc=int(time.time());binding=hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        clocks=timing.validate_operation_clock(started_ns=started,deadline_ns=deadline,started_utc=started_utc)
    writer=timing.EventWriter(started_ns=started,deadline_ns=deadline,run_binding=binding)
    e_state=dict(active=None,count=0)
    def events(value):
        kind=value.get('kind');phase=value.get('phase','PERSISTENCE')
        if kind in timing.KINDS:
            data={k:v for k,v in value.items()if k not in ('kind','phase')}
            if 'readback_ref'in data:data['readback_ref']=_reference(project,data['readback_ref'])
            if phase not in timing.PHASES:phase='PERSISTENCE'
            return writer.emit(kind,phase,**data)
        stage=value.get('stage')
        if stage=='DYNAMIC_NATIVE_E_START':
            gate.require(not supervised_console,'ordinary_supervised_console_E_forbidden')
            e_state['count']+=1
            gate.require(not args.owner_scenario or e_state['count']==1,'ordinary_exact_one_owner_E')
            e_state['active']=value['e_call_id']
            return writer.emit('E_ENTER','E',e_call_id=e_state['active'],readback_ref=_reference(project,value['capture_ref']))
        if stage=='DYNAMIC_NATIVE_E_RETURN':
            gate.require(e_state['active']is not None,'ordinary_E_return_without_entry')
            writer.emit('E_EXIT','E',e_call_id=e_state['active'],readback_ref=_reference(project,value['native_return_ref']))
            e_state['active']=None;return
        return writer.emit('STATUS','E'if e_state['active']else'NATIVE',stage=stage or'APPLICATION_EVENT',semantic_progress=False)
    # AUTH/HTTP fixtures are selected before any real private-store constructor.
    if context is not None:
        from app.ordinary_rehearsal import install_fence,make_auth
        fence=install_fence(project,context);auth=make_auth(project,context)
    else:
        gate.require_external_owner(project,'AUTH')
        from app.plan_auth import PlanAuth
        auth=PlanAuth(project);auth.access_for_plan()
        fence=None
    install(project)
    from review.transport.direct_plan_gate import source_identity,console_transition,console_execution_entry,dependency_review
    from app import normal_session
    from app.task_budget import read_state
    from app.runtime import make_client,main
    from app.contracts import canonical,digest
    from app.evidence import persist
    from app.native_authority import plain
    lock_path=project/'review/direct_plan_passage/owner_start.lock';own_lock=args.owner_lock_fd is None
    fd=os.open(lock_path,os.O_RDWR|os.O_NOFOLLOW)if own_lock else args.owner_lock_fd
    opened=os.fstat(fd);expected=lock_path.stat()
    gate.require((opened.st_dev,opened.st_ino)==(expected.st_dev,expected.st_ino),'ordinary_owner_lock_identity')
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    operation_ref=None;keep_open=False;code=2;primary=None;refs=[]
    output=project/'workspace/owner_documents/review/p28_entry'/binding[:24];output.mkdir(parents=True,exist_ok=False)
    def export(label,value):
        ref=persist(output,label,plain(value));refs.append(_reference(project,ref));return ref
    def command_observer(value):
        reference=export('ordinary_console_command',value)
        events(dict(kind='STATUS',phase='PERSISTENCE',
            stage='CONSOLE_READY' if value['command']=='ready' else 'CONSOLE_COMMAND_COMPLETED',
            command_sequence=value['command_sequence'],command=value['command'],
            task_id=value['task_id'],outcome_status=value['status'],
            readback_ref=reference,semantic_progress=True))
    client=None;open_span=None;boundary='BOOTSTRAP'
    def close_span():
        nonlocal open_span
        if open_span is not None:
            phase,span_id,native=open_span
            open_span=None
            writer.emit('PHASE_EXIT',phase,span_id=span_id,native=native)
    try:
        writer.emit('PHASE_ENTER','BOOTSTRAP',span_id='ordinary_bootstrap',native=False)
        open_span=('BOOTSTRAP','ordinary_bootstrap',False)
        boundary='DEPENDENCY_REVIEW';dependency=dependency_review(project)
        boundary='CONSOLE_TRANSITION';console_transition(project)
        boundary='CONSOLE_EXECUTION_ENTRY';console_execution_entry(project)
        boundary='SOURCE_IDENTITY';source=source_identity(project,scope='console')
        boundary='TASK_BUDGET_READ_STATE';state=read_state(project)
        export('ordinary_source_history_boundary',dict(status='PASS',clocks=clocks,interpreter=sys.executable,
            sys_prefix=sys.prefix,argv=list(sys.argv),cwd=str(Path.cwd()),source_identity_sha256=digest(source),
            source_pins=source,current_state=state,dependency=dependency,fence=fence,
            selected_profile_ref=selected['profile_ref'],synthetic_external_fixtures=context is not None))
        boundary='NATIVE_SCHEMA_CALLBACK_ORIGINS'
        if args.owner_scenario or supervised_console or context is not None and args.rehearsal_action=='entry':
            _sources(project,selected,export)
            if not supervised_console:
                from app.native_report_observer import preflight_report_writer
                writer_probe=output/'native_report_writer_preflight';writer_probe.mkdir(mode=0o700)
                export('ordinary_native_report_writer_preflight',preflight_report_writer(project,manifest,writer_probe))
        boundary='NORMAL_OPERATION_OPEN'
        operation_id=str(uuid.uuid4());run_id=uuid.uuid4().hex[:12]
        client=make_client(auth,scope='console');client.owner_event_sink=events
        client._ordinary_profile_manifest=manifest
        client._ordinary_operation_deadline_utc=started_utc+timing.LIMITS['operation_seconds']
        action=args.rehearsal_action if context is not None else'entry'
        if action=='grant_review':
            active=json.loads(gate._read(project,normal_session.ACTIVE));operation_ref=active['operation_ref']
            operation=normal_session.validate_operation(project,operation_ref)
            operation_id=operation['owner_operation_id'];run_id=operation['run_id']
        elif action!='restart_read':
            normal_session.apply_transition(project,owner_lock_fd=fd,source_identity_sha256=digest(source),
                auth_source_identity_sha256=digest(selected['auth_review']['pins']))
            boundary='STAGE05_EXPLICIT_OWNER_DISPOSITION'
            disposition=_stage05_owner_disposition(project,args,selected,gate,owner_lock_fd=fd,
                owner_operation_id=operation_id,run_id=run_id,source_identity_sha256=digest(source),
                auth_source_identity_sha256=digest(selected['auth_review']['pins']))
            if disposition is not None:export('stage05_explicit_owner_disposition',disposition)
            boundary='NORMAL_OPERATION_OPEN'
            operation_ref=normal_session.open_operation(project,owner_lock_fd=fd,owner_operation_id=operation_id,run_id=run_id,
                source_review_ref=manifest['source_review_ref'],source_admission_ref=manifest['source_admission_ref'],
                source_identity_sha256=digest(source),auth_source_identity_sha256=digest(selected['auth_review']['pins']),
                profile_ref=selected['profile_ref'],opened_at=started_utc)
        client.budget.set_console_operation(operation_id,run_id)
        if operation_ref is not None:client.budget.set_normal_operation(operation_ref)
        close_span()
        boundary='ORDINARY_SCENARIO'
        writer.emit('PHASE_ENTER','NATIVE',span_id='ordinary_scenario',native=True)
        open_span=('NATIVE','ordinary_scenario',True)
        if context is not None and action!='ordinary_console':
            if action=='ordinary_controls':
                helper=_helper(project,manifest,
                    'review/g2e_successor_passage/proposals/g2e_no_effects_v31_stage04_closure/post_controls.py',
                    'radik_p31_ordinary_controls')
                result=helper.run(project=project,context=context,client=client,
                    operation_ref=operation_ref,owner_lock_fd=fd,export=export)
            elif action=='entry':
                _boundary_checks(project,context,export,fd,manifest)
                helper=_helper(project,manifest,PREFIX+'/scenario_preparation.py','radik_p28_rehearsal_scenario')
                helper.structural_checks(project,context,export)
                result=helper.run(project=project,client=client,operation_ref=operation_ref,context=context,export=export,event_sink=events)
            else:
                helper=_helper(project,manifest,PREFIX+'/rehearsal_lifecycle.py','radik_p28_rehearsal_lifecycle')
                result=helper.run(action,project=project,context=context,client=client,operation_ref=operation_ref,
                    owner_lock_fd=fd,export=export)
                keep_open=result.get('leave_operation_open')is True
                if result.get('operation_closed')is True:operation_ref=None
            export('ordinary_transport_guard_observations',dict(status='PASS',guards=client.guard_observations,
                transport_evidence_refs=client._evidence_refs,external_requests=auth.requests,actual_model_calls=0,fixture_dispatches=len([r for r in auth.requests if r['method']=='POST'])))
        else:
            code=main(client=client,interactive=not args.owner_scenario,owner_scenario=args.owner_scenario,
                command_observer=None if args.owner_scenario else command_observer)
            gate.require(code==0,'ordinary_owner_scenario_stopped')
            if context is not None:
                export('ordinary_transport_guard_observations',dict(status='PASS',guards=client.guard_observations,
                    transport_evidence_refs=client._evidence_refs,external_requests=auth.requests,
                    actual_model_calls=0,fixture_dispatches=len([r for r in auth.requests if r['method']=='POST'])))
        close_span()
        boundary='NORMAL_OPERATION_CLOSE'
        if operation_ref is not None and not keep_open:
            close=normal_session.close_operation(project,owner_lock_fd=fd,operation_ref=operation_ref,failed=False)
            operation_ref=None;export('ordinary_operation_closed',dict(reference=close))
        boundary='FINAL_WITNESS'
        final=export('ordinary_entry_result',dict(status='PASS_SOURCE_REHEARSAL' if context else
                'OWNER_SCENARIO_COMPLETED' if args.owner_scenario else 'OWNER_CONSOLE_COMPLETED',
            partial_scope=context is not None,action=action,refs=list(refs),kept_unstarted_operation=keep_open,
            restored_live_authority=False,automatic_retry=False,profile_ref=selected['profile_ref']))
        writer.emit('FINAL','FINALIZATION',success=True,readback_ref=_reference(project,final))
        return 0
    except BaseException as error:
        primary=error
        cause=error.args[0]if isinstance(error,ValueError)and error.args and type(error.args[0])is str and re.fullmatch('[A-Za-z0-9_:./-]{1,256}',error.args[0])else'ordinary_entry_failure'
        detail=_failure_detail(project,environment,error,boundary)
        missing=detail['missing_owned_path']
        if isinstance(error,FileNotFoundError)and missing is not None:
            basename=Path(missing['path']).name
            if re.fullmatch('[A-Za-z0-9_.-]{1,100}',basename):cause='ordinary_required_file_missing:'+basename
        failure=dict(phase=boundary,error_class=type(error).__name__,code=cause)
        failure_ref=None
        try:
            partial_transport=None if client is None else dict(guards=client.guard_observations,
                transport_evidence_refs=client._evidence_refs,
                external_requests=auth.requests if context is not None else None,
                classification='PARTIAL_OBSERVATIONS_NOT_A_SUCCESS')
            failure_ref=export('ordinary_entry_failure',dict(primary_failure=failure,detail=detail,
                refs=list(refs),partial_transport=partial_transport,automatic_retry=False))
        except BaseException:pass
        try:close_span()
        except BaseException:pass
        pointer={}
        if failure_ref is not None:
            try:pointer=dict(readback_ref=_reference(project,failure_ref))
            except BaseException:pass
        writer.emit('PRIMARY_FAILURE','FINALIZATION',failure=failure,**pointer)
        writer.emit('FINAL','FINALIZATION',success=False,failure=failure,**pointer)
        return 2
    finally:
        if operation_ref is not None and not keep_open:
            try:normal_session.close_operation(project,owner_lock_fd=fd,operation_ref=operation_ref,failed=True)
            except BaseException:
                if primary is None:raise
        if own_lock:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
