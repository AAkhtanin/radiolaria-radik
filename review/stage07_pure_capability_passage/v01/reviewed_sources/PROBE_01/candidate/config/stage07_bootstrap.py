"""Source admission for one ordinary zero-model U3 task operation."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

PREFIX='review/stage07_pure_capability_passage/v01'


def require(value,code):
    if not value:raise ValueError(code)


def _safe(error,pins,codes):
    if error is None:return None
    code=error.args[0] if isinstance(error,ValueError) and error.args else None
    if type(code)is not str or code not in codes:code='stage07_application_failure'
    rows=[];trace=error.__traceback__
    while trace is not None:
        path=str(Path(trace.tb_frame.f_code.co_filename).absolute())
        if path in pins:rows.append(dict(path=path,sha256=pins[path]['sha256'],
            function=trace.tb_frame.f_code.co_name,line=trace.tb_lineno))
        trace=trace.tb_next
    return dict(code=code,error_class=type(error).__name__,frames=rows[-24:])


def select_stage07(project,args):
    project=Path(project).resolve();environment=project.parents[3]
    require(project==environment/PREFIX/'candidate' and args.stage07_pure_capability and args.console,
        'stage07_explicit_candidate_mode')
    launch_path=Path(args.stage07_launch).absolute()
    require(any(launch_path.is_relative_to(environment/PREFIX/name)
        for name in ('owner_terminal_runs','offline_attempts')),'stage07_launch_scope')
    launch_raw=launch_path.read_bytes();launch=json.loads(launch_raw)
    require(launch['schema']=='radik.stage07.application_launch.v1','stage07_launch_schema')
    manifest_ref=launch['code_manifest_ref'];raw=Path(manifest_ref['path']).read_bytes()
    require(len(raw)==manifest_ref['size_bytes'] and hashlib.sha256(raw).hexdigest()==manifest_ref['sha256'],
        'stage07_manifest_changed')
    manifest=json.loads(raw);pins={row['path']:row for row in manifest['files']}
    require(manifest['schema']=='radik.stage07.source_manifest.v1' and manifest['candidate_root']==str(project)
        and manifest['environment_root']==str(environment),'stage07_manifest_context')
    helper=project/'config/stage07_io.py';raw=helper.read_bytes()
    require(hashlib.sha256(raw).hexdigest()==pins[str(helper)]['sha256'],'stage07_io_preimport_pin')
    from config import stage07_io as io
    admission_ref=launch['admission_ref'];admission=json.loads(io.read_ref(admission_ref))
    mode=launch['mode'];selector='pure_capability_owner_v01' if mode=='owner' else 'pure_capability_probe_v01'
    require(mode in ('owner','engineering') and admission['mode']==mode
        and admission['schema']=='radik.stage07.owner_admission.v1'
        and admission['reviewer']=='/root/private_remote_controls'
        and admission['status']==('OWNER_COMMAND_SOURCE_READY_NOT_EXECUTED' if mode=='owner'
            else 'SOURCE_ACCEPTED_FOR_BOUNDED_ENGINEERING_PROBE')
        and admission['task_selector']==launch['task_selector']==selector
        and admission['expected_model_calls']==0 and admission['code_manifest_ref']==manifest_ref,
        'stage07_independent_source_admission')
    reservation=json.loads(io.read_ref(launch['reservation_ref']))
    keys=('mode','operation_id','operation_started_ns','operation_deadline_ns','operation_started_utc','task_selector','limits')
    require(reservation['state']=='OPEN' and all(reservation[key]==launch[key] for key in keys)
        and reservation['run_directory']==str(launch_path.parent) and reservation['admission_ref']==admission_ref
        and reservation['code_manifest_ref']==manifest_ref and launch['limits']==admission['limits'],
        'stage07_fresh_operation_binding')
    folder=Path(launch['folder']);require(folder==launch_path.parent/'application' and folder.is_dir()
        and not folder.is_symlink() and args.stage07_role==launch['role']=='application'
        and args.stage07_session==launch['session']==1,'stage07_application_identity')
    lock_fd=args.owner_lock_fd;opened=os.fstat(lock_fd);lockpath=environment/'review/direct_plan_passage/owner_start.lock'
    locked=lockpath.stat();require(lock_fd==launch['owner_lock_fd'] and
        (opened.st_dev,opened.st_ino)==(locked.st_dev,locked.st_ino),'stage07_lock_identity')
    fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    require(sys.dont_write_bytecode,'stage07_bytecode_disabled')
    allowed=set(manifest['peer_read_paths']);require(allowed<=set(pins),'stage07_finite_read_inventory')
    for path in allowed:io.read_ref(pins[path])
    for path in manifest['startup_absent_paths']:
        require(not Path(path).exists() and not Path(path).is_symlink(),'stage07_startup_surface_changed')
    require(not list(Path(manifest['site_root']).glob('*.pth')),'stage07_pth_surface_changed')
    baseline=admission['live_guards'];codes=frozenset(manifest['failure_codes'])
    def current():
        require(launch['operation_started_ns']<=time.monotonic_ns()<launch['operation_deadline_ns']
            and launch['operation_deadline_ns']==launch['operation_started_ns']+
                int(launch['limits']['operation_seconds']*10**9),'stage07_operation_expired')
        for row in baseline:io.read_ref(row)
        return dict(preserved=True,guard_count=len(baseline),observed_utc_ns=time.time_ns())
    initial=current()
    out=folder/'entry_sessions/session_1';out.mkdir(parents=True,exist_ok=False)
    evidence=out/'evidence';evidence.mkdir();records=folder/'worker_records';records.mkdir()
    worker_tmp=folder/'worker_tmp';worker_tmp.mkdir();tempfile.tempdir=str(worker_tmp)
    sys.pycache_prefix=str(folder/'app_bytecode')
    sys.path[:]=list(manifest['import_paths'])+[path for path in sys.path if path not in manifest['import_paths']]
    worker_env=dict(PATH='/usr/bin:/bin',LANG='en_US.UTF-8',PYTHONDONTWRITEBYTECODE='1',
        PYTHONNOUSERSITE='1',PYTHONSAFEPATH='1',PYTHONPATH=os.pathsep.join(manifest['worker_import_paths']),
        PYTHONPYCACHEPREFIX=str(folder/'worker_bytecode'),TMPDIR=str(worker_tmp),
        STAGE07_WORKER_LAUNCH=str(launch_path),STAGE07_WORKER_PARENT_PID=str(os.getpid()))
    os.environ.clear();os.environ.update(worker_env)
    sequence=0;refs=[];finished=False;worker_intents=[];active_span=None
    launch_ref=dict(path=str(launch_path),sha256=hashlib.sha256(launch_raw).hexdigest(),size_bytes=len(launch_raw))
    def event(label,value):
        nonlocal sequence,active_span
        require(type(label)is str and re.fullmatch('[A-Za-z0-9_]{1,80}',label),'stage07_event_label')
        if label=='native_enter':
            require(active_span is None,'stage07_overlapping_native_span');active_span=value['span_id']
        elif label=='native_exit':
            require(active_span==value['span_id'],'stage07_native_exit_binding');active_span=None
        sequence+=1;require(sequence<=512,'stage07_event_count')
        ref=io.save(evidence/('%04d_%s.json'%(sequence,label)),value);refs.append(ref);now=time.monotonic_ns()
        print(json.dumps(dict(stage07_event=dict(label=label,ref=ref,at_monotonic_ns=now,
            operation_started_ns=launch['operation_started_ns'],wall_ns=now-launch['operation_started_ns'],
            cpu_ns=time.process_time_ns(),pid=os.getpid(),sequence=sequence,role='application',session=1)),sort_keys=True),flush=True)
        return ref
    def loaded(label):return event(label,dict(schema='radik.stage07.loaded_source.v1',**io.loaded(pins,allowed)))
    def allow_worker(args):
        executable,argv,cwd,env=args
        require(executable==sys.executable and argv==[sys.executable,'-B','-m','hedgehog.wasm_pure_worker_v01']
            and cwd is None and env==worker_env,'stage07_exact_native_worker_launch')
        frame=sys._getframe();found=False
        worker=str(Path(manifest['reference_root'])/'hedgehog/wasm_pure_worker_v01.py')
        while frame is not None:
            if frame.f_code.co_filename==worker and frame.f_code.co_name=='run_pure_wasm_worker_v01':found=True
            frame=frame.f_back
        require(found and active_span is not None and len(worker_intents)<7,'stage07_worker_public_callsite');io.read_ref(pins[worker]);current()
        require(not list(Path(manifest['site_root']).glob('*.pth')),'stage07_pth_surface_changed')
        for name in manifest['startup_absent_paths']:require(not Path(name).exists(),'stage07_startup_surface_changed')
        temporary=[p for p in worker_tmp.iterdir() if p.is_dir() and not p.is_symlink()]
        require(len(temporary)==1 and temporary[0].name.startswith('radiolaria-pure-worker-'),
            'stage07_single_worker_temporary_scope')
        input_path=temporary[0]/'input';raw=input_path.read_bytes();value=json.loads(raw)
        require(len(raw)<=65536 and set(value)=={'source','format','inputs','fuel'}
            and value['format']in('wat','wasm') and 0<len(base64.b64decode(value['source'],validate=True))<=16384
            and type(value['fuel'])is int and 0<value['fuel']<=100000
            and 0<len(value['inputs'])<=256 and all(type(x)is int and 0<=x<=255 for x in value['inputs']),
            'stage07_worker_request_contract')
        request_sha=hashlib.sha256(raw).hexdigest();job=hashlib.sha256((str(input_path)+'\0'+request_sha).encode()).hexdigest()
        intent=dict(schema='radik.stage07.worker_intent.v1',job_id=job,input_path=str(input_path),
            request_sha256=request_sha,parent_pid=os.getpid(),launch_ref=launch_ref,
            native_argv=argv,native_span_id=active_span,source_manifest_ref=manifest_ref,scope='UNCHANGED_NATIVE_PUBLIC_WORKER')
        ref=io.save(records/(job+'_intent.json'),intent);worker_intents.append(ref)
        event('worker_launch_prepared',dict(intent_ref=ref))
    reads=allowed|{row['path'] for row in baseline}|{str(launch_path),manifest_ref['path'],
        admission_ref['path'],launch['reservation_ref']['path']}
    io.fence(folder,reads,manifest['directory_paths'],pins,allow_worker=allow_worker)
    def observe_workers(results):
        require(type(results)is list and len(results)==len(worker_intents),'stage07_worker_result_count')
        observations=[]
        for intent_ref,result in zip(worker_intents,results):
            intent=json.loads(io.read_ref(intent_ref));job=intent['job_id']
            failed_path=records/(job+'_failed.json')
            if failed_path.exists():
                detail=json.loads(failed_path.read_bytes());event('worker_observer_failed',detail)
                raise ValueError(detail['reason'])
            require((records/(job+'_started.json')).is_file(),'stage07_worker_start_observation_missing')
            require((records/(job+'_closed.json')).is_file(),'stage07_worker_exit_observation_missing')
            start_ref=io.reference(records/(job+'_started.json'));close_ref=io.reference(records/(job+'_closed.json'))
            started=json.loads(io.read_ref(start_ref));closed=json.loads(io.read_ref(close_ref))
            require(started['request_sha256']==intent['request_sha256']==closed['request_sha256']
                and closed['pid']==started['pid'] and started['parent_pid']==os.getpid()
                and closed['started_ref']==start_ref,'stage07_worker_observer_binding')
            require(result['stdout_sha256']==closed['stdout_sha256']
                and result['stderr_sha256']==closed['stderr_sha256'],'stage07_worker_native_result_missing')
            require(result['process_reaped'] is True and result['engine_version']=='48.0.0'
                and result['profile_version']=='pure-i32-closed-v01'
                and result['return_code'] in (0,1),'stage07_worker_reap_or_profile')
            observations.append(dict(intent_ref=intent_ref,started_ref=start_ref,closed_ref=close_ref,
                native_span_id=intent['native_span_id'],actual_native_result=result,process_reaped_basis='ACTUAL_NATIVE_PURE_WORKER_RESULT'))
        return event('worker_observation_complete',dict(workers=observations,model_calls=0))
    def finish(report,error):
        nonlocal finished
        require(not finished,'stage07_entry_already_closed');finished=True
        primary=_safe(error,pins,codes);secondary=[];worker_ref=None
        try:
            final_guard=current()
            if primary is None:worker_ref=observe_workers(report['worker_results'])
        except BaseException as exc:
            final_guard=None
            if primary is None:primary=_safe(exc,pins,codes)
            else:secondary.append(_safe(exc,pins,codes))
        ref=event('ordinary_entry_closed',dict(schema='radik.stage07.ordinary_native_entry_receipt.v1',
            operation_id=launch['operation_id'],role='application',session=1,
            status='CLOSED' if primary is None else 'STOPPED_NO_RETRY',code_manifest_ref=manifest_ref,
            admission_ref=admission_ref,launch_ref=launch_ref,report=report,
            initial_live_guards=initial,final_live_guards=final_guard,worker_observation_ref=worker_ref,
            primary_failure=primary,secondary_failures=secondary,checkpoints=refs[:],model_calls=0,
            auth_calls=0,native_E_calls=0,generic_SAVE_calls=0,restored_authority=False))
        if error is None and primary is not None:raise ValueError(primary['code'])
        return ref
    return dict(stage07=dict(role='application',session=1,folder=folder,task_selector=selector,
        scenario=json.loads((folder/'scenario.json').read_bytes()),on_event=event,observe_loaded=loaded,
        assert_current=current,finish=finish,mode=mode,operation_ref=launch['reservation_ref']))
