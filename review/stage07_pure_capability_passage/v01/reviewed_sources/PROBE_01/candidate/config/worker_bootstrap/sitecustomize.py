"""Source-pinned observer for the unchanged native finite Wasmtime worker.

Startup and exit observations are evidence only. The native parent still owns
execution, timeout, kill/wait and its actual PureWorkerResultV01.
"""
import atexit
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import time
import types


_STATE={}

def _start():
    launch_path=Path(os.environ['STAGE07_WORKER_LAUNCH'])
    launch_raw=launch_path.read_bytes();launch=json.loads(launch_raw)
    ref=launch['code_manifest_ref'];raw=Path(ref['path']).read_bytes()
    if len(raw)!=ref['size_bytes'] or hashlib.sha256(raw).hexdigest()!=ref['sha256']:
        raise ValueError('stage07_worker_manifest_changed')
    manifest=json.loads(raw);pins={row['path']:row for row in manifest['files']};_STATE['pins']=pins
    own=str(Path(__file__).absolute())
    if own not in pins or hashlib.sha256(Path(own).read_bytes()).hexdigest()!=pins[own]['sha256']:
        raise ValueError('stage07_worker_observer_changed')
    helper=Path(manifest['candidate_root'])/'config/stage07_io.py'
    helper_raw=helper.read_bytes()
    if hashlib.sha256(helper_raw).hexdigest()!=pins[str(helper)]['sha256']:
        raise ValueError('stage07_worker_io_changed')
    io=types.ModuleType('stage07_worker_observation_io');io.__file__=str(helper)
    sys.modules[io.__name__]=io
    exec(compile(helper_raw,str(helper),'exec'),io.__dict__)
    folder=Path(launch['folder']);records=folder/'worker_records'
    io.require(time.monotonic_ns()<launch['operation_deadline_ns'],'stage07_worker_operation_expired')
    io.require(os.getppid()==int(os.environ['STAGE07_WORKER_PARENT_PID']),
        'stage07_worker_parent_identity')
    io.require(sys.dont_write_bytecode and sys.flags.no_user_site==1 and sys.flags.safe_path,
        'stage07_worker_startup_flags')
    io.require(os.environ['PYTHONPATH']==os.pathsep.join(manifest['worker_import_paths'])
        and sys.pycache_prefix==str(folder/'worker_bytecode'),'stage07_worker_import_route')
    for row in manifest['files']:
        if row['path'] in manifest['peer_read_paths']:io.read_ref(row)
    for name in manifest['startup_absent_paths']:
        io.require(not Path(name).exists() and not Path(name).is_symlink(),'stage07_worker_startup_surface_changed')
    io.require(not list(Path(manifest['site_root']).glob('*.pth')),'stage07_worker_pth_surface_changed')
    input_path=io.fd_path(0)
    io.require(input_path.name=='input' and input_path.parent.parent==folder/'worker_tmp',
        'stage07_worker_input_identity')
    # A separate read-only descriptor cannot advance the native stdin offset.
    request_raw=input_path.read_bytes();request_sha=hashlib.sha256(request_raw).hexdigest()
    job=hashlib.sha256((str(input_path)+'\0'+request_sha).encode()).hexdigest()
    _STATE.update(records=records,job=job,io=io)
    intent_path=records/(job+'_intent.json');intent=json.loads(intent_path.read_bytes())
    io.require(intent['request_sha256']==request_sha and intent['parent_pid']==os.getppid()
        and intent['input_path']==str(input_path) and intent['launch_ref']['path']==str(launch_path),
        'stage07_worker_intent_binding')
    io.require(len(launch_raw)==intent['launch_ref']['size_bytes']
        and hashlib.sha256(launch_raw).hexdigest()==intent['launch_ref']['sha256']
        and io.read_ref(intent['launch_ref'])==launch_raw,'stage07_worker_launch_changed')
    request=json.loads(request_raw)
    io.require(set(request)=={'source','format','inputs','fuel'} and len(request_raw)<=65536
        and request['format']in('wat','wasm') and type(request['fuel'])is int and 0<request['fuel']<=100000
        and 0<len(request['inputs'])<=256,'stage07_worker_request_bound')
    allowed=set(manifest['peer_read_paths'])|{str(launch_path),ref['path'],str(intent_path)}
    libraries=io.fence(folder,allowed,manifest['directory_paths'],pins)
    started=time.monotonic_ns()
    start=dict(schema='radik.stage07.worker_start.v1',job_id=job,pid=os.getpid(),parent_pid=os.getppid(),
        operation_id=launch['operation_id'],native_span_id=intent['native_span_id'],
        launch_ref=intent['launch_ref'],request_sha256=request_sha,
        input_path=str(input_path),input_count=len(request['inputs']),fuel_per_input=request['fuel'],
        source_format=request['format'],started_ns=started,source_manifest_ref=ref,
        observer_ref=pins[own],startup_observation=io.loaded(pins,allowed),native_worker_unchanged=True)
    start_ref=io.save(records/(job+'_started.json'),start)

    def close():
        terminal=None
        try:
            stdout_path,stderr_path=io.fd_path(1),io.fd_path(2)
            io.require(stdout_path==input_path.parent/'stdout' and stderr_path==input_path.parent/'stderr',
                'stage07_worker_output_identity')
            stdout,stderr=stdout_path.read_bytes(),stderr_path.read_bytes()
            io.require(len(stdout)+len(stderr)<=65536,'stage07_worker_output_bound')
            lines=[json.loads(row) for row in stdout.splitlines() if row.strip()]
            terminal=lines[-1] if lines else {}
            io.require(type(terminal)is dict and terminal.get('status')in('REFUSED','SUCCEEDED'),
                'stage07_worker_terminal_missing')
            io.require(time.monotonic_ns()<launch['operation_deadline_ns'],'stage07_worker_operation_expired')
            observation=io.loaded(pins,allowed)
            worker_path=str(Path(manifest['reference_root'])/'hedgehog/wasm_pure_worker_v01.py')
            io.require(any(row['module']=='__main__' and row['path']==worker_path
                and row['spec_name']=='hedgehog.wasm_pure_worker_v01' for row in observation['modules']),
                'stage07_worker_main_origin')
            ffi=sys.modules.get('wasmtime._ffi');library=getattr(getattr(ffi,'dll',None),'_name',None)
            engine_observed=(library==manifest['wasmtime_library_ref']['path'] and
                any(row['path']==library for row in libraries))
            io.require(engine_observed or terminal['status']=='REFUSED' and library is None,
                'stage07_worker_engine_library_origin')
            io.read_ref(manifest['wasmtime_library_ref']);io.read_ref(manifest['wasmtime_metadata_ref'])
            io.save(records/(job+'_closed.json'),dict(schema='radik.stage07.worker_observation.v1',
                job_id=job,pid=os.getpid(),parent_pid=os.getppid(),started_ref=start_ref,
                request_sha256=request_sha,stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                stderr_sha256=hashlib.sha256(stderr).hexdigest(),terminal_status=terminal.get('status'),
                terminal_phase=terminal.get('phase'),loaded_source=observation,dynamic_libraries=libraries,
                engine_library_observed=engine_observed,
                wasmtime_library_ref=manifest['wasmtime_library_ref'] if engine_observed else None,
                wasmtime_metadata_ref=manifest['wasmtime_metadata_ref'],
                elapsed_wall_ns=time.monotonic_ns()-started,process_cpu_ns=time.process_time_ns(),
                observation_phase='ATEXIT_BEFORE_PROCESS_TERMINATION',process_reaped_claimed=False))
        except BaseException as error:
            _failure(error,'ATEXIT',87,native_terminal=terminal)
    atexit.register(close)


def _failure(error,phase,exit_code,*,native_terminal=None):
    code=error.args[0] if isinstance(error,ValueError) and error.args else None
    pins=_STATE.get('pins',{});frames=[];trace=error.__traceback__
    if type(code)is not str or not re.fullmatch('stage07_[a-z0-9_]{1,140}',code):
        code='stage07_worker_observer_failure'
    while trace is not None:
        path=str(Path(trace.tb_frame.f_code.co_filename).absolute())
        if path in pins:frames.append(dict(path=path,sha256=pins[path]['sha256'],
            function=trace.tb_frame.f_code.co_name,line=trace.tb_lineno))
        trace=trace.tb_next
    preserve_refusal=type(native_terminal)is dict and native_terminal.get('status')=='REFUSED'
    value=dict(status='REFUSED',reason=code,phase='stage07_observer_'+phase.lower(),
        error_class=type(error).__name__,frames=frames[-24:],pid=os.getpid(),parent_pid=os.getppid())
    value['native_refusal_preserved']=preserve_refusal
    try:
        if 'io' in _STATE:
            _STATE['io'].save(_STATE['records']/(_STATE['job']+'_failed.json'),value)
        if not preserve_refusal:print(json.dumps(value,sort_keys=True),flush=True)
    except BaseException:pass
    if not preserve_refusal:os._exit(exit_code)


try:
    _start()
except BaseException as error:
    # site.main may suppress import errors; os._exit makes absence fail closed.
    _failure(error,'STARTUP',86)
