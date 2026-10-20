"""One finite ordinary-entry rehearsal, never a production activation.

Raw SOURCE pins precede all copied execution. All children use the admitted real
read-only interpreter, home cwd, closed copied scope and zero external services.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

PROJECT=Path('/Users/admin/Projects/RadiolariaRadik')
PREFIX='review/g2e_successor_passage/proposals/g2e_no_effects_v28_ordinary_entry_owner_scenario'
INPUTS=PREFIX+'/rehearsal_inputs.json'
SEAL=PREFIX+'/rehearsal_seal.json'
SELF=PREFIX+'/entry_runner.py'
STARTED=time.monotonic()
LIMIT=900
CLEANUP=30
MUTABLE_WITNESSES=('state/console_model_turns.json','state/task_model_settings.json','state/normal_grant_index.json',
    'workspace/owner_documents/state/dynamic_tasks.json','workspace/owner_documents/state/dynamic_source_successors.json')
TWO_REF_PREFIXES=('state/normal_rounds/','state/normal_operations/',
    'workspace/owner_documents/state/source_successors/','workspace/owner_documents/input/',
    'state/p28_owner_scenario_reservations/')


def require(value,code):
    if not value:raise ValueError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def read(root,name,cap=64*1024*1024):
    require(type(name)is str and name and not name.startswith('/')and all(x not in ('','.','..')for x in name.split('/')),'entry_exam_relative')
    path=root/name
    for node in (path,*path.parents):
        require(not node.is_symlink(),'entry_exam_symlink')
        if node==root:break
    before=path.stat();require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=cap,'entry_exam_file_bound')
    raw=path.read_bytes();require(len(raw)==before.st_size,'entry_exam_read_changed');return raw


def reference(root,name):
    raw=read(root,name);return dict(path=name,sha256=sha(raw),size_bytes=len(raw))


def verify(root,ref):
    raw=read(root,ref['path']);require(sha(raw)==ref['sha256']and len(raw)==ref['size_bytes'],'entry_exam_reference_changed');return raw


def put(path,value):
    require(not path.exists()and not path.is_symlink(),'entry_exam_no_overwrite');path.parent.mkdir(parents=True,exist_ok=True)
    raw=canonical(value)+b'\n';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    require(path.read_bytes()==raw,'entry_exam_write_readback')
    return dict(path=str(path.relative_to(PROJECT)),sha256=sha(raw),size_bytes=len(raw))


def safe_error(error):
    """Never project TimeoutExpired's argv or arbitrary exception payloads."""
    kind=type(error).__name__
    kind=kind if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',kind)else'Exception'
    if isinstance(error,(TimeoutError,subprocess.TimeoutExpired)):
        code='entry_exam_work_limit'
    elif isinstance(error,KeyboardInterrupt):
        code='entry_exam_owner_interrupt'
    elif type(error)is ValueError and len(error.args)==1 and type(error.args[0])is str \
            and re.fullmatch(r'[A-Za-z0-9_:./-]{1,256}',error.args[0]):
        code=error.args[0]
    else:code='entry_exam_sanitized_failure'
    return dict(error_class=kind,code=code)


def collect_actual_references(root,initial,*,stdout_refs=(),seed_refs=(),strict=False):
    """Follow finite exact new witness references; no directory/source/private walk.

    This pure harness helper is available even when preparation or entry stops.
    Only already registered stdout/receipt paths and the explicit mutable
    witnesses seed the closure. JSON values supply references, never execution.
    """
    found={};gaps=[];excluded=0;seen_stdout=set()
    def bounded():
        require(time.monotonic()<STARTED+LIMIT,'entry_exam_harvest_limit')
    def gap(error):
        value=safe_error(error)
        if value not in gaps and len(gaps)<128:gaps.append(value)
        if strict:raise error
    def enqueue(ref):
        nonlocal excluded
        bounded()
        path=Path(ref['path']);path=path if path.is_absolute()else root/path
        if not path.is_relative_to(root):return
        relative=str(path.relative_to(root));size=ref.get('size_bytes',ref.get('bytes'))
        digest=ref.get('sha256')
        if (relative,digest)in initial:return
        two_ref=set(ref)=={'path','sha256'}and relative.startswith(TWO_REF_PREFIXES)
        if type(size)is not int and not two_ref:return
        require(type(digest)is str and re.fullmatch('[0-9a-f]{64}',digest),
            'entry_exam_actual_reference_shape')
        if any(part in ('private','.git','.aws','.codex','.venv-plan')for part in path.relative_to(root).parts) \
                or relative.startswith(('app/','config/','source/')) \
                or path.suffix in ('.py','.pyc','.so','.dylib') \
                or '/native_runtime/'in relative:
            excluded+=1;return
        key=(relative,digest)
        if key in found:return
        require(len(found)<512,'entry_exam_actual_reference_bound')
        if two_ref:
            require(all(part not in ('','.','..')for part in relative.split('/')),
                'entry_exam_actual_reference_scope')
            info=path.lstat()
            require(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and 0<=info.st_size<=64*1024*1024,
                'entry_exam_actual_reference_stat_bound')
            size=info.st_size
        raw=read(root,relative);bounded()
        require(len(raw)==size and sha(raw)==digest,'entry_exam_new_actual_changed')
        physical=dict(path=str(path.relative_to(PROJECT)),sha256=digest,size_bytes=len(raw))
        found[key]=physical
        if path.suffix=='.json':walk(json.loads(raw))
        elif relative.startswith(TWO_REF_PREFIXES):
            # Closed durable JSON grants have a .json.closed suffix; owned
            # input references may instead contain ordinary UTF-8 source bytes.
            try:value=json.loads(raw)
            except (json.JSONDecodeError,UnicodeDecodeError):pass
            else:walk(value)
        elif path.name=='child_stdout.raw':scan_stdout(raw)
    def walk(value):
        bounded()
        if isinstance(value,dict):
            if {'path','sha256'}<=set(value)and('size_bytes'in value or'bytes'in value or set(value)=={'path','sha256'}):
                try:enqueue(value)
                except BaseException as error:gap(error)
            for item in value.values():walk(item)
        elif isinstance(value,list):
            for item in value:walk(item)
    def scan_stdout(raw):
        # Includes FINAL.readback_ref on success and failure; the latter leads
        # to the stable failure JSON's transport and full partial references.
        for line in raw.decode(errors='replace').splitlines():
            bounded()
            if line.startswith('{'):
                try:value=json.loads(line)
                except json.JSONDecodeError:continue
                walk(value)
    for ref in stdout_refs:
        try:
            key=(ref['path'],ref['sha256'])
            if key in seen_stdout:continue
            seen_stdout.add(key);bounded();raw=verify(PROJECT,ref);bounded();scan_stdout(raw)
        except BaseException as error:gap(error)
    for ref in seed_refs:
        try:enqueue(ref)
        except BaseException as error:gap(error)
    for name in MUTABLE_WITNESSES:
        try:
            bounded()
            if (root/name).is_file():enqueue(reference(root,name))
        except BaseException as error:gap(error)
    return dict(status='PASS'if not gaps else'PARTIAL',refs=list(found.values()),
        evidence_gaps=gaps,input_unchanged_refs_excluded=True,no_recursive_walk=True,
        excluded_private_or_source_refs=excluded)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--rehearsal-seal-sha256',required=True);args=parser.parse_args()
    seal_raw=read(PROJECT,SEAL);require(sha(seal_raw)==args.rehearsal_seal_sha256,'entry_exam_seal_changed');seal=json.loads(seal_raw)
    require(seal['reviewer']=='/root/p20_reviewer'and seal['maximum_wall_seconds']==LIMIT
        and seal['network']=='DENIED'and seal['real_AUTH_provider_native_E_SAVE_allowed']is False
        and seal['production_writes_allowed']is False,'entry_exam_scope')
    source=json.loads(verify(PROJECT,seal['source_review_ref']))
    require(source['source_only_rehearsal_authorized']is True and source['code_pins']==seal['code_pins'],'entry_exam_source_review')
    inputs=json.loads(verify(PROJECT,seal['rehearsal_inputs_ref']))
    require(sha(read(PROJECT,SELF))==seal['code_pins'][SELF],'entry_exam_self_pin')
    root=Path(seal['owned_copy_root']);require(root==PROJECT/PREFIX/'rehearsal_actual/ENTRY_V03/project'
        and not root.exists(),'entry_exam_fresh_copy_required')
    actual=root.parent;actual.mkdir(parents=True,exist_ok=False)
    result=dict(schema='radik.p28.ordinary_entry_exam_result.v01',status='STARTED',steps=[],public_refs=[],
        real_AUTH_calls=0,real_provider_calls=0,native_D_E_calls=0,automatic_retry=False,
        source_review_ref=seal['source_review_ref'],rehearsal_seal_sha256=args.rehearsal_seal_sha256)
    child=None;active_log=None;primary=None
    initial={(r['path'],r['sha256'])for r in inputs['copy_refs']+seal['generated_refs']}
    def checkpoint(name,value):
        ref=put(actual/(name+'.json'),value);result['public_refs'].append(ref);return ref
    def deadline(_signum,_frame):raise TimeoutError('entry_exam_work_limit')
    old=signal.signal(signal.SIGALRM,deadline);signal.setitimer(signal.ITIMER_REAL,max(.001,LIMIT-CLEANUP-(time.monotonic()-STARTED)))
    try:
        root.mkdir(mode=0o700)
        (root/'process_tmp').mkdir(mode=0o700)
        for ref in inputs['copy_refs']:
            require(time.monotonic()-STARTED<LIMIT-CLEANUP,'entry_exam_work_limit')
            raw=verify(PROJECT,ref);dst=root/ref['path'];dst.parent.mkdir(parents=True,exist_ok=True)
            require(not dst.exists(),'entry_exam_copy_duplicate');dst.write_bytes(raw)
            os.chmod(dst,int(ref['mode'],8)if isinstance(ref['mode'],str)else ref['mode'])
        for ref in seal['generated_refs']:
            raw=verify(PROJECT,ref);dst=root/ref['path'];dst.parent.mkdir(parents=True,exist_ok=True)
            require(not dst.exists(),'entry_exam_copy_duplicate');dst.write_bytes(raw);os.chmod(dst,0o444)
        dst=root/SEAL;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(seal_raw);os.chmod(dst,0o444)
        binding=root/'state/ordinary_rehearsal_context.json';binding.write_bytes(canonical(dict(schema='radik.p28.rehearsal_context.v01',seal_sha256=args.rehearsal_seal_sha256)));os.chmod(binding,0o600)
        lock=root/'review/direct_plan_passage/owner_start.lock';lock.parent.mkdir(parents=True,exist_ok=True)
        if not lock.exists():lock.write_bytes(b'')
        lock.chmod(0o600);info=lock.stat()
        admission=json.loads(verify(PROJECT,seal['rehearsal_terminal_admission_ref']))
        admission['lock_identity']=dict(device=info.st_dev,inode=info.st_ino,owner=info.st_uid,mode=stat.S_IMODE(info.st_mode),links=info.st_nlink)
        # SOURCE-only terminal data is copy-local, never final owner eligibility.
        target=root/PREFIX/'owner_admission.json';require(not target.exists(),'entry_exam_owner_admission_collision')
        target.write_bytes(canonical(admission)+b'\n');target.chmod(0o444);admission_sha=sha(target.read_bytes())
        checkpoint('copy_inventory',dict(files=inputs['copy_refs'],generated_refs=seal['generated_refs'],
            copied_root=str(root),typed_context=dict(path='state/ordinary_rehearsal_context.json',seal_sha256=args.rehearsal_seal_sha256),
            interpreter_ref=seal['interpreter_ref'],initial_count=len(initial)))
        python=seal['interpreter_ref']['path'];require(sha(Path(python).read_bytes())==seal['interpreter_ref']['sha256'],'entry_exam_interpreter_changed')
        def invoke(name,argv,expected):
            nonlocal child,active_log
            log_path=actual/(name+'_stdout.txt');require(not log_path.exists(),'entry_exam_no_retry');active_log=log_path.open('xb')
            begun=time.monotonic();remaining=LIMIT-CLEANUP-(begun-STARTED);require(remaining>0,'entry_exam_work_limit')
            child=subprocess.Popen(argv,cwd=seal['home_directory'],stdin=subprocess.DEVNULL,stdout=active_log,
                stderr=subprocess.STDOUT,close_fds=True,env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1','LANG':'en_US.UTF-8','TMPDIR':str(root/'process_tmp')})
            try:code=child.wait(timeout=remaining)
            finally:active_log.flush();os.fsync(active_log.fileno());active_log.close();active_log=None
            elapsed=time.monotonic()-begun;reaped=child.poll()is not None
            row=dict(name=name,argv=argv,cwd=seal['home_directory'],exit_code=code,elapsed_wall_seconds=elapsed,child_reaped=reaped,
                stdout_ref=reference(PROJECT,str(log_path.relative_to(PROJECT))))
            checkpoint(name+'_receipt',row);result['steps'].append(row);child=None
            require(code==expected,'entry_exam_unexpected_child_exit:'+name)
            print('P28_ENTRY_STEP '+name+' exit='+str(code)+' wall_s='+str(round(elapsed,3)),flush=True)
            return log_path.read_bytes()
        invoke('ordinary_owner_entry',[python,'-I','-S','-B',str(root/PREFIX/'owner_terminal_v02.py'),
            '--admission-sha256',admission_sha,'--rehearsal-seal-sha256',args.rehearsal_seal_sha256],0)
        raw=invoke('owner_reservation_repeat_refusal',[python,'-I','-S','-B',str(root/PREFIX/'owner_terminal_v02.py'),
            '--admission-sha256',admission_sha,'--rehearsal-seal-sha256',args.rehearsal_seal_sha256],2)
        require(b'terminal_owner_scenario_admission_already_reserved'in raw,'entry_exam_reservation_wrong_refusal')
        base=[python,'-I','-S','-B',str(root/'config/launch.py'),'--console','--rehearsal-seal-sha256',args.rehearsal_seal_sha256]
        for action in ('restart_read','grant_stage','grant_review'):
            invoke(action,base+['--rehearsal-action',action],0)
        for marker,reason in (('state/application_profile_install.json.pending','profile_gate_partial_installation'),
                ('state/application_profile.json.pending','profile_gate_partial_activation')):
            target=root/marker;require(not target.exists(),'entry_exam_partial_marker_collision')
            target.write_bytes(canonical(dict(classification='INERT_PARTIAL_STATE_NEGATIVE_NO_AUTHORITY')))
            checkpoint('partial_'+target.name.replace('.','_'),dict(marker=marker,reason=reason))
            raw=invoke('refusal_'+reason,base+['--rehearsal-action','restart_read'],2)
            require(reason.encode()in raw,'entry_exam_partial_wrong_refusal')
            target.unlink()
        schema=inputs['required_schema_mutation_ref'];target=root/schema['path'];original=verify(root,schema)
        target.chmod(0o644);target.write_bytes(original+b' ')
        checkpoint('required_schema_mutation',dict(original_ref=schema,mutated_ref=reference(root,schema['path']),
            classification='OWNED_COPY_NEGATIVE_REQUIRED_SCHEMA_MUTATION'))
        raw=invoke('required_schema_refusal',base+['--rehearsal-action','restart_read'],2)
        require(b'profile_gate_installed_source_changed'in raw,'entry_exam_schema_wrong_refusal')
        target.write_bytes(original);target.chmod(0o444);require(verify(root,schema)==original,'entry_exam_schema_restore')
        # Discover only the supervisor run registered by its own stdout receipt.
        stdout=(actual/'ordinary_owner_entry_stdout.txt').read_text()
        import re
        matches=re.findall(r'receipt=([^\s]+/receipt.json)',stdout);require(len(matches)==1,'entry_exam_terminal_receipt_locator')
        receipt_path=matches[0];receipt=json.loads(read(root,receipt_path))
        require(receipt['primary_failure']is None and receipt['child_reaped']is True,'entry_exam_terminal_not_closed')
        checkpoint('ordinary_terminal_closed_receipt',dict(reference=reference(root,receipt_path),receipt=receipt))
        seeded=[reference(root,name)for name in (receipt_path,
            receipt_path.replace('/receipt.json','/launch.json'),
            receipt_path.replace('/receipt.json','/installation_receipt.json'),
            receipt_path.replace('/receipt.json','/reservation_outcome.json'),
            receipt_path.replace('/receipt.json','/child_stdout.raw'))]
        harvested=collect_actual_references(root,initial,
            stdout_refs=[row['stdout_ref']for row in result['steps']],seed_refs=seeded,strict=True)
        checkpoint('new_actual_reference_inventory',harvested)
        for ref in inputs['production_guard_refs']:verify(PROJECT,ref)
        result.update(status='PASS_ORDINARY_ENTRY_REHEARSAL_AND_ADDRESSED_NEGATIVES',
            elapsed_wall_seconds=time.monotonic()-STARTED,all_children_reaped=True,
            copied_new_actual_refs=harvested['refs'],production_refs_unchanged=True)
    except BaseException as error:
        primary=error
        projection=safe_error(error)
        print('PRIMARY_FAILURE phase=ORDINARY_ENTRY_EXAM error_class='+projection['error_class']+
            ' code='+projection['code'],flush=True)
        result.update(status='STOPPED_NO_RETRY',primary_failure=projection,
            elapsed_wall_seconds=time.monotonic()-STARTED)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)
        if child is not None:
            stop=min(STARTED+LIMIT,time.monotonic()+CLEANUP)
            for sig,grace in ((signal.SIGINT,23),(signal.SIGTERM,3),(signal.SIGKILL,3)):
                try:
                    if child.poll()is not None:break
                    child.send_signal(sig)
                    try:child.wait(timeout=max(0,min(grace,stop-time.monotonic())))
                    except subprocess.TimeoutExpired:pass
                except BaseException as cleanup_error:
                    result.setdefault('secondary_failures',[]).append(safe_error(cleanup_error))
            result['child_reaped_after_stop']=child.poll()is not None
        if active_log is not None:
            try:active_log.flush();os.fsync(active_log.fileno());active_log.close()
            except BaseException as log_error:result.setdefault('secondary_failures',[]).append(safe_error(log_error))
        # A direct supervisor reap and its application child's closure are distinct.
        # Only this invocation's printed registered locator is followed; no walk.
        result['direct_supervisor_reaped']=child is None or child.poll()is not None
        nested=dict(status='UNCONFIRMED',application_child_reaped=None,refs=[],evidence_gaps=[])
        try:
            log_path=actual/'ordinary_owner_entry_stdout.txt'
            stdout=log_path.read_text()if log_path.exists()else ''
            locators=re.findall(r'RESERVED run=([^\s]+)',stdout)
            receipts=re.findall(r'receipt=([^\s]+/receipt.json)',stdout)
            if not locators and len(receipts)==1:locators=[receipts[0].rsplit('/',1)[0]]
            require(len(set(locators))==1,'entry_exam_nested_locator_unavailable')
            run_name=locators[0];require(run_name.startswith(PREFIX+'/owner_terminal_runs/')
                and len(run_name.split('/'))==len(PREFIX.split('/'))+2,'entry_exam_nested_locator_scope')
            require(result['direct_supervisor_reaped'],'entry_exam_supervisor_not_reaped')
            nested['run_locator']=run_name
            for name in ('receipt.json','launch.json','installation_receipt.json','reservation_outcome.json','child_stdout.raw'):
                target=root/run_name/name
                if target.is_file():nested['refs'].append(reference(PROJECT,str(target.relative_to(PROJECT))))
                else:nested['evidence_gaps'].append('ABSENT:'+name)
            receipt_file=root/run_name/'receipt.json'
            if receipt_file.is_file():
                nested_receipt=json.loads(read(root,run_name+'/receipt.json'))
                if 'child_pid'in nested_receipt:
                    nested['application_child_reaped']=nested_receipt.get('child_reaped')is True
                    nested['status']='CHILD_REAPED'if nested['application_child_reaped']else 'CHILD_CLOSURE_UNCONFIRMED'
                elif nested_receipt.get('child_started')is False:nested['status']='NOT_LAUNCHED'
        except BaseException as harvest_error:
            detail=safe_error(harvest_error)
            nested['evidence_gaps'].append(detail['error_class']+':'+detail['code'])
        result['nested_application_closure']=nested
        if not result['status'].startswith('PASS_'):
            try:
                stdout_refs=[row['stdout_ref']for row in result['steps']]
                log_path=actual/'ordinary_owner_entry_stdout.txt'
                if log_path.is_file():stdout_refs.append(reference(PROJECT,str(log_path.relative_to(PROJECT))))
                seeded=[dict(ref,path=str(PROJECT/ref['path']))for ref in nested['refs']]
                harvested=collect_actual_references(root,initial,stdout_refs=stdout_refs,
                    seed_refs=seeded,strict=False)
                checkpoint('stopped_actual_reference_inventory',harvested)
                result['copied_new_actual_refs']=harvested['refs']
                result['actual_reference_evidence_gaps']=harvested['evidence_gaps']
            except BaseException as harvest_error:
                result.setdefault('actual_reference_evidence_gaps',[]).append(safe_error(harvest_error))
        if result['status'].startswith('PASS_'):
            result['all_children_reaped']=result['direct_supervisor_reaped']and nested['application_child_reaped']is True
            if not result['all_children_reaped']:
                result.update(status='STOPPED_NO_RETRY',primary_failure=dict(error_class='ClosureEvidenceGap',
                    code='entry_exam_nested_child_not_closed'))
        result['elapsed_total_wall_seconds']=time.monotonic()-STARTED
        put(actual/'result.json',result)
    print(json.dumps(dict(status=result['status'],result_ref=reference(PROJECT,str((actual/'result.json').relative_to(PROJECT)))),sort_keys=True))
    return 0 if result['status'].startswith('PASS_')else 2


if __name__=='__main__':raise SystemExit(main())
