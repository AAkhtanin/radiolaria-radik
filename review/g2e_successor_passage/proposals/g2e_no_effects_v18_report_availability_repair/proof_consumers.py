"""Finite passive native producer records; no validation, authority or replay."""
from dataclasses import fields
from functools import wraps
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import threading
from types import MappingProxyType

KINDS=('RETAINED_CALL_INPUT','RUNTIME_BOUND_SOURCE','RETAINED_ADMISSION','RETAINED_CONSUMPTION',
    'FRESH_CHILD_COMPLETION','PARENT_COMPLETION','PRODUCED_RETAINED_BUNDLE')
LIMITS=dict(records=7,file_bytes=67108864,total_bytes=536870912,inventory_bytes=65536,projection_depth=80,projection_nodes=1048576)
KEYS={
    'RETAINED_CALL_INPUT':{'source_context','observed_work_context','plan_review','retained_evidence','temporal_binding'},
    'RUNTIME_BOUND_SOURCE':{'source_context','observed_work_context','temporal_binding'},
    'RETAINED_ADMISSION':{'admission','current_prefix'},
    'RETAINED_CONSUMPTION':{'admission','consumption','artifact','current_prefix','running_slot','running_slot_artifact'},
    'FRESH_CHILD_COMPLETION':{'child_input','scope_projection','completion'},
    'PARENT_COMPLETION':{'parent_input','completion'},
    'PRODUCED_RETAINED_BUNDLE':{'bundle'}}
CODES=frozenset(('PASSIVE_TYPE_REFUSED','PASSIVE_RESOURCE_REFUSED','PASSIVE_DUPLICATE_REFUSED',
    'PASSIVE_PROJECTION_REFUSED','PASSIVE_IO_FAILED','PASSIVE_FOREIGN_THREAD_REFUSED'))


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()



def required_passive_output(method):
    @wraps(method)
    def guarded(self,name,*args,**kwargs):
        try:return method(self,name,*args,**kwargs)
        except BaseException as error:
            code=error.args[0]if type(error)is ValueError and len(error.args)==1 and type(error.args[0])is str and error.args[0]in CODES else 'REQUIRED_OUTPUT_IO_FAILED'
            if self.availability is not None:self.availability('PASSIVE_INVENTORY'if name=='inventory.json'else'PASSIVE_BODY',code)
            raise
    return guarded

class ProducedConsumers:
    def __init__(self,workspace,type_inventory,candidate_pins,input_refs,*,shared_budget=None,availability=None):
        self.availability=availability
        self.workspace=workspace;self.directory=workspace/'public_consumers';self.main_ident=threading.get_ident()
        self.input_refs=tuple(dict(row)for row in input_refs);self.attempted=set();self.files=[];self.failures=[];self.total=0;self.dropped_failures=0
        self.types={};self.frozen_types=set();self.shared_budget=shared_budget
        for module,row in type_inventory['modules'].items():
            loaded=sys.modules.get(module)
            if loaded is None:continue
            if candidate_pins.get(row['path'])!=row['source_sha256']:raise ValueError('candidate_passive_type_source_pin')
            for name in row['classes']:
                cls=vars(loaded).get(name)
                if type(cls)is not type or cls.__module__!=module:raise ValueError('candidate_passive_type_identity')
                self.types[module+'.'+name]=cls
            if module in ('hedgehog.kernel.abi_v01','hedgehog.kernel.root_decision_v01','hedgehog.kernel.semantic_work_v01'):
                self.frozen_types.add(vars(loaded)['_FrozenJSONObject'])
        self.allowed=frozenset(self.types.values())
        self.directory.mkdir(mode=0o700,exist_ok=False);self.fsync_parent(self.workspace)

    def require(self,value):
        if not value:raise ValueError('PASSIVE_TYPE_REFUSED')

    def nominal(self,value,name):
        self.require(type(value)is self.types.get(name))

    def shape(self,kind,value):
        self.require(type(value)is dict and set(value)==KEYS[kind])
        d='hedgehog.kernel.fractal_runtime_v02.';a='hedgehog.kernel.abi_v01.'
        for key,name in (('source_context','FractalRuntimeSourceContextV02'),('observed_work_context','RuntimeObservedWorkContextV02'),
                ('plan_review','FractalRetainedPlanReviewV01'),('temporal_binding','FractalCurrentTemporalBindingV02'),
                ('admission','FractalRetainedWorkAdmissionV01'),('consumption','FractalRetainedWorkConsumptionV01'),
                ('current_prefix','FractalRetainedWorkPrefixV01'),('child_input','FractalCellInputV02'),
                ('parent_input','FractalCellInputV02'),('scope_projection','ParentChildScopeProjectionV02'),
                ('bundle','FractalRetainedWorkExecutionBundleV01')):
            if key in value:self.nominal(value[key],d+name)
        for key in ('artifact','running_slot_artifact'):
            if key in value:self.nominal(value[key],a+'KernelArtifactV01')
        if 'retained_evidence'in value:
            self.require(type(value['retained_evidence'])is tuple and len(value['retained_evidence'])==1)
            self.nominal(value['retained_evidence'][0],d+'FractalRetainedWorkEvidenceV01')
        if 'running_slot'in value:self.nominal(value['running_slot'],d+'FractalCellQueueEntryV02')
        if 'completion'in value:
            completion=value['completion']
            self.require(type(completion)is dict and set(completion)=={'result','result_artifact','final_cell_budget',
                'completion_global_budget','terminal_entries','terminal_artifacts','proposal','post_vv_report',
                'gt_advisory_report','transient_reports','pre_result_report'})
            self.nominal(completion['result'],d+'FractalCellResultV02')
            self.nominal(completion['result_artifact'],a+'KernelArtifactV01')
            self.nominal(completion['final_cell_budget'],d+'FractalRuntimeBudgetV02')
            self.nominal(completion['completion_global_budget'],d+'FractalRuntimeBudgetV02')

    def project(self,value):
        # Iterative projection; no callable/property/repr/asdict/formatter fallback.
        root=[None];pending=[('VALUE',value,root,0,0)];active=set();minimum=0;nodes=0
        while pending:
            operation,current,parent,key,depth=pending.pop()
            if operation=='EXIT':active.remove(current);continue
            nodes+=1
            if nodes>LIMITS['projection_nodes']or depth>LIMITS['projection_depth']:raise ValueError('PASSIVE_RESOURCE_REFUSED')
            typ=type(current)
            if current is None or typ in (bool,int,str,float):
                if typ is float and not math.isfinite(current):raise ValueError('PASSIVE_TYPE_REFUSED')
                if typ is str and len(current)>LIMITS['file_bytes']-minimum:raise ValueError('PASSIVE_RESOURCE_REFUSED')
                minimum+=len(canonical(current));parent[key]=current
            else:
                identity=id(current)
                if identity in active:raise ValueError('PASSIVE_PROJECTION_REFUSED')
                active.add(identity);pending.append(('EXIT',identity,None,None,depth))
                if typ in self.frozen_types:
                    pairs=current.items
                    self.require(type(pairs)is tuple and all(type(pair)is tuple and len(pair)==2 and type(pair[0])is str for pair in pairs))
                    self.require(len({pair[0]for pair in pairs})==len(pairs));children=list(pairs);output={}
                elif typ in self.allowed:
                    definitions=fields(current)
                    self.require(all(not field.name.startswith('_')for field in definitions))
                    children=[(field.name,getattr(current,field.name))for field in definitions];output={}
                elif typ in (dict,MappingProxyType):
                    self.require(all(type(name)is str for name in current));children=list(current.items());output={}
                elif typ in (tuple,list):children=list(enumerate(current));output=[None]*len(current)
                else:raise ValueError('PASSIVE_TYPE_REFUSED')
                minimum+=2+max(0,len(children)-1)
                if type(output)is dict:minimum+=sum(len(canonical(name))+1 for name,_ in children)
                parent[key]=output
                for name,child in reversed(children):pending.append(('VALUE',child,output,name,depth+1))
            if minimum>LIMITS['file_bytes']:raise ValueError('PASSIVE_RESOURCE_REFUSED')
        return root[0]

    def fsync_parent(self,path):
        self.check_directory(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY)
        unwinding=False
        try:os.fsync(fd)
        except BaseException as error:unwinding=not isinstance(error,Exception);raise
        finally:
            try:os.close(fd)
            except BaseException:
                if not unwinding:raise

    def check_directory(self,path):
        if path not in (self.workspace,self.directory):raise ValueError('PASSIVE_IO_FAILED')
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=os.geteuid()or stat.S_IMODE(info.st_mode)&0o022:
            raise ValueError('PASSIVE_IO_FAILED')

    @required_passive_output
    def persist(self,name,raw,cap):
        self.check_directory(self.directory)
        if len(raw)>cap:raise ValueError('PASSIVE_RESOURCE_REFUSED')
        # P12 adds only conservative shared accounting; old kinds, nominal
        # projections, local limits and file/readback semantics stay unchanged.
        try:shared_ticket=self.shared_budget.reserve('old',name,len(raw))if self.shared_budget is not None else None
        except ValueError as error:
            if error.args==('REPORT_SHARED_BUDGET_REFUSED',):raise ValueError('PASSIVE_RESOURCE_REFUSED')from None
            raise
        path=self.directory/name;fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);unwinding=False
        try:
            count=os.write(fd,raw)
            if shared_ticket is not None:self.shared_budget.observed_write(shared_ticket,count)
            if count!=len(raw):raise OSError()
            os.fsync(fd)
        except BaseException as error:unwinding=not isinstance(error,Exception);raise
        finally:
            try:os.close(fd)
            except BaseException:
                if not unwinding:raise
        self.fsync_parent(self.directory);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);unwinding=False
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode)or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.geteuid()or not 0<=info.st_size<=cap:
                raise ValueError('PASSIVE_IO_FAILED')
            copied=os.read(fd,info.st_size+1);after=os.fstat(fd)
            identity=lambda q:(q.st_dev,q.st_ino,q.st_size,q.st_mode,q.st_nlink,q.st_uid,q.st_mtime_ns,q.st_ctime_ns)
            if copied!=raw or identity(info)!=identity(after):raise ValueError('PASSIVE_IO_FAILED')
        except BaseException as error:unwinding=not isinstance(error,Exception);raise
        finally:
            try:os.close(fd)
            except BaseException:
                if not unwinding:raise
        if shared_ticket is not None:self.shared_budget.acknowledge(shared_ticket)
        return dict(path='public_consumers/'+name,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))

    def consume(self,kind,factory):
        if threading.get_ident()!=self.main_ident:
            self.failure(kind,'PASSIVE_FOREIGN_THREAD_REFUSED');return
        if kind not in KINDS or kind in self.attempted:
            self.failure(kind,'PASSIVE_DUPLICATE_REFUSED');return
        self.attempted.add(kind)
        try:
            value=factory();self.shape(kind,value);material=self.project(value);value=None;factory=None
            record=dict(schema='radik.g2e.passive_produced_consumer.v01',kind=kind,
                status='ACTUAL_PRODUCED_INTERMEDIATE_NOT_FINAL_ACCEPTANCE',
                terminal_bundle_validation='NOT_YET_COMPLETED'if kind=='PRODUCED_RETAINED_BUNDLE'else'NOT_INFERRED',
                material=material,prerequisite_public_refs=list(self.input_refs),
                omissions=['LIVE_HOST_AND_CAPTURE_TEMPORAL_VERIFICATION_NOT_SERIALIZED'],
                InitVar_public_binding_and_observed_context='DIRECT_ARGUMENT_AND_BOUND_SOURCE_RECORDS',
                native_acceptance_or_authority_restored=False)
            # Encoding buffers are finite after projection; this is no general allocation firewall.
            parts=[];size=0
            for piece in json.JSONEncoder(sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).iterencode(record):
                chunk=piece.encode();size+=len(chunk)
                if size>LIMITS['file_bytes']or self.total+size>LIMITS['total_bytes']:raise ValueError('PASSIVE_RESOURCE_REFUSED')
                parts.append(chunk)
            raw=b''.join(parts);ref=self.persist(kind.lower()+'.json',raw,LIMITS['file_bytes'])
            self.files.append(ref);self.total+=len(raw)
            return ref
        except Exception as error:
            code=error.args[0]if type(error)is ValueError and len(error.args)==1 and type(error.args[0])is str and error.args[0]in CODES else'PASSIVE_IO_FAILED'
            self.failure(kind,code)

    def failure(self,kind,code):
        if self.availability is not None:self.availability('PASSIVE_BODY',code)
        if len(self.failures)<14:self.failures.append(dict(kind=kind if kind in KINDS else'UNKNOWN',code=code))
        else:self.dropped_failures+=1

    def finish(self):
        if self.availability is not None and (self.failures or any(kind not in self.attempted for kind in KINDS)):
            self.availability('PASSIVE_INVENTORY','REQUIRED_OUTPUT_MISSING')
        value=dict(schema='radik.g2e.passive_produced_inventory.v01',files=list(self.files),
            attempted_kinds=sorted(self.attempted),not_attempted_kinds=[kind for kind in KINDS if kind not in self.attempted],
            missing_verified_kinds=[kind for kind in KINDS if not any(
                row['path']=='public_consumers/'+kind.lower()+'.json'for row in self.files)],
            failed_observations=list(self.failures),dropped_failure_records=self.dropped_failures,limits=LIMITS,total_verified_bytes=self.total,
            native_final_acceptance_inferred=False,unreturned_objects_reconstructed=False,
            type_identity_is_not_runtime_authority=True)
        return self.persist('inventory.json',canonical(value),LIMITS['inventory_bytes'])


def consume_produced_v01(writer,kind,factory):
    """Observed source-pinned sink callback; serialize now and retain no live values."""
    return writer.consume(kind,factory)
