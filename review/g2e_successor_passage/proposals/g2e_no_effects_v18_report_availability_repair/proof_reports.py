"""Passive selected report records and one conservative shared byte allowance.

This module performs no native validation, formatting, authority lookup or replay.
Its raw storage methods are also usable by separately admitted pure-data controls.
"""
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import stat
import threading

KINDS=('D_CELL_PROPOSAL_REPORT','D_CELL_POST_VV_REPORT','D_CELL_GT_REPORT',
    'D_CELL_PRE_RESULT_REPORT','D_CELL_RESULT_REPORT','D_COMPLETE_RESULTS_REPORTS',
    'D_RUNTIME_REPORT_VALIDATION','D_STAGE_VALIDATION','D_ABI_VALIDATION',
    'D_CAUSAL_VALIDATION','D_TERMINAL_VALIDATION','E_BINDING_VALIDATION',
    'E_PRESERVATION_VALIDATION','E_RESULT_STRUCTURAL_VALIDATION',
    'E_RESULT_CONTEXT_VALIDATION','E_PAIR2_CORE','E_TRACE_VALIDATION',
    'E_RUNTIME_REPORT_VALIDATION','E_INNER_FINAL_VALIDATION','E_V02_FINAL_VALIDATION')
CELL_KINDS=frozenset(KINDS[:5])
OLD_NAMES=('retained_call_input.json','runtime_bound_source.json','retained_admission.json',
    'retained_consumption.json','fresh_child_completion.json','parent_completion.json',
    'produced_retained_bundle.json')
LIMITS=dict(body_leaves=32,entries=96,file_bytes=67108864,total_shared_bytes=3221225472,
    inventory_bytes=65536,journal_rows=58,journal_row_bytes=16384,journal_file_bytes=2097152)
CODES=frozenset(('REPORT_TYPE_REFUSED','REPORT_RESOURCE_REFUSED','REPORT_DUPLICATE_REFUSED',
    'REPORT_IO_FAILED','REPORT_FOREIGN_THREAD_REFUSED','REPORT_JOURNAL_UNCERTAIN',
    'REPORT_SHARED_BUDGET_REFUSED'))
KEYS={
    'D_CELL_PROPOSAL_REPORT':{'cell_input','proposal','proposal_report','source_context','topology',
        'pre_post_vv_terminal_queue_entries','child_results','partial_failures'},
    'D_CELL_POST_VV_REPORT':{'cell_input','post_vv_report','post_report','proposal'},
    'D_CELL_GT_REPORT':{'cell_input','gt_advisory_report','gt_report','post_vv_report'},
    'D_CELL_PRE_RESULT_REPORT':{'pre_result_report','cell_input','terminal_entries','child_results',
        'partial_failures','proposal','post_vv_report','gt_advisory_report','final_cell','final_global',
        'source_context','topology'},
    'D_CELL_RESULT_REPORT':{'result','result_report','cell_input','pre_result_report'},
    'D_COMPLETE_RESULTS_REPORTS':{'retained_prefix','reports'},
    'D_RUNTIME_REPORT_VALIDATION':{'runtime_trace','runtime_report','report_artifact',
        'report_validation','parent_return_decision','retained_prefix'},
    'D_STAGE_VALIDATION':{'stage','artifacts','stage_report','runtime_report','retained_prefix'},
    'D_ABI_VALIDATION':{'stage_d_c','abi_report','runtime_report','retained_prefix'},
    'D_CAUSAL_VALIDATION':{'causal_refs','causal_report','runtime_report','retained_prefix'},
    'D_TERMINAL_VALIDATION':{'terminal_report','bundle_runtime_report_id','bundle_topology_id',
        'same_native_value_argument_as_preceding_produced_bundle'},
    'E_BINDING_VALIDATION':{'binding','binding_report','recomputation_plan_id','recomputed_runtime_report_id'},
    'E_PRESERVATION_VALIDATION':{'preservation_proof','preservation_artifact','recomputed_bindings',
        'preservation_report','plan','affected_result'},
    'E_RESULT_STRUCTURAL_VALIDATION':{'recomputation_result','result_structural_report'},
    'E_RESULT_CONTEXT_VALIDATION':{'result_context_report','pre_final_causal_refs','recomputation_result'},
    'E_PAIR2_CORE':{'final_root_input','final_root_result','final_root_artifact','packet_id',
        'packet_is_input_root_review_packet','branch'},
    'E_TRACE_VALIDATION':{'runtime_trace','trace_report'},
    'E_RUNTIME_REPORT_VALIDATION':{'runtime_report','runtime_report_artifact','runtime_report_validation'},
    'E_INNER_FINAL_VALIDATION':{'value','report'},
    'E_V02_FINAL_VALIDATION':{'value','checked'}}


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def report_names():
    names=[]
    for kind in KINDS:
        if kind in CELL_KINDS:names.extend(kind.lower()+'_'+role+'.json'for role in ('child','parent'))
        elif kind=='D_STAGE_VALIDATION':names.extend(kind.lower()+'_'+stage.lower()+'.json'
            for stage in ('STAGE_D_A','STAGE_D_B','STAGE_D_C'))
        elif kind=='E_BINDING_VALIDATION':names.append('e_binding_validation.jsonl')
        else:names.append(kind.lower()+'.json')
    return tuple(names)


class SharedObservationBudget:
    """Charges never decrease, including zero, partial or uncertain attempts."""
    def __init__(self,*,limit=LIMITS['total_shared_bytes']):
        if type(limit)is not int or not 2*LIMITS['inventory_bytes']<=limit<=LIMITS['total_shared_bytes']:
            raise ValueError('REPORT_SHARED_BUDGET_REFUSED')
        self.limit=limit;self.reserved=2*LIMITS['inventory_bytes'];self.rows={}
        self.main_ident=threading.get_ident()
        for scope in ('old','new'):
            self.rows[(scope,'inventory.json',1)]=dict(scope=scope,path='inventory.json',ordinal=1,
                reserved_bytes=LIMITS['inventory_bytes'],encoded_bytes=None,attempted=False,
                observed_write_bytes=None,readback_verified=False)

    def reserve(self,scope,name,size,*,ordinal=1):
        if threading.get_ident()!=self.main_ident or scope not in ('old','new') \
                or type(name)is not str or type(size)is not int or size<0 \
                or type(ordinal)is not int or ordinal<1:
            raise ValueError('REPORT_SHARED_BUDGET_REFUSED')
        allowed=OLD_NAMES if scope=='old'else report_names()
        key=(scope,name,ordinal)
        if name=='inventory.json':
            row=self.rows.get(key)
            if ordinal!=1 or row is None or row['attempted']or size>LIMITS['inventory_bytes']:
                raise ValueError('REPORT_SHARED_BUDGET_REFUSED')
            row['attempted']=True;row['encoded_bytes']=size;return key
        journal=scope=='new'and name=='e_binding_validation.jsonl'
        if name not in allowed or key in self.rows or ordinal>(58 if journal else 1) \
                or size>(LIMITS['journal_row_bytes']if journal else LIMITS['file_bytes']) \
                or self.reserved+size>self.limit:
            raise ValueError('REPORT_SHARED_BUDGET_REFUSED')
        self.reserved+=size
        self.rows[key]=dict(scope=scope,path=name,ordinal=ordinal,reserved_bytes=size,
            encoded_bytes=size,attempted=True,observed_write_bytes=None,readback_verified=False)
        return key

    def observed_write(self,key,count):
        row=self.rows[key]
        if type(count)is not int or not 0<=count<=row['encoded_bytes']:
            raise ValueError('REPORT_SHARED_BUDGET_REFUSED')
        row['observed_write_bytes']=count

    def acknowledge(self,key):
        row=self.rows[key]
        if row['observed_write_bytes']!=row['encoded_bytes']:
            raise ValueError('REPORT_SHARED_BUDGET_REFUSED')
        row['readback_verified']=True

    def snapshot(self):
        rows=[dict(row)for row in self.rows.values()]
        return dict(schema='radik.g2e.shared_observation_budget.v01',limit_bytes=self.limit,
            reserved_bytes=self.reserved,inventory_capacity_reserved_bytes=2*LIMITS['inventory_bytes'],
            inventory_capacity_is_not_actual_physical_bytes=True,
            actual_verified_bytes=sum(row['encoded_bytes']for row in rows if row['readback_verified']),
            unverified_attempt_reserved_bytes=sum(row['reserved_bytes']for row in rows
                if row['attempted']and not row['readback_verified']),reservations=rows,
            no_release_or_lost_acknowledgement_retry=True,native_budget_or_authority=False)



def required_report_output(component):
    def decorate(method):
        @wraps(method)
        def guarded(self,*args,**kwargs):
            try:return method(self,*args,**kwargs)
            except BaseException as error:
                code=error.args[0]if type(error)is ValueError and len(error.args)==1 and type(error.args[0])is str and error.args[0]in CODES else 'REQUIRED_OUTPUT_IO_FAILED'
                kind='REPORT_INVENTORY'if component=='REPORT_BODY'and kwargs.get('inventory')is True else component
                if self.availability is not None:self.availability(kind,code)
                raise
        return guarded
    return decorate

class ReportStorage:
    """Exclusive fixed paths; each journal row is reserved and verified alone."""
    def __init__(self,workspace,budget,*,availability=None):
        self.availability=availability
        if type(budget)is not SharedObservationBudget:raise ValueError('REPORT_SHARED_BUDGET_REFUSED')
        self.workspace=workspace;self.directory=workspace/'public_reports';self.budget=budget
        self.journal_size=0;self.journal_rows=0;self.journal_uncertain=False
        self.directory.mkdir(mode=0o700,exist_ok=False);self.fsync_parent(workspace)

    def directory_check(self,path):
        if path not in (self.workspace,self.directory):raise ValueError('REPORT_IO_FAILED')
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=os.geteuid()or stat.S_IMODE(info.st_mode)&0o022:
            raise ValueError('REPORT_IO_FAILED')

    def fsync_parent(self,path):
        self.directory_check(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY);unwinding=False
        try:os.fsync(fd)
        except BaseException as error:unwinding=not isinstance(error,Exception);raise
        finally:
            try:os.close(fd)
            except BaseException:
                if not unwinding:raise

    def readback(self,path,expected):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);unwinding=False
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode)or before.st_nlink!=1 or before.st_uid!=os.geteuid() \
                    or stat.S_IMODE(before.st_mode)!=0o600 \
                    or before.st_size!=len(expected):raise ValueError('REPORT_IO_FAILED')
            copied=os.read(fd,len(expected)+1);after=os.fstat(fd)
            identity=lambda q:(q.st_dev,q.st_ino,q.st_size,q.st_mode,q.st_nlink,q.st_uid,q.st_mtime_ns,q.st_ctime_ns)
            if copied!=expected or identity(before)!=identity(after):raise ValueError('REPORT_IO_FAILED')
        except BaseException as error:unwinding=not isinstance(error,Exception);raise
        finally:
            try:os.close(fd)
            except BaseException:
                if not unwinding:raise

    @required_report_output('REPORT_BODY')
    def persist(self,name,raw,*,inventory=False):
        self.directory_check(self.directory)
        if type(raw)is not bytes or (name!='inventory.json'if inventory else name not in report_names()) \
                or name.endswith('.jsonl')or len(raw)>(LIMITS['inventory_bytes']if inventory else LIMITS['file_bytes']):
            raise ValueError('REPORT_RESOURCE_REFUSED')
        ticket=self.budget.reserve('new',name,len(raw))
        path=self.directory/name;fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);unwinding=False
        try:
            count=os.write(fd,raw);self.budget.observed_write(ticket,count)
            if count!=len(raw):raise OSError()
            os.fsync(fd)
        except BaseException as error:unwinding=not isinstance(error,Exception);raise
        finally:
            try:os.close(fd)
            except BaseException:
                if not unwinding:raise
        self.fsync_parent(self.directory);self.readback(path,raw);self.budget.acknowledge(ticket)
        return dict(path='public_reports/'+name,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))

    @required_report_output('BINDING_JOURNAL')
    def append_binding(self,raw):
        self.directory_check(self.directory)
        if self.journal_uncertain:raise ValueError('REPORT_JOURNAL_UNCERTAIN')
        if type(raw)is not bytes or not raw.endswith(b'\n')or len(raw)>LIMITS['journal_row_bytes'] \
                or self.journal_rows>=LIMITS['journal_rows'] \
                or self.journal_size+len(raw)>LIMITS['journal_file_bytes']:
            raise ValueError('REPORT_RESOURCE_REFUSED')
        ordinal=self.journal_rows+1
        ticket=self.budget.reserve('new','e_binding_validation.jsonl',len(raw),ordinal=ordinal)
        self.journal_uncertain=True
        path=self.directory/'e_binding_validation.jsonl'
        flags=os.O_WRONLY|os.O_NOFOLLOW|os.O_APPEND|(os.O_CREAT|os.O_EXCL if ordinal==1 else 0)
        fd=os.open(path,flags,0o600);unwinding=False
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode)or before.st_nlink!=1 or before.st_uid!=os.geteuid() \
                    or before.st_size!=self.journal_size:raise ValueError('REPORT_IO_FAILED')
            count=os.write(fd,raw);self.budget.observed_write(ticket,count)
            if count!=len(raw):raise OSError()
            os.fsync(fd)
        except BaseException as error:unwinding=not isinstance(error,Exception);raise
        finally:
            try:os.close(fd)
            except BaseException:
                if not unwinding:raise
        if ordinal==1:self.fsync_parent(self.directory)
        # Read a bounded complete prefix. No previous row is credited after a
        # changed prefix; an uncertain append is never attempted again.
        read_fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);unwinding=False
        try:
            info=os.fstat(read_fd);expected_size=self.journal_size+len(raw)
            if info.st_size!=expected_size or info.st_nlink!=1 or info.st_uid!=os.geteuid() \
                    or stat.S_IMODE(info.st_mode)!=0o600 or not stat.S_ISREG(info.st_mode):
                raise ValueError('REPORT_IO_FAILED')
            full=os.read(read_fd,expected_size+1);after=os.fstat(read_fd)
            identity=lambda q:(q.st_dev,q.st_ino,q.st_size,q.st_mode,q.st_nlink,q.st_uid,q.st_mtime_ns,q.st_ctime_ns)
            if len(full)!=expected_size or full[-len(raw):]!=raw \
                    or identity(info)!=identity(after) \
                    or self.journal_size and hashlib.sha256(full[:self.journal_size]).hexdigest()!=self.journal_digest:
                raise ValueError('REPORT_IO_FAILED')
        except BaseException as error:unwinding=not isinstance(error,Exception);raise
        finally:
            try:os.close(read_fd)
            except BaseException:
                if not unwinding:raise
        self.budget.acknowledge(ticket);self.journal_rows=ordinal;self.journal_size=len(full)
        self.journal_digest=hashlib.sha256(full).hexdigest();self.journal_uncertain=False
        return dict(path='public_reports/e_binding_validation.jsonl',sha256=self.journal_digest,
            size_bytes=self.journal_size,verified_rows=self.journal_rows)


class ProducedReports:
    def __init__(self,workspace,projector,budget,input_refs,*,progress=None,availability=None):
        self.availability=availability
        self.projector=projector;self.budget=budget;self.storage=ReportStorage(workspace,budget,availability=availability)
        self.input_refs=tuple(dict(row)for row in input_refs);self.main_ident=threading.get_ident()
        self.attempted={};self.files=[];self.failures=[];self.journal_ref=None;self.finished=False
        self.last_verified_journal_prefix=None;self.dropped_failures=0;self.progress=progress

    def nominal(self,value,name):
        try:self.projector.nominal(value,name)
        except ValueError as error:
            if error.args==('PASSIVE_TYPE_REFUSED',):raise ValueError('REPORT_TYPE_REFUSED')from None
            raise

    def shape(self,kind,value):
        if type(value)is not dict or set(value)!=KEYS[kind]:raise ValueError('REPORT_TYPE_REFUSED')
        d='hedgehog.kernel.fractal_runtime_v02.';e='hedgehog.kernel.continuous_delta_runtime_v01.'
        dv=d+'FractalRuntimeValidationReportV02';ev=e+'ContinuousDeltaValidationReportV01'
        report_fields={'proposal_report','post_report','gt_report','pre_result_report','result_report',
            'report_validation','stage_report','abi_report','causal_report','terminal_report'}if kind.startswith('D_')else {
            'binding_report','preservation_report','result_structural_report','result_context_report',
            'trace_report','runtime_report_validation','report','checked'}
        for field in report_fields&set(value):self.nominal(value[field],dv if kind.startswith('D_')else ev)
        for field,name in {'cell_input':d+'FractalCellInputV02','source_context':d+'FractalRuntimeSourceContextV02',
                'topology':d+'RuntimeExecutionTopologyV02','result':d+'FractalCellResultV02',
                'retained_prefix':d+'FractalRetainedWorkPrefixV01','binding':e+'RecomputedArtifactBindingV01',
                'preservation_proof':e+'RetainedWorkPreservationProofV01','plan':e+'RetainedSelectiveRecomputationPlanV01',
                'affected_result':e+'AffectedSetResultV01','recomputation_result':e+'SelectiveRecomputationResultV01',
                'final_root_input':'hedgehog.kernel.root_decision_v01.RootDecisionInputV01',
                'final_root_result':'hedgehog.kernel.root_decision_v01.RootDecisionResultV01'}.items():
            if field in value:self.nominal(value[field],name)
        for field in ('final_cell','final_global'):
            if field in value:self.nominal(value[field],d+'FractalRuntimeBudgetV02')
        for field,name in {'pre_post_vv_terminal_queue_entries':d+'FractalCellQueueEntryV02',
                'terminal_entries':d+'FractalCellQueueEntryV02','child_results':d+'FractalCellResultV02',
                'partial_failures':d+'FractalPartialFailureRecordV02',
                'artifacts':'hedgehog.kernel.abi_v01.KernelArtifactV01',
                'stage_d_c':'hedgehog.kernel.abi_v01.KernelArtifactV01',
                'causal_refs':'hedgehog.kernel.abi_v01.CausalConsumptionRefV01',
                'pre_final_causal_refs':'hedgehog.kernel.abi_v01.CausalConsumptionRefV01',
                'recomputed_bindings':e+'RecomputedArtifactBindingV01'}.items():
            if field in value:
                if type(value[field])is not tuple:raise ValueError('REPORT_TYPE_REFUSED')
                for item in value[field]:self.nominal(item,name)
        for field in ('proposal','post_vv_report','gt_advisory_report'):
            if field in value and type(value[field])is not dict:raise ValueError('REPORT_TYPE_REFUSED')
        if 'parent_return_decision'in value:
            self.nominal(value['parent_return_decision'],'hedgehog.kernel.transition_registry_v01.TransitionDecisionV01')
        for field in ('report_artifact','preservation_artifact','final_root_artifact','runtime_report_artifact'):
            if field in value:self.nominal(value[field],'hedgehog.kernel.abi_v01.KernelArtifactV01')
        for field,suffix in (('runtime_trace','FractalRuntimeTraceV02'if kind.startswith('D_')else'ContinuousDeltaRuntimeTraceV01'),
                ('runtime_report','FractalRuntimeReportV02'if kind.startswith('D_')else'ContinuousDeltaRuntimeReportV01')):
            if field in value:self.nominal(value[field],(d if kind.startswith('D_')else e)+suffix)
        if kind=='D_COMPLETE_RESULTS_REPORTS':
            if type(value['reports'])is not tuple:raise ValueError('REPORT_TYPE_REFUSED')
            for report in value['reports']:self.nominal(report,dv)
        if kind in ('E_INNER_FINAL_VALIDATION','E_V02_FINAL_VALIDATION'):
            self.nominal(value['value'],e+('ContinuousDeltaExecutionBundleV01'if kind=='E_INNER_FINAL_VALIDATION'
                else'ContinuousDeltaExecutionBundleV02'))
        if kind=='E_PAIR2_CORE'and(type(value['packet_is_input_root_review_packet'])is not bool
                or value['branch']not in ('SUCCESS','BLOCKED')):raise ValueError('REPORT_TYPE_REFUSED')
        if kind=='D_TERMINAL_VALIDATION'and value['same_native_value_argument_as_preceding_produced_bundle']is not True:
            raise ValueError('REPORT_TYPE_REFUSED')

    def consume(self,kind,factory):
        if threading.get_ident()!=self.main_ident:self.failure(kind,'REPORT_FOREIGN_THREAD_REFUSED');return
        if kind not in KINDS:self.failure(kind,'REPORT_TYPE_REFUSED');return
        limit=2 if kind in CELL_KINDS else 3 if kind=='D_STAGE_VALIDATION'else 58 if kind=='E_BINDING_VALIDATION'else 1
        attempt=self.attempted.get(kind,0)+1;self.attempted[kind]=attempt
        if attempt>limit or sum(self.attempted.values())>LIMITS['entries']:
            self.failure(kind,'REPORT_DUPLICATE_REFUSED');return
        try:
            if kind=='E_BINDING_VALIDATION'and self.storage.journal_uncertain:
                raise ValueError('REPORT_JOURNAL_UNCERTAIN')
            value=factory();self.shape(kind,value)
            if kind in CELL_KINDS:
                role='parent'if value['cell_input'].parent_cell_id is None else'child'
                name=kind.lower()+'_'+role+'.json'
            elif kind=='D_STAGE_VALIDATION':
                if value['stage']not in ('STAGE_D_A','STAGE_D_B','STAGE_D_C'):raise ValueError('REPORT_TYPE_REFUSED')
                name=kind.lower()+'_'+value['stage'].lower()+'.json'
            else:name=kind.lower()+'.json'
            try:material=self.projector.project(value)
            except ValueError as error:
                if error.args==('PASSIVE_RESOURCE_REFUSED',):raise ValueError('REPORT_RESOURCE_REFUSED')from None
                if error.args in (('PASSIVE_TYPE_REFUSED',),('PASSIVE_PROJECTION_REFUSED',)):
                    raise ValueError('REPORT_TYPE_REFUSED')from None
                raise
            value=None;factory=None
            record=dict(schema='radik.g2e.selected_native_report.v01',kind=kind,kind_attempt=attempt,
                status='ACTUAL_RETURNED_REPORT_NOT_ACCEPTANCE',material=material,
                prerequisite_public_refs=list(self.input_refs),
                omissions=['LIVE_HOST_PRIVATE_VERIFICATION_AND_INITVAR_HANDLES_NOT_INSPECTED'],
                native_acceptance_or_authority_restored=False)
            if kind=='D_TERMINAL_VALIDATION':
                matches=[dict(row)for row in self.projector.files
                    if row['path']=='public_consumers/produced_retained_bundle.json']
                record['preceding_produced_bundle_verified_ref']=matches[0]if len(matches)==1 else None
                record['preceding_produced_bundle_ref_status']='VERIFIED_RAW_REF_AVAILABLE'if len(matches)==1 \
                    else'RAW_REF_NOT_VERIFIED_OR_NOT_AVAILABLE'
                record['same_value_association_basis']='SOURCE_LEXICAL_ARGUMENT_NOT_RUNTIME_IDENTITY_TEST'
            raw=canonical(record)
            if kind=='E_BINDING_VALIDATION':
                ref=self.append_report_row(raw+b'\n')
                self.emit_progress(kind,ref);return dict(ref)
            if any(row['path']=='public_reports/'+name for row in self.files):raise ValueError('REPORT_DUPLICATE_REFUSED')
            ref=self.storage.persist(name,raw);self.files.append(ref)
            self.emit_progress(kind,ref);return dict(ref)
        except Exception as error:
            code=error.args[0]if type(error)is ValueError and len(error.args)==1 \
                and type(error.args[0])is str and error.args[0]in CODES else'REPORT_IO_FAILED'
            self.failure(kind,code)

    def failure(self,kind,code):
        if self.availability is not None:self.availability('BINDING_JOURNAL'if kind=='E_BINDING_VALIDATION'else'REPORT_BODY',code)
        if len(self.failures)<40:self.failures.append(dict(kind=kind if kind in KINDS else'UNKNOWN',code=code))
        else:self.dropped_failures+=1

    def append_report_row(self,raw):
        # An attempted append can change the physical file. A previous prefix
        # hash must never be advertised as its current whole-file hash.
        self.journal_ref=None
        self.journal_ref=self.storage.append_binding(raw)
        self.last_verified_journal_prefix=dict(self.journal_ref)
        return dict(self.journal_ref)

    def emit_progress(self,kind,ref):
        if self.progress is not None:
            try:self.progress(kind,dict(ref))
            except Exception:self.failure(kind,'REPORT_IO_FAILED')

    def verified_files(self):
        return [*(dict(row)for row in self.files),*([dict(self.journal_ref)]if self.journal_ref is not None else[])]

    def finish(self):
        if self.finished:raise ValueError('REPORT_DUPLICATE_REFUSED')
        self.finished=True
        if self.availability is not None and (self.failures or any(kind not in self.attempted for kind in KINDS)):
            self.availability('REPORT_INVENTORY','REQUIRED_OUTPUT_MISSING')
        value=dict(schema='radik.g2e.selected_report_inventory.v01',files=self.verified_files(),
            attempted_kinds=dict(self.attempted),failures=list(self.failures),
            dropped_failure_records=self.dropped_failures,limits=LIMITS,
            binding_journal_uncertain=self.storage.journal_uncertain,
            last_verified_journal_prefix=self.last_verified_journal_prefix,
            prefix_is_not_current_whole_file_ref=self.journal_ref is None,
            shared_budget_snapshot=self.budget.snapshot(),
            snapshot_scope='BEFORE_THIS_INVENTORY_ATTEMPT_NOT_FINAL_PUBLICATION_STATE',
            final_budget_state_belongs_in_technical_result=True,native_acceptance_inferred=False)
        return self.storage.persist('inventory.json',canonical(value),inventory=True)


def consume_report_v01(writer,kind,factory):
    return writer.consume(kind,factory)
