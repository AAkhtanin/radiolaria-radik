"""Passive ordinary-loader observation of actual reports returned inside one E.

This adapter reuses the immutable P18 report storage/projector and the finite
P23 nominal type inventory. It performs no native validation, replay, authority
lookup, root decision, route choice, model turn or native execution of its own.
"""
from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time
import types


P18 = 'review/g2e_successor_passage/proposals/g2e_no_effects_v18_report_availability_repair'
P30 = 'review/g2e_successor_passage/proposals/g2e_no_effects_v30_witness_repair'
P23 = 'review/g2e_successor_passage/proposals/g2e_no_effects_v23_observable_e_early_checkpoint'
HELPER_PINS = {
    P30+'/proof_reports.py': 'c3fd6357365384e508c8031d47ad81ff65c62a107a6d4a097ac75bdda6ea86c2',
    P18+'/proof_consumers.py': '7fc4a4f0492edbc5e8cb0545f0f9170cb54cfa1eb7a7313742fa345312d065e4',
    P23+'/consumer_types.json': 'fe0967fa976283619fbcaf3f19d3fb52ad8286353f8c9db6d36c8883ac5c195c'}
EMERGENCY_IO_EXIT = 86
MAX_BYTES = 67108864
PASS_FIELDS = {
    'D_CELL_PROPOSAL_REPORT': 'proposal_report',
    'D_CELL_POST_VV_REPORT': 'post_report',
    'D_CELL_GT_REPORT': 'gt_report',
    'D_CELL_PRE_RESULT_REPORT': 'pre_result_report',
    'D_CELL_RESULT_REPORT': 'result_report',
    'D_RUNTIME_REPORT_VALIDATION': 'report_validation',
    'D_STAGE_VALIDATION': 'stage_report',
    'D_ABI_VALIDATION': 'abi_report',
    'D_CAUSAL_VALIDATION': 'causal_report',
    'D_TERMINAL_VALIDATION': 'terminal_report',
    'E_PRESERVATION_VALIDATION': 'preservation_report',
    'E_RESULT_STRUCTURAL_VALIDATION': 'result_structural_report',
    'E_RESULT_CONTEXT_VALIDATION': 'result_context_report',
    'E_TRACE_VALIDATION': 'trace_report',
    'E_RUNTIME_REPORT_VALIDATION': 'runtime_report_validation',
    'E_INNER_FINAL_VALIDATION': 'report',
    'E_V02_FINAL_VALIDATION': 'checked'}


class RequiredNativeWitnessLoss(BaseException):
    """Bypass optional native diagnostic Exception containment after technical loss."""


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False).encode()


def logical(name):
    require(type(name) is str and name and not name.startswith('/') and
        all(part not in ('','.','..','.git','.codex','.aws','Arena','arena')
            for part in name.split('/')), 'native_observer_path')
    return name


def safe_token(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_:./-]{1,256}',value),
        'native_observer_token')
    return value


def owned_path(project, name):
    path=project/logical(name)
    current=project
    require(current.is_absolute() and current.is_dir() and not current.is_symlink(),
        'native_observer_project')
    for part in path.relative_to(project).parts[:-1]:
        current=current/part
        require(current.is_dir() and not current.is_symlink(),'native_observer_parent')
    require(not path.is_symlink(),'native_observer_symlink')
    return path


def read_raw(project, name, cap=MAX_BYTES):
    path=owned_path(project,name)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
            before.st_uid==os.geteuid() and 0<=before.st_size<=cap,'native_observer_regular')
        raw=stream.read(before.st_size+1)
        after=os.fstat(stream.fileno())
    identity=lambda q:(q.st_dev,q.st_ino,q.st_size,q.st_mode,q.st_nlink,
        q.st_uid,q.st_mtime_ns,q.st_ctime_ns)
    require(len(raw)==before.st_size and identity(before)==identity(after),
        'native_observer_unstable_read')
    return raw


def put(project, workspace, name, value, cap=262144):
    raw=canonical(value)
    require(len(raw)<=cap,'native_observer_inventory_bound')
    target=owned_path(project,str((workspace/name).relative_to(project)))
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        require(stream.write(raw)==len(raw),'native_observer_short_write')
        stream.flush();os.fsync(stream.fileno())
    fd=os.open(workspace,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    logical_name=str(target.relative_to(project))
    require(read_raw(project,logical_name,cap)==raw,'native_observer_inventory_readback')
    return dict(path=logical_name,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))


def load_helper(project, name, raw):
    module=types.ModuleType(name)
    module.__file__=str(project/name)
    exec(compile(raw,module.__file__,'exec',dont_inherit=True),module.__dict__)
    return module


def prepare_registry(project, profile):
    """Raw-pin first; then load finite nominal classes through the ordinary finder.

    Its returned raw registry observations prove origins/types, not native
    validation, authorization, schema use, D/E execution or semantic acceptance.
    """
    project=Path(project)
    require(type(profile) is dict and type(profile.get('native_files')) is dict
        and type(profile.get('pins')) is dict,'native_observer_profile')
    raw_helpers={}
    for name,sha in HELPER_PINS.items():
        raw=read_raw(project,name)
        require(profile['pins'].get(name)==sha and hashlib.sha256(raw).hexdigest()==sha,
            'native_observer_helper_not_in_profile')
        raw_helpers[name]=raw
    inventory=json.loads(raw_helpers[P23+'/consumer_types.json'])
    require(inventory.get('schema')=='radik.g2e.passive_consumer_type_inventory.v01'
        and type(inventory.get('modules')) is dict and 1<=len(inventory['modules'])<=32,
        'native_observer_type_inventory')
    native=profile['native_files']
    for module,row in inventory['modules'].items():
        name=row['path']
        reference=native.get(name)
        require(type(reference) is dict and reference.get('sha256')==row['source_sha256']
            and profile['pins'].get(reference['path'])==row['source_sha256']
            and hashlib.sha256(read_raw(project,reference['path'])).hexdigest()==row['source_sha256'],
            'native_observer_native_pin_before_import')
        require(module==name[:-3].replace('/','.') and type(row.get('classes')) is list,
            'native_observer_module_inventory')
    observations=[]
    for module,row in inventory['modules'].items():
        loaded=importlib.import_module(module)
        reference=native[row['path']]
        origin=str(project/reference['path'])
        spec=vars(loaded).get('__spec__')
        loader=vars(loaded).get('__loader__')
        require(vars(loaded).get('__file__')==origin and spec is not None and
            spec.origin==origin and type(loader).__module__=='config.native_profile_loader'
            and type(loader).__name__=='_Loader' and getattr(loader,'path',None)==project/reference['path']
            and type(getattr(loader,'raw',None)) is bytes and
            hashlib.sha256(loader.raw).hexdigest()==row['source_sha256'],
            'native_observer_ordinary_loader_identity')
        observations.append(dict(module=module,origin=origin,
            loader_module=type(loader).__module__,loader_type=type(loader).__name__,
            source_sha256=row['source_sha256'],classes=list(row['classes'])))
    diagnostic_name='hedgehog.kernel.diagnostic_telemetry_v01'
    diagnostic_ref=native[diagnostic_name.replace('.','/')+'.py']
    diagnostic_raw=read_raw(project,diagnostic_ref['path'])
    require(hashlib.sha256(diagnostic_raw).hexdigest()==diagnostic_ref['sha256']
        and profile['pins'].get(diagnostic_ref['path'])==diagnostic_ref['sha256'],
        'native_observer_diagnostic_pin')
    diagnostics=importlib.import_module(diagnostic_name)
    diagnostic_loader=vars(diagnostics).get('__loader__')
    require(vars(diagnostics).get('__file__')==str(project/diagnostic_ref['path']) and
        type(diagnostic_loader).__module__=='config.native_profile_loader' and
        type(diagnostic_loader).__name__=='_Loader' and
        hashlib.sha256(diagnostic_loader.raw).hexdigest()==diagnostic_ref['sha256'],
        'native_observer_diagnostic_loader')
    reports=load_helper(project,P30+'/proof_reports.py',raw_helpers[P30+'/proof_reports.py'])
    consumers=load_helper(project,P18+'/proof_consumers.py',raw_helpers[P18+'/proof_consumers.py'])
    candidate_pins={name:reference['sha256'] for name,reference in native.items()}
    return dict(profile=profile,type_inventory=inventory,candidate_pins=candidate_pins,
        reports=reports,consumers=consumers,diagnostics=diagnostics,
        module_observations=observations,helper_pins=dict(HELPER_PINS))


def admitted_entrypoint(registry,callback):
    """Bind a finite public entrypoint to its exact already pinned module function."""
    module_name='hedgehog.kernel.continuous_delta_runtime_v01'
    require(type(callback)is types.FunctionType and callback.__module__==module_name,
        'native_observer_entrypoint_identity')
    symbol=module_name+'.'+callback.__name__
    contract=registry['reports'].entrypoint_contract(symbol)
    module=sys.modules[module_name]
    require(vars(module).get(callback.__name__)is callback and callback.__globals__ is vars(module)
        and callback.__code__.co_filename==vars(module)['__file__'],
        'native_observer_entrypoint_identity')
    row=registry['profile']['native_files'][module_name.replace('.','/')+'.py']
    return dict(contract=contract,source_ref=dict(path=row['path'],sha256=row['sha256']),
        binding='EXACT_PINNED_PUBLIC_FUNCTION_PASSED_AND_CALLED_BY_ORDINARY_ADAPTER')


def preflight_report_writer(project,profile,workspace):
    """Source-admitted ordinary-loader fixture; no native validator or D/E runs.

    The nominal report is deliberately constructed as a labelled FAIL fixture.
    It proves passive type projection/storage/readback and earns no progress.
    """
    project,workspace=Path(project),Path(workspace)
    require(workspace.is_absolute() and workspace.is_relative_to(project)
        and workspace.is_dir() and not workspace.is_symlink(),
        'native_observer_preflight_workspace')
    registry=prepare_registry(project,profile)
    budget=registry['reports'].SharedObservationBudget()
    def unavailable(_component,_code,**_diagnostic):
        raise ValueError('native_observer_preflight_output_failed')
    projector=registry['consumers'].ProducedConsumers(workspace,registry['type_inventory'],
        registry['candidate_pins'],(),shared_budget=budget,availability=unavailable)
    preflight_entrypoint=sys.modules['hedgehog.kernel.continuous_delta_runtime_v01'].run_continuous_delta_runtime_v01
    binding=admitted_entrypoint(registry,preflight_entrypoint)
    reports=registry['reports'].ProducedReports(workspace,projector,budget,(),
        entrypoint=binding['contract']['entrypoint'],availability=unavailable)
    report_type=projector.types['hedgehog.kernel.fractal_runtime_v02.FractalRuntimeValidationReportV02']
    report=report_type(validation_report_id='fixture:p28:typed_failure',
        validation_target='P28_PASSIVE_STORAGE_PREFLIGHT',validated_object_id=None,
        status='FAIL',failure_stage='P28_FIXTURE',reason_codes=('FIXTURE_NOT_NATIVE_RESULT',),
        source_reason_codes=(),return_to_root_required=True,root_review_required=True,
        authority_created=False,permission_created=False,action_commit_packet_created=False,
        final_output_created=False,drs_write_created=False,real_world_effects_count=0)
    projector.nominal(report,'hedgehog.kernel.fractal_runtime_v02.FractalRuntimeValidationReportV02')
    record=dict(schema='radik.p28.report_writer_preflight.v01',
        status='FIXTURE_TYPED_FAILURE_REPORT_NOT_ACTUAL_NATIVE_REPORT',
        material=projector.project(report),native_validation_performed=False,
        useful_checkpoint=False,native_acceptance_inferred=False)
    raw=canonical(record)
    reference=reports.storage.persist('d_cell_proposal_report_child.json',raw)
    bound=dict(path=str((workspace/reference['path']).relative_to(project)),
        sha256=reference['sha256'],size_bytes=reference['size_bytes'])
    require(read_raw(project,bound['path'])==raw and report.status!='PASS',
        'native_observer_preflight_readback')
    return put(project,workspace,'preflight_result.json',dict(
        schema='radik.p28.native_report_writer_preflight_result.v01',status='PASS',
        modules=registry['module_observations'],helper_pins=registry['helper_pins'],
        report_ref=bound,nominal_report_type=report_type.__module__+'.'+report_type.__name__,
        report_status=report.status,checkpoint_emissions=0,native_validator_calls=0,
        native_D_E_Work_calls=0,AUTH_provider_SAVE_calls=0))


class ReportObserver:
    def __init__(self,controller,event_sink,workspace,*,profile,e_call_id,native_entrypoint,input_refs=()):
        self.controller=controller
        self.project=Path(controller.client.project)
        self.workspace=Path(workspace)
        require(self.workspace.is_absolute() and self.workspace.is_relative_to(self.project)
            and self.workspace.is_dir() and not self.workspace.is_symlink(),
            'native_observer_workspace')
        info=self.workspace.lstat()
        require(info.st_uid==os.geteuid() and not stat.S_IMODE(info.st_mode)&0o022,
            'native_observer_workspace_mode')
        self.event_sink=event_sink
        require(callable(event_sink),'native_observer_event_sink')
        self.e_call_id=safe_token(e_call_id)
        self.main_ident=threading.get_ident()
        self.semantic_stack=[]
        self.secondary_codes=[]
        self.primary_failure=None
        self.closed=False
        self.native_status=None
        self.active_kind='UNKNOWN';self.active_stage='OBSERVER_PREPARE'
        self.diagnostic_ref=None;self.observer_inventory_ref=None
        self.registry=None;self.registry_ref=None;self.entrypoint_binding=None
        self.consumers=None;self.reports=None;self.budget=None;self.completed_report_refs=[]
        try:
            self.registry=prepare_registry(self.project,profile)
            self.entrypoint_binding=admitted_entrypoint(self.registry,native_entrypoint)
            self.registry_ref=put(self.project,self.workspace,'nominal_registry.json',dict(
                schema='radik.p28.native_observer_registry.v01',
                modules=self.registry['module_observations'],helper_pins=self.registry['helper_pins'],
                entrypoint_binding=self.entrypoint_binding,native_execution=False,native_authority_restored=False))
            refs=[]
            for ref in input_refs:
                require(type(ref) is dict and set(ref)=={'path','sha256','size_bytes'},
                    'native_observer_prerequisite_ref')
                raw=read_raw(self.project,ref['path'])
                require(len(raw)==ref['size_bytes'] and hashlib.sha256(raw).hexdigest()==ref['sha256'],
                    'native_observer_prerequisite_readback')
                refs.append(dict(ref))
            budget=self.registry['reports'].SharedObservationBudget()
            self.budget=budget
            self.consumers=self.registry['consumers'].ProducedConsumers(self.workspace,
                self.registry['type_inventory'],self.registry['candidate_pins'],refs,
                shared_budget=budget,availability=self.availability)
            self.reports=self.registry['reports'].ProducedReports(self.workspace,self.consumers,
                budget,refs,entrypoint=self.entrypoint_binding['contract']['entrypoint'],
                availability=self.availability)
    
        except RequiredNativeWitnessLoss:raise
        except BaseException as error:
            self.availability('OBSERVER_INITIALIZATION','REQUIRED_OUTPUT_INITIALIZATION_FAILED',
                diagnostic=dict(report_kind='UNKNOWN',stage='OBSERVER_INITIALIZATION',
                    error_class=type(error).__name__))

    def main_only(self):
        if threading.get_ident()!=self.main_ident:
            self.availability('REPORT_BODY','FOREIGN_THREAD_REFUSED')

    def observer_put(self,name,value):
        require(name in ('required_witness_failure.json','observer_inventory.json'),
            'native_observer_inventory_name')
        capacity=262144
        raw=canonical(value)
        require(len(raw)<=capacity,'native_observer_inventory_bound')
        ticket=None if self.budget is None else self.budget.reserve('observer',name,len(raw))
        ref=put(self.project,self.workspace,name,value,cap=capacity)
        if ticket is not None:
            self.budget.observed_write(ticket,len(raw));self.budget.acknowledge(ticket)
        return ref

    def report_snapshot(self):
        return dict(status='NOT_INITIALIZED')if self.reports is None else self.reports.diagnostic_snapshot()

    def budget_snapshot(self):
        return dict(status='NOT_INITIALIZED')if self.budget is None else self.budget.snapshot()

    def snapshot(self,*,body_failed):
        return dict(schema='radik.p30.native_report_observer_inventory.v02',
            status='PARTIAL_BODY_FAILED'if body_failed else'REPORTS_READ_BACK_NOT_SEMANTIC_ACCEPTANCE'
                if self.native_status=='PASS'else'RETURNED_NONPASS_REPORT',
            registry_ref=self.registry_ref,entrypoint_binding=self.entrypoint_binding,body_failed=body_failed,
            native_overall_report_status=self.native_status,consumer_refs=[]if self.consumers is None else list(self.consumers.files),
            passive_attempted_kinds=[]if self.consumers is None else sorted(self.consumers.attempted),
            report_state=self.report_snapshot(),
            consumer_inventory_ref=getattr(self,'consumer_inventory_ref',None),
            report_inventory_ref=getattr(self,'report_inventory_ref',None if self.reports is None else self.reports.inventory_ref),
            completed_report_refs=self.completed_report_refs,primary_witness_failure=self.primary_failure,
            required_witness_diagnostic_ref=self.diagnostic_ref,secondary_codes=list(self.secondary_codes),
            semantic_stack_at_close=[row[0]for row in self.semantic_stack],
            shared_budget_snapshot=self.budget_snapshot(),
            budget_snapshot_scope='BEFORE_THIS_OBSERVER_INVENTORY_ATTEMPT',
            no_replay=True,native_acceptance_inferred=False,native_authority_restored=False)

    def publish_inventory(self,*,body_failed):
        if self.observer_inventory_ref is None:
            self.active_kind='OBSERVER_INVENTORY';self.active_stage='OBSERVER_INVENTORY_CLOSURE'
            self.observer_inventory_ref=self.observer_put('observer_inventory.json',self.snapshot(body_failed=body_failed))
        return self.observer_inventory_ref

    def availability(self,component,code,*,diagnostic=None):
        failure=dict(phase='REQUIRED_WITNESS_AVAILABILITY',
            error_class='RequiredNativeWitnessLoss',code=safe_token(code))
        if self.primary_failure is None:
            self.primary_failure=failure
            detail={}if diagnostic is None else dict(diagnostic)
            kind=detail.get('report_kind',self.active_kind)
            stage=detail.get('stage',self.active_stage)
            error_class=detail.get('error_class','UNRECORDED_BY_LEGACY_CONSUMER')
            metadata=dict(component=safe_token(component),e_call_id=self.e_call_id,
                report_kind=safe_token(kind),stage=safe_token(stage),primary_code=failure['code'],
                primary_error_class=safe_token(error_class))
            record=dict(schema='radik.p30.required_witness_diagnostic.v01',**metadata,
                primary_failure=failure,entrypoint_binding=self.entrypoint_binding,
                passive_attempted_kinds=[]if self.consumers is None else sorted(self.consumers.attempted),
                passive_failure_records=[]if self.consumers is None else list(self.consumers.failures),
                legacy_passive_original_exception='NOT_RECORDED_BY_LEGACY_CONSUMER',
                report_state=self.report_snapshot(),
                consumer_refs=[]if self.consumers is None else list(self.consumers.files),completed_report_refs=list(self.completed_report_refs),
                shared_budget_snapshot=self.budget_snapshot(),
                budget_snapshot_scope='BEFORE_THIS_DIAGNOSTIC_ATTEMPT',
                exception_text_locals_or_live_values_retained=False,native_acceptance_inferred=False)
            try:
                self.diagnostic_ref=self.observer_put('required_witness_failure.json',record)
                metadata['diagnostic_ref']=dict(self.diagnostic_ref)
            except BaseException:
                self.secondary('REQUIRED_DIAGNOSTIC_PERSIST_FAILED')
            try:self.publish_inventory(body_failed=True)
            except BaseException:self.secondary('REQUIRED_PARTIAL_INVENTORY_PERSIST_FAILED')
            try:self.event_sink('REQUIRED_WITNESS_UNAVAILABLE','E',failure=failure,**metadata)
            except BaseException:os._exit(EMERGENCY_IO_EXIT)
        raise RequiredNativeWitnessLoss(self.primary_failure['code'])

    def secondary(self,code):
        if code not in self.secondary_codes and len(self.secondary_codes)<32:
            self.secondary_codes.append(safe_token(code))

    def enter(self,label,value):
        self.main_only()
        return time.monotonic_ns()

    def exit(self,ticket,raised):
        self.main_only()
        return None

    def semantic_enter(self,stage):
        self.main_only()
        require(len(self.semantic_stack)<32,'native_observer_semantic_depth')
        ticket=(safe_token(stage),time.monotonic_ns())
        self.semantic_stack.append(ticket)
        return ticket

    def semantic_exit(self,ticket,raised):
        self.main_only()
        require(self.semantic_stack and self.semantic_stack[-1] is ticket,
            'native_observer_semantic_stack')
        self.semantic_stack.pop()

    def progress(self,kind,factory):
        # Producer pulses/queue changes are liveness. Do not evaluate or retain
        # their live factories and never turn them into semantic readbacks.
        self.main_only()

    def produced(self,kind,factory):
        self.main_only()
        self.active_kind=kind;self.active_stage='PASSIVE_FACTORY'
        try:value=factory()
        except BaseException as error:
            self.availability('PASSIVE_BODY','PASSIVE_FACTORY_FAILED',diagnostic=dict(
                report_kind=kind,stage='PASSIVE_FACTORY',error_class=type(error).__name__))
        self.active_stage='PASSIVE_CONSUME'
        if self.registry['consumers'].consume_produced_v01(self.consumers,kind,lambda:value) is None:
            self.availability('PASSIVE_BODY','REQUIRED_OUTPUT_MISSING')

    def is_useful(self,kind,value):
        # P18 shape() has already asserted the exact loaded nominal report type.
        field=PASS_FIELDS.get(kind)
        if field is not None:
            return value[field].status=='PASS'
        if kind=='D_COMPLETE_RESULTS_REPORTS':
            return bool(value['reports']) and all(row.status=='PASS' for row in value['reports'])
        # E_PAIR2_CORE is Root material, and E_BINDING_VALIDATION is an append
        # journal prefix; neither supplies a stable useful report checkpoint.
        return False

    def native_return(self,report):
        """Observe the same overall returned report; no validator is invoked here."""
        self.main_only()
        require(self.native_status is None,'native_observer_duplicate_overall_report')
        self.consumers.nominal(report,
            'hedgehog.kernel.continuous_delta_runtime_v01.ContinuousDeltaValidationReportV01')
        self.native_status=safe_token(report.status)

    def reported(self,kind,factory):
        self.main_only()
        self.active_kind=kind;self.active_stage='REPORT_FACTORY'
        try:
            value=factory()
            self.active_stage='REPORT_SHAPE';self.reports.shape(kind,value)
            self.active_stage='REPORT_STATUS';useful=self.is_useful(kind,value)
            self.active_stage='REPORT_CONSUME'
            ref=self.registry['reports'].consume_report_v01(self.reports,kind,lambda:value)
            value=None
            if ref is None:
                self.availability('REPORT_BODY','REQUIRED_OUTPUT_MISSING')
            if useful:
                name=str((self.workspace/ref['path']).relative_to(self.project))
                raw=read_raw(self.project,name)
                require(len(raw)==ref['size_bytes'] and hashlib.sha256(raw).hexdigest()==ref['sha256'],
                    'native_observer_completed_report_readback')
                bound=dict(path=name,sha256=ref['sha256'],size_bytes=ref['size_bytes'])
                self.completed_report_refs.append(bound)
                try:
                    self.event_sink('REPORT_READBACK_ACK','E',useful=True,
                        e_call_id=self.e_call_id,report_kind=kind,readback_ref=bound,
                        native_acceptance_inferred=False)
                except BaseException:
                    os._exit(EMERGENCY_IO_EXIT)
        except RequiredNativeWitnessLoss:
            raise
        except BaseException as error:
            code=(error.args[0]if type(error)is ValueError and len(error.args)==1 and
                type(error.args[0])is str and error.args[0]in self.registry['reports'].CODES else
                'REPORT_FACTORY_FAILED'if self.active_stage=='REPORT_FACTORY'else'REQUIRED_OUTPUT_REPORT_FAILED')
            self.availability('REPORT_BODY',code,diagnostic=dict(report_kind=kind,
                stage=self.active_stage,error_class=type(error).__name__))

    def finish(self,*,body_failed):
        if self.closed:
            return
        self.closed=True
        self.active_kind='OVERALL_NATIVE_REPORT';self.active_stage='NATIVE_RETURN_REQUIRED'
        if not body_failed:
            require(self.native_status is not None,'native_observer_overall_report_missing')
        complete=not body_failed and self.native_status=='PASS'
        if complete:
            self.active_kind='PASSIVE_INVENTORY';self.active_stage='PASSIVE_INVENTORY_CLOSURE'
            self.consumer_inventory_ref=self.consumers.finish()
            self.active_kind='REPORT_INVENTORY';self.active_stage='REPORT_INVENTORY_CLOSURE'
            self.report_inventory_ref=self.reports.finish()
        # An interrupted body naturally lacks later reports. Preserve its exact
        # primary by publishing a partial inventory without imposing success's
        # required-kind completeness predicate or repeating any uncertain write.
        return self.publish_inventory(body_failed=body_failed)


@contextmanager
def observe_e(controller,event_sink,workspace,*,native_entrypoint,profile=None,e_call_id=None,input_refs=()):
    """Attach only around the same actual public E; reset its ContextVar on exit."""
    if profile is None:
        profile=getattr(controller,'_ordinary_profile_manifest',None)
    require(type(profile) is dict,'native_observer_admitted_profile_required')
    if e_call_id is None:
        e_call_id=getattr(controller,'_owner_e_call_id',None)
    observer=ReportObserver(controller,event_sink,workspace,profile=profile,
        e_call_id=e_call_id,native_entrypoint=native_entrypoint,input_refs=input_refs)
    diagnostics=observer.registry['diagnostics']
    token=diagnostics.activate_diagnostic_telemetry_v01(observer)
    failed=False
    try:
        yield observer
    except BaseException:
        failed=True
        raise
    finally:
        if failed:
            observer.active_kind='TELEMETRY';observer.active_stage='TELEMETRY_RESET_DURING_UNWIND'
            try:diagnostics.reset_diagnostic_telemetry_v01(token)
            except BaseException:observer.secondary('TELEMETRY_RESET_DURING_UNWIND_FAILED')
            try:observer.finish(body_failed=True)
            except BaseException:observer.secondary('PARTIAL_OBSERVER_INVENTORY_DURING_UNWIND_FAILED')
        else:
            observer.active_kind='TELEMETRY';observer.active_stage='TELEMETRY_RESET'
            try:diagnostics.reset_diagnostic_telemetry_v01(token)
            except BaseException as error:
                observer.availability('TELEMETRY','REQUIRED_COLLECTOR_RESET_FAILED',diagnostic=dict(
                    report_kind='TELEMETRY',stage='TELEMETRY_RESET',error_class=type(error).__name__))
            try:observer.finish(body_failed=False)
            except RequiredNativeWitnessLoss:raise
            except BaseException as error:
                observer.availability('REPORT_INVENTORY','REQUIRED_OUTPUT_INVENTORY_FAILED',diagnostic=dict(
                    report_kind=observer.active_kind,stage=observer.active_stage,error_class=type(error).__name__))
