"""Finite profile source selection and separately typed external eligibility.

A SOURCE rehearsal seal can select exact code in one owned copy. It can never
satisfy the owner predicate, create real AUTH, or authorize an external request.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

REAL_PROJECT=Path('/Users/admin/Projects/RadiolariaRadik')
PREFIX='review/stage05_qualified_experience_passage/v09/integration'
PREDECESSOR_MANIFEST='review/stage05_qualified_experience_passage/v05/ordinary_profile_manifest.json'
STAGE05_V02_MANIFEST='review/stage05_qualified_experience_passage/v02/ordinary_profile_manifest.json'
STAGE04_MANIFEST='review/g2e_successor_passage/proposals/g2e_no_effects_v31_stage04_closure/ordinary_profile_manifest.json'
PREDECESSOR_MANIFEST_SHA256='61937b185e160be1b38e8c35b024951d2ddbd75ed33ebaf96a64beb4835db6ca'
HISTORICAL_MANIFESTS={
    STAGE04_MANIFEST:'99fadcd8e2949d63aad1f2796111546447979b19e123e880e3432e5d03ea03dc',
    'review/g2e_successor_passage/proposals/g2e_no_effects_v30_witness_repair/ordinary_profile_manifest.json':
        '9c2fa1df2d581b4d542dd1aaa9fb65cdcc047dff2a35d14ba92ec39db4cf7c8a',
    'review/g2e_successor_passage/proposals/g2e_no_effects_v29_g2c_domain_repair/ordinary_profile_manifest.json':
        '7108b29baed71d0d3b25c5877ae3e7f9b56f8f43a68c82bfde27cb757a43d58d',
    'review/g2e_successor_passage/proposals/g2e_no_effects_v28_ordinary_entry_owner_scenario/ordinary_profile_manifest.json':
        '81afd01ed6c87a4639e2b34c8f70c56a0895982c467c270916ce9a956e8e289e',
    STAGE05_V02_MANIFEST:'783d8a626468ea7369ba63b7530639197856b643f77c0dde3014603c584dee7e',
    PREDECESSOR_MANIFEST:PREDECESSOR_MANIFEST_SHA256}
UPGRADE=PREFIX+'/predecessor_install_state.json'
MANIFEST=PREFIX+'/ordinary_profile_manifest.json'
OWNER_ADMISSION=PREFIX+'/owner_admission.json'
REHEARSAL_SEAL=PREFIX+'/rehearsal_seal.json'
REHEARSAL_BINDING='state/ordinary_rehearsal_context.json'
ACTIVATION='state/application_profile.json'
PROFILE='stage04_dynamic_informational_delta_v28'
_REHEARSAL_KEY=object()


def require(value,code):
    if not value:raise ValueError(code)


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _path(project,relative):
    root=Path(project)
    require(root.is_absolute()and root.resolve(strict=True)==root and not root.is_symlink(),'profile_gate_owned_root')
    require(type(relative)is str and relative and not relative.startswith('/')and '\\'not in relative
        and all(p not in ('','.','..')for p in relative.split('/')),'profile_gate_owned_path')
    path=root
    for part in relative.split('/'):
        path=path/part;require(not path.is_symlink(),'profile_gate_symlink')
    require(path.resolve().is_relative_to(root),'profile_gate_owned_path')
    return path


def _read(project,relative,cap=64*1024*1024):
    path=_path(project,relative);before=path.stat()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        opened=os.fstat(stream.fileno());raw=stream.read(cap+1);after=os.fstat(stream.fileno())
    identity=lambda i:(i.st_dev,i.st_ino,i.st_size,i.st_mode,i.st_nlink,i.st_mtime_ns,i.st_ctime_ns)
    require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=cap
        and identity(before)==identity(opened)==identity(after)and len(raw)==before.st_size,'profile_gate_regular_bound')
    return raw


def _reference(project,reference):
    require(type(reference)is dict and {'path','sha256'}<=set(reference)<= {'path','sha256','size_bytes'},'profile_gate_reference')
    raw=_read(project,reference['path']);require(_sha(raw)==reference['sha256']and('size_bytes'not in reference or len(raw)==reference['size_bytes']),'profile_gate_reference_changed')
    return json.loads(raw)


@dataclass(frozen=True)
class RehearsalContext:
    application_root:Path
    environment_root:Path
    seal_sha256:str
    _key:object


def rehearsal_context(project,seal_sha256=None):
    root=Path(project)
    binding=_path(root,REHEARSAL_BINDING)
    if not binding.exists():
        require(seal_sha256 is None,'rehearsal_context_missing')
        return None
    require(root!=REAL_PROJECT and root.is_relative_to(REAL_PROJECT/PREFIX/'rehearsal_actual'),
        'rehearsal_production_or_foreign_root_refused')
    record=json.loads(_read(root,REHEARSAL_BINDING,4096))
    require(type(record)is dict and set(record)=={'schema','seal_sha256'}and record['schema']=='radik.p28.rehearsal_context.v01',
        'rehearsal_context_shape')
    pin=record['seal_sha256'];require(seal_sha256 is None or pin==seal_sha256,'rehearsal_context_invocation_changed')
    raw=_read(root,REHEARSAL_SEAL);require(_sha(raw)==pin,'rehearsal_seal_changed');seal=json.loads(raw)
    require(seal.get('schema')=='radik.p28.isolated_rehearsal_seal.v01'and seal.get('reviewer')=='/root/private_remote_controls'
        and seal.get('owned_copy_root')==str(root)and seal.get('production_root')==str(REAL_PROJECT)
        and seal.get('real_AUTH_provider_native_E_SAVE_allowed')is False and seal.get('production_writes_allowed')is False
        and seal.get('network')=='DENIED','rehearsal_seal_scope')
    source=_reference(root,seal['source_review_ref'])
    require(source.get('reviewer')=='/root/private_remote_controls'and source.get('source_only_rehearsal_authorized')is True
        and source.get('code_pins')==seal.get('code_pins'),'rehearsal_seal_source')
    require(seal.get('environment_root')==str(REAL_PROJECT),'rehearsal_environment_root')
    return RehearsalContext(root,REAL_PROJECT,pin,_REHEARSAL_KEY)


def validate_rehearsal_context(project,context):
    require(type(context)is RehearsalContext and context._key is _REHEARSAL_KEY
        and context.application_root==Path(project),'rehearsal_typed_context_required')
    fresh=rehearsal_context(project,context.seal_sha256)
    require(fresh==context,'rehearsal_context_changed')
    return context


def environment_root(project):
    context=rehearsal_context(project)
    return context.environment_root if context is not None else Path(project)


def load_profile(project,reference):
    require(type(reference)is dict and reference.get('path')in {MANIFEST,*HISTORICAL_MANIFESTS},
        'profile_gate_unregistered_manifest')
    if reference['path']in HISTORICAL_MANIFESTS:
        require(reference.get('sha256')==HISTORICAL_MANIFESTS[reference['path']],'profile_gate_historical_manifest_changed')
    value=_reference(project,reference)
    fields={'schema','profile_id','pins','source_review_ref','source_admission_ref','auth_source_review_ref',
        'native_files','native_origin_inventory_ref','auth_source_identity_sha256','historical_source_inventory_ref',
        'task_state_path','modes','activation_order','install_files','before_install_pins'}
    require(type(value)is dict and set(value)==fields and value['schema']=='radik.application_profile.v02'
        and value['profile_id']==PROFILE and value['task_state_path']=='workspace/owner_documents/state/dynamic_tasks.json'
        and value['modes']==dict(COLD=3,MEMORY_ONLY=0,NATIVE_CONTINUE=0,INFORMATIONAL_DELTA=3)
        and value['activation_order']=='INSTALL_COMPATIBLE_READER_THEN_ACTIVATE_BEFORE_NEW_ROWS','profile_gate_manifest')
    review=_reference(project,value['source_review_ref']);auth=_reference(project,value['auth_source_review_ref'])
    admission=_reference(project,value['source_admission_ref'])
    expected_reviewer=('/root/private_remote_controls' if reference['path'] in (MANIFEST,PREDECESSOR_MANIFEST,STAGE05_V02_MANIFEST) else
        '/root/s04_reviewer' if reference['path']==STAGE04_MANIFEST else '/root/p20_reviewer')
    require(review.get('reviewer')==auth.get('reviewer')==expected_reviewer
        and review.get('status')=='SOURCE_ACCEPTED_FOR_ISOLATED_ORDINARY_REHEARSAL'
        and auth.get('status')=='SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT'
        and review.get('code_pins')==value['pins']and review.get('pins')==value['pins']
        and review.get('source_only_rehearsal_authorized')is True
        and type(auth.get('pins'))is dict and set(auth['pins'])<=set(value['pins'])
        and all(value['pins'][p]==h for p,h in auth['pins'].items())
        and _sha(json.dumps(auth['pins'],sort_keys=True,separators=(',',':')).encode())==value['auth_source_identity_sha256']
        and admission.get('schema')=='radik.p28.profile_source_admission.v01'
        and admission.get('owner_execution_allowed')is False
        and admission.get('source_review_ref')==value['source_review_ref']
        and admission.get('profile_id')==PROFILE,'profile_gate_source_admission')
    pins=value['pins'];required={'config/launch.py','config/application_profile_gate.py','config/native_profile_loader.py',
        'review/transport/radik_owner_start.py','review/transport/direct_plan_gate.py','app/normal_profile.py',
        'app/source_admission.py','app/runtime.py','app/task_budget.py','app/normal_session.py','app/source_successor.py',
        'app/task_store.py','app/budget.py','app/ordinary_rehearsal.py','app/owner_scenario.py'}
    require(type(pins)is dict and required<=set(pins)and len(pins)<=256,'profile_gate_source_closure')
    historical=_reference(project,value['historical_source_inventory_ref'])
    require(historical.get('status')=='VERIFIED_IMMUTABLE_HISTORICAL_SOURCE_INVENTORY'
        and historical.get('reviewer')==expected_reviewer and type(historical.get('files'))is dict,'profile_gate_historical_inventory')
    for ref in historical['files'].values():
        require(_sha(_read(project,ref['path']))==ref['sha256'],'profile_gate_historical_preimage_changed')
    selected=dict(profile_ref=reference,manifest=value,runtime_review=review,auth_review=auth,admission=admission)
    if reference['path']==MANIFEST:preserving_upgrade(project,selected)
    return selected


def preserving_upgrade(project,selected):
    """Read original input identities; this never adopts historical authority."""
    require(selected['profile_ref']['path']==MANIFEST,'profile_gate_upgrade_current_profile')
    reference=selected['runtime_review'].get('preserving_upgrade_ref')
    require(type(reference)is dict and set(reference)=={'path','sha256','size_bytes'}
        and reference['path']==UPGRADE and selected['manifest']['pins'].get(UPGRADE)==reference['sha256'],
        'profile_gate_upgrade_input_reference')
    value=_reference(project,reference)
    require(type(value)is dict and value.get('schema')=='radik.stage05.preserving_stopped_predecessor.v01'
        and value.get('historical_authority_restored')is False
        and value.get('expected_console_attempts')==53
        and value.get('expected_active_attempt_id')=='radik-call:3d5197d2edd747e8b4ec5dd56afcb16a',
        'profile_gate_upgrade_input_shape')
    predecessor=value.get('predecessor_manifest_ref')
    require(type(predecessor)is dict and set(predecessor)=={'path','sha256','size_bytes'}
        and predecessor['path']==PREDECESSOR_MANIFEST
        and predecessor['sha256']==PREDECESSOR_MANIFEST_SHA256,'profile_gate_upgrade_predecessor_reference')
    old=_reference(project,predecessor)
    require(value.get('predecessor_code_pins')==old.get('pins')
        and len(old['pins'])==181 and value.get('predecessor_install_files')==old.get('install_files'),
        'profile_gate_upgrade_predecessor_inventory')
    states=value.get('predecessor_state')
    require(type(states)is dict and set(states)=={'activation','install','ledger','tasks'},
        'profile_gate_upgrade_predecessor_states')
    for label,logical in (('activation',ACTIVATION),('install','state/application_profile_install.json'),
            ('ledger','state/console_model_turns.json'),
            ('tasks','workspace/owner_documents/state/dynamic_tasks.json')):
        row=states[label]
        require(type(row)is dict and set(row)=={'original_ref','original_mode','snapshot_ref'}
            and row['original_ref'].get('path')==logical
            and row['snapshot_ref'].get('path')==PREFIX+'/original_actual/'+logical
            and row['original_ref'].get('sha256')==row['snapshot_ref'].get('sha256')
            and row['original_ref'].get('size_bytes')==row['snapshot_ref'].get('size_bytes'),
            'profile_gate_upgrade_snapshot_binding')
        _reference(project,row['snapshot_ref'])
    return reference,value


def validate_owner_focused_review(project,value):
    """Validate the exact focused producer contract for all production consumers."""
    focused=_reference(project,value['rehearsal_result_review_ref'])
    require(focused.get('reviewer')=='/root/private_remote_controls'and focused.get('status')=='PASS_FOCUSED_STAGE05_QUALIFIED_EXPERIENCE_WIRING'
        and focused.get('all_required_controls_passed')is True and focused.get('owner_execution_authorized')is True
        and focused.get('code_pins')==value['code_pins'],'profile_gate_focused_wiring_admission')
    return focused


def owner_eligibility(project,selected):
    require(Path(project)==REAL_PROJECT and rehearsal_context(project)is None,'rehearsal_external_action_refused')
    value=json.loads(_read(project,OWNER_ADMISSION))
    require(value.get('schema')=='radik.p28.owner_terminal_admission.v01'
        and value.get('status')=='OWNER_EXECUTION_ADMITTED_AFTER_SOURCE_AND_REHEARSAL'
        and value.get('owner_execution_authorized')is True and value.get('independent_reviewer')=='/root/private_remote_controls'
        and value.get('code_pins')==selected['manifest']['pins']
        and value.get('ordinary_profile_manifest_ref',{}).get('path')==MANIFEST
        and value['ordinary_profile_manifest_ref']['sha256']==selected['profile_ref']['sha256']
        and value.get('source_review_ref')==selected['manifest']['source_review_ref'],'profile_gate_owner_admission')
    validate_owner_focused_review(project,value)
    return value


def select(project):
    require(not _path(project,ACTIVATION+'.pending').exists(),'profile_gate_partial_activation')
    require(not _path(project,'state/application_profile_install.json.pending').exists(),'profile_gate_partial_installation')
    if not _path(project,ACTIVATION).exists():return None
    activation=json.loads(_read(project,ACTIVATION,4096))
    require(type(activation)is dict and set(activation)=={'schema','profile_ref'}
        and activation['schema']=='radik.application_profile_activation.v01','profile_gate_activation')
    require(activation['profile_ref'].get('path')==MANIFEST,'profile_gate_current_profile_required')
    selected=load_profile(project,activation['profile_ref'])
    for relative,pin in selected['manifest']['pins'].items():
        require(_sha(_read(project,relative))==pin,'profile_gate_installed_source_changed')
    context=rehearsal_context(project)
    if context is None:owner_eligibility(project,selected)
    else:
        seal=json.loads(_read(project,REHEARSAL_SEAL));require(seal['code_pins']==selected['manifest']['pins'],'rehearsal_profile_source_changed')
    selected['rehearsal_context']=context
    return selected


def require_external_owner(project,action):
    require(action in ('AUTH','HTTP','MODEL','PRODUCTION_ACTIVATION'),'profile_gate_external_action')
    require(rehearsal_context(project)is None,'rehearsal_external_action_refused')
    selected=select(project)
    if selected is not None:return owner_eligibility(project,selected)
    require(Path(project)==REAL_PROJECT,'profile_gate_foreign_runtime_refused')
    return None
