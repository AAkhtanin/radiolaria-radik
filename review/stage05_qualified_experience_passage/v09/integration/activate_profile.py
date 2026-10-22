"""Finite preserving installed-v05-to-v07 SOURCE upgrade; no application or native imports.

The ordinary launcher pins this support module before calling activate. This
module independently pins the raw gate and entire candidate closure before
loading that gate. No recovery path rolls back a compatible history reader.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types


REAL_PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
PREFIX = 'review/stage05_qualified_experience_passage/v09/integration'
MANIFEST = PREFIX + '/ordinary_profile_manifest.json'
SELF = PREFIX + '/activate_profile.py'
JOURNAL = 'state/application_profile_install.json'
PENDING = JOURNAL + '.pending'
FINISH_PENDING = JOURNAL + '.finish.pending'
ACTIVATION = 'state/application_profile.json'
MAX_FILE_BYTES = 64 * 1024 * 1024
READER_FIRST = ('config/application_profile_gate.py', 'app/stage05_disposition.py', 'app/normal_profile.py',
    'app/normal_session.py', 'app/console_continuation.py', 'app/task_budget.py',
    'app/task_store.py', 'app/budget.py')
_GATE_MODULE = '_radik_stage05_activation_raw_gate'
OWNER_LOCK = 'review/direct_plan_passage/owner_start.lock'


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
        allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def path(project, relative):
    require(type(relative) is str and relative and not relative.startswith('/')
        and '\\' not in relative and all(p not in ('', '.', '..') for p in relative.split('/')),
        'profile_install_owned_path')
    root = Path(project)
    require(root.is_absolute() and root.resolve(strict=True) == root and not root.is_symlink(),
        'profile_install_owned_root')
    target = root
    for part in relative.split('/'):
        target = target / part
        require(not target.is_symlink(), 'profile_install_symlink')
    require(target.resolve().is_relative_to(root), 'profile_install_owned_path')
    return target


def read(project, relative, cap=MAX_FILE_BYTES):
    target = path(project, relative)
    before = target.stat()
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mode,
        info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap
        and identity(before) == identity(opened) == identity(after) and len(raw) == before.st_size,
        'profile_install_regular_bound')
    return raw


def reference(project, ref):
    require(type(ref) is dict and {'path', 'sha256'} <= set(ref) <= {'path', 'sha256', 'size_bytes'},
        'profile_install_reference')
    raw = read(project, ref['path'])
    require(sha(raw) == ref['sha256'] and ('size_bytes' not in ref or len(raw) == ref['size_bytes']),
        'profile_install_reference_changed')
    return json.loads(raw)


def sync_parent(target):
    fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def exclusive(project, relative, raw):
    target = path(project, relative)
    require(target.parent.is_dir(), 'profile_install_parent_required')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync_parent(target)
    require(read(project, relative) == raw, 'profile_install_write_readback')


def replace(project, relative, raw, *, suffix='.profile_install_pending'):
    pending = relative + suffix
    exclusive(project, pending, raw)
    os.replace(path(project, pending), path(project, relative))
    sync_parent(path(project, relative))
    require(read(project, relative) == raw, 'profile_install_replace_readback')


def raw_candidate(project):
    """Check reviewed source bytes before executing the raw profile gate."""
    raw = read(project, MANIFEST, 4 * 1024 * 1024)
    manifest = json.loads(raw)
    require(type(manifest) is dict and manifest.get('schema') == 'radik.application_profile.v02',
        'profile_install_manifest_shape')
    pins = manifest.get('pins')
    install = manifest.get('install_files')
    before = manifest.get('before_install_pins')
    require(type(pins) is dict and 1 <= len(pins) <= 256 and type(install) is dict
        and install and set(install) <= set(pins) and type(before) is dict and set(before) == set(install),
        'profile_install_finite_inventory')
    review = reference(project, manifest['source_review_ref'])
    require(review.get('reviewer') == '/root/private_remote_controls'
        and review.get('status') == 'SOURCE_ACCEPTED_FOR_ISOLATED_ORDINARY_REHEARSAL'
        and review.get('source_only_rehearsal_authorized') is True
        and review.get('code_pins') == pins and review.get('pins') == pins,
        'profile_install_source_review')
    require(SELF in pins and sha(read(project, SELF)) == pins[SELF]
        and Path(__file__).resolve(strict=True) == path(project, SELF),
        'profile_install_executed_source_identity')
    payloads = {}
    for logical, ref in install.items():
        require(logical.startswith(('app/', 'config/', 'review/transport/'))
            and not logical.endswith(('.pending', '.profile_install_pending'))
            and type(ref) is dict and set(ref) == {'path', 'sha256'}
            and ref['path'].startswith(PREFIX + '/after/')
            and ref['sha256'] == pins[logical], 'profile_install_target_inventory')
        path(project, logical)
        candidate = read(project, ref['path'])
        require(sha(candidate) == ref['sha256'], 'profile_install_candidate_changed')
        payloads[logical] = candidate
        require(before[logical] is None or type(before[logical]) is str and len(before[logical]) == 64
            and all(c in '0123456789abcdef' for c in before[logical]), 'profile_install_preimage_pin')
    require('config/application_profile_gate.py' in payloads and 'config/launch.py' in payloads,
        'profile_install_entry_and_reader_required')
    for logical, pin in pins.items():
        if logical not in payloads:
            require(sha(read(project, logical)) == pin, 'profile_install_support_source_changed')
    return manifest, dict(path=MANIFEST, sha256=sha(raw)), payloads


def load_raw_gate(project, payloads):
    require(_GATE_MODULE not in sys.modules, 'profile_install_gate_already_loaded')
    module = types.ModuleType(_GATE_MODULE)
    module.__file__ = str(path(project, PREFIX + '/after/config/application_profile_gate.py'))
    # Dataclasses resolve their declared module through sys.modules. This exact
    # admitted module is never installed as config or substituted into a console.
    sys.modules[_GATE_MODULE] = module
    try:
        exec(compile(payloads['config/application_profile_gate.py'], module.__file__, 'exec'), module.__dict__)
    except BaseException:
        sys.modules.pop(_GATE_MODULE, None)
        raise
    return module


PRESERVED_STATE = ('state/console_model_turns.json','state/task_model_settings.json',
    'state/normal_grant_index.json','workspace/owner_documents/state/dynamic_tasks.json',
    'workspace/owner_documents/state/dynamic_source_successors.json')


def unchanged_state(project, predecessor):
    """Capture only exact mutable state paths; installation never writes them."""
    names=PRESERVED_STATE+tuple(ref['path'] for ref in predecessor['consumed_reservation_refs'])
    result={}
    for relative in names:
        target=path(project,relative)
        result[relative]=read(project,relative) if target.exists() else None
    return result


def check_unchanged_state(project, observed):
    for relative,raw in observed.items():
        target=path(project,relative)
        require((not target.exists()) if raw is None else target.exists()
            and read(project,relative)==raw,'profile_install_preserved_state_changed')


def _completed(manifest, manifest_ref, payloads, mode, upgrade_ref, predecessor):
    state=predecessor['predecessor_state']
    activation=dict(schema='radik.application_profile_activation.v01',profile_ref=manifest_ref)
    return dict(schema='radik.p28.profile_install.v01',status='COMPLETED',mode=mode,
        manifest_ref=manifest_ref,installed_pins={key:manifest['pins'][key] for key in payloads},
        activation=activation,compatible_reader_installed_before_activation=True,
        preserving_upgrade_ref=upgrade_ref,predecessor_manifest_ref=predecessor['predecessor_manifest_ref'],
        predecessor_install_ref=state['install']['snapshot_ref'],
        predecessor_activation_ref=state['activation']['snapshot_ref'])


def _predecessor(project, gate, selected, manifest, payloads):
    """Check the intact installed predecessor before creating any pending fence."""
    upgrade_ref,predecessor=gate.preserving_upgrade(project,selected)
    old_selected=gate.load_profile(project,predecessor['predecessor_manifest_ref'])
    old=old_selected['manifest']
    require(old['pins']==predecessor['predecessor_code_pins'] and len(old['pins'])==181,
        'profile_install_predecessor_pin_inventory')
    require(set(old['install_files']) <= set(payloads)
        and all(manifest['before_install_pins'][name]==old['pins'].get(name) for name in payloads),
        'profile_install_predecessor_target_inventory')
    state=predecessor['predecessor_state']
    for label,relative in (('activation',ACTIVATION),('install',JOURNAL),('ledger','state/console_model_turns.json'),
            ('tasks','workspace/owner_documents/state/dynamic_tasks.json')):
        row=state[label]
        snapshot=read(project,row['snapshot_ref']['path'])
        require(sha(snapshot)==row['snapshot_ref']['sha256'] and len(snapshot)==row['snapshot_ref']['size_bytes'],
            'profile_install_predecessor_snapshot_changed')
        actual=read(project,relative)
        require(actual==snapshot,'profile_install_predecessor_state_changed')
    old_ref=dict(path=predecessor['predecessor_manifest_ref']['path'],sha256=predecessor['predecessor_manifest_ref']['sha256'])
    require(json.loads(read(project,ACTIVATION,4096))==dict(
        schema='radik.application_profile_activation.v01',profile_ref=old_ref),
        'profile_install_predecessor_activation')
    old_journal=json.loads(read(project,state['install']['snapshot_ref']['path'],4*1024*1024))
    require(set(old_journal)=={'schema','status','mode','manifest_ref','installed_pins','activation',
        'compatible_reader_installed_before_activation','preserving_upgrade_ref',
        'predecessor_manifest_ref','predecessor_install_ref','predecessor_activation_ref'}
        and old_journal['schema']=='radik.p28.profile_install.v01'
        and old_journal['status']=='COMPLETED' and old_journal['mode']=='PRODUCTION_OWNER'
        and old_journal['manifest_ref']==old_ref
        and old_journal['installed_pins']=={key:old['pins'][key] for key in old['install_files']}
        and old_journal['activation']==dict(schema='radik.application_profile_activation.v01',profile_ref=old_ref)
        and old_journal['compatible_reader_installed_before_activation']is True,
        'profile_install_predecessor_journal')
    # These exact historical references remain evidence, never current admission.
    for key in ('preserving_upgrade_ref','predecessor_manifest_ref','predecessor_install_ref',
            'predecessor_activation_ref'):
        reference(project,old_journal[key])
    for logical,pin in old['pins'].items():
        require(sha(read(project,logical))==pin,'profile_install_predecessor_source_changed')
    require(not path(project,'state/normal_session_active.json').exists(),
        'profile_install_active_operation_refused')
    ledger=json.loads(read(project,'state/console_model_turns.json',4*1024*1024))
    require(ledger.get('version')=='radik.console_turn_ledger.v05'
        and ledger.get('active_attempt_id')==predecessor['expected_active_attempt_id']
        =='radik-call:3d5197d2edd747e8b4ec5dd56afcb16a' and type(ledger.get('attempts'))is list
        and len(ledger['attempts'])==predecessor['expected_console_attempts'] and predecessor['expected_console_attempts']==53,'profile_install_predecessor_ledger_occupancy')
    for consumed in predecessor['consumed_reservation_refs']:
        reservation=reference(project,consumed)
        require(reservation.get('one_use')is True and reservation.get('automatic_retry')is False,
            'profile_install_predecessor_reservation')
    # Exact predecessor snapshots bind all existing rows. Historical operation
    # receipts are evidence, not credentials restored by this upgrade.
    tasks=json.loads(read(project,'workspace/owner_documents/state/dynamic_tasks.json'))
    require(tasks.get('active_task_id') is None, 'profile_install_predecessor_active_task')
    return upgrade_ref,predecessor


def _activate_locked(project, *, rehearsal_context=None):
    """One future owner upgrade, or the exact reviewed independently sealed copy."""
    project=Path(project)
    manifest,manifest_ref,payloads=raw_candidate(project)
    require(not path(project,PENDING).exists() and not path(project,FINISH_PENDING).exists()
        and not path(project,ACTIVATION+'.pending').exists(),'profile_install_partial_state')
    gate=load_raw_gate(project,payloads)
    try:
        selected=gate.load_profile(project,manifest_ref)
        if rehearsal_context is None:
            gate.owner_eligibility(project,selected)
            mode='PRODUCTION_OWNER'
        else:
            canonical_gate=sys.modules.get(type(rehearsal_context).__module__)
            require(canonical_gate is not None and type(rehearsal_context)is canonical_gate.RehearsalContext
                and sha(read(project,str(Path(canonical_gate.__file__).resolve(strict=True).relative_to(project))))
                    ==manifest['pins']['config/application_profile_gate.py'],
                'profile_install_typed_rehearsal_context')
            canonical_gate.validate_rehearsal_context(project,rehearsal_context)
            raw_context=gate.rehearsal_context(project,rehearsal_context.seal_sha256)
            gate.validate_rehearsal_context(project,raw_context)
            require(project!=REAL_PROJECT and raw_context.application_root==project
                and raw_context.environment_root==REAL_PROJECT,'profile_install_rehearsal_production_refused')
            seal=json.loads(gate._read(project,gate.REHEARSAL_SEAL))
            require(seal['code_pins']==manifest['pins'],'profile_install_rehearsal_source_changed')
            mode='SOURCE_ONLY_REHEARSAL'
        upgrade_ref,predecessor=gate.preserving_upgrade(project,selected)
        completed=_completed(manifest,manifest_ref,payloads,mode,upgrade_ref,predecessor)
        installed=path(project,JOURNAL)
        require(installed.exists(),'profile_install_predecessor_journal_required')
        if json.loads(read(project,JOURNAL,4*1024*1024))==completed:
            require(json.loads(read(project,ACTIVATION,4096))==completed['activation'],
                'profile_install_completed_activation_mismatch')
            for logical,pin in manifest['pins'].items():
                require(sha(read(project,logical))==pin,'profile_install_completed_source_changed')
            return dict(status='ALREADY_INSTALLED_VERIFIED',manifest_ref=manifest_ref,
                activation=completed['activation'],mode=mode,preserving_upgrade_ref=upgrade_ref)
        upgrade_ref,predecessor=_predecessor(project,gate,selected,manifest,payloads)
        observed=unchanged_state(project,predecessor)
        historical=reference(project,manifest['historical_source_inventory_ref'])
        preserved={ref['sha256'] for ref in historical['files'].values()}
        require(all(old_pin is None or old_pin in preserved
            for old_pin in manifest['before_install_pins'].values()),
            'profile_install_missing_immutable_preimage')
        for logical,old_pin in manifest['before_install_pins'].items():
            require((not path(project,logical).exists()) if old_pin is None else
                path(project,logical).exists() and sha(read(project,logical))==old_pin,
                'profile_install_preimage_changed')
            require(not path(project,logical+'.profile_install_pending').exists(),
                'profile_install_partial_target')
        readers=[logical for logical in READER_FIRST if logical in payloads]
        rest=sorted(logical for logical in payloads if logical not in readers and logical!='config/launch.py')
        order=readers+rest+['config/launch.py']
        require(len(order)==len(payloads) and len(set(order))==len(order),'profile_install_order')
        exclusive(project,PENDING,canonical(dict(schema='radik.p28.profile_install.v01',
            status='INSTALLING_NO_RUNTIME_ADMISSION',mode=mode,manifest_ref=manifest_ref,
            preserving_upgrade_ref=upgrade_ref,predecessor_manifest_ref=predecessor['predecessor_manifest_ref'],
            order=order,automatic_retry=False,rollback_allowed=False)))
        for logical in order:
            replace(project,logical,payloads[logical])
        for logical,pin in manifest['pins'].items():
            require(sha(read(project,logical))==pin,'profile_install_final_source_changed')
        check_unchanged_state(project,observed)
        # The fence blocks both readers until activation and the successor journal
        # read back. A failure retains its fence and never rolls back or retries.
        activation_path=path(project,ACTIVATION)
        exclusive(project,ACTIVATION+'.pending',canonical(completed['activation']))
        os.replace(path(project,ACTIVATION+'.pending'),activation_path)
        sync_parent(activation_path)
        require(json.loads(read(project,ACTIVATION,4096))==completed['activation'],
            'profile_install_activation_readback')
        exclusive(project,FINISH_PENDING,canonical(completed))
        os.replace(path(project,FINISH_PENDING),installed)
        sync_parent(installed)
        require(json.loads(read(project,JOURNAL,4*1024*1024))==completed,
            'profile_install_completed_readback')
        check_unchanged_state(project,observed)
        os.unlink(path(project,PENDING))
        sync_parent(installed)
        return dict(status='UPGRADED_AND_ACTIVATED_VERIFIED',manifest_ref=manifest_ref,
            activation=completed['activation'],mode=mode,preserving_upgrade_ref=upgrade_ref,
            predecessor_manifest_ref=completed['predecessor_manifest_ref'],
            predecessor_install_ref=completed['predecessor_install_ref'],
            predecessor_activation_ref=completed['predecessor_activation_ref'])
    finally:
        sys.modules.pop(_GATE_MODULE,None)


def activate(project, *, rehearsal_context=None, owner_lock_fd=None):
    """Hold the existing owner lock through every installation mutation."""
    project = Path(project)
    lock_path = path(project, OWNER_LOCK)
    owned = owner_lock_fd is None
    descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK) if owned else owner_lock_fd
    try:
        require(type(descriptor) is int and descriptor >= 0, 'profile_install_owner_lock_fd')
        before, opened = lock_path.stat(), os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
            and (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
            'profile_install_owner_lock_identity')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('profile_install_another_owner_active') from None
        return _activate_locked(project, rehearsal_context=rehearsal_context)
    finally:
        if owned:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
