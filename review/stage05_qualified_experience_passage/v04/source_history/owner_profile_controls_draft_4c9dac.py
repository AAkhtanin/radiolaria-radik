"""Finite copied-profile installation and synthetic owner-driver controls.

The candidate gate and installer definitions are AST-selected after exact pins.
No application, native, model, AUTH or network entry is imported or invoked.
Driver witnesses are explicitly synthetic; they prove validation, not execution.
"""
import argparse
import ast
import builtins
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage05_qualified_experience_passage/v04'
SELF = BASE + '/owner_profile_controls.py'
PROPOSAL = BASE + '/owner_profile_controls_proposal.json'
GATE = BASE + '/after/config/application_profile_gate.py'
INSTALLER = BASE + '/activate_profile.py'
OWNER = BASE + '/owner_terminal.py'
ENTRY = BASE + '/after/app/ordinary_entry.py'
WORK = None
COPY_ROOT = None
STARTED = time.monotonic()


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
        allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def relative(name):
    require(type(name) is str and name and name == Path(name).as_posix()
        and not Path(name).is_absolute() and all(part not in ('', '.', '..', 'private', '.git', '.codex')
        and not part.startswith(('.env', '.venv')) for part in name.split('/')), 'profile_control_path')
    return name


def read(path):
    path = Path(path)
    require(path.is_absolute() and path.is_relative_to(PROJECT) and '..' not in path.parts,
        'profile_control_read_scope')
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'profile_control_symlink')
        if parent == PROJECT: break
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 67108864,
            'profile_control_regular')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size, 'profile_control_read_changed')
    return raw


def exact(ref):
    raw = read(PROJECT / relative(ref['path']))
    require(digest(raw) == ref['sha256'] and len(raw) == ref['size_bytes'], 'profile_control_pin')
    return raw


def put(path, raw):
    path = Path(path)
    require(path.is_relative_to(WORK) or path.is_relative_to(COPY_ROOT), 'profile_control_write_scope')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(read(path) == raw, 'profile_control_write_readback')
    return dict(path=path.relative_to(PROJECT).as_posix(), sha256=digest(raw), size_bytes=len(raw))


def persist(name, value):
    require(re.fullmatch(r'[a-z0-9_]+\.json', name), 'profile_control_output_name')
    return put(WORK / name, canonical(value) + b'\n')


def fence(allowed_reads):
    stdlib = Path(sys.base_prefix).resolve()
    def audit(event, args):
        if event.startswith(('socket.', 'subprocess.')) or event in ('os.system', 'os.fork', 'os.forkpty',
                'os.posix_spawn', 'os.exec', 'ctypes.dlopen', 'ctypes.dlsym'):
            raise ValueError('profile_control_external_action_refused')
        if event == 'import' and args:
            require(str(args[0]).split('.')[0] not in ('app', 'config', 'hedgehog'),
                'profile_control_whole_application_import_refused')
        if event == 'open' and args and not isinstance(args[0], int):
            path = Path(os.fsdecode(args[0])).absolute()
            mode, flags = args[1:3]
            writing = isinstance(mode, str) and any(c in mode for c in 'wax+')
            writing = writing or isinstance(flags, int) and bool(flags &
                (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            local = path.is_relative_to(WORK) or path.is_relative_to(COPY_ROOT)
            require('..' not in path.parts and (local if writing else local or path in allowed_reads
                or path.resolve().is_relative_to(stdlib)), 'profile_control_io_scope')
        if event in ('os.remove', 'os.unlink', 'os.rmdir', 'os.mkdir', 'os.rename', 'os.chmod',
                'os.chown', 'os.link', 'os.symlink', 'os.truncate'):
            for value in args[:2] if event in ('os.rename', 'os.link', 'os.symlink') else args[:1]:
                if isinstance(value, (str, bytes, Path)):
                    path = Path(os.fsdecode(value)).absolute()
                    require(path.is_relative_to(WORK) or path.is_relative_to(COPY_ROOT),
                        'profile_control_mutation_scope')
    sys.addaudithook(audit)


def extract(raw, name, *, constants=(), functions=(), classes=(), extra=None):
    body, found = [], set()
    for node in ast.parse(raw, filename=name).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            key = node.targets[0].id
            if key in constants: body.append(node); found.add(key)
        elif isinstance(node, ast.FunctionDef) and node.name in functions:
            body.append(node); found.add(node.name)
        elif isinstance(node, ast.ClassDef) and node.name in classes:
            body.append(node); found.add(node.name)
    require(found == set(constants) | set(functions) | set(classes), 'profile_control_ast_inventory')
    module = types.ModuleType(name)
    module.__dict__.update(__builtins__=vars(builtins), **(extra or {}))
    sys.modules[name] = module
    exec(compile(ast.Module(body=body, type_ignores=[]), str(PROJECT / name), 'exec'), module.__dict__)
    return module


def refused(call, expected):
    try:
        call()
    except ValueError as error:
        require(type(error) is ValueError and error.args == (expected,), 'profile_control_wrong_refusal')
        return expected
    raise ValueError('profile_control_expected_refusal')


def main():
    global WORK, COPY_ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True); parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    require(re.fullmatch(re.escape(BASE) + r'/grants/OWNER_PROFILE_V[0-9]{2}\.json', args.grant),
        'profile_control_grant_path')
    raw = read(PROJECT / args.grant); require(digest(raw) == args.sha256, 'profile_control_grant_hash')
    grant = json.loads(raw)
    require(grant['reviewer'] == '/root/private_remote_controls' and grant['approved_executor'] == '/root'
        and grant['approved_invocation_count'] == 1 and re.fullmatch(r'OWNER_PROFILE_V[0-9]{2}', grant['actual_id'])
        and args.grant == BASE + '/grants/' + grant['actual_id'] + '.json'
        and grant['network'] == 'DENIED' and grant['production_writes_allowed'] is False
        and grant['real_AUTH_provider_native_E_SAVE_allowed'] is False and grant['automatic_retry'] is False
        and grant['total_budget_seconds'] == 300, 'profile_control_independent_grant')
    require(grant['runner_ref']['path'] == SELF and grant['proposal_ref']['path'] == PROPOSAL,
        'profile_control_grant_source_paths')
    exact(grant['runner_ref']); proposal = json.loads(exact(grant['proposal_ref']))
    refs = proposal['source_refs']
    source = {r['path']: exact(r) for r in refs}
    copy_rows = proposal['copy_refs']
    require(type(copy_rows) is list and len(copy_rows) <= 4096
        and len({relative(row['destination']) for row in copy_rows}) == len(copy_rows),
        'profile_control_copy_inventory')
    copied = [(row['destination'], exact(row['source_ref'])) for row in copy_rows]
    require(sum(len(raw) for _, raw in copied) <= 536870912, 'profile_control_copy_bound')
    WORK = PROJECT / BASE / 'offline_actual' / grant['actual_id'] / 'work'
    COPY_ROOT = PROJECT / BASE / 'rehearsal_actual' / grant['actual_id'] / 'ordinary/source_under_test'
    require(not WORK.exists() and not COPY_ROOT.exists(), 'profile_control_no_retry')
    WORK.mkdir(parents=True, mode=0o700); COPY_ROOT.mkdir(parents=True, mode=0o700)
    fence({PROJECT / r['path'] for r in refs} | {PROJECT / row['source_ref']['path'] for row in copy_rows}
        | {PROJECT / SELF, PROJECT / args.grant, PROJECT / PROPOSAL})
    persist('reservation.json', dict(grant_sha256=args.sha256, actual_id=grant['actual_id'],
        cumulative_prior_charged_ns=grant['prior_charged_ns'], automatic_retry=False))
    for destination, raw in copied: put(COPY_ROOT / destination, raw)
    common = dict(Path=Path, hashlib=hashlib, json=json, os=os, stat=stat, sys=sys,
        types=types, dataclass=dataclass, re=re, time=time)
    gate_constants = ('REAL_PROJECT', 'PREFIX', 'PREDECESSOR_MANIFEST', 'STAGE04_MANIFEST',
        'PREDECESSOR_MANIFEST_SHA256', 'HISTORICAL_MANIFESTS', 'UPGRADE', 'MANIFEST', 'OWNER_ADMISSION',
        'REHEARSAL_SEAL', 'REHEARSAL_BINDING', 'ACTIVATION', 'PROFILE', '_REHEARSAL_KEY')
    gate_functions = ('require', '_sha', '_path', '_read', '_reference', 'rehearsal_context',
        'validate_rehearsal_context', 'load_profile', 'preserving_upgrade')
    def gate_module(name):
        return extract(source[GATE], name, constants=gate_constants, functions=gate_functions,
            classes=('RehearsalContext',), extra=dict(common, __file__=str(COPY_ROOT / GATE)))
    canonical_gate = gate_module('_radik_owner_profile_canonical_gate')
    manifest = json.loads(read(COPY_ROOT / (BASE + '/ordinary_profile_manifest.json')))
    manifest_ref = dict(path=BASE + '/ordinary_profile_manifest.json',
        sha256=digest(read(COPY_ROOT / (BASE + '/ordinary_profile_manifest.json'))))
    seal = dict(schema='radik.p28.isolated_rehearsal_seal.v01', reviewer=grant['reviewer'],
        owned_copy_root=str(COPY_ROOT), production_root=str(PROJECT), environment_root=str(PROJECT),
        source_review_ref=manifest['source_review_ref'], code_pins=manifest['pins'],
        real_AUTH_provider_native_E_SAVE_allowed=False, production_writes_allowed=False, network='DENIED')
    seal_raw = canonical(seal)
    put(COPY_ROOT / canonical_gate.REHEARSAL_SEAL, seal_raw)
    put(COPY_ROOT / canonical_gate.REHEARSAL_BINDING,
        canonical(dict(schema='radik.p28.rehearsal_context.v01', seal_sha256=digest(seal_raw))))
    context = canonical_gate.rehearsal_context(COPY_ROOT, digest(seal_raw))
    selected = canonical_gate.load_profile(COPY_ROOT, manifest_ref)
    _, predecessor = canonical_gate.preserving_upgrade(COPY_ROOT, selected)
    installer_constants = ('REAL_PROJECT', 'PREFIX', 'MANIFEST', 'SELF', 'JOURNAL', 'PENDING',
        'FINISH_PENDING', 'ACTIVATION', 'MAX_FILE_BYTES', 'READER_FIRST', '_GATE_MODULE', 'OWNER_LOCK', 'PRESERVED_STATE')
    installer_functions = ('require', 'canonical', 'sha', 'path', 'read', 'reference', 'sync_parent',
        'exclusive', 'replace', 'raw_candidate', 'unchanged_state', 'check_unchanged_state',
        '_completed', '_predecessor', '_activate_locked')
    def pinned_gate_loader(project, payloads):
        require(project == COPY_ROOT and payloads['config/application_profile_gate.py'] == source[GATE],
            'profile_control_loader_identity')
        return gate_module('_radik_stage05_activation_raw_gate')
    installer = extract(source[INSTALLER], '_radik_owner_profile_installer',
        constants=installer_constants, functions=installer_functions,
        extra=dict(common, __file__=str(COPY_ROOT / INSTALLER), load_raw_gate=pinned_gate_loader))
    admitted_manifest, admitted_manifest_ref, payloads = installer.raw_candidate(COPY_ROOT)
    require(admitted_manifest == manifest and admitted_manifest_ref == manifest_ref
        and len(manifest['pins']) == 181 and len(payloads) == 57, 'profile_control_final_inventory')
    installer._predecessor(COPY_ROOT, canonical_gate, selected, manifest, payloads)
    historical_profiles = []
    for reference in proposal['historical_profile_refs']:
        old_selected = canonical_gate.load_profile(COPY_ROOT, reference)
        historical_profiles.append(dict(profile_ref=reference,
            source_reviewer=old_selected['runtime_review']['reviewer'],
            code_pin_count=len(old_selected['manifest']['pins'])))
    before = installer.unchanged_state(COPY_ROOT, predecessor)
    before_ledger = json.loads(before['state/console_model_turns.json'])
    require(len(before_ledger['attempts']) == 50 and before_ledger['active_attempt_id'] ==
        'radik-call:c146081f7b9a4d649f3c7e916189271e', 'profile_control_original_unknown')
    # Negative input checks modify only the new owned copy, then restore exact bytes.
    manifest_name = BASE + '/ordinary_profile_manifest.json'
    manifest_raw = read(COPY_ROOT / manifest_name)
    bad_manifest = copy.deepcopy(manifest); bad_manifest['modes']['COLD'] = 4
    installer.replace(COPY_ROOT, manifest_name, canonical(bad_manifest))
    manifest_refusal = refused(lambda: canonical_gate.load_profile(COPY_ROOT,
        dict(path=manifest_name, sha256=digest(canonical(bad_manifest)))), 'profile_gate_manifest')
    installer.replace(COPY_ROOT, manifest_name, manifest_raw)
    bad_ledger = copy.deepcopy(before_ledger); bad_ledger['attempts'].pop()
    installer.replace(COPY_ROOT, 'state/console_model_turns.json', canonical(bad_ledger))
    stopped_state_refusal = refused(lambda: installer._predecessor(COPY_ROOT, canonical_gate,
        selected, manifest, payloads),
        'profile_install_predecessor_state_changed')
    installer.replace(COPY_ROOT, 'state/console_model_turns.json', before['state/console_model_turns.json'])
    installation = installer._activate_locked(COPY_ROOT, rehearsal_context=context)
    require(installation['status'] == 'UPGRADED_AND_ACTIVATED_VERIFIED'
        and installation['mode'] == 'SOURCE_ONLY_REHEARSAL', 'profile_control_installation')
    installer.check_unchanged_state(COPY_ROOT, before)
    require(all(read(COPY_ROOT / name) == raw for name, raw in before.items() if raw is not None),
        'profile_control_original_state_exact')
    preservation = [dict(path=name, sha256=digest(raw), size_bytes=len(raw))
        for name, raw in sorted(before.items()) if raw is not None]
    installation_ref = persist('installation.json', dict(status='PASS', installation=installation,
        unchanged_state_refs=preservation, ledger_rows=50, active_UNKNOWN_unchanged=True,
        applied_ACK=False, raw_gate_loader_scope='TWO_DISTINCT_EXACT_AST_GATE_NAMESPACES',
        manifest_shape_refusal=manifest_refusal, changed_stopped_state_refusal=stopped_state_refusal,
        current_code_pin_count=181, current_install_file_count=57, historical_profiles=historical_profiles))
    # Source input and prior refs are read exactly, but driver events are synthetic.
    def checked_reference(reference, *, cap=67108864, prefixes=None):
        name = relative(reference['path'])
        require(prefixes is None or name.startswith(prefixes), 'profile_control_prior_reference_scope')
        raw = read(COPY_ROOT / name)
        require(len(raw) <= cap and digest(raw) == reference['sha256']
            and ('size_bytes' not in reference or len(raw) == reference['size_bytes']),
            'profile_control_prior_reference_pin')
        return raw
    owner_writes = []
    def owner_put(path, value, **kwargs):
        owner_writes.append(put(path, canonical(value)))
    owner = extract(source[OWNER], '_radik_owner_profile_driver', constants=('PREFIX',),
        functions=('require', 'canonical', 'token', 'load_scenario_inputs'),
        classes=('CommandRefusal', 'OrdinaryDriver'),
        extra=dict(common, checked_reference=checked_reference, put=owner_put))
    input_ref = proposal['scenario_input_ref']
    inputs = owner.load_scenario_inputs(dict(scenario_input_ref=input_ref))
    ledger = copy.deepcopy(before_ledger); ledger['active_attempt_id'] = None
    tasks = json.loads(before['workspace/owner_documents/state/dynamic_tasks.json'])
    require(digest(ledger['attempts']) == inputs['expected_historical_prefix_sha256'],
        'profile_control_driver_exact50')
    checkpoint_names = ['prospective_scenario', 'ordinary_accepted_result', 'cold_current_consumer',
        'qualified_feedback', 'qualified_current_consumer', 'causal_chain_verified',
        'unrelated_prospective_task', 'unrelated_accepted_result', 'unrelated_current_consumer',
        'source_revision_before', 'source_revision_after', 'source_revision_stale_binding_refused']
    synthetic_result = dict(schema='radik.stage05.qualified_experience_result.v01',
        status='OWNER_SCENARIO_COMPLETED_REQUIRES_REVIEW', actual_model_calls=6, native_E_calls=0, effects=0,
        scenario_mode='remaining_only', completed_scope='FRESH_REMAINING_ONLY', repeated_G4_allocations=0,
        repeated_aged_consumers=0, prior_closed_process_authority_restored=False,
        prior_actual_evidence=inputs['prior_actual_evidence'], observations=[dict(step=name) for name in checkpoint_names])
    after_ledger = copy.deepcopy(ledger)
    after_ledger['attempts'] += [dict(synthetic_fixture_row=True, ordinal=index) for index in range(6)]
    def ready_driver(label):
        driver = owner.OrdinaryDriver(inputs, WORK / label)
        driver.begin_process(0)
        driver.observe_ready(dict(status='READY', ledger_before=copy.deepcopy(ledger),
            ledger_after=copy.deepcopy(ledger), store_state=copy.deepcopy(tasks)))
        return driver
    driver = ready_driver('driver_positive')
    require(driver.next_line(dict(prompt_id='command', command_sequence=1)) == 'experience',
        'profile_control_experience_command')
    witness = dict(command_sequence=1, command='experience', status='COMPLETED',
        ledger_before=copy.deepcopy(ledger), ledger_after=copy.deepcopy(after_ledger),
        store_state=copy.deepcopy(tasks), qualified_experience_result=synthetic_result)
    driver.complete(dict(command_sequence=1), witness, dict(synthetic=True))
    require(driver.next_line(dict(prompt_id='command', command_sequence=2)) == 'exit', 'profile_control_exit_command')
    driver.complete(dict(command_sequence=2), dict(command_sequence=2, command='exit', status='EXIT',
        ledger_before=copy.deepcopy(after_ledger), ledger_after=copy.deepcopy(after_ledger),
        store_state=copy.deepcopy(tasks)), dict(synthetic=True))
    driver.process_closed(0); driver_result = driver.result()
    negative_driver = []
    for label, mutate, expected in (
        ('checkpoint_missing', lambda value: value['qualified_experience_result']['observations'].pop(),
            'terminal_remaining_checkpoint_sequence'),
        ('wrong_mode', lambda value: value['qualified_experience_result'].update(scenario_mode='full'),
            'terminal_experience_result_contract'),
        ('repeated_G4', lambda value: value['qualified_experience_result'].update(repeated_G4_allocations=1),
            'terminal_experience_result_contract'),
        ('seventh_role', lambda value: value['ledger_after']['attempts'].append(dict(synthetic_fixture_row=True)),
            'terminal_driver_scenario_role_call_limit'),
        ('historical_row_changed', lambda value: value['ledger_after']['attempts'][0].update(synthetic_mutation=True),
            'terminal_driver_historical_ledger_changed')):
        negative = ready_driver('driver_' + label)
        negative.next_line(dict(prompt_id='command', command_sequence=1))
        bad = copy.deepcopy(witness); mutate(bad)
        negative_driver.append(dict(case=label, code=refused(
            lambda: negative.complete(dict(command_sequence=1), bad, dict(synthetic=True)), expected)))
    # Exact timing selector: synthetic launch metadata cannot create an operation.
    entry = extract(source[ENTRY], '_radik_owner_profile_entry', constants=('PREFIX',),
        functions=('_operation_timing_name',), extra=common)
    launch_path = BASE + '/owner_terminal_runs/SYNTHETIC_PROFILE_CONTROL/launch.json'
    launch = dict(schema='radik.p28.owner_terminal_launch.v01', source_review_ref=manifest['source_review_ref'],
        process_index=1, prior_child_receipt_ref=None, operation_started_ns=1,
        operation_deadline_ns=2, operation_started_utc='SYNTHETIC_NO_CLOCK_AUTHORITY')
    launch_raw = canonical(launch)
    timing_args = types.SimpleNamespace(owner_supervisor_launch=launch_path, owner_scenario=False,
        owner_run_binding=digest(launch_raw), owner_operation_started_ns=1, owner_operation_deadline_ns=2,
        owner_operation_started_utc='SYNTHETIC_NO_CLOCK_AUTHORITY')
    timing_gate = types.SimpleNamespace(require=require, _read=lambda project, name: launch_raw)
    require(entry._operation_timing_name(COPY_ROOT, timing_args, manifest, timing_gate,
        inherited_clock=True) == BASE + '/supervisor_timing.py', 'profile_control_timing_selected')
    require(entry._operation_timing_name(COPY_ROOT, timing_args, manifest, timing_gate,
        inherited_clock=False) == entry.PREFIX + '/supervisor_timing.py', 'profile_control_timing_legacy')
    bad_args = copy.copy(timing_args); bad_args.owner_run_binding = '0'*64
    timing_refusal = refused(lambda: entry._operation_timing_name(COPY_ROOT, bad_args, manifest,
        timing_gate, inherited_clock=True), 'ordinary_stage05_launch_binding')
    # Registry-only evidence for the narrow disposition literals; no transport replay.
    def owned_literals(raw):
        tree = ast.parse(raw)
        nodes = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'OWNED_ERROR_CODES']
        require(len(nodes) == 1 and isinstance(nodes[0].value, ast.Call)
            and isinstance(nodes[0].value.func, ast.Name) and nodes[0].value.func.id == 'frozenset'
            and len(nodes[0].value.args) == 1, 'profile_control_registry_literal')
        return set(ast.literal_eval(nodes[0].value.args[0]))
    before_codes = owned_literals(source[BASE + '/source_history/stage04_diagnostics_transport_v02.py'])
    current_codes = owned_literals(source[BASE + '/after/app/stage04_diagnostics.py'])
    additions = current_codes - before_codes
    expected_codes = set(json.loads(source[BASE + '/unknown_disposition_diagnostic_codes.json'])) | {
        'ordinary_stage05_disposition_launch', 'ordinary_stage05_explicit_unknown_decision'}
    require(len(additions) == 42 and additions == expected_codes and before_codes <= current_codes,
        'profile_control_exact_disposition_registry')
    for reference in refs: exact(reference)
    for row in copy_rows: exact(row['source_ref'])
    result = dict(schema='radik.stage05.owner_profile_controls.v04', status='PASS', actual_id=grant['actual_id'],
        installation_ref=installation_ref, driver_result=driver_result, driver_negative_cases=negative_driver,
        driver_witness_basis='SYNTHETIC_EVENTS_WITH_EXACT50_ORIGINAL_ATTEMPT_PREFIX_NO_RUNTIME_ROLE_CALLS',
        driver_event_readback_or_native_semantics_tested=False, timing_selector='PASS', timing_refusal=timing_refusal,
        fixture_ACK_applied=False, active_UNKNOWN_preserved_on_installer_copy=True,
        diagnostic_registry_additions=sorted(additions), diagnostic_scope='STATIC_EXACT42_LITERAL_ONLY_NO_TRANSPORT_REPLAY',
        source_refs=refs, original_source_and_state_refs_unchanged=True,
        real_AUTH=False, provider_calls=0, native_calls=0, effects=0, production_writes=False,
        elapsed_seconds=time.monotonic()-STARTED, owner_actual=False, Stage05_acceptance='NOT_INFERRED')
    result_ref = persist('result.json', result)
    print('OWNER_PROFILE_CONTROLS ' + json.dumps(dict(status='PASS', result_ref=result_ref)), flush=True)


if __name__ == '__main__':
    main()
