"""Finite source-admitted ordinary CLI rehearsal in exclusively created copies.

External responses are inert fixtures behind the typed rehearsal gate. The single
qualified-experience process use the same driver, stdin dispatcher and native consumers
as the future owner command. No production application module is imported.
"""
import argparse
import fcntl
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
import types

REAL = Path('/Users/admin/Projects/RadiolariaRadik')
PREFIX = 'review/stage05_qualified_experience_passage/v01'
SELF = PREFIX + '/rehearsal_runner.py'
STARTED = time.monotonic()
MAX_SECONDS = 900
MAX_BYTES = 64 * 1024 * 1024
CHILD = None


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()


def safe_path(root, name):
    require(type(name) is str and name and not name.startswith('/')
        and '\\' not in name and all(x not in ('', '.', '..', '.git', '.codex',
        '.aws', 'private', 'Arena', 'arena') for x in name.split('/')), 'exam_path')
    path = Path(root)
    for part in name.split('/'):
        path /= part
        require(not path.is_symlink(), 'exam_symlink')
    return path


def read(root, name):
    path = safe_path(root, name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= MAX_BYTES, 'exam_regular_file')
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    require(before == after and len(raw) == before.st_size, 'exam_read_stability')
    return raw


def verify(root, ref):
    raw = read(root, ref['path'])
    require(sha(raw) == ref['sha256'] and len(raw) == ref['size_bytes'],
        'exam_reference_changed')
    return raw


def put(root, name, raw, mode=0o600):
    path = safe_path(root, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        require(stream.write(raw) == len(raw), 'exam_short_write')
        stream.flush()
        os.fsync(stream.fileno())
    require(read(root, name) == raw, 'exam_write_readback')
    return dict(path=name, sha256=sha(raw), size_bytes=len(raw))


def load(root, name, expected, module_name):
    raw = read(root, name)
    require(sha(raw) == expected and module_name not in sys.modules,
        'exam_preimport_pin')
    module = types.ModuleType(module_name)
    module.__file__ = str(Path(root) / name)
    sys.modules[module_name] = module
    exec(compile(raw, module.__file__, 'exec', dont_inherit=True), module.__dict__)
    return module


def guard(grant):
    for ref in grant['production_guard_refs']:
        verify(REAL, ref)


def install_parent_fence(grant):
    """Deny sockets and private reads; writes stay in this new exam directory."""
    allowed = REAL / PREFIX / 'rehearsal_actual' / grant['actual_id']
    roots = {Path(case['owned_copy_root']) for case in grant['cases']}
    def audit(event, args):
        if event.startswith('socket.') or event in ('os.system', 'os.fork', 'os.posix_spawn'):
            raise ValueError('exam_network_or_unowned_process_refused')
        if event == 'subprocess.Popen':
            executable, argv, cwd, _env = args
            require(executable == grant['interpreter_ref']['path'] and type(argv) is list
                and argv[1:4] == ['-I', '-S', '-B'] and len(argv) >= 6
                and argv[5] == '--console' and Path(argv[4]).parent.name == 'config'
                and Path(argv[4]).name == 'launch.py'
                and Path(argv[4]).parent.parent in roots
                and '--owner-scenario' not in argv
                and '--rehearsal-seal-sha256' in argv,
                'exam_exact_cli_child_required')
        if event == 'open' and args and isinstance(args[0], (str, bytes, Path)):
            path = Path(args[0]).absolute()
            require(not set(path.parts).intersection(
                ('private', '.codex', '.aws', 'Arena', 'arena')), 'exam_private_read_refused')
            mode, flags = args[1:3]
            writing = isinstance(mode, str) and any(c in mode for c in 'wax+')
            writing = writing or isinstance(flags, int) and bool(flags & (1 | 2 | 64 | 512 | 1024))
            require(not writing or path.is_relative_to(allowed), 'exam_production_write_refused')
        if event in ('os.mkdir', 'os.remove', 'os.unlink', 'os.rmdir', 'os.rename', 'os.chmod'):
            for value in (args[:2] if event == 'os.rename' else args[:1]):
                if isinstance(value, (str, bytes, Path)):
                    require(Path(value).absolute().is_relative_to(allowed),
                        'exam_production_mutation_refused')
    sys.addaudithook(audit)


def copy_case(grant, case):
    root = Path(case['owned_copy_root'])
    expected = REAL / PREFIX / 'rehearsal_actual' / grant['actual_id'] / case['name'] / 'source_under_test'
    require(root == expected and not root.exists(), 'exam_exclusive_copy')
    root.mkdir(parents=True, mode=0o700)
    refs = grant['copy_refs']
    require(1 <= len(refs) <= 4096 and len({r['path'] for r in refs}) == len(refs),
        'exam_copy_inventory')
    total = 0
    for ref in refs:
        require(not ref['path'].startswith(('.venv', '.settings', 'state/local_operator')),
            'exam_no_environment_or_operator_copy')
        raw = verify(REAL, ref)
        total += len(raw)
        require(total <= 512 * 1024 * 1024, 'exam_copy_byte_bound')
        mode = ref.get('mode', 0o600)
        require(mode in (0o444, 0o600, 0o644, 0o755), 'exam_copy_mode')
        put(root, ref['path'], raw, mode)
    seal_raw = verify(REAL, case['rehearsal_seal_ref'])
    seal = json.loads(seal_raw)
    require(seal['owned_copy_root'] == str(root) and seal['code_pins'] == grant['code_pins'],
        'exam_copy_seal_binding')
    put(root, PREFIX + '/rehearsal_seal.json', seal_raw, 0o444)
    put(root, 'state/ordinary_rehearsal_context.json',
        canonical(dict(schema='radik.p28.rehearsal_context.v01',
            seal_sha256=sha(seal_raw))), 0o444)
    return root


def safe_error(error):
    value = error.args[0] if type(error) is ValueError and error.args else 'exam_sanitized_failure'
    if type(value) is not str or not re.fullmatch('[A-Za-z0-9_:./-]{1,256}', value):
        value = 'exam_sanitized_failure'
    result = dict(error_class=type(error).__name__, code=value)
    def public_name(name):
        if type(name) is not str:
            return None
        path = Path(name).absolute()
        if not path.is_relative_to(REAL) or set(path.parts).intersection(
                ('private', '.codex', '.aws', 'Arena', 'arena')):
            return None
        return str(path.relative_to(REAL))
    missing = public_name(getattr(error, 'filename', None))
    if missing is not None:
        result['missing_owned_path'] = missing
        result['code'] = 'exam_required_owned_file_missing'
    frames = []
    trace = error.__traceback__
    while trace is not None and len(frames) < 24:
        name = public_name(trace.tb_frame.f_code.co_filename)
        if name is not None:
            frames.append(dict(path=name, line=trace.tb_lineno,
                function=trace.tb_frame.f_code.co_name))
        trace = trace.tb_next
    result['source_frames'] = frames
    return result


def case_run(grant, case, root):
    global CHILD
    pins = grant['code_pins']
    module = load(root, PREFIX + '/owner_terminal.py', pins[PREFIX + '/owner_terminal.py'],
        'stage05_exam_supervisor_' + case['name'])
    timing = module.load_pinned_timing(pins)
    manifest = json.loads(verify(root, grant['manifest_ref']))
    lock_path = root / module.LOCK
    info = lock_path.stat()
    lock = module.acquire_lock(dict(device=info.st_dev, inode=info.st_ino,
        owner=info.st_uid, mode=stat.S_IMODE(info.st_mode), links=info.st_nlink))
    case_output = root / PREFIX / 'owner_terminal_runs' / case['name']
    case_output.mkdir(parents=True, mode=0o700)
    result = dict(name=case['name'], status='STARTED', production_calls=0,
        semantic_acceptance=False, copy_root=str(root))
    try:
        def before_pin():
            require(time.monotonic() - STARTED < MAX_SECONDS, 'exam_total_deadline')
        admission = dict(code_pins=pins, ordinary_profile_manifest_ref=grant['manifest_ref'])
        result['installation'] = module.prepare_installation(admission, manifest,
            lock_fd=lock, rehearsal_sha=case['rehearsal_seal_ref']['sha256'], before_pin=before_pin)
        started = time.monotonic_ns()
        launch = dict(schema='radik.stage05.source_rehearsal_launch.v01', operation_started_ns=started,
            operation_started_utc=int(time.time()), operation_deadline_ns=started + timing.LIMITS['operation_seconds'] * 10**9,
            source_review_ref=grant['source_review_ref'], semantic_acceptance=False,
            real_AUTH_provider_native_E_SAVE_allowed=False)
        if case['name'] == 'ordinary':
            def spawn(*args, **kwargs):
                global CHILD
                CHILD = subprocess.Popen(*args, **kwargs)
                return CHILD
            receipt = module.supervise(dict(argv=['.venv-plan/bin/python', '-I', '-S', '-B',
                'config/launch.py', '--console'], limits=timing.LIMITS,
                interpreter_ref=grant['interpreter_ref'], evidence_prefixes=['workspace/owner_documents/'],
                home_directory=str(root.parent), rehearsal_seal_sha256=case['rehearsal_seal_ref']['sha256'],
                diagnostic_source_pins=module.diagnostic_source_pins(manifest),
                scenario_inputs=module.load_scenario_inputs(dict(scenario_input_ref=grant['scenario_input_ref']))),
                started_ns=started, lock_fd=lock, launch=launch, timing=timing, run=case_output,
                interrupted=lambda: time.monotonic() - STARTED >= MAX_SECONDS, popen=spawn)
            result['receipt_ref'] = dict(path=str((case_output / 'receipt.json').relative_to(REAL)),
                sha256=sha((case_output / 'receipt.json').read_bytes()),
                size_bytes=(case_output / 'receipt.json').stat().st_size)
            require(receipt['status'] == 'CHILD_CLOSED_REVIEW_REQUIRED'
                and receipt['child_reaped'] and receipt['primary_failure'] is None, 'exam_ordinary_failed')
        else:
            raise ValueError('exam_only_single_ordinary_case')
        result['status'] = 'PASS_SOURCE_WIRING_NOT_ACTUAL_SEMANTICS'
    except BaseException as error:
        result['status'] = 'STOPPED_NO_RETRY'
        result['failure'] = safe_error(error)
        raise
    finally:
        reaped = CHILD is None or CHILD.poll() is not None
        result['all_started_children_reaped'] = reaped
        if not reaped:
            result['status'] = 'CLEANUP_UNCONFIRMED'
        result['lock_explicit_unlock_permitted'] = module.release_owned_lock(
            lock, child_started=CHILD is not None,
            receipt={'lock_explicit_unlock_permitted': reaped})
        put(REAL, str((root.parent / 'case_result.json').relative_to(REAL)), canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    raw = read(REAL, args.grant)
    require(sha(raw) == args.sha256, 'exam_grant_changed')
    grant = json.loads(raw)
    require(grant['reviewer'] == '/root/private_remote_controls' and grant['approved_executor'] == '/root'
        and grant['approved_invocation_count'] == 1 and grant['network'] == 'DENIED'
        and grant['production_writes_allowed'] is False
        and grant['real_AUTH_provider_native_E_SAVE_allowed'] is False
        and grant['status'] == 'SOURCE_ACCEPTED_FOR_ISOLATED_STAGE05_ORDINARY_WIRING',
        'exam_independent_admission')
    require(verify(REAL, grant['runner_ref']) == read(REAL, SELF), 'exam_runner_pin')
    interpreter = grant['interpreter_ref']
    require(interpreter['path'] == str(REAL / '.venv-plan/bin/python')
        and sha(read(REAL, '.venv-plan/bin/python')) == interpreter['sha256'],
        'exam_interpreter_pin')
    require(len(grant['cases']) == 1 and grant['cases'][0]['name'] == 'ordinary', 'exam_one_case_only')
    guard(grant)
    base = PREFIX + '/rehearsal_actual/' + grant['actual_id']
    # Create the outer parent before installing the fence; no candidate import
    # has happened. Every subsequent write belongs to this exclusive exam.
    (REAL / base).mkdir(parents=True, mode=0o700)
    install_parent_fence(grant)
    put(REAL, base + '/reservation.json', canonical(dict(grant_sha256=args.sha256,
        one_use=True, automatic_retry=False, source_only=True)))
    results = []
    final = dict(status='STARTED', semantic_acceptance=False, production_calls=0)
    try:
        for case in grant['cases']:
            require(time.monotonic() - STARTED < MAX_SECONDS, 'exam_total_deadline')
            root = copy_case(grant, case)
            results.append(case_run(grant, case, root))
        guard(grant)
        final['status'] = 'PASS_SOURCE_ONLY_STAGE05_ORDINARY_WIRING'
        return 0
    except BaseException as error:
        final.update(status='STOPPED_NO_RETRY', failure=safe_error(error))
        return 2
    finally:
        final.update(cases=results, elapsed_wall_seconds=time.monotonic() - STARTED)
        try:
            guard(grant)
            final['production_guard_unchanged'] = True
        except BaseException as error:
            final['production_guard_unchanged'] = False
            final['guard_failure'] = safe_error(error)
        put(REAL, base + '/result.json', canonical(final))
        print(json.dumps(final, sort_keys=True), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
