"""Exact source admission and per-peer I/O boundary for ordinary native mode.

This is an application-level boundary for reviewed local Python. It does not
claim protection against a hostile process with the same operating-system UID.
No credential, provider, legacy activation, or model constructor is used.
"""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


PREFIX = 'review/stage06_external_drs_passage/v01'
_INSTALLED = False


def require(condition, code):
    if not condition:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def read_ref(reference):
    require(type(reference) is dict and {'path', 'sha256', 'size_bytes'} <= set(reference),
            'stage06_reference_shape')
    path = Path(reference['path'])
    require(path.is_absolute() and path.is_file() and not path.is_symlink(),
            'stage06_reference_regular_absolute')
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size == reference['size_bytes'],
            'stage06_reference_size')
    raw = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and hashlib.sha256(raw).hexdigest() == reference['sha256'],
            'stage06_reference_changed')
    return raw


def reference(path):
    raw = Path(path).read_bytes()
    return dict(path=str(Path(path).absolute()), sha256=hashlib.sha256(raw).hexdigest(),
                size_bytes=len(raw))


def _inside(path, root):
    return path == root or path.is_relative_to(root)


def _fence(*, folder, read_paths, directory_paths, pipe_fds):
    """Permit own peer state and finite pinned reads, denying cross-peer reads."""
    global _INSTALLED
    require(not _INSTALLED, 'stage06_fence_already_installed')
    _INSTALLED = True
    folder = folder.resolve()
    allowed = {str(Path(p).absolute()) for p in read_paths}
    directories = {str(Path(p).absolute()) for p in directory_paths}
    descriptors = {0, 1, 2, *pipe_fds}

    def path_value(value):
        require(isinstance(value, (str, bytes, os.PathLike)), 'stage06_io_path_type')
        return Path(os.fsdecode(value)).absolute()

    def writable(value):
        path = path_value(value)
        require(_inside(path, folder) and _inside(path.resolve(), folder),
                'stage06_peer_write_outside_own_state')

    def audit(event, args):
        if event == 'open':
            name, mode, flags = args
            if type(name) is int:
                if name in descriptors:
                    return
                require(sys.platform == 'darwin' and stat.S_ISREG(os.fstat(name).st_mode),
                        'stage06_unowned_file_descriptor')
                # F_GETPATH=50 in the installed macOS public fcntl header.
                name = fcntl.fcntl(name, 50, b'\0' * 1024).split(b'\0', 1)[0]
            path = path_value(name)
            writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            writing = writing or isinstance(mode, str) and any(x in mode for x in 'wa+')
            if writing:
                writable(path)
            else:
                own = _inside(path, folder) and _inside(path.resolve(), folder)
                require(own or str(path) in allowed, 'stage06_peer_read_outside_admitted_scope')
        elif event in ('os.listdir', 'os.scandir'):
            path = path_value(args[0] if args and args[0] is not None else '.')
            require(_inside(path, folder) or str(path) in directories,
                    'stage06_directory_outside_admitted_scope')
        elif event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.utime'):
            writable(args[0])
        elif event in ('os.rename', 'os.link', 'os.symlink'):
            writable(args[0]); writable(args[1])
            require(event != 'os.symlink', 'stage06_symlink_creation_forbidden')
        elif event in ('subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty', 'os.exec',
                       'os.posix_spawn', 'socket.__new__', 'socket.connect', 'socket.bind'):
            raise ValueError('stage06_unadmitted_process_or_network')
        elif event == 'ctypes.dlopen' and args and args[0] is not None:
            require(str(path_value(args[0])) in allowed, 'stage06_unpinned_dynamic_library')
    sys.addaudithook(audit)


def _safe_failure(error, pins, codes):
    """Retain bounded pinned traceback locations, never arbitrary error text."""
    if error is None:
        return None
    code = error.args[0] if isinstance(error, ValueError) and error.args else None
    if type(code) is not str or code not in codes:
        code = 'stage06_native_entry_failure'
    frames = []
    trace = error.__traceback__
    while trace is not None:
        frame = trace.tb_frame
        path = str(Path(frame.f_code.co_filename).absolute())
        if path in pins:
            frames.append(dict(path=path, function=frame.f_code.co_name,
                line=trace.tb_lineno, sha256=pins[path]['sha256']))
        trace = trace.tb_next
    return dict(code=code, error_class=type(error).__name__, frames=frames[-24:])


def select_stage06(project, args):
    project = Path(project).resolve()
    environment = project.parents[3]
    require(project == environment / PREFIX / 'candidate', 'stage06_candidate_location')
    require(args.stage06_external_drs and args.console, 'stage06_explicit_console_mode_required')
    launch_path = Path(args.stage06_launch).absolute()
    allowed_roots = (environment / PREFIX / 'owner_terminal_runs',
                     environment / PREFIX / 'offline_attempts')
    require(any(launch_path.is_relative_to(p) for p in allowed_roots)
            and not launch_path.is_symlink(), 'stage06_owned_launch_required')
    launch_raw = launch_path.read_bytes()
    launch = json.loads(launch_raw)
    require(launch.get('schema') == 'radik.stage06.peer_launch.v1', 'stage06_launch_schema')
    manifest_ref = launch['code_manifest_ref']
    manifest = json.loads(read_ref(manifest_ref))
    require(manifest['schema'] == 'radik.stage06.source_manifest.v1'
            and manifest['environment_root'] == str(environment)
            and manifest['candidate_root'] == str(project), 'stage06_manifest_context')
    admission_ref = launch['admission_ref']
    admission = json.loads(read_ref(admission_ref))
    require(admission.get('reviewer') == '/root/private_remote_controls'
            and admission.get('code_manifest_ref') == manifest_ref
            and admission.get('expected_model_calls') == 0,
            'stage06_independent_source_admission_required')
    mode = launch['mode']
    require(mode in ('owner', 'engineering'), 'stage06_mode')
    expected = ('OWNER_COMMAND_SOURCE_READY_NOT_EXECUTED' if mode == 'owner'
                else 'SOURCE_ACCEPTED_FOR_BOUNDED_ENGINEERING_PROBE')
    require(admission.get('status') == expected
            and admission.get('task_selector') == ('external_drs_owner_v01' if mode == 'owner'
                else 'engineering_probe_v01'), 'stage06_admission_scope')
    reservation = json.loads(read_ref(launch['reservation_ref']))
    bound_fields = ('mode', 'operation_id', 'operation_started_ns',
                    'operation_deadline_ns', 'operation_started_utc', 'task_selector', 'limits')
    require(reservation.get('state') == 'OPEN'
            and all(reservation.get(key) == launch.get(key) for key in bound_fields)
            and reservation.get('admission_ref') == admission_ref
            and reservation.get('code_manifest_ref') == manifest_ref
            and reservation.get('run_directory') == str(launch_path.parent)
            and launch.get('limits') == admission.get('limits')
            and launch.get('task_selector') == admission.get('task_selector')
            and admission.get('mode') == mode,
            'stage06_fresh_operation_reservation_required')
    require(type(launch['operation_started_ns']) is int
            and type(launch['operation_deadline_ns']) is int
            and launch['operation_deadline_ns'] == launch['operation_started_ns'] +
                int(admission['limits']['operation_seconds'] * 1000000000)
            and launch['operation_started_ns'] <= time.monotonic_ns() < launch['operation_deadline_ns'],
            'stage06_operation_expired')
    role = args.stage06_role
    require(role in ('producer', 'recipient') and role == launch['role'], 'stage06_role_binding')
    require(args.stage06_session == launch['session'] and args.stage06_session in (1, 2),
            'stage06_session_binding')
    require(args.stage06_read_fd == launch['read_fd'] and args.stage06_write_fd == launch['write_fd'],
            'stage06_pipe_binding')
    require(all(type(fd) is int and fd > 2 and stat.S_ISFIFO(os.fstat(fd).st_mode)
                for fd in (args.stage06_read_fd, args.stage06_write_fd)), 'stage06_inherited_pipes_required')
    lock_fd = launch['owner_lock_fd']
    require(type(lock_fd) is int and lock_fd > 2 and lock_fd == args.owner_lock_fd,
            'stage06_inherited_owner_lock')
    lock_path = environment / 'review/direct_plan_passage/owner_start.lock'
    opened, expected_lock = os.fstat(lock_fd), lock_path.stat()
    require((opened.st_dev, opened.st_ino) == (expected_lock.st_dev, expected_lock.st_ino),
            'stage06_owner_lock_identity')
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    folder = Path(launch['folder']).absolute()
    require(folder == launch_path.parent/role
            and folder.is_dir() and not folder.is_symlink(), 'stage06_role_state_folder')
    files = manifest['files']
    require(1 <= len(files) <= 12000 and len({r['path'] for r in files}) == len(files),
            'stage06_finite_unique_source_inventory')
    peer_reads = set(manifest['peer_read_paths'])
    require(not peer_reads.intersection(row['path'] for row in admission['scenario_refs']),
            'stage06_master_scenario_not_peer_input')
    require(peer_reads <= {row['path'] for row in files}, 'stage06_read_inventory_subset')
    for row in files:
        if row['path'] in peer_reads:
            read_ref(row)
    failure_pins = {row['path']: row for row in files}
    failure_codes = frozenset(manifest['failure_codes'])
    baseline = admission['live_guards']

    def assert_current():
        require(time.monotonic_ns() < launch['operation_deadline_ns'], 'stage06_operation_expired')
        for row in baseline:
            read_ref(row)
        return dict(guard_count=len(baseline), preserved=True, checked_at_utc_ns=time.time_ns())

    initial = assert_current()
    require(sys.dont_write_bytecode, 'stage06_bytecode_disabled_required')
    # Prevent pre-existing bytecode from substituting for reviewed Python source.
    sys.pycache_prefix = str(folder / 'disabled_bytecode')
    for path in manifest['import_paths']:
        require(type(path) is str and Path(path).is_absolute(), 'stage06_import_path')
    # All module/resource bytes are pinned before the first native import.
    sys.path[:] = list(manifest['import_paths']) + [p for p in sys.path if p not in manifest['import_paths']]
    out = folder / 'entry_sessions' / ('session_' + str(args.stage06_session))
    out.mkdir(parents=True, exist_ok=False)
    evidence = out / 'evidence'; evidence.mkdir()
    started = time.monotonic_ns(); cpu_started = time.process_time_ns()
    sequence = 0
    refs = []
    finished = False

    def on_event(label, value):
        nonlocal sequence
        require(type(label) is str and re.fullmatch(r'[A-Za-z0-9_]{1,80}', label),
                'stage06_event_label')
        sequence += 1
        require(sequence <= 256, 'stage06_event_count')
        raw = canonical(value) + b'\n'
        require(len(raw) <= 16777216, 'stage06_evidence_size')
        name = '%04d_%s_%s.json' % (sequence, label, hashlib.sha256(raw).hexdigest())
        path = evidence / name
        with path.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        ref = reference(path)
        require(ref['size_bytes'] == len(raw) and ref['sha256'] == hashlib.sha256(raw).hexdigest(),
                'stage06_evidence_readback')
        refs.append(ref)
        observed = time.monotonic_ns()
        print(json.dumps(dict(stage06_event=dict(label=label, ref=ref,
            at_monotonic_ns=observed, operation_started_ns=launch['operation_started_ns'],
            wall_ns=observed-launch['operation_started_ns'], cpu_ns=time.process_time_ns(),
            pid=os.getpid(), sequence=sequence, role=role, session=args.stage06_session)),
            sort_keys=True), flush=True)
        return ref

    def observe_loaded(label):
        rows = []; builtin = []
        for name, module in tuple(sys.modules.items()):
            if module is None:
                continue
            path_value = getattr(module, '__file__', None)
            if path_value is None:
                spec = getattr(module, '__spec__', None)
                builtin.append(dict(module=name, origin=getattr(spec, 'origin', None)))
                continue
            path = str(Path(path_value).absolute())
            require(path in failure_pins and path in peer_reads,
                    'stage06_loaded_module_not_admitted')
            read_ref(failure_pins[path])
            rows.append(dict(module=name, path=path, sha256=failure_pins[path]['sha256']))
        value = dict(schema='radik.stage06.loaded_source_observation.v1',
            module_count=len(rows), modules=sorted(rows, key=lambda row: row['module']),
            builtins_or_namespaces=sorted(builtin, key=lambda row: row['module']),
            authority_restored=False, source_only_observation=True)
        return on_event(label, value)


    def finish(report, error):
        nonlocal finished
        require(not finished, 'stage06_entry_already_closed')
        finished = True
        primary = _safe_failure(error, failure_pins, failure_codes)
        secondary = []
        try:
            final_guard = assert_current()
        except BaseException as failure:
            final_guard = None
            if primary is None:
                primary = _safe_failure(failure, failure_pins, failure_codes)
            else:
                secondary.append(_safe_failure(failure, failure_pins, failure_codes))
        result = dict(schema='radik.stage06.ordinary_native_entry_receipt.v1',
            operation_id=launch['operation_id'], role=role, session=args.stage06_session,
            status='CLOSED' if primary is None else 'STOPPED_NO_RETRY',
            code_manifest_ref=manifest_ref, admission_ref=admission_ref,
            launch_ref=dict(path=str(launch_path), sha256=hashlib.sha256(launch_raw).hexdigest(),
                            size_bytes=len(launch_raw)),
            initial_live_guards=initial, final_live_guards=final_guard,
            report=report, primary_failure=primary, secondary_failures=secondary,
            checkpoints=refs[:], model_calls=0, auth_calls=0, native_E_calls=0,
            generic_SAVE_calls=0, restored_authority=False,
            wall_seconds=(time.monotonic_ns()-started)/1e9)
        closed_ref = on_event('ordinary_entry_closed', result)
        if error is None and primary is not None:
            raise ValueError(primary['code'])
        return closed_ref

    read_paths = set(manifest['peer_read_paths']) | {r['path'] for r in baseline}
    require(read_paths <= set(failure_pins) | {r['path'] for r in baseline},
            'stage06_read_inventory_subset')
    read_paths.update((str(launch_path), manifest_ref['path'], admission_ref['path'],
                      launch['reservation_ref']['path']))
    directories = set(manifest['directory_paths'])
    _fence(folder=folder, read_paths=read_paths, directory_paths=directories,
           pipe_fds=(args.stage06_read_fd, args.stage06_write_fd))
    return dict(stage06=dict(role=role, read_fd=args.stage06_read_fd,
        write_fd=args.stage06_write_fd, folder=folder, session=args.stage06_session,
        operation_ref=launch['reservation_ref'], launch_ref=reference(launch_path),
        on_event=on_event, assert_current=assert_current, finish=finish,
        observe_loaded=observe_loaded, task_selector=launch['task_selector'], mode=mode,
        peer_private_path=launch.get('peer_private_path')))
