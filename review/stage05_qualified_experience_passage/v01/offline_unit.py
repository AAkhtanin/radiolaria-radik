"""Run only reviewed pure unit controls against a retained finite source copy.

This runner performs no task migration, controller run, native Work execution,
owner operation, provider call or AUTH. A separate reviewer admits the runner,
the preserved native source inventory and fresh read-only test copies first.
"""
import argparse
import fcntl
import hashlib
import importlib.abc
import importlib.machinery
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import types
import unittest

PASSAGE = 'review/stage05_qualified_experience_passage/v01'
PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


class PinnedFinder(importlib.abc.MetaPathFinder):
    def __init__(self, root, pins, loaded):
        self.root, self.pins, self.loaded = root, pins, loaded

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in ('app', 'hedgehog', 'review', 'config'):
            return None
        search = path if path is not None else [str(self.root / 'source/reference'
            if fullname == 'hedgehog' else self.root)]
        spec = importlib.machinery.PathFinder.find_spec(fullname, search)
        if spec is None:
            raise ImportError('stage05_unit_missing_protected_import:' + fullname)
        if spec.origin is None:
            require(spec.submodule_search_locations and all(Path(p).resolve().is_relative_to(self.root)
                for p in spec.submodule_search_locations), 'stage05_unit_namespace_outside_source')
            return spec
        source = Path(spec.origin).resolve()
        require(source.is_relative_to(self.root) and source.suffix == '.py', 'stage05_unit_import_outside_source')
        relative = str(source.relative_to(self.root))
        require(relative in self.pins, 'stage05_unit_unreviewed_import:' + relative)
        raw = source.read_bytes()
        require(sha(raw) == self.pins[relative], 'stage05_unit_import_changed:' + relative)
        loaded = self.loaded
        class Loader(importlib.abc.Loader):
            def create_module(self, _spec):
                return None
            def exec_module(self, module):
                require(source.read_bytes() == raw, 'stage05_unit_import_race')
                module.__file__ = str(source)
                loaded.append(dict(module=fullname, path=relative, sha256=sha(raw)))
                exec(compile(raw, str(source), 'exec'), module.__dict__)
        spec.loader = Loader()
        return spec


def fence(root, tests, workspace):
    environments = tuple(Path(value).resolve() for value in (sys.prefix, sys.base_prefix))
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def location(value, directory_fd=None):
        require(isinstance(value, (str, bytes, os.PathLike)), 'stage05_unit_audit_nonpath')
        path = Path(os.fsdecode(value))
        if not path.is_absolute() and directory_fd is not None and directory_fd != -1:
            require(type(directory_fd) is int and directory_fd >= 0, 'stage05_unit_invalid_directory_descriptor')
            # macOS exposes the already-open directory path without changing
            # cwd or weakening the mutation boundary for fd-relative cleanup.
            parent = fcntl.fcntl(directory_fd, fcntl.F_GETPATH, b'\0' * 1024)
            path = Path(os.fsdecode(parent.split(b'\0', 1)[0])) / path
        path = path.resolve()
        require(not {'.codex', '.ssh', '.aws', '.azure', '.gnupg'}.intersection(path.parts)
            and path.name not in {'auth.json', '.netrc', '.env', 'credentials', 'credentials.json'},
            'stage05_unit_credential_path')
        return path

    def writable(value, directory_fd=None):
        require(location(value, directory_fd).is_relative_to(workspace), 'stage05_unit_write_outside_workspace')

    def audit(event, args):
        if (event.startswith(('socket.', 'subprocess.', 'ctypes.'))
                or event in ('os.system', 'os.posix_spawn', 'os.posix_spawnp', 'os.exec',
                    'os.fork', 'os.forkpty', 'pty.spawn', 'os.chdir', 'os.fchdir')):
            raise PermissionError('stage05_unit_external_operation:' + event)
        if event == 'open':
            name, mode, flags = args
            if type(name) is int:
                require(name >= 0, 'stage05_unit_invalid_descriptor')
                return
            path = location(name)
            if bool((flags or 0) & write_flags) or any(c in (mode or '') for c in 'wax+'):
                writable(path)
            else:
                require(any(path.is_relative_to(allowed) for allowed in (root, tests, workspace) + environments),
                    'stage05_unit_read_outside_admitted_paths')
        elif event in ('os.rename', 'os.link'):
            writable(args[0], args[2]); writable(args[1], args[3])
        elif event == 'os.symlink':
            writable(args[0], args[2]); writable(args[1], args[2])
        elif event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.chown', 'os.utime'):
            writable(args[0], args[-1])
        elif event in ('os.truncate', 'os.setxattr', 'os.removexattr'):
            writable(args[0])

    sys.addaudithook(audit)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-source-root', required=True)
    parser.add_argument('--native-source-review', required=True)
    parser.add_argument('--test-root', required=True)
    parser.add_argument('--unit-review', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--deadline-seconds', type=int, default=60)
    args = parser.parse_args()
    anchor = (PROJECT / PASSAGE / 'offline_actual').resolve(strict=True)
    root = Path(args.native_source_root).resolve(strict=True)
    tests = Path(args.test_root).resolve(strict=True)
    workspace = Path(args.workspace).absolute()
    source_review = Path(args.native_source_review).resolve(strict=True)
    unit_review = Path(args.unit_review).resolve(strict=True)
    require(all(path.is_relative_to(anchor) and path != anchor for path in
        (root, tests, workspace.resolve(), source_review, unit_review)), 'stage05_unit_owned_anchor')
    require(root != tests and not tests.is_relative_to(root) and not root.is_relative_to(tests)
        and not workspace.exists() and not workspace.is_symlink()
        and not any(workspace.resolve().is_relative_to(path) or path.is_relative_to(workspace.resolve())
            for path in (root, tests)) and 1 <= args.deadline_seconds <= 180, 'stage05_unit_workspace_or_limit')
    source_raw, review_raw = source_review.read_bytes(), unit_review.read_bytes()
    source, review = json.loads(source_raw), json.loads(review_raw)
    require(source['schema'] == 'radik.stage05.offline_source_admission.v01'
        and source['decision'] == 'ACCEPTED_FOR_BOUNDED_OFFLINE_NATIVE_CHECKS'
        and source['owner_actual_allowed'] is False, 'stage05_unit_original_source_admission')
    require(review['schema'] == 'radik.stage05.unit_source_admission.v01'
        and review['decision'] == 'ACCEPTED_FOR_PURE_UNIT_CHECKS'
        and review['owner_actual_allowed'] is False
        and review['source_admission_sha256'] == sha(source_raw)
        and review['runner_sha256'] == sha(Path(__file__).read_bytes())
        and review['source_root'] == str(root) and review['test_root'] == str(tests),
        'stage05_unit_independent_source_admission')
    pins = source['pins']
    for relative, expected in pins.items():
        path = root / relative
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
            and not path.is_symlink() and path.resolve().is_relative_to(root)
            and sha(path.read_bytes()) == expected, 'stage05_unit_source_pin:' + relative)
    test_pins = review['test_pins']
    require(set(test_pins) == {'test_qualified_experience.py', 'test_qualified_strategy.py'},
        'stage05_unit_finite_test_set')
    test_bytes = {}
    for name, expected in test_pins.items():
        path = tests / name
        require(not path.is_symlink() and path.stat().st_mode & 0o222 == 0,
            'stage05_unit_test_copy_not_read_only')
        raw = path.read_bytes()
        require(sha(raw) == expected, 'stage05_unit_test_pin:' + name)
        test_bytes[name] = raw
    workspace.mkdir(parents=True, mode=0o700)
    temporary = workspace / 'temporary'
    temporary.mkdir(mode=0o700)
    tempfile.tempdir = str(temporary)
    loaded = []
    result = dict(schema='radik.stage05.offline_unit_result.v01', status='STOPPED_NO_RETRY',
        unit_review_sha256=sha(review_raw), source_review_sha256=sha(source_raw), test_pins=test_pins,
        loaded_modules=loaded, scope='PURE_DATA_BOUNDARY_CONTROLS_ONLY', owner_actual=False,
        provider_calls=0, AUTH_calls=0, SAVE_calls=0, native_Work_executions=0, native_E_calls=0)
    finder = PinnedFinder(root, pins, loaded)
    sys.meta_path.insert(0, finder)
    sys.dont_write_bytecode = True
    fence(root, tests, workspace.resolve())
    started = time.monotonic()

    def deadline(_signal, _frame):
        # unittest propagates KeyboardInterrupt instead of swallowing the
        # one-shot alarm as an ordinary per-test failure and continuing.
        raise KeyboardInterrupt('stage05_unit_deadline')

    previous = signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, args.deadline_seconds)
    success = False
    try:
        suite = unittest.TestSuite()
        for name, raw in test_bytes.items():
            module = types.ModuleType('stage05_pinned_' + Path(name).stem)
            module.__file__ = str(tests / name)
            sys.modules[module.__name__] = module
            exec(compile(raw, module.__file__, 'exec'), module.__dict__)
            loaded.append(dict(module=module.__name__, path=str(tests / name), sha256=sha(raw)))
            suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
        outcome = unittest.TextTestRunner(verbosity=2).run(suite)
        success = outcome.wasSuccessful()
        result.update(status='PURE_UNIT_CHECKS_PASSED_REQUIRES_REVIEW' if success else 'PURE_UNIT_CHECKS_FAILED',
            test_methods=outcome.testsRun, failures=[dict(test=str(test), traceback=detail) for test, detail in outcome.failures],
            errors=[dict(test=str(test), traceback=detail) for test, detail in outcome.errors])
    except BaseException as error:
        result['error'] = dict(type=type(error).__name__, message=str(error)[:1000])
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        result['seconds'] = time.monotonic() - started
        (workspace / 'result.json').write_bytes(canonical(result))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
