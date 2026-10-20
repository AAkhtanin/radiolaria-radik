"""One reviewed synthetic-role controller and bounded Stage05 native wiring.

This is an isolated engineering check, never an owner operation. A separate
reviewer supplies exact source admission before imports. Real sockets, AUTH,
provider calls, subprocesses and SAVE are unavailable. The accepted Stage04
multi-case runner and full E are not called.
"""
import argparse
from contextlib import ExitStack
import copy
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from unittest.mock import patch

PASSAGE = 'review/stage05_qualified_experience_passage/v01'
LEGACY = 'review/stage04_dynamic_passage'
OWNED_PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


class PinnedFinder(importlib.abc.MetaPathFinder):
    def __init__(self, root, pins, loaded):
        self.root, self.pins, self.loaded = root, pins, loaded

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in ('app', 'hedgehog', 'review', 'config'):
            return None
        # Resolve protected top-level packages only within the admitted copy.
        # The invoking interpreter may retain an unrelated working directory.
        search = path
        if search is None:
            search = [str(self.root / 'source/reference' if fullname == 'hedgehog' else self.root)]
        spec = importlib.machinery.PathFinder.find_spec(fullname, search)
        if spec is None:
            raise ImportError('stage05_missing_protected_import:' + fullname)
        if spec.origin is None:
            require(spec.submodule_search_locations and all(Path(p).resolve().is_relative_to(self.root)
                for p in spec.submodule_search_locations), 'stage05_namespace_outside_source')
            return spec
        source = Path(spec.origin).resolve()
        require(source.is_relative_to(self.root) and source.suffix == '.py', 'stage05_import_outside_source')
        relative = str(source.relative_to(self.root))
        require(relative in self.pins, 'stage05_unreviewed_import:' + relative)
        raw = source.read_bytes()
        require(sha(raw) == self.pins[relative], 'stage05_import_changed:' + relative)
        loaded = self.loaded
        class Loader(importlib.abc.Loader):
            def create_module(self, _spec):
                return None
            def exec_module(self, module):
                require(sha(source.read_bytes()) == sha(raw), 'stage05_import_race')
                module.__file__ = str(source)
                loaded.append(dict(module=fullname, path=relative, sha256=sha(raw)))
                exec(compile(raw, str(source), 'exec'), module.__dict__)
        spec.loader = Loader()
        return spec


def install_audit_fence(root, workspace):
    """Refuse external I/O while the independently reviewed fixture executes."""
    environment = tuple(Path(value).resolve() for value in (sys.prefix, sys.base_prefix))
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    credential_parts = {'.codex', '.ssh', '.aws', '.azure', '.gnupg'}
    credential_names = {'auth.json', '.netrc', '.env', 'credentials', 'credentials.json'}

    def path_value(value):
        require(isinstance(value, (str, bytes, os.PathLike)), 'stage05_audit_nonpath')
        candidate = Path(os.fsdecode(value)).resolve()
        require(not credential_parts.intersection(candidate.parts)
            and candidate.name not in credential_names, 'stage05_audit_credential_path')
        return candidate

    def writable(value):
        candidate = path_value(value)
        require(candidate.is_relative_to(workspace), 'stage05_audit_write_outside_workspace')

    def audit(event, args):
        if (event.startswith(('socket.', 'subprocess.', 'ctypes.'))
                or event in ('os.system', 'os.posix_spawn', 'os.posix_spawnp', 'os.exec',
                    'os.fork', 'os.forkpty', 'pty.spawn', 'os.chdir', 'os.fchdir')):
            raise PermissionError('stage05_audit_external_operation:' + event)
        if event == 'open':
            name, mode, flags = args
            if type(name) is int:
                # fdopen wraps an existing descriptor; acquisition of its
                # filesystem path has already passed this audit fence.
                require(name >= 0, 'stage05_audit_invalid_descriptor')
                return
            candidate = path_value(name)
            writing = bool((flags or 0) & write_flags) or any(character in (mode or '') for character in 'wax+')
            if writing:
                writable(candidate)
            else:
                require(candidate.is_relative_to(root) or candidate.is_relative_to(workspace)
                    or any(candidate.is_relative_to(prefix) for prefix in environment),
                    'stage05_audit_read_outside_admitted_paths')
        elif event in ('os.rename', 'os.link', 'os.symlink'):
            writable(args[0]); writable(args[1])
        elif event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.chown',
                'os.truncate', 'os.utime', 'os.setxattr', 'os.removexattr'):
            writable(args[0])

    sys.addaudithook(audit)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--source-review', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--deadline-seconds', type=int, default=180)
    args = parser.parse_args()
    root = Path(args.source_root).resolve(strict=True)
    workspace = Path(args.workspace).absolute()
    anchor = (OWNED_PROJECT / PASSAGE / 'offline_actual').resolve(strict=True)
    review_path = Path(args.source_review).resolve(strict=True)
    require(root.is_relative_to(anchor) and root != anchor
        and workspace.resolve().is_relative_to(anchor) and workspace.resolve() != anchor
        and not workspace.resolve().is_relative_to(root) and not root.is_relative_to(workspace.resolve())
        and review_path.is_relative_to(OWNED_PROJECT / PASSAGE), 'stage05_offline_owned_anchor')
    require(not workspace.exists() and not workspace.is_symlink()
            and 1 <= args.deadline_seconds <= 300, 'stage05_offline_workspace_or_limit')
    review_raw = review_path.read_bytes()
    review = json.loads(review_raw)
    require(review['schema'] == 'radik.stage05.offline_source_admission.v01'
        and review['decision'] == 'ACCEPTED_FOR_BOUNDED_OFFLINE_NATIVE_CHECKS'
        and review['owner_actual_allowed'] is False, 'stage05_independent_source_admission')
    pins = review['pins']
    require(type(pins) is dict and len(pins) >= 10, 'stage05_source_pin_inventory')
    sources = {}
    for relative, expected in pins.items():
        path = root / relative
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
                and not path.is_symlink() and path.resolve().is_relative_to(root), 'stage05_source_path')
        raw = path.read_bytes()
        require(sha(raw) == expected, 'stage05_source_pin:' + relative)
        sources[relative] = raw
    require(sha(Path(__file__).read_bytes()) == pins[PASSAGE + '/offline_native.py'], 'stage05_runner_pin')
    workspace.mkdir(parents=True, mode=0o700)
    loaded, phases = [], []
    result = dict(schema='radik.stage05.offline_native_result.v01', status='STOPPED_NO_RETRY',
        source_review_sha256=sha(review_raw), scope='SYNTHETIC_ROLE_HTTP_ACTUAL_NATIVE_WORK',
        real_provider_calls=0, real_AUTH_calls=0, SAVE_calls=0, native_E_calls=0,
        owner_actual=False, source_pins=pins, loaded_modules=loaded, phases=phases)
    finder = PinnedFinder(root, pins, loaded)
    started = time.monotonic()
    original_path = list(sys.path)
    sys.meta_path.insert(0, finder)
    sys.path[:0] = [str(root), str(root / 'source/reference')]
    sys.dont_write_bytecode = True
    install_audit_fence(root, workspace.resolve())

    def forbidden(*_args, **_kwargs):
        raise ValueError('stage05_offline_external_operation_forbidden')

    def deadline(_signal, _frame):
        raise TimeoutError('stage05_offline_deadline')

    def phase(name, call):
        before = time.monotonic()
        print('Stage05 offline phase: ' + name, flush=True)
        value = call()
        elapsed = time.monotonic() - before
        phases.append(dict(name=name, seconds=elapsed))
        (workspace / 'partial.json').write_bytes(canonical(result))
        return value

    def helper(relative, name):
        raw = sources[relative]
        module_spec = importlib.util.spec_from_loader(name, loader=None)
        module = importlib.util.module_from_spec(module_spec)
        module.__file__ = str(root / relative)
        sys.modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
        loaded.append(dict(module=name, path=relative, sha256=sha(raw)))
        return module

    prior_handler = signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, args.deadline_seconds)
    try:
        with ExitStack() as stack:
            for obj, name in ((socket, 'create_connection'), (socket.socket, 'connect'),
                (socket.socket, 'bind'), (socket.socket, 'listen'), (subprocess, 'run'),
                (subprocess, 'Popen'), (os, 'execve')):
                stack.enter_context(patch.object(obj, name, forbidden))
            from app import budget, contracts, plan_auth, openai_plan_transport as transport
            from app import dynamic_native, task_spec, qualified_experience, qualified_strategy
            wire = helper(LEGACY + '/dynamic_wire.py', 'stage05_reviewed_wire')
            migration = helper(LEGACY + '/migration_cases.py', 'stage05_reviewed_fixture_copy')
            fixtures = helper(LEGACY + '/native_cases.py', 'stage05_reviewed_product_factory')
            data = json.loads(sources[LEGACY + '/exam_inputs.json'])
            file_bytes = {}
            for relative, item in data['file_bytes'].items():
                raw = sources[item['path']]
                require(sha(raw) == item['sha256'], 'stage05_fixture_data_pin:' + relative)
                file_bytes[relative] = raw
            file_bytes.update(sources)
            project = migration.clone_migrated(workspace, 'one_short_controller',
                file_bytes=file_bytes, budget_module=budget)
            counter = budget.TurnBudget.for_scope(project, 'console')
            counter.set_console_operation('00000000-0000-0000-0000-000000000505', sha(b'stage05-offline-operation')[:12])
            client, _ = wire.create_wire_client(workspace, 'stage05', transport=transport, controller=None,
                contracts=contracts, budget_module=budget, auth_module=plan_auth,
                policy_bytes=file_bytes['config/model_policy.json'],
                product_factory=fixtures.product_factory(route='short', optional_exceptions=False),
                project_override=project, console_budget=counter)
            now = int(time.time())
            text = 'Support: Replies arrive on working days.\nUnknown: Call prices are unspecified.\n'
            material = [dict(source_ref='radik:source:' + sha(b'stage05-one-source')[:32], revision=1,
                text=text, sha256=sha(text.encode()), observed_at=now)]
            spec = task_spec.TaskSpec(version='radik.dynamic.task.v01', task_id='radik-task:' + sha(b'stage05-offline')[:32],
                profile='explain', goal='Explain fictional support conditions.', criterion='Preserve unknown call charges.',
                topic='stage05_offline_source_markers', source_ids=(material[0]['source_ref'],),
                resource_scope=(material[0]['source_ref'],), supplied_candidate=None,
                predecessor_task_id=None, created_at=now)
            controller = dynamic_native.DynamicDocumentController(project, client, task_spec=spec,
                source_reader=lambda: copy.deepcopy(material), clock=lambda: int(time.time()))
            dependencies = dict(meaning_key=task_spec.meaning_key(spec, material), sources=dynamic_native.descriptors(material))
            counter.begin_task_round(task_id=spec.task_id, profile=spec.profile, task_spec_sha256=contracts.digest(spec.plain()),
                dependencies_sha256=contracts.digest(dependencies), max_attempts=3)
            before = len(counter.snapshot()['attempts'])
            try:
                phase('one_short_native_controller', controller.run)
            finally:
                counter.end_task_round()
            after = counter.snapshot()
            require(len(after['attempts']) - before == 3 and len(controller.results) == 1,
                    'stage05_offline_three_roles_one_short_work')
            result['synthetic_role_attempts'] = 3
            result['ordinary_controller_result'] = controller.accepted.plain
            experience = qualified_experience.QualifiedExperience(project / 'state/qualified_experience')
            cold = phase('cold_G3_current_work', lambda: experience.consume(controller, cold=True))
            baseline = phase('cold_G4_native_work', lambda: qualified_strategy.run(controller, cold, label='cold'))
            feedback = phase('prospective_native_feedback', lambda: experience.observe(controller, predicted=True))
            warm = phase('qualified_G3_current_work', lambda: experience.consume(controller))
            subsequent = phase('qualified_G4_native_work', lambda: qualified_strategy.run(controller, warm, label='qualified'))
            unscorable = experience.audit_unscorable(controller, reason='UNSCORABLE_MODEL_RESPONSE')
            eligibility = phase('native_eligibility_controls', lambda: experience.eligibility_controls(controller))
            require(cold.report['selected_operation'] != warm.report['selected_operation']
                and warm.report['prior_fp'] == -62500000, 'stage05_offline_real_lesson_consumption')
            require(baseline['budget_total'] == subsequent['budget_total'] == 9
                and baseline['consumed_units'] == subsequent['consumed_units'] == 9
                and baseline['allocation_counts'] == {'quotation':4, 'qualification':3}
                and subsequent['allocation_counts'] == {'quotation':3, 'qualification':4}, 'stage05_offline_actual_redistribution')
            require(counter.snapshot()['attempts'] == after['attempts'], 'stage05_offline_unexpected_role_call')
            result.update(status='BOUNDED_OFFLINE_NATIVE_OBSERVED_REQUIRES_REVIEW', cold_G3=cold.report,
                qualified_G3=warm.report, cold_G4=baseline, qualified_G4=subsequent,
                feedback=feedback, unscorable=unscorable, eligibility=eligibility)
    except BaseException as error:
        result['error'] = dict(type=type(error).__name__, message=str(error)[:1000])
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prior_handler)
        result['seconds'] = time.monotonic() - started
        (workspace / 'result.json').write_bytes(canonical(result))
        sys.path[:] = original_path
        sys.meta_path.remove(finder)


if __name__ == '__main__':
    main()
