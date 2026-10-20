"""Finite diagnostic of the public PURE G4 bootstrap, never an owner replay.

Historical V02 documents supply inert bytes only. This fixture creates a new
current source reader, Root decision, policy, empty registry, Host and Work.
It does not reconstruct an accepted controller or an ExperienceBinding, and
therefore cannot certify the ordinary G3/G4 path or its original failure.
"""
import argparse
from dataclasses import replace
import hashlib
import importlib.abc
import importlib.machinery
import json
import os
from pathlib import Path
import signal
import sys
import time

PASSAGE = 'review/stage05_qualified_experience_passage/v01'
OWNED_PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
INPUT = PASSAGE + '/inputs/g4_bootstrap_inert_v01.json'
RUNNER = PASSAGE + '/g4_bootstrap_fixture.py'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


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
            raise ImportError('g4_fixture_protected_import_absent')
        if spec.origin is None:
            require(spec.submodule_search_locations and all(Path(p).resolve().is_relative_to(self.root)
                for p in spec.submodule_search_locations), 'g4_fixture_namespace_outside_source')
            return spec
        source = Path(spec.origin).resolve()
        require(source.is_relative_to(self.root) and source.suffix == '.py', 'g4_fixture_import_outside_source')
        relative = str(source.relative_to(self.root))
        require(relative in self.pins, 'g4_fixture_unreviewed_import')
        raw = source.read_bytes()
        require(sha(raw) == self.pins[relative], 'g4_fixture_import_changed')
        loaded = self.loaded

        class Loader(importlib.abc.Loader):
            def create_module(self, _spec):
                return None

            def exec_module(self, module):
                require(source.read_bytes() == raw, 'g4_fixture_import_race')
                module.__file__ = str(source)
                loaded.append(dict(module=fullname, path=relative, sha256=sha(raw)))
                exec(compile(raw, str(source), 'exec'), module.__dict__)

        spec.loader = Loader()
        return spec


def install_audit_fence(root, workspace):
    environment = tuple(Path(value).resolve() for value in (sys.prefix, sys.base_prefix))
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    forbidden_parts = {'.codex', '.ssh', '.aws', '.azure', '.gnupg'}
    forbidden_names = {'auth.json', '.netrc', '.env', 'credentials', 'credentials.json'}

    def path_value(value):
        require(isinstance(value, (str, bytes, os.PathLike)), 'g4_fixture_audit_nonpath')
        path = Path(os.fsdecode(value)).resolve()
        require(not forbidden_parts.intersection(path.parts) and path.name not in forbidden_names,
                'g4_fixture_credential_path')
        return path

    def writable(value):
        require(path_value(value).is_relative_to(workspace), 'g4_fixture_write_outside_workspace')

    def audit(event, args):
        if event.startswith(('socket.', 'subprocess.', 'ctypes.')) or event in (
            'os.system', 'os.posix_spawn', 'os.posix_spawnp', 'os.exec', 'os.fork', 'os.forkpty',
            'pty.spawn', 'os.chdir', 'os.fchdir'):
            raise PermissionError('g4_fixture_external_operation')
        if event == 'open':
            name, mode, flags = args
            if type(name) is int:
                require(name >= 0, 'g4_fixture_invalid_descriptor')
                return
            path = path_value(name)
            writing = bool((flags or 0) & write_flags) or any(c in (mode or '') for c in 'wax+')
            if writing:
                writable(path)
            else:
                require(path.is_relative_to(root) or path.is_relative_to(workspace)
                    or any(path.is_relative_to(prefix) for prefix in environment), 'g4_fixture_read_outside_scope')
        elif event in ('os.rename', 'os.link', 'os.symlink'):
            writable(args[0]); writable(args[1])
        elif event in ('os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod', 'os.chown',
                       'os.truncate', 'os.utime', 'os.setxattr', 'os.removexattr'):
            writable(args[0])

    sys.addaudithook(audit)


def failure(error, stage, root, pins, reason_codes):
    code = (error.args[0] if len(error.args) == 1 and type(error.args[0]) is str
            and error.args[0] in reason_codes else 'UNLISTED_SOURCE_REASON')
    frames, node = [], error.__traceback__
    while node is not None:
        path = Path(node.tb_frame.f_code.co_filename).resolve()
        if path.is_relative_to(root):
            relative = str(path.relative_to(root))
            if relative in pins:
                frames.append(dict(path=relative, sha256=pins[relative], line=node.tb_lineno,
                                   function=node.tb_frame.f_code.co_name))
        node = node.tb_next
    return dict(type=type(error).__name__, code=code, stage=stage, frames=frames[-24:],
                raw_error_recorded=False, locals_recorded=False, original_exception_preserved=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--source-review', required=True)
    parser.add_argument('--source-review-sha256', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--deadline-seconds', type=int, default=60)
    args = parser.parse_args()
    anchor = (OWNED_PROJECT / PASSAGE / 'offline_actual').resolve(strict=True)
    root, workspace = Path(args.source_root).resolve(strict=True), Path(args.workspace).resolve()
    review_path = Path(args.source_review).resolve(strict=True)
    require(root.is_relative_to(anchor) and workspace.is_relative_to(anchor) and root != anchor
        and workspace != anchor and not root.is_relative_to(workspace) and not workspace.is_relative_to(root)
        and review_path.is_relative_to(OWNED_PROJECT / PASSAGE), 'g4_fixture_owned_anchor')
    require(not workspace.exists() and not workspace.is_symlink() and 1 <= args.deadline_seconds <= 120,
            'g4_fixture_workspace_or_limit')
    review_raw = review_path.read_bytes()
    require(sha(review_raw) == args.source_review_sha256, 'g4_fixture_review_pin')
    review = json.loads(review_raw)
    require(review['schema'] == 'radik.stage05.g4_bootstrap_source_admission.v01'
        and review['decision'] == 'ACCEPTED_FOR_DIRECT_PURE_BOOTSTRAP_ONLY'
        and review['owner_actual_allowed'] is False and review['ordinary_acceptance_allowed'] is False,
        'g4_fixture_independent_admission')
    pins, reason_codes = review['pins'], review['reason_codes']
    require(type(pins) is dict and RUNNER in pins and INPUT in pins
        and type(reason_codes) is list and all(type(x) is str for x in reason_codes), 'g4_fixture_review_shape')
    for relative, expected in pins.items():
        path = root / relative
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
            and not path.is_symlink() and path.resolve().is_relative_to(root), 'g4_fixture_pin_path')
        require(sha(path.read_bytes()) == expected, 'g4_fixture_source_pin')
    require(Path(__file__).resolve() == root / RUNNER and sha(Path(__file__).read_bytes()) == pins[RUNNER],
            'g4_fixture_runner_pin')
    workspace.mkdir(parents=True, mode=0o700)
    loaded, phases = [], []
    result = dict(schema='radik.stage05.g4_bootstrap_result.v01', status='STOPPED_NO_RETRY',
        scope='DIRECT_PURE_BOOTSTRAP_NOT_NORMAL_ROUTE_ACCEPTANCE', owner_actual=False,
        ordinary_acceptance=False, historical_permission_restored=False, source_review_sha256=sha(review_raw),
        loaded_modules=loaded, phases=phases, real_provider_calls=0, AUTH_calls=0, SAVE_calls=0, native_E_calls=0)
    started, stage = time.monotonic(), 'IMPORTS'
    sys.dont_write_bytecode = True
    sys.meta_path.insert(0, PinnedFinder(root, pins, loaded))
    sys.path[:0] = [str(root), str(root / 'source/reference')]
    install_audit_fence(root, workspace)

    def persist(name, value):
        raw = canonical(value)
        path = workspace / (name + '_' + sha(raw) + '.json')
        with path.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        require(path.read_bytes() == raw, 'g4_fixture_evidence_readback')
        return dict(path=str(path.relative_to(workspace)), bytes=len(raw), sha256=sha(raw))

    def phase(name, callback):
        nonlocal stage
        stage, before = name, time.monotonic()
        print('G4_BOOTSTRAP_PHASE ' + name, flush=True)
        value = callback()
        phases.append(dict(name=name, seconds=time.monotonic() - before))
        result['last_completed_phase'] = name
        persist('checkpoint', result)
        return value

    def deadline(_signal, _frame):
        raise TimeoutError('g4_fixture_deadline')

    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, args.deadline_seconds)
    try:
        from app import qualified_strategy as strategy, qualified_experience as experience
        from app import native_authority as authority
        from hedgehog import action_commit_packet_v02 as action, work_execution_host_v01 as hosts
        from hedgehog.kernel import abi_v01 as abi, work_composition_v01 as work, effect_firewall_v01 as firewall
        from hedgehog.kernel import execution_mode_router_v01 as router

        def read_inert():
            raw = (root / INPUT).read_bytes()
            require(sha(raw) == pins[INPUT], 'g4_fixture_input_changed')
            value = json.loads(raw)
            require(value['schema'] == 'radik.stage05.g4_bootstrap_inert_fixture.v01'
                and value['classification'] == 'HISTORICAL_ADVISORY_DATA_NOT_AUTHORITY', 'g4_fixture_inert_input')
            strategy._source_gate(value['material'])
            return value

        fixture = phase('CURRENT_INERT_SOURCE_READ', read_inert)
        source = fixture['material']
        now = int(time.time())
        task_id = 'radik-task:g4-bootstrap-fixture:' + sha(canonical(dict(input=pins[INPUT], now=now)))[:32]
        root_id, transaction = 'root:radik:g4-bootstrap-fixture', 'transaction:' + task_id
        review_material = dict(input_sha256=pins[INPUT], source_gate=strategy._source_gate(source),
                               authority_claim='FRESH_FIXTURE_BYTE_CHECK_ONLY')
        root_review = phase('FRESH_SOURCE_ROOT', lambda: authority.root_review(
            'radik:fixture_root:' + sha(canonical(review_material)), review_material,
            dict(current_input_bytes=read_inert() == fixture,
                 source_hashes=all(sha(row['text'].encode()) == row['sha256'] for row in source['sources']),
                 no_restored_authority=fixture['classification'] == 'HISTORICAL_ADVISORY_DATA_NOT_AUTHORITY'),
            now, transaction_id=transaction, owning_root_id=root_id, task_id=task_id))
        require(root_review[2].decision == 'ACCEPT', 'g4_fixture_source_root_refused')
        result['source_root'] = persist('source_root', authority.root_plain(root_review))
        fields = json.loads(canonical(fixture['source_context']))
        for name in ('replay_source_safe_file_contents', 'replay_reconstructed_safe_file_contents',
                     'g2a_current_dependency_observations', 'g2b_compatibility_projections'):
            require(fields[name] == [], 'g4_fixture_nonempty_historical_binding')
            fields[name] = ()
        advisory = {'business_request_context_packet', 'bsep_packet', 'bsep_route_context_packet',
                    'bsep_orchestrator_proposal', 'bsep_structured_rationale'}
        clocks = {'g2a_evaluation_time', 'g2a_evaluation_time_source', 'g2a_evaluation_context_id'}
        require(all(value is None or value == () for key, value in fields.items()
                    if key not in advisory | clocks), 'g4_fixture_historical_authority_forbidden')
        retained = phase('ADVISORY_SOURCE_CONTEXT', lambda: router.build_execution_mode_source_context_v01(**fields))
        source_context = replace(experience._request_source(retained, task_id),
            g2a_evaluation_time=int(time.time()), g2a_evaluation_time_source='radik:trusted_clock',
            g2a_evaluation_context_id=task_id)
        host_ref = 'radik:qualified_host:' + authority.digest(task_id)
        catalogue = phase('EXACT_CALLBACK_ADMISSION', lambda: (
            strategy._admit(strategy.SOURCE_OPERATION, ('material',), host_ref),
            strategy._admit(strategy.CHECK_OPERATION, ('material',), host_ref),
            strategy._admit(strategy.FINAL_OPERATION, ('material', 'allocation_proof', 'previous',
                *('q' + str(i) for i in range(strategy.DISCRETIONARY_UNITS))), host_ref)))
        result['callback_admissions'] = persist('callback_admissions', authority.plain(tuple(
            firewall.snapshot_admitted_capability_v01(row) for row in catalogue)))
        definitions = tuple(row.definition.definition_id for row in catalogue)
        now, intent = int(time.time()), 'radik:fixture_intent:' + sha(canonical(review_material))
        semantic = abi.build_kernel_artifact_v01(abi_version='v1.0',
            artifact_id='radik:fixture_proposal:' + authority.digest(intent), artifact_type='SemanticArchitectProposal',
            schema_version='v1', transaction_id=transaction, owner_root_id=root_id,
            source_component='radik:qualified_adapter', authority_class='ADVISORY', lifecycle_state='PROPOSED',
            payload=dict(profile=strategy.PROFILE, source=source, fixture_only=True,
                         inventory=strategy.QUANTA, total_units=strategy.TOTAL_UNITS),
            trace_refs=(intent, source['task']['task_id']), parent_refs=(source_context.bsep_packet['packet_id'],),
            time_envelope=dict(pt_created_at=authority.stamp(now), kt_asof=authority.stamp(now), et_observed_at=None,
                ct_session_anchor=task_id, ttl_seconds=args.deadline_seconds, freshness_class='static',
                valid_from=authority.stamp(now), valid_to=authority.stamp(now + args.deadline_seconds)))
        common = dict(catalogue=catalogue, source_context=source_context, semantic_proposal=semantic)
        item = work.WorkItemV01('source_gate', definitions[0], root_id,
            (strategy._literal('material', source),), (), (), None, None)
        candidate = phase('BUILD_CANDIDATE', lambda: work.build_work_program_candidate_v01(task_id=task_id,
            previous_revision_id=None, intent_ref=intent, bsep_ref=source_context.bsep_packet['packet_id'],
            semantic_proposal_ref=semantic.artifact_id, catalogue_revision=0,
            budget=work.WorkBudgetV01(16, 0, 0, strategy.TOTAL_UNITS, 2), items=(item,), trigger_evidence_refs=(), **common))
        program = phase('MATERIALIZE', lambda: work.materialize_work_program_v01(candidate, **common))
        policy = phase('BUILD_POLICY', lambda: work.build_work_task_policy_v01(candidate, **common,
            host_instance_ref=host_ref, definition_ids=tuple(sorted(definitions)), resource_refs=()))

        class FreshSource:
            def __init__(self):
                clock = int(time.time())
                self.snapshot = hosts.TrustedWorkSourceSnapshotV01((), action.build_logical_time_bridge_v01(
                    origin_utc_epoch_seconds=clock, seconds_per_tick=1, bridge_policy_version=strategy.PROFILE),
                    clock, 'radik:trusted_clock', task_id, 0)
                self.reads = []

            def read_current_v01(self):
                require(read_inert() == fixture, 'g4_fixture_current_source_changed')
                clock = int(time.time())
                require(clock >= self.snapshot.evaluation_time, 'g4_fixture_clock_rollback')
                self.snapshot = replace(self.snapshot, evaluation_time=clock,
                    source_revision=self.snapshot.source_revision + int(clock != self.snapshot.evaluation_time))
                self.reads.append(dict(evaluation_time=clock, source_revision=self.snapshot.source_revision,
                                      input_sha256=pins[INPUT]))
                return self.snapshot

        trusted = FreshSource()
        clock = phase('EXPLICIT_TRUSTED_SOURCE_READ', trusted.read_current_v01)
        host = phase('FRESH_HOST', lambda: hosts.build_root_work_execution_host_v01(owning_root_id=root_id,
            registry=action.build_empty_action_commit_packet_registry_v02(), catalogue=catalogue, packet_bindings=(),
            current_dependency_observations=(), logical_time_bridge=clock.logical_time_bridge,
            trusted_source=trusted, task_policies=(policy,)))
        phase('ENROLL', lambda: work.enroll_work_program_v01(host, program, **common, expected_revision=host.state_revision))

        def context():
            return work.work_continuation_context_v01(host, task_id=task_id, expected_revision=host.state_revision)

        result['pre_dispatch'] = persist('pre_dispatch', authority.plain(dict(program=program, semantic=semantic,
            source_context=source_context, policy=policy, usage=work.inspect_work_task_v01(host, task_id=task_id),
            trusted_reads=trusted.reads)))
        outcome = phase('G4_BOOTSTRAP_ADVANCE', lambda: work.advance_work_program_v01(program, **common,
            host_map={root_id: host}, continuation_context=context()))
        result['bootstrap_outcome'] = persist('bootstrap_outcome', authority.plain(outcome))
        validation = phase('G4_BOOTSTRAP_VALIDATE', lambda: work.validate_work_continuation_outcome_v01(
            outcome, context=context(), **common))
        result['validation'] = authority.plain(validation)
        require(validation == (True, ()) and outcome.status == 'COMPLETED'
            and all(row.status == 'COMPLETED' for row in outcome.results), 'qualified_native_work_return')
        artifact = phase('G4_BOOTSTRAP_ARTIFACT', lambda: work.work_program_result_to_artifact_v01(program,
            outcome.results, **common, host_map={root_id: host}, continuation_context=context()))
        result['bootstrap_artifact'] = persist('bootstrap_artifact', authority.plain(artifact))
        snapshot = work.inspect_work_task_v01(host, task_id=task_id)
        require(snapshot.usage.compute_units == 1 and host.registry.action_packet_lifecycle_entries == ()
            and len(outcome.results) == 1 and all(row.invocation.candidate_id is None
                and row.invocation.packet_id is None for row in outcome.results), 'g4_fixture_pure_accounting')
        result['final_native_state'] = persist('final_native_state', authority.plain(dict(snapshot=snapshot,
            history=work.inspect_work_task_history_v01(context()), trusted_reads=trusted.reads)))
        result['status'] = 'DIRECT_PURE_BOOTSTRAP_OBSERVED_REQUIRES_INDEPENDENT_REVIEW'
    except BaseException as error:
        result['primary_failure'] = failure(error, stage, root, pins, reason_codes)
        print('G4_BOOTSTRAP_STOP ' + canonical(result['primary_failure']).decode(), flush=True)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        result['seconds'] = time.monotonic() - started
        reference = persist('result', result)
        print('G4_BOOTSTRAP_RESULT ' + canonical(reference).decode(), flush=True)
    return 0 if result['status'] == 'DIRECT_PURE_BOOTSTRAP_OBSERVED_REQUIRES_INDEPENDENT_REVIEW' else 1


if __name__ == '__main__':
    raise SystemExit(main())
