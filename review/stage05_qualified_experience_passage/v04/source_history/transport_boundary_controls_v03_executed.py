"""One granted AST boundary series, with explicit inert external interfaces.

This executes exact selected candidate definitions, never a whole app module.
It proves transport failure/product boundary behavior only. Request admission,
AUTH, HTTP, SSE, budget and native semantic authority are synthetic interfaces.
"""
import argparse
import ast
import builtins
import copy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import SimpleNamespace

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage05_qualified_experience_passage/v03'
SELF = BASE + '/transport_boundary_controls.py'
WORK = PROJECT / BASE / 'offline_actual/TRANSPORT_BOUNDARY_V01/work'
TRANSPORT = BASE + '/after/app/openai_plan_transport.py'
DIAGNOSTICS = BASE + '/after/app/stage04_diagnostics.py'
SCENARIO = BASE + '/after/app/qualified_experience_scenario.py'
OWNER = BASE + '/owner_terminal.py'
PROPOSAL = BASE + '/transport_boundary_controls_proposal.json'
STARTED = time.monotonic()


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
        allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def read(path):
    path = Path(path)
    require(path.is_absolute() and path.is_relative_to(PROJECT) and '..' not in path.parts,
        'boundary_path_scope')
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'boundary_source_symlink')
        if parent == PROJECT:
            break
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= 67108864, 'boundary_regular_file')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size,
        s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
        'boundary_read_stability')
    return raw


def exact(ref):
    raw = read(PROJECT / ref['path'])
    require(digest(raw) == ref['sha256'] and len(raw) == ref['size_bytes'],
        'boundary_source_pin')
    return raw


def persist(name, value):
    require(re.fullmatch('[a-z0-9_]+\\.json', name), 'boundary_output_name')
    raw = canonical(value) + b'\n'
    path = WORK / name
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(path.read_bytes() == raw, 'boundary_output_readback')
    return dict(path=path.relative_to(PROJECT).as_posix(), sha256=digest(raw), size_bytes=len(raw))


def fence(allowed_reads):
    stdlib = Path(sys.base_prefix).resolve()
    def audit(event, args):
        if event.startswith(('socket.', 'subprocess.')) or event in ('os.system', 'os.fork',
                'os.forkpty', 'os.posix_spawn', 'os.exec', 'ctypes.dlopen', 'ctypes.dlsym'):
            raise ValueError('boundary_external_action_refused')
        if event == 'import' and args:
            require(not str(args[0]).split('.')[0] in ('app', 'hedgehog', 'config'),
                'boundary_whole_application_import_refused')
        if event == 'open' and args and not isinstance(args[0], int):
            path = Path(os.fsdecode(args[0])).absolute()
            require('..' not in path.parts, 'boundary_relative_escape')
            mode, flags = args[1:3]
            writing = isinstance(mode, str) and any(c in mode for c in 'wax+')
            writing = writing or isinstance(flags, int) and bool(flags &
                (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            require(path.is_relative_to(WORK) if writing else
                path in allowed_reads or path.is_relative_to(WORK) or path.resolve().is_relative_to(stdlib),
                'boundary_io_scope')
        if event in ('os.remove', 'os.unlink', 'os.rmdir', 'os.mkdir', 'os.rename',
                'os.chmod', 'os.chown', 'os.link', 'os.symlink', 'os.truncate'):
            for value in args[:2] if event in ('os.rename', 'os.link', 'os.symlink') else args[:1]:
                if isinstance(value, (str, bytes, Path)):
                    require(Path(os.fsdecode(value)).absolute().is_relative_to(WORK),
                        'boundary_mutation_scope')
    sys.addaudithook(audit)


def extract(raw, path, *, constants=(), functions=(), classes=None, extra=None):
    selected, found = [], set()
    for node in ast.parse(raw, filename=path).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in constants:
                selected.append(node); found.add(name)
        elif isinstance(node, ast.FunctionDef) and node.name in functions:
            selected.append(node); found.add(node.name)
        elif isinstance(node, ast.ClassDef) and node.name in (classes or {}):
            methods = classes[node.name]
            if methods is not None:
                node = copy.deepcopy(node)
                node.body = [child for child in node.body if isinstance(child, ast.FunctionDef)
                    and child.name in methods]
                require({child.name for child in node.body} == set(methods), 'boundary_class_inventory')
            selected.append(node); found.add(node.name)
    require(found == set(constants) | set(functions) | set(classes or {}), 'boundary_ast_inventory')
    namespace = dict(__name__='__main__', __package__='radik_boundary', __builtins__=vars(builtins))
    namespace.update(extra or {})
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(PROJECT / path), 'exec'), namespace)
    return namespace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant', required=True); parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    require(args.grant == BASE + '/transport_boundary_grant.json', 'boundary_grant_path')
    grant_raw = read(PROJECT / args.grant)
    require(digest(grant_raw) == args.sha256, 'boundary_grant_hash')
    grant = json.loads(grant_raw)
    require(grant['reviewer'] == '/root/private_remote_controls' and grant['approved_executor'] == '/root'
        and grant['approved_invocation_count'] == 1 and grant['actual_id'] == 'TRANSPORT_BOUNDARY_V01'
        and grant['network'] == 'DENIED' and grant['production_writes_allowed'] is False
        and grant['real_AUTH_provider_native_E_SAVE_allowed'] is False
        and grant['automatic_retry'] is False, 'boundary_independent_grant')
    require(grant['runner_ref']['path'] == SELF, 'boundary_runner_path')
    exact(grant['runner_ref'])
    proposal = json.loads(exact(grant['proposal_ref']))
    require(grant['proposal_ref']['path'] == PROPOSAL, 'boundary_proposal_path')
    refs = proposal['source_refs'] + proposal['dependency_refs']
    sources = {ref['path']: exact(ref) for ref in refs}
    require(not WORK.exists(), 'boundary_no_retry')
    WORK.mkdir(parents=True, mode=0o700)
    persist('reservation.json', dict(grant_sha256=args.sha256, owner_actual=False, automatic_retry=False))
    allowed_reads = {PROJECT / ref['path'] for ref in refs}
    allowed_reads |= {PROJECT / SELF, PROJECT / args.grant, PROJECT / PROPOSAL}
    fence(allowed_reads)
    class PinnedDependencyLoader:
        def __init__(self, path, package): self.path, self.package = path, package
        def create_module(self, spec): return None
        def exec_module(self, module):
            relative = self.path.relative_to(PROJECT).as_posix()
            raw = read(self.path)
            require(raw == sources[relative], 'boundary_dependency_changed')
            module.__file__ = str(self.path)
            if self.package: module.__path__ = [str(self.path.parent)]
            exec(compile(raw, str(self.path), 'exec'), module.__dict__)
    class PinnedDependencyFinder:
        def find_spec(self, fullname, path=None, target=None):
            spec = importlib.machinery.PathFinder.find_spec(fullname, path)
            if spec is None or not spec.origin or '/site-packages/' not in spec.origin:
                return None
            origin = Path(spec.origin)
            relative = origin.relative_to(PROJECT).as_posix()
            require(relative in sources, 'boundary_dependency_inventory')
            if origin.suffix == '.py':
                package = spec.submodule_search_locations is not None
                return importlib.util.spec_from_loader(fullname,
                    PinnedDependencyLoader(origin, package), origin=str(origin), is_package=package)
            require(any(str(origin).endswith(suffix) for suffix in importlib.machinery.EXTENSION_SUFFIXES),
                'boundary_dependency_extension')
            return spec
    sys.meta_path.insert(0, PinnedDependencyFinder())
    # All third-party files were hashed before the first dependency import.
    from jsonschema import Draft202012Validator
    dependency_modules = []
    for name, module in list(sys.modules.items()):
        filename = getattr(module, '__file__', None)
        if filename and '/site-packages/' in filename:
            path = Path(filename)
            if path.suffix == '.pyc':
                path = Path(__import__('importlib.util', fromlist=['source_from_cache']).source_from_cache(str(path)))
            relative = path.relative_to(PROJECT).as_posix()
            require(relative in sources, 'boundary_unpinned_dependency')
            dependency_modules.append(dict(module=name, path=relative, sha256=digest(read(path))))
    common = dict(Path=Path, re=re, json=json, time=time, datetime=datetime, timezone=timezone,
        dataclass=dataclass, asdict=asdict, canonical=canonical, digest=digest)
    def no_stream(value):
        require(value is None, 'boundary_stream_decoder_out_of_scope')
        return None
    diag_constants = ('OWNED_ERROR_CODES', 'MEMORY_ERROR_CODES', 'MEMORY_WRITEBACK_CODES',
        'RETURN_ERROR_CODES', 'TYPED_GUARD_NAMES', 'PHASES', 'STEPS', 'PERSISTENCE_STATES',
        'SAFE_ERROR_TYPES', 'MAX_SECONDARY_FAILURES', '_STATE_KEY', '_CORE_FIELDS',
        'TRANSPORT_FAILURE_SUBSTAGES', 'TRANSPORT_FAILURE_CATEGORIES', 'TRANSPORT_FRAME_FUNCTIONS')
    diag_functions = ('project_transport_failure', '_closed', '_attribute', '_name', '_code',
        '_secondary_valid', '_state', 'project_error', 'observe_failure', 'record_secondary', 'safe_projection')
    diag = extract(sources[DIAGNOSTICS], DIAGNOSTICS, constants=diag_constants,
        functions=diag_functions, extra=dict(common, project_stream_event=no_stream))
    data_path = BASE + '/inputs/transport_boundary_critic_data.json'
    data = json.loads(sources[data_path])
    require(data['authority_restored'] is False, 'boundary_inert_data_only')
    product, schema, context = data['value'], data['output_schema'], data['context']
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(product)
    observations = extract(sources['app/proposal.py'], 'app/proposal.py',
        classes={'ProposalObservation': None}, extra=common)
    pins = {path: digest(raw) for path, raw in sources.items() if path.endswith('.py')
        and '/site-packages/' not in path}
    fixture_pin = digest(read(PROJECT / SELF)); pins[SELF] = fixture_pin
    source_sha = digest(pins)
    interface_calls = []
    class RoleRequest:
        """Explicit synthetic request guard, not an issued application request."""
        def __init__(self):
            self.role, self.context, self.schema_bytes = 'critic', context, canonical(schema)
        def validate(self, **kwargs):
            interface_calls.append('SYNTHETIC_ROLE_VALIDATE')
            require(kwargs['role'] == self.role and kwargs['context'] == context
                and kwargs['output_schema'] == schema, 'boundary_synthetic_request_shape')
            return dict(scope='SYNTHETIC_BOUNDARY_ONLY')
        def emit(self, *, sender, observation, body):
            interface_calls.append('SYNTHETIC_ROLE_EMIT')
            require(sender._emitted_for(self, observation, body), 'boundary_emission_identity')
    class DynamicRoleRequest: pass
    class RehearsalAuth: pass
    def synthetic_external(*args):
        interface_calls.append('SYNTHETIC_EXTERNAL_GUARD')
    modules = {'controller': SimpleNamespace(RoleRequest=RoleRequest),
        'dynamic_roles': SimpleNamespace(DynamicRoleRequest=DynamicRoleRequest,
            CONTEXT_VERSION='radik.dynamic.role_context.v01',
            closed_role_schema=lambda role, material: copy.deepcopy(schema)),
        'ordinary_rehearsal': SimpleNamespace(RehearsalAuth=RehearsalAuth),
        'config.application_profile_gate': SimpleNamespace(require_external_owner=synthetic_external,
            validate_rehearsal_context=synthetic_external)}
    def inert_import(name, globals=None, locals=None, fromlist=(), level=0):
        require(name in modules and (level == 1 or name == 'config.application_profile_gate'),
            'boundary_unreviewed_import')
        return modules[name]
    closed_builtins = dict(vars(builtins), __import__=inert_import)
    def stream_complete(lines, *, diagnostic, **kwargs):
        # Deliberately synthetic terminal input: this is not an SSE parser test.
        diagnostic.update(lifecycle_terminal_received=True, lifecycle_terminal_kind='response.completed',
            parser_product_accepted=True)
        return SimpleNamespace(text=canonical(product).decode(), usage=dict(input_tokens=1, output_tokens=1),
            response_id='response_boundary_inert', event_count=1, stream_bytes=0,
            output_item_count=1, model='gpt-6.1-sol', effort='high', service_tier='default')
    constants = ('TRANSPORT_VERSION', 'STREAM_PROFILE_VERSION', 'HOST', 'MODELS_PATH', 'RESPONSES_PATH',
        'MODEL', 'EFFORT', 'SERVICE_TIER', 'ROLES', 'MAX_CONTEXT_BYTES', 'MAX_SCHEMA_BYTES', 'MAX_BODY_BYTES',
        'REQUEST_SECONDS', 'CATALOG_TTL_SECONDS', 'TRANSPORT_SUBSTAGES', '_TRANSPORT_FRAME_FUNCTIONS')
    functions = ('unobserved_http_response', 'unobserved_stream_body', 'unobserved_completed_output',
        '_diagnostic_pins', '_transport_substage', '_transport_failure', '_secondary_without_replacement',
        '_check', '_json', '_request_profile', 'build_request_body', '_closed_schema', 'validate_final_request', '_close_http')
    methods = ('__init__', 'request_profile', '_source', '_send', 'propose', '_emitted_for', '_provider_wait')
    ns = extract(sources[TRANSPORT], TRANSPORT, constants=constants, functions=functions,
        classes={'PlanTransportError': None, 'OpenAIPlanTransport': methods},
        extra=dict(common, __builtins__=closed_builtins, Draft202012Validator=Draft202012Validator,
            ProposalObservation=observations['ProposalObservation'], project_error=diag['project_error'],
            record_secondary=diag['record_secondary'], unobserved_stream_event=lambda: None,
            project_stream_event=no_stream, bind_stream_event=lambda *a, **k: None,
            _sse_lines=lambda *a, **k: (), consume_sse=stream_complete,
            ROLE_CONTEXT_VERSION='radik.role_context.v01'))
    results = []
    retained_errors = []
    for case in ('pre_http', 'postterminal_local', 'valid_critic', 'primary_plus_cleanup'):
        calls, persisted, finished = [], [], []
        class Deadline:
            def __init__(self, connection, seconds):
                self.expired = SimpleNamespace(is_set=lambda: False)
                self.deadline = time.monotonic() + 60
            def bind(self, sock): calls.append('deadline_bind')
            def apply_remaining_timeout(self): calls.append('deadline_apply')
            def finish(self):
                calls.append('deadline_finish')
                if case == 'primary_plus_cleanup':
                    def broken_projection(*args, **kwargs):
                        raise RuntimeError('SECRET_DIAGNOSTIC_TEXT')
                    ns['project_error'] = broken_projection
                    raise KeyboardInterrupt('SECRET_CLEANUP_TEXT')
                return True
        ns['_Deadline'] = Deadline
        class Connection:
            host, port, sock = 'api.openai.com', 443, object()
            def connect(self): calls.append('connect')
            def request(self, *a, **k):
                calls.append('request')
                if case in ('pre_http', 'primary_plus_cleanup'): raise OSError('SECRET_REQUEST_TEXT')
            def getresponse(self):
                calls.append('getresponse')
                return SimpleNamespace(status=200, close=lambda: calls.append('response_close'))
            def close(self): calls.append('connection_close')
        connection = Connection()
        grant = SimpleNamespace(access_token='SYNTHETIC_NOT_A_CREDENTIAL', expires_at=int(time.time())+600,
            scopes=('chatgpt.tokens.use.direct',), connection_id='inert_boundary_connection')
        class Budget:
            def reserve(self, **kwargs):
                calls.append('reserve'); return 'boundary-call:' + case
            def finish(self, attempt_id, **kwargs):
                calls.append('budget_finish'); finished.append(copy.deepcopy(kwargs))
                if case == 'primary_plus_cleanup': raise RuntimeError('SECRET_BUDGET_TEXT')
        transport = ns['OpenAIPlanTransport'](project=PROJECT,
            auth=SimpleNamespace(access_for_plan=lambda: grant), budget=Budget(), observation_directory='unused',
            source_validator=lambda: dict(pins), admission_validator=lambda **k: True)
        transport._catalog = dict(observed_at=int(time.time()), source_identity_sha256=source_sha,
            requested_effort='high', selected_model='gpt-6.1-sol')
        transport._grant = grant
        transport._connection = lambda: connection
        transport._guard_observed = lambda *a, **k: calls.append('synthetic_guard_observed')
        def prepare(response, *, metadata, **kwargs):
            calls.append('synthetic_http_metadata'); metadata.update(observation='OBSERVED', status=200)
        transport._prepare_http_response = prepare
        def save(name, value):
            calls.append('persist_' + name.split('_')[0])
            copied = json.loads(canonical(value)); persisted.append(copied)
            persist(case + '_' + name, copied)
        transport._persist = save
        real_observation = observations['ProposalObservation']
        def fail_observation(**kwargs): raise ValueError('dynamic_current_sources_changed')
        ns['ProposalObservation'] = fail_observation if case == 'postterminal_local' else real_observation
        error = None
        try:
            observation = transport.propose(role='critic', context=context, output_schema=schema,
                role_request=RoleRequest())
        except ns['PlanTransportError'] as caught:
            error = caught; retained_errors.append(caught)
        last = persisted[-1]
        require(len(finished) == 1 and len(persisted) == 2 and 'connection_close' in calls
            and 'deadline_finish' in calls, 'boundary_finalizers_attempted')
        require(last['dispatch_may_have_started'] is True, 'boundary_dispatch_evidence')
        if case == 'valid_critic':
            require(error is None and observation.value == product and last['outcome'] == 'COMPLETED'
                and last['completed_output']['role_product_accepted'] is True
                and len(transport.observations) == 1, 'boundary_valid_critic_product')
        else:
            expected_terminal = case == 'postterminal_local'
            expected_code = 'plan_completed_local_product_failed' if expected_terminal else 'plan_dispatch_or_stream_uncertain'
            require(error is not None and error.code == expected_code and error.terminal_observed == expected_terminal
                and last['terminal_observed'] == expected_terminal
                and last['outcome'] == ('FAILED' if expected_terminal else 'UNKNOWN'), 'boundary_primary_classification')
            failure = error.transport_failure
            require(failure == last['transport_failure'] and failure['original_type'] ==
                ('ValueError' if expected_terminal else 'OSError')
                and failure['original_code'] == ('dynamic_current_sources_changed' if expected_terminal
                    else 'SANITIZED_OPERATION_FAILURE')
                and failure['substage'] == ('OBSERVATION_BUILD' if expected_terminal else 'REQUEST_SEND')
                and failure['failure_category'] == ('POSTTERMINAL_LOCAL' if expected_terminal else 'PRETERMINAL_UNCERTAIN')
                and failure['source_frames'] and diag['project_transport_failure'](failure, source_pins=pins) == failure,
                'boundary_original_diagnostic')
            require('SECRET_' not in canonical(last).decode(), 'boundary_secret_projection')
            if not expected_terminal: require('getresponse' not in calls, 'boundary_pre_http_evidence')
            if case == 'primary_plus_cleanup':
                projected = diag['project_error'](error)
                require(len(projected['secondary_failures']) == 4
                    and projected['secondary_failures'][0]['type'] == 'KeyboardInterrupt'
                    and projected['primary_preserved'] is True
                    and projected['code'] == expected_code, 'boundary_cleanup_primary_preserved')
        results.append(dict(case=case, status='PASS', calls=calls,
            outcome=last['outcome'], terminal_observed=last['terminal_observed'],
            dispatch_may_have_started=last['dispatch_may_have_started'],
            diagnostic=last.get('transport_failure'), failure_observation=last.get('failure_observation'),
            independent_failure_projection=diag['project_error'](error) if error is not None else None))
    # The exact app and owner projections must reject arbitrary text and bad pins.
    failure = retained_errors[0].transport_failure
    mutations = []
    for name, mutate in (
        ('unknown_text_field', lambda v: v.update(raw_error='SECRET_PAYLOAD')),
        ('unknown_category', lambda v: v.update(failure_category='SECRET_PAYLOAD')),
        ('unknown_error_code', lambda v: v.update(original_code='SECRET_PAYLOAD')),
        ('frame_pin_mismatch', lambda v: v['source_frames'][0].update(sha256='0'*64)),
        ('frame_private_path', lambda v: v['source_frames'][0].update(path='private/secret.py'))):
        bad = copy.deepcopy(failure); mutate(bad)
        require(diag['project_transport_failure'](bad, source_pins=pins) is None, 'boundary_projection_negative')
        mutations.append(name)
    projected = diag['safe_projection'](dict(type='OSError', code='SECRET_PAYLOAD', secret='SECRET_PAYLOAD',
        transport_failure=dict(failure, raw_error='SECRET_PAYLOAD')))
    require('SECRET_' not in canonical(projected).decode() and 'transport_failure' not in projected,
        'boundary_safe_projection_text')
    scenario = extract(sources[SCENARIO], SCENARIO,
        constants=('STAGE05_SCENARIO_STAGES', 'STAGE05_NATIVE_STAGES', 'STAGE05_FRAME_FUNCTIONS'),
        functions=('diagnostic_source_pins', '_failure_context'),
        extra=dict(common, require=require, project_transport_failure=diag['project_transport_failure']))
    context_failure = scenario['_failure_context'](PROJECT, dict(pins=pins, native_files={}),
        retained_errors[0], 'UNRELATED_TASK')
    require(context_failure['transport_failure'] == failure, 'boundary_scenario_attachment')
    shown = []
    owner_pins = dict(pins, **{'app/stage04_diagnostics.py': digest(sources[DIAGNOSTICS])})
    def pinned_registry(path):
        require(path == PROJECT / 'app/stage04_diagnostics.py', 'boundary_owner_registry_read')
        return sources[DIAGNOSTICS], None
    owner = extract(sources[OWNER], OWNER,
        constants=('STAGE05_SCENARIO_STAGES', 'STAGE05_NATIVE_STAGES', 'STAGE05_FRAME_FUNCTIONS'),
        functions=('transport_diagnostic_tables', 'terminal_transport_failure', 'stage05_failure_context'),
        extra=dict(common, PROJECT=PROJECT, ast=ast, hashlib=hashlib, require=require,
            read_bytes=pinned_registry, show=shown.append))
    owner_result = owner['stage05_failure_context'](dict(failure_context=context_failure, sequence=1), owner_pins)
    require(owner_result['transport_failure'] == failure and any('TRANSPORT_FAILURE' in line for line in shown)
        and all('SECRET_' not in line for line in shown), 'boundary_terminal_projection')
    bad = copy.deepcopy(failure); bad['source_frames'][0]['sha256'] = '0'*64
    try: owner['terminal_transport_failure'](bad, owner_pins)
    except ValueError: pass
    else: raise ValueError('boundary_terminal_bad_pin_accepted')
    # Recheck every admitted source after execution; no candidate source was mutated.
    for ref in refs: exact(ref)
    result = dict(schema='radik.stage05.transport_boundary_controls.v01', status='PASS',
        series_count=1, cases=results, negative_projection_cases=mutations,
        scenario_attachment='PASS', terminal_renderer='PASS', terminal_lines=shown,
        source_refs=proposal['source_refs'],
        dependency_modules=sorted(dependency_modules, key=lambda r:r['module']),
        elapsed_seconds=time.monotonic()-STARTED, owner_actual=False, provider_calls=0,
        real_AUTH=False, native_calls=0, effects=0, production_writes=False,
        scope='AST transport failure and product boundary only; actual strict saved Critic schema validation.',
        test_doubles=['RoleRequest/current-context/admission', 'Auth/grant', 'catalog', 'HTTP connection/metadata',
            'SSE completed parser result', 'budget', 'deadline/watchdog', 'owner registry read routed to exact candidate bytes'],
        historical_data_authority_restored=False, failed_Alder_product_available=False,
        interface_calls=interface_calls, source_pins_unchanged=True, owner_ready=False)
    reference = persist('result.json', result)
    print('TRANSPORT_BOUNDARY_CONTROLS ' + json.dumps(dict(status='PASS', result_ref=reference)), flush=True)


if __name__ == '__main__':
    main()
