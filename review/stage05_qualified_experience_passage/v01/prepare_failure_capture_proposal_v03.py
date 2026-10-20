"""Source-only construction of a reviewed failure-capture proposal; no imports of candidates."""
import ast
import difflib
import hashlib
import json
from pathlib import Path
import re

BASE = Path('review/stage05_qualified_experience_passage/v01')
manifest = json.loads((BASE/'ordinary_profile_manifest.json').read_text())
paths = [BASE/'after/app/stage04_diagnostics.py', BASE/'after/app/qualified_experience_scenario.py', BASE/'owner_terminal.py', BASE/'rehearsal_runner.py']
before = {str(p): p.read_text() for p in paths}
after = dict(before)
provenance = {}
node = next(n for n in ast.parse(before[str(paths[0])]).body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'OWNED_ERROR_CODES' for t in n.targets))
old_codes = set(ast.literal_eval(node.value.args[0]))
for name in ('hedgehog/kernel/work_composition_v01.py', 'hedgehog/work_execution_host_v01.py'):
    ref = manifest['native_files'][name]
    raw = Path(ref['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ref['sha256']
    for item in ast.walk(ast.parse(raw)):
        if not isinstance(item, ast.Call): continue
        called = item.func.id if isinstance(item.func, ast.Name) else ''
        index = 1 if called in ('_require', 'require', '_native_require') else 0 if called == 'ValueError' else None
        if index is None or len(item.args) <= index or not isinstance(item.args[index], ast.Constant): continue
        value = item.args[index].value
        if type(value) is not str or not re.fullmatch('[A-Za-z][A-Za-z0-9_:./-]{1,160}', value): continue
        if value not in old_codes:
            provenance.setdefault(value, []).append(dict(source_ref=ref, line=item.lineno, literal_call=called))
after[str(paths[0])] = before[str(paths[0])].replace('OWNED_ERROR_CODES = frozenset({\n', 'OWNED_ERROR_CODES = frozenset({\n' + ''.join('    '+repr(code)+',\n' for code in sorted(set(provenance) | {'stage05_failure_source_identity'})), 1)

constants = '''STAGE05_SCENARIO_STAGES = frozenset((
    'UNKNOWN', 'ORDINARY_TASK', 'COLD_DECISION', 'PROSPECTIVE_FEEDBACK',
    'SUBSEQUENT_WORK', 'CAUSAL_CHECKS', 'UNSCORABLE_CONTROL',
    'ELIGIBILITY_CONTROLS', 'FINALIZATION',
))
STAGE05_NATIVE_STAGES = frozenset((
    'UNKNOWN', 'G4_BOOTSTRAP_ADVANCE', 'G4_BOOTSTRAP_ARTIFACT', 'G4_HISTORY',
    'G4_ALLOCATION', 'G4_TASK_ROOT', 'G4_REVISION', 'G4_PRE_DISPATCH_PERSISTENCE',
    'G4_ALLOCATED_ADVANCE', 'G4_ALLOCATED_ARTIFACT', 'G4_FINAL_CHECKS', 'G4_CUSTODY',
))
STAGE05_FRAME_FUNCTIONS = frozenset(('<module>', '<lambda>', '<genexpr>',
    '<listcomp>', '<dictcomp>', '<setcomp>'))


def diagnostic_source_pins(manifest):
    """Use only the finite independently admitted application and native paths."""
    result = {path: value for path, value in manifest['pins'].items() if path.endswith('.py')}
    for item in manifest['native_files'].values():
        path, value = item['path'], item['sha256']
        if path.endswith('.py'):
            require(path not in result or result[path] == value, 'stage05_failure_source_identity')
            result[path] = value
    require(len(result) <= 4096 and all(type(path) is str and path == Path(path).as_posix()
        and not Path(path).is_absolute() and not any(part in ('.', '..', 'private', '.git')
        for part in Path(path).parts) and len(path) <= 1024 and type(value) is str
        and re.fullmatch('[0-9a-f]{64}', value) for path, value in result.items()),
        'stage05_failure_source_identity')
    return result


'''
helper = '''def _failure_context(project, manifest, error, scenario_stage):
    """Retain bounded admitted frame coordinates, never error text or frame locals."""
    pins = diagnostic_source_pins(manifest)
    frames = []
    skipped = 0
    visited = 0
    cursor = error.__traceback__
    while cursor is not None and visited < 128:
        visited += 1
        try:
            relative = Path(cursor.tb_frame.f_code.co_filename).absolute().relative_to(project.absolute()).as_posix()
        except (ValueError, OSError):
            relative = None
        if relative in pins:
            function = cursor.tb_frame.f_code.co_name
            if (type(function) is not str or len(function) > 96 or not
                    (re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', function)
                     or function in STAGE05_FRAME_FUNCTIONS)):
                function = 'UNKNOWN'
            line = cursor.tb_lineno
            if type(line) is int and 1 <= line <= 1000000:
                frames.append(dict(path=relative, sha256=pins[relative], line=line, function=function))
            else:
                skipped += 1
        else:
            skipped += 1
        cursor = cursor.tb_next
    try:
        native = getattr(error, '_radik_stage05_native_stage', None)
    except BaseException:
        native = None
    return dict(schema='radik.stage05.failure_context.v01',
        scenario_stage=scenario_stage if scenario_stage in STAGE05_SCENARIO_STAGES else 'UNKNOWN',
        native_stage=native if type(native) is str and native in STAGE05_NATIVE_STAGES else 'UNKNOWN',
        source_frames=frames[-32:], omitted_frames=max(0, len(frames)-32),
        unadmitted_frames=skipped, traceback_truncated=cursor is not None,
        raw_error_recorded=False, locals_recorded=False)


'''
text = before[str(paths[1])].replace('import json\n', 'import json\nimport re\n', 1)
text = text.replace('from .native_authority import plain\n', 'from .native_authority import plain\nfrom .stage04_diagnostics import observe_failure, project_error, record_secondary\n', 1)
text = text.replace('\ndef run(*,', '\n'+constants+helper+'def run(*,', 1)
text = text.replace('    @contextmanager\n    def phase(name):\n', "    scenario_stage = 'ORDINARY_TASK'\n\n    @contextmanager\n    def phase(name):\n        nonlocal scenario_stage\n        scenario_stage = name.upper()\n        primary = None\n", 1)
text = text.replace('''        try:
            yield
        finally:
            if event_sink is not None:
                event_sink(dict(kind='PHASE_EXIT', phase='NATIVE', span_id='stage05_'+name, native=True))
            report.setdefault('native_phase_measurements', []).append(
                dict(phase=name, elapsed_wall_ns=time.monotonic_ns()-started))
''', '''        try:
            yield
        except BaseException as error:
            primary = error
            observe_failure(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
            raise
        finally:
            try:
                report.setdefault('native_phase_measurements', []).append(
                    dict(phase=name, elapsed_wall_ns=time.monotonic_ns()-started))
                if event_sink is not None:
                    event_sink(dict(kind='PHASE_EXIT', phase='NATIVE', span_id='stage05_'+name, native=True))
            except BaseException as secondary:
                if primary is None:
                    raise
                record_secondary(primary, secondary, phase='TERMINAL_OUTPUT', step='STAGE05_EXPERIENCE')
''', 1)
text = text.replace("        require(feedback['feedback']['update_eligibility']", "        scenario_stage = 'CAUSAL_CHECKS'\n        require(feedback['feedback']['update_eligibility']", 1)
text = text.replace("        final = client.budget.snapshot()", "        scenario_stage = 'FINALIZATION'\n        final = client.budget.snapshot()", 1)
text = text.replace('''    except BaseException as error:
        from .stage04_diagnostics import project_error, observe_failure
        observe_failure(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        report['status'] = 'STOPPED_NO_RETRY'
        report['primary_failure'] = project_error(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        try:
            persist(output, 'stopped_result', report)
        except Exception:
            pass
        raise
''', '''    except BaseException as error:
        observe_failure(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        report['status'] = 'STOPPED_NO_RETRY'
        detail = dict(schema='radik.stage05.failure_context.v01', scenario_stage='UNKNOWN',
            native_stage='UNKNOWN', source_frames=[], omitted_frames=0, unadmitted_frames=0,
            traceback_truncated=False, raw_error_recorded=False, locals_recorded=False)
        try:
            detail = _failure_context(project, manifest, error, scenario_stage)
        except BaseException as secondary:
            record_secondary(error, secondary, phase='NATIVE_SNAPSHOT', step='STAGE05_EXPERIENCE')
        report['failure_context'] = detail
        report['primary_failure'] = project_error(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        ref = None
        try:
            ref = persist(output, 'stopped_result', report)
        except BaseException as secondary:
            record_secondary(error, secondary, phase='CONNECTED_REPORT_WRITE', step='STAGE05_EXPERIENCE')
        projected = project_error(error, phase='TASK_EXECUTION', step='STAGE05_EXPERIENCE')
        try:
            if event_sink is not None:
                attachment = dict(readback_ref=ref) if ref is not None else {}
                event_sink(dict(kind='PRIMARY_FAILURE', phase='FINALIZATION', stage='STAGE05_FAILURE',
                    failure=dict(phase='STAGE05_EXPERIENCE', error_class=projected['type'], code=projected['code']),
                    failure_context=detail, **attachment))
        except BaseException as secondary:
            record_secondary(error, secondary, phase='TERMINAL_OUTPUT', step='STAGE05_EXPERIENCE')
        raise
''', 1)
after[str(paths[1])] = text

owner_helper = '''def stage05_failure_context(row, source_pins):
    """Validate the exact-child attachment before displaying safe source coordinates."""
    value = row.get('failure_context')
    require(type(value) is dict and set(value) == {'schema', 'scenario_stage', 'native_stage',
        'source_frames', 'omitted_frames', 'unadmitted_frames', 'traceback_truncated',
        'raw_error_recorded', 'locals_recorded'}
        and value['schema'] == 'radik.stage05.failure_context.v01'
        and type(value['scenario_stage']) is str and value['scenario_stage'] in STAGE05_SCENARIO_STAGES
        and type(value['native_stage']) is str and value['native_stage'] in STAGE05_NATIVE_STAGES
        and value['raw_error_recorded'] is False and value['locals_recorded'] is False
        and type(value['traceback_truncated']) is bool
        and type(value['source_frames']) is list and len(value['source_frames']) <= 32
        and all(type(value[key]) is int and 0 <= value[key] <= 128
            for key in ('omitted_frames', 'unadmitted_frames')), 'terminal_stage05_failure_context')
    frames = []
    for frame in value['source_frames']:
        require(type(frame) is dict and set(frame) == {'path', 'sha256', 'line', 'function'}
            and type(frame['path']) is str and frame['path'] in source_pins
            and type(frame['sha256']) is str and frame['sha256'] == source_pins[frame['path']]
            and type(frame['line']) is int and 1 <= frame['line'] <= 1000000
            and type(frame['function']) is str and len(frame['function']) <= 96
            and (re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', frame['function'])
                or frame['function'] in STAGE05_FRAME_FUNCTIONS), 'terminal_stage05_failure_frame')
        frames.append(dict(frame))
    result = dict(value, source_frames=frames, event_sequence=row['sequence'],
        reference_readback_verified=False)
    show('STAGE05_FAILURE_CONTEXT scenario='+value['scenario_stage']+' native='+value['native_stage'])
    for frame in frames:
        show('SOURCE_FRAME '+frame['path']+':'+str(frame['line'])+' '+frame['function']+' sha256='+frame['sha256'])
    return result


'''
text = before[str(paths[2])].replace('def required_witness_diagnostic(', constants+owner_helper+'def required_witness_diagnostic(', 1)
text = text.replace("                        verified = False;witness = None\n", """                        failure_context = None
                        if kind == 'PRIMARY_FAILURE' and row.get('stage') == 'STAGE05_FAILURE':
                            failure_context = stage05_failure_context(row, profile['diagnostic_source_pins'])
                            contexts = receipt.setdefault('stage05_failure_contexts', [])
                            require(len(contexts) < 16, 'terminal_stage05_failure_context_bound')
                            contexts.append(failure_context)
                        verified = False;witness = None
""", 1)
text = text.replace("                            sub['readbacks'].append(ref);sub['last_readback_ref']=ref;verified = True\n", """                            sub['readbacks'].append(ref);sub['last_readback_ref']=ref;verified = True
                            if failure_context is not None:
                                require(type(witness) is dict and type(witness.get('body')) is dict
                                    and witness['body'].get('failure_context') == row['failure_context'],
                                    'terminal_stage05_failure_readback_binding')
                                failure_context['reference_readback_verified'] = True
                                failure_context['readback_ref'] = dict(ref)
""", 1)
text = text.replace('            scenario_inputs=scenario_inputs,\n', '            scenario_inputs=scenario_inputs, diagnostic_source_pins=diagnostic_source_pins(manifest),\n', 1)
after[str(paths[2])] = text
text = before[str(paths[3])].replace("                home_directory=str(root.parent), rehearsal_seal_sha256=case['rehearsal_seal_ref']['sha256'],\n", "                home_directory=str(root.parent), rehearsal_seal_sha256=case['rehearsal_seal_ref']['sha256'],\n                diagnostic_source_pins=module.diagnostic_source_pins(manifest),\n", 1)
after[str(paths[3])] = text

# Source construction and syntax only. The postimages are not imported or executed.
for name, text in after.items():
    assert text != before[name], name
    ast.parse(text, filename=name)
patch = ''.join(''.join(difflib.unified_diff(before[name].splitlines(True), text.splitlines(True), fromfile=name, tofile=name)) for name, text in after.items())
for name, data in (
    ('stage05_failure_capture_proposed_v03.diff', patch.encode()),
    ('stage05_failure_native_literal_provenance_v03.json', (json.dumps(dict(schema='radik.stage05.failure_literal_provenance.v01', classification='SOURCE_ONLY_NOT_ACTUAL_CAUSE_RECOVERY', code_count=len(provenance), codes=provenance), indent=2, sort_keys=True)+'\n').encode()),
):
    with (BASE/name).open('xb') as stream: stream.write(data)
proposal = dict(schema='radik.stage05.failure_capture_proposal.v01', status='SOURCE_ONLY_REQUIRES_INDEPENDENT_REVIEW', supersedes='stage05_failure_capture_proposal_v02.json', author='/root/stage05_g3_contract', actual_V02_primary_cause='UNKNOWN_SANITIZED_NOT_RECOVERED', scope='No runtime execution, native contract changes, timer changes, authority restoration or provider calls.', candidates=[dict(path=name, before_sha256=hashlib.sha256(before[name].encode()).hexdigest(), proposed_sha256=hashlib.sha256(text.encode()).hexdigest()) for name,text in after.items()], native_literal_count=len(provenance), own_literal_additions=['stage05_failure_source_identity'], bounds=dict(traceback_nodes=128, retained_admitted_frames=32, source_pin_paths=4096, path_characters=1024, function_characters=96), frame_semantics='Manifest-pinned source coordinates from the current traceback; not a separate loaded-code attestation. Unadmitted frames have counts only. No locals, source lines, raw arguments, absolute paths, exception messages or dynamic wrapper parsing.', first_cause='Same original exception re-raised. PHASE_EXIT, context capture, stopped-result persistence and event emission failures are recorded as separate closed secondary projections. Parent retains primary before reading context/report.', terminal='Only exact-child STAGE05_FAILURE with closed stage labels and manifest-matching path/hash coordinates is displayed. Durable report readback is independently verified and marked; primary cause stays visible even if that read fails.', dependencies='G4 author attaches only the agreed 11 closed native stages via _radik_stage05_native_stage; owner and rehearsal supervisor receive a finite source map from their admitted manifest.', proposed_controls=['AST-only scenario phase-finally precedence and identical rethrow, exact closed native codes and sentinel sanitization.', 'AST-only bounded synthetic traceback projection: admitted/unadmitted paths, long stack and unknown native label.', 'AST-only supervisor attachment projection: accepted exact hashes, rejected mismatches, unknown label/frame, readback mismatch remains secondary.', 'Independently reviewed focused native G4 bootstrap control is separate from these observability changes.'])
proposal['artifacts'] = [dict(path=str(BASE/name),sha256=hashlib.sha256((BASE/name).read_bytes()).hexdigest(),size_bytes=(BASE/name).stat().st_size) for name in ('stage05_failure_capture_proposed_v03.diff','stage05_failure_native_literal_provenance_v03.json')]
with (BASE/'stage05_failure_capture_proposal_v03.json').open('x') as stream:json.dump(proposal,stream,indent=2,sort_keys=True);stream.write('\n')
for name in ('stage05_failure_capture_proposed_v03.diff','stage05_failure_capture_proposal_v03.json','stage05_failure_native_literal_provenance_v03.json'):
    raw=(BASE/name).read_bytes();print(name,hashlib.sha256(raw).hexdigest(),len(raw))
