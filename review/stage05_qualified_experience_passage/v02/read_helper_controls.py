"""Narrow AST-extracted stable-read controls; no application or native imports."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

ROOT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage05_qualified_experience_passage/v02'
SELF = BASE + '/read_helper_controls.py'
RUNNER = BASE + '/rehearsal_runner.py'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
          'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_atime', 'st_atime_ns')


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def extracted(raw):
    names = {'require', 'sha', 'safe_path', 'check_deadline', 'read', 'verify', 'put'}
    nodes = [node for node in ast.parse(raw, filename=RUNNER).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    require({node.name for node in nodes} == names, 'control_function_closure')
    return compile(ast.Module(body=nodes, type_ignores=[]), RUNNER, 'exec')


def namespace(code, changed_field=None):
    calls = []

    def observed(fd):
        value = os.fstat(fd)
        row = {field: getattr(value, field) for field in FIELDS}
        calls.append(row.copy())
        if len(calls) == 2 and changed_field is not None:
            row[changed_field] += 1
            if changed_field == 'st_atime_ns':
                row['st_atime'] += 1e-9
        return SimpleNamespace(**row)

    proxy = SimpleNamespace(**{name: getattr(os, name) for name in (
        'open', 'fdopen', 'fsync', 'O_RDONLY', 'O_WRONLY', 'O_CREAT',
        'O_EXCL', 'O_NOFOLLOW', 'O_NONBLOCK')}, fstat=observed)
    ns = dict(os=proxy, Path=Path, stat=stat, hashlib=hashlib,
              time=SimpleNamespace(monotonic_ns=lambda: 1),
              ACTIVE_DEADLINE_NS=2, MAX_BYTES=64*1024*1024)
    exec(code, ns)
    return ns, calls


def expect_code(callback, code):
    try:
        callback()
    except ValueError as error:
        require(error.args == (code,), 'control_wrong_refusal')
    else:
        raise ValueError('control_missing_refusal')


def run_controls(raw, scratch):
    code = extracted(raw)
    original = b'original'
    results = []
    ns, calls = namespace(code)
    reference = ns['put'](scratch, 'baseline.bin', original)
    require(reference == dict(path='baseline.bin', sha256=sha(original), size_bytes=8)
            and len(calls) == 2, 'control_put_readback')
    results.append(dict(case='ACTUAL_SMALL_FILE_WRITE_AND_EXACT_READBACK', outcome='PASS'))

    for field in ('st_atime_ns', 'st_dev', 'st_ino', 'st_mode', 'st_nlink',
                  'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
        ns, calls = namespace(code, field)
        if field == 'st_atime_ns':
            require(ns['verify'](scratch, reference) == original, 'control_atime_only_rejected')
            outcome = 'ACCEPTED_EXACT_BYTES_AND_HASH'
        else:
            expect_code(lambda: ns['verify'](scratch, reference), 'exam_read_stability')
            outcome = 'REFUSED_EXAM_READ_STABILITY'
        require(len(calls) == 2, 'control_two_fstat_observations')
        results.append(dict(case='SYNTHETIC_SECOND_FSTAT_' + field.upper(), outcome=outcome))

    (scratch / 'changed.bin').write_bytes(b'changed!')
    ns, _calls = namespace(code)
    expect_code(lambda: ns['verify'](scratch, dict(reference, path='changed.bin')),
                'exam_reference_changed')
    results.append(dict(case='ACTUAL_SAME_SIZE_CONTENT_DIFFERS_FROM_PIN',
                        outcome='REFUSED_EXAM_REFERENCE_CHANGED'))

    ns, _calls = namespace(code)
    ns['read'] = lambda _root, _name: b'changed!'
    expect_code(lambda: ns['put'](scratch, 'readback.bin', original), 'exam_write_readback')
    results.append(dict(case='SYNTHETIC_READBACK_BYTES_DIFFER', outcome='REFUSED_EXAM_WRITE_READBACK'))
    return results


def install_fence(output):
    def audit(event, args):
        if event.startswith('socket.') or event in (
                'subprocess.Popen', 'os.system', 'os.fork', 'os.posix_spawn'):
            raise ValueError('control_network_or_process_forbidden')
        if event == 'open' and args and isinstance(args[0], (str, bytes, Path)):
            path = Path(args[0]).absolute()
            require(not set(path.parts).intersection(('private', '.codex', '.aws', 'Arena', 'arena')),
                    'control_private_read_forbidden')
            mode, flags = args[1:3]
            writing = isinstance(mode, str) and any(char in mode for char in 'wax+')
            writing = writing or isinstance(flags, int) and bool(flags & (1 | 2 | 64 | 512 | 1024))
            require(not writing or path.is_relative_to(output), 'control_write_scope')
        if event in ('os.mkdir', 'os.remove', 'os.unlink', 'os.rmdir', 'os.rename', 'os.chmod'):
            for item in (args[:2] if event == 'os.rename' else args[:1]):
                if isinstance(item, (str, bytes, Path)):
                    require(Path(item).absolute().is_relative_to(output), 'control_mutation_scope')
    sys.addaudithook(audit)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant-sha256', required=True)
    args = parser.parse_args()
    grant_raw = (ROOT / BASE / 'read_helper_control_grant.json').read_bytes()
    require(sha(grant_raw) == args.grant_sha256, 'control_grant_identity')
    grant = json.loads(grant_raw)
    require(grant['reviewer'] == '/root/private_remote_controls'
            and grant['status'] == 'ACCEPTED_ONE_AST_READ_HELPER_CONTROL'
            and grant['approved_executor'] == '/root'
            and grant['approved_invocation_count'] == 1
            and grant['network'] == 'DENIED'
            and grant['application_native_model_AUTH_E_SAVE_execution_allowed'] is False,
            'control_independent_grant')
    sources = {}
    require(len(grant['source_refs']) == 2
            and {ref['path'] for ref in grant['source_refs']} == {SELF, RUNNER},
            'control_exact_source_closure')
    for ref in grant['source_refs']:
        raw = (ROOT / ref['path']).read_bytes()
        require(len(raw) == ref['size_bytes'] and sha(raw) == ref['sha256'], 'control_source_pin')
        sources[ref['path']] = raw
    output = ROOT / BASE / 'read_helper_control_actual' / 'READ_HELPER_V01'
    output.mkdir(parents=True, exist_ok=False)
    install_fence(output)
    (output / 'reservation.json').write_bytes(canonical(dict(grant_sha256=args.grant_sha256, retry=False)))
    scratch = output / 'scratch'
    scratch.mkdir()
    result = dict(status='PASS_AST_READ_HELPER_CONTROL_ONLY', cases=run_controls(sources[RUNNER], scratch),
        application_imports=0, native_calls=0, provider_calls=0, process_calls=0,
        real_alarms=0, historical_stat_change_identified=False,
        scope='Synthetic fstat deltas and three finite scratch files; no historical cause recovery.')
    raw = canonical(result)
    with (output / 'result.json').open('xb') as stream:
        stream.write(raw)
    require((output / 'result.json').read_bytes() == raw, 'control_result_readback')
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
