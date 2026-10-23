"""Pass one independently selected local SOURCE/actual payload to the old publisher.

This packaging adapter imports no application module and grants no execution.
It preserves the existing publisher's reservation, checksum and delivery rules.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage07_pure_capability_passage/v01'
SELF = BASE + '/return_package/build_return.py'
PUBLISHER = 'review/package_direct_plan_return.py'
REPORT_ROOT = Path('/Users/admin/Downloads/Radik/stage07_pure_capability_v01')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(reference, *, external=False):
    name = reference['path']
    path = Path(name) if external else PROJECT / name
    root = REPORT_ROOT if external else PROJECT
    require(path.is_absolute() and path.is_relative_to(root), 'return_selection_owned_path')
    relative = path.relative_to(root)
    require(relative.parts and all(part not in ('..', '.', '.git', 'private', '.codex', '.aws',
        '.venv', '.venv-plan', 'Arena', 'arena', 'credentials.json', 'tokens.json',
        'local_operator', 'local_operator_private', '.settings', '.env')
        and not part.startswith('.env.') for part in relative.parts), 'return_selection_path_scope')
    for node in (path, *path.parents):
        require(not node.is_symlink(), 'return_selection_symlink')
        if node == root:
            break
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= 67108864, 'return_selection_regular_file')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    require(identity(after) == identity(before) and len(raw) == reference['size_bytes'] == before.st_size
        and digest(raw) == reference['sha256'], 'return_selection_changed')
    return raw


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _public_field_shape(parent, key, kind, pointer):
    """Exact deterministic Root claims and empty native diagnostics only."""
    if kind == 'EMPTY_PREPARATION_DIAGNOSTIC':
        require(key == 'stderr' and parent[key] == '', 'return_public_empty_diagnostic')
        return
    if kind == 'STAGE07_EMPTY_NATIVE_WORKER_STDERR':
        fields = {'configuration_sha256','elapsed_seconds','engine_version','measured_fuel',
            'phase','process_reaped','profile_version','reason','return_code','status',
            'stderr','stdout','trials','wasm'}
        require(key == 'stderr' and set(parent) == fields
            and parent['engine_version'] == '48.0.0'
            and parent['profile_version'] == 'pure-i32-closed-v01'
            and parent['status'] in ('SUCCEEDED','REFUSED')
            and parent[key] == {'encoding':'base64','bytes':'','sha256':digest(b''),'size_bytes':0},
            'return_public_empty_worker_diagnostic')
        return
    require(kind == 'STAGE07_CURRENT_ROOT_CLAIM' and key == 'subject', 'return_public_field_kind')
    fields = {'claim_id','subject','predicate','object_or_value','time_envelope_ref',
        'provenance_refs','evidence_refs','confidence_micros','source_role','source_mode','authority_class'}
    require(set(parent) == fields and parent['source_role'] == 'deterministic_runtime'
        and parent['source_mode'] == 'DETERMINISTIC' and parent['authority_class'] == 'NONE'
        and type(parent['confidence_micros']) is int and parent['confidence_micros'] == 1000000
        and type(parent[key]) is str
        and (parent[key] == 'radik:archive_shelf'
            or re.fullmatch(r'drsaddr_v01:[0-9a-f]{64}', parent[key]) is not None
            or re.fullmatch(r'task:radik:stage07:[0-9a-f]{32}:(cold|warm|controls|disabled)', parent[key]) is not None
            or re.fullmatch(r'root:radik:stage07:([0-9a-f]{32}|[a-p]{32})', parent[key]) is not None)
        and re.search(r'/root_review_packet/synthesis_proposal/normalized_claims/[0-9]+/subject$', pointer) is not None
        and all(type(parent[name]) is str and parent[name] for name in ('claim_id','predicate','time_envelope_ref'))
        and all(type(parent[name]) is list and all(type(item) is str for item in parent[name])
            for name in ('provenance_refs','evidence_refs')),
        'return_public_stage07_claim')


def _exceptions(review, publisher_ref):
    raw = exact(review['public_field_inventory_ref'])
    value = json.loads(raw)
    require(value['schema'] == 'radik.stage07.exact_public_fields.v1'
        and value['publisher_ref'] == publisher_ref and len(value['entries']) <= 20000,
        'return_public_field_inventory')
    entries = {}
    for entry in value['entries']:
        ref, pointer = entry['file_ref'], entry['json_pointer']
        require(ref['path'].startswith(BASE + '/') and ref['path'].endswith('.json')
            and pointer.startswith('/') and pointer.rsplit('/',1)[-1] in ('subject','stderr'),
            'return_public_field_scope')
        identity = ref['path'], pointer
        require(identity not in entries, 'return_public_field_duplicate')
        entries[identity] = entry
    return entries, raw


def _scan_json(publisher, value, reference, exceptions, used):
    source_ref = {key: reference[key] for key in ('path', 'sha256', 'size_bytes')}
    def walk(item, path=(), depth=0):
        require(depth <= 96, 'return_observation_json_depth')
        if type(item) is list:
            return [walk(child, path+(index,), depth+1) for index,child in enumerate(item)]
        if type(item) is not dict: return item
        result = {}
        for key,child in item.items():
            pointer = '/'+'/'.join(str(part).replace('~','~0').replace('/','~1') for part in path+(key,))
            identity = source_ref['path'], pointer
            entry = exceptions.get(identity)
            if entry is None:
                result[key] = walk(child, path+(key,), depth+1)
                continue
            require(source_ref == entry['file_ref'] and digest(canonical(child)) == entry['value_sha256']
                and digest(canonical(item)) == entry['containing_object_sha256'], 'return_public_field_exact_binding')
            _public_field_shape(item, key, entry['kind'], pointer)
            publisher._no_secrets(walk(child, path+(key,), depth+1))
            used.add(identity)
        return result
    publisher._no_secrets(walk(value))


def current_reviewer_matches(record, read_reference, binding_path):
    """Bind current grants to the owner's exact reviewer designation.

    This is a pinned local record boundary, not a cryptographic identity proof.
    Historical reviews keep their original author and are checked separately.
    """
    reference = record.get('reviewer_binding_ref')
    if type(reference) is not dict or reference.get('path') != str(binding_path):
        return False
    binding = json.loads(read_reference(reference))
    reviewer = binding.get('reviewer')
    return (binding.get('schema') == 'radik.stage07.reviewer_binding.v1'
        and binding.get('status') == 'OWNER_DESIGNATED_CURRENT_REVIEWER'
        and binding.get('scope') == 'STAGE07_V01'
        and binding.get('source_authors') == ['/root', '/root/stage05_g4_contract']
        and type(reviewer) is str and 1 <= len(reviewer) <= 160
        and reviewer.isascii()
        and all(char.isalnum() or char in '/_-.@:' for char in reviewer)
        and reviewer not in binding['source_authors']
        and reviewer != '/root/private_remote_controls'
        and record.get('reviewer') == reviewer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--review-sha256', required=True)
    args = parser.parse_args()
    review_path = PROJECT / BASE / 'return_packaging_review.json'
    review_raw = review_path.read_bytes()
    require(digest(review_raw) == args.review_sha256, 'return_packaging_review_changed')
    review = json.loads(review_raw)
    require(current_reviewer_matches(review, exact, PROJECT/BASE/'reviewer_binding.json')
        and review['status'] == 'ACCEPTED_FOR_ONE_LOCAL_SOURCE_ACTUAL_RETURN'
        and review['approved_executor'] == '/root'
        and review['approved_invocation_count'] == 1
        and review['public_push_authorized'] is False, 'return_packaging_grant')
    for reference in review['writer_refs']:
        exact(reference)
    require({row['path'] for row in review['writer_refs']} == {SELF, PUBLISHER},
        'return_packaging_writer_closure')
    publisher_ref = next(row for row in review['writer_refs'] if row['path'] == PUBLISHER)
    publisher_raw = exact(publisher_ref)
    publisher = types.ModuleType('radik_stage07_existing_return_publisher')
    publisher.__file__ = str(PROJECT / PUBLISHER)
    exec(compile(publisher_raw, publisher.__file__, 'exec', dont_inherit=True), publisher.__dict__)
    selection = json.loads(exact(review['selection_ref']))
    require(selection['publication'] == 'LOCAL_ONLY' and 1 <= len(selection['files']) <= 4096,
        'return_selection_finite_local_scope')
    exceptions, exception_raw = _exceptions(review, publisher_ref)
    used_exceptions = set()
    payload = {}
    total = 0
    review_archive_path = 'reviewed_basis/' + BASE + '/return_packaging_review.json'
    for row in selection['files']:
        name = row['archive_path']
        require(type(name) is str and name and name != '.', 'return_selection_archive_name')
        path = Path(name)
        require(name == path.as_posix() and not path.is_absolute() and '..' not in path.parts
            and not publisher.excluded(path.parts) and name not in payload
            and name not in ('manifest.json', review_archive_path),
            'return_selection_archive_scope')
        source_suffix = Path(row['path']).suffix
        require(source_suffix not in ('.json', '.jsonl') or path.suffix == source_suffix,
            'return_selection_json_suffix_preserved')
        raw = exact(row, external=row.get('external_owner_report') is True)
        if path.suffix == '.json':
            _scan_json(publisher, json.loads(raw), row, exceptions, used_exceptions)
        elif path.suffix == '.jsonl':
            for line in raw.splitlines():
                if line.strip():
                    publisher._no_secrets(json.loads(line))
        total += len(raw)
        require(total <= 536870912, 'return_selection_total_bound')
        payload[name] = raw
    require(used_exceptions == set(exceptions), 'return_subject_unused_exception')
    payload[review_archive_path] = review_raw
    if exception_raw is not None:
        exception_archive_path = 'reviewed_basis/' + BASE + '/public_field_inventory.json'
        require(exception_archive_path not in payload, 'return_subject_inventory_archive_collision')
        payload[exception_archive_path] = exception_raw
    result = publisher._build(kind='source', key='stage07_pure_capability_v01',
        payload=payload, record=review, review_raw=review_raw,
        basis=selection['basis'], prior=selection['prior_archives'])
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
