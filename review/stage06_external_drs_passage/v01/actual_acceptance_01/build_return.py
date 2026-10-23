"""Pass one independently selected local SOURCE/actual payload to the old publisher.

This packaging adapter imports no application module and grants no execution.
It preserves the existing publisher's reservation, checksum and delivery rules.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import types

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage06_external_drs_passage/v01/actual_acceptance_01'
SELF = BASE + '/build_return.py'
PUBLISHER = 'review/package_direct_plan_return.py'
REPORT_ROOT = Path('/Users/admin/Downloads/Radik/stage06_actual_acceptance_01')


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


def _public_field_shape(parent, key, kind):
    """Exact public wire/current-Root fields, never authentication credentials."""
    if kind == 'EMPTY_PREPARATION_DIAGNOSTIC':
        require(key == 'stderr' and parent[key] == '', 'return_public_empty_diagnostic')
        return
    if kind == 'GATE5_PUBLIC_REQUEST_NONCE':
        fields = {
            'g51.request.v01': {'version','request_id','op','requester','publisher','task_ref','request_revision','pointer_ref','trust_profile_hash','use_class','object_id','allowed_size','nonce','deadline','issued_at','subject_request_ref','owner_transport_scope'},
            'g51.status.v01': {'version','entry','requested_pointer_hash','requester','subject_request_ref','request_revision','nonce','checked_at','valid_until'},
            'g51.release.v01': {'version','state','request_ref','request_revision','pointer_ref','manifest_ref','body_hash','recipient','use_class','nonce','deadline','release_review_ref'},
        }
        value = parent[key]
        require(key == 'nonce' and set(parent) == fields.get(parent.get('version'))
            and type(value) is str and len(value) == 64
            and all(char in '0123456789abcdef' for char in value), 'return_public_gate5_nonce')
        return
    require(kind == 'STAGE06_CURRENT_ROOT_CLAIM' and key == 'subject', 'return_public_field_kind')
    fields = {'claim_id','subject','predicate','object_or_value','time_envelope_ref',
        'provenance_refs','evidence_refs','confidence_micros','source_role','source_mode','authority_class'}
    require(set(parent) == fields and parent['source_role'] == 'deterministic_runtime'
        and parent['source_mode'] == 'DETERMINISTIC' and parent['authority_class'] == 'NONE'
        and parent['confidence_micros'] == 1000000 and type(parent[key]) is str
        and parent[key].startswith(('stage06:', 'task:stage06:', 'source:stage06:', 'root:radik:stage06:')),
        'return_public_stage06_claim')


def _exceptions(review, publisher_ref):
    raw = exact(review['public_field_inventory_ref'])
    value = json.loads(raw)
    require(value['schema'] == 'radik.stage06.exact_public_fields.v1'
        and value['publisher_ref'] == publisher_ref and len(value['entries']) <= 20000,
        'return_public_field_inventory')
    entries = {}
    for entry in value['entries']:
        ref, pointer = entry['file_ref'], entry['json_pointer']
        require(ref['path'].startswith(BASE + '/') and ref['path'].endswith('.json')
            and pointer.startswith('/') and pointer.rsplit('/',1)[-1] in ('subject','nonce','stderr'),
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
            _public_field_shape(item, key, entry['kind'])
            publisher._no_secrets(walk(child, path+(key,), depth+1))
            used.add(identity)
        return result
    publisher._no_secrets(walk(value))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--review-sha256', required=True)
    args = parser.parse_args()
    review_path = PROJECT / BASE / 'return_packaging_review.json'
    review_raw = review_path.read_bytes()
    require(digest(review_raw) == args.review_sha256, 'return_packaging_review_changed')
    review = json.loads(review_raw)
    require(review['reviewer'] == '/root/private_remote_controls'
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
    publisher = types.ModuleType('radik_stage06_existing_return_publisher')
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
    result = publisher._build(kind='source', key='stage06_external_drs_actual_acceptance_01',
        payload=payload, record=review, review_raw=review_raw,
        basis=selection['basis'], prior=selection['prior_archives'])
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
