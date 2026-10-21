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
BASE = 'review/stage05_qualified_experience_passage/v03'
SELF = BASE + '/build_return.py'
PUBLISHER = 'review/package_direct_plan_return.py'
REPORT_ROOT = Path('/Users/admin/Downloads/Radik/stage05_actual_074128_repair_v03')


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


def _subject_shape(kind, parent, location):
    """Three fixed public G34 shapes; file and pointer pins are also mandatory."""
    subject = parent.get('subject')
    claim_fields = {'claim_id', 'subject', 'predicate', 'object_or_value', 'time_envelope_ref',
        'provenance_refs', 'evidence_refs', 'confidence_micros', 'source_role', 'source_mode', 'authority_class'}
    if kind in ('G34_CURRENT_ROOT_CLAIM', 'G34_HISTORY_ROOT_CLAIM'):
        require(len(location) >= 4 and location[-4:-1] ==
            ('root_review_packet', 'synthesis_proposal', 'normalized_claims')
            and type(location[-1]) is int and set(parent) == claim_fields
            and parent['source_role'] == 'deterministic_runtime' and parent['source_mode'] == 'DETERMINISTIC'
            and parent['authority_class'] == 'NONE' and parent['confidence_micros'] == 1000000
            and type(subject) is str and parent['claim_id'] == subject,
            'return_subject_normalized_claim_shape')
        if kind == 'G34_CURRENT_ROOT_CLAIM':
            require(subject in ('verify', 'audit') and parent['predicate'] == 'g34_current_pure_work',
                'return_subject_current_root_scope')
        else:
            require(len(subject) == 64 and all(char in '0123456789abcdef' for char in subject)
                and parent['predicate'] == 'g34_record_exact_history'
                and type(parent['object_or_value']) is dict
                and parent['object_or_value'].get('snapshot_id') == subject,
                'return_subject_history_root_scope')
        return
    require(kind == 'G34_TYPED_CURRENT_CLAIM', 'return_subject_kind')
    required = {'operation', 'definition_id', 'material_sha256', 'observation_refs',
        'subject', 'history_key', 'claim_id'}
    extra = {'advisory_ref', 'bridge_ref', 'review_requirement', 'additional_receipt_ref'}
    require(required <= set(parent) <= required | extra and parent['operation'] in
        ('radik.experience.source_verification.v01', 'radik.experience.source_condition_audit.v01'),
        'return_subject_typed_claim_shape')
    fields = {'local_root_scope_id', 'domain_scope_id', 'pack_family_id', 'advisory_source_class',
        'advisory_source_revision', 'advice_claim_profile_id', 'route_family_id', 'task_risk_class',
        'validation_profile_id', 'policy_semantics_version', 'history_key_profile_id'}
    require(type(subject) is dict and set(subject) == fields
        and all(type(value) is str and 0 < len(value) <= 256 for value in subject.values()),
        'return_subject_typed_scope_shape')
    root = subject['local_root_scope_id']
    require(root == 'root:radik:experience:' + root.rsplit(':', 1)[-1]
        and len(root.rsplit(':', 1)[-1]) == 24
        and all(char in '0123456789abcdef' for char in root.rsplit(':', 1)[-1])
        and subject['domain_scope_id'] == 'RADIK_DYNAMIC_INFORMATION'
        and subject['pack_family_id'] == 'RADIK_INFORMATIONAL'
        and len(subject['advisory_source_revision']) == 64
        and all(char in '0123456789abcdef' for char in subject['advisory_source_revision'])
        and subject['advice_claim_profile_id'] == 'G34_CONTROLLED_BOOLEAN_WORK_PREDICTION_V01'
        and (subject['advisory_source_class'], subject['route_family_id']) in (
            ('CONTROLLED_RAW_SOURCE_PREDICATE', 'PURE_SOURCE_VERIFICATION'),
            ('CONTROLLED_SOURCE_AUDIT', 'PURE_SOURCE_CONDITION_AUDIT'))
        and subject['task_risk_class'] == 'INFORMATIONAL'
        and subject['validation_profile_id'] == 'G34_TYPED_BOOLEAN_COMPLETED_WORK_V01'
        and subject['policy_semantics_version'] == 'radik.qualified_experience.v01'
        and subject['history_key_profile_id'] == 'G3_TYPED_HISTORY_KEY_V01',
        'return_subject_typed_scope_values')


def _subject_exceptions(review, publisher_ref):
    reference = review.get('public_native_subject_exception_ref')
    if reference is None:
        return {}, None
    require(reference['path'] == BASE + '/public_native_subject_exceptions.json',
        'return_subject_inventory_path')
    raw = exact(reference)
    value = json.loads(raw)
    require(set(value) == {'schema', 'classification', 'publisher_ref', 'entries'}
        and value['schema'] == 'radik.stage05.exact_public_native_subjects.v01'
        and value['classification'] == 'PUBLIC_NATIVE_MEANING_NOT_AUTH_IDENTITY'
        and value['publisher_ref'] == publisher_ref and type(value['entries']) is list
        and 1 <= len(value['entries']) <= 4096, 'return_subject_inventory_shape')
    result = {}
    observed_prefixes = (BASE + '/original_actual/workspace/owner_documents/',)
    for entry in value['entries']:
        require(type(entry) is dict and set(entry) == {'file_ref', 'json_pointer',
            'subject_sha256', 'containing_object_sha256', 'kind'}, 'return_subject_entry_shape')
        ref = entry['file_ref']
        require(type(ref) is dict and set(ref) == {'path', 'sha256', 'size_bytes'}
            and type(ref['path']) is str and ref['path'].endswith('.json')
            and ref['path'].startswith(observed_prefixes),
            'return_subject_actual_file_scope')
        pointer = entry['json_pointer']
        require(type(pointer) is str and 1 <= len(pointer) <= 4096 and pointer.startswith('/')
            and pointer.endswith('/subject'), 'return_subject_pointer')
        require(all(type(entry[key]) is str and len(entry[key]) == 64
            and all(char in '0123456789abcdef' for char in entry[key])
            for key in ('subject_sha256', 'containing_object_sha256')), 'return_subject_hash_shape')
        key = ref['path'], pointer
        require(key not in result, 'return_subject_duplicate_exception')
        result[key] = entry
    return result, raw


def _scan_json(publisher, value, reference, exceptions, used):
    """Scan an exact validation view; archive bytes remain untouched."""
    source_ref = {key: reference[key] for key in ('path', 'sha256', 'size_bytes')}

    def walk(item, path=(), depth=0):
        require(depth <= 96, 'return_observation_json_depth')
        if type(item) is list:
            return [walk(child, path + (index,), depth + 1) for index, child in enumerate(item)]
        if type(item) is not dict:
            return item
        result = {}
        for key, child in item.items():
            pointer = '/' + '/'.join(str(part).replace('~', '~0').replace('/', '~1')
                for part in path + (key,))
            identity = source_ref['path'], pointer
            entry = exceptions.get(identity)
            if entry is not None:
                require(key == 'subject' and source_ref == entry['file_ref']
                    and digest(canonical(child)) == entry['subject_sha256']
                    and digest(canonical(item)) == entry['containing_object_sha256'],
                    'return_subject_exact_binding')
                _subject_shape(entry['kind'], item, path)
                # Subject values are inspected too; no nested secret field is hidden.
                publisher._no_secrets(walk(child, path + (key,), depth + 1))
                used.add(identity)
            else:
                result[key] = walk(child, path + (key,), depth + 1)
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
    publisher = types.ModuleType('radik_stage05_existing_return_publisher')
    publisher.__file__ = str(PROJECT / PUBLISHER)
    exec(compile(publisher_raw, publisher.__file__, 'exec', dont_inherit=True), publisher.__dict__)
    selection = json.loads(exact(review['selection_ref']))
    require(selection['publication'] == 'LOCAL_ONLY' and 1 <= len(selection['files']) <= 4096,
        'return_selection_finite_local_scope')
    exceptions, exception_raw = _subject_exceptions(review, publisher_ref)
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
        exception_archive_path = 'reviewed_basis/' + BASE + '/public_native_subject_exceptions.json'
        require(exception_archive_path not in payload, 'return_subject_inventory_archive_collision')
        payload[exception_archive_path] = exception_raw
    result = publisher._build(kind='source', key='stage05_actual_074128_transport_repair_v03',
        payload=payload, record=review, review_raw=review_raw,
        basis=selection['basis'], prior=selection['prior_archives'])
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
