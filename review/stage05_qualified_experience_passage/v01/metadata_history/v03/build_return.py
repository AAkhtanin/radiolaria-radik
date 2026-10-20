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
BASE = 'review/stage05_qualified_experience_passage/v01'
SELF = BASE + '/build_return.py'
PUBLISHER = 'review/package_direct_plan_return.py'
REPORT_ROOT = Path('/Users/admin/Downloads/Radik/stage05_owner_handoff_v01')


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
    payload = {}
    total = 0
    review_archive_path = 'reviewed_basis/' + BASE + '/return_packaging_review.json'
    for row in selection['files']:
        name = row['archive_path']
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts
            and not publisher.excluded(path.parts) and name not in payload
            and name not in ('manifest.json', review_archive_path),
            'return_selection_archive_scope')
        raw = exact(row, external=row.get('external_owner_report') is True)
        if path.suffix == '.json':
            publisher._no_secrets(json.loads(raw))
        elif path.suffix == '.jsonl':
            for line in raw.splitlines():
                if line.strip():
                    publisher._no_secrets(json.loads(line))
        total += len(raw)
        require(total <= 536870912, 'return_selection_total_bound')
        payload[name] = raw
    payload[review_archive_path] = review_raw
    result = publisher._build(kind='source', key='stage05_qualified_experience_v01',
        payload=payload, record=review, review_raw=review_raw,
        basis=selection['basis'], prior=selection['prior_archives'])
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
