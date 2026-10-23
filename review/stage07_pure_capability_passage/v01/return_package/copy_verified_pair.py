"""Copy one reviewed publisher pair without rebuilding or claiming owner execution."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = PROJECT / 'review/stage07_pure_capability_passage/v01'
DESTINATION = Path('/Users/admin/Downloads/Radik')
SELF = BASE / 'return_package/copy_verified_pair.py'
RESERVATION = PROJECT / 'review/return_verifications/before_owner_fix_source_stage07_pure_capability_v01_build.json'
OLD_HANDOFF = DESTINATION / 'RADIK_RETURN_20261023T093324.935252Z_STAGE07_REVIEW_HANDOFF.tar.gz'
OLD_SHA = '3f8e2c9e4e81589babeaba64391d60e84254c08a13eed505112478c1990abb52'


def require(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe(path):
    require(path.is_absolute() and '..' not in path.parts
        and (path.is_relative_to(PROJECT) or path.is_relative_to(DESTINATION)), 'delivery_path')
    require(all(not node.is_symlink() for node in (path, *path.parents)), 'delivery_symlink')


def read(path):
    safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= 67108864, 'delivery_regular_bound')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size, 'delivery_read_changed')
    return raw


def exact(reference):
    path = Path(reference['path'])
    require(path.is_absolute(), 'delivery_absolute_reference')
    raw = read(path)
    require(digest(raw) == reference['sha256'] and len(raw) == reference['size_bytes'], 'delivery_pin')
    return raw


def write_new(path, raw):
    safe(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        require(stream.write(raw) == len(raw), 'delivery_write')
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    require(read(path) == raw, 'delivery_write_readback')


def verify_manifest(path):
    with tarfile.open(path, 'r:gz') as bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)) and all(member.isfile() for member in members)
            and all(not Path(name).is_absolute() and '..' not in Path(name).parts for name in names),
            'delivery_tar_inventory')
        manifest = json.loads(bundle.extractfile('manifest.json').read())
        rows = manifest['files']
        require(len(rows) == len({row['archive_path'] for row in rows})
            and set(names) == {row['archive_path'] for row in rows} | {'manifest.json'}, 'delivery_manifest_members')
        for row in rows:
            raw = bundle.extractfile(row['archive_path']).read()
            require(len(raw) == row['size_bytes'] and digest(raw) == row['sha256'], 'delivery_manifest_bytes')
    return len(rows)


def main():
    started = time.monotonic_ns()
    parser = argparse.ArgumentParser()
    parser.add_argument('--grant-sha256', required=True)
    args = parser.parse_args()
    grant_path = BASE / 'return_package/final_delivery_grant.json'
    grant_raw = read(grant_path)
    require(digest(grant_raw) == args.grant_sha256, 'delivery_grant_hash')
    grant = json.loads(grant_raw)
    binding_ref = grant['reviewer_binding_ref']
    require(binding_ref['path'] == str(BASE / 'reviewer_binding.json'), 'delivery_binding_path')
    binding = json.loads(exact(binding_ref))
    require(binding['schema'] == 'radik.stage07.reviewer_binding.v1'
        and binding['status'] == 'OWNER_DESIGNATED_CURRENT_REVIEWER'
        and binding['scope'] == 'STAGE07_V01'
        and binding['source_authors'] == ['/root', '/root/stage05_g4_contract']
        and grant['reviewer'] == binding['reviewer']
        and grant['reviewer'] not in binding['source_authors'] + ['/root/private_remote_controls'], 'delivery_reviewer')
    require(grant['status'] == 'ACCEPTED_FOR_ONE_VERIFIED_PAIR_COPY'
        and grant['approved_executor'] == '/root' and grant['approved_invocation_count'] == 1
        and grant['helper_ref']['path'] == str(SELF), 'delivery_scope')
    exact(grant['helper_ref'])
    require(grant['reservation_ref']['path'] == str(RESERVATION), 'delivery_reservation_path')
    reservation = json.loads(exact(grant['reservation_ref']))
    require(reservation['kind'] == 'source' and reservation['key'] == 'stage07_pure_capability_v01'
        and reservation['retry_or_reset_allowed'] is False, 'delivery_reserved_scope')
    archive = PROJECT / reservation['archive_path']
    match = re.fullmatch(r'RADIK_RETURN_([0-9]{8}T[0-9]{6}\.[0-9]+Z)\.tar\.gz', archive.name)
    require(match is not None and archive.parent == PROJECT / 'review/returns', 'delivery_archive_scope')
    checksum = Path(str(archive) + '.sha256')
    verify_dir = PROJECT / ('review/return_verifications/before_owner_fix_source_' + match.group(1))
    require(grant['local_readback_ref']['path'] == str(verify_dir / 'local_readback.json'), 'delivery_readback_path')
    local = json.loads(exact(grant['local_readback_ref']))
    require(grant['archive_ref']['path'] == str(archive)
        and grant['checksum_ref']['path'] == str(checksum), 'delivery_pair_paths')
    raw, checksum_raw = exact(grant['archive_ref']), exact(grant['checksum_ref'])
    expected = digest(raw)
    require(local['status'] == 'PASS_COMPLETE_TAR_MANIFEST_READBACK'
        and local['archive_sha256'] == expected and local['archive_path'] == str(archive)
        and local['reservation_path'] == str(RESERVATION.relative_to(PROJECT))
        and checksum_raw == (expected + '  ' + archive.name + '\n').encode(), 'delivery_verified_pair')
    require(digest(read(OLD_HANDOFF)) == OLD_SHA, 'delivery_old_handoff_changed')
    payload_files = verify_manifest(archive)
    require(payload_files == local['payload_files'], 'delivery_payload_count')
    destination_archive, destination_checksum = DESTINATION / archive.name, DESTINATION / checksum.name
    receipt_path = PROJECT / 'state/local_operator' / (archive.name + '.delivery.json')
    result_path = verify_dir / 'final_delivery_readback.json'
    for path in (destination_archive, destination_checksum, receipt_path, result_path):
        safe(path)
        require(not path.exists(), 'delivery_prior_artifact_requires_readback_no_retry')
    write_new(destination_archive, raw)
    write_new(destination_checksum, checksum_raw)
    require(verify_manifest(destination_archive) == payload_files
        and digest(read(OLD_HANDOFF)) == OLD_SHA, 'delivery_final_readback')
    result = dict(schema='radik.stage07.final_pair_delivery.v1', status='DELIVERED_AND_VERIFIED',
        archive_sha256=expected, archive=str(destination_archive), checksum=str(destination_checksum),
        launch_context='AGENT_TOOL_AUTHORIZED_COPY', model_turns=0, payload_files=payload_files,
        original_handoff_sha256=OLD_SHA, existing_publisher_used=True, archive_rebuilt=False,
        grant_sha256=args.grant_sha256, helper_sha256=grant['helper_ref']['sha256'],
        recorded_at_utc=datetime.now(timezone.utc).isoformat(), elapsed_wall_ns=time.monotonic_ns()-started)
    output = json.dumps(result, sort_keys=True, ensure_ascii=False).encode() + b'\n'
    write_new(receipt_path, output)
    write_new(result_path, output)
    print(output.decode(), end='', flush=True)


if __name__ == '__main__':
    main()
