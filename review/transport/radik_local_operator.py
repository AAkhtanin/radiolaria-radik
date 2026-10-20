#!/usr/bin/env python3
"""Owner-started report delivery and optional native ChatGPT device login.

Run this file from the owner's ordinary Terminal, not from an agent tool.
It imports no Radik application or reference code and performs no inference.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
RETURNS = PROJECT / 'review/returns'
DESTINATION = Path('/Users/admin/Downloads/Radik')
PUBLIC_STATE = PROJECT / 'state/local_operator'
CODEX = Path('/opt/homebrew/Caskroom/codex/0.160.0/bin/codex')
BINARY_SHA256 = '112fae7a5a1223e673c8a1791d32338f37df8b527ff1159bb8adac6c4dbf1b4b'
NATIVE_HOME = PROJECT / 'review/transport/isolated_attempts/20261013T124818.269912Z/codex-home'
NATIVE_TMP = NATIVE_HOME.parent / 'process-tmp'
NAME = re.compile(r'RADIK_RETURN_[0-9]{8}T[0-9]{6}(?:\.[0-9]+)?Z\.tar\.gz\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def owned_directory(path, *, create=False):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        require(not current.is_symlink(), 'symlink_directory:' + str(current))
        if create and not current.exists():
            current.mkdir(mode=0o700)
        require(current.is_dir(), 'missing_directory:' + str(current))
    return path


def digest_file(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'not_regular:' + str(path))
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
        after = os.fstat(stream.fileno())
        require((before.st_size, before.st_mtime_ns) ==
                (after.st_size, after.st_mtime_ns), 'source_changed:' + str(path))
        return value.hexdigest()


def copy_bytes(source, destination, expected_sha):
    require(not destination.is_symlink(), 'destination_symlink:' + str(destination))
    if destination.exists():
        require(digest_file(destination) == expected_sha,
                'destination_conflict:' + str(destination))
        return
    src_fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    created = False
    identity = None
    try:
        with os.fdopen(src_fd, 'rb') as incoming:
            require(stat.S_ISREG(os.fstat(incoming.fileno()).st_mode), 'source_not_regular')
            dst_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, 'O_NOFOLLOW', 0), 0o600)
            created = True
            with os.fdopen(dst_fd, 'wb') as outgoing:
                status = os.fstat(outgoing.fileno())
                identity = (status.st_dev, status.st_ino)
                value = hashlib.sha256()
                for block in iter(lambda: incoming.read(1024 * 1024), b''):
                    outgoing.write(block)
                    value.update(block)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            require(value.hexdigest() == expected_sha, 'source_changed_during_copy')
        require(digest_file(destination) == expected_sha, 'destination_readback_mismatch')
    except BaseException:
        if created and identity is not None:
            try:
                current = destination.lstat()
                if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
                    destination.unlink()
            except OSError:
                pass
        raise


def receipt(name, data):
    owned_directory(PUBLIC_STATE, create=True)
    target = PUBLIC_STATE / name
    require(not target.is_symlink(), 'receipt_symlink')
    temporary = PUBLIC_STATE / (name + '.' + str(os.getpid()) + '.pending')
    data = dict(data, recorded_at_utc=datetime.now(timezone.utc).isoformat())
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)


def read_checksum(sidecar):
    fd = os.open(sidecar, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                 getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'checksum_not_regular')
        data = stream.read(1025)
    require(len(data) <= 1024, 'checksum_size')
    return data


def deliver(archive, checksum_bytes):
    sidecar = archive.with_name(archive.name + '.sha256')
    text = checksum_bytes.decode('ascii').strip()
    match = re.fullmatch(r'([0-9a-f]{64})[ \t]+\*?([^\r\n]+)', text)
    require(match is not None and match.group(2) == archive.name, 'checksum_identity')
    expected = match.group(1)
    require(digest_file(archive) == expected, 'source_checksum_mismatch')
    copy_bytes(archive, DESTINATION / archive.name, expected)
    copy_bytes(sidecar, DESTINATION / sidecar.name, hashlib.sha256(checksum_bytes).hexdigest())
    require(digest_file(DESTINATION / archive.name) == expected, 'pair_readback_mismatch')
    require((DESTINATION / sidecar.name).read_bytes() == checksum_bytes,
            'checksum_readback_mismatch')
    receipt(archive.name + '.delivery.json', {
        'status': 'DELIVERED_AND_VERIFIED', 'archive_sha256': expected,
        'archive': str(DESTINATION / archive.name),
        'checksum': str(DESTINATION / sidecar.name),
        'launch_context': 'OWNER_TERMINAL', 'model_turns': 0})
    print('Доставлено и проверено: ' + str(DESTINATION / archive.name), flush=True)


def native_device_login():
    require(not CODEX.is_symlink() and digest_file(CODEX) == BINARY_SHA256,
            'native_binary_identity_changed')
    owned_directory(NATIVE_HOME)
    owned_directory(NATIVE_TMP, create=True)
    private = owned_directory(PROJECT / 'state/local_operator_private', create=True)
    log_dir = owned_directory(private / 'log', create=True)
    sqlite_dir = owned_directory(private / 'sqlite', create=True)
    child_env = dict(os.environ)
    child_env.update(CODEX_HOME=str(NATIVE_HOME), TMPDIR=str(NATIVE_TMP),
                     CODEX_SQLITE_HOME=str(sqlite_dir))
    child_env.pop('OPENAI_API_KEY', None)
    child_env.pop('CODEX_ACCESS_TOKEN', None)
    command = [str(CODEX), '-c', 'cli_auth_credentials_store="file"',
               '-c', 'forced_login_method="chatgpt"',
               '-c', 'log_dir=' + json.dumps(str(log_dir)),
               '-c', 'sqlite_home=' + json.dumps(str(sqlite_dir))]
    status_result = subprocess.run(command + ['login', 'status'], env=child_env,
                                   cwd=PROJECT, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=15)
    if status_result.returncode == 0:
        receipt('device_login_result.json', {
            'status': 'NATIVE_CACHED_LOGIN_PRESENT', 'exit_code': 0,
            'codex_home': str(NATIVE_HOME), 'credential_store': 'file',
            'auth_mode_requested': 'chatgpt', 'auth_mode_observed': 'UNVERIFIED',
            'launch_context': 'OWNER_TERMINAL', 'runtime_admission': 'NOT_ADMITTED',
            'model_turns': 0, 'account_readback': 'PENDING_NATIVE_ACCOUNT_READ'})
        print('Сохранённый вход найден; новый вход не запускаю. Тип аккаунта проверит Radik.', flush=True)
        return
    help_result = subprocess.run(command + ['login', '--help'], env=child_env,
                                 cwd=PROJECT, capture_output=True, timeout=15)
    require(help_result.returncode == 0 and b'--device-auth' in help_result.stdout,
            'installed_device_login_not_supported')
    print('Штатный вход ChatGPT: открой ссылку и введи код, показанные Codex.', flush=True)
    # Native URL/code streams stay in the owner's Terminal; do not capture them.
    result = subprocess.run(command + ['login', '--device-auth'], env=child_env,
                            cwd=PROJECT, timeout=900)
    receipt('device_login_result.json', {
        'status': 'NATIVE_DEVICE_LOGIN_EXIT_ZERO' if result.returncode == 0 else 'NATIVE_DEVICE_LOGIN_FAILED',
        'exit_code': result.returncode, 'codex_home': str(NATIVE_HOME),
        'credential_store': 'file', 'auth_mode_requested': 'chatgpt',
        'launch_context': 'OWNER_TERMINAL', 'runtime_admission': 'NOT_ADMITTED',
        'model_turns': 0, 'account_readback': 'PENDING_NATIVE_ACCOUNT_READ'})
    print('Вход завершён.' if result.returncode == 0 else
          'Вход не завершён. Автоматического повтора нет.', flush=True)


def main():
    parser = argparse.ArgumentParser(description='Передача отчётов Radik и штатный вход.')
    parser.add_argument('--login', action='store_true', help='Начать один device-code вход сейчас.')
    parser.add_argument('--once', action='store_true', help='Доставить готовые пары и завершиться.')
    args = parser.parse_args()
    owned_directory(PROJECT)
    owned_directory(RETURNS)
    owned_directory(DESTINATION, create=True)
    seen = set()
    incomplete_since = {}

    def scan():
        for archive in sorted(RETURNS.iterdir()):
            if NAME.fullmatch(archive.name) and archive.name not in seen:
                require(not archive.is_symlink(), 'archive_symlink')
                sidecar = archive.with_name(archive.name + '.sha256')
                if not sidecar.exists():
                    continue  # Producer publishes the checksum after the archive.
                checksum_bytes = read_checksum(sidecar)
                try:
                    checksum_text = checksum_bytes.decode('ascii').strip()
                except UnicodeDecodeError:
                    checksum_text = ''
                complete = re.fullmatch(r'([0-9a-f]{64})[ \t]+\*?([^\r\n]+)', checksum_text)
                if complete is None:
                    first_seen = incomplete_since.setdefault(archive.name, time.monotonic())
                    require(time.monotonic() - first_seen < 10, 'incomplete_checksum:' + str(sidecar))
                    continue
                deliver(archive, checksum_bytes)
                seen.add(archive.name)
                incomplete_since.pop(archive.name, None)

    scan()  # Real delivery precedes auth or any long-running stage.
    while incomplete_since:
        time.sleep(0.25)
        scan()
    if args.login:
        try:
            native_device_login()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            failure = {'status': 'NATIVE_DEVICE_LOGIN_OPERATOR_ERROR',
                       'error_category': type(error).__name__,
                       'errno': getattr(error, 'errno', None),
                       'launch_context': 'OWNER_TERMINAL', 'runtime_admission': 'NOT_ADMITTED',
                       'model_turns': 0, 'account_readback': 'PENDING_NATIVE_ACCOUNT_READ'}
            try:
                receipt('device_login_result.json', failure)
            except (OSError, ValueError):
                print('Не удалось записать результат входа.', flush=True)
            print('Вход остановлен (' + type(error).__name__ + '). Передача отчётов продолжится.', flush=True)
    if args.once:
        require(not incomplete_since, 'unfinished_checksum_publication')
        return
    print('Передача новых отчётов включена. Оставь это окно открытым; Ctrl+C остановит передачу.', flush=True)
    while True:
        time.sleep(3)
        scan()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nПередача остановлена.', flush=True)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('Остановлено: ' + str(error), flush=True)
        raise SystemExit(1)
