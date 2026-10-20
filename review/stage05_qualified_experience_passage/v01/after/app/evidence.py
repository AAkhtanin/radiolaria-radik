"""Finite administrative evidence files; these are never user SAVE commands.

Portable historical captures do not restore live Root, Host or effect authority.
Only an explicitly supplied owned directory is writable through this module.
"""
import os
from pathlib import Path
import re

from .native_authority import canonical, digest, plain, require

MAX_EVIDENCE_BYTES = 64 * 1024 * 1024


def persist(directory, label, value):
    require(re.fullmatch(r"[a-z][a-z0-9_]{0,47}", label) is not None, "evidence_label")
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), "evidence_owned_directory")
    resolved = directory.resolve(strict=True)
    require(directory.absolute() == resolved, "evidence_symlink_path")
    wrapper = dict(classification="PORTABLE_EVIDENCE_NOT_LIVE_AUTHORITY",
        type=type(value).__module__ + "." + type(value).__name__, body=plain(value))
    payload = canonical(wrapper)
    require(len(payload) <= MAX_EVIDENCE_BYTES, "evidence_byte_budget")
    target = resolved / (label + "_" + digest(payload) + ".json")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError:
        require(not target.is_symlink() and target.read_bytes() == payload, "evidence_existing_mismatch")
    else:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    require(target.read_bytes() == payload, "evidence_readback")
    return dict(path=str(target), sha256=digest(payload), bytes=len(payload), classification=wrapper["classification"])
