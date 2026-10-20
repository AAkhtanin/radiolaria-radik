"""Owned logical source intake; revision follows observed raw-byte changes."""
import json
import os
import stat
import time
from pathlib import Path

from .contracts import canonical, digest, require


class ApprovedSourceStore:
    def __init__(self, project, registry=None, *, dynamic=False):
        self.project = Path(project).resolve()
        self.directory = self.project / 'input'
        self.dynamic = dynamic
        require(type(dynamic) is bool, 'intake_profile')
        self.state = self.project / 'state' / ('dynamic_source_revisions.json' if dynamic else 'source_revisions.json')
        self.registry = registry if registry is not None else {
            'radik:fixture:left': 'service_a.txt', 'radik:fixture:right': 'service_b.txt'}
        require(type(self.registry) is dict and (1 <= len(self.registry) <= 4 if dynamic else len(self.registry) == 2)
                and all(type(k) is str and type(v) is str and Path(v).name == v and v.endswith('.txt')
                    for k, v in self.registry.items()), 'intake_closed_registry')
        require(all(Path(v).name == v and v.endswith('.txt')
                for v in self.registry.values()), 'intake_closed_registry')
        require(len(set(self.registry.values())) == len(self.registry), 'intake_duplicate_file')
        if dynamic:
            from .task_spec import SOURCE_ID
            require(all(SOURCE_ID.fullmatch(key) is not None for key in self.registry), 'intake_dynamic_source_id')

    def read(self):
        require(not self.directory.is_symlink() and not self.state.is_symlink()
                and not self.state.parent.is_symlink(), 'intake_symlink')
        require(self.state.parent.resolve().parent == self.project
                and self.directory.resolve().parent == self.project, 'intake_owned_directory')
        self.state.parent.mkdir(parents=True, exist_ok=True)
        prior = json.loads(self.state.read_bytes()) if self.state.exists() else {}
        require(type(prior) is dict and (len(prior) <= 64 if self.dynamic else not prior or set(prior) == set(self.registry)),
                'intake_revision_inventory')
        for previous in prior.values():
            require(type(previous) is dict and set(previous) == {'revision', 'sha256'}
                    and type(previous['revision']) is int and previous['revision'] >= 1
                    and type(previous['sha256']) is str and len(previous['sha256']) == 64,
                    'intake_revision_record')
        current, output = (dict(prior) if self.dynamic else {}), []
        for logical, name in sorted(self.registry.items()):
            path = self.directory / name
            require(not path.is_symlink() and path.resolve().parent == self.directory.resolve(),
                    'intake_owned_path')
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
            fd = os.open(path, flags)
            try:
                require(stat.S_ISREG(os.fstat(fd).st_mode), 'intake_regular_file')
                with os.fdopen(fd, 'rb') as stream:
                    raw = stream.read(16385)
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            require(len(raw) <= 16384 and b'\0' not in raw, 'intake_input_limit')
            require(not self.dynamic or len(raw) > 0, 'intake_dynamic_empty_source')
            text = raw.decode('utf-8', errors='strict')
            sha = digest(raw)
            previous = prior.get(logical, {})
            revision = previous.get('revision', 0) + (previous.get('sha256') != sha)
            require(type(revision) is int and revision >= 1, 'intake_revision_state')
            current[logical] = {'revision': revision, 'sha256': sha}
            output.append({'source_ref': logical, 'revision': revision, 'sha256': sha,
                           'text': text, 'observed_at': int(time.time())})
        temporary = self.state.with_suffix('.new')
        require(not temporary.exists(), 'intake_pending_state_write')
        with temporary.open('xb') as stream:
            stream.write(canonical(current)); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, self.state)
        return tuple(output)
