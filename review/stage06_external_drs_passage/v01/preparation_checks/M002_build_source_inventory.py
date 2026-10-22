"""Prepare an exact finite inventory by reading files; never import the candidate."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = PROJECT/'review/stage06_external_drs_passage/v01'
CANDIDATE = BASE/'candidate'
PLATFORM = Path('/opt/homebrew/Cellar/python@3.14/3.14.5/Frameworks/Python.framework/Versions/3.14')
SITE = PROJECT/'.venv-plan/lib/python3.14/site-packages'


def build():
    selected = {}
    def add(path, classification, peer=True):
        if path.is_symlink() or not path.is_file():
            raise ValueError('stage06_inventory_regular_file_required')
        selected[path.absolute()] = (classification, peer)
    def tree(root, classification, peer=True, suffixes=None):
        for path in root.rglob('*'):
            if '__pycache__' in path.parts or path.is_dir() or classification == 'platform' and any(part in ('test', 'tests', 'turtledemo', 'idlelib', 'tkinter', 'site-packages') for part in path.relative_to(root).parts):
                continue
            if suffixes is None or path.suffix in suffixes:
                add(path, classification, peer)
    tree(CANDIDATE, 'candidate', suffixes={'.py'})
    tree(PROJECT/'source/reference/hedgehog', 'reference', suffixes={'.py', '.json'})
    tree(PROJECT/'source/reference/schemas', 'reference_resource')
    for name in ('__init__.py', 'run_action_packet_portability_v01.py', 'work_composition_mock_capabilities_v01.py'):
        path = PROJECT/'source/reference/demo'/name
        if path.exists(): add(path, 'reference')
    for name in ('cryptography', 'jsonschema', 'jsonschema_specifications', 'referencing', 'rpds',
                 'attr', 'attrs', 'cffi', 'pycparser'):
        tree(SITE/name, 'dependency', suffixes={'.py', '.so', '.json', '.typed', ''})
    for path in SITE.glob('*.py'): add(path, 'dependency')
    for path in SITE.glob('*.so'): add(path, 'dependency')
    # Exact interpreter-distribution files, including importlib resource data.
    tree(PLATFORM/'lib/python3.14', 'platform', suffixes={'.py', '.so', '.json'})
    for path in BASE.glob('*.py'):
        add(path, 'supervisor', False)
    for name in ('scenario.json', 'engineering_scenario.json'):
        if (BASE/name).exists(): add(BASE/name, 'parent_only', False)
    for name in ('owner_terminal.py', 'supervisor_timing.py'):
        add(PROJECT/'review/stage05_qualified_experience_passage/v09/integration'/name, 'accepted_supervisor', False)
    files, directories, codes = [], set(), set()
    for path, (classification, peer) in sorted(selected.items()):
        raw = path.read_bytes()
        files.append(dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(),
                          size_bytes=len(raw), classification=classification))
        if peer:
            for parent in path.parents:
                directories.add(str(parent))
                if parent in (PROJECT, PLATFORM): break
        if path.suffix == '.py':
            for node in ast.walk(ast.parse(raw, filename=str(path))):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.fullmatch('[a-z][a-z0-9_]{1,159}', node.value):
                    codes.add(node.value)
    value = dict(schema='radik.stage06.source_manifest.v1', environment_root=str(PROJECT),
        candidate_root=str(CANDIDATE), files=files,
        peer_read_paths=[str(p) for p, (_, peer) in sorted(selected.items()) if peer],
        import_paths=[str(CANDIDATE), str(PROJECT/'source/reference'), str(SITE),
                      str(PLATFORM/'lib/python3.14'), str(PLATFORM/'lib/python3.14/lib-dynload')],
        directory_paths=sorted(directories), failure_codes=sorted(codes),
        parent_only_bytes_not_read_by_peer=True,
        native_reference_commit='800f38c3407b3f4ec93dc943c977ffeecb614881')
    raw = json.dumps(value, sort_keys=True, indent=2).encode()+b'\n'
    (BASE/'source_manifest.json').write_bytes(raw)
    print(json.dumps(dict(files=len(files), bytes=sum(x['size_bytes'] for x in files),
        manifest_sha256=hashlib.sha256(raw).hexdigest(), manifest_bytes=len(raw))))


if __name__ == '__main__':
    build()
