"""Prepare exact public-field exceptions from an explicitly selected finite payload.

This source-only packaging helper never imports application or publisher code.
Its invocation requires a separate independent source and input review.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
BASE = 'review/stage07_pure_capability_passage/v01'
PACKAGE = PROJECT / BASE / 'actual_acceptance_01'
ADAPTER = PACKAGE / 'build_return.py'
PUBLISHER = PROJECT / 'review/package_direct_plan_return.py'
REPORT_ROOT = Path('/Users/admin/Downloads/Radik/stage07_actual_acceptance_01')


def require(value, code):
    if not value:
        raise ValueError(code)


def pin(path, expected):
    require(path.is_file() and not path.is_symlink(), 'inventory_source_regular')
    raw = path.read_bytes()
    require(len(raw) <= 67108864 and hashlib.sha256(raw).hexdigest() == expected,
        'inventory_source_changed')
    return raw, dict(path=str(path.relative_to(PROJECT)), sha256=expected, size_bytes=len(raw))


def main():
    started = time.monotonic_ns()
    parser = argparse.ArgumentParser()
    parser.add_argument('--selection', required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--adapter-sha256', required=True)
    parser.add_argument('--publisher-sha256', required=True)
    parser.add_argument('--output-name', required=True)
    args = parser.parse_args()
    selection_path = PROJECT / args.selection
    require(selection_path.is_relative_to(PROJECT / BASE)
        and '..' not in selection_path.parts and selection_path.suffix == '.json',
        'inventory_selection_scope')
    require(re.fullmatch(r'public_field_inventory(?:_[A-Za-z0-9_]+)?\.json', args.output_name),
        'inventory_output_scope')
    output = PACKAGE / args.output_name
    require(not output.exists() and not output.is_symlink(), 'inventory_output_exists')
    selection_raw, selection_ref = pin(selection_path, args.selection_sha256)
    adapter_raw, adapter_ref = pin(ADAPTER, args.adapter_sha256)
    publisher_raw, publisher_ref = pin(PUBLISHER, args.publisher_sha256)
    names = {'require','digest','exact','canonical','_public_field_shape'}
    tree = ast.parse(adapter_raw, filename=str(ADAPTER))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    require({node.name for node in selected} == names and len(selected) == len(names),
        'inventory_adapter_functions')
    namespace = dict(PROJECT=PROJECT, REPORT_ROOT=REPORT_ROOT, hashlib=hashlib,
        json=json, os=os, Path=Path, stat=stat, re=re)
    # Execute only these independently pinned packaging functions, never main.
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(ADAPTER), 'exec'), namespace)
    key_nodes = [node.value for node in ast.parse(publisher_raw).body
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
            and target.id == 'SECRET_KEYS' for target in node.targets)]
    require(len(key_nodes) == 1, 'inventory_publisher_key_definition')
    secret_keys = ast.literal_eval(key_nodes[0])
    require(type(secret_keys) is set and all(type(key) is str for key in secret_keys),
        'inventory_publisher_key_shape')
    selection = json.loads(selection_raw)
    require(selection['publication'] == 'LOCAL_ONLY' and 1 <= len(selection['files']) <= 4096,
        'inventory_selection_bound')
    entries = []
    seen = set()
    total = 0
    counts = {}

    def walk(value, reference, path=(), depth=0):
        require(depth <= 96, 'inventory_json_depth')
        if type(value) is list:
            for index, child in enumerate(value):
                walk(child, reference, path + (index,), depth + 1)
        elif type(value) is dict:
            for key, child in value.items():
                pointer = '/' + '/'.join(str(part).replace('~','~0').replace('/','~1')
                    for part in path + (key,))
                if key in secret_keys:
                    require(reference['path'].startswith(BASE + '/')
                        and reference['path'].endswith('.json'), 'inventory_exception_file_scope')
                    if key == 'subject':
                        kind = 'STAGE07_CURRENT_ROOT_CLAIM'
                    elif key == 'stderr' and child == '':
                        kind = 'EMPTY_PREPARATION_DIAGNOSTIC'
                    else:
                        require(key == 'stderr', 'inventory_unapproved_private_field')
                        kind = 'STAGE07_EMPTY_NATIVE_WORKER_STDERR'
                    namespace['_public_field_shape'](value, key, kind, pointer)
                    entries.append(dict(file_ref=reference, json_pointer=pointer, kind=kind,
                        value_sha256=namespace['digest'](namespace['canonical'](child)),
                        containing_object_sha256=namespace['digest'](namespace['canonical'](value))))
                    require(len(entries) <= 20000, 'inventory_exception_count')
                    counts[kind] = counts.get(kind, 0) + 1
                walk(child, reference, path + (key,), depth + 1)

    for row in selection['files']:
        reference = {key: row[key] for key in ('path','sha256','size_bytes')}
        require(reference['path'] not in seen, 'inventory_duplicate_source')
        seen.add(reference['path'])
        raw = namespace['exact'](reference, external=row.get('external_owner_report') is True)
        total += len(raw)
        require(total <= 536870912, 'inventory_total_bound')
        suffix = Path(reference['path']).suffix
        if suffix == '.json':
            walk(json.loads(raw), reference)
        elif suffix == '.jsonl':
            for line in raw.splitlines():
                if line.strip():
                    walk(json.loads(line), reference)
    value = dict(schema='radik.stage07.exact_public_fields.v1', publisher_ref=publisher_ref,
        adapter_ref=adapter_ref, selection_ref=selection_ref, entries=entries,
        selected_file_count=len(seen), selected_total_bytes=total, exception_counts=counts,
        source_author_acceptance=False, application_imports=0, publisher_imports=0,
        packaging_performed=False, elapsed_wall_ns=time.monotonic_ns()-started)
    raw = namespace['canonical'](value) + b'\n'
    with output.open('xb') as stream:
        require(stream.write(raw) == len(raw), 'inventory_write')
        stream.flush()
        os.fsync(stream.fileno())
    require(output.read_bytes() == raw, 'inventory_readback')
    print(json.dumps(dict(path=str(output.relative_to(PROJECT)),
        sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw),
        entries=len(entries), selected_files=len(seen), elapsed_wall_ns=value['elapsed_wall_ns']),
        sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
