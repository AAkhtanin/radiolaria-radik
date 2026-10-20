"""Finite P31 actual Stage04 acceptance and evidence dossier return through the immutable publisher.

This wrapper never imports candidate application modules or starts the delivery
operator. Its preparation mode writes one unsigned finite data descriptor.
Its independently admitted build mode calls the existing single-build boundary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
PASSAGE = 'review/g2e_successor_passage'
PREFIX = PASSAGE + '/delivery_drafts/p31_actual_stage04_acceptance_v01'
SELF = PREFIX + '/package_return.py'
CONTRACT = PREFIX + '/CONTRACT.md'
MATERIALS = PREFIX + '/return_materials_v02.json'
INPUTS = PREFIX + '/return_inputs_v02.json'
REVIEW = PREFIX + '/return_source_review.json'
PUBLISHER = 'review/package_direct_plan_return.py'
PUBLISHER_SHA = 'c94aafcd966692f389c13694059256639f9cf5d2cc2e496407fc38463008066e'
OPERATOR = 'review/transport/radik_local_operator.py'
OPERATOR_SHA = '217a013f5ada2f246959be3a432f4303f3c950b1f74fc2d244d833cd0eaded58'
AUTHOR = '/root/p31_reference_mapper'
REVIEWER = '/root'
SCOPE = 'ACTUAL_P31_STAGE04_COMPOSITE_ACCEPTANCE_AND_EVIDENCE_DOSSIER'
BUILD_KEY = 'p31_actual_stage04_acceptance'
P31 = PASSAGE + '/proposals/g2e_no_effects_v31_stage04_closure'
ACTUAL = PASSAGE + '/p31_actual_acceptance'
PUBLIC_EVIDENCE = ACTUAL + '/public_evidence'
OWNER_RUN = (P31 + '/owner_terminal_runs/'
    + 'OWNER_20261020T135920_1936851b33af4ae2aeaef4ead90cbb34')
RAW_ACTUAL = frozenset(PUBLIC_EVIDENCE + '/' + OWNER_RUN
    + '/process_' + number + '/child_stdout.raw' for number in ('1', '2'))
DOSSIER_XML = (PASSAGE + '/publication_drafts/stage04_examination_v01/'
    + 'READ_RADIK_STAGE04.xml')
PUBLIC_PREFIXES = (PASSAGE + '/',)
PUBLIC_EXACT = frozenset((PUBLISHER, OPERATOR))
CLOSED_ACTUAL = re.compile(re.escape(PUBLIC_EVIDENCE + '/state/')
    + r'normal_(?:operations|rounds)/[0-9a-f]{32}\.json\.closed\Z')
EXTERNAL = {
    '@owner_instruction': Path('/Users/admin/Downloads/RADIK_P31_ACTUAL_STAGE04_ACCEPTANCE_RU.md'),
    '@owner_report': Path('/private/tmp/radik_p31_actual_acceptance_return/README_FIRST_RU.txt'),
    '@master_plan_original': Path('/Users/admin/Downloads/RADIK_MASTER_PLAN_RU.txt'),
    '@master_plan_copy': Path('/Users/admin/Downloads/RADIK_MASTER_PLAN_RU (1).txt'),
    '@stage04_owner_instruction': Path('/Users/admin/Downloads/RADIK_STAGE04_DYNAMIC_TASKS_RU.txt'),
}
EXTERNAL_NAMES = {
    '@owner_instruction': 'owner_handoff/RADIK_P31_ACTUAL_STAGE04_ACCEPTANCE_RU.md',
    '@owner_report': 'README_FIRST_RU.txt',
    '@master_plan_original': 'owner_handoff/RADIK_MASTER_PLAN_RU.txt',
    '@master_plan_copy': 'owner_handoff/RADIK_MASTER_PLAN_RU (1).txt',
    '@stage04_owner_instruction': 'owner_handoff/RADIK_STAGE04_DYNAMIC_TASKS_RU.txt',
}
FORBIDDEN = frozenset(('.git', '.venv', '.venv-plan', '.codex', '.aws',
    '__pycache__', 'node_modules', 'private', 'source_under_test',
    'test_dependencies', 'wheels', 'wheelhouse', 'env', 'venv', 'Arena',
    'arena', 'state_private', 'codex-home', 'nativecache', 'native-cache',
    'cache', 'sqlite', 'logs', 'log', 'return_verifications',
    'owned_simulated_project', '.env', 'credentials.json', 'tokens.json'))
SUFFIXES = frozenset(('.py', '.json', '.jsonl', '.txt', '.md', '.diff',
    '.sha256', '.toml', '.lock', '.journal'))
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 1536
FINAL_METADATA_MEMBERS = 3
MAX_DESCRIPTOR_BYTES = 4 * 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}\Z')
SOURCE_SCHEMA_PREFIX = (PASSAGE + '/proposals/'
    'g2e_no_effects_v28_ordinary_entry_owner_scenario/native_runtime/schemas/')
SOURCE_SCHEMA_DEFINITIONS = {
    SOURCE_SCHEMA_PREFIX + 'fractal_runtime_v02.schema.json': {
        'sha256': '8fa988bbce1f89689fb411c219c99f8f3011b60fca94a6aee94dd80b52d4b6e2',
        'schema_id': 'https://hedgehog.local/schemas/fractal_runtime_v02.schema.json',
        'top_keys': ('$schema', '$id', 'title', 'version', '$ref', '$defs'),
        'subject_locations': (
            ('$defs', 'NormalizedClaimV01', 'properties'),
            ('$defs', 'ConflictSetV01', 'properties')),
    },
    SOURCE_SCHEMA_PREFIX + 'outcome_feedback_g34_predictive_v01.schema.json': {
        'sha256': 'cb92d9429dd96efbda062dbe9507df18453402e481a8135c87841f9ac9fd6668',
        'schema_id': 'https://hedgehog.local/schemas/outcome_feedback_g34_predictive_v01.schema.json',
        'top_keys': ('$comment', '$defs', '$id', '$ref', '$schema'),
        'subject_locations': (('$defs',),),
    },
    SOURCE_SCHEMA_PREFIX + 'outcome_feedback_g35_sources_v01.schema.json': {
        'sha256': '9272dd580aa7514a4e807aaec28abfccf415d250159d4648d8329cfee2375e1b',
        'schema_id': 'urn:hedgehog:g35:sources:v0.1',
        'top_keys': ('$comment', '$defs', '$id', '$ref', '$schema'),
        'subject_locations': (
            ('$defs', 'shape_500', 'properties'),
            ('$defs', 'shape_55', 'properties'),
            ('$defs', 'shape_604', 'properties'),
            ('$defs', 'shape_656', 'properties'),
            ('$defs', 'shape_700', 'properties')),
    },
    SOURCE_SCHEMA_PREFIX + 'outcome_feedback_v01.schema.json': {
        'sha256': 'e89426aabdc36f62997a15b26e04fe6a1e07e046dcf609977a221ba337bcf26e',
        'schema_id': 'urn:hedgehog:g3:outcome-feedback:v0.1',
        'top_keys': ('$schema', '$id', '$comment', '$ref', '$defs'),
        'subject_locations': (('$defs',),),
    },
    SOURCE_SCHEMA_PREFIX + 'semantic_work_v01.schema.json': {
        'sha256': 'eeb1969866aa00a9144912e56574afe2a93e47a3906974db83eaabdc3507a0e4',
        'schema_id': 'https://hedgehog.local/schemas/semantic_work_v01.schema.json',
        'top_keys': ('$schema', '$id', 'title', '$ref', '$defs'),
        'subject_locations': (
            ('$defs', 'constraintBinding', 'properties'),
            ('$defs', 'normalizedClaim', 'properties'),
            ('$defs', 'conflictSet', 'properties')),
    },
}
SCHEMA_SUBJECT_MARKER = '__radik_public_source_schema_subject_declaration__'


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()


def relative(value):
    require(type(value) is str and value and not Path(value).is_absolute()
        and '\\' not in value and all(part not in ('', '.', '..')
            for part in value.split('/')), 'return_relative_path')
    source_value = value[len('evidence/'):] if value.startswith('evidence/') else value
    raw_witness = source_value in RAW_ACTUAL
    dossier_xml = source_value == DOSSIER_XML
    normal_close = CLOSED_ACTUAL.fullmatch(source_value) is not None
    require(not set(Path(value).parts).intersection(FORBIDDEN)
        and (Path(value).suffix in SUFFIXES or raw_witness or normal_close
            or dossier_xml), 'return_public_file_scope')
    return value


def regular(target, owner, cap=MAX_FILE_BYTES):
    require(owner.is_absolute() and owner.is_dir() and not owner.is_symlink()
        and owner.resolve() == owner and target.is_relative_to(owner),
        'return_owned_read_root')
    for current in (target, *target.parents):
        require(not current.is_symlink(), 'return_symlink_refused')
        if current == owner:
            break
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        and 0 <= before.st_size <= cap, 'return_regular_read_bound')
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
        item.st_mode, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
    require(identity(before) == identity(opened) == identity(after)
        and len(raw) == before.st_size, 'return_read_changed')
    return raw, stat.S_IMODE(before.st_mode)


def read(value, cap=MAX_FILE_BYTES):
    relative(value)
    require(value.startswith(PUBLIC_PREFIXES) or value in PUBLIC_EXACT,
        'return_exact_source_scope')
    return regular(PROJECT / value, PROJECT, cap)


def verify_ref(ref, *, external=False):
    require(type(ref) is dict and set(ref) ==
        {'path', 'sha256', 'size_bytes', 'mode'}, 'return_exact_reference_shape')
    require(type(ref['sha256']) is str and HASH.fullmatch(ref['sha256'])
        and type(ref['size_bytes']) is int
        and type(ref['mode']) is int, 'return_exact_reference_fields')
    if external:
        require(ref['path'] in EXTERNAL, 'return_external_marker')
        target = EXTERNAL[ref['path']]
        raw, mode = regular(target, target.parent)
    else:
        raw, mode = read(ref['path'])
    require(sha(raw) == ref['sha256'] and len(raw) == ref['size_bytes']
        and mode == ref['mode'], 'return_exact_reference_changed')
    return raw


def code_source(value):
    item = Path(value)
    return item.suffix in ('.py', '.toml') or (
        item.suffix == '.lock' and 'config' in item.parts) or (
        item.suffix == '.txt' and item.name.startswith('requirements')
        and item.parts[0] == 'config') or (
        item.suffix == '.json' and any(part in ('config', 'schema', 'schemas')
            for part in item.parts))


def check_json_payload(value, raw, namespace):
    """Inspect five exact public schema definitions without changing payload bytes."""
    view = json.loads(raw)
    definition = SOURCE_SCHEMA_DEFINITIONS.get(value)
    if definition is not None:
        require(sha(raw) == definition['sha256'], 'return_source_schema_exact_pin')
        require(type(view) is dict and set(view) == set(definition['top_keys'])
            and view.get('$schema') == 'https://json-schema.org/draft/2020-12/schema'
            and view.get('$id') == definition['schema_id']
            and type(view.get('$defs')) is dict and type(view.get('$ref')) is str,
            'return_source_schema_definition_shape')
        # Rename only twelve declaration keys in this temporary inspection view.
        # Their complete values remain subject to the unchanged secret predicate.
        for location in definition['subject_locations']:
            node = view
            for part in location:
                require(type(node) is dict and part in node,
                    'return_source_schema_declaration_location')
                node = node[part]
            require(type(node) is dict and type(node.get('subject')) is dict
                and SCHEMA_SUBJECT_MARKER not in node,
                'return_source_schema_declaration_shape')
            node[SCHEMA_SUBJECT_MARKER] = node.pop('subject')
    namespace['_no_secrets'](view)


def output(raw):
    require(len(raw) <= MAX_DESCRIPTOR_BYTES, 'return_descriptor_bytes')
    target = PROJECT / INPUTS
    require(not target.exists() and not target.is_symlink(),
        'return_descriptor_must_be_absent')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(target.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    require(read(INPUTS, MAX_DESCRIPTOR_BYTES)[0] == raw,
        'return_descriptor_readback')


def prepare(materials_sha):
    require(type(materials_sha) is str and HASH.fullmatch(materials_sha),
        'return_materials_hash')
    materials_raw, _ = read(MATERIALS, MAX_DESCRIPTOR_BYTES)
    require(sha(materials_raw) == materials_sha, 'return_materials_changed')
    materials = json.loads(materials_raw)
    require(type(materials) is dict and set(materials) == {'schema', 'scope',
        'payload_refs', 'external_payload_refs', 'basis', 'prior_hashlinks'}
        and materials['schema'] == 'radik.p31_actual_stage04_acceptance_return_materials.v01'
        and materials['scope'] == SCOPE, 'return_materials_shape')
    require(type(materials['payload_refs']) is list
        and 1 <= len(materials['payload_refs']) <= MAX_MEMBERS - 10,
        'return_payload_reference_count')
    external_refs = materials['external_payload_refs']
    require(type(external_refs) is list and len(external_refs) == len(EXTERNAL)
        and {item.get('path') for item in external_refs} == set(EXTERNAL),
        'return_external_reference_set')
    require(type(materials['basis']) is dict
        and type(materials['prior_hashlinks']) is list
        and len(materials['prior_hashlinks']) <= 16,
        'return_basis_and_historical_links')
    inventory = {}
    refs = {}
    total_bytes = 0

    def add(value, ref):
        nonlocal total_bytes
        name = 'evidence/' + value
        relative(name)
        require(value not in refs and name not in inventory
            and value not in (INPUTS, REVIEW), 'return_duplicate_or_cycle')
        verify_ref(ref)
        total_bytes += ref['size_bytes']
        require(total_bytes <= MAX_TOTAL_BYTES, 'return_total_byte_bound')
        refs[value] = ref
        inventory[name] = value

    for ref in materials['payload_refs']:
        require(type(ref) is dict, 'return_payload_reference_object')
        add(ref.get('path'), ref)
    for value in (SELF, CONTRACT, MATERIALS, PUBLISHER, OPERATOR):
        if value not in refs:
            raw, mode = read(value)
            add(value, dict(path=value, sha256=sha(raw), size_bytes=len(raw),
                mode=mode))
    require(refs[PUBLISHER]['sha256'] == PUBLISHER_SHA
        and refs[OPERATOR]['sha256'] == OPERATOR_SHA,
        'return_immutable_writer_identity')
    for ref in external_refs:
        verify_ref(ref, external=True)
        total_bytes += ref['size_bytes']
        require(total_bytes <= MAX_TOTAL_BYTES, 'return_total_byte_bound')
        inventory[EXTERNAL_NAMES[ref['path']]] = ref['path']
    require(len(inventory) + FINAL_METADATA_MEMBERS <= MAX_MEMBERS,
        'return_final_member_bound')
    descriptor = dict(schema='radik.p31_actual_stage04_acceptance_return_inputs.v01',
        status='UNSIGNED_FINITE_TARGETED_RETURN_PENDING_INDEPENDENT_REVIEW',
        scope=SCOPE, author=AUTHOR, author_acceptance=False,
        source_payload_inventory=dict(sorted(inventory.items())),
        source_payload_refs=dict(sorted(refs.items())),
        code_source_pins={name: ref['sha256'] for name, ref in sorted(refs.items())
            if code_source(name)}, external_payload_refs=external_refs,
        materials_ref=dict(path=MATERIALS, sha256=materials_sha,
            size_bytes=len(materials_raw)), basis=materials['basis'],
        prior_hashlinks=materials['prior_hashlinks'],
        selector_member_count=len(inventory), selected_total_bytes=total_bytes,
        final_metadata_members_reserved=FINAL_METADATA_MEMBERS,
        no_native_execution=True, no_general_protected_audit=True,
        no_recursive_walk=True, runtime_adoption=False,
        behavior_acceptance='NOT_AWARDED_BY_PACKAGING')
    raw = canonical(descriptor) + b'\n'
    output(raw)
    return dict(path=INPUTS, sha256=sha(raw), size_bytes=len(raw),
        selected_members=len(inventory),
        final_member_count=len(inventory) + FINAL_METADATA_MEMBERS)


def build(review_sha):
    require(type(review_sha) is str and HASH.fullmatch(review_sha),
        'return_review_hash')
    review_raw, _ = read(REVIEW, MAX_DESCRIPTOR_BYTES)
    require(sha(review_raw) == review_sha, 'return_review_changed')
    review = json.loads(review_raw)
    require(type(review) is dict and review.get('reviewer') == REVIEWER
        and review.get('reviewer') != AUTHOR
        and review.get('status') == 'ACCEPTED_FOR_ONE_P31_ACTUAL_STAGE04_ACCEPTANCE_RETURN'
        and review.get('scope') == SCOPE
        and review.get('approved_executor') == '/root'
        and review.get('approved_invocation_count') == 1,
        'return_independent_build_admission')
    source_pins = review.get('source_pins')
    require(type(source_pins) is dict
        and set(source_pins) == {SELF, CONTRACT, PUBLISHER, OPERATOR}
        and source_pins[PUBLISHER] == PUBLISHER_SHA
        and source_pins[OPERATOR] == OPERATOR_SHA,
        'return_writer_source_closure')
    verified = {}
    for value, pin in source_pins.items():
        raw, _ = read(value)
        require(type(pin) is str and HASH.fullmatch(pin) and sha(raw) == pin,
            'return_writer_source_changed')
        verified[value] = raw
    inputs_ref = review.get('return_inputs_ref')
    require(type(inputs_ref) is dict and set(inputs_ref) ==
        {'path', 'sha256', 'size_bytes'} and inputs_ref['path'] == INPUTS,
        'return_inputs_review_reference')
    inputs_raw, _ = read(INPUTS, MAX_DESCRIPTOR_BYTES)
    require(sha(inputs_raw) == inputs_ref['sha256']
        and len(inputs_raw) == inputs_ref['size_bytes'], 'return_inputs_changed')
    record = json.loads(inputs_raw)
    require(record.get('schema') == 'radik.p31_actual_stage04_acceptance_return_inputs.v01'
        and record.get('scope') == SCOPE and record.get('author') == AUTHOR
        and record.get('runtime_adoption') is False,
        'return_descriptor_scope')
    namespace = {'__name__': 'p31_actual_stage04_acceptance_frozen_publisher',
        '__file__': str(PROJECT / PUBLISHER)}
    exec(compile(verified[PUBLISHER], str(PROJECT / PUBLISHER), 'exec'), namespace)
    inventory = record['source_payload_inventory']
    refs = record['source_payload_refs']
    require(type(inventory) is dict and type(refs) is dict
        and 1 <= len(inventory) + FINAL_METADATA_MEMBERS <= MAX_MEMBERS
        and record.get('final_metadata_members_reserved') == FINAL_METADATA_MEMBERS,
        'return_final_descriptor_capacity')
    require({value for value in inventory.values() if value not in EXTERNAL}
        == set(refs) and record['code_source_pins'] == {
            value: ref['sha256'] for value, ref in sorted(refs.items())
            if namespace['code_source'](value)}, 'return_final_code_map')
    external_refs = record['external_payload_refs']
    require(type(external_refs) is list and len(external_refs) == len(EXTERNAL)
        and {item.get('path') for item in external_refs} == set(EXTERNAL),
        'return_final_external_set')
    external_map = {item['path']: item for item in external_refs}
    payload = {}
    total_bytes = 0
    for name, value in sorted(inventory.items()):
        relative(name)
        require(not namespace['excluded'](Path(name).parts),
            'return_immutable_publisher_path_guard')
        if value in EXTERNAL:
            require(name == EXTERNAL_NAMES[value], 'return_external_name')
            raw = verify_ref(external_map[value], external=True)
        else:
            require(name == 'evidence/' + value, 'return_project_archive_name')
            raw = verify_ref(refs[value])
            if Path(value).suffix == '.json' or CLOSED_ACTUAL.fullmatch(value) is not None:
                check_json_payload(value, raw, namespace)
            elif Path(value).suffix == '.jsonl':
                for line in raw.splitlines():
                    namespace['_no_secrets'](json.loads(line))
        total_bytes += len(raw)
        require(total_bytes <= MAX_TOTAL_BYTES, 'return_final_total_bytes')
        payload[name] = raw
    require(total_bytes == record['selected_total_bytes'],
        'return_final_total_binding')
    for value, raw in ((INPUTS, inputs_raw), (REVIEW, review_raw)):
        name = 'evidence/' + value
        require(name not in payload, 'return_final_review_cycle')
        namespace['_no_secrets'](json.loads(raw))
        payload[name] = raw
    return namespace['_build'](kind='source', key=BUILD_KEY, payload=payload,
        record=record, review_raw=review_raw, basis=dict(scope=SCOPE,
            reference_commit='800f38c3407b3f4ec93dc943c977ffeecb614881',
            production_adoption='UNCHANGED_COMPLETED_OWNER_ACTUAL_ONLY',
            actual_acceptance='SEPARATE_INDEPENDENT_EVIDENCE_REVIEW_REQUIRED',
            new_runtime_execution=False,
            generic_builder_seam='FINITE_P31_ACTUAL_STAGE04_ACCEPTANCE_AND_EVIDENCE_DOSSIER_RETURN'),
        prior=[dict(link, verification='HISTORICAL_DECLARED_PIN_NOT_REHASHED')
            for link in record['prior_hashlinks']])


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--prepare', action='store_true')
    modes.add_argument('--build', action='store_true')
    parser.add_argument('--materials-sha256')
    parser.add_argument('--review-sha256')
    args = parser.parse_args()
    require((args.prepare and args.materials_sha256 is not None
        and args.review_sha256 is None) or (args.build
        and args.review_sha256 is not None and args.materials_sha256 is None),
        'return_mode_arguments')
    result = prepare(args.materials_sha256) if args.prepare else build(args.review_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
