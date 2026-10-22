"""Stdlib source/dependency and reviewed owner-transition predicates.

Current credentials, ledgers and quota are use-time state, never code pins.
These predicates evaluate an independent source contract; they issue no review.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

PROJECT = Path(__file__).resolve().parents[2]
PASSAGE = 'review/direct_plan_passage'
LEGACY_REVIEW_PASSAGE = 'review/actual_save_console_passage'
PRIOR_STAGE04 = 'review/stage04_dynamic_passage'
REVIEW_PASSAGE = 'review/normal_session_g2e_passage'
AUTH_REVIEW_PASSAGE = REVIEW_PASSAGE
OWNER_REVIEW = AUTH_REVIEW_PASSAGE + '/owner_source_review.json'
RUNTIME_REVIEW = REVIEW_PASSAGE + '/runtime_source_review.json'
BEHAVIOR_REVIEW = REVIEW_PASSAGE + '/console_source_review.json'
ACTUAL_REVIEW = LEGACY_REVIEW_PASSAGE + '/actual_acceptance_review.json'
ACTUAL_CONSOLE_REVIEW = PRIOR_STAGE04 + '/actual_console_review.json'
MECHANICAL_REVIEW = REVIEW_PASSAGE + '/mechanical_result_review.json'
FOCUSED_SOURCE_REVIEW = REVIEW_PASSAGE + '/mechanical_source_review.json'
HISTORICAL_STARTUP_BASIS = {
    'review/actual_save_console_passage/mechanical_source_review.json': '1db2082a9125b081b155053f352d0e2a87e3f649888a868ac9069d5c43ac6884',
    'review/actual_save_console_passage/mechanical_result_review.json': 'c3b98e711075daa626474593c04281398028808cc7e9f9d74fbb975590af4522',
    'review/actual_save_console_passage/offline_attempts/ACTUAL_SAVE_CONSOLE_V01/result.json': '5bffe53fd3db6f944b7107eb419c104babfc9d4d8c3619e93c3cbbcdfbb17879',
    'review/bounded_memory_return_passage/mechanical_source_review.json': 'fd2397849f6230b1b1f405424667eb5f297678469d614653624e30a0483e1719',
    'review/bounded_memory_return_passage/mechanical_result_review.json': '62f98f9b51abb359cfa1c4e5e66c6e062ddf166b10e5ba8ff1cb32c0011566ce',
    'review/bounded_memory_return_passage/offline_attempts/BOUNDED_MEMORY_RETURN_V02/result.json': '978470600dc2edb392c01ebe064e34c0029e561a5f746b7b2b649d6f3816f9bf',
    'review/semantic_continuation_passage/mechanical_source_review.json': '12b0c40c8f9b40e4c969a158c3b9f21cd5026f78faf8a08b4c8d7651286f457e',
    'review/semantic_continuation_passage/mechanical_result_review.json': 'f747f8f8d0254bdfeac1948587d9c568dcb5b0dacf1d9de54b333de7031873fa',
    'review/semantic_continuation_passage/offline_attempts/SEMANTIC_CONTINUATION_V03/result.json': '0281b0b5f54bc0af249be125a51bedc308e079f39490b2e603b37c4558e070ab',
    'review/usage_projection_passage/mechanical_source_review.json': '8997ade7413a35266b61b0715fd6f6858eee00dbdff4e29e9a1ccd04922324c9',
    'review/usage_projection_passage/mechanical_result_review.json': '92881c7480a079accbb0d1c184fda226db9e65bf3d354fd066a1b67323bb8990',
    'review/usage_projection_passage/offline_attempts/USAGE_PROJECTION_V01/result.json': '5d17c0f5a56cb443c224eec8e821a1b44dc1bbcdcbf4776d547ced1e73bb7d19',
    'review/finalized_stream_passage/mechanical_result_review.json': '67dda5acf019d7c36bb38bc1a0bab174a244a98e1ee2c8508d7e64da65c8db56',
    'review/finalized_stream_passage/mechanical_source_review.json': '5428b978fd99767b1b78b429b15c70746c7a6a5c257eb93a329735da053e56b4',
    'review/finalized_stream_passage/offline_attempts/FINALIZED_STREAM_V01/result.json': 'b9c5ff8fc1f08a8dd886db8807db85d75fedd10fdf6011e393349d7525bcc1ae',
    'review/stream_compatibility_passage/mechanical_result_review.json': '7da74bca6203c3f93f89a26142d063aa0f1e796f71ce6abee203ec37cf88e0e5',
    'review/stream_compatibility_passage/mechanical_source_review.json': '68ba624a2862d790fb911b3c56ad88eb8a10dc3c617fd69891ac31679f71a4f2',
    'review/stream_compatibility_passage/offline_attempts/STREAM_COMPATIBILITY_V01/result.json': 'd90819f2072b2536cff562f46819defb2824adbac8ba4d2d06fa5473e9f40062',
    'review/transport_response_recovery_passage/mechanical_result_review.json': 'f95f079c27bb036c09af319011459bf124a726bb31b80c0f314f4950ea9f0b4f',
    'review/transport_response_recovery_passage/mechanical_source_review.json': '2bcf2424da61254220f23a6549eabbb0801332e7556acd49940b6c38bb4e7213',
    'review/transport_response_recovery_passage/offline_attempts/20261014T115406Z/result.json': 'c41fea8976f982f0b3b2664b6c4e3402921961dbfc97c1cc1921fcd2ec56927b',
    'review/checkpoint_startup_passage/mechanical_result_review.json': '7e12b6e9ec56779d37c4d72914ffbd18b84c0ccb31b42422ec734d05ce224cad',
    'review/checkpoint_startup_passage/focused_source_review.json': 'e404a6866e6203d91f21804a44e9e86c53d0efda28b23d20467b2fe1ec4e6e79',
    'review/checkpoint_startup_passage/focused_attempts/STARTUP_FOCUSED_V01/result.json': '77d1a4d63392b2a030d15baa0e6bf9035fba42e0375059eae01b073b3492c21c',
    'review/completed_output_passage/mechanical_result_review.json': '9961de805b2afb6d4b935448c28278a12740affd6f080999509de85a1a6996f7',
    'review/completed_output_passage/mechanical_source_review.json': '6e4339c4c20e7662f0685943f0a8b754c1c590144087523674a8a203b0888140',
    'review/completed_output_passage/offline_attempts/COMPLETED_OUTPUT_V01/result.json': 'eb0b438cf4dc938cf6f396e61e9bb93fd1659cdd390f33e52f3895b970bdeebf',
}
AUTH_SOURCE_FILES = frozenset({
    'review/transport/radik_owner_start.py', 'review/transport/direct_plan_gate.py',
    'review/transport/plan_dependencies.py', 'review/package_direct_plan_return.py',
    'review/transport/owner_failure_report.py', 'app/__init__.py', 'app/plan_auth.py',
    'review/transport/model_scope.py', 'config/console_model_policy.json',
    'app/task_budget.py', 'config/task_model_policy.json',
    'app/source_admission.py', 'app/stage04_diagnostics.py', 'app/console_continuation.py',
    'app/normal_session.py', 'config/normal_session_policy.json',
    'config/model_policy.json', 'config/requirements-plan-base.txt', 'config/requirements-plan-auth.txt',
    'review/dependencies/inventory.json', 'review/direct_plan_passage/bootstrap_identity.json',
    'review/direct_plan_passage/auth_dependency_metadata.json', 'review/direct_plan_passage/protocol_references.json',
})
REQUIRED_SCOPES = {'openid', 'profile', 'email', 'offline_access',
                   'resource.invoke', 'chatgpt.tokens.use.direct'}
HISTORICAL_REVIEW_PINS = {
    'review/first_live_passage/mechanical_result_review.json': '4d0bf9c8a81a34fb3e73f07ca352989d45bb297f6fb9b6616d6912c9a793ab51',
    'review/first_live_passage/mechanical_source_review.json': '051ec7a9dea3e68d20f9c89db118094f4663cb6dbe2253314e92db162ce4a26b',
    'review/canonical_semantic_passage/runtime_source_review.json': '73e7a6c1027f18993a0c3c7f6724f38cddb6626c38f7f5b0671829f9bf2bc5de',
    'review/canonical_semantic_passage/mechanical_result_review.json': '6d1b7107257eaff81d8e4270655f71164fcfca75a9eef31067c555cdb04779fd',
    'review/jwt_audience_passage/owner_source_review.json': '99d0429b1a1f8a49ce81bfe8461220c077a03db963c365a0536437cd41cb8944',
    'review/jwt_audience_passage/mechanical_result_review.json': 'e45166b226bd97f6eeeae1b31adc7b7a34c0a56d8d297d4a7ed0ffa0049893df',
}
HISTORICAL_RESULT_PINS = {
    'review/first_live_passage/offline_attempts/20261014T102432Z/result.json': 'ca80ed3176d68bede36dfc8324eafe39d00079d809529782469a3636ba71e8f4',
    'review/first_live_passage/offline_attempts/20261014T102432Z/public_witnesses/inventory.json': '06b52ca5aa0e9f83a85f1b24af5274a91ae6611ae6969fe6fd7ec45ee15b23a2',
    'review/canonical_semantic_passage/mechanical_attempts/20261014T072831.972907Z/result.json': 'b0c4658cb36e5a3996f2301b72f21904931508ad5dadeff9b87286aafe9df7e8',
    'review/jwt_audience_passage/offline_attempts/20261014090001Z/result.json': '43e25c610250ae2798e18a3ffd7f4dd67f38bf4293b4bffdd90325563873fc4b',
}


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def owned(project, relative):
    project = Path(project)
    require(project.is_absolute() and project.resolve(strict=True) == project,
            'direct_gate_project_identity')
    require(type(relative) is str and relative and not Path(relative).is_absolute()
            and not set(Path(relative).parts).intersection(('.', '..')),
            'direct_gate_relative_path')
    path = project / relative
    for node in (path, *path.parents):
        require(not node.is_symlink(), 'direct_gate_symlink')
        if node == project:
            break
    require(path.resolve().is_relative_to(project), 'direct_gate_owned_path')
    return path


def read(project, relative, cap=8 * 1024 * 1024):
    path = owned(project, relative)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                'direct_gate_regular_file')
        raw = stream.read(cap + 1)
    require(len(raw) <= cap, 'direct_gate_file_bound')
    return raw


def verify_pins(project, pins):
    require(type(pins) is dict and pins, 'direct_gate_pin_inventory')
    for relative, expected in pins.items():
        parts = Path(relative).parts
        require(not relative.startswith(('state/', 'drs/', 'output/', '.venv'))
                and not set(parts).intersection(('private', 'codex-home', 'Arena', 'arena')),
                'direct_gate_mutable_or_private_code_pin')
        require(type(expected) is str and len(expected) == 64
                and digest(read(project, relative,64 * 1024 * 1024)) == expected,
                'direct_gate_source_pin_mismatch')
    return dict(pins)


def source_review(project=PROJECT, *, runtime=False):
    from config.application_profile_gate import select
    selected=select(project)
    if selected is not None:
        return selected['runtime_review' if runtime else 'auth_review']
    relative = RUNTIME_REVIEW if runtime else OWNER_REVIEW
    review = json.loads(read(project, relative))
    expected = 'SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION' if runtime else 'SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT'
    require(review.get('status') == expected and review.get('reviewer') == '/root/semantic_continuation_reviewer'
            and review.get('scope') == 'DIRECT_CHATGPT_PLAN_SOURCE_ONLY',
            'direct_gate_independent_source_review_required')
    if not runtime:
        require(set(review.get('pins', {})) == AUTH_SOURCE_FILES,
                'direct_gate_auth_only_source_closure')
        verify_pins(project, review['pins'])
        return review
    required = AUTH_SOURCE_FILES | {'review/transport/radik_owner_start.py', 'review/transport/direct_plan_gate.py',
                'review/transport/plan_dependencies.py', 'app/plan_auth.py',
                'app/openai_plan_transport.py', 'app/stream_observation.py', 'app/proposal.py', 'app/runtime.py',
                'app/controller.py', 'app/budget.py', 'config/launch.py',
                'app/task_spec.py', 'app/task_store.py', 'app/dynamic_roles.py',
                'app/dynamic_semantics.py', 'app/dynamic_native.py', 'app/dynamic_control.py', 'app/dynamic_work.py',
                'app/dynamic_temporal.py',
                'config/model_policy.json', 'config/requirements-plan-base.txt',
                'config/requirements-plan-auth.txt', 'review/live_exam_document.py',
                'review/package_direct_plan_return.py','review/transport/owner_failure_report.py',
                'app/semantic_membrane.py'}
    require(required.issubset(review.get('pins', {})), 'direct_gate_source_closure_incomplete')
    verify_pins(project, review['pins'])
    return review


def dependency_review(project=PROJECT):
    from review.transport.plan_dependencies import verify_installed
    from config.application_profile_gate import environment_root
    return verify_installed(environment_root(project))


def source_identity(project=PROJECT, *, scope="exam"):
    from config.application_profile_gate import select
    require(scope=='console' or select(project) is None,'direct_gate_legacy_exam_is_historical_under_current_profile')
    review = source_review(project, runtime=True)
    dependency_review(project)
    from app.task_budget import read_state
    require(read_state(project)['source_identity_sha256'] == digest(review['pins']),
        'direct_gate_prelive_current_admission_required')
    return review['pins']


def mechanical_review(project, current_source):
    """Current normal-session proof; accepted earlier scopes remain historical."""
    value = json.loads(read(project, MECHANICAL_REVIEW))
    require(value.get('schema') == 'radik.independent.normal_session_aggregate_review.v01'
            and value.get('reviewer') == '/root/semantic_continuation_reviewer'
            and value.get('status') == 'PASS_CURRENT_AGGREGATE_MECHANICAL_BOUNDARIES'
            and value.get('scope') == 'NORMAL_SESSION_ROUNDS_RESTART_AND_PREPARED_NATIVE_SCENARIO'
            and value.get('native_E_status') == 'BLOCKED_INFORMATIONAL_ACTION_PACKET_UNAVAILABLE'
            and value.get('current_source_identity_sha256') == digest(current_source['pins'])
            and value.get('code_pins') == current_source['pins'],
            'direct_gate_current_aggregate_acceptance_required')
    verify_pins(project, value['code_pins'])
    require(value.get('historical_review_pins') == HISTORICAL_REVIEW_PINS
            and value.get('historical_result_pins') == HISTORICAL_RESULT_PINS
            and value.get('historical_startup_basis') == HISTORICAL_STARTUP_BASIS,
            'direct_gate_historical_basis_identity')
    for relative, expected in {**HISTORICAL_REVIEW_PINS, **HISTORICAL_RESULT_PINS, **HISTORICAL_STARTUP_BASIS}.items():
        require(digest(read(project, relative, 64 * 1024 * 1024)) == expected,
                'direct_gate_historical_basis_changed')
    historical = json.loads(read(project, 'review/transport_response_recovery_passage/mechanical_result_review.json'))
    for relative, expected in historical['full_witness_pins'].items():
        require(relative.startswith('review/transport_response_recovery_passage/')
                and 'private' not in Path(relative).parts
                and digest(read(project, relative, 64 * 1024 * 1024)) == expected,
                'direct_gate_historical_transport_witness_changed')
    prior_path = PRIOR_STAGE04 + '/mechanical_result_review.json'
    prior_raw = read(project, prior_path)
    prior = json.loads(prior_raw)
    require(value.get('prior_stage04_review_sha256') == digest(prior_raw)
            == 'd34a1a195771d74d8e665d758ed658739f793de5310d85dd0992bbce7e355572'
            and prior.get('current_source_identity_sha256')
                == 'cfb430a3fc863049eb2503ebc02026b0fc7b1a2d4350f397da7d8bb860a0c343'
            and digest(read(project, prior['result_path'])) == prior['result_sha256'],
            'direct_gate_prelive_historical_basis')
    for relative, expected in prior['supplemental_result_pins'].items():
        require(relative.startswith(PRIOR_STAGE04 + '/offline_attempts/')
                and digest(read(project, relative, 64 * 1024 * 1024)) == expected,
                'direct_gate_prelive_historical_witness_changed')
    prior_prelive = 'review/stage04_prelive_passage/mechanical_result_review.json'
    prior_prelive_raw = read(project,prior_prelive)
    prior_prelive_value = json.loads(prior_prelive_raw)
    require(value.get('prior_prelive_review_sha256') == digest(prior_prelive_raw)
        and prior_prelive_value.get('current_source_identity_sha256')
            == 'd7398e45cc8e5da4969c839b95cc282cf9bb4f3fe42495dfa8db7f11c0449cef'
        and digest(read(project,prior_prelive_value['result_path'])) == prior_prelive_value['result_sha256']
        and value.get('actual_behavior_review_sha256')
            == digest(read(project,REVIEW_PASSAGE+'/actual_behavior_review.json')),
        'direct_gate_stream_console_historical_basis')
    stream_path = 'review/stream_console_continuation_passage/mechanical_result_review.json'
    stream_raw = read(project, stream_path); stream = json.loads(stream_raw)
    require(value.get('prior_stream_review_sha256') == digest(stream_raw)
        == 'aa50e8ca510e7758370a75b0f35a656cb5fdcead5abdf7d587cbb9f3f292daa6'
        and stream.get('current_source_identity_sha256')
            == 'db19ce4e5bd70a7fda650541549ace86b32a843025c8cb3219405067b1cce8b3'
        and digest(read(project, stream['result_path'])) == stream['result_sha256'],
        'direct_gate_metadata_historical_basis')
    for historical_key in ('public_witness_pins', 'supplemental_result_pins'):
        for path, pin in stream.get(historical_key, {}).items():
            require(path.startswith('review/stream_console_continuation_passage/')
                and 'private' not in Path(path).parts and digest(read(project, path)) == pin,
                'direct_gate_metadata_historical_witness_changed')
    metadata_path = 'review/metadata_continuation_passage/mechanical_result_review.json'
    metadata_raw = read(project, metadata_path)
    metadata = json.loads(metadata_raw)
    require(value.get('prior_metadata_review_sha256') == digest(metadata_raw)
        == '3e7f7f69e2219874de00c70c1732f824b19a8da6c165b578e389349dc1ad75e7'
        and metadata.get('current_source_identity_sha256')
            == 'c4434a67904ca29ab5e3ac49b0cb8f20e5e68779ae4eb658c98fd56e75ac5154'
        and digest(read(project, metadata['result_path'])) == metadata['result_sha256'],
        'direct_gate_opaque_metadata_historical_basis')
    # Historical narrow-profile outcomes retain their exact bytes and scope;
    # the current opaque profile is established by the separate current exam.
    for historical_key in ('public_witness_pins', 'supplemental_result_pins', 'historical_preservation_pins'):
        for path, pin in metadata.get(historical_key, {}).items():
            require(path.startswith('review/metadata_continuation_passage/')
                and 'private' not in Path(path).parts and digest(read(project, path)) == pin,
                'direct_gate_opaque_metadata_historical_witness_changed')
    opaque_path = 'review/opaque_metadata_passage/mechanical_result_review.json'
    opaque_raw = read(project, opaque_path)
    opaque = json.loads(opaque_raw)
    require(value.get('prior_opaque_review_sha256') == digest(opaque_raw)
        == 'fb4a3e1101c7c6e360957a70d2e157653d762f358dbda5eb0ba7a3aac2f47c4a'
        and opaque.get('current_source_identity_sha256')
            == '85e561f6c30aa29d25f6b1c7a3be151f6fcee20bbeb9e6ba74c21210ad559fbc'
        and digest(read(project, opaque['result_path'])) == opaque['result_sha256'],
        'direct_gate_normal_session_historical_basis')
    for historical_key in ('public_witness_pins', 'supplemental_result_pins', 'historical_preservation_pins'):
        for path, pin in opaque.get(historical_key, {}).items():
            require(path.startswith('review/opaque_metadata_passage/')
                and 'private' not in Path(path).parts and digest(read(project, path)) == pin,
                'direct_gate_normal_session_historical_witness_changed')
    relative = value.get('result_path')
    require(type(relative) is str
            and re.fullmatch(re.escape(REVIEW_PASSAGE)
                + r'/offline_attempts/NORMAL_SESSION_V[0-9]{2}/result\.json', relative) is not None
            and digest(read(project, relative)) == value.get('result_sha256'),
            'direct_gate_focused_delta_evidence_changed')
    focused_path = FOCUSED_SOURCE_REVIEW
    focused_raw = read(project, focused_path)
    focused = json.loads(focused_raw)
    result = json.loads(read(project, relative))
    require(value.get('focused_source_review_path') == focused_path
            and value.get('focused_source_review_sha256') == digest(focused_raw)
            and focused.get('reviewer') == '/root/semantic_continuation_reviewer'
            and focused.get('status') == 'SOURCE_ACCEPTED_FOR_NORMAL_SESSION_FOCUSED_EXAM'
            and focused.get('scope') == 'NORMAL_ROUNDS_AND_NATIVE_SCENARIO_ONLY_NO_REAL_AUTH_MODEL_OR_SAVE'
            and focused.get('runtime_pins') == current_source['pins']
            and focused.get('approved_argv') == ['.venv-plan/bin/python', '-I', '-S', '-B',
                REVIEW_PASSAGE + '/focused.py', '--workspace', str(Path(relative).parent)]
            and result.get('schema') == 'radik.normal_session_focused_result.v01'
            and result.get('status') == 'OBSERVATIONS_COMPLETE_INDEPENDENT_INTERPRETATION_REQUIRED'
            and type(result.get('case_count')) is int and 1 <= result['case_count'] <= 128
            and result['case_count'] == focused.get('expected_case_count')
            and type(result.get('cases')) is list and len(result['cases']) == result['case_count']
            and result.get('source_review_sha256') == digest(focused_raw)
            and result.get('code_pins') == focused.get('code_pins'),
            'direct_gate_focused_source_certificate_binding')
    verify_pins(project, focused['code_pins'])
    for relative, expected in value.get('supplemental_result_pins', {}).items():
        require(relative.startswith(REVIEW_PASSAGE + '/offline_attempts/')
                and digest(read(project, relative, 64 * 1024 * 1024)) == expected,
                'direct_gate_mechanical_supplement_changed')
    return value


def live_transition(*, preflight_receipt, role=None, project=PROJECT, scope="exam"):
    """B is current predicate satisfaction, not an author-issued certificate."""
    from config.application_profile_gate import select
    selected_profile=select(project)
    require(scope=='console' or selected_profile is None,'direct_gate_legacy_exam_is_historical_under_current_profile')
    review = source_review(project, runtime=True)
    require(review.get('transition_contract') == ('DYNAMIC_INFORMATIONAL_O_A_E_WORK_C_V28' if selected_profile is not None else 'DYNAMIC_INFORMATIONAL_O_A_WORK_C_V01'),
            'direct_gate_transition_not_reviewed')
    dependency_review(project)
    if selected_profile is None:mechanical_review(project, review)
    value = preflight_receipt
    require(type(value) is dict and value.get('schema') == 'radik.direct_plan_catalog_receipt.v01'
            and value.get('source_identity_sha256') == digest(review['pins'])
            and value.get('catalog_origin') == 'https://api.openai.com/v1/models'
            and value.get('selected_model') == 'gpt-6.1-sol'
            and value.get('selected_model_observed') is True
            and value.get('requested_effort') in ('low','medium','high','xhigh','max')
            and value.get('requested_service_tier') == 'default'
            and value.get('inference_calls') == 0, 'direct_gate_actual_catalog_required')
    now = int(time.time())
    require(type(value.get('observed_at')) is int and 0 <= now - value['observed_at'] < 300,
            'direct_gate_catalog_expired')
    from config.application_profile_gate import rehearsal_context,require_external_owner
    rehearsal=rehearsal_context(project)
    connection = value.get('connection', {})
    if rehearsal is not None:
        from app.ordinary_rehearsal import validate_fixture_catalog
        validate_fixture_catalog(project,rehearsal,value)
    else:
        require_external_owner(project,'MODEL')
    require(connection.get('status') == ('ISOLATED_REHEARSAL_GRANT_NO_AUTHORITY' if rehearsal is not None else 'OWN_PLAN_GRANT_VERIFIED')
            and connection.get('issuer_verified') is (False if rehearsal is not None else True)
            and connection.get('issued_client_identity_binding_verified') is (False if rehearsal is not None else True)
            and type(connection.get('connection_id')) is str
            and connection['connection_id'].startswith('radik-plan:')
            and REQUIRED_SCOPES.issubset(set(connection.get('scopes', [])))
            and type(connection.get('expires_at')) is int
            and connection['expires_at'] > now + 30,
            'direct_gate_current_verified_own_grant_required')
    require(role is None or role in ('orchestrator', 'architect', 'critic'), 'direct_gate_role_scope')
    from review.transport.model_scope import read_scope_state
    selected = read_scope_state(project, scope)
    require(selected['active_attempt_id'] is None and selected['remaining_attempts'] > 0,
            'direct_gate_budget_active_unknown_or_exhausted')
    if scope == 'console':
        console_execution_entry(project)
        require(not selected.get('unacknowledged_unknown_attempt_ids',selected['unknown_attempt_ids']), 'direct_gate_budget_active_unknown_or_exhausted')
        settings = selected.get('model_settings')
        require(type(settings) is dict and settings.get('model') == value['selected_model']
                and settings.get('effort') == value['requested_effort']
                and settings.get('service_tier') == value['requested_service_tier']
                and selected.get('source_identity_sha256') == digest(review['pins']),
                'direct_gate_current_console_settings_required')
    else:
        require(value['requested_effort'] == 'high','direct_gate_legacy_exam_effort')
    return True


def actual_business_review(project=PROJECT):
    """Accept historical business observations without rewriting their late STOPPED."""
    raw = read(project, ACTUAL_REVIEW)
    value = json.loads(raw)
    require(value.get('schema') == 'radik.independent.actual_business_chain_acceptance.v01'
            and value.get('status') == 'ACTUAL_BUSINESS_CHAIN_ACCEPTED_WITH_LATE_NEGATIVE_FAILURE'
            and value.get('reviewer') == '/root/semantic_continuation_reviewer'
            and value.get('scope') == 'ACTUAL_F2902C1EF6C5_FIXED_TWO_DOCUMENT_OWNED_REFERENCE_SAVE_ONLY'
            and value.get('run_id') == 'f2902c1ef6c5'
            and value.get('original_result', {}).get('status') == 'LIVE_EXAM_STOPPED_NO_AUTOMATIC_RESTART',
            'direct_gate_actual_business_acceptance_required')
    # Mutable originals are copied into the immutable actual basis. Future owner
    # checkpoints may advance; activation separately verifies current quota/head.
    basis = json.loads(read(project, LEGACY_REVIEW_PASSAGE + '/actual_basis_inventory.json'))
    require(basis.get('actual_review_sha256') == digest(raw)
            and basis.get('original_pins') == value['evidence_pins'],
            'direct_gate_actual_basis_inventory_binding')
    for original, expected in value['evidence_pins'].items():
        ref = basis['copies'].get(original)
        require(type(ref) is dict and ref.get('sha256') == expected,
                'direct_gate_actual_basis_copy_binding')
        path = ref.get('path')
        if original == 'review/returns/RADIK_RETURN_20261015T145048.532310Z.tar.gz':
            require(path == original and ref.get('kind') == 'HASH_LINKED_ORIGINAL_ARCHIVE_NOT_EMBEDDED',
                    'direct_gate_actual_archive_hash_link')
        else:
            require(type(path) is str and path.startswith(LEGACY_REVIEW_PASSAGE + '/actual_basis/'),
                    'direct_gate_actual_basis_copy_binding')
        require(digest(read(project, path, 64 * 1024 * 1024)) == expected,
                'direct_gate_actual_basis_changed')
    return value


def console_source_entry(project=PROJECT):
    from config.application_profile_gate import select
    selected=select(project)
    if selected is not None:
        from app.task_budget import read_state
        current=read_state(project)
        require(current['application_profile_ref']==selected['profile_ref'],'direct_gate_profile_source_scope')
        return selected['admission']
    """Pre-setup source predicate grants no inference or effect authority."""
    source = source_review(project, runtime=True)
    actual = actual_business_review(project)
    console_raw = read(project, ACTUAL_CONSOLE_REVIEW)
    console_actual = json.loads(console_raw)
    require(console_actual.get('schema') == 'radik.independent.actual_console_cold_writeback_review.v01'
            and console_actual.get('status') == 'ACTUAL_CONSOLE_COLD_AND_WRITEBACK_ACCEPTED'
            and console_actual.get('scope') == 'ACTUAL_46A45D14FCC1_BASELINE_TWO_DOCUMENT_INFORMATIONAL_CONSOLE_ONLY'
            and console_actual.get('reviewer') == '/root/semantic_continuation_reviewer'
            and console_actual.get('baseline_sha256') == digest(read(project, PRIOR_STAGE04 + '/baseline.json')),
            'direct_gate_actual_console_review_required')
    copies = console_actual.get('immutable_evidence_copy_pins')
    require(type(copies) is dict and copies, 'direct_gate_actual_console_basis_required')
    for relative, expected in copies.items():
        require(type(relative) is str and relative.startswith(PRIOR_STAGE04 + '/actual_basis/')
                and digest(read(project, relative,64 * 1024 * 1024)) == expected,
                'direct_gate_actual_console_basis_changed')
    value = json.loads(read(project, BEHAVIOR_REVIEW))
    migration_raw = read(project, PRIOR_STAGE04 + '/migration_review.json')
    migration = json.loads(migration_raw)
    proposal_raw = read(project, PRIOR_STAGE04 + '/migration_proposal.json')
    require(migration.get('reviewer') == '/root/semantic_continuation_reviewer'
            and migration.get('status') == 'ACCEPTED_FOR_PRESERVING_STAGE04_CONSOLE_SOURCE_TRANSITION'
            and migration.get('proposal_sha256') == digest(proposal_raw)
            and migration.get('source_identity_sha256')
                == 'cfb430a3fc863049eb2503ebc02026b0fc7b1a2d4350f397da7d8bb860a0c343',
            'direct_gate_console_migration_review_required')
    from app.task_budget import read_state
    current = read_state(project)
    require(current['source_identity_sha256'] == digest(source['pins'])
            and current['historical_transition_preserved'] is True,
            'direct_gate_prelive_current_admission_required')
    require(value.get('schema') == 'radik.independent.normal_session_source_review.v01'
            and value.get('status') == 'SOURCE_ACCEPTED_FOR_STAGE04_CONSOLE_ENTRY_WITHOUT_INFERENCE'
            and value.get('reviewer') == '/root/semantic_continuation_reviewer'
            and value.get('scope') == 'DYNAMIC_INFORMATIONAL_TASKS_NO_EFFECTS_ENTRY_ONLY'
            and value.get('code_pins') == source['pins']
            and value.get('console_profile') == 'stage04_dynamic_information_v01'
            and value.get('current_source_identity_sha256') == digest(source['pins'])
            and value.get('actual_acceptance_review_sha256') == digest(read(project, ACTUAL_REVIEW))
            and value.get('actual_console_review_sha256') == digest(console_raw)
            and value.get('migration_review_sha256') == digest(migration_raw)
            and value.get('migration_proposal_sha256') == digest(proposal_raw)
            and value.get('current_source_admission_sha256') == current['current_source_admission_sha256']
            and value.get('separate_current_mechanical_result_before_provider') is True
            and value.get('entry_authorizes_model_or_effect') is False,
            'direct_gate_console_source_review_required')
    verify_pins(project, value['code_pins'])
    require(actual.get('consumed_permission', {}).get('actual_effect_policy') == 'CLOSED_REVISION2',
            'direct_gate_exam_effect_window_not_closed')
    return value


def console_transition(project=PROJECT):
    """Dependency-bound no-effect menu entry; model dispatch separately needs M."""
    value = console_source_entry(project)
    dependency_review(project)
    return value


def console_execution_entry(project=PROJECT):
    from config.application_profile_gate import select
    selected=select(project)
    if selected is not None:
        console_source_entry(project)
        return selected['admission']
    """Require result-bound real-use approval separately from copied-ledger proof."""
    source = source_review(project, runtime=True)
    console_source_entry(project)
    mechanical = mechanical_review(project,source)
    value = json.loads(read(project,REVIEW_PASSAGE + '/real_execution_review.json'))
    from app.task_budget import read_state
    current = read_state(project)
    require(value.get('schema') == 'radik.independent.normal_session_real_execution_review.v01'
            and value.get('status') == 'ACCEPTED_FOR_STAGE04_OWNED_CONSOLE_EXECUTION'
            and value.get('scope') == 'INFORMATIONAL_TASKS_ONLY_NO_SAVE_NATIVE_E_BLOCKED'
            and value.get('reviewer') == '/root/semantic_continuation_reviewer'
            and value.get('code_pins') == source['pins']
            and value.get('source_identity_sha256') == digest(source['pins'])
            and value.get('migration_proposal_sha256') == digest(read(project,PRIOR_STAGE04 + '/migration_proposal.json'))
            and value.get('migration_review_sha256') == digest(read(project,PRIOR_STAGE04 + '/migration_review.json'))
            and value.get('current_source_admission_sha256') == current['current_source_admission_sha256']
            and value.get('mechanical_result_review_sha256') == digest(read(project,MECHANICAL_REVIEW))
            and value.get('focused_result_sha256') == mechanical['result_sha256'],
            'direct_gate_stage04_real_execution_review_required')
    verify_pins(project,value['code_pins'])
    return value
