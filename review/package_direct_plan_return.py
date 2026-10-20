"""Reviewed source return and future owned live-evidence return selection.

This stdlib-only writer conveys no auth, inference, behavior or SAVE admission.
Source packaging uses an independently pinned inventory. Future live packaging
uses independently reviewed selectors and preserves actual success or failure.
Private directories are pruned before descent; no P/Git/network/native execution.
"""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import tarfile
import time

PROJECT = Path('/Users/admin/Projects/RadiolariaRadik')
PASSAGE = 'review/direct_plan_passage'
SOURCE_PASSAGE = 'review/actual_save_console_passage'
RUNTIME_PASSAGE = SOURCE_PASSAGE
SETUP_PASSAGE = 'review/before_owner_run_fix_passage'
SOURCE_KEY = 'actual_save_console'
SOURCE = 'review/package_direct_plan_return.py'
PACK_REVIEW = SOURCE_PASSAGE + '/return_source_review.json'
LIVE_PACK_REVIEW = RUNTIME_PASSAGE + '/live_return_source_review.json'
OWNER_REVIEW = SOURCE_PASSAGE + '/owner_source_review.json'
RUNTIME_REVIEW = RUNTIME_PASSAGE + '/runtime_source_review.json'
MECHANICAL_REVIEW = RUNTIME_PASSAGE + '/mechanical_result_review.json'
FOCUSED_SOURCE_REVIEW = RUNTIME_PASSAGE + '/mechanical_source_review.json'
FOCUSED_RESULT = RUNTIME_PASSAGE + '/offline_attempts/ACTUAL_SAVE_CONSOLE_V01/result.json'
HISTORICAL_STARTUP_BASIS = {
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
SOURCE_SELECTION = SOURCE_PASSAGE + '/source_selection.json'
SOURCE_REPORT = Path('/private/tmp/radik_owner_delivery_actual_save_console/README_FIRST_RU.txt')
CONTINUATION_REPORT = Path('/private/tmp/radik_owner_delivery_actual_save_console/CONTINUE_AFTER_OWNER_RUN_RU.txt')
HANDOFF = Path('/private/tmp/radik_owner_delivery_actual_save_console/HANDOFF_REPORT_RU.txt')
LIVE_HANDOFF = Path('/Users/admin/Downloads/RADIK_BOUNDED_MEMORY_AND_RETURN_REPAIR_RU.txt')
LIVE_HANDOFF_PINS = {
    '/Users/admin/Downloads/RADIK_SEMANTIC_CONTRACT_AND_CONTINUATION_RU.txt': '8b033f40513f3af4840ef9d913272b2360f71d5636eaf392ef0964b5f5290dc2',
    '/Users/admin/Downloads/RADIK_BOUNDED_MEMORY_AND_RETURN_REPAIR_RU.txt': '140a0c12d07ebaa3d05b93993703367109c786f5df6283a80d2e47821cf6b73f',
}
PASSAGE_PRIOR_ARCHIVES = {
    'RADIK_RETURN_20261015T142133.456027Z.tar.gz': 'ffc6a8c454048d8ff3e5cba530ff1cf491ec2072fae7272317d45ef8e672a4e1',
    'RADIK_RETURN_20261015T145048.532310Z.tar.gz': '9bd0b9f52fde9d25e54d3868410a6c7b6acb86b3d5a2de8fe9a46b8e8f91003f',
    'RADIK_RETURN_20261015T120432.490005Z.tar.gz': 'c48dd503c9db9ed4da581ff9385b594340d90a4bfb4c549c934b00d2a9350aa0',
    'RADIK_RETURN_20261015T125744.255577Z.tar.gz': 'e911481389b0e3bd2fb9c6710896dec11cd836532dc199ceefd2791a3a40bab7',
    'RADIK_RETURN_20261015T102502.394948Z.tar.gz': '21053aeaeaa7cc1d52638c420b2e046fc7141a340e4854ac5ac3944c2be3880d',
    'RADIK_RETURN_20261015T103542.714907Z.tar.gz': '5da46ef030ecdaa4ee01ec5d4a7517aaccccf0f43976e421261a7e5b1ac3a9ba',
    'RADIK_RETURN_20261014T202833.103479Z.tar.gz': 'a0c7956fa66f1c93ee5c403d1522f4e8a0eed320f22901340ee2f31b5b775879',
    'RADIK_RETURN_20261014T210111.656464Z.tar.gz': '4ec7e02db1e6575c504760707ae16123f8d6a13cb402dad2d84c206495caf008',
    'RADIK_RETURN_20261014T165247.081767Z.tar.gz': 'c2978ce5afa6c01edff62b1992762d1e96b8e439da2776d3473352b8749f93f4',
    'RADIK_RETURN_20261014T170950.719783Z.tar.gz': '017fa7d391d290b1752e0fb44a3e1c61dcaa8221029b95f0029b942bbf5352c5',
    'RADIK_RETURN_20261014T124555.685750Z.tar.gz': 'bde27af9cfc79e3cdc23d8f7231888f2b48b84da3e7c9ae52cefe6d59bb6e998',
    'RADIK_RETURN_20261014T104722.187947Z.tar.gz': 'a22eb0243b0057f9a025064a4c81ee8220c1f612b0f12f8838ac742450bfc647',
    'RADIK_RETURN_20261014T105611.872418Z.tar.gz': '5e19eaeed3fc5e542ff92d425a6491af7decabd087a7111b3e4d8d582c95c23f',
    'RADIK_RETURN_20261014T080854.132485Z.tar.gz': 'ee0be02b459f022c3a2c4555a41a80876867e49ff383f23bca8ae3534d5013bf',
    'RADIK_RETURN_20261014T092636.852889Z.tar.gz': 'c9714eb5738955f9af8f5f5354b9b50ca8332b7813583ab8f00f98ebfd9589fd',
    'RADIK_RETURN_20261014T093853.924752Z.tar.gz': 'bdba975fe1caac0dc0676e0e2ab69949c4bd6e3039f0539a2627785e4bc16a89',
    'RADIK_RETURN_20261014T142237.612273Z.tar.gz': '519a55d1a83e35001357651e8a2a2daac4cc6c1e70da957237c14df22ec2cd0b',
    'RADIK_RETURN_20261014T152454.037248Z.tar.gz': '6abbb84e29ec757cbac77b6b267235bfc980f17e0801782980ea726df0e48bca',
    'RADIK_RETURN_20261014T183449.314330Z.tar.gz': 'a9646aaa1181f9d6d694cb6d8b892c093097cfc56ddd567b693e685c6662b123',
    'RADIK_RETURN_20261014T193000.908500Z.tar.gz': '30971a333822bf17a66dfc7f3ae93d73a85456467f878261cbe3c40b02222370',
}
REFERENCE_REVIEW = 'review/login_local_deny_passage/source_preparation_review_before_deferred.json'
REFERENCE_SHA = '0f84b5136e4d8b266db74759936ec9de833928173b7da4ed44cfd7e940e5cb1e'
PRIOR_ARCHIVES = {
    'RADIK_RETURN_20261014T055156.299001Z.tar.gz': '84feaae117af0ea49745acca072950e9b3aff9d4264cefac852e898aa2d0a30d',
    'RADIK_RETURN_20261014T052030.964818Z.tar.gz': '6bcac2b02558dc7e97131fd00cc3cd6d762f480182be8b353126587b0261dafb',
    'RADIK_RETURN_20261014T050338.196184Z.tar.gz': '9b594381fee41790567c7553ffdec1052e8cd010e161a9f53a24f5495ca9d38e',
    'RADIK_RETURN_20261014T042644.028460Z.tar.gz': 'e0555de1d7ffef7fd336f90e6eaaed18409a15ed95b0d98aee3e556f321ded62',
    'RADIK_RETURN_20261013T230541.387790Z.tar.gz': '44d1c923b8f037e57b36589b382162c5ffe6cb4fc0e9c24d0a5cdfcaf5a1af9b',
    'RADIK_RETURN_20261013T213734.604112Z.tar.gz': 'd45ba69bcf7eb9b1f21417a38c5a81db419fa3b1d504cb989b5d1cfc72c0a79b',
    'RADIK_RETURN_20261013T082836.974197Z.tar.gz': '243d0bc6d52e5ef359295293d217ebd49a0f86b6323995fbbf3573e5f022bd85',
    'RADIK_RETURN_20261013T120716.437783Z.tar.gz': 'bcb0ac6a021eb3fa90003d1fc2e7fdd99f98077e04ee9125e236e3f07e7f29da',
    'RADIK_RETURN_20261013T135227.733723Z.tar.gz': '7193fce1d1346c883753b9329c2c47d082b14e5140bad205ab800b19259130ba',
    'RADIK_RETURN_20261013T164943.826453Z.tar.gz': '8506eb2a8bf4ef3366ec8f7d8ad0ef558f319a93fdfb3764d645c1466622e25f',
    'RADIK_RETURN_20261013T192009.835281Z.tar.gz': 'c9ac7929ab99ebe0d6491856fe7dd81b5c4f7dc03900d528e56a7ee9da553e1d',
    'RADIK_RETURN_20261013T200102.009193Z.tar.gz': '146d81e41a1c546b7110a76f5b6aa46d14c7ebcef768d2efdf6e7410d8cb2154',
}
FORBIDDEN = {'.git', '.venv', '.venv-plan', '.codex', '.aws', '__pycache__', 'node_modules',
    'private', 'state_private', 'codex-home', 'nativecache', 'native-cache', 'cache', 'sqlite',
    'logs', 'log', 'test_dependencies', 'wheels', 'wheelhouse', 'env', 'venv', 'Arena', 'arena',
    'return_verifications', 'owned_simulated_project', '.env', 'credentials.json', 'tokens.json'}
FORBIDDEN_PREFIXES = ('private_native', 'process-tmp', 'owned_auth_phase_mechanical', 'auth.json', '.env.')
SUFFIXES = {'.py', '.json', '.jsonl', '.txt', '.md', '.lock', '.journal', '.sha256', '.toml', '.diff'}
SECRET_KEYS = {'access_token', 'refresh_token', 'id_token', 'authorization_code', 'code_verifier',
    'client_secret', 'Authorization', 'headers', 'token_endpoint_body', 'callback_url',
    'authorization_url','email','subject','client_id','host_id','id_nonce','nonce',
    'raw_environment','environment_variables','stderr','raw_body','jwks_response'}
CURRENT_FILES = ('README.md', 'AGENTS.md', '.gitignore', 'radik', SOURCE, 'review/live_exam_document.py',
    'review/transport/radik_owner_start.py', 'review/transport/radik_local_operator.py',
    'review/transport/direct_plan_gate.py', 'review/transport/plan_dependencies.py',
    'review/direct_plan_mechanical.py', 'review/direct_plan_auth_cases.py', 'review/transport/owner_failure_report.py')
HISTORICAL_FILES = ('review/reference-before.json', REFERENCE_REVIEW,
    'review/login_local_deny_passage/reference_boundary_before.json',
    'review/current_passage/connected_result_review.json', 'review/current_passage/source_review.json',
    'review/dependencies/inventory.json', 'review/dependencies/upstream_checks.txt',
    'review/fix_transport_passage/auth_reuse_result_review.json',
    'review/fix_transport_passage/native_host/readiness.json')
LIVE_STATUSES = ('OBSERVATIONS_COMPLETE_INDEPENDENT_LIVE_INTERPRETATION_REQUIRED',
    'LIVE_EXAM_STOPPED_NO_AUTOMATIC_RESTART')
MUTABLE_OWNER_OBSERVATIONS = tuple(PASSAGE + '/' + name for name in (
    'owner_auth_observations.json', 'owner_dependency_observation.json', 'owner_state.json','owner_phase_journal.json'))
AUTH_SOURCE_FILES = frozenset({
    'review/transport/radik_owner_start.py', 'review/transport/direct_plan_gate.py',
    'review/transport/plan_dependencies.py', 'review/package_direct_plan_return.py',
    'review/transport/owner_failure_report.py', 'app/__init__.py', 'app/plan_auth.py',
    'config/model_policy.json', 'review/transport/model_scope.py', 'config/console_model_policy.json',
    'app/task_budget.py', 'config/task_model_policy.json',
    'app/source_admission.py', 'app/stage04_diagnostics.py', 'app/console_continuation.py',
    'config/requirements-plan-base.txt', 'config/requirements-plan-auth.txt',
    'review/dependencies/inventory.json', 'review/direct_plan_passage/bootstrap_identity.json',
    'review/direct_plan_passage/auth_dependency_metadata.json', 'review/direct_plan_passage/protocol_references.json',
})
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


RETURN_REFUSAL_CODES = frozenset({
    'return_B_exact_source_required',
    'return_actual_delivered_pair_readback',
    'return_actual_early_failure_required',
    'return_actual_live_result_and_policy_close_observation_required',
    'return_auth_accounting_closed_row',
    'return_auth_actual_continuation_required',
    'return_auth_actual_phase_binding',
    'return_auth_actual_terminal_checkpoint_changed',
    'return_auth_delta_A_identity_binding',
    'return_auth_delta_code_identity_changed',
    'return_auth_delta_code_pin_closure',
    'return_auth_delta_exact_passage_paths',
    'return_auth_delta_exact_source_required',
    'return_auth_delta_finite_source_selection',
    'return_auth_delta_independent_packaging_review_required',
    'return_auth_delta_prior_source_pair_identity',
    'return_auth_delta_source_selector_not_accepted',
    'return_auth_ledger_or_quota_changed',
    'return_auth_only_failure_current_source_phase_binding',
    'return_auth_only_failure_phase',
    'return_auth_only_failure_selector_not_accepted',
    'return_auth_only_no_transport_directory',
    'return_auth_only_source_closure',
    'return_auth_only_source_identity_changed',
    'return_auth_operation_id',
    'return_auth_public_http_accounting_required',
    'return_auth_quota_directory',
    'return_auth_success_current_source_terminal_required',
    'return_auth_success_selector_not_accepted',
    'return_auth_verified_public_receipt_required',
    'return_auth_writer_closure',
    'return_auth_writer_identity_changed',
    'return_auth_writer_not_accepted',
    'return_catalog_observation_schema',
    'return_checksum_created_before_publish',
    'return_checksum_final_must_be_absent',
    'return_code_identity_changed',
    'return_complete_safe_tar_inventory',
    'return_completed_prior_reference_basis',
    'return_current_state_or_reference_refused',
    'return_delivery_receipt_binding',
    'return_destination_required',
    'return_duplicate_archive_path',
    'return_early_failure_selector_not_accepted',
    'return_engineering_actual_live_manifest_basis',
    'return_engineering_exact_live_link',
    'return_engineering_independent_behavior_result_binding',
    'return_engineering_live_delivered_pair_readback',
    'return_engineering_live_delivery_receipt_binding',
    'return_engineering_live_pair_identity',
    'return_engineering_live_review_status_binding',
    'return_engineering_owned_live_archive',
    'return_exact_applied_recovery_basis',
    'return_exact_owned_live_directory',
    'return_exact_owner_continuation_required',
    'return_exact_project_required',
    'return_exact_public_recovery_receipt_path',
    'return_exact_source_snapshot_and_code_closure',
    'return_failure_continuation_identity',
    'return_failure_writer_closure',
    'return_failure_writer_identity_changed',
    'return_failure_writer_not_accepted',
    'return_file_changed_during_read',
    'return_first_live_aggregate_source_changed',
    'return_first_live_current_aggregate_binding',
    'return_first_live_focused_evidence_changed',
    'return_first_live_focused_source_certificate_binding',
    'return_first_live_focused_source_changed',
    'return_first_live_focused_supplement_changed',
    'return_first_live_historical_basis_changed',
    'return_first_live_runtime_basis_binding',
    'return_first_live_runtime_identity_changed',
    'return_future_selector_review_required',
    'return_handoff_finite_selector',
    'return_handoff_identity',
    'return_handoff_operation_binding',
    'return_historical_transport_witness_changed',
    'return_independent_packaging_review_required',
    'return_independent_review_required',
    'return_manifest_exact_inventory',
    'return_no_arbitrary_mode_or_paths',
    'return_normal_journal_bytes_changed',
    'return_normal_journal_reference',
    'return_normal_journal_resource_bound',
    'return_normal_operation_identity',
    'return_normal_operation_witness_missing',
    'return_normal_public_journal_path',
    'return_normal_round_close',
    'return_normal_round_operation',
    'return_normal_round_reference',
    'return_normal_transition_required',
    'return_observation_json_depth',
    'return_outside_owned_root',
    'return_owned_public_relative_path',
    'return_owned_root_identity',
    'return_owner_operation_id',
    'return_owner_phase_binding',
    'return_payload_full_readback',
    'return_payload_type',
    'return_preflight_dispatch_ledger_changed_or_unknown',
    'return_prior_archive_outer_identity',
    'return_prior_public_recovery_receipt_binding',
    'return_prior_public_recovery_receipt_path',
    'return_prior_reference_identity',
    'return_prior_reference_review_identity',
    'return_private_fields_refused',
    'return_public_file_type',
    'return_public_ledger_closed_shape',
    'return_public_ledger_schema',
    'return_public_local_recovery_schema',
    'return_public_recovery_history_shape',
    'return_public_symlink_refused',
    'return_reference_baseline_binding',
    'return_reference_current_runtime_review_required',
    'return_reference_exact_public_pin_path',
    'return_reference_executable_closure_required',
    'return_reference_normative_review_binding',
    'return_reference_regular_single_link_bound',
    'return_reference_runtime_pin_map',
    'return_reference_selected_bytes_changed',
    'return_reference_unselected_path',
    'return_regular_single_link_bound',
    'return_resolved_outside_owned_root',
    'return_reviewed_transition_required',
    'return_runtime_closure_path_class',
    'return_runtime_exact_mixed_closure',
    'return_selected_directory_required',
    'return_semantic_activation_binding',
    'return_semantic_continuation_selector',
    'return_semantic_entered_binding',
    'return_semantic_historical_basis_changed',
    'return_semantic_operation_references_required',
    'return_semantic_proposal_binding',
    'return_semantic_reference_shape',
    'return_setup_phase_binding',
    'return_source_inventory_changed',
    'return_source_prompt_archive_path',
    'return_source_prompt_identity',
    'return_source_prompt_member',
    'return_source_ready_honest_pending_required',
    'return_source_snapshot_identity',
    'return_stage04_actual_checkpoint',
    'return_stage04_actual_operation_binding',
    'return_stage04_actual_result_selector',
    'return_stage04_actual_result_shape',
    'return_stage04_approved_source_bytes',
    'return_stage04_approved_source_filename',
    'return_stage04_approved_source_id',
    'return_stage04_archive_path',
    'return_stage04_connected_schema',
    'return_stage04_continuation_chain_binding',
    'return_stage04_continuation_chain_prefix',
    'return_stage04_continuation_chain_review',
    'return_stage04_continuation_chain_source',
    'return_stage04_continuation_operation_binding',
    'return_stage04_continuation_receipt_binding',
    'return_stage04_continuation_review_binding',
    'return_stage04_current_source',
    'return_stage04_drs_payload_readback',
    'return_stage04_drs_record_readback',
    'return_stage04_drs_writeback_reference',
    'return_stage04_exact_code_closure',
    'return_stage04_execution_basis_invalid',
    'return_stage04_execution_basis_required',
    'return_stage04_external_scope',
    'return_stage04_failure_operation',
    'return_stage04_failure_result_selector',
    'return_stage04_failure_transport_binding',
    'return_stage04_finite_inventory',
    'return_stage04_independent_review',
    'return_stage04_material_boundaries_required',
    'return_stage04_native_witness_bound',
    'return_stage04_native_witness_changed',
    'return_stage04_native_witness_selector',
    'return_stage04_no_state_walk',
    'return_stage04_prior_source_pair',
    'return_stage04_project',
    'return_stage04_public_bound',
    'return_stage04_public_selector',
    'return_stage04_reference_pin',
    'return_stage04_report_reservation',
    'return_stage04_result_transport_binding',
    'return_stage04_selected_bytes_changed',
    'return_stage04_selected_path',
    'return_stage04_selected_task',
    'return_stage04_selected_task_shape',
    'return_stage04_snapshot_count',
    'return_stage04_snapshot_scope',
    'return_stage04_source_basis_invalid',
    'return_stage04_task_index_shape',
    'return_stage04_task_result_readback',
    'return_stage04_task_result_reference',
    'return_stage04_task_selection',
    'return_stage04_transport_count',
    'return_stage04_transport_current_source',
    'return_stage04_transport_foreign_reservation',
    'return_stage04_transport_ledger',
    'return_stage04_transport_origin',
    'return_stage04_transport_schema',
    'return_stage04_transport_selector',
    'return_stage04_transport_task_binding',
    'return_stage04_truthful_partial_boundary',
    'return_stage04_witness_owned',
    'return_stage04_writer_changed',
    'return_stage04_writer_review_required',
    'return_symlink_path',
    'return_unknown_guard',
})


_RETURN_STAGE = 'RETURN_PREBUILD'


class ReturnRefusal(ValueError):
    """A closed source guard; no arbitrary exception message is exported."""
    def __init__(self, code):
        self.code = code if code in RETURN_REFUSAL_CODES else 'return_unknown_guard'
        self.stage = _RETURN_STAGE
        super().__init__(self.code)


def return_error_projection(error, *, stage='RETURN_PREBUILD'):
    code=getattr(error,'code',None)
    if type(code) is not str or code not in RETURN_REFUSAL_CODES:code='UNCLASSIFIED_RETURN_FAILURE'
    if stage not in ('RETURN_PREBUILD','RETURN_LOCAL_PAIR','RETURN_DELIVERY','RETURN_CHECKPOINT'):
        stage='UNKNOWN'
    return {'code':code,'stage':stage,'raw_error_recorded':False}


def require(value, reason):
    if not value:
        raise ReturnRefusal(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def excluded(parts):
    return any(part in FORBIDDEN or part.startswith(FORBIDDEN_PREFIXES)
        or part.endswith(('.sqlite', '.sqlite3', '.db', '.wal', '.shm', '.log', '.whl')) for part in parts)


def safe_parents(path, root):
    require(path.is_absolute() and root.is_absolute() and root.is_dir()
        and not root.is_symlink() and root.resolve() == root, 'return_owned_root_identity')
    require(path.is_relative_to(root), 'return_outside_owned_root')
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'return_symlink_path')
        if item == root:
            break
    require(path.resolve().is_relative_to(root), 'return_resolved_outside_owned_root')


def regular(path, root, cap=64 * 1024 * 1024):
    safe_parents(path, root)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= cap,
        'return_regular_single_link_bound')
    return info


def owned(relative):
    require(type(relative) is str and not Path(relative).is_absolute() and '..' not in Path(relative).parts
        and not excluded(Path(relative).parts), 'return_owned_public_relative_path')
    require(not relative.startswith(('state/', 'drs/', 'output/', 'source/reference/')), 'return_current_state_or_reference_refused')
    path = PROJECT / relative
    safe_parents(path, PROJECT)
    return path


def read(relative):
    path = owned(relative)
    info = regular(path, PROJECT)
    raw = path.read_bytes()
    require(len(raw) == info.st_size, 'return_file_changed_during_read')
    return raw


def read_json(relative):
    return json.loads(read(relative))


# Finite normative records required by the current canonical source passage.
# They are reviewed packaging inputs, not a general permission to read P.
REFERENCE_NORMATIVE_PINS = {
    'source/reference/schemas/work_composition_v01.schema.json': 'ac385c7202e39c88890d66fd148c85bfafe35e9c8f79ec9748866be39e6ba6a0',
    'source/reference/schemas/capability_admission_v01.schema.json': 'b09ac99cb2e62ffd95098401a5695a0f018d87d4f2e61f9de723f710ac7455e0',
    'source/reference/schemas/common.schema.json': '961e73333fe62a7d935c7951a1104f1eb02ed7a20cf36c5e7df6d74e6d4d7880',
    'source/reference/schemas/time_envelope.schema.json': 'fffa05739e3eeed6d4cc6b4342d8833d6435aa8e9edbdfdafb96e5a7f3a99424',
    'source/reference/schemas/result_proposal.schema.json': 'd880876a28a03cd586db8f84d3c5c27a40ca526b9a4b8438f62894ef0d75b382',
    'source/reference/schemas/vv_report.schema.json': '44d9db2f5046e39178acc1461a93c670870fae0a2c71db79d61dfd5e193f4854',
    'source/reference/docs/common_action_and_dynamic_composition_checkpoint_v01.md': 'fd708a885e0635e9f82bb8baad212f9cbd6db363888a8ae380893a718201e5e9',
    'source/reference/docs/common_action_and_dynamic_composition_contract_v01.md': '7f747d14065c11e6194fce94aabcd107693e7d27cd75c5558c37cef0a0a3092d',
    'source/reference/specs/current_architecture_lock_v01.md': '0e122424aa2cd7f6b3156596f7038d4b46a5d9fc9b4c0962b565730ea5164682',
    'source/reference/specs/document_authority_index_v01.json': '346c9bb839abc5c24f4bf55a02d46f6dae45ec87e9008ae48918aaa6a8b91d48',
}


def immutable_reference_pins():
    """Only executable paths explicitly present in the current accepted B."""
    runtime = _review(RUNTIME_REVIEW, 'SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION',
                      'DIRECT_CHATGPT_PLAN_SOURCE_ONLY')
    require(runtime.get('transition_contract') == 'CANONICAL_BSEP_BEFORE_ROLE_WIRE_V02',
            'return_reference_current_runtime_review_required')
    pins = runtime.get('pins', {})
    require(type(pins) is dict, 'return_reference_runtime_pin_map')
    result = {relative: expected for relative, expected in pins.items()
              if type(relative) is str and relative.startswith('source/reference/') and relative.endswith('.py')}
    require(result, 'return_reference_executable_closure_required')
    for relative, expected in REFERENCE_NORMATIVE_PINS.items():
        require(pins.get(relative) == expected, 'return_reference_normative_review_binding')
        result[relative] = expected
    for relative, expected in result.items():
        require(not Path(relative).is_absolute() and not set(Path(relative).parts).intersection(('.', '..'))
                and not excluded(Path(relative).parts)
                and type(expected) is str and re.fullmatch(r'[0-9a-f]{64}', expected),
                'return_reference_exact_public_pin_path')
    return result


def source_payload_read(relative):
    """Finite reviewed source postimages; ordinary/auth readers still refuse P."""
    if type(relative) is str and relative.startswith('source/reference/'):
        pins = immutable_reference_pins()
        require(relative in pins, 'return_reference_unselected_path')
        path = PROJECT / relative
        regular(path, PROJECT)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= 64 * 1024 * 1024,
                    'return_reference_regular_single_link_bound')
            raw = stream.read(64 * 1024 * 1024 + 1)
        require(len(raw) == info.st_size and sha(raw) == pins[relative],
                'return_reference_selected_bytes_changed')
        return raw
    return read(relative)


def code_source(relative):
    path = Path(relative)
    return path.name in ('radik', '.gitignore') or path.suffix in ('.py', '.toml') or (
        path.suffix == '.lock' and 'config' in path.parts) or (
        path.suffix == '.txt' and path.name.startswith('requirements') and path.parts[0] == 'config') or (
        path.suffix == '.json' and any(part in ('config', 'schema', 'schemas') for part in path.parts))


def _walk(relative, inventory, group, *, source=False):
    folder = owned(relative)
    require(folder.is_dir(), 'return_selected_directory_required')
    with os.scandir(folder) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        child = relative + '/' + name
        # Do not stat, read, hash or descend into any private excluded entry.
        if excluded(Path(child).parts) or (source and relative in (PASSAGE, SOURCE_PASSAGE, SETUP_PASSAGE)
                and name in ('live_attempts', 'transport_observations',
                'owner_state.json', 'owner_auth_observations.json', 'owner_dependency_observation.json', 'owner_phase_journal.json', 'setup_journal.json')):
            continue
        path = owned(child)
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'return_public_symlink_refused')
        if stat.S_ISDIR(info.st_mode):
            _walk(child, inventory, group, source=source)
        else:
            require(stat.S_ISREG(info.st_mode) and (path.suffix in SUFFIXES or path.name in ('radik', '.gitignore')), 'return_public_file_type')
            _add(child, inventory, group)


def _add(relative, inventory, group):
    path = owned(relative)
    regular(path, PROJECT)
    require(path.suffix in SUFFIXES or path.name in ('radik', '.gitignore'), 'return_payload_type')
    name = group + '/' + relative
    require(name not in inventory, 'return_duplicate_archive_path')
    inventory[name] = relative


def collect_source():
    """A finite current passage, without walking prior campaign or P trees."""
    inventory = {}
    for relative in sorted(AUTH_SOURCE_FILES):
        _add(relative, inventory, 'postimages')
    selection = read_json(SOURCE_SELECTION)
    require(type(selection) is dict and set(selection) == {'schema', 'files'}
        and selection['schema'] == 'radik.actual_save_console_source_selection.v01'
        and type(selection['files']) is list and 4 <= len(selection['files']) <= 512,
        'return_auth_delta_finite_source_selection')
    files = selection['files']
    require(all(type(relative) is str and relative.startswith(SOURCE_PASSAGE + '/')
        and relative not in (SOURCE_SELECTION, PACK_REVIEW) for relative in files)
        and len(files) == len(set(files))
        and {SOURCE_PASSAGE + '/' + name for name in ('status.json', 'owner_source_review.json',
            'failure_reporter_review.json', 'auth_reporter_review.json')}.issubset(files),
        'return_auth_delta_exact_passage_paths')
    _add(SOURCE_SELECTION, inventory, 'evidence')
    for relative in sorted(files):
        _add(relative, inventory, 'evidence')
    for name in PASSAGE_PRIOR_ARCHIVES:
        _add('review/returns/' + name + '.sha256', inventory, 'historical_source_link')
    inventory['README_FIRST_RU.txt'] = '@source_report'
    inventory['CONTINUE_AFTER_OWNER_RUN_RU.txt'] = '@continuation_report'
    inventory['owner_handoff/' + HANDOFF.name] = '@owner_handoff'
    inventory['evidence/' + PACK_REVIEW] = '@packaging_review'
    return inventory


def transport_recovery_return_gate():
    """A final engineering return links evidence without granting behavior."""
    require(sys.dont_write_bytecode and Path(__file__).resolve() == PROJECT / SOURCE,
        'return_auth_delta_exact_source_required')
    raw = read(PACK_REVIEW)
    record = json.loads(raw)
    require(record.get('status') == 'ACCEPTED_FOR_ACTUAL_SAVE_CONSOLE_ENGINEERING_RETURN_PACKAGING'
        and record.get('scope') == 'ACTUAL_SAVE_CONSOLE_REPAIR_RETURN_ONLY'
        and record.get('reviewer') == '/root/semantic_continuation_reviewer'
        and record.get('final_return_branch') in ('SOURCE_FALLBACK', 'LIVE_REVIEWED'),
        'return_auth_delta_independent_packaging_review_required')
    pins = record.get('code_source_pins')
    require(type(pins) is dict and SOURCE in pins and pins, 'return_auth_delta_code_pin_closure')
    for relative, expected in pins.items():
        require(code_source(relative) and sha(read(relative)) == expected,
            'return_auth_delta_code_identity_changed')
    owner = _auth_owner_review()
    require(record.get('auth_source_identity_sha256') == sha(canonical(owner['pins'])),
        'return_auth_delta_A_identity_binding')
    failure_gate()
    auth_return_gate()
    require(record.get('source_selector') == {
        'schema': 'radik.actual_save_console_source_selector.v01', 'selection_path': SOURCE_SELECTION,
        'selection_schema': 'radik.actual_save_console_source_selection.v01',
        'current_auth_closure': sorted(AUTH_SOURCE_FILES),
        'prior_archives': PASSAGE_PRIOR_ARCHIVES, 'prior_archive_binaries_included': False,
        'P_walk': False, 'campaign_walk': False, 'packaging_awards_behavior': False,
        'one_return_per_passage': True, 'automatic_repack': False},
        'return_auth_delta_source_selector_not_accepted')
    runtime = _review(RUNTIME_REVIEW, 'SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION', 'DIRECT_CHATGPT_PLAN_SOURCE_ONLY')
    require(record.get('runtime_source_identity_sha256') == sha(canonical(runtime['pins'])),
        'return_first_live_runtime_basis_binding')
    for relative, expected in runtime['pins'].items():
        require(sha(source_payload_read(relative)) == expected, 'return_first_live_runtime_identity_changed')
    current_mechanical_basis(runtime)
    return record, raw


def _review(relative, status, scope):
    record = read_json(relative)
    require(record.get('status') == status and record.get('scope') == scope
        and record.get('reviewer') == '/root/semantic_continuation_reviewer', 'return_independent_review_required')
    return record


def current_mechanical_basis(runtime):
    value = _review(MECHANICAL_REVIEW, 'PASS_CURRENT_AGGREGATE_MECHANICAL_BOUNDARIES',
                    'DIRECT_PLAN_BOUNDARIES_ONLY')
    require(value.get('schema') == 'radik.independent.actual_save_console_aggregate_review.v01'
            and value.get('current_source_identity_sha256') == sha(canonical(runtime['pins']))
            and value.get('code_pins') == runtime['pins']
            and value.get('historical_review_pins') == HISTORICAL_REVIEW_PINS
            and value.get('historical_result_pins') == HISTORICAL_RESULT_PINS
            and value.get('historical_startup_basis') == HISTORICAL_STARTUP_BASIS,
            'return_first_live_current_aggregate_binding')
    for relative, expected in runtime['pins'].items():
        require(sha(source_payload_read(relative)) == expected, 'return_first_live_aggregate_source_changed')
    for relative, expected in {**HISTORICAL_REVIEW_PINS, **HISTORICAL_RESULT_PINS, **HISTORICAL_STARTUP_BASIS}.items():
        require(sha(read(relative)) == expected, 'return_first_live_historical_basis_changed')
    historical = read_json('review/transport_response_recovery_passage/mechanical_result_review.json')
    for relative, expected in historical['full_witness_pins'].items():
        require(relative.startswith('review/transport_response_recovery_passage/')
                and 'private' not in Path(relative).parts and sha(read(relative)) == expected,
                'return_historical_transport_witness_changed')
    relative = value.get('result_path')
    require(relative == FOCUSED_RESULT and sha(read(relative)) == value.get('result_sha256'),
            'return_first_live_focused_evidence_changed')
    focused_path = FOCUSED_SOURCE_REVIEW
    focused_raw = read(focused_path); focused = json.loads(focused_raw); result = read_json(relative)
    require(value.get('focused_source_review_path') == focused_path
            and value.get('focused_source_review_sha256') == sha(focused_raw)
            and focused.get('reviewer') == '/root/semantic_continuation_reviewer'
            and focused.get('status') == 'SOURCE_ACCEPTED_FOR_ACTUAL_SAVE_CONSOLE_FOCUSED_EXAM'
            and focused.get('scope') == 'ACTUAL_ACCEPTANCE_AND_BASELINE_CONSOLE_ONLY'
            and focused.get('runtime_pins') == runtime['pins']
            and result.get('schema') == 'radik.actual_save_console_focused_result.v01'
            and result.get('status') == 'OBSERVATIONS_COMPLETE_INDEPENDENT_INTERPRETATION_REQUIRED'
            and type(result.get('case_count')) is int and 1 <= result['case_count'] <= 128
            and result['case_count'] == focused.get('expected_case_count')
            and type(result.get('cases')) is list and len(result['cases']) == result['case_count']
            and result.get('source_review_sha256') == sha(focused_raw)
            and result.get('code_pins') == focused.get('code_pins'),
            'return_first_live_focused_source_certificate_binding')
    for relative, expected in focused['code_pins'].items():
        require(sha(source_payload_read(relative)) == expected, 'return_first_live_focused_source_changed')
    for relative, expected in value.get('supplemental_result_pins', {}).items():
        require(relative.startswith(SOURCE_PASSAGE + '/offline_attempts/')
                and sha(read(relative)) == expected, 'return_first_live_focused_supplement_changed')
    return value


def gate():
    global _RETURN_STAGE
    _RETURN_STAGE='RETURN_PREBUILD'
    require(sys.dont_write_bytecode and Path(__file__).resolve() == PROJECT / SOURCE, 'return_B_exact_source_required')
    raw = read(LIVE_PACK_REVIEW)
    record = json.loads(raw)
    require(record.get('status') == 'ACCEPTED_FOR_SOURCE_AND_OWNER_LIVE_RETURN_PACKAGING'
        and record.get('scope') == 'DIRECT_PLAN_PASSAGE_RETURN_ONLY'
        and record.get('reviewer') == '/root/semantic_continuation_reviewer', 'return_independent_packaging_review_required')
    # The runtime closure contains code and finite reviewed metadata/normative inputs.
    # Validate the accepted runtime first; SOURCE code classification stays narrow.
    runtime = _review(RUNTIME_REVIEW, 'SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION', 'DIRECT_CHATGPT_PLAN_SOURCE_ONLY')
    pins = record.get('runtime_source_closure_pins')
    require(record.get('runtime_source_closure_contract') == 'radik.mixed_runtime_source_closure.v01'
            and type(pins) is dict and SOURCE in pins and pins == runtime.get('pins')
            and record.get('code_source_pins') == pins, 'return_runtime_exact_mixed_closure')
    for relative, expected in pins.items():
        require(type(relative) is str and (code_source(relative) or relative in AUTH_SOURCE_FILES
                or relative in REFERENCE_NORMATIVE_PINS), 'return_runtime_closure_path_class')
        require(sha(source_payload_read(relative)) == expected, 'return_code_identity_changed')
    owner = _review(OWNER_REVIEW, 'SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT', 'DIRECT_CHATGPT_PLAN_SOURCE_ONLY')
    require(runtime.get('transition_contract') == 'CANONICAL_BSEP_BEFORE_ROLE_WIRE_V02', 'return_reviewed_transition_required')
    selector = record.get('owner_live_selector')
    require(selector == {'version': 'radik.owner_live_return_selector.v01',
        'evidence_prefix': PASSAGE + '/live_attempts/', 'transport_prefix': PASSAGE + '/transport_observations/',
        'result_statuses': list(LIVE_STATUSES), 'action_policy_close_observation_required': True,
        'mutable_public_observations': list(MUTABLE_OWNER_OBSERVATIONS),
        'behavior_acceptance': 'NOT_AWARDED_BY_PACKAGING', 'automatic_repack': False}, 'return_future_selector_review_required')
    return record, raw, owner, runtime


def _public_native_claim(value, path):
    """Only the public subject of an exact deterministic native claim is exempt."""
    fields={'claim_id','subject','predicate','object_or_value','time_envelope_ref',
        'provenance_refs','evidence_refs','confidence_micros','source_role','source_mode','authority_class'}
    return (len(path)>=4 and path[-4:-1]==('root_review_packet','synthesis_proposal','normalized_claims')
        and type(path[-1]) is int and set(value)==fields
        and value['source_role']=='deterministic_runtime' and value['source_mode']=='DETERMINISTIC'
        and value['authority_class']=='NONE' and type(value['subject']) is str
        and (value['subject'] in ('radik:documents','radik:accepted_document_result',
             'execution_mode_route','selective_recomputation_plan','selective_recomputation_result')
             or re.fullmatch(r'drsaddr_v01:[0-9a-f]{64}',value['subject']) is not None)
        and type(value['confidence_micros']) is int and 0<=value['confidence_micros']<=1000000
        and all(type(value[key]) is str and value[key] for key in ('claim_id','predicate','time_envelope_ref'))
        and all(type(value[key]) is list and all(type(item) is str for item in value[key])
                for key in ('provenance_refs','evidence_refs')))


def _no_secrets(value, depth=0, path=()):
    require(depth <= 96, 'return_observation_json_depth')
    if type(value) is dict:
        forbidden=set(value).intersection(SECRET_KEYS)
        if 'subject' in forbidden and _public_native_claim(value,path):forbidden.remove('subject')
        require(not forbidden, 'return_private_fields_refused')
        for key,item in value.items():
            _no_secrets(item, depth + 1, path+(key,))
    elif type(value) is list:
        for index,item in enumerate(value):
            _no_secrets(item, depth + 1, path+(index,))


def reference_basis():
    raw = read(REFERENCE_REVIEW)
    require(sha(raw) == REFERENCE_SHA, 'return_prior_reference_review_identity')
    review = json.loads(raw)
    proof = review['reference']
    require(review['status'] == 'SOURCE_PREPARED_EXECUTION_BLOCKED' and review.get('reviewer')
        and proof['files_independently_rehashed'] == 8715 and proof['changed_missing_or_symlink'] == 0
        and proof['git_status'] == 'CLEAN_READONLY_OBSERVED', 'return_completed_prior_reference_basis')
    baseline = read('review/reference-before.json')
    require(sha(baseline) == proof['baseline_sha256'], 'return_reference_baseline_binding')
    boundary = read_json('review/login_local_deny_passage/reference_boundary_before.json')
    identities = json.loads(baseline)
    require(len(identities['files']) == 8715 and boundary['reference_files_checked'] == 8715
        and boundary['reference_bytes_unchanged'] is True and
        all(identities[name] == boundary[name] == proof[name] for name in ('commit', 'tree')), 'return_prior_reference_identity')
    return {'basis': 'REUSED_COMPLETED_INDEPENDENT_8715_FILE_OBSERVATION', 'review_sha256': REFERENCE_SHA,
        'commit': proof['commit'], 'tree': proof['tree'], 'new_P_scans': 0, 'new_git_calls': 0,
        'checkout_included': False}


def prior_archives():
    result = []
    for name, expected in PRIOR_ARCHIVES.items():
        raw = read('review/returns/' + name)
        checksum = read('review/returns/' + name + '.sha256').decode().strip()
        require(sha(raw) == expected and checksum == expected + '  ' + name, 'return_prior_archive_outer_identity')
        result.append({'name': name, 'sha256': expected, 'outer_verified': True, 'binary_included': False})
    return result


def passage_prior_archives():
    """Verify historical SOURCE/AUTH pairs; link them without their binaries."""
    result = []
    for name, expected in PASSAGE_PRIOR_ARCHIVES.items():
        raw = read('review/returns/' + name)
        checksum = read('review/returns/' + name + '.sha256').decode().strip()
        require(sha(raw) == expected and checksum == expected + '  ' + name,
            'return_auth_delta_prior_source_pair_identity')
        result.append({'name': name, 'sha256': expected, 'outer_verified': True,
            'binary_included': False, 'semantic_evidence': 'ORIGINAL_IDENTITY_NOT_RERUN'})
    return result


def sync_directory(path):
    safe_parents(path, PROJECT)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exclusive(path, raw):
    safe_parents(path, PROJECT)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync_directory(path.parent)


def verify_archive(path):
    regular(path, PROJECT)
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        names = [item.name for item in members]
        require(len(names) == len(set(names)) and all(item.isfile() for item in members)
            and all(not Path(name).is_absolute() and '..' not in Path(name).parts
                and not excluded(Path(name).parts) for name in names), 'return_complete_safe_tar_inventory')
        manifest = json.loads(archive.extractfile('manifest.json').read())
        rows = manifest['files']
        require(len(rows) == len({row['archive_path'] for row in rows})
            and set(names) == {row['archive_path'] for row in rows} | {'manifest.json'}, 'return_manifest_exact_inventory')
        for row in rows:
            raw = archive.extractfile(row['archive_path']).read()
            require(len(raw) == row['size_bytes'] and sha(raw) == row['sha256'], 'return_payload_full_readback')
    return {'status': 'PASS_COMPLETE_TAR_MANIFEST_READBACK', 'archive_sha256': sha(path.read_bytes()),
        'payload_files': len(rows), 'archive_bytes': path.stat().st_size}


def _wait_delivery(archive, expected, checksum):
    destination = Path('/Users/admin/Downloads/Radik')
    receipt_path = PROJECT / 'state/local_operator' / (archive.name + '.delivery.json')
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        safe_parents(receipt_path, PROJECT)
        if receipt_path.exists():
            regular(receipt_path, PROJECT, 16384)
            receipt = json.loads(receipt_path.read_bytes())
            copied, copied_checksum = destination / archive.name, destination / (archive.name + '.sha256')
            require(receipt.get('status') == 'DELIVERED_AND_VERIFIED' and receipt.get('archive_sha256') == expected
                and receipt.get('archive') == str(copied) and receipt.get('checksum') == str(copied_checksum), 'return_delivery_receipt_binding')
            regular(copied, destination); regular(copied_checksum, destination, 1024)
            require(sha(copied.read_bytes()) == expected and copied_checksum.read_bytes() == checksum,
                'return_actual_delivered_pair_readback')
            return {'status': 'DELIVERY_VERIFIED', 'receipt_path': str(receipt_path.relative_to(PROJECT)),
                'receipt_sha256': sha(receipt_path.read_bytes()), 'archive': str(copied), 'checksum': str(copied_checksum)}
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    return {'status': 'DELIVERY_PENDING', 'local_archive': str(archive), 'local_checksum': str(archive) + '.sha256'}


def _build(*, kind, key, payload, record, review_raw, basis, prior):
    global _RETURN_STAGE
    _RETURN_STAGE='RETURN_LOCAL_PAIR'
    returns = owned('review/returns')
    require(returns.is_dir(), 'return_destination_required')
    reservation = PROJECT / 'review/return_verifications' / ('before_owner_fix_' + kind + '_' + key + '_build.json')
    safe_parents(reservation, PROJECT)
    reservation.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    archive = returns / ('RADIK_RETURN_' + stamp + '.tar.gz')
    manifest = {'schema': 'radik.direct_plan_return_manifest.v01', 'kind': kind,
        'created_at_utc': stamp, 'packaging_review_sha256': sha(review_raw), 'reference': basis,
        'code_source_pins': record['code_source_pins'], 'payload_hashes_scope': 'PACKAGING_ONLY_NOT_RUNTIME_CODE_OR_BEHAVIOR_AUTHORITY',
        'mutable_public_owner_observations': list(MUTABLE_OWNER_OBSERVATIONS) if kind == 'live' else [],
        'prior_archives': prior, 'behavior_acceptance': 'NOT_AWARDED_BY_PACKAGING',
        'runtime_ready': 'NOT_CLAIMED', 'files': [{'archive_path': name, 'size_bytes': len(raw), 'sha256': sha(raw)}
            for name, raw in sorted(payload.items())]}
    # This permanent artifact reservation is separate from model/SAVE ledgers.
    # A partial/UNKNOWN build or pending delivery never opens a repack attempt.
    write_exclusive(reservation, canonical({'schema': 'radik.single_return_build.v01', 'kind': kind,
        'key': key, 'stage': 'RESERVED_BEFORE_ARCHIVE', 'archive_path': str(archive.relative_to(PROJECT)),
        'packaging_review_sha256': sha(review_raw), 'retry_or_reset_allowed': False}) + b'\n')
    with archive.open('xb') as stream:
        with tarfile.open(fileobj=stream, mode='w:gz') as bundle:
            for name, raw in sorted({**payload, 'manifest.json': canonical(manifest) + b'\n'}.items()):
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = len(raw), 0o600, 0
                bundle.addfile(member, io.BytesIO(raw))
        stream.flush(); os.fsync(stream.fileno())
    verified = verify_archive(archive)
    final = Path(str(archive) + '.sha256')
    pending = Path(str(final) + '.pending')
    checksum = (verified['archive_sha256'] + '  ' + archive.name + '\n').encode()
    require(not final.exists() and not final.is_symlink(), 'return_checksum_final_must_be_absent')
    write_exclusive(pending, checksum)
    require(not final.exists() and not final.is_symlink(), 'return_checksum_created_before_publish')
    os.rename(pending, final)
    sync_directory(returns)
    verification_dir = PROJECT / 'review/return_verifications' / ('before_owner_fix_' + kind + '_' + stamp)
    safe_parents(verification_dir, PROJECT)
    verification_dir.mkdir(mode=0o700, exist_ok=False)
    verified.update(kind=kind, archive_path=str(archive), checksum_path=str(final),
        checksum_publication='ATOMIC_AFTER_CLOSED_FSYNCED_ARCHIVE_AND_FULL_READBACK',
        reservation_path=str(reservation.relative_to(PROJECT)), behavior_acceptance='NOT_AWARDED_BY_PACKAGING')
    verified['report_status'] = 'LOCAL_PAIR_VERIFIED'
    write_exclusive(verification_dir / 'local_readback.json', canonical(verified) + b'\n')
    try:
        verified['delivery'] = _wait_delivery(archive, verified['archive_sha256'], checksum)
        verified['report_status'] = ('DELIVERY_VERIFIED'
            if verified['delivery'].get('status') == 'DELIVERY_VERIFIED' else 'DELIVERY_UNCONFIRMED')
    except Exception as error:
        verified['delivery'] = {'status':'DELIVERY_UNCONFIRMED_WITH_VERIFIED_LOCAL_PAIR',
            'automatic_repack':False,'raw_error_recorded':False}
        verified['report_status'] = 'DELIVERY_UNCONFIRMED'
        verified['secondary_reporting_failure'] = return_error_projection(error, stage='RETURN_DELIVERY')
    try:
        write_exclusive(verification_dir / 'delivery_readback.json', canonical(verified) + b'\n')
    except Exception as error:
        verified['delivery_record_persistence'] = 'FAILED_NO_REPACK_VERIFIED_PAIR_PRESERVED'
        verified['secondary_recording_failure'] = return_error_projection(error, stage='RETURN_CHECKPOINT')

    _RETURN_STAGE='RETURN_PREBUILD'
    return verified


def publish_source():
    """One final passage return; retain the separate automatic LIVE pair."""
    record, review_raw = transport_recovery_return_gate()
    inventory = collect_source()
    require(record.get('source_payload_inventory') == inventory, 'return_source_inventory_changed')
    paths = {relative for relative in inventory.values() if not relative.startswith('@')}
    snapshots = record.get('source_payload_hashes', {})
    require(set(snapshots) == paths and set(record['code_source_pins']) == {path for path in paths if code_source(path)},
        'return_exact_source_snapshot_and_code_closure')
    payload = {}
    for name, relative in sorted(inventory.items()):
        if relative == '@packaging_review':
            raw, expected = review_raw, sha(review_raw)
        elif relative in ('@source_report', '@continuation_report', '@owner_handoff'):
            path = {'@source_report': SOURCE_REPORT, '@continuation_report': CONTINUATION_REPORT,
                '@owner_handoff': HANDOFF}[relative]
            regular(path, path.parent)
            raw, expected = path.read_bytes(), record['external_payload_hashes'][relative]
        else:
            raw, expected = read(relative), snapshots[relative]
        require(sha(raw) == expected, 'return_source_snapshot_identity')
        if not relative.startswith('@') and Path(relative).suffix == '.json':
            _no_secrets(json.loads(raw))
        payload[name] = raw
    status = json.loads(payload['evidence/' + SOURCE_PASSAGE + '/status.json'])
    branch = record['final_return_branch']
    prior = passage_prior_archives()
    if branch == 'SOURCE_FALLBACK':
        require(type(status.get('status')) is str and status['status'].startswith('SOURCE_READY')
            and status.get('live_cold_warm_delta_SAVE') == 'NOT_RUN'
            and type(status.get('launch_context_blocker')) is str and status['launch_context_blocker']
            and record.get('actual_live_return_link') is None, 'return_source_ready_honest_pending_required')
        kind = 'source'
    else:
        linked = reviewed_live_return_link(record)
        require(status.get('status') == 'LIVE_REVIEW_COMPLETE'
                and status.get('behavior_review_sha256') == linked['behavior_review_sha256'],
                'return_engineering_live_review_status_binding')
        prior.append(linked); kind = 'engineering'
    # Both final branches share one permanent reservation, in addition to the
    # unchanged archive builder's own reservation. Neither is a model/SAVE grant.
    marker = PROJECT / 'review/return_verifications/actual_save_console_final_engineering_build.json'
    safe_parents(marker, PROJECT)
    marker.parent.mkdir(parents=True, exist_ok=True)
    write_exclusive(marker, canonical({'schema': 'radik.actual_save_console_final_return_reservation.v01',
        'branch': branch, 'packaging_review_sha256': sha(review_raw),
        'automatic_repack': False, 'live_pair_republished': False}) + b'\n')
    return _build(kind=kind, key=SOURCE_KEY, payload=payload, record=record, review_raw=review_raw,
        basis={'scope': 'ACTUAL_SAVE_CONSOLE_REPAIR_RETURN_ONLY', 'P_campaign': 'NOT_RERUN',
            'historical_semantic_and_JWT_evidence': 'LINKED_ORIGINAL_IDENTITIES_NOT_RERUN',
            'final_return_branch': branch, 'behavior_awarded_by_packaging': False}, prior=prior)


def reviewed_live_return_link(record):
    """Read back the existing automatic pair and its later independent review."""
    link = record.get('actual_live_return_link')
    require(type(link) is dict and set(link) == {'archive_path', 'archive_sha256',
        'checksum_sha256', 'delivery_receipt_sha256', 'behavior_review_sha256',
        'result_path', 'result_sha256'}, 'return_engineering_exact_live_link')
    relative = link['archive_path']
    require(type(relative) is str and re.fullmatch(
        r'review/returns/RADIK_RETURN_[0-9]{8}T[0-9]{6}\.[0-9]{6}Z\.tar\.gz', relative),
        'return_engineering_owned_live_archive')
    archive = owned(relative); verified = verify_archive(archive)
    checksum = read(relative + '.sha256')
    require(verified['archive_sha256'] == link['archive_sha256']
            and sha(checksum) == link['checksum_sha256']
            and checksum == (link['archive_sha256'] + '  ' + archive.name + '\n').encode(),
            'return_engineering_live_pair_identity')
    with tarfile.open(archive, 'r:gz') as bundle:
        manifest = json.loads(bundle.extractfile('manifest.json').read())
    require(manifest.get('kind') == 'live'
            and manifest.get('packaging_review_sha256') == sha(read(LIVE_PACK_REVIEW)),
            'return_engineering_actual_live_manifest_basis')
    receipt_path = PROJECT / 'state/local_operator' / (archive.name + '.delivery.json')
    regular(receipt_path, PROJECT, 16384); receipt_raw = receipt_path.read_bytes(); receipt = json.loads(receipt_raw)
    destination = Path('/Users/admin/Downloads/Radik')
    require(sha(receipt_raw) == link['delivery_receipt_sha256']
            and receipt.get('status') == 'DELIVERED_AND_VERIFIED'
            and receipt.get('archive_sha256') == link['archive_sha256']
            and receipt.get('archive') == str(destination / archive.name)
            and receipt.get('checksum') == str(destination / (archive.name + '.sha256')),
            'return_engineering_live_delivery_receipt_binding')
    regular(destination / archive.name, destination)
    regular(destination / (archive.name + '.sha256'), destination, 1024)
    require(sha((destination / archive.name).read_bytes()) == link['archive_sha256']
            and (destination / (archive.name + '.sha256')).read_bytes() == checksum,
            'return_engineering_live_delivered_pair_readback')
    behavior_path = SOURCE_PASSAGE + '/behavior_review.json'
    behavior_raw = read(behavior_path); behavior = json.loads(behavior_raw)
    require(sha(behavior_raw) == link['behavior_review_sha256']
            and behavior.get('reviewer') == '/root/semantic_continuation_reviewer'
            and behavior.get('scope') == 'DIRECT_PLAN_FIXED_LIVE_ONLY'
            and behavior.get('status') in ('BEHAVIOR_ACCEPTED', 'BEHAVIOR_REFUSED_NO_RETRY')
            and behavior.get('evidence_pins', {}).get(link['result_path']) == link['result_sha256']
            and link['result_path'].startswith(PASSAGE + '/live_attempts/')
            and sha(read(link['result_path'])) == link['result_sha256'],
            'return_engineering_independent_behavior_result_binding')
    _no_secrets(receipt); _no_secrets(behavior)
    return dict(link, outer_verified=True, binary_included=False,
                live_pair_republished=False, behavior_status=behavior['status'])


def _live_directory(project, value, prefix, pattern):
    path = Path(value)
    path = path if path.is_absolute() else project / path
    safe_parents(path, project)
    require(path.is_dir() and path.parent == project / prefix and re.fullmatch(pattern, path.name),
        'return_exact_owned_live_directory')
    return str(path.relative_to(project))


def operation_handoff(state,record):
    """The packaged operation selects its own historical permission document."""
    require(record.get('operation_handoff_pins')==LIVE_HANDOFF_PINS,'return_handoff_finite_selector')
    expected=state.get('semantic_continuation_proposal_sha256')
    if expected is None:
        path=str(LIVE_HANDOFF);expected_sha=LIVE_HANDOFF_PINS[path]
    else:
        require(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected),'return_semantic_continuation_selector')
        raw=read(PASSAGE+'/semantic_continuations/'+expected+'.json');activation=json.loads(raw)
        require(sha(raw)==state.get('semantic_continuation_activation_sha256')
                and activation.get('owner_operation_id')==state.get('operation_id')
                and activation.get('continuation_id')==state.get('continuation_id')
                and activation.get('run_id')==state.get('continuation_run_id'),
                'return_semantic_activation_binding')
        permission=activation.get('effect_permission',{});path=permission.get('handoff_path')
        expected_sha=permission.get('handoff_sha256')
        require(type(path) is str and LIVE_HANDOFF_PINS.get(path)==expected_sha,
                'return_handoff_operation_binding')
    return Path(path),expected_sha


def publish_owner_live(project, evidence_directory, transport_directory):
    """After runtime finally: preserve actual observations, never award behavior."""
    project = Path(project)
    require(project == PROJECT and project.resolve() == project, 'return_exact_project_required')
    record, review_raw, _, _ = gate()
    evidence = _live_directory(project, evidence_directory, PASSAGE + '/live_attempts', r'[0-9]{8}T[0-9]{6}\.[0-9]{6}Z')
    transport = _live_directory(project, transport_directory, PASSAGE + '/transport_observations', r'[0-9]{10,22}')
    result = read_json(evidence + '/result.json')
    require(result.get('schema') == 'radik.fixed_first_live_exam.v01' and result.get('status') in LIVE_STATUSES
        and type(result.get('action_policy_closed')) is bool
        and (result['status'] != LIVE_STATUSES[0] or result['action_policy_closed'] is True),
        'return_actual_live_result_and_policy_close_observation_required')
    inventory = {}
    _walk(evidence, inventory, 'actual_live')
    _walk(transport, inventory, 'actual_transport')
    for relative in (SOURCE, OWNER_REVIEW, RUNTIME_REVIEW, LIVE_PACK_REVIEW,
                     PASSAGE + '/continuation.json', PASSAGE + '/protocol_references.json',
                     *MUTABLE_OWNER_OBSERVATIONS):
        _add(relative, inventory, 'reviewed_basis')
    for relative in record['code_source_pins']:
        if relative.startswith('source/reference/'):
            source_payload_read(relative)
            inventory['source_postimages/' + relative] = relative
        else:
            _add(relative, inventory, 'source_postimages')
    payload = {}
    for name, relative in sorted(inventory.items()):
        raw = source_payload_read(relative) if relative.startswith('source/reference/') else read(relative)
        if Path(relative).suffix == '.json':
            _no_secrets(json.loads(raw))
        payload[name] = raw
    payload.update(local_recovery_payload(read_json(PASSAGE+'/owner_state.json')))
    payload.update(completed_semantic_payload(read_json(PASSAGE+'/owner_state.json')))
    checkpoint = read_json(PASSAGE + '/continuation.json')
    expected_next = 'independent_behavior_review' if result['status'] == LIVE_STATUSES[0] and result['action_policy_closed'] is True else 'review_actual_failure_no_retry'
    require(checkpoint.get('next_operation') == expected_next
        and checkpoint.get('actual_result_path') == evidence + '/result.json'
        and checkpoint.get('transport_observations') == transport, 'return_exact_owner_continuation_required')
    summary = ('Radik: actual owner-run evidence.\nStatus: ' + result['status']
        + '\nBehavior acceptance: pending independent review.\nConsole admission: pending independent behavior review.\n'
        + 'Inference and SAVE are not repeated by this return writer.\n')
    payload['README_OWNER_LIVE.txt'] = summary.encode()
    handoff,handoff_sha=operation_handoff(read_json(PASSAGE+'/owner_state.json'),record)
    regular(handoff,handoff.parent)
    payload['owner_handoff/'+handoff.name]=handoff.read_bytes()
    require(sha(payload['owner_handoff/'+handoff.name])==handoff_sha,'return_handoff_identity')
    return _build(kind='live', key=Path(evidence).name, payload=payload, record=record, review_raw=review_raw,
        basis=reference_basis(), prior=prior_archives())


FAILURE_REPORTER='review/transport/owner_failure_report.py'
FAILURE_REVIEW=SOURCE_PASSAGE+'/failure_reporter_review.json'


def failure_gate():
    """Independent minimal writer closure, usable when app admission is refused."""
    raw=read(FAILURE_REVIEW);record=json.loads(raw)
    require(record.get('status')=='ACCEPTED_FOR_STDLIB_OWNER_FAILURE_RETURN'
            and record.get('scope')=='CURATED_OWNER_FAILURE_ONLY'
            and record.get('reviewer')=='/root/semantic_continuation_reviewer','return_failure_writer_not_accepted')
    require(set(record['code_source_pins'])=={SOURCE,FAILURE_REPORTER},'return_failure_writer_closure')
    for relative,expected in record['code_source_pins'].items():
        require(sha(read(relative))==expected,'return_failure_writer_identity_changed')
    return record,raw


def _public_ledger(*,with_identity=False):
    path=PROJECT/'state/model_turns.json';regular(path,PROJECT)
    raw=path.read_bytes();value=json.loads(raw);_no_secrets(value)
    require(value.get('version') in ('radik.turn_ledger.v01','radik.turn_ledger.v02','radik.turn_ledger.v03'),
            'return_public_ledger_schema')
    expected={'version','policy_sha256','attempts','active_attempt_id'}
    if value['version'] in ('radik.turn_ledger.v02','radik.turn_ledger.v03'):
        expected|={'local_occupancy_contract','local_recovery'}
        require(value.get('local_occupancy_contract')==
                'ONE_MANAGED_LOCAL_REQUEST_WITH_ACKNOWLEDGED_REMOTE_UNKNOWN'
                and type(value.get('local_recovery')) is dict,
                'return_public_local_recovery_schema')
    if value['version']=='radik.turn_ledger.v03':
        expected.add('recovery_history')
        history=value.get('recovery_history')
        require(type(history) is list and 2<=len(history)<=16
                and all(type(item) is dict for item in history)
                and history[0]==value['local_recovery'], 'return_public_recovery_history_shape')
    require(set(value)==expected,'return_public_ledger_closed_shape')
    return (value,sha(raw)) if with_identity else value


def local_recovery_payload(state):
    """Retain one explicitly applied public receipt, not an automatic recovery."""
    relative=state.get('unknown_recovery_receipt_path')
    if relative is None:return {}
    require(type(relative) is str and re.fullmatch(PASSAGE+
        r'/local_unknown_recovery_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json',relative),
        'return_exact_public_recovery_receipt_path')
    raw=read(relative);value=json.loads(raw);_no_secrets(value)
    contract_path=SOURCE_PASSAGE+'/recovery_contract.json'
    review_path=SOURCE_PASSAGE+'/recovery_source_review.json'
    contract_raw=read(contract_path);review_raw=read(review_path)
    review=json.loads(review_raw);_no_secrets(json.loads(contract_raw));_no_secrets(review)
    require(sha(raw)==state.get('unknown_recovery_receipt_sha256')
            and value.get('schema')=='radik.owner_local_unknown_recovery.v01'
            and value.get('owner_operation_id')==state.get('operation_id')
            and value.get('contract_sha256')==sha(contract_raw)==state.get('unknown_recovery_contract_sha256')
            and value.get('review_sha256')==sha(review_raw)==state.get('unknown_recovery_review_sha256')
            and review.get('reviewer')=='/root/semantic_continuation_reviewer'
            and review.get('status')=='ACCEPTED_PREPARED_LOCAL_CLOSED_REMOTE_UNKNOWN_CONTINUATION'
            and value['budget_receipt'].get('old_outcome')=='UNKNOWN'
            and value['budget_receipt'].get('remote_completion_or_cancellation')=='NOT_OBSERVED_NOT_CLAIMED',
            'return_exact_applied_recovery_basis')
    payload={'actual_recovery/'+relative:raw,'reviewed_basis/'+contract_path:contract_raw,
             'reviewed_basis/'+review_path:review_raw}
    for ref in value['budget_receipt']['application'].get('prior_recovery_receipts',[]):
        old_path=ref['path']
        require(type(old_path) is str and re.fullmatch(PASSAGE+
            r'/local_unknown_recovery_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json',old_path),
            'return_prior_public_recovery_receipt_path')
        old_raw=read(old_path);old=json.loads(old_raw);_no_secrets(old)
        require(sha(old_raw)==ref['sha256'] and old.get('schema')=='radik.owner_local_unknown_recovery.v01'
                and sha(canonical(old['budget_receipt']['application']))==ref['application_sha256']
                and old.get('contract_sha256')==ref['contract_sha256'],
                'return_prior_public_recovery_receipt_binding')
        payload['actual_recovery/'+old_path]=old_raw
    return payload


# Legacy activations predate explicit path references. Only this already reviewed
# public ancestry is addressable through that historical schema.
LEGACY_SEMANTIC_REFERENCES = {
    '48eae7f117986ca52a93a722dace1e0452d6880ca7c6eed02e8ae8512a24547f': {
        'proposal_ref': {'path':'review/semantic_continuation_passage/continuation_proposal.json',
            'sha256':'48eae7f117986ca52a93a722dace1e0452d6880ca7c6eed02e8ae8512a24547f'},
        'proposal_review_ref': {'path':'review/semantic_continuation_passage/continuation_source_review.json',
            'sha256':'adbc6e63866c749bca90455234bb76976f48d584c8e96a0833c60754083f4f59'},
        'actual_review_ref': {'path':'review/semantic_continuation_passage/actual_failure_review.json',
            'sha256':'bc233a127ca8ad39f6c5ffdcad0b1c6fcb14806fd8c3bddf2dd11e10c0b3a248'},
    },
}


def _semantic_reference(reference):
    require(type(reference) is dict and set(reference)=={'path','sha256'}
            and type(reference['path']) is str and reference['path'].startswith('review/')
            and reference['path'].endswith('.json') and type(reference['sha256']) is str
            and re.fullmatch('[0-9a-f]{64}',reference['sha256']), 'return_semantic_reference_shape')
    raw=read(reference['path'])
    require(sha(raw)==reference['sha256'],'return_semantic_historical_basis_changed')
    return raw,json.loads(raw)


def completed_semantic_payload(state):
    """Select immutable ancestry by the packaged operation, never current passage."""
    expected=state.get('semantic_continuation_proposal_sha256')
    if expected is None:return {}
    require(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected)
            and state.get('operation_kind')=='EXPLICIT_COMPLETED_SEMANTIC_CONTINUATION',
            'return_semantic_continuation_selector')
    activation_path=PASSAGE+'/semantic_continuations/'+expected+'.json'
    activation_raw=read(activation_path);activation=json.loads(activation_raw)
    require(sha(activation_raw)==state.get('semantic_continuation_activation_sha256')
            and activation['proposal_sha256']==expected
            and activation['continuation_id']==state.get('continuation_id')
            and activation['run_id']==state.get('continuation_run_id')
            and activation['owner_operation_id']==state['operation_id'],
            'return_semantic_activation_binding')
    references=({key:activation.get(key) for key in ('proposal_ref','proposal_review_ref','actual_review_ref')}
        if activation.get('schema')=='radik.completed_semantic_continuation_activation.v02'
        else LEGACY_SEMANTIC_REFERENCES.get(expected))
    require(type(references) is dict,'return_semantic_operation_references_required')
    raw,proposal=_semantic_reference(references['proposal_ref'])
    review_raw,review=_semantic_reference(references['proposal_review_ref'])
    actual_raw,actual_review=_semantic_reference(references['actual_review_ref'])
    require(sha(raw)==expected and proposal['owner_operation_id']==state['operation_id']
            and review.get('proposal_sha256')==expected
            and sha(review_raw)==activation['proposal_review_sha256']
            and review.get('actual_failure_review_sha256')==sha(actual_raw)
            and review.get('reviewer')==actual_review.get('reviewer')=='/root/semantic_continuation_reviewer',
            'return_semantic_proposal_binding')
    payload={'actual_continuation/'+activation_path:activation_raw}
    for key,data in (('proposal_ref',raw),('proposal_review_ref',review_raw),('actual_review_ref',actual_raw)):
        payload['reviewed_continuation/'+references[key]['path']]=data
    entered_path=PASSAGE+'/semantic_continuations/'+expected+'.entered.json'
    if (PROJECT/entered_path).exists():
        entered_raw=read(entered_path);entered=json.loads(entered_raw)
        require(entered['semantic_continuation_activation_sha256']==sha(activation_raw)
                and entered['continuation_id']==activation['continuation_id'],
                'return_semantic_entered_binding')
        payload['actual_continuation/'+entered_path]=entered_raw
    historical=[*proposal['receipt_refs'],proposal['old_closed_policy'],
        *proposal['actual']['evidence_refs'].values()]
    if proposal.get('schema')=='radik.completed_semantic_continuation_proposal.v02':
        predecessor=proposal['predecessor']
        historical.extend([*predecessor['ancestry'].values(),
            predecessor['ledger_prefix_ref'],predecessor['owner_checkpoint_ref']])
    for reference in historical:
        old_raw,_=_semantic_reference(reference)
        payload['historical_occupancy_or_permission/'+reference['path']]=old_raw
    for item in payload.values():_no_secrets(json.loads(item))
    return payload


def failure_payload(state, *, source_admitted, transport_directory=None):
    """Closed public selectors; no live result or private traversal is allowed."""
    require(type(state) is dict and state.get('stage') in ('STOPPED_BEFORE_LIVE','BOOTSTRAP_SOURCE_REFUSED')
            and state.get('actual_result_path') is None,'return_actual_early_failure_required')
    require(re.fullmatch(r'[0-9a-f-]{32,36}',state.get('operation_id','')) is not None,'return_owner_operation_id')
    _no_secrets(state)
    ledger,ledger_sha=_public_ledger(with_identity=True)
    payload={'actual_owner/owner_state.json':canonical(state)+b'\n',
             'actual_owner/public_ledger_snapshot.json':canonical(ledger)+b'\n'}
    payload.update(local_recovery_payload(state))
    payload.update(completed_semantic_payload(state))
    observations={'auth':'NOT_OBSERVED','dependencies':'NOT_OBSERVED','catalog':'NOT_STARTED',
                  'live':'NOT_STARTED','Work_E_SAVE':'NOT_STARTED','runtime':'NOT_ADMITTED','console':'NOT_ADMITTED',
                  'effect_policy_closure':'NOT_OBSERVED_NOT_CLAIMED'}
    if source_admitted:
        require(state.get('ledger_after_sha256',state.get('ledger_sha256'))==ledger_sha
                and ledger.get('active_attempt_id') is None,
                'return_preflight_dispatch_ledger_changed_or_unknown')
        journal=read_json(PASSAGE+'/owner_phase_journal.json')
        require(journal.get('operation_id')==state['operation_id'] and journal.get('phase') in ('SETUP','SETUP_READY','AUTH','CATALOG'),
                'return_owner_phase_binding')
        payload['actual_owner/owner_phase_journal.json']=canonical(journal)+b'\n'
        observations['auth']='NOT_STARTED' if journal.get('auth_started') is False else 'NOT_OBSERVED'
        for relative in (PASSAGE+'/owner_dependency_observation.json',PASSAGE+'/owner_auth_observations.json'):
            if owned(relative).exists():
                value=read_json(relative);_no_secrets(value)
                if value.get('owner_operation_id')!=state['operation_id']:continue
                payload['actual_owner/'+Path(relative).name]=canonical(value)+b'\n'
        if owned(SETUP_PASSAGE+'/setup_journal.json').exists():
            value=read_json(SETUP_PASSAGE+'/setup_journal.json');_no_secrets(value)
            require(value.get('phase_binding')==state.get('setup_binding'),'return_setup_phase_binding')
            payload['actual_owner/setup_journal.json']=canonical(value)+b'\n'
        if transport_directory is not None and (PROJECT/transport_directory).exists():
            relative=_live_directory(PROJECT,transport_directory,PASSAGE+'/transport_observations',r'[0-9]{10,22}')
            # Finite known catalog basenames only; never descend or read an
            # unselected/private/identity/debug file, even if planted nearby.
            included_catalogs=0
            for name in sorted(os.listdir(owned(relative))):
                if re.fullmatch(r'catalog_(?:failure_|http_)?[0-9a-f]{32}\.json',name) is None:continue
                value=read_json(relative+'/'+name);_no_secrets(value)
                require(value.get('schema') in ('radik.direct_plan_catalog_receipt.v01','radik.direct_plan_catalog_failure.v01',
                                               'radik.direct_plan_http_header_observation.v01')
                        and value.get('inference_calls')==0,'return_catalog_observation_schema')
                payload['actual_transport/'+relative+'/'+name]=canonical(value)+b'\n'
                included_catalogs+=1
            observations['catalog']='ACTUAL_CREATED_OBSERVATIONS_INCLUDED' if included_catalogs else 'NOT_OBSERVED_NO_CREATED_CATALOG_OBSERVATION'
        elif transport_directory is not None:
            observations['catalog']='NOT_OBSERVED_NO_CREATED_CATALOG_OBSERVATION'
    selected_reviews=(OWNER_REVIEW,FAILURE_REVIEW) if state.get('operation_kind')=='AUTH_ONLY_RECOVERY' else (
        OWNER_REVIEW,RUNTIME_REVIEW,MECHANICAL_REVIEW,FAILURE_REVIEW)
    for relative in selected_reviews:
        if owned(relative).exists():payload['reviewed_basis/'+relative]=read(relative)
    observations['observation_basis']='Source-bound operation phase and actual created public files; absent files do not establish current credential state.'
    payload['actual_owner/observation_scope.json']=canonical(observations)+b'\n'
    payload['CONTINUE_AFTER_OWNER_RUN_RU.txt']=continuation_prompt(failure_gate()[0])
    payload['README_OWNER_FAILURE_RU.txt']=('Radik остановлен до live. Исходная причина: '+state['error']['code']+
        '. Runtime и console NOT_ADMITTED. Login/model/Work/SAVE не повторяются упаковщиком. '
        'Отправьте в Codex текст CONTINUE_AFTER_OWNER_RUN_RU.txt; private/project JSON искать не требуется.\n').encode()
    return payload


def continuation_prompt(record):
    expected=record['continuation_prompt_sha256']
    if CONTINUATION_REPORT.exists():
        regular(CONTINUATION_REPORT,CONTINUATION_REPORT.parent)
        raw=CONTINUATION_REPORT.read_bytes()
    else:
        marker=PROJECT/('review/return_verifications/before_owner_fix_source_'+SOURCE_KEY+'_build.json')
        regular(marker,PROJECT);value=json.loads(marker.read_bytes())
        relative=value['archive_path']
        require(relative.startswith('review/returns/RADIK_RETURN_') and relative.endswith('.tar.gz'),'return_source_prompt_archive_path')
        archive=owned(relative);regular(archive,PROJECT)
        with tarfile.open(archive,'r:gz') as bundle:
            member=bundle.getmember('CONTINUE_AFTER_OWNER_RUN_RU.txt')
            require(member.isfile() and 0<member.size<=65536,'return_source_prompt_member')
            raw=bundle.extractfile(member).read()
    require(sha(raw)==expected,'return_source_prompt_identity')
    return raw


def publish_owner_preflight(state, *, source_admitted=True, transport_directory=None):
    record,raw=failure_gate()
    if source_admitted and state.get('operation_kind')=='AUTH_ONLY_RECOVERY':
        accepted_auth=_auth_owner_review();auth_identity=sha(canonical(accepted_auth['pins']))
        require(transport_directory is None,'return_auth_only_no_transport_directory')
        require(record.get('auth_only_failure_selector')=={
            'operation_kind':'AUTH_ONLY_RECOVERY','phases':['SETUP','SETUP_READY','AUTH'],
            'runtime_gate':'NOT_REQUIRED_FOR_AUTH','automatic_repack':False},
            'return_auth_only_failure_selector_not_accepted')
        journal=read_json(PASSAGE+'/owner_phase_journal.json')
        require(journal.get('phase') in ('SETUP','SETUP_READY','AUTH'),
                'return_auth_only_failure_phase')
        require(read_json(PASSAGE+'/owner_state.json')==state
                and state.get('source_identity_sha256')==auth_identity
                and state.get('quota_state')==_auth_quota_state()
                and all(journal.get(key)==state.get(key) for key in (
                    'operation_id','operation_kind','setup_binding','source_identity_sha256','ledger_sha256',
                    'quota_state','auth_ever_started','live_ever_started'))
                and type(state.get('auth_ever_started')) is bool
                and type(state.get('live_ever_started')) is bool
                and journal.get('auth_started')==state['auth_ever_started']
                and journal.get('live_started')==state['live_ever_started']
                and (state.get('auth_source_identity_sha256') is None or
                     state['auth_source_identity_sha256']==auth_identity==journal.get('auth_source_identity_sha256')),
                'return_auth_only_failure_current_source_phase_binding')
    elif source_admitted:
        admitted,_,_,_=gate()
        require(admitted.get('owner_failure_selector')=={
            'statuses':['STOPPED_BEFORE_LIVE','BOOTSTRAP_SOURCE_REFUSED'],
            'live_evidence':'FORBIDDEN','private_reads':'FORBIDDEN','ledger':'PUBLIC_SNAPSHOT_NOT_CODE_PIN',
            'one_return_per_operation':True},'return_early_failure_selector_not_accepted')
    payload=failure_payload(state,source_admitted=source_admitted,transport_directory=transport_directory)
    for relative in record['code_source_pins']:payload['writer_basis/'+relative]=read(relative)
    key=state.get('continuation_id',state['operation_id'])
    require(type(key) is str and re.fullmatch('[0-9a-f-]{32,36}',key),'return_failure_continuation_identity')
    return _build(kind='preflight',key=key,payload=payload,record=record,review_raw=raw,
                  basis={'P':'NOT_READ_BY_FAILURE_REPORTER'},prior=[])


AUTH_REPORT_REVIEW=SOURCE_PASSAGE+'/auth_reporter_review.json'


def _auth_owner_review():
    record=_review(OWNER_REVIEW,'SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT','DIRECT_CHATGPT_PLAN_SOURCE_ONLY')
    require(set(record.get('pins',{}))==AUTH_SOURCE_FILES,'return_auth_only_source_closure')
    for relative,expected in record['pins'].items():
        require(sha(read(relative))==expected,'return_auth_only_source_identity_changed')
    return record


def auth_return_gate():
    raw=read(AUTH_REPORT_REVIEW);record=json.loads(raw)
    require(record.get('status')=='ACCEPTED_FOR_STDLIB_AUTH_ONLY_RETURN'
            and record.get('scope')=='CURATED_AUTH_ONLY_OWNER_RETURN'
            and record.get('reviewer')=='/root/semantic_continuation_reviewer','return_auth_writer_not_accepted')
    require(set(record.get('code_source_pins',{}))=={SOURCE,FAILURE_REPORTER},'return_auth_writer_closure')
    for relative,expected in record['code_source_pins'].items():
        require(sha(read(relative))==expected,'return_auth_writer_identity_changed')
    require(record.get('auth_success_selector')=={
        'operation_kind':'AUTH_ONLY_RECOVERY','stage':'AUTH_RECOVERED_NO_LIVE_REPLAY',
        'phase':'AUTH_RECOVERED','ledger':'UNCHANGED_PUBLIC_BASELINE','quota':'UNCHANGED_CURRENT_STATE',
        'live_catalog_model_native':'NOT_STARTED_BY_RECOVERY','one_return_per_operation':True,
        'delivery_failure_changes_auth':False,'automatic_repack':False},'return_auth_success_selector_not_accepted')
    return record,raw


def _auth_quota_state():
    path=PROJECT/'state/live_save_quota';safe_parents(path,PROJECT)
    if not path.exists():return {'state':'NOT_STARTED'}
    require(path.is_dir(),'return_auth_quota_directory')
    return {'state':'KNOWN_USED_NOT_RESET' if any(path.iterdir()) else 'KNOWN_EMPTY'}


def auth_success_payload(state):
    """Read only the fixed public auth terminal records, never private auth/P."""
    accepted=_auth_owner_review();identity=sha(canonical(accepted['pins']))
    require(type(state) is dict and state.get('stage')=='AUTH_RECOVERED_NO_LIVE_REPLAY'
            and state.get('operation_kind')=='AUTH_ONLY_RECOVERY'
            and state.get('auth_status')=='OWN_PLAN_GRANT_VERIFIED'
            and state.get('actual_result_path') is None
            and state.get('source_identity_sha256')==identity
            and state.get('auth_source_identity_sha256')==identity,
            'return_auth_success_current_source_terminal_required')
    require(re.fullmatch(r'[0-9a-f-]{32,36}',state.get('operation_id','')) is not None,'return_auth_operation_id')
    _no_secrets(state)
    require(read_json(PASSAGE+'/owner_state.json')==state,'return_auth_actual_terminal_checkpoint_changed')
    ledger,ledger_sha=_public_ledger(with_identity=True);quota=_auth_quota_state()
    require(state.get('ledger_sha256')==ledger_sha and ledger.get('active_attempt_id') is None
            and state.get('quota_state')==quota,'return_auth_ledger_or_quota_changed')
    phase=read_json(PASSAGE+'/owner_phase_journal.json')
    require(phase.get('phase')=='AUTH_RECOVERED'
            and phase.get('operation_kind')=='AUTH_ONLY_RECOVERY'
            and all(phase.get(key)==state.get(key) for key in ('operation_id','operation_kind','setup_binding',
                'source_identity_sha256','auth_source_identity_sha256','ledger_sha256','quota_state',
                'auth_ever_started','live_ever_started'))
            and state.get('auth_ever_started') is True and type(state.get('live_ever_started')) is bool
            and phase.get('auth_started') is True and phase.get('live_started')==state['live_ever_started'],
            'return_auth_actual_phase_binding')
    connection=state.get('connection',{})
    require(type(connection) is dict and set(connection)=={'schema','status','connection_id','scopes','expires_at',
        'issuer_verified','issued_client_identity_binding_verified','workspace_binding_basis'}
        and connection['schema']=='radik.plan_connection_receipt.v01'
        and connection['status']=='OWN_PLAN_GRANT_VERIFIED'
        and connection['issuer_verified'] is True and connection['issued_client_identity_binding_verified'] is True
        and connection['workspace_binding_basis']=='ISSUED_CLIENT_REGISTRATION_NOT_EMAIL_OR_SUBJECT'
        and type(connection['connection_id']) is str
        and re.fullmatch(r'radik-plan:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',connection['connection_id']) is not None
        and type(connection['expires_at']) is int
        and type(connection['scopes']) is list and len(connection['scopes'])<=32
        and all(type(value) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,96}',value) for value in connection['scopes'])
        and {'openid','profile','email','offline_access','resource.invoke','chatgpt.tokens.use.direct'}.issubset(connection['scopes']),
        'return_auth_verified_public_receipt_required')
    accounting=read_json(PASSAGE+'/owner_auth_observations.json');_no_secrets(accounting)
    require(set(accounting)=={'schema','basis','requests','operation_totals','dropped_rows','owner_operation_id'}
            and accounting['schema']=='radik.plan_auth_http_observations.v01'
            and accounting['basis']=='OWN_FIXED_AUTH_HTTP_OPERATIONS_NOT_INFERENCE'
            and accounting['owner_operation_id']==state['operation_id']
            and type(accounting['requests']) is list and len(accounting['requests'])<=128
            and type(accounting['operation_totals']) is dict
            and set(accounting['operation_totals'])=={'discovery','jwks','exchange','refresh'}
            and all(type(value) is int and value>=0 for value in accounting['operation_totals'].values())
            and type(accounting['dropped_rows']) is int and accounting['dropped_rows']>=0,
            'return_auth_public_http_accounting_required')
    row_fields={'operation','attempted_http_dispatch','returned_status','curated_error','duration_seconds',
                'cleanup','caller_total_deadline','worker_finished'}
    for row in accounting['requests']:
        require(type(row) is dict and set(row)==row_fields and row['operation'] in accounting['operation_totals']
                and type(row['attempted_http_dispatch']) is bool and type(row['caller_total_deadline']) is bool
                and type(row['worker_finished']) is bool and row['cleanup'] in ('COMPLETE','PENDING','UNKNOWN')
                and (row['returned_status'] is None or type(row['returned_status']) is int and 100<=row['returned_status']<=599)
                and (row['curated_error'] is None or type(row['curated_error']) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{0,100}',row['curated_error']))
                and (row['duration_seconds'] is None or type(row['duration_seconds']) in (int,float) and 0<=row['duration_seconds']<86400),
                'return_auth_accounting_closed_row')
    continuation=read_json(PASSAGE+'/continuation.json');_no_secrets(continuation)
    require(continuation.get('schema')=='radik.auth_only_continuation.v01'
            and continuation.get('next_operation')=='independent_actual_auth_result_review_no_live'
            and continuation.get('operation_id')==state['operation_id']
            and continuation.get('auth_source_identity_sha256')==identity
            and continuation.get('verified_connection')==connection
            and continuation.get('auth_http_accounting')=={key:value for key,value in accounting.items() if key!='owner_operation_id'}
            and continuation.get('ledger_sha256')==ledger_sha and continuation.get('quota_state')==quota
            and continuation.get('live_admission')=='NOT_GRANTED','return_auth_actual_continuation_required')
    payload={'actual_auth/owner_state.json':canonical(state)+b'\n',
        'actual_auth/owner_phase_journal.json':canonical(phase)+b'\n',
        'actual_auth/owner_auth_observations.json':canonical(accounting)+b'\n',
        'actual_auth/continuation.json':canonical(continuation)+b'\n',
        'actual_auth/public_ledger_snapshot.json':canonical(ledger)+b'\n',
        'actual_auth/quota_state.json':canonical(quota)+b'\n',
        'actual_auth/scope.json':canonical({'auth':'OWN_PLAN_GRANT_VERIFIED','catalog_model_Work_E_SAVE_C':'NOT_STARTED_BY_AUTH_RECOVERY',
            'runtime':'NOT_ADMITTED','console':'NOT_ADMITTED','automatic_retry':False,
            'source_scope':'AUTH_DEPENDENCIES_REPORTING_ONLY','delivery':'RECORDED_SEPARATELY_AFTER_BUILD'})+b'\n',
        'reviewed_basis/'+OWNER_REVIEW:read(OWNER_REVIEW)}
    payload['CONTINUE_AFTER_OWNER_RUN_RU.txt']=('Проверьте actual AUTH-only результат операции '+state['operation_id']+
        '. Grant проверен этим owner recovery; catalog/model/live/Work/E/SAVE/C не запускались. '
        'Сохраните текущие ledger/quota, пару и состояние доставки. Вход и упаковку не повторять автоматически. '
        'Live требует отдельной проверки corrected canonical BSEP-before-Architect source и допуска; console не открывать.\n').encode()
    payload['README_OWNER_AUTH_RU.txt']=('AUTH Radik успешно проверен. Это отдельный AUTH-only возврат, не отказ и не live result. '
        'Следующий шаг — проверка actual auth result в Codex. Catalog/model/Work/E/SAVE/C этой recovery не запускались. '
        'Доставка учитывается отдельно; её отказ не отменяет grant и не разрешает повтор входа.\n').encode()
    return payload


def publish_owner_auth_success(state):
    record,raw=auth_return_gate();payload=auth_success_payload(state)
    for relative in record['code_source_pins']:payload['writer_basis/'+relative]=read(relative)
    payload['reviewed_basis/'+AUTH_REPORT_REVIEW]=raw
    return _build(kind='auth',key=state['operation_id'],payload=payload,record=record,review_raw=raw,
                  basis={'P':'NOT_READ_BY_AUTH_RETURN','live_admission':'NOT_GRANTED'},prior=[])


STAGE04_PASSAGE = 'review/normal_session_g2e_passage'
STAGE04_EXTERNAL = Path('/private/tmp/radik_owner_delivery_normal_session_g2e')
STAGE04_DIAGNOSTICS = 'app/stage04_diagnostics.py'
STAGE04_PRIOR = ('RADIK_RETURN_20261016T140101.598238Z.tar.gz',
    '3b6cd595227ca620dbfa3741418cc9365e223c16de78b461c9387f7a6b8f97c0')


def _stage04_writer_review(name, status, scope):
    relative=STAGE04_PASSAGE+'/'+name;raw=read(relative);record=json.loads(raw)
    require(record.get('reviewer')=='/root/semantic_continuation_reviewer'
        and record.get('status')==status and record.get('scope')==scope
        and set(record.get('code_source_pins',{}))=={SOURCE,FAILURE_REPORTER,STAGE04_DIAGNOSTICS},
        'return_stage04_writer_review_required')
    require(all(sha(read(path))==pin for path,pin in record['code_source_pins'].items()),
        'return_stage04_writer_changed')
    return record,raw


def _stage04_failure_line(state):
    """Render only the shared finite projection after the writer seal checked it."""
    diagnostics = runpy.run_path(str(PROJECT/STAGE04_DIAGNOSTICS),
        run_name='reviewed_stage04_return_diagnostics')
    return diagnostics['projection_line'](state.get('error', {}))


def _stage04_current_basis(payload, *, require_execution=False):
    """Failure evidence can precede behavior admission; success cannot."""
    for name in ('current_source_admission.json', 'owner_source_review.json',
            'runtime_source_review.json', 'console_source_review.json'):
        relative = STAGE04_PASSAGE+'/'+name
        payload['reviewed_basis/'+relative] = read(relative)
    runtime=json.loads(payload['reviewed_basis/'+STAGE04_PASSAGE+'/runtime_source_review.json'])
    owner=json.loads(payload['reviewed_basis/'+STAGE04_PASSAGE+'/owner_source_review.json'])
    admission=json.loads(payload['reviewed_basis/'+STAGE04_PASSAGE+'/current_source_admission.json'])
    console=json.loads(payload['reviewed_basis/'+STAGE04_PASSAGE+'/console_source_review.json'])
    require(all(item.get('reviewer')=='/root/semantic_continuation_reviewer'
        for item in (runtime,owner,admission,console))
        and runtime.get('status')=='SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION'
        and owner.get('status')=='SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT'
        and runtime.get('scope')==owner.get('scope')=='DIRECT_CHATGPT_PLAN_SOURCE_ONLY'
        and admission.get('status')=='SOURCE_ACCEPTED_FOR_NORMAL_SESSION_CARRYFORWARD'
        and admission.get('entry_authorizes_model_or_effect') is False
        and admission.get('source_identity_sha256')==sha(canonical(runtime['pins']))
        and admission.get('auth_source_identity_sha256')==sha(canonical(owner['pins']))
        and admission.get('runtime_review_sha256')==sha(payload['reviewed_basis/'+STAGE04_PASSAGE+'/runtime_source_review.json'])
        and admission.get('owner_review_sha256')==sha(payload['reviewed_basis/'+STAGE04_PASSAGE+'/owner_source_review.json'])
        and console.get('code_pins')==runtime['pins']
        and console.get('current_source_admission_sha256')==sha(payload['reviewed_basis/'+STAGE04_PASSAGE+'/current_source_admission.json'])
        and console.get('entry_authorizes_model_or_effect') is False
        and console.get('status')=='SOURCE_ACCEPTED_FOR_STAGE04_CONSOLE_ENTRY_WITHOUT_INFERENCE',
        'return_stage04_source_basis_invalid')
    missing=[]
    for name in ('mechanical_result_review.json','real_execution_review.json'):
        relative=STAGE04_PASSAGE+'/'+name
        if not (PROJECT/relative).exists():
            require(not (PROJECT/relative).is_symlink() and not require_execution,
                'return_stage04_execution_basis_required')
            missing.append(relative)
            continue
        raw=read(relative);record=json.loads(raw)
        expected='PASS_CURRENT_AGGREGATE_MECHANICAL_BOUNDARIES' if name.startswith('mechanical') else 'ACCEPTED_FOR_STAGE04_OWNED_CONSOLE_EXECUTION'
        identity=record.get('current_source_identity_sha256') if name.startswith('mechanical') else record.get('source_identity_sha256')
        require(record.get('reviewer')=='/root/semantic_continuation_reviewer'
            and record.get('status')==expected and record.get('code_pins')==runtime['pins']
            and identity==sha(canonical(runtime['pins'])), 'return_stage04_execution_basis_invalid')
        payload['reviewed_basis/'+relative]=raw
    payload['report/execution_basis.json']=canonical(dict(
        schema='radik.return.execution_basis_observation.v01',
        state='MISSING_NOT_ESTABLISHED' if missing else 'PRESENT_REVIEWED',
        missing=missing,source_admission_authorizes_execution=False))


def _stage04_public_file(relative, cap=64*1024*1024):
    """Only callers' fixed public selectors may reach state or witness bytes."""
    require(type(relative) is str and not Path(relative).is_absolute()
        and not set(Path(relative).parts).intersection(('.', '..'))
        and not excluded(Path(relative).parts), 'return_stage04_public_selector')
    path=PROJECT/relative;regular(path,PROJECT,cap);raw=path.read_bytes()
    require(len(raw)<=cap,'return_stage04_public_bound')
    return raw


def _stage04_legacy_continuation_payload(state, connected=None):
    """Select exact acknowledgement ancestry, without conferring authority."""
    ledger=json.loads(_stage04_public_file('state/console_model_turns.json'))
    if ledger.get('version') not in ('radik.console_turn_ledger.v03','radik.console_turn_ledger.v04',
            'radik.console_turn_ledger.v05'):return {}
    relative='state/console_continuation_073219.json'
    raw=_stage04_public_file(relative,65536);receipt=json.loads(raw)
    actual_raw=read('review/stream_console_continuation_passage/actual_evidence/actual_owner/console_model_turns.json')
    require(sha(actual_raw)=='f0c74ab2e07b93c04fa7d7c4e723e362bbccf223a81282c1f6d1b7cfb4228fbf',
        'return_stage04_continuation_receipt_binding')
    actual=json.loads(actual_raw)
    fields={'schema','disposition','attempt_id','response_id','old_ledger_raw_sha256',
        'old_ledger_canonical_sha256','historical_prefix_sha256','context_sha256','body_sha256',
        'local_http_closed','local_watchdog_finished','remote_outcome','usage','automatic_retry',
        'server_cancellation_observed','source_identity_sha256','auth_source_identity_sha256',
        'review_ref','owner_operation_id','run_id','recorded_at','receipt_sha256'}
    require(type(receipt)is dict and set(receipt)==fields
        and receipt.get('disposition')=='LOCAL_OCCUPANCY_RELEASED_REMOTE_OUTCOME_UNKNOWN'
        and receipt.get('response_id')=='resp_0c638e609fc87bee016ad1d2f9e49487d29d567b460c366f39'
        and receipt.get('old_ledger_raw_sha256')==sha(actual_raw)
        and receipt.get('old_ledger_canonical_sha256')=='17c3d973808448b9a85b6c4894962574fa1fc9fd10dc6c9201fdc1192660dc55'
        and receipt.get('body_sha256')=='434b16d7161bb64a7c2ae0607e74c164631fc66900f3981f6827dacf756bb951'
        and receipt.get('context_sha256')=='78e9001b014a5e0096c0ea9b4b953e0d903745a2102adffeaf6eadb2b1db7755'
        and receipt.get('local_http_closed') is True and receipt.get('local_watchdog_finished') is True
        and receipt.get('automatic_retry') is False and receipt.get('server_cancellation_observed') is False
        and type(receipt.get('recorded_at'))is int and receipt['recorded_at']>=0
        and type(receipt.get('owner_operation_id'))is str
        and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',receipt['owner_operation_id'])
        and type(receipt.get('run_id'))is str and re.fullmatch(r'[0-9a-f]{12}',receipt['run_id'])
        and all(receipt['owner_operation_id']!=row['owner_operation_id']
            and receipt['run_id']!=row['run_id'] for row in actual['attempts'])
        and ledger.get('console_continuation_ref')==dict(path=relative,sha256=sha(raw))
        and raw==canonical(receipt)
        and receipt.get('receipt_sha256')==sha(canonical({k:v for k,v in receipt.items() if k!='receipt_sha256'}))
        and receipt.get('schema')=='radik.console_local_continuation_receipt.v01'
        and receipt.get('remote_outcome')=='UNKNOWN' and receipt.get('usage')=='UNKNOWN'
        and receipt.get('attempt_id')=='radik-call:1548d2e6967447c1a718a99676bf8818'
        and receipt.get('historical_prefix_sha256')==sha(canonical(actual['attempts']))
        and ledger['attempts'][:4]==actual['attempts']
        and len(ledger['attempts'])>=4, 'return_stage04_continuation_receipt_binding')
    require(sha(raw)=='f17bb3460fe86f9b1e3e4928ed4f97093b971cc3d51a386c81774d679e22d9ab',
        'return_stage04_continuation_receipt_binding')
    review_path='review/stream_console_continuation_passage/continuation_review.json'
    review_raw=read(review_path);review=json.loads(review_raw)
    proposal_path='review/stream_console_continuation_passage/continuation_proposal.json';proposal_raw=read(proposal_path)
    require(receipt.get('review_ref')==dict(path=review_path,sha256=sha(review_raw))
        and review.get('reviewer')=='/root/semantic_continuation_reviewer'
        and review.get('status')=='SOURCE_ACCEPTED_FOR_EXPLICIT_CONSOLE_LOCAL_CONTINUATION'
        and review.get('scope')=='LOCAL_OCCUPANCY_ONLY_REMOTE_UNKNOWN_PRESERVED'
        and review.get('proposal_sha256')==sha(proposal_raw)
        and review.get('source_identity_sha256')==receipt.get('source_identity_sha256')
        and review.get('auth_source_identity_sha256')==receipt.get('auth_source_identity_sha256'),
        'return_stage04_continuation_review_binding')
    if len(ledger['attempts'])>4:
        first=ledger['attempts'][4]
        require(first.get('owner_operation_id')==receipt.get('owner_operation_id')
            and first.get('run_id')==receipt.get('run_id'), 'return_stage04_continuation_operation_binding')
    for document in ((state,connected) if ledger.get('version')=='radik.console_turn_ledger.v03' else ()):
        context=document.get('console_continuation') if type(document)is dict else None
        if type(context)is dict:
            require(context.get('receipt_ref')==ledger['console_continuation_ref']
                and document.get('owner_operation_id',document.get('operation_id'))==receipt['owner_operation_id']
                and document.get('run_id',document.get('console_run_id'))==receipt['run_id'],
                'return_stage04_continuation_operation_binding')
    return {'actual_owner/console_continuation_073219.json':raw,
        'reviewed_basis/'+review_path:review_raw,'reviewed_basis/'+proposal_path:proposal_raw}


def _stage04_continuation_payload(state, connected=None):
    """Finite, stdlib-only ancestry selection; receipts confer no authority here."""
    ledger=json.loads(_stage04_public_file('state/console_model_turns.json'))
    payload=_stage04_legacy_continuation_payload(state,connected)
    if ledger.get('version') not in ('radik.console_turn_ledger.v04','radik.console_turn_ledger.v05'):return payload
    refs=ledger.get('console_continuation_chain')
    require(type(refs)is list and 2<=len(refs)<=16 and refs[0]==ledger.get('console_continuation_ref')
        and len({item.get('path') for item in refs if type(item)is dict})==len(refs),
        'return_stage04_continuation_chain_binding')
    def document(reference, *, receipt=False):
        require(type(reference)is dict and set(reference)=={'path','sha256'}
            and type(reference['path'])is str and type(reference['sha256'])is str
            and re.fullmatch('[0-9a-f]{64}',reference['sha256'])
            and reference['path'].startswith('state/console_continuations/' if receipt else 'review/')
            and reference['path'].endswith('.json'), 'return_stage04_continuation_chain_binding')
        raw=_stage04_public_file(reference['path'],4*1024*1024)
        require(sha(raw)==reference['sha256'],'return_stage04_continuation_chain_binding')
        value=json.loads(raw)
        require(type(value)is dict,'return_stage04_continuation_chain_binding')
        return raw,value
    def basis(value, expected_B, expected_A):
        require(type(value)is dict and set(value)=={'runtime_review_ref','owner_review_ref','source_files'},
            'return_stage04_continuation_chain_source')
        runtime_raw,runtime=document(value['runtime_review_ref']);owner_raw,owner=document(value['owner_review_ref'])
        require(runtime.get('reviewer')==owner.get('reviewer')=='/root/semantic_continuation_reviewer'
            and runtime.get('status')=='SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION'
            and owner.get('status')=='SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT'
            and runtime.get('scope')==owner.get('scope')=='DIRECT_CHATGPT_PLAN_SOURCE_ONLY'
            and sha(canonical(runtime['pins']))==expected_B and sha(canonical(owner['pins']))==expected_A
            and type(value['source_files'])is dict and set(value['source_files'])==set(runtime['pins'])
            and set(owner['pins'])<=set(runtime['pins'])
            and all(runtime['pins'][name]==pin for name,pin in owner['pins'].items()),
            'return_stage04_continuation_chain_source')
        for name,pin in runtime['pins'].items():
            ref=value['source_files'][name]
            require(type(ref)is dict and set(ref)=={'path','sha256'} and ref['sha256']==pin
                and sha(_stage04_public_file(ref['path']))==pin,'return_stage04_continuation_chain_source')
        for ref,raw in ((value['runtime_review_ref'],runtime_raw),(value['owner_review_ref'],owner_raw)):
            payload['reviewed_basis/'+ref['path']]=raw
    acknowledged=['radik-call:1548d2e6967447c1a718a99676bf8818'];latest=None
    for index,reference in enumerate(refs[1:],1):
        raw,receipt=document(reference,receipt=True)
        fields={'schema','proposal_ref','review_ref','previous_receipt_refs','selected_attempt_id',
            'response_id','context_sha256','body_sha256','before_ledger_sha256','before_ledger_canonical_sha256',
            'historical_prefix_sha256','source_identity_sha256','auth_source_identity_sha256','owner_operation_id',
            'run_id','recorded_at','local_http_closed','local_watchdog_finished','remote_outcome','usage',
            'automatic_retry','server_cancellation_observed','operation_allowance_sha256','receipt_sha256'}
        require(set(receipt)==fields and raw==canonical(receipt)
            and receipt['schema']=='radik.console_local_continuation_receipt.v02'
            and receipt['receipt_sha256']==sha(canonical({k:v for k,v in receipt.items() if k!='receipt_sha256'}))
            and receipt['previous_receipt_refs']==refs[:index]
            and receipt['remote_outcome']==receipt['usage']=='UNKNOWN'
            and receipt['local_http_closed'] is receipt['local_watchdog_finished'] is True
            and receipt['automatic_retry'] is receipt['server_cancellation_observed'] is False,
            'return_stage04_continuation_chain_binding')
        proposal_raw,proposal=document(receipt['proposal_ref']);review_raw,review=document(receipt['review_ref'])
        require(set(proposal)=={'schema','scope','before_ledger_ref','before_task_state_ref','selected_attempt_id',
            'transport_result_ref','previous_receipt_refs','actual_evidence_pins','historical_source_basis',
            'source_basis','receipt_path','operation_allowance','automatic_retry','entry_authorizes_model_or_effect'}
            and proposal['schema']=='radik.console_local_continuation_proposal.v02'
            and proposal['previous_receipt_refs']==refs[:index] and proposal['receipt_path']==reference['path']
            and proposal['selected_attempt_id']==receipt['selected_attempt_id']
            and proposal['automatic_retry'] is proposal['entry_authorizes_model_or_effect'] is False
            and review.get('schema')=='radik.independent.console_local_continuation_review.v02'
            and review.get('reviewer')=='/root/semantic_continuation_reviewer'
            and review.get('status')=='SOURCE_ACCEPTED_FOR_VERSIONED_CONSOLE_CONTINUATION_WITH_FINITE_ALLOWANCE'
            and review.get('scope')==proposal['scope']
            and review.get('proposal_sha256')==sha(proposal_raw)
            and review.get('source_identity_sha256')==receipt['source_identity_sha256']
            and review.get('auth_source_identity_sha256')==receipt['auth_source_identity_sha256']
            and review.get('entry_authorizes_model_or_effect') is False,
            'return_stage04_continuation_chain_review')
        before_raw,before=document(proposal['before_ledger_ref']);_task_raw,_tasks=document(proposal['before_task_state_ref'])
        result_raw,result=document(proposal['transport_result_ref'])
        require(before_raw==canonical(before) and receipt['before_ledger_sha256']==sha(before_raw)
            and receipt['before_ledger_canonical_sha256']==before.get('ledger_sha256')
            and before['ledger_sha256']==sha(canonical({k:v for k,v in before.items() if k!='ledger_sha256'}))
            and receipt['historical_prefix_sha256']==sha(canonical(before['attempts']))
            and before.get('console_continuation_chain',[before.get('console_continuation_ref')])==refs[:index]
            and before['active_attempt_id']==receipt['selected_attempt_id']
            and ledger['attempts'][:len(before['attempts'])]==before['attempts']
            and receipt['operation_allowance_sha256']==sha(canonical(proposal['operation_allowance'])),
            'return_stage04_continuation_chain_prefix')
        selected=[row for row in before['attempts'] if row.get('attempt_id')==receipt['selected_attempt_id']]
        require(len(selected)==1 and receipt['selected_attempt_id'] not in acknowledged,
            'return_stage04_continuation_chain_prefix')
        row=selected[0]
        require(row['outcome']==row['usage']=='UNKNOWN' and result.get('reservation_id')==row['attempt_id']
            and result.get('response_id')==receipt['response_id']==row['telemetry']['response_id']
            and result.get('context_sha256')==receipt['context_sha256']==row['context_sha256']
            and result.get('wire',{}).get('body_sha256')==receipt['body_sha256']==row['telemetry']['wire_body_sha256']
            and result.get('client_http_closed') is result.get('deadline_watchdog_finished') is True
            and result.get('terminal_observed') is False and result.get('outcome')==result.get('usage')=='UNKNOWN'
            and type(receipt['recorded_at'])is int and receipt['recorded_at']>=row['finished_at']
            and type(receipt['owner_operation_id'])is str
            and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',receipt['owner_operation_id'])
            and type(receipt['run_id'])is str and re.fullmatch('[0-9a-f]{12}',receipt['run_id'])
            and all(old['owner_operation_id']!=receipt['owner_operation_id'] and old['run_id']!=receipt['run_id']
                for old in before['attempts']), 'return_stage04_continuation_chain_binding')
        basis(proposal['source_basis'],receipt['source_identity_sha256'],receipt['auth_source_identity_sha256'])
        old_runtime_raw,old_runtime=document(proposal['historical_source_basis']['runtime_review_ref'])
        _old_owner_raw,old_owner=document(proposal['historical_source_basis']['owner_review_ref'])
        basis(proposal['historical_source_basis'],result['source_identity_sha256'],sha(canonical(old_owner['pins'])))
        if len(ledger['attempts'])>len(before['attempts']):
            first=ledger['attempts'][len(before['attempts'])]
            require(first.get('owner_operation_id')==receipt['owner_operation_id'] and first.get('run_id')==receipt['run_id'],
                'return_stage04_continuation_operation_binding')
        payload['actual_owner/console_continuations/'+Path(reference['path']).name]=raw
        for ref,data in ((receipt['proposal_ref'],proposal_raw),(receipt['review_ref'],review_raw),
                (proposal['before_ledger_ref'],before_raw),(proposal['before_task_state_ref'],_task_raw),
                (proposal['transport_result_ref'],result_raw)):
            payload['reviewed_basis/'+ref['path']]=data
        acknowledged.append(receipt['selected_attempt_id']);latest=(reference,receipt)
    require(latest is not None,'return_stage04_continuation_chain_binding')
    for value in (state,connected):
        context=value.get('console_continuation') if type(value)is dict else None
        if type(context)is dict:
            require(context.get('receipt_ref')==latest[0]
                and value.get('owner_operation_id',value.get('operation_id'))==latest[1]['owner_operation_id']
                and value.get('run_id',value.get('console_run_id'))==latest[1]['run_id'],
                'return_stage04_continuation_operation_binding')
    return payload


def _stage04_normal_payload(state, *, required=False):
    """Copy a finite current normal journal; packaging creates no round authority."""
    ledger_raw = _stage04_public_file('state/console_model_turns.json')
    ledger = json.loads(ledger_raw)
    if ledger.get('version') != 'radik.console_turn_ledger.v05':
        require(not required, 'return_normal_transition_required')
        return {}
    payload = {}

    def select(relative, expected=None):
        require(type(relative) is str and (relative.startswith((STAGE04_PASSAGE+'/',
                'state/normal_operations/', 'state/normal_rounds/'))
            or relative in ('config/normal_session_policy.json', 'state/normal_session_transition.json',
                'state/normal_session_committed.json', 'state/normal_session_active.json',
                'state/console_model_turns.json', 'state/task_model_settings.json',
                'workspace/owner_documents/state/dynamic_tasks.json')),
            'return_normal_public_journal_path')
        raw = _stage04_public_file(relative, 32*1024*1024)
        require(expected is None or sha(raw) == expected, 'return_normal_journal_bytes_changed')
        value = json.loads(raw)
        _no_secrets(value)
        payload['actual_normal/'+relative] = raw
        return value, raw

    def reference(ref):
        require(type(ref) is dict and set(ref) == {'path','sha256'}
            and type(ref['sha256']) is str and re.fullmatch('[0-9a-f]{64}',ref['sha256']),
            'return_normal_journal_reference')
        return select(ref['path'], ref['sha256'])

    transition_ref = ledger.get('normal_policy_transition_ref')
    require(type(transition_ref) is dict and transition_ref.get('path') == 'state/normal_session_transition.json',
        'return_normal_transition_required')
    transition, _ = reference(transition_ref)
    require(transition.get('schema') == 'radik.normal_session_transition.v01',
        'return_normal_transition_required')
    proposal, _ = reference(transition.get('proposal_ref'))
    reference(transition.get('review_ref'))
    require(proposal.get('schema') == 'radik.normal_session_transition_proposal.v01',
        'return_normal_transition_required')
    for field in ('before_ledger_ref','task_state_ref','normal_policy_ref','source_review_ref','source_admission_ref'):
        reference(proposal.get(field))
    for relative in ('state/normal_session_committed.json','state/console_model_turns.json',
            'state/task_model_settings.json'):
        select(relative)
    tasks, _ = select('workspace/owner_documents/state/dynamic_tasks.json')
    operation, run = state.get('operation_id'), state.get('console_run_id')
    require(type(operation) is str and re.fullmatch('[0-9a-f-]{36}',operation)
        and type(run) is str and re.fullmatch('[0-9a-f]{12}',run), 'return_normal_operation_identity')
    relative = 'state/normal_operations/'+operation.replace('-','')+'.json'
    if not (PROJECT/relative).exists():
        require(not required and not (PROJECT/relative).is_symlink(), 'return_normal_operation_witness_missing')
        return payload
    value, raw = select(relative)
    operation_ref = dict(path=relative, sha256=sha(raw))
    require(value.get('schema') == 'radik.normal_operation.v01'
        and value.get('owner_operation_id') == operation and value.get('run_id') == run
        and value.get('transition_ref') == transition_ref, 'return_normal_operation_identity')
    for field in ('source_review_ref','source_admission_ref'):
        reference(value.get(field))
    for optional in (relative+'.closed','state/normal_session_active.json'):
        if (PROJECT/optional).exists():
            select(optional)
        else:
            require(not (PROJECT/optional).is_symlink(), 'return_normal_public_journal_path')
    grants = {}
    for row in tasks.get('tasks',{}).values():
        for event in row.get('history',[]):
            proof = event.get('operation_round',{}).get('normal_round_scope')
            if type(proof) is not dict or proof.get('owner_operation_id') != operation or proof.get('run_id') != run:
                continue
            require(proof.get('operation_ref') == operation_ref, 'return_normal_round_operation')
            grant_ref = proof.get('grant_ref')
            require(type(grant_ref) is dict and re.fullmatch('state/normal_rounds/[0-9a-f]{32}\\.json',
                grant_ref.get('path','')), 'return_normal_round_reference')
            grants[grant_ref['path']] = grant_ref
    active_path = PROJECT/'state/normal_session_active.json'
    if active_path.exists():
        active = json.loads(payload['actual_normal/state/normal_session_active.json'])
        if active.get('operation_ref') == operation_ref and type(active.get('round_ref')) is dict:
            grant_ref = active['round_ref']
            require(re.fullmatch('state/normal_rounds/[0-9a-f]{32}\\.json',grant_ref.get('path','')),
                'return_normal_round_reference')
            grants[grant_ref['path']] = grant_ref
    require(len(grants) <= 512, 'return_normal_journal_resource_bound')
    for relative, grant_ref in sorted(grants.items()):
        grant, _ = reference(grant_ref)
        require(grant.get('schema') == 'radik.normal_round_grant.v01'
            and grant.get('operation_ref') == operation_ref
            and grant.get('owner_operation_id') == operation and grant.get('run_id') == run,
            'return_normal_round_operation')
        closed = relative+'.closed'
        if (PROJECT/closed).exists():
            close, _ = select(closed)
            require(close.get('schema') == 'radik.normal_round_close.v01'
                and close.get('grant_ref') == grant_ref, 'return_normal_round_close')
        else:
            require(not (PROJECT/closed).is_symlink(), 'return_normal_public_journal_path')
    return payload


def _stage04_transport_payload(directory, *, source_identity_sha256=None, owner_operation_id=None, task_ids=None):
    payload={}
    if directory is None:return payload
    path=Path(directory);path=path if path.is_absolute() else PROJECT/path
    safe_parents(path,PROJECT)
    require(path.parent==PROJECT/PASSAGE/'transport_observations'
        and re.fullmatch(r'[0-9]{10,22}',path.name),'return_stage04_transport_selector')
    if not path.exists():return payload
    relative=_live_directory(PROJECT,directory,PASSAGE+'/transport_observations',r'[0-9]{10,22}')
    require(type(source_identity_sha256) is str and re.fullmatch(r'[0-9a-f]{64}',source_identity_sha256)
        and type(owner_operation_id) is str and re.fullmatch(r'[0-9a-f-]{36}',owner_operation_id),
        'return_stage04_transport_origin')
    ledger=json.loads(_stage04_public_file('state/console_model_turns.json'))
    require(type(ledger.get('attempts')) is list,'return_stage04_transport_ledger')
    attempts={row['attempt_id']:row for row in ledger['attempts']
        if row.get('owner_operation_id')==owner_operation_id
        and (task_ids is None or row.get('round_binding',{}).get('task_id') in task_ids)}
    names=sorted(os.listdir(owned(relative)))
    require(len(names)<=256,'return_stage04_transport_count')
    for name in names:
        if re.fullmatch(r'(?:catalog_(?:failure_|http_)?|reserved_|http_|result_)[0-9a-f]{32}\.json',name) is None:continue
        raw=read(relative+'/'+name);value=json.loads(raw);_no_secrets(value)
        require(type(value) is dict and value.get('schema') in (
            'radik.direct_plan_role_observation.v01','radik.direct_plan_catalog_receipt.v01',
            'radik.direct_plan_catalog_failure.v01','radik.direct_plan_http_header_observation.v01'),
            'return_stage04_transport_schema')
        require(value.get('source_identity_sha256')==source_identity_sha256,
            'return_stage04_transport_current_source')
        reservation=value.get('reservation_id')
        if reservation is not None:
            require(reservation in attempts,'return_stage04_transport_foreign_reservation')
        if value['schema']=='radik.direct_plan_role_observation.v01':
            row=attempts.get(reservation);guard=value.get('semantic_reservation_guard',{})
            require(row is not None and guard.get('task_id')==row['round_binding']['task_id']
                and value.get('role')==row['role'] and value.get('context_sha256')==row['context_sha256'],
                'return_stage04_transport_task_binding')
        payload['actual_transport/'+name]=raw
    return payload


def _stage04_connected_payload(result):
    """Select exact task, source, native and DRS producer/consumer witnesses.

    No directory discovery occurs. The saved current index, approved IDs and
    snapshots provide the finite references; every content address is reread.
    """
    require(type(result) is dict and result.get('schema') in ('radik.stage04.actual_connected_result.v01',
            'radik.stage04.native_scenario_result.v01'),
        'return_stage04_connected_schema')
    native_scenario = result['schema'] == 'radik.stage04.native_scenario_result.v01'
    payload={};prefix='workspace/owner_documents/'
    index_path=prefix+'state/dynamic_tasks.json'
    index_raw=_stage04_public_file(index_path,1024*1024);index=json.loads(index_raw)
    require(index.get('version')=='radik.dynamic.task_store.v01' and type(index.get('tasks')) is dict
        and len(index['tasks'])<=64 and type(index.get('sources')) is dict and len(index['sources'])<=64,
        'return_stage04_task_index_shape')
    payload['actual_task_state/dynamic_tasks.json']=index_raw
    selected=result.get('task_ids',{})
    require(type(selected) is dict
        and set(selected) <= ({'decomposed','nested'} if native_scenario else {'a','b','c'})
        and len(selected) <= (2 if native_scenario else 3),
        'return_stage04_task_selection')
    source_ids=set()
    for task_id in selected.values():
        require(type(task_id) is str and re.fullmatch(r'radik-task:[0-9a-f]{32}',task_id)
            and task_id in index['tasks'],'return_stage04_selected_task')
        row=index['tasks'][task_id];spec=row.get('spec')
        require(type(spec) is dict and spec.get('task_id')==task_id and type(spec.get('source_ids')) is list
            and 1<=len(spec['source_ids'])<=4 and type(row.get('results')) is list and len(row['results'])<=256,
            'return_stage04_selected_task_shape')
        source_ids.update(spec['source_ids'])
        for ref in row['results']:
            require(type(ref) is dict and re.fullmatch(task_id.split(':')[-1]+r'-[0-9a-f]{64}\.json',ref.get('filename',''))
                and re.fullmatch(r'[0-9a-f]{64}',ref.get('sha256','')),'return_stage04_task_result_reference')
            path=prefix+'output/'+ref['filename'];raw=_stage04_public_file(path,262144);value=json.loads(raw)
            require(sha(raw)==ref['sha256'] and value.get('task_id')==task_id
                and value.get('result_id')==ref['result_id'],'return_stage04_task_result_readback')
            payload['actual_task_results/'+ref['filename']]=raw
    for source_id in source_ids:
        require(type(source_id) is str and re.fullmatch(r'radik:source:[0-9a-f]{32}',source_id)
            and source_id in index['sources'],'return_stage04_approved_source_id')
        filename=source_id.split(':')[-1]+'.txt'
        require(index['sources'][source_id].get('filename')==filename,'return_stage04_approved_source_filename')
        raw=_stage04_public_file(prefix+'input/'+filename,16384);raw.decode('utf-8')
        require(raw and b'\0' not in raw,'return_stage04_approved_source_bytes')
        payload['actual_sources/'+filename]=raw
    for name in ('dynamic_source_revisions.json','owned_effect_policy.json'):
        path=prefix+'state/'+name
        if (PROJECT/path).exists():payload['actual_task_state/'+name]=_stage04_public_file(path,1048576)
    steps=result.get('steps',[]);partial=result.get('partial_snapshots',[])
    require(type(steps) is list and len(steps) <= (5 if native_scenario else 4)
        and type(partial) is list and len(partial) <= (2 if native_scenario else 3),
        'return_stage04_snapshot_count')
    snapshots=[step['native_snapshot'] for step in steps]+partial
    witnesses={}
    for snapshot in snapshots:
        require(type(snapshot) is dict and snapshot['task']['task_id'] in selected.values()
            and type(snapshot.get('evidence_refs')) is list and len(snapshot['evidence_refs'])<=128
            and type(snapshot.get('memory_events')) is list and len(snapshot['memory_events'])<=512,
            'return_stage04_snapshot_scope')
        for ref in snapshot['evidence_refs']:
            path=Path(ref['path']);require(path.is_relative_to(PROJECT),'return_stage04_witness_owned')
            relative=str(path.relative_to(PROJECT))
            expected_folder=sha(canonical(snapshot['task']['task_id']))
            require(re.fullmatch(r'workspace/owner_documents/review/task_evidence/'+expected_folder+
                r'/[a-z][a-z0-9_]{0,47}_[0-9a-f]{64}\.json',relative),
                'return_stage04_native_witness_selector')
            raw=_stage04_public_file(relative)
            require(sha(raw)==ref['sha256'] and len(raw)==ref['bytes'],'return_stage04_native_witness_changed')
            witnesses[relative]=raw
        for event in snapshot['memory_events']:
            if event.get('operation')!='WRITEBACK':continue
            record_id,payload_sha=event.get('record_id'),event.get('payload_sha256')
            require(type(record_id) is str and re.fullmatch(r'drsmeaning_v01:[0-9a-f]{64}',record_id)
                and type(payload_sha) is str and re.fullmatch(r'[0-9a-f]{64}',payload_sha),
                'return_stage04_drs_writeback_reference')
            path=prefix+'state/document_memory/work/'+record_id.replace(':','_')+'.json'
            raw=_stage04_public_file(path,65536);record=json.loads(raw)
            require(record.get('record_id')==record_id and sha(canonical(record))==event['persisted_record_sha256'],
                'return_stage04_drs_record_readback')
            witnesses[path]=raw
            path=prefix+'state/document_memory/payloads/'+payload_sha+'.json'
            raw=_stage04_public_file(path,262144)
            require(sha(raw)==payload_sha,'return_stage04_drs_payload_readback')
            witnesses[path]=raw
    require(len(witnesses)<=512 and sum(map(len,witnesses.values()))<=256*1024*1024,
        'return_stage04_native_witness_bound')
    payload.update({'actual_witnesses/'+path:raw for path,raw in witnesses.items()})
    return payload


def publish_stage04_owner_failure(state, *, source_admitted, transport_directory=None):
    """One truthful source/catalog/console refusal report, never an automatic retry."""
    record,raw=_stage04_writer_review('failure_reporter_review.json',
        'ACCEPTED_FOR_STDLIB_OWNER_FAILURE_RETURN','CURATED_OWNER_FAILURE_ONLY')
    require(type(state) is dict and type(source_admitted) is bool
        and re.fullmatch(r'[0-9a-f-]{32,36}',state.get('operation_id','')) is not None,
        'return_stage04_failure_operation')
    _no_secrets(state)
    for kind in ('stage04_actual','stage04_failure'):
        relative='review/return_verifications/before_owner_fix_'+kind+'_'+state['operation_id']+'_build.json'
        # Internal writer metadata stays excluded from every payload selector.
        path=PROJECT/relative;safe_parents(path,PROJECT)
        if path.exists():
            regular(path,PROJECT,65536)
            reservation_raw=path.read_bytes();reservation=json.loads(reservation_raw)
            require(reservation.get('schema')=='radik.single_return_build.v01'
                and reservation.get('kind')==kind and reservation.get('key')==state['operation_id']
                and reservation.get('retry_or_reset_allowed') is False,'return_stage04_report_reservation')
            return dict(report_status='DELIVERY_UNCONFIRMED',
                publication_state='EXISTING_REPORT_BUILD_OR_DELIVERY_UNCONFIRMED',
                reservation_path=relative,reservation_sha256=sha(reservation_raw),automatic_repack=False,
                archive_verification='NOT_ESTABLISHED_BY_RESERVATION')
    if source_admitted:
        require(read_json(PASSAGE+'/owner_state.json')==state,'return_stage04_actual_checkpoint')
    payload={'actual_owner/owner_state.json':canonical(state)+b'\n',
        'actual_owner/exam_ledger.json':_stage04_public_file('state/model_turns.json')}
    payload.update(_stage04_continuation_payload(state))
    for relative in ('state/console_model_turns.json','state/console_budget_activation.json',
        'state/console_stage04_transition.json','state/console_stage04_committed.json','state/task_model_settings.json'):
        if (PROJECT/relative).exists():payload['actual_owner/'+Path(relative).name]=_stage04_public_file(relative)
    require(not source_admitted or transport_directory==state.get('stage04_transport_directory'),
        'return_stage04_failure_transport_binding')
    payload.update(_stage04_transport_payload(transport_directory,
        source_identity_sha256=state.get('source_identity_sha256'),owner_operation_id=state['operation_id']))
    for name in ('owner_phase_journal.json','owner_auth_observations.json','owner_dependency_observation.json'):
        path=PASSAGE+'/'+name
        if not (PROJECT/path).exists():continue
        raw_observation=read(path);observation=json.loads(raw_observation)
        if observation.get('owner_operation_id',observation.get('operation_id'))==state['operation_id']:
            payload['actual_owner/'+name]=raw_observation
    result_path=state.get('stage04_actual_result_path')
    if result_path is not None:
        require(type(result_path) is str and re.fullmatch(
            r'workspace/owner_documents/review/stage04_actual_runs/[0-9a-f]{12}\.json',result_path),
            'return_stage04_failure_result_selector')
        result_raw=_stage04_public_file(result_path)
        payload['actual_owner/connected_result.json']=result_raw
        connected=json.loads(result_raw)
        payload.update(_stage04_continuation_payload(state,connected))
        if connected.get('task_ids'):payload.update(_stage04_connected_payload(connected))
    payload.update(_stage04_normal_payload(state))
    payload['README_OWNER_FAILURE_RU.txt']=(_stage04_failure_line(state)+'\n'
        +'Сохранены фактические публичные наблюдения и счётчики. Native G2-E для NO_EFFECTS не принят.\n').encode()
    payload['CONTINUE_AFTER_OWNER_RUN_RU.txt']=('Проверьте actual_owner и actual_transport из этого архива. Различайте отсутствие catalog, неопределённую попытку модели, принятый native результат и ошибку отчёта. Не повторяйте запрос до проверки ledger и receipts.\n').encode()
    payload['reviewed_basis/'+STAGE04_PASSAGE+'/failure_reporter_review.json']=raw
    if source_admitted:_stage04_current_basis(payload)
    for path in record['code_source_pins']:payload['writer_basis/'+path]=read(path)
    for name,value in payload.items():
        if name.endswith('.json'):_no_secrets(json.loads(value))
    return _build(kind='stage04_failure',key=state['operation_id'],payload=payload,record=record,
        review_raw=raw,basis=dict(scope='STAGE04_ACTUAL_FAILURE_ONLY',inference_or_effect_retry=False),prior=[])


def publish_stage04_owner_result(project, result_relative, transport_directory):
    """Automatic bounded actual return through the established archive/exporter."""
    require(Path(project)==PROJECT,'return_stage04_project')
    record,raw=_stage04_writer_review('live_return_source_review.json',
        'ACCEPTED_FOR_STAGE04_ACTUAL_INFORMATIONAL_RETURN','STAGE04_ACTUAL_INFORMATIONAL_OBSERVATIONS_ONLY')
    from review.transport.direct_plan_gate import console_execution_entry, source_review
    console_execution_entry(PROJECT);runtime=source_review(PROJECT,runtime=True)
    require(re.fullmatch(r'workspace/owner_documents/review/stage04_actual_runs/[0-9a-f]{12}\.json',result_relative),
        'return_stage04_actual_result_selector')
    result_raw=_stage04_public_file(result_relative);result=json.loads(result_raw)
    native_scenario = result.get('schema') == 'radik.stage04.native_scenario_result.v01'
    require((native_scenario and result.get('status') in (
            'NATIVE_SCENARIO_OBSERVATIONS_COMPLETE_E_BLOCKED','NATIVE_SCENARIO_PARTIAL_OBSERVATIONS_E_BLOCKED')
            and type(result.get('steps')) is list and 0 <= len(result['steps']) <= 5)
        or (result.get('schema')=='radik.stage04.actual_connected_result.v01'
            and result.get('status')=='CONNECTED_INFORMATIONAL_OBSERVATIONS_COMPLETE_E_BLOCKED'
            and type(result.get('steps')) is list and len(result['steps'])==4),
        'return_stage04_actual_result_shape')
    require(result.get('selective_delta_accepted') is False and result.get('external_effects')==0,
        'return_stage04_actual_result_shape')
    state=read_json(PASSAGE+'/owner_state.json')
    require(state.get('operation_id')==result.get('owner_operation_id')
        and state.get('console_run_id')==result.get('run_id')
        and state.get('source_identity_sha256')==sha(canonical(runtime['pins'])),
        'return_stage04_actual_operation_binding')
    payload={'actual_owner/connected_result.json':result_raw,
        'actual_owner/owner_state.json':canonical(state)+b'\n'}
    payload.update(_stage04_continuation_payload(state,result))
    payload.update(_stage04_normal_payload(state, required=native_scenario))
    require(transport_directory==result.get('transport_directory'), 'return_stage04_result_transport_binding')
    payload.update(_stage04_transport_payload(transport_directory,
        source_identity_sha256=state['source_identity_sha256'],owner_operation_id=result['owner_operation_id'],
        task_ids=set(result.get('task_ids',{}).values())))
    payload.update(_stage04_connected_payload(result))
    for relative in ('state/model_turns.json','state/console_model_turns.json','state/console_budget_activation.json',
        'state/console_stage04_transition.json','state/console_stage04_committed.json','state/task_model_settings.json'):
        payload['actual_owner/'+Path(relative).name]=_stage04_public_file(relative)
    payload['README_OWNER_RESULT_RU.txt']=(
        'Сохранены фактические наблюдения подготовленного native сценария. Маршруты, роли, дочерние возвраты, потребление и U2 учитываются только по выполнению; short или неполный результат не доказывает nested. Native G2-E NO_EFFECTS не принят.\n'
        if native_scenario else
        'Связанный информационный сценарий создал фактические результаты compare, explain и verify; переход A→B→A проверил текущую память. Это evidence для независимой приёмки. Native G2-E NO_EFFECTS остаётся заблокирован; selective delta не принята.\n').encode()
    payload['CONTINUE_AFTER_OWNER_RUN_RU.txt']=('Проверьте actual_owner/connected_result.json, полные actual_transport и actual_witnesses. Сверьте реальные роли, native потребление, свежую память, ledger и границу NO_EFFECTS. Не повторяйте платные действия для оформления отчёта.\n').encode()
    payload['reviewed_basis/'+STAGE04_PASSAGE+'/live_return_source_review.json']=raw
    _stage04_current_basis(payload,require_execution=True)
    for path in record['code_source_pins']:payload['writer_basis/'+path]=read(path)
    for name,value in payload.items():
        if name.endswith('.json'):_no_secrets(json.loads(value))
    return _build(kind='stage04_actual',key=result['owner_operation_id'],payload=payload,record=record,
        review_raw=raw,basis=dict(scope='STAGE04_ACTUAL_INFORMATIONAL_OBSERVATIONS_ONLY',
            current_source_identity_sha256=sha(canonical(runtime['pins'])),
            native_E='BLOCKED_PUBLIC_NO_EFFECTS_CONTRACT',behavior_awarded_by_packaging=False),prior=[])


def publish_stage04_source():
    """Extend the existing single-return writer with one finite reviewed passage.

    The independent selector fixes every byte before this function runs. It does
    not walk application, reference, state, evidence or private directories.
    Source and bounded results remain distinct from provider or E acceptance.
    """
    review_path = STAGE04_PASSAGE + '/return_source_review.json'
    review_raw = read(review_path); record = json.loads(review_raw)
    require(record.get('reviewer') == '/root/semantic_continuation_reviewer'
        and record.get('status') == 'ACCEPTED_FOR_NORMAL_SESSION_AND_G2E_SINGLE_SOURCE_RETURN'
        and record.get('scope') == 'NORMAL_SESSION_ACTIVE_SOURCE_CANDIDATE_AND_G2E_UPSTREAM_ONLY',
        'return_stage04_independent_review')
    runtime = read_json(STAGE04_PASSAGE + '/runtime_source_review.json')
    require(runtime.get('reviewer') == '/root/semantic_continuation_reviewer'
        and runtime.get('status') == 'SOURCE_ACCEPTED_FOR_BOUNDED_LIVE_TRANSITION'
        and record.get('runtime_source_identity_sha256') == sha(canonical(runtime['pins'])),
        'return_stage04_current_source')
    inventory = record.get('source_payload_inventory', {})
    hashes = record.get('source_payload_hashes', {})
    code = record.get('code_source_pins', {})
    require(type(inventory) is dict and 10 <= len(inventory) <= 4096
        and type(hashes) is dict and type(code) is dict and code
        and record.get('runtime_source_closure_pins') == runtime['pins']
        and record.get('A_scope') == 'NORMAL_SESSION_ACTIVE_SOURCE_CANDIDATE'
        and record.get('B_scope') == 'UPSTREAM_ONLY_G2E_CANDIDATE_REVIEW_ONLY_NOT_ACTIVE'
        and not any('/proposals/' in path for path in runtime['pins'])
        and all(hashes.get(path) == pin for path, pin in runtime['pins'].items()),
        'return_stage04_finite_inventory')
    paths = {path for path in inventory.values() if type(path) is str and not path.startswith('@')}
    require(set(hashes) == paths and set(code) == {path for path in paths if code_source(path)}
        and all(pin == hashes[path] for path,pin in code.items()),
        'return_stage04_exact_code_closure')
    external = {'@stage04_report': STAGE04_EXTERNAL / 'README_FIRST_RU.txt',
        '@stage04_continuation': STAGE04_EXTERNAL / 'CONTINUE_AFTER_OWNER_RUN_RU.txt',
        '@stage04_handoff': Path('/Users/admin/Downloads/RADIK_STAGE04_NORMAL_SESSION_AND_G2E_CANDIDATE_RU.txt')}
    require(set(record.get('external_payload_hashes', {})) == set(external),
        'return_stage04_external_scope')
    payload = {}
    for name, relative in sorted(inventory.items()):
        require(type(name) is str and not Path(name).is_absolute()
            and '..' not in Path(name).parts and not excluded(Path(name).parts), 'return_stage04_archive_path')
        if relative in external:
            path = external[relative]; regular(path, path.parent)
            raw = path.read_bytes(); expected = record['external_payload_hashes'][relative]
        else:
            require(relative in paths and not Path(relative).is_absolute()
                and not set(Path(relative).parts).intersection(('.', '..'))
                and not excluded(Path(relative).parts)
                and (relative.startswith(('app/', 'config/', 'docs/', 'review/', 'source/reference/'))
                    or relative in ('README.md', 'AGENTS.md', 'radik', '.gitignore')),
                'return_stage04_selected_path')
            require(not relative.startswith(('state/', 'drs/', 'output/')), 'return_stage04_no_state_walk')
            if relative.startswith('source/reference/'):
                require(runtime['pins'].get(relative) == hashes[relative], 'return_stage04_reference_pin')
                path = PROJECT / relative; regular(path, PROJECT); raw = path.read_bytes()
            else:
                raw = read(relative)
            expected = hashes[relative]
        require(sha(raw) == expected, 'return_stage04_selected_bytes_changed')
        if not relative.startswith('@') and Path(relative).suffix == '.json':
            _no_secrets(json.loads(raw))
        payload[name] = raw
    require(all(path in paths for path in (STAGE04_PASSAGE+'/status.json',
        STAGE04_PASSAGE+'/mechanical_result_review.json',
        'review/stage04_dynamic_passage/native_e_no_effects_contract_review.json')),
        'return_stage04_material_boundaries_required')
    status = json.loads(payload[next(name for name,path in inventory.items()
        if path == STAGE04_PASSAGE+'/status.json')])
    require(status.get('stage04_complete') is False and status.get('selective_delta_accepted') is False
        and status.get('native_no_effects_e') == 'BLOCKED_PUBLIC_CONTRACT'
        and status.get('A_scope') == 'NORMAL_SESSION_ACTIVE_SOURCE_CANDIDATE'
        and status.get('B_scope') == 'UPSTREAM_ONLY_G2E_CANDIDATE_REVIEW_ONLY_NOT_ACTIVE'
        and status.get('B_candidate_in_runtime') is False,
        'return_stage04_truthful_partial_boundary')
    payload['evidence/'+review_path] = review_raw
    name, expected = STAGE04_PRIOR
    require(sha(read('review/returns/'+name)) == expected
        and read('review/returns/'+name+'.sha256').decode().strip() == expected+'  '+name,
        'return_stage04_prior_source_pair')
    marker = PROJECT / 'review/return_verifications/normal_session_g2e_final_engineering_build.json'
    marker.parent.mkdir(parents=True, exist_ok=True)
    write_exclusive(marker, canonical(dict(schema='radik.stage04.single_engineering_return.v01',
        packaging_review_sha256=sha(review_raw), automatic_repack=False)) + b'\n')
    return _build(kind='source', key='normal_session_g2e', payload=payload, record=record,
        review_raw=review_raw, basis=dict(scope='NORMAL_SESSION_SOURCE_AND_SEPARATE_UPSTREAM_ONLY_G2E_PROPOSAL',
            reference_commit='800f38c3407b3f4ec93dc943c977ffeecb614881',
            P_campaign='NOT_RERUN', selective_delta='BLOCKED_PUBLIC_NO_EFFECTS_CONTRACT',
            candidate_G2E_runtime_selection='NOT_ACTIVE'),
        prior=[dict(name=name, sha256=expected, outer_verified=True, binary_included=False)])


if __name__ == '__main__':
    require(sys.argv[1:] in ([], ['--stage04']), 'return_no_arbitrary_mode_or_paths')
    print(json.dumps(publish_stage04_source() if sys.argv[1:] else publish_source(), ensure_ascii=False, indent=2))
