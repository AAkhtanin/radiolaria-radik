#!/usr/bin/env python3
"""Explicit owner-started direct-plan setup, authorization, fixed live and console.

Import and --status perform no dependency setup, authorization or inference.
The application and immutable native callbacks load only after exact source pins.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid
from urllib.parse import urlsplit

PROJECT = Path(__file__).resolve().parents[2]
PASSAGE = PROJECT / 'review/direct_plan_passage'
SOURCE_PASSAGE = PROJECT / 'review/actual_save_console_passage'
CURRENT_SOURCE_PASSAGE = PROJECT / 'review/normal_session_g2e_passage'
SETUP_PASSAGE = PROJECT / 'review/before_owner_run_fix_passage'
STATE = PASSAGE / 'owner_state.json'
_CONTEXT = {}
COMMAND = str(PROJECT / '.venv/bin/python') + ' -B ' + str(PROJECT / 'review/transport/radik_owner_start.py')
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


def require(value, code):
    if not value: raise ValueError(code)


def _read(path, cap=8 * 1024 * 1024):
    for node in (path, *path.parents):
        require(not node.is_symlink(), 'owner_source_symlink')
        if node == PROJECT: break
    fd=os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'owner_source_regular')
        raw=stream.read(cap+1)
    require(len(raw)<=cap,'owner_source_byte_bound')
    return raw


def _profile_selection():
    activation=PROJECT/'state/application_profile.json'
    require(not (PROJECT/'state/application_profile.json.pending').exists(),'owner_profile_partial_activation')
    if not activation.exists():return None
    selected=json.loads(_read(activation))
    relative=('review/g2e_successor_passage/proposals/'
        'g2e_no_effects_v31_stage04_closure/ordinary_profile_manifest.json')
    require(selected.get('schema')=='radik.application_profile_activation.v01'
        and selected.get('profile_ref',{}).get('path')==relative,'owner_profile_selection')
    manifest_raw=_read(PROJECT/relative)
    require(hashlib.sha256(manifest_raw).hexdigest()==selected['profile_ref']['sha256'],'owner_profile_manifest_changed')
    manifest=json.loads(manifest_raw);reference=manifest['source_review_ref'];review_raw=_read(PROJECT/reference['path'])
    require(hashlib.sha256(review_raw).hexdigest()==reference['sha256'],'owner_profile_review_changed')
    review=json.loads(review_raw)
    require(review.get('reviewer')=='/root/s04_reviewer'
        and review.get('status')=='SOURCE_ACCEPTED_FOR_ISOLATED_ORDINARY_REHEARSAL'
        and review.get('code_pins')==manifest['pins'],'owner_profile_independent_source_required')
    gate_path=PROJECT/'config/application_profile_gate.py'
    require(hashlib.sha256(_read(gate_path)).hexdigest()==review['code_pins'].get('config/application_profile_gate.py'),
        'owner_profile_preimport_gate_changed')
    require(not (PROJECT/'config/__init__.py').exists(),'owner_profile_namespace_initializer')
    if str(PROJECT)not in sys.path:sys.path.insert(0,str(PROJECT))
    from config.application_profile_gate import select
    return select(PROJECT)


def _early_failure(args,error):
    import time
    import re
    code=getattr(error,'code',None)
    if type(code)is not str:code=error.args[0]if error.args and type(error.args[0])is str else'ordinary_bootstrap_failure'
    if not re.fullmatch('[a-z][a-z0-9_]{1,159}',code):code='ordinary_bootstrap_failure'
    failure=dict(phase='AUTH'if type(error).__name__=='PlanAuthError'else'ORDINARY_BOOTSTRAP',
        error_class=type(error).__name__,code=code)
    print('PRIMARY_FAILURE phase='+failure['phase']+' code='+code+' error_class='+failure['error_class'],flush=True)
    started=getattr(args,'owner_operation_started_ns',None)if args is not None else None
    binding=getattr(args,'owner_run_binding',None)if args is not None else None
    if type(started)is int and re.fullmatch('[0-9a-f]{64}',binding or''):
        for sequence,kind in ((1,'PRIMARY_FAILURE'),(2,'FINAL')):
            observed_ns=time.monotonic_ns()
            row=dict(schema='radik.p28.owner_event.v01',child_pid=os.getpid(),run_binding=binding,
                operation_started_ns=started,sequence=sequence,kind=kind,phase='FINALIZATION',
                at_monotonic_ns=observed_ns,elapsed_wall_ns=max(0,observed_ns-started),
                elapsed_process_cpu_ns=time.process_time_ns(),elapsed_main_thread_cpu_ns=time.thread_time_ns(),failure=failure)
            if kind=='FINAL':row['success']=False
            print(json.dumps(row,sort_keys=True,separators=(',',':')),flush=True)
    return 2


def _ordinary_profile_main(args,selected):
    try:
        from app.ordinary_entry import run
        return run(PROJECT,args,selected)
    except Exception as error:return _early_failure(args,error)


def bootstrap():
    require(sys.dont_write_bytecode and sys.version_info[:2]==(3,14),'owner_python_profile')
    require(PROJECT.resolve(strict=True)==PROJECT,'owner_project_identity')
    selected=_profile_selection()
    if selected is not None:return selected['auth_review']
    review=json.loads(_read(CURRENT_SOURCE_PASSAGE/'owner_source_review.json'))
    require(review.get('status')=='SOURCE_ACCEPTED_FOR_OWNER_AUTH_PREFLIGHT'
            and review.get('scope')=='DIRECT_CHATGPT_PLAN_SOURCE_ONLY'
            and review.get('reviewer')=='/root/semantic_continuation_reviewer','owner_source_acceptance_required')
    pins=review.get('pins',{})
    require(set(pins)==AUTH_SOURCE_FILES,'owner_bootstrap_auth_closure')
    for relative in ('review/__init__.py','review/transport/__init__.py'):
        require(not (PROJECT/relative).exists() and not (PROJECT/relative).is_symlink(),
                'owner_unreviewed_namespace_initializer')
    for relative,sha in pins.items():
        require(type(relative) is str and not Path(relative).is_absolute()
                and not set(Path(relative).parts).intersection(('.', '..','private','codex-home','Arena','arena'))
                and not relative.startswith(('state/','drs/','output/','.venv')),
                'owner_immutable_code_pin_path')
        require(hashlib.sha256(_read(PROJECT/relative)).hexdigest()==sha,'owner_source_pin_mismatch')
    return review


def _scope_projection(scope):
    """Project the selected finite ledger without altering historical records."""
    from review.transport.model_scope import read_scope_state
    selected=read_scope_state(PROJECT,scope)
    raw=_read(PROJECT/selected['ledger_path']);ledger=json.loads(raw)
    unknown=[row['attempt_id'] for row in ledger['attempts'] if row['outcome']=='UNKNOWN']
    return dict(counted_attempts=selected['counted'],remaining_attempts=selected['remaining_attempts'],
        active_attempt=selected['active_attempt_id'],ledger_after_sha256=hashlib.sha256(raw).hexdigest(),
        active_attempt_scope='MANAGED_LOCAL_OCCUPANCY',remote_unknown_attempt_ids=unknown,
        local_occupancy_contract=ledger.get('local_occupancy_contract','UNAMENDED'),
        historical_local_release=selected.get('local_occupancy_released',False),
        acknowledged_remote_unknown_attempt_ids=selected.get('acknowledged_remote_unknown_attempt_ids',[]),
        unacknowledged_unknown_attempt_ids=selected.get('unacknowledged_unknown_attempt_ids',selected['unknown_attempt_ids']))


def public_state():
    path=STATE if STATE.exists() else CURRENT_SOURCE_PASSAGE/'status.json'
    value=json.loads(_read(path))
    from review.transport.model_scope import read_scope_state
    scope=value.get('budget_scope','exam')
    projection=_scope_projection(scope)
    return dict(value,**projection,console_budget=read_scope_state(PROJECT,'console'),
        legacy_exam_budget=read_scope_state(PROJECT,'exam'),
        ledger_sha256_scope='OPERATION_START_IDENTITY')


def checkpoint(stage, **details):
    projection=_scope_projection(_CONTEXT.get('budget_scope','exam'))
    # Context carries the operation-start identity. Details cannot replace it
    # or any field computed from the authoritative current ledger.
    computed={'schema','stage','recorded_at_utc','runtime_behavior','console',
        'ledger_before_sha256','ledger_sha256_scope','ledger_after_sha256',
        'counted_attempts','remaining_attempts','active_attempt','active_attempt_scope',
        'remote_unknown_attempt_ids','local_occupancy_contract','historical_local_release',
        'acknowledged_remote_unknown_attempt_ids','unacknowledged_unknown_attempt_ids'}
    require(not set(details).intersection(computed|set(_CONTEXT)),
            'owner_checkpoint_reserved_detail')
    require(not set(_CONTEXT).intersection(computed-{'ledger_before_sha256'}),
            'owner_checkpoint_reserved_context')
    value={**_CONTEXT,**details}
    value.update(schema='radik.direct_plan_owner_state.v01',stage=stage,
        recorded_at_utc=datetime.now(timezone.utc).isoformat(),runtime_behavior='NOT_ACCEPTED',
        console='BEHAVIOR_REVIEW_PENDING',
        ledger_before_sha256=_CONTEXT.get('ledger_before_sha256',_CONTEXT.get('ledger_sha256')),
        ledger_sha256_scope='OPERATION_START_IDENTITY',
        **projection)
    require(not STATE.is_symlink(),'owner_state_symlink')
    temporary=PASSAGE/('owner_state.'+str(os.getpid())+'.pending')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(json.dumps(value,ensure_ascii=False,sort_keys=True).encode()+b'\n')
        stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,STATE)
    directory=os.open(PASSAGE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
    return value


def public_observation(name,value):
    require(name in ('owner_auth_observations.json','owner_dependency_observation.json','owner_phase_journal.json'),
            'owner_observation_closed_selector')
    if name!='owner_phase_journal.json':value=dict(value,owner_operation_id=_CONTEXT.get('operation_id'))
    target=PASSAGE/name
    require(not target.is_symlink(),'owner_observation_symlink')
    temporary=target.with_suffix('.pending')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(json.dumps(value,ensure_ascii=False,sort_keys=True,allow_nan=False).encode()+b'\n')
        stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,target)
    directory=os.open(PASSAGE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)


# Only exact owned guard literals may enter public diagnostics.
KNOWN_OWNED_VALUE_ERROR_CODES = frozenset(('accept_current_source_mismatch', 'accepted_result_byte_budget', 'architect_accepted_route', 'architect_declared_obligations', 'architect_no_future_candidate', 'architect_projection_evidence_budget', 'architect_projection_scope', 'architect_schema_evidence_budget', 'architect_schema_projection', 'architect_unprojected_evidence', 'avf_route_refused', 'bounded_live_activation_permission_consistency', 'bounded_live_actual_task_required', 'bounded_live_candidate_postimage_pin_mismatch', 'bounded_live_distinct_continuation_required', 'bounded_live_exact_left_fixture_change', 'bounded_live_handoff_binding', 'bounded_live_ledger_telemetry', 'bounded_live_prior_ledger_mutation', 'bounded_live_prior_timing_mutation', 'bounded_live_provider_phase', 'bounded_live_recovery_effect_expired_or_changed', 'bounded_live_reference_byte_limit', 'bounded_live_reference_object', 'bounded_live_reference_path', 'bounded_live_reference_regular_file', 'bounded_live_reference_symlink', 'bounded_live_runner_source_pin_required', 'bounded_live_semantic_activation_changed', 'bounded_live_semantic_activation_required', 'bounded_live_semantic_current_source_changed', 'bounded_live_semantic_handoff_binding', 'bounded_live_semantic_permission_binding', 'bounded_live_semantic_proposal_identity', 'bounded_live_semantic_proposal_reference', 'bounded_live_six_role_attempts_not_available', 'bounded_live_source_acceptance_required', 'budget_active_or_unknown_call', 'budget_attempt_shape', 'budget_context_hash', 'budget_exhausted', 'budget_finish_identity', 'budget_ledger_active_consistency', 'budget_ledger_identity', 'budget_ledger_shape', 'budget_local_occupancy_contract', 'budget_lock_regular', 'budget_lock_symlink', 'budget_operation_binding_already_set', 'budget_operation_binding_shape', 'budget_pending_write', 'budget_policy_changed', 'budget_recovered_new_reservation_binding', 'budget_recovered_old_request_replay', 'budget_recovered_operation_binding_required', 'budget_recovered_original_history_changed', 'budget_recovered_unknown_row_changed', 'budget_recovery_active_identity', 'budget_recovery_already_applied', 'budget_recovery_application_hash', 'budget_recovery_application_shape', 'budget_recovery_basis_fields', 'budget_recovery_canonical_contract', 'budget_recovery_contract_fields', 'budget_recovery_contract_hash', 'budget_recovery_contract_identity', 'budget_recovery_contract_identity_hash', 'budget_recovery_contract_pin', 'budget_recovery_contract_scope', 'budget_recovery_current_attempt', 'budget_recovery_current_ledger', 'budget_recovery_current_source_or_policy', 'budget_recovery_effect_scope', 'budget_recovery_evidence_fields', 'budget_recovery_evidence_reference', 'budget_recovery_history_duplicate', 'budget_recovery_history_predecessor', 'budget_recovery_history_receipt_binding', 'budget_recovery_history_receipt_substitution', 'budget_recovery_history_shape', 'budget_recovery_ledger_bytes', 'budget_recovery_ledger_changed', 'budget_recovery_local_cleanup', 'budget_recovery_new_operation', 'budget_recovery_old_operation_binding', 'budget_recovery_original_ledger', 'budget_recovery_prior_receipts', 'budget_recovery_receipt_application', 'budget_recovery_receipt_bound', 'budget_recovery_receipt_ledger', 'budget_recovery_receipt_pin', 'budget_recovery_receipt_reference', 'budget_recovery_receipt_regular', 'budget_recovery_receipt_symlink', 'budget_recovery_requires_unknown', 'budget_recovery_response_identity_mismatch', 'budget_recovery_transport_observation_required', 'budget_recovery_transport_pin', 'budget_recovery_transport_reference', 'budget_recovery_unexpected_prior_receipt', 'budget_recovery_unknown_telemetry', 'budget_role', 'budget_symlink', 'budget_terminal_evidence', 'budget_terminal_outcome', 'candidate_fixed_obligations', 'checkpoint_pending', 'checkpoint_symlink', 'claim_allowed_logical_source', 'claim_binding_types', 'claim_both_sources', 'claim_byte_span', 'claim_closed_fields', 'claim_current_binding', 'claim_duplicate', 'claim_each_source_required', 'claim_exact_raw_span', 'claim_quote_budget', 'claim_quote_limit', 'claim_quote_mismatch', 'claim_shape', 'claim_source_binding', 'claim_span_bounds', 'claim_utf8_boundary', 'clock_regression', 'cold_actual_role_pipeline_required', 'comparison_actual_branch_outputs', 'comparison_scope', 'connection', 'console_effect_policy_must_remain_closed', 'console_exam_workspace_refused', 'console_owned_input_symlink', 'console_private_source_refused', 'console_save_not_admitted', 'console_source_byte_limit', 'console_source_not_regular', 'console_source_symlink', 'continuation_actual_prior_result', 'continuation_changed_source_revision_or_hash', 'continuation_control_baseline_not_admitted_before_provider', 'continuation_current_source_order', 'continuation_dependency_binding', 'continuation_duplicate_sources', 'continuation_exactly_one_source_changed', 'continuation_observation_fields', 'continuation_observed_source_binding', 'continuation_observed_source_not_current', 'continuation_prior_ordered_selection_binding', 'continuation_prior_result_hash', 'continuation_prior_result_shape', 'continuation_prior_source_binding', 'continuation_projection_closed_fields', 'continuation_projection_hash', 'continuation_projection_scope', 'continuation_requires_pending_save_policy_before_provider', 'continuation_retained_claims_scope', 'continuation_retained_selection_changed', 'continuation_schema_scope', 'continuation_source_order_or_identity', 'continuation_source_raw_hash', 'continuation_source_shape', 'continuation_trusted_intake_observation_time', 'continuation_two_sources', 'continuation_unchanged_source_bytes', 'control_baseline_scope_or_duplicate', 'controller_continuation_mode', 'controller_directory_symlink', 'controller_no_accepted_result', 'controller_no_current_task', 'controller_owned_directory', 'controller_owned_relative', 'controller_task_already_active', 'critic_candidate_obligations', 'critic_candidate_refused', 'critic_check_fields', 'critic_closed_fields', 'critic_current_candidate', 'critic_exact_candidate', 'critic_schema_actual_candidate', 'delta_actual_intake_mismatch', 'delta_actual_output_evidence', 'delta_actual_parent_consumption', 'delta_actual_retained_business_consumption', 'delta_actual_role_pipeline_required', 'delta_current_host_origin', 'delta_current_root_refused', 'delta_declared_control_baseline_required', 'delta_expected_one_changed_source', 'delta_foreign_source_family', 'delta_foreign_sources', 'delta_genuine_unchanged_work_trigger', 'delta_immutable_work_origin_changed', 'delta_invalidation_binding', 'delta_missing_legitimate_pending_save_carrier', 'delta_native_causal_parent_chain', 'delta_native_observed_source_consumption', 'delta_native_retained_profile', 'delta_recomputed_result_binding', 'delta_retained_D_result_changed', 'delta_retained_proposal_changed', 'delta_retained_source_changed', 'delta_source_binding', 'delta_source_inventory', 'delta_stale_source_observation', 'delta_stale_time', 'delta_swapped_source_binding', 'delta_typed_return_required', 'delta_unknown_impact', 'direct_gate_actual_catalog_required', 'direct_gate_auth_only_source_closure', 'direct_gate_behavior_evidence_changed', 'direct_gate_budget_active_unknown_or_exhausted', 'direct_gate_budget_policy_changed', 'direct_gate_catalog_expired', 'direct_gate_console_behavior_review_pending', 'direct_gate_current_aggregate_acceptance_required', 'direct_gate_current_verified_own_grant_required', 'direct_gate_exam_effect_window_not_closed', 'direct_gate_file_bound', 'direct_gate_focused_delta_evidence_changed', 'direct_gate_focused_source_certificate_binding', 'direct_gate_historical_basis_changed', 'direct_gate_historical_basis_identity', 'direct_gate_historical_transport_witness_changed', 'direct_gate_independent_source_review_required', 'direct_gate_mechanical_supplement_changed', 'direct_gate_mutable_or_private_code_pin', 'direct_gate_owned_path', 'direct_gate_pin_inventory', 'direct_gate_project_identity', 'direct_gate_regular_file', 'direct_gate_relative_path', 'direct_gate_role_scope', 'direct_gate_source_closure_incomplete', 'direct_gate_source_pin_mismatch', 'direct_gate_symlink', 'direct_gate_transition_not_reviewed', 'direct_plan_requires_reviewed_owner_start_entry', 'direct_proposal_has_no_causal_role_chain', 'direct_runtime_own_auth_required', 'downstream_role_projection', 'duplicate', 'effect_policy_closed_fields', 'effect_policy_shape', 'effect_policy_symlink', 'evidence_byte_budget', 'evidence_existing_mismatch', 'evidence_label', 'evidence_nonportable_value', 'evidence_owned_directory', 'evidence_readback', 'evidence_symlink_path', 'execution_phase_not_supported', 'extraction_claims', 'extraction_duplicate_span', 'extraction_quote', 'extraction_source', 'extraction_span', 'fields', 'final_current_source_mismatch', 'final_root_refused', 'general_runtime_not_authorized_by_bounded_handoff', 'goal_limit', 'host', 'intake_closed_registry', 'intake_duplicate_file', 'intake_input_limit', 'intake_owned_directory', 'intake_owned_path', 'intake_pending_state_write', 'intake_regular_file', 'intake_revision_inventory', 'intake_revision_record', 'intake_revision_state', 'intake_symlink', 'live_action_policy_close_readback', 'live_cold_actual_counts', 'live_cold_actual_producer_required', 'live_delta_actual_counts', 'live_delta_actual_unchanged_business_output_required', 'live_quota_second_executor_observed', 'live_semantic_stage_not_admitted', 'live_warm_actual_accepted_material_changed', 'live_warm_actual_memory_consumer_required', 'live_warm_no_model_or_thread_attempt', 'membrane_actual_observation_refs', 'membrane_live_family_required', 'membrane_memory_no_provider_claim', 'membrane_policy_binding', 'membrane_policy_shape', 'membrane_provenance_closed_fields', 'membrane_provenance_hashes', 'membrane_provenance_product_scope', 'membrane_source_bytes', 'membrane_source_identity', 'membrane_source_shape', 'membrane_two_sources', 'memory_accepted_source_binding', 'memory_accepted_task_binding', 'memory_accepted_time_binding', 'memory_actual_descent_material_binding', 'memory_actual_descent_payload_binding', 'memory_checked_selection_required', 'memory_closed_artifact_pointer', 'memory_closed_pointer_profile', 'memory_context_shape', 'memory_current_policy_or_owner_mismatch', 'memory_current_root_refused', 'memory_current_source_or_scope_mismatch', 'memory_current_time_type', 'memory_directory_symlink', 'memory_finite_time', 'memory_fresh_root_required', 'memory_legacy_result_not_causally_qualified', 'memory_logical_path_invalid', 'memory_origin_clock', 'memory_origin_identity', 'memory_origin_shape', 'memory_original_root_provenance', 'memory_original_work_provenance_binding', 'memory_outcome_validator_must_return_verified_plain', 'memory_owned_path_symlink', 'memory_path_outside_owned_directory', 'memory_payload_canonical_binding', 'memory_payload_identity_conflict', 'memory_persisted_payload_corrupt', 'memory_persisted_payload_size', 'memory_qualified_current_pipeline_required', 'memory_record_count_limit', 'memory_record_file_boundary', 'memory_record_id_invalid', 'memory_record_size_limit', 'memory_refusal_contract', 'memory_requires_causal_v02_history', 'memory_root_callback_shape', 'memory_root_exact_claim_binding', 'memory_root_input_invalid', 'memory_root_kernel_invalid', 'memory_root_owner_or_transaction', 'memory_root_result_invalid', 'memory_saved_outcome_not_verified', 'memory_saved_record_fields', 'memory_saved_record_identity', 'memory_saved_record_shape', 'memory_saved_record_tuple', 'memory_saved_root_provenance_binding', 'memory_saved_tuple_shape', 'memory_saved_typed_identity_or_hash', 'memory_saved_typed_shape', 'memory_selected_current_sources', 'memory_selected_payload_source_or_context', 'memory_selected_scope', 'memory_semantic_origin_descent', 'memory_source_duplicate', 'memory_source_hash', 'memory_source_identity', 'memory_source_shape', 'memory_swapped_record_identity', 'memory_swapped_wrapper', 'memory_two_sources_required', 'memory_typed_current_eligibility_refused', 'memory_work_business_comparison', 'memory_work_candidate_binding', 'memory_work_projection_origin', 'memory_work_projection_shape', 'memory_work_sources', 'memory_write_requires_causal_v02', 'memory_writeback_expired', 'memory_writeback_payload_readback', 'memory_writeback_record_readback', 'model_policy_inactive_or_invalid', 'native_D_supplied_validation', 'native_E_supplied_validation', 'native_bsep_relational_refused', 'native_control_root', 'native_control_route', 'native_information_ineligible', 'native_information_root_binding', 'native_information_root_refused', 'native_retained_D_supplied_validation', 'native_semantic_source_refused', 'object', 'one_delta_per_task', 'orchestrator_both_sources', 'orchestrator_closed_fields', 'orchestrator_current_source', 'orchestrator_duplicate_span', 'orchestrator_evidence_budget', 'orchestrator_evidence_fields', 'orchestrator_evidence_types', 'orchestrator_rationale_refused', 'orchestrator_retained_scope_changed', 'orchestrator_scope', 'orchestrator_span_budget', 'orchestrator_span_utf8', 'orchestrator_text_budget', 'outcome_actual_current_semantic_pipeline', 'outcome_actual_root_work_binding', 'outcome_actual_task_origin', 'outcome_current_intake', 'owner_actual_live_result_missing', 'owner_another_process_active', 'owner_auth_recovery_mode', 'owner_auth_terminal_ledger_or_quota_changed', 'owner_auth_terminal_source_binding_changed', 'owner_auth_terminal_verified_receipt_required', 'owner_bootstrap_auth_closure', 'owner_browser_destination', 'owner_checkpoint_reserved_context', 'owner_checkpoint_reserved_detail', 'owner_console_behavior_review_pending', 'owner_continuation_pending_or_symlink', 'owner_dependency_base_binary_changed', 'owner_dependency_base_python_prefix_changed', 'owner_dependency_base_python_version_changed', 'owner_dependency_bootstrap_wheel_changed', 'owner_dependency_combined_lock_changed', 'owner_dependency_download_hash', 'owner_dependency_download_http', 'owner_dependency_download_origin', 'owner_dependency_exact_profile', 'owner_dependency_existing_wheel_changed', 'owner_dependency_fixture_cache_isolation', 'owner_dependency_installed_file_mismatch', 'owner_dependency_installed_symlink', 'owner_dependency_interpreter_not_selected_environment', 'owner_dependency_lock_conflict', 'owner_dependency_lock_format', 'owner_dependency_partial_regular_single_link', 'owner_dependency_public_identity', 'owner_dependency_selected_binary_changed', 'owner_dependency_site_ancestor_symlink', 'owner_dependency_site_missing', 'owner_dependency_startup_hook_refused', 'owner_dependency_unlisted_import_surface', 'owner_dependency_venv_configuration_changed', 'owner_dependency_wheel_changed', 'owner_dependency_wheel_closure', 'owner_dependency_wheel_duplicate', 'owner_dependency_wheel_filename', 'owner_dependency_wheel_path', 'owner_dependency_wheel_unavailable_or_changed', 'owner_disabled_cache_must_be_absent', 'owner_explicit_auth_recovery_required', 'owner_fixed_effect_handoff_missing_or_changed', 'owner_immutable_code_pin_path', 'owner_lock_identity', 'owner_lock_symlink', 'owner_observation_closed_selector', 'owner_observation_symlink', 'owner_one_operation_required', 'owner_phase_closed_name', 'owner_plan_python_copy', 'owner_prior_attempt_checkpoint_no_automatic_restart', 'owner_prior_save_state_no_reset', 'owner_project_identity', 'owner_python_profile', 'owner_quota_symlink', 'owner_ready_carryforward_current_binding_changed', 'owner_ready_carryforward_historical_evidence_changed', 'owner_ready_carryforward_historical_selector', 'owner_ready_carryforward_independent_review_required', 'owner_ready_carryforward_installed_identity_changed', 'owner_ready_checkpoint_source_phase_or_ledger_changed', 'owner_ready_setup_identity_changed', 'owner_recovery_cannot_restart_live', 'owner_reexec_checkpoint_binding', 'owner_reporter_identity_changed', 'owner_reporting_verified_pair_state', 'owner_resume_setup_after_unknown_refused', 'owner_resume_setup_phase_or_ledger_refused', 'owner_resume_setup_ready_journal_required', 'owner_selected_environment_required', 'owner_semantic_actual_closure_binding', 'owner_semantic_actual_evidence_changed', 'owner_semantic_actual_review_binding', 'owner_semantic_actual_run_binding', 'owner_semantic_already_started_no_retry', 'owner_semantic_ancestry_shape', 'owner_semantic_completed_attempt_binding', 'owner_semantic_completed_delta_summary', 'owner_semantic_consumed_ancestry_binding', 'owner_semantic_current_ledger_changed', 'owner_semantic_current_source_binding', 'owner_semantic_evidence_reference', 'owner_semantic_exact_history_prefix', 'owner_semantic_exact_proposal_hash_required', 'owner_semantic_fresh_run_required', 'owner_semantic_historical_occupancy_binding', 'owner_semantic_independent_proposal_review_required', 'owner_semantic_legacy_prefix_path', 'owner_semantic_native_partial_evidence_binding', 'owner_semantic_old_policy_changed', 'owner_semantic_ordered_role_sequence', 'owner_semantic_permission_handoff_changed', 'owner_semantic_permission_scope', 'owner_semantic_predecessor_kind', 'owner_semantic_predecessor_shape', 'owner_semantic_prior_state_changed', 'owner_semantic_proposal_shape', 'owner_semantic_quota_changed', 'owner_semantic_receipt_changed', 'owner_semantic_record_binding', 'owner_semantic_record_path', 'owner_semantic_record_symlink', 'owner_semantic_reexec_activation_binding', 'owner_semantic_stopped_checkpoint_required', 'owner_semantic_terminal_wire_binding', 'owner_setup_after_unknown_refused', 'owner_setup_explicit_resume_required', 'owner_setup_missing_known_environment', 'owner_setup_resume_identity_or_stage', 'owner_setup_unknown_partial_environment', 'owner_setup_unrelated_environment', 'owner_six_attempts_not_available', 'owner_source_acceptance_required', 'owner_source_byte_bound', 'owner_source_pin_mismatch', 'owner_source_regular', 'owner_source_symlink', 'owner_state_symlink', 'owner_status_no_actions', 'owner_unknown_actual_failure_binding', 'owner_unknown_checkpoint_or_ledger_changed', 'owner_unknown_current_source_binding', 'owner_unknown_effect_permission_expired_or_changed', 'owner_unknown_exact_budget_required', 'owner_unknown_exact_contract_hash_required', 'owner_unknown_exact_current_failure_review_required', 'owner_unknown_exact_stopped_checkpoint_required', 'owner_unknown_immutable_evidence_changed', 'owner_unknown_independent_contract_review_required', 'owner_unknown_limited_amendment_required', 'owner_unknown_original_effect_handoff_changed', 'owner_unknown_quota_changed', 'owner_unknown_receipt_already_exists', 'owner_unknown_reexec_context_binding', 'owner_unreviewed_namespace_initializer', 'pending_declared_control_baseline_required', 'policy_consent', 'policy_owned_workspace', 'policy_shape', 'policy_types', 'prior_live_save_state_requires_receipt_review_no_reset', 'proposal_claim_budget', 'proposal_claim_count', 'proposal_closed_fields', 'proposal_foreign_task', 'proposal_foreign_topic', 'proposal_scope', 'proposal_shape', 'proposal_statement_budget', 'proposal_strategy', 'proposal_total_limit', 'proposal_uncertainty', 'pure_actual_output_binding', 'pure_current_extraction_membrane', 'pure_input_budget', 'pure_selection_identity', 'pure_selection_proof_shape', 'pure_selection_source_binding', 'pure_semantic_business_binding', 'pure_semantic_origin_refs', 'pure_semantic_witness_hashes', 'pure_semantic_witness_shape', 'pure_unknown_operation', 'quota_actual_delta_outcome_required', 'quota_actual_effect_host', 'quota_actual_native_receipt', 'quota_actual_native_result_binding', 'quota_actual_output_readback', 'quota_busy', 'quota_clock', 'quota_consumed_or_unknown', 'quota_context_changed', 'quota_current_policy', 'quota_current_source_scope', 'quota_directory_changed', 'quota_exact_target_shape', 'quota_expired', 'quota_grant_expired', 'quota_grant_hash', 'quota_grant_identity', 'quota_grant_kind', 'quota_grant_policy', 'quota_grant_replacement_forbidden', 'quota_grant_shape', 'quota_grant_source_scope', 'quota_grant_sources', 'quota_handoff_bytes', 'quota_handoff_consent', 'quota_ledger_budget', 'quota_ledger_canonical_bytes', 'quota_ledger_corrupt_or_truncated', 'quota_ledger_identity', 'quota_ledger_transition', 'quota_live_document_grant_required', 'quota_lock_missing', 'quota_missing_ledger_no_reset', 'quota_native_output_directory', 'quota_owned_directory', 'quota_receipt_or_executor_binding', 'quota_regular_private_file', 'quota_run_id', 'quota_target_exists_no_overwrite', 'quota_target_not_allowed', 'quota_unexpected_existing_ledger', 'redirect', 'reporter_auth_closure', 'reporter_auth_independent_acceptance_required', 'reporter_auth_source_identity_changed', 'reporter_byte_bound', 'reporter_closure', 'reporter_independent_acceptance_required', 'reporter_regular_file', 'reporter_source_identity_changed', 'reporter_symlink', 'result_root_refused', 'return_B_exact_source_required', 'return_actual_delivered_pair_readback', 'return_actual_early_failure_required', 'return_actual_live_result_and_policy_close_observation_required', 'return_auth_accounting_closed_row', 'return_auth_actual_continuation_required', 'return_auth_actual_phase_binding', 'return_auth_actual_terminal_checkpoint_changed', 'return_auth_delta_A_identity_binding', 'return_auth_delta_code_identity_changed', 'return_auth_delta_code_pin_closure', 'return_auth_delta_exact_passage_paths', 'return_auth_delta_exact_source_required', 'return_auth_delta_finite_source_selection', 'return_auth_delta_independent_packaging_review_required', 'return_auth_delta_prior_source_pair_identity', 'return_auth_delta_source_selector_not_accepted', 'return_auth_ledger_or_quota_changed', 'return_auth_only_failure_current_source_phase_binding', 'return_auth_only_failure_phase', 'return_auth_only_failure_selector_not_accepted', 'return_auth_only_no_transport_directory', 'return_auth_only_source_closure', 'return_auth_only_source_identity_changed', 'return_auth_operation_id', 'return_auth_public_http_accounting_required', 'return_auth_quota_directory', 'return_auth_success_current_source_terminal_required', 'return_auth_success_selector_not_accepted', 'return_auth_verified_public_receipt_required', 'return_auth_writer_closure', 'return_auth_writer_identity_changed', 'return_auth_writer_not_accepted', 'return_catalog_observation_schema', 'return_checksum_created_before_publish', 'return_checksum_final_must_be_absent', 'return_code_identity_changed', 'return_complete_safe_tar_inventory', 'return_completed_prior_reference_basis', 'return_current_state_or_reference_refused', 'return_delivery_receipt_binding', 'return_destination_required', 'return_duplicate_archive_path', 'return_early_failure_selector_not_accepted', 'return_engineering_actual_live_manifest_basis', 'return_engineering_exact_live_link', 'return_engineering_independent_behavior_result_binding', 'return_engineering_live_delivered_pair_readback', 'return_engineering_live_delivery_receipt_binding', 'return_engineering_live_pair_identity', 'return_engineering_live_review_status_binding', 'return_engineering_owned_live_archive', 'return_exact_applied_recovery_basis', 'return_exact_owned_live_directory', 'return_exact_owner_continuation_required', 'return_exact_project_required', 'return_exact_public_recovery_receipt_path', 'return_exact_source_snapshot_and_code_closure', 'return_failure_continuation_identity', 'return_failure_writer_closure', 'return_failure_writer_identity_changed', 'return_failure_writer_not_accepted', 'return_file_changed_during_read', 'return_first_live_aggregate_source_changed', 'return_first_live_current_aggregate_binding', 'return_first_live_focused_evidence_changed', 'return_first_live_focused_source_certificate_binding', 'return_first_live_focused_source_changed', 'return_first_live_focused_supplement_changed', 'return_first_live_historical_basis_changed', 'return_first_live_runtime_basis_binding', 'return_first_live_runtime_identity_changed', 'return_future_selector_review_required', 'return_handoff_finite_selector', 'return_handoff_identity', 'return_handoff_operation_binding', 'return_historical_transport_witness_changed', 'return_independent_packaging_review_required', 'return_independent_review_required', 'return_manifest_exact_inventory', 'return_no_arbitrary_mode_or_paths', 'return_observation_json_depth', 'return_outside_owned_root', 'return_owned_public_relative_path', 'return_owned_root_identity', 'return_owner_operation_id', 'return_owner_phase_binding', 'return_payload_full_readback', 'return_payload_type', 'return_preflight_dispatch_ledger_changed_or_unknown', 'return_prior_archive_outer_identity', 'return_prior_public_recovery_receipt_binding', 'return_prior_public_recovery_receipt_path', 'return_prior_reference_identity', 'return_prior_reference_review_identity', 'return_private_fields_refused', 'return_public_file_type', 'return_public_ledger_closed_shape', 'return_public_ledger_schema', 'return_public_local_recovery_schema', 'return_public_recovery_history_shape', 'return_public_symlink_refused', 'return_reference_baseline_binding', 'return_reference_current_runtime_review_required', 'return_reference_exact_public_pin_path', 'return_reference_executable_closure_required', 'return_reference_normative_review_binding', 'return_reference_regular_single_link_bound', 'return_reference_runtime_pin_map', 'return_reference_selected_bytes_changed', 'return_reference_unselected_path', 'return_regular_single_link_bound', 'return_resolved_outside_owned_root', 'return_reviewed_transition_required', 'return_runtime_closure_path_class', 'return_runtime_exact_mixed_closure', 'return_selected_directory_required', 'return_semantic_activation_binding', 'return_semantic_continuation_selector', 'return_semantic_entered_binding', 'return_semantic_historical_basis_changed', 'return_semantic_operation_references_required', 'return_semantic_proposal_binding', 'return_semantic_reference_shape', 'return_setup_phase_binding', 'return_source_inventory_changed', 'return_source_prompt_archive_path', 'return_source_prompt_identity', 'return_source_prompt_member', 'return_source_ready_honest_pending_required', 'return_source_snapshot_identity', 'return_symlink_path', 'role_name', 'role_schema_name', 'role_scope', 'role_source_hash', 'role_source_shape', 'role_two_sources', 'root_adapter_checks', 'root_invalid_result', 'root_route_refused', 'save_consent_substitution', 'save_context_missing', 'save_current_source_mismatch', 'save_current_validation', 'save_declared_control_baseline_required', 'save_directory_changed', 'save_exact_result_binding', 'save_expired', 'save_invocation_scope', 'save_no_accepted_result', 'save_no_current_consent', 'save_no_current_policy', 'save_owned_target', 'save_policy_withdrawn', 'save_readback_mismatch', 'save_root_refused', 'save_standalone_effect_host_required', 'save_unknown_or_missing_receipt', 'save_unsafe_target', 'saved_actual_combine', 'saved_actual_semantic_witness_consumption', 'saved_actual_work_output', 'saved_comparison_binding', 'saved_content_binding', 'saved_control_purpose', 'saved_current_sources', 'saved_distinct_actual_role_producers', 'saved_memory_projection_binding', 'saved_memory_work_contract_binding', 'saved_memory_work_input_binding', 'saved_memory_work_output_binding', 'saved_outcome_closed_fields', 'saved_outcome_hash', 'saved_outcome_shape', 'saved_proposal_hash', 'saved_result_id', 'saved_root_claim_binding', 'saved_root_material_hash', 'saved_root_owner', 'saved_root_provenance_hash', 'saved_root_public_identity_reconstruction', 'saved_root_selected_candidate', 'saved_semantic_business_witness', 'saved_semantic_family_public_reconstruction', 'saved_semantic_family_scope', 'saved_semantic_family_shape', 'saved_semantic_memory_origin', 'saved_semantic_origin_shape', 'saved_semantic_pipeline_scope', 'saved_semantic_pipeline_shape', 'saved_semantic_producer_bindings', 'saved_semantic_qualification', 'saved_time_shape', 'saved_work_abi', 'saved_work_artifact_hash', 'saved_work_closed_fields', 'saved_work_producer_profile', 'semantic_accepted_product_or_provenance_changed', 'semantic_actual_architect_missing', 'semantic_actual_predecessor_missing', 'semantic_complete_pipeline_required', 'semantic_control_purpose_changed', 'semantic_current_family_missing_or_foreign', 'semantic_delta_retained_selection', 'semantic_distinct_actual_role_observations', 'semantic_exact_context_schema', 'semantic_exact_wire_body', 'semantic_family_actual_predecessor', 'semantic_family_current_source_policy', 'semantic_family_native_binding_changed', 'semantic_family_projection_changed', 'semantic_family_relational_bsep', 'semantic_family_root_refused', 'semantic_family_root_source_binding', 'semantic_family_scope', 'semantic_family_time', 'semantic_observation_replaced_or_mutated', 'semantic_owned_transport_required', 'semantic_pending_request', 'semantic_pipeline_provenance', 'semantic_policy_changed', 'semantic_predecessor_mutated', 'semantic_predecessor_origin_changed', 'semantic_projection_byte_budget', 'semantic_refusal_closed_code_or_role', 'semantic_refusal_projection_shape', 'semantic_run_time', 'semantic_runtime_request_origin', 'semantic_scope_shape', 'semantic_source_changed', 'semantic_stage_order', 'semantic_task_current_sources', 'semantic_task_pipeline_changed', 'semantic_time_reversal', 'semantic_transaction_scope', 'semantic_transport_emission_origin', 'semantic_transport_observation_binding', 'semantic_transport_receipt_missing', 'source_bytes_hash', 'source_ids_distinct', 'source_ids_unique', 'source_logical_id', 'source_raw_hash', 'source_revision', 'source_revision_text', 'source_shape', 'task_already_started', 'task_continuation_profile', 'task_goal_criterion', 'task_intake_current_mismatch', 'task_owned_evidence', 'task_owned_output', 'two_sources_required', 'warm_cache_miss_before_provider', 'work_intake_changed', 'work_not_completed', 'work_outcome_invalid'))
CLOSED_RETURN_REFUSAL_CODES = frozenset(('return_B_exact_source_required', 'return_actual_delivered_pair_readback', 'return_actual_early_failure_required', 'return_actual_live_result_and_policy_close_observation_required', 'return_auth_accounting_closed_row', 'return_auth_actual_continuation_required', 'return_auth_actual_phase_binding', 'return_auth_actual_terminal_checkpoint_changed', 'return_auth_delta_A_identity_binding', 'return_auth_delta_code_identity_changed', 'return_auth_delta_code_pin_closure', 'return_auth_delta_exact_passage_paths', 'return_auth_delta_exact_source_required', 'return_auth_delta_finite_source_selection', 'return_auth_delta_independent_packaging_review_required', 'return_auth_delta_prior_source_pair_identity', 'return_auth_delta_source_selector_not_accepted', 'return_auth_ledger_or_quota_changed', 'return_auth_only_failure_current_source_phase_binding', 'return_auth_only_failure_phase', 'return_auth_only_failure_selector_not_accepted', 'return_auth_only_no_transport_directory', 'return_auth_only_source_closure', 'return_auth_only_source_identity_changed', 'return_auth_operation_id', 'return_auth_public_http_accounting_required', 'return_auth_quota_directory', 'return_auth_success_current_source_terminal_required', 'return_auth_success_selector_not_accepted', 'return_auth_verified_public_receipt_required', 'return_auth_writer_closure', 'return_auth_writer_identity_changed', 'return_auth_writer_not_accepted', 'return_catalog_observation_schema', 'return_checksum_created_before_publish', 'return_checksum_final_must_be_absent', 'return_code_identity_changed', 'return_complete_safe_tar_inventory', 'return_completed_prior_reference_basis', 'return_current_state_or_reference_refused', 'return_delivery_receipt_binding', 'return_destination_required', 'return_duplicate_archive_path', 'return_early_failure_selector_not_accepted', 'return_engineering_actual_live_manifest_basis', 'return_engineering_exact_live_link', 'return_engineering_independent_behavior_result_binding', 'return_engineering_live_delivered_pair_readback', 'return_engineering_live_delivery_receipt_binding', 'return_engineering_live_pair_identity', 'return_engineering_live_review_status_binding', 'return_engineering_owned_live_archive', 'return_exact_applied_recovery_basis', 'return_exact_owned_live_directory', 'return_exact_owner_continuation_required', 'return_exact_project_required', 'return_exact_public_recovery_receipt_path', 'return_exact_source_snapshot_and_code_closure', 'return_failure_continuation_identity', 'return_failure_writer_closure', 'return_failure_writer_identity_changed', 'return_failure_writer_not_accepted', 'return_file_changed_during_read', 'return_first_live_aggregate_source_changed', 'return_first_live_current_aggregate_binding', 'return_first_live_focused_evidence_changed', 'return_first_live_focused_source_certificate_binding', 'return_first_live_focused_source_changed', 'return_first_live_focused_supplement_changed', 'return_first_live_historical_basis_changed', 'return_first_live_runtime_basis_binding', 'return_first_live_runtime_identity_changed', 'return_future_selector_review_required', 'return_handoff_finite_selector', 'return_handoff_identity', 'return_handoff_operation_binding', 'return_historical_transport_witness_changed', 'return_independent_packaging_review_required', 'return_independent_review_required', 'return_manifest_exact_inventory', 'return_no_arbitrary_mode_or_paths', 'return_observation_json_depth', 'return_outside_owned_root', 'return_owned_public_relative_path', 'return_owned_root_identity', 'return_owner_operation_id', 'return_owner_phase_binding', 'return_payload_full_readback', 'return_payload_type', 'return_preflight_dispatch_ledger_changed_or_unknown', 'return_prior_archive_outer_identity', 'return_prior_public_recovery_receipt_binding', 'return_prior_public_recovery_receipt_path', 'return_prior_reference_identity', 'return_prior_reference_review_identity', 'return_private_fields_refused', 'return_public_file_type', 'return_public_ledger_closed_shape', 'return_public_ledger_schema', 'return_public_local_recovery_schema', 'return_public_recovery_history_shape', 'return_public_symlink_refused', 'return_reference_baseline_binding', 'return_reference_current_runtime_review_required', 'return_reference_exact_public_pin_path', 'return_reference_executable_closure_required', 'return_reference_normative_review_binding', 'return_reference_regular_single_link_bound', 'return_reference_runtime_pin_map', 'return_reference_selected_bytes_changed', 'return_reference_unselected_path', 'return_regular_single_link_bound', 'return_resolved_outside_owned_root', 'return_reviewed_transition_required', 'return_runtime_closure_path_class', 'return_runtime_exact_mixed_closure', 'return_selected_directory_required', 'return_semantic_activation_binding', 'return_semantic_continuation_selector', 'return_semantic_entered_binding', 'return_semantic_historical_basis_changed', 'return_semantic_operation_references_required', 'return_semantic_proposal_binding', 'return_semantic_reference_shape', 'return_setup_phase_binding', 'return_source_inventory_changed', 'return_source_prompt_archive_path', 'return_source_prompt_identity', 'return_source_prompt_member', 'return_source_ready_honest_pending_required', 'return_source_snapshot_identity', 'return_symlink_path', 'return_unknown_guard'))
CLOSED_MEMORY_REFUSAL_CODES = frozenset(('memory_accepted_source_binding', 'memory_accepted_task_binding', 'memory_accepted_time_binding', 'memory_context_shape', 'memory_current_root_refused', 'memory_finite_time', 'memory_logical_path_invalid', 'memory_origin_clock', 'memory_origin_identity', 'memory_origin_shape', 'memory_original_root_provenance', 'memory_outcome_validator_must_return_verified_plain', 'memory_owned_path_symlink', 'memory_path_outside_owned_directory', 'memory_payload_canonical_binding', 'memory_payload_depth_limit', 'memory_payload_identity_conflict', 'memory_payload_size_limit', 'memory_record_count_limit', 'memory_record_file_boundary', 'memory_record_id_invalid', 'memory_record_size_limit', 'memory_root_callback_shape', 'memory_root_exact_claim_binding', 'memory_root_input_invalid', 'memory_root_kernel_invalid', 'memory_root_owner_or_transaction', 'memory_root_result_invalid', 'memory_source_duplicate', 'memory_source_hash', 'memory_source_identity', 'memory_source_shape', 'memory_two_sources_required', 'memory_work_business_comparison', 'memory_work_candidate_binding', 'memory_work_current_time', 'memory_work_projection_budget', 'memory_work_projection_origin', 'memory_work_projection_shape', 'memory_work_sources', 'memory_work_sources_budget', 'memory_write_requires_causal_v02', 'memory_writeback_expired', 'memory_writeback_payload_readback', 'memory_writeback_record_readback', 'saved_memory_projection_binding', 'saved_memory_work_contract_binding', 'saved_memory_work_input_binding', 'saved_memory_work_output_binding', 'saved_outcome_budget', 'saved_outcome_depth_limit'))
CLOSED_MEMORY_WRITEBACK_REFUSAL_CODES = frozenset(('memory_accepted_source_binding', 'memory_accepted_task_binding', 'memory_accepted_time_binding', 'memory_context_shape', 'memory_current_root_refused', 'memory_finite_time', 'memory_logical_path_invalid', 'memory_original_root_provenance', 'memory_outcome_validator_must_return_verified_plain', 'memory_owned_path_symlink', 'memory_path_outside_owned_directory', 'memory_payload_canonical_binding', 'memory_payload_identity_conflict', 'memory_record_count_limit', 'memory_record_file_boundary', 'memory_record_id_invalid', 'memory_record_size_limit', 'memory_root_callback_shape', 'memory_root_exact_claim_binding', 'memory_root_input_invalid', 'memory_root_kernel_invalid', 'memory_root_owner_or_transaction', 'memory_root_result_invalid', 'memory_source_duplicate', 'memory_source_hash', 'memory_source_identity', 'memory_source_shape', 'memory_two_sources_required', 'memory_write_requires_causal_v02', 'memory_writeback_expired', 'memory_writeback_payload_readback', 'memory_writeback_record_readback'))


def closed_guard_projection(error):
    code=getattr(error,'code',None)
    if code is None and isinstance(error,ValueError) and len(error.args)==1:
        code=error.args[0]
    if type(code) is not str:return None
    if code in CLOSED_RETURN_REFUSAL_CODES:
        stage=getattr(error,'stage','RETURN_PREBUILD')
        if stage not in ('RETURN_PREBUILD','RETURN_LOCAL_PAIR','RETURN_DELIVERY','RETURN_CHECKPOINT'):
            stage='RETURN_PREBUILD'
    elif code in CLOSED_MEMORY_REFUSAL_CODES:
        stage=getattr(error,'stage',None)
        if stage not in ('ACCEPTED_RESULT_PREPUBLICATION','MEMORY_WRITEBACK_VALIDATION','MEMORY_CONSUMER_VALIDATION'):
            stage=('MEMORY_WRITEBACK_VALIDATION' if code in CLOSED_MEMORY_WRITEBACK_REFUSAL_CODES
                or code.startswith(('memory_payload_','saved_outcome_'))
                else 'MEMORY_CONSUMER_VALIDATION')
    else:return None
    return {'code':code,'stage':stage,'raw_error_recorded':False}


def error_projection(error):
    def attribute(value, name, default=None):
        try:return getattr(value,name,default)
        except BaseException:return default
    code='SANITIZED_OPERATION_FAILURE'
    if type(error) is ValueError and len(error.args)==1 and type(error.args[0]) is str:
        if error.args[0] in KNOWN_OWNED_VALUE_ERROR_CODES:code=error.args[0]
    elif type(error).__name__ in ('PlanAuthError','PlanTransportError'):
        typed_code=attribute(error,'code',None)
        if type(typed_code) is str and typed_code in KNOWN_OWNED_VALUE_ERROR_CODES:code=typed_code
    error_type=type(error).__name__
    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',error_type) is None:error_type='Exception'
    result={'type':error_type,'code':code,'raw_error_recorded':False}
    try:closed=closed_guard_projection(error)
    except BaseException:closed=None
    if closed is not None:result.update(closed)
    operation=attribute(error,'operation',None)
    if type(operation) is str and operation in ('grant','jwt','callback','store','discovery','jwks',
            'registration','authorize','exchange','scopes','refresh'):result['operation']=operation
    verification_stage=attribute(error,'verification_stage',None)
    if isinstance(verification_stage,str) and verification_stage in ('DEPENDENCY','HEADER','KEY_SET','KEY_IDENTITY','KEY_PROFILE',
                              'KEY_MATERIAL','SIGNED_CLAIMS','SUBJECT','NONCE'):
        result['verification_stage']=verification_stage
    status=attribute(error,'http_status',None)
    if type(status) is int and 100<=status<=599:result['http_status']=status
    # Full safe HTTP/stream receipts remain in their normal transport witnesses.
    # The shared module is executable only after the exact current A closure.
    try:
        admitted=bootstrap()
        relative='app/stage04_diagnostics.py'
        expected=admitted['pins'].get(relative)
        require(type(expected) is str and hashlib.sha256(_read(PROJECT/relative)).hexdigest()==expected,
                'owner_stage04_diagnostic_source_pin')
        from app import stage04_diagnostics as diagnostics
        require(Path(diagnostics.__file__).resolve(strict=True)==PROJECT/relative,
                'owner_stage04_diagnostic_source_pin')
        diagnostics.observe_failure(error,phase='OWNER_ENTRY',step='UNKNOWN')
        shared=diagnostics.project_error(error)
        result.update(shared)
    except Exception:
        result.setdefault('phase','UNKNOWN');result.setdefault('step','UNKNOWN')
    return result


def failure_recovery_command(error, phase_name):
    """Recommend explicit auth only for a proved auth refusal, never a model error."""
    if getattr(_ARGS,'continue_semantic',None):return None
    if phase_name == 'SETUP':
        return None if (getattr(_ARGS,'accept_remote_unknown',None)
                       or getattr(_ARGS,'continue_semantic',None)) else COMMAND + ' --resume-setup'
    code = getattr(error, 'code', None)
    operation = getattr(error, 'operation', None)
    if phase_name == 'AUTH' and (code == 'OWNER_REAUTHORIZATION_REQUIRED'
            or code == 'AUTHORIZATION_REQUIRED' and operation in ('store', 'grant', 'scopes')):
        return COMMAND + ' --recover-auth'
    return None


def owner_browser(url):
    uri=urlsplit(url)
    require(uri.scheme=='https' and uri.netloc=='auth.openai.com'
            and uri.path=='/api/accounts/authorize' and not uri.fragment,
            'owner_browser_destination')
    # The URL is never logged, persisted or hashed. This call is owner-only.
    return subprocess.run(['/usr/bin/open',url],stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,timeout=15).returncode==0


def _lock(inherited):
    path=PASSAGE/'owner_start.lock'
    require(not path.is_symlink(),'owner_lock_symlink')
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600) if inherited is None else inherited
    info=os.fstat(fd);actual=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.getuid()
            and (info.st_dev,info.st_ino)==(actual.st_dev,actual.st_ino),'owner_lock_identity')
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise ValueError('owner_another_process_active') from None
    return fd


def _reexec(fd):
    from review.transport.plan_dependencies import verify_bootstrap
    verify_bootstrap(PROJECT,PROJECT/'.venv-plan')
    python=PROJECT/'.venv-plan/bin/python'
    require(python.is_file() and not python.is_symlink(),'owner_plan_python_copy')
    os.set_inheritable(fd,True)
    child=dict(os.environ)
    for key in ('PYTHONPATH','PYTHONHOME','OPENAI_API_KEY','CODEX_API_KEY','CODEX_ACCESS_TOKEN','ACCESS_TOKEN'):
        child.pop(key,None)
    child['PYTHONDONTWRITEBYTECODE']='1'
    args=[str(python),'-I','-S','-B',str(PROJECT/'review/transport/radik_owner_start.py'), '--_lock-fd',str(fd)]
    if _ARGS.recover_auth:args.append('--recover-auth')
    if _ARGS.console:args.append('--console')
    if _ARGS.stage04_acceptance:args.append('--stage04-acceptance')
    if _ARGS.stage04_native_scenario:args.append('--stage04-native-scenario')
    if _ARGS.continue_console_stream:args.extend(('--continue-console-stream',_ARGS.continue_console_stream))
    if _ARGS.accept_remote_unknown:args.extend(('--accept-remote-unknown',_ARGS.accept_remote_unknown))
    if _ARGS.continue_semantic:args.extend(('--continue-semantic',_ARGS.continue_semantic))
    os.execve(python,args,child)


def reporting_observation(package=None, *, started=False, error=None):
    """Publication progress is independent of live start and primary outcome."""
    if package is not None:
        require(type(package) is dict and package.get('report_status') in
                ('LOCAL_PAIR_VERIFIED','DELIVERY_VERIFIED','DELIVERY_UNCONFIRMED'),
                'owner_reporting_verified_pair_state')
        status=package['report_status']
    else:
        guard=closed_guard_projection(error) if error is not None else None
        if not started:status='NOT_STARTED'
        elif guard is not None and guard['stage']=='RETURN_PREBUILD':status='PREBUILD_REFUSED'
        elif guard is not None and guard['stage']=='RETURN_LOCAL_PAIR':status='LOCAL_BUILD_UNCONFIRMED'
        else:status='UNCONFIRMED'
    value={'schema':'radik.owner_reporting_progress.v01','status':status,
        'return_pair':package,'automatic_repack':False}
    if error is not None:
        value['secondary_failure']=error_projection(error)
        value['failure_stage']=value['secondary_failure'].get('stage','UNKNOWN')
    return value


def owner_failure_observation(*, primary_live_failure, secondary_failure, action_policy_closed,
                              package=None, report_started=False):
    """Keep the first live failure, closure, and later reporting evidence separate."""
    return {'primary_live_failure':primary_live_failure,
        'secondary_reporting_failure':error_projection(secondary_failure),
        'action_policy_closed':action_policy_closed,
        'reporting':reporting_observation(package,started=report_started,error=secondary_failure)}


def _continue_review(report_path, transport_directory, package=None):
    report=json.loads(_read(PROJECT/report_path,64 * 1024 * 1024))
    complete=report.get('status')=='OBSERVATIONS_COMPLETE_INDEPENDENT_LIVE_INTERPRETATION_REQUIRED' and report.get('action_policy_closed') is True
    value={'schema':'radik.direct_plan_continuation.v01',
        'next_operation':'independent_behavior_review' if complete else 'review_actual_failure_no_retry',
        'reviewer':'/root/semantic_continuation_reviewer','actual_result_path':report_path,
        'transport_observations':transport_directory,'return_pair':package,
        'reporting':reporting_observation(package),
        'primary_live_failure':report.get('error'),
        'action_policy_closed':report.get('action_policy_closed'),
        'no_repeat':'Do not rerun authorization/model/exam/SAVE; counted or UNKNOWN attempts and quota never reset.',
        'after_PASS':'Issue independent BEHAVIOR_ACCEPTED with actual evidence pins, separately admit the no-effect owner console, then provide its command.',
        'after_FAIL':'Repair only the proved affected source delta; preserve actual ledger/quota; no automatic effect replay.'}
    _write_continuation(value)


def _write_continuation(value):
    target=PASSAGE/'continuation.json'
    temporary=target.with_suffix('.pending')
    require(not target.is_symlink() and not temporary.exists(),'owner_continuation_pending_or_symlink')
    with temporary.open('xb') as stream:
        stream.write(json.dumps(value,sort_keys=True).encode()+b'\n');stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,target)
    directory=os.open(PASSAGE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)


def finish_auth_recovery(connection, accounting, *, recovery_mode):
    """Auth success and reporting are separate terminal states; never retry either."""
    require(recovery_mode in ('EXPLICIT_NEW_AUTHORIZATION','RETAINED_VERIFIED_GRANT'),
            'owner_auth_recovery_mode')
    require(type(connection) is dict and connection.get('status')=='OWN_PLAN_GRANT_VERIFIED'
            and connection.get('issuer_verified') is True
            and connection.get('issued_client_identity_binding_verified') is True,
            'owner_auth_terminal_verified_receipt_required')
    from review.transport.direct_plan_gate import source_review,digest
    accepted=source_review(PROJECT,runtime=False)
    auth_identity=digest(accepted['pins'])
    require(_CONTEXT.get('auth_source_identity_sha256')==auth_identity,
            'owner_auth_terminal_source_binding_changed')
    ledger_raw=_read(PROJECT/'state/model_turns.json');ledger=json.loads(ledger_raw)
    require(_CONTEXT.get('ledger_sha256')==hashlib.sha256(ledger_raw).hexdigest()
            and ledger.get('active_attempt_id') is None
            and _CONTEXT.get('quota_state')==quota_state(require_unspent=False),
            'owner_auth_terminal_ledger_or_quota_changed')
    if STATE.exists():
        prior_terminal=json.loads(_read(STATE))
        if (prior_terminal.get('stage')=='AUTH_RECOVERED_NO_LIVE_REPLAY'
                and prior_terminal.get('operation_id')==_CONTEXT['operation_id']):
            print('AUTH уже успешно завершён этой операцией. Сохранённые report/pair не перепаковываются; нужен разбор actual AUTH и доставки.',flush=True)
            return 0
    continuation=dict(schema='radik.auth_only_continuation.v01',
        next_operation='independent_actual_auth_result_review_no_live',
        operation_id=_CONTEXT['operation_id'],auth_source_identity_sha256=auth_identity,
        verified_connection=connection,auth_http_accounting=accounting,
        ledger_sha256=hashlib.sha256(ledger_raw).hexdigest(),counted_attempts=len(ledger['attempts']),
        remaining_attempts=16-len(ledger['attempts']),active_attempt=None,
        quota_state=_CONTEXT['quota_state'],auth='OWN_PLAN_GRANT_VERIFIED',
        catalog_model_runtime_Work_E_SAVE_C='NOT_STARTED_BY_AUTH_RECOVERY',
        live_admission='NOT_GRANTED',console='NOT_ADMITTED',automatic_retry=False,
        no_repeat='Review this actual auth result. Do not repeat authorization or begin catalog/model/live/SAVE automatically.')
    package=None;reporting={'status':'NOT_ATTEMPTED'}
    # All errors below concern terminal recording/publication, not grant failure.
    try:
        phase('AUTH_RECOVERED')
        public_observation('owner_auth_observations.json',accounting)
        state=checkpoint('AUTH_RECOVERED_NO_LIVE_REPLAY',connection=connection,
            auth_status='OWN_PLAN_GRANT_VERIFIED',recovery_mode=recovery_mode,
            reporting_status='AUTH_REPORT_PENDING',actual_result_path=None)
        _write_continuation(continuation)
        from review.transport.owner_failure_report import report_auth_success
        package=report_auth_success(state)
        reporting={'status':'VERIFIED_LOCAL_AUTH_RETURN','return_pair':package,
                   'delivery':package.get('delivery',{'status':'UNKNOWN'})}
    except Exception:
        reporting={'status':'AUTH_REPORT_NOT_COMPLETED_NO_REPACK',
                   'delivery':{'status':'NOT_CONFIRMED'},'auth_status':'OWN_PLAN_GRANT_VERIFIED',
                   'raw_error_recorded':False}
    try:
        checkpoint('AUTH_RECOVERED_NO_LIVE_REPLAY',connection=connection,
            auth_status='OWN_PLAN_GRANT_VERIFIED',recovery_mode=recovery_mode,
            reporting_status=reporting['status'],auth_return=package,report_delivery=reporting,
            actual_result_path=None)
        _write_continuation(dict(continuation,auth_return=package,report_delivery=reporting))
    except Exception:
        print('AUTH прошёл; public report checkpoint не завершён. Не повторяйте вход или упаковку; нужен разбор сохранённой пары и состояния.',flush=True)
    print('AUTH прошёл: отдельное разрешение Radik проверено. Catalog/model/live/Work/E/SAVE/C не запускались этой recovery.',flush=True)
    if package is not None:
        archive_path=reporting['delivery'].get('archive',package['archive_path'])
        checksum_path=reporting['delivery'].get('checksum',package['checksum_path'])
        print('AUTH-only отчёт: '+reporting['delivery']['status']+'. Архив: '+archive_path+
              '. Checksum: '+checksum_path+'.',flush=True)
    else:
        print('AUTH-only отчёт/доставка не завершены; успешный grant сохранён. Вход и repack автоматически не повторяются.',flush=True)
    print('Следующий шаг: передайте actual AUTH report/continuation в Codex для проверки. Live и console пока не допущены.',flush=True)
    return 0


def quota_state(*,require_unspent=True):
    path=PROJECT/'state/live_save_quota'
    require(not path.is_symlink(),'owner_quota_symlink')
    if not path.exists():return {'state':'NOT_STARTED'}
    require(path.is_dir(),'owner_prior_save_state_no_reset')
    if any(path.iterdir()):
        require(not require_unspent,'owner_prior_save_state_no_reset')
        return {'state':'KNOWN_USED_NOT_RESET'}
    return {'state':'KNOWN_EMPTY'}


def phase(name):
    require(name in ('SETUP','SETUP_READY','AUTH','AUTH_RECOVERED','CATALOG','CONSOLE','LIVE'),
            'owner_phase_closed_name')
    _CONTEXT['command_phase']=name
    if name!='SETUP':_CONTEXT['command_point']='PHASE_BOUNDARY'
    _CONTEXT['auth_this_operation']=_CONTEXT.get('auth_this_operation',False) or name in ('AUTH','AUTH_RECOVERED','CATALOG','LIVE')
    _CONTEXT['live_this_operation']=_CONTEXT.get('live_this_operation',False) or name=='LIVE'
    _CONTEXT['auth_ever_started']=_CONTEXT.get('auth_ever_started',False) or name in ('AUTH','AUTH_RECOVERED','CATALOG','LIVE')
    _CONTEXT['live_ever_started']=_CONTEXT.get('live_ever_started',False) or name=='LIVE'
    current=dict(_CONTEXT,phase=name,auth_started=_CONTEXT['auth_ever_started'],
                 live_started=_CONTEXT['live_ever_started'],
                 legacy_started_fields_scope='CUMULATIVE_HISTORY_NOT_CURRENT_OPERATION',
                 runtime='NOT_ADMITTED',console='NOT_ADMITTED')
    public_observation('owner_phase_journal.json',current)


def require_setup_resume(prior):
    journal=json.loads(_read(PASSAGE/'owner_phase_journal.json'))
    require(prior.get('stage') in ('STOPPED_BEFORE_LIVE','DEPENDENCY_SETUP_OWNER_STARTED')
            and journal.get('phase') in ('SETUP','SETUP_READY') and journal.get('auth_started') is False
            and journal.get('live_started') is False
            and all(prior.get(key)==journal.get(key) for key in ('operation_id','setup_binding','source_identity_sha256','ledger_sha256','quota_state'))
            and journal.get('source_identity_sha256')==hashlib.sha256(json.dumps(bootstrap()['pins'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
            and journal.get('ledger_sha256')==hashlib.sha256(_read(PROJECT/'state/model_turns.json')).hexdigest()
            and journal.get('quota_state')==quota_state(), 'owner_resume_setup_phase_or_ledger_refused')
    if journal['phase']=='SETUP_READY':
        setup=json.loads(_read(SETUP_PASSAGE/'setup_journal.json'))
        require(setup.get('stage')=='READY' and setup.get('phase_binding')==journal['setup_binding'],'owner_resume_setup_ready_journal_required')
    ledger=json.loads(_read(PROJECT/'state/model_turns.json'))
    require(ledger['active_attempt_id'] is None,'owner_resume_setup_after_unknown_refused')
    return journal


def require_ready_checkpoint(prior, admitted):
    """An accepted installation transition preserves one exact failed operation."""
    if prior.get('stage')!='DEPENDENCIES_READY_OWNER_AUTHORIZATION_PENDING':return
    journal=json.loads(_read(PASSAGE/'owner_phase_journal.json'))
    identity=hashlib.sha256(json.dumps(admitted['pins'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
    ledger_raw=_read(PROJECT/'state/model_turns.json');ledger=json.loads(ledger_raw)
    require(journal.get('phase')=='SETUP_READY'
            and all(prior.get(key)==journal.get(key) for key in (
                'operation_id','setup_binding','source_identity_sha256','ledger_sha256','quota_state',
                'auth_ever_started','live_ever_started'))
            and prior.get('source_identity_sha256')==identity
            and prior.get('ledger_sha256')==hashlib.sha256(ledger_raw).hexdigest()
            and ledger['active_attempt_id'] is None and prior.get('quota_state')==quota_state()
            and prior.get('auth_ever_started') is False and prior.get('live_ever_started') is False
            and journal.get('auth_started') is False and journal.get('live_started') is False,
            'owner_ready_checkpoint_source_phase_or_ledger_changed')
    from review.transport.plan_dependencies import setup_identity,verify_distribution_files
    setup_raw=_read(SETUP_PASSAGE/'setup_journal.json');setup=json.loads(setup_raw)
    require(setup.get('stage')=='READY'
            and setup.get('status')=='DEPENDENCIES_READY_OWNER_AUTHORIZATION_PENDING'
            and setup.get('phase_binding')==prior['setup_binding']
            and setup.get('identity')==setup_identity(PROJECT)
            and setup.get('auth_started') is False,'owner_ready_setup_identity_changed')
    if 'carryforward_review_sha256' not in prior:return
    relative='review/python_identity_fix_passage/carryforward_review.json'
    raw=_read(PROJECT/relative);review=json.loads(raw)
    require(hashlib.sha256(raw).hexdigest()==prior['carryforward_review_sha256']
            and review.get('reviewer')=='/root/app_examiner'
            and review.get('status')=='ACCEPTED_EXACT_PYTHON_IDENTITY_READY_CARRYFORWARD'
            and review.get('scope')=='INSTALLED_ENVIRONMENT_ONLY_NO_AUTH_LIVE_EFFECTS',
            'owner_ready_carryforward_independent_review_required')
    expected=dict(review['new_owner_checkpoint'],carryforward_review_sha256=hashlib.sha256(raw).hexdigest())
    require(prior==expected and journal==review['new_phase_journal']
            and hashlib.sha256(setup_raw).hexdigest()==review['new_setup_journal_sha256']
            and identity==review['new_source_identity_sha256'],
            'owner_ready_carryforward_current_binding_changed')
    for relative,expected_sha in review['historical_pins'].items():
        require(relative.startswith('review/python_identity_fix_passage/before/')
                or relative==review['failed_archive_path']
                or relative==review['failed_archive_path']+'.sha256',
                'owner_ready_carryforward_historical_selector')
        require(hashlib.sha256(_read(PROJECT/relative)).hexdigest()==expected_sha,
                'owner_ready_carryforward_historical_evidence_changed')
    installed=verify_distribution_files(PROJECT,PROJECT/'.venv-plan')
    require(installed['installed_identity_sha256']==review['installed_identity_sha256']
            and installed['lock_sha256']==review['lock_sha256'],
            'owner_ready_carryforward_installed_identity_changed')


def unknown_recovery_material(expected_sha256, admitted):
    """Read an independently reviewed proposal; never apply it on default entry."""
    require(type(expected_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_sha256),
            'owner_unknown_exact_contract_hash_required')
    raw=_read(SOURCE_PASSAGE/'recovery_contract.json')
    review_raw=_read(SOURCE_PASSAGE/'recovery_source_review.json')
    review=json.loads(review_raw);contract=json.loads(raw)
    require(hashlib.sha256(raw).hexdigest()==expected_sha256==review.get('contract_sha256')
            and review.get('reviewer')=='/root/semantic_continuation_reviewer'
            and review.get('status')=='ACCEPTED_PREPARED_LOCAL_CLOSED_REMOTE_UNKNOWN_CONTINUATION'
            and review.get('scope')=='EXPLICIT_OWNER_APPLY_ONLY_NO_CURRENT_MUTATION_OR_DISPATCH',
            'owner_unknown_independent_contract_review_required')
    from review.transport.direct_plan_gate import source_review,mechanical_review,digest
    runtime=source_review(PROJECT,runtime=True)
    mechanical_review(PROJECT,runtime)
    identity=digest(runtime['pins'])
    require(review.get('current_source_identity_sha256')==identity
            and contract.get('current_source_identity_sha256')==identity
            and review.get('code_pins')==runtime['pins']
            and review.get('auth_source_identity_sha256')==digest(admitted['pins']),
            'owner_unknown_current_source_binding')
    failure_raw=_read(SOURCE_PASSAGE/'actual_failure_review.json')
    failure=json.loads(failure_raw)
    require(hashlib.sha256(failure_raw).hexdigest()==review.get('actual_failure_review_sha256')
            and failure.get('reviewer')=='/root/semantic_continuation_reviewer'
            and failure.get('status')=='ACCEPTED_ACTUAL_USAGE_VALIDATION_FAILURE_EVIDENCE'
            and failure.get('scope')=='ACTUAL210111_PUBLIC_USAGE_FAILURE_ONLY'
            and failure.get('operation_id')==contract.get('old_owner_operation_id')
            and failure.get('response_id')==contract.get('local_cleanup',{}).get('response_id'),
            'owner_unknown_actual_failure_binding')
    require(contract.get('owner_acceptance')=='EXPLICIT_ACCEPT_REMOTE_UNKNOWN_REQUIRED'
            and contract.get('disposition')=='LOCAL_CLOSED_REMOTE_OUTCOME_UNKNOWN'
            and contract.get('occupancy_contract')==
                'ONE_MANAGED_LOCAL_REQUEST_WITH_ACKNOWLEDGED_REMOTE_UNKNOWN',
            'owner_unknown_limited_amendment_required')
    for ref in contract['evidence_refs'].values():
        require(hashlib.sha256(_read(PROJECT/ref['path'])).hexdigest()==ref['sha256'],
                'owner_unknown_immutable_evidence_changed')
    require(quota_state()==contract['no_effect']['quota_state'],
            'owner_unknown_quota_changed')
    effect=review['effect_permission']
    old_policy_raw=_read(PROJECT/effect['old_policy_path'])
    old_policy=json.loads(old_policy_raw)
    require(hashlib.sha256(old_policy_raw).hexdigest()==effect['old_policy_sha256']
            and old_policy.get('save_allowed') is False
            and old_policy.get('valid_to')==effect['maximum_valid_to']
            and type(effect['maximum_valid_to']) is int
            and effect['maximum_valid_to']>int(datetime.now(timezone.utc).timestamp())
            and effect.get('renew_old_interval') is False
            and effect.get('fresh_Root_and_target_required') is True,
            'owner_unknown_effect_permission_expired_or_changed')
    handoff=Path('/Users/admin/Downloads/RADIK_BOOTSTRAP_AND_LIVE_EXAM_RU.txt')
    require(hashlib.sha256(_read(handoff)).hexdigest()==effect['handoff_sha256']==
            '2af8077da9aeda9b31b4b3cb61cf9e584b801f9fb1da85ba9e75e41ba28e73f1',
            'owner_unknown_original_effect_handoff_changed')
    return raw,contract,review,hashlib.sha256(review_raw).hexdigest()


def prepare_unknown_owner_continuation(prior, admitted, expected_sha256):
    """Under the owner lock, check the exact blocked checkpoint without writes."""
    raw,contract,review,review_sha=unknown_recovery_material(expected_sha256,admitted)
    failure=json.loads(_read(SOURCE_PASSAGE/'actual_failure_review.json'))
    require(failure.get('current_public_state_pins')==review['old_public_state_pins']
            and failure.get('active_attempt_id')==contract['attempt_id']
            and failure.get('operation_id')==contract['old_owner_operation_id']
            and failure.get('ledger_version') in ('radik.turn_ledger.v02','radik.turn_ledger.v03')
            and failure.get('business_Work_E_SAVE_count')==0,
            'owner_unknown_exact_current_failure_review_required')
    require(prior.get('stage')=='LIVE_STOPPED_REVIEW_REQUIRED'
            and prior.get('operation_id')==contract['old_owner_operation_id']
            and prior.get('source_identity_sha256')==contract['old_source_identity_sha256']
            and prior.get('action_policy_closed') is True,
            'owner_unknown_exact_stopped_checkpoint_required')
    for relative,expected in review['old_public_state_pins'].items():
        require(hashlib.sha256(_read(PROJECT/relative)).hexdigest()==expected,
                'owner_unknown_checkpoint_or_ledger_changed')
    ledger_raw=_read(PROJECT/'state/model_turns.json');ledger=json.loads(ledger_raw)
    require(hashlib.sha256(ledger_raw).hexdigest()==contract['ledger_before_file_sha256']
            and ledger['active_attempt_id']==contract['attempt_id']
            and len(ledger['attempts'])==contract['counted_attempts']
            and len(ledger['attempts'])+6<=16,
            'owner_unknown_exact_budget_required')
    return {'unknown_recovery_contract_sha256':expected_sha256,
            'unknown_recovery_review_sha256':review_sha,
            'unknown_previous_owner_operation_id':contract['old_owner_operation_id'],
            'unknown_effect_valid_to':review['effect_permission']['maximum_valid_to']}


def apply_unknown_owner_continuation(admitted, expected_sha256):
    """Only the explicit selected owner operation may durably release local occupancy."""
    raw,contract,review,review_sha=unknown_recovery_material(expected_sha256,admitted)
    require(_CONTEXT.get('unknown_recovery_contract_sha256')==expected_sha256
            and _CONTEXT.get('unknown_recovery_review_sha256')==review_sha
            and _CONTEXT.get('unknown_previous_owner_operation_id')==contract['old_owner_operation_id']
            and _CONTEXT.get('operation_id')!=contract['old_owner_operation_id'],
            'owner_unknown_reexec_context_binding')
    from app.budget import TurnBudget
    budget=TurnBudget(PROJECT/'state/model_turns.json',PROJECT/'config/model_policy.json')
    receipt=budget.apply_local_closed_recovery(raw,expected_contract_sha256=expected_sha256,
        current_source_identity_sha256=contract['current_source_identity_sha256'],
        owner_operation_id=_CONTEXT['operation_id'],applied_at=int(datetime.now(timezone.utc).timestamp()))
    value={'schema':'radik.owner_local_unknown_recovery.v01','budget_receipt':receipt,
           'owner_operation_id':_CONTEXT['operation_id'],'contract_sha256':expected_sha256,
           'review_sha256':review_sha,'effect_permission':review['effect_permission'],
           'application':'EXPLICIT_OWNER_ACCEPTANCE_NOT_SERVER_COMPLETION_OR_CANCELLATION'}
    receipt_raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
    path=PASSAGE/('local_unknown_recovery_'+_CONTEXT['operation_id']+'.json')
    require(not path.exists() and not path.is_symlink(),'owner_unknown_receipt_already_exists')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(receipt_raw);stream.flush();os.fsync(stream.fileno())
    directory=os.open(PASSAGE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
    _CONTEXT.update(unknown_recovery_receipt_path=str(path.relative_to(PROJECT)),
                    unknown_recovery_receipt_sha256=hashlib.sha256(receipt_raw).hexdigest())
    return {'owner_operation_id':_CONTEXT['operation_id'],'contract_sha256':expected_sha256,
            'disposition':'LOCAL_CLOSED_REMOTE_OUTCOME_UNKNOWN','old_outcome':'UNKNOWN',
            'receipt_path':_CONTEXT['unknown_recovery_receipt_path'],
            'receipt_sha256':_CONTEXT['unknown_recovery_receipt_sha256'],
            'effect_permission':review['effect_permission']}


def _canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _now():
    return int(datetime.now(timezone.utc).timestamp())


def _semantic_evidence(reference):
    """Re-read a finite public reference under the owned project, without rebasing."""
    require(type(reference) is dict and set(reference)=={'path','sha256'}
            and type(reference['path']) is str and not Path(reference['path']).is_absolute()
            and reference['path'].startswith(('review/','state/'))
            and not set(Path(reference['path']).parts).intersection(('.', '..','private','Arena','arena'))
            and reference['path'].endswith('.json') and type(reference['sha256']) is str
            and re.fullmatch('[0-9a-f]{64}',reference['sha256']), 'owner_semantic_evidence_reference')
    raw=_read(PROJECT/reference['path'],64*1024*1024)
    require(hashlib.sha256(raw).hexdigest()==reference['sha256'],'owner_semantic_actual_evidence_changed')
    return json.loads(raw)


def semantic_continuation_material(expected_sha256, admitted):
    """A reviewed typed predecessor supplies evidence, never current permission."""
    require(type(expected_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_sha256),
            'owner_semantic_exact_proposal_hash_required')
    raw=_read(SOURCE_PASSAGE/'continuation_proposal.json')
    review_raw=_read(SOURCE_PASSAGE/'continuation_source_review.json')
    proposal=json.loads(raw);review=json.loads(review_raw)
    require(hashlib.sha256(raw).hexdigest()==expected_sha256==review.get('proposal_sha256')
            and raw==_canonical(proposal)+b'\n'
            and review.get('reviewer')=='/root/semantic_continuation_reviewer'
            and review.get('status')=='ACCEPTED_PREPARED_COMPLETED_SEMANTIC_CONTINUATION'
            and review.get('scope')=='EXPLICIT_SAME_OPERATION_NEW_PERMISSION_ONLY',
            'owner_semantic_independent_proposal_review_required')
    common={'schema','proposal_id','prepared_at_utc','owner_operation_id','actual',
            'current_source_identity_sha256','auth_source_identity_sha256','ledger_before',
            'old_public_state_pins','receipt_refs','occupancy_binding','old_closed_policy',
            'quota_state','effect_permission'}
    version=proposal.get('schema')
    require((version=='radik.completed_semantic_continuation_proposal.v01' and set(proposal)==common)
            or (version=='radik.completed_semantic_continuation_proposal.v02'
                and set(proposal)==common|{'predecessor'}), 'owner_semantic_proposal_shape')
    from review.transport.direct_plan_gate import source_review,digest
    runtime=source_review(PROJECT,runtime=True)
    require(proposal['current_source_identity_sha256']==review.get('current_source_identity_sha256')
            ==digest(runtime['pins']) and review.get('code_pins')==runtime['pins']
            and proposal['auth_source_identity_sha256']==review.get('auth_source_identity_sha256')
            ==digest(admitted['pins']), 'owner_semantic_current_source_binding')
    actual_raw=_read(SOURCE_PASSAGE/'actual_predecessor_review.json');actual_review=json.loads(actual_raw)
    refs=proposal['actual'].get('evidence_refs',{})
    require(hashlib.sha256(actual_raw).hexdigest()==review.get('actual_failure_review_sha256')
            and actual_review.get('reviewer')=='/root/semantic_continuation_reviewer'
            and actual_review.get('status')=='ACCEPTED_ACTUAL_PREDECESSOR_EVIDENCE'
            and actual_review.get('scope')=='BOUND_COMPLETED_OPERATION_HISTORY_ONLY_NO_RUNTIME_ADMISSION'
            and actual_review.get('operation_id')==proposal['owner_operation_id']
            and type(refs) is dict and 'result' in refs and 'run_start' in refs
            and all(actual_review.get('evidence_pins',{}).get(ref['path'])==ref['sha256']
                for ref in refs.values()), 'owner_semantic_actual_review_binding')
    for reference in refs.values():_semantic_evidence(reference)
    effect=proposal['effect_permission']
    require(effect=={'handoff_path':'/Users/admin/Downloads/RADIK_BOUNDED_MEMORY_AND_RETURN_REPAIR_RU.txt',
            'handoff_sha256':'140a0c12d07ebaa3d05b93993703367109c786f5df6283a80d2e47821cf6b73f',
            'consent_ref':'permission:owner-semantic-continuation:140a0c12d07ebaa3d05b93993703367109c786f5df6283a80d2e47821cf6b73f',
            'duration_seconds':86400,'model_attempt_recipe':{'cold':3,'warm':0,'delta':3},
            'max_new_model_requests':6,'SAVE_dispatch_attempts':1,'request_seconds':600,
            'pending_save_seconds':3600,'fresh_owned_workspace':True,
            'activation':'EXPLICIT_OWNER_COMMAND_ONLY'},'owner_semantic_permission_scope')
    handoff=Path(effect['handoff_path'])
    require(hashlib.sha256(_read(handoff)).hexdigest()==effect['handoff_sha256'],
            'owner_semantic_permission_handoff_changed')
    return proposal,hashlib.sha256(review_raw).hexdigest()


def _semantic_predecessor(proposal, ledger):
    """Normalize both reviewed shapes to one exact-prefix and completed-role rule."""
    actual=proposal['actual'];refs=actual['evidence_refs']
    result=_semantic_evidence(refs['result']);start=_semantic_evidence(refs['run_start'])
    require(result.get('schema')=='radik.fixed_first_live_exam.v01'
            and result.get('status')=='LIVE_EXAM_STOPPED_NO_AUTOMATIC_RESTART'
            and result.get('run_id')==actual['run_id']
            and result.get('action_policy_closed') is True
            and proposal['old_closed_policy']['path']==result.get('workspace','')+'/state/owned_effect_policy.json'
            and result.get('ledger_after_sha256')==hashlib.sha256(_canonical(ledger)).hexdigest()
            and start.get('source_inventory_pins_sha256')==actual['source_identity_sha256']
            and result.get('run_start_basis',{}).get('path')==refs['run_start']['path']
            and result['run_start_basis'].get('sha256')==refs['run_start']['sha256'],
            'owner_semantic_actual_run_binding')
    if proposal['schema']=='radik.completed_semantic_continuation_proposal.v01':
        require(actual.get('transport_outcome')=='COMPLETED' and actual.get('semantic_product')=='REFUSED',
                'owner_semantic_predecessor_kind')
        prefix_path=result.get('shared_budget_before_ref')
        require(type(prefix_path) is str and prefix_path.startswith('review/direct_plan_passage/live_attempts/')
                and prefix_path.endswith('/shared_budget_before.json')
                and '..' not in Path(prefix_path).parts,'owner_semantic_legacy_prefix_path')
        prefix=json.loads(_read(PROJECT/prefix_path,64*1024*1024))
        require(hashlib.sha256(_canonical(prefix)).hexdigest()==result.get('ledger_before_sha256'),
                'owner_semantic_exact_history_prefix')
        rows=[{'role':'orchestrator','attempt_id':actual['attempt_id'],
            'row_sha256':proposal['ledger_before']['latest_attempt_sha256'],
            'request_ref':refs['request'],'response_ref':refs['response']}]
    else:
        require(set(actual)=={'kind','run_id','source_identity_sha256','evidence_refs','completed_roles'}
                and actual['kind']=='COMPLETED_ROLE_SEQUENCE_PARTIAL_NATIVE',
                'owner_semantic_predecessor_kind')
        predecessor=proposal['predecessor']
        require(type(predecessor) is dict and set(predecessor)=={'ledger_prefix_ref','ledger_prefix_count',
                'ledger_prefix_canonical_sha256','owner_checkpoint_ref','closure','ancestry'},
                'owner_semantic_predecessor_shape')
        prefix=_semantic_evidence(predecessor['ledger_prefix_ref'])
        require(predecessor['ledger_prefix_ref']['path']==result.get('shared_budget_before_ref')
                and predecessor['ledger_prefix_count']==len(prefix['attempts'])
                and predecessor['ledger_prefix_canonical_sha256']==result.get('ledger_before_sha256')
                ==hashlib.sha256(_canonical(prefix)).hexdigest(), 'owner_semantic_exact_history_prefix')
        rows=actual['completed_roles']
        require(type(rows) is list and [row.get('role') for row in rows]==['orchestrator','architect','critic']
                and all(set(row)=={'role','attempt_id','row_sha256','request_ref','response_ref','transport_result_ref'}
                    for row in rows), 'owner_semantic_ordered_role_sequence')
        closure=predecessor['closure']
        require(closure=={'result_ref':refs['result'],'policy_ref':proposal['old_closed_policy']},
                'owner_semantic_actual_closure_binding')
        ancestor=predecessor['ancestry']
        require(type(ancestor) is dict and set(ancestor)=={'proposal_ref','proposal_review_ref',
                'actual_review_ref','activation_ref','entered_ref'}, 'owner_semantic_ancestry_shape')
        old_proposal=_semantic_evidence(ancestor['proposal_ref'])
        old_review=_semantic_evidence(ancestor['proposal_review_ref'])
        old_actual_review=_semantic_evidence(ancestor['actual_review_ref'])
        old_activation=_semantic_evidence(ancestor['activation_ref'])
        old_entered=_semantic_evidence(ancestor['entered_ref'])
        old_checkpoint=_semantic_evidence(predecessor['owner_checkpoint_ref'])
        require(old_proposal.get('owner_operation_id')==old_activation.get('owner_operation_id')
                ==old_checkpoint.get('operation_id')==proposal['owner_operation_id']
                and old_review.get('proposal_sha256')==old_activation.get('proposal_sha256')
                ==ancestor['proposal_ref']['sha256']==old_checkpoint.get('semantic_continuation_proposal_sha256')
                and old_activation.get('proposal_review_sha256')==ancestor['proposal_review_ref']['sha256']
                and old_review.get('actual_failure_review_sha256')==ancestor['actual_review_ref']['sha256']
                and old_review.get('reviewer')==old_actual_review.get('reviewer')=='/root/semantic_continuation_reviewer'
                and old_entered.get('semantic_continuation_activation_sha256')==ancestor['activation_ref']['sha256']
                ==old_checkpoint.get('semantic_continuation_activation_sha256')
                and old_entered.get('continuation_id')==old_activation.get('continuation_id')
                ==old_checkpoint.get('continuation_id')
                and old_activation.get('run_id')==actual['run_id']==old_checkpoint.get('continuation_run_id')
                and old_activation.get('ledger_before_sha256')==old_proposal['ledger_before']['sha256']
                ==hashlib.sha256(_canonical(prefix)).hexdigest()
                and _semantic_evidence(proposal['old_closed_policy']).get('valid_to')==old_activation.get('valid_to')
                and _semantic_evidence(proposal['old_closed_policy']).get('consent_ref')==old_activation['effect_permission']['consent_ref']
                and result.get('owner_semantic_continuation')==old_activation
                and old_checkpoint.get('actual_result_path')==refs['result']['path'],
                'owner_semantic_consumed_ancestry_binding')
        cold=_semantic_evidence(refs['cold_consumer']);cold_final=_semantic_evidence(refs['cold_final_events'])
        warm=_semantic_evidence(refs['warm_final_events'])
        require(result.get('stopped_phase')=='WARM'
                and result.get('cases',{}).get('cold',{}).get('business_Work')==3
                and result['cases']['cold'].get('actual_model_calls')==3
                and cold.get('task',{}).get('native_work_attempts')==3
                and cold_final.get('task',{}).get('stage')=='ACCEPTED_RESULT'
                and warm.get('task',{}).get('stage')=='ACCEPTED_RESULT'
                and warm['task'].get('native_work_attempts')==1 and warm.get('model_calls')==0
                and any(event.get('stage')=='ACCEPTED_RESULT' for event in warm.get('events',[])),
                'owner_semantic_native_partial_evidence_binding')
    require(len(ledger['attempts'])==len(prefix['attempts'])+len(rows)
            and ledger['attempts'][:len(prefix['attempts'])]==prefix['attempts']
            and {key:value for key,value in ledger.items() if key!='attempts'}
                =={key:value for key,value in prefix.items() if key!='attempts'},
            'owner_semantic_exact_history_prefix')
    summaries=result.get('model_attempt_ledger',{}).get('attempts',[])
    require(len(summaries)==len(rows),'owner_semantic_completed_delta_summary')
    for description,row,summary in zip(rows,ledger['attempts'][len(prefix['attempts']):],summaries):
        request=_semantic_evidence(description['request_ref']);response=_semantic_evidence(description['response_ref'])
        telemetry=row.get('telemetry',{})
        require(hashlib.sha256(_canonical(row)).hexdigest()==description['row_sha256']
                and row.get('attempt_id')==description['attempt_id']==response.get('reservation_id')==summary.get('attempt_id')
                and row.get('role')==description['role']==request.get('role')==summary.get('role')
                and row.get('owner_operation_id')==proposal['owner_operation_id']
                and row.get('run_id')==actual['run_id'] and row.get('outcome')==response.get('outcome')==summary.get('outcome')=='COMPLETED'
                and telemetry.get('terminal_observed') is True and summary.get('terminal_observed') is True
                and telemetry.get('response_id')==response.get('response_id')==summary.get('response_id')
                and row.get('context_sha256')==request.get('context_sha256')==response.get('context_sha256')==summary.get('context_sha256')
                and hashlib.sha256(_canonical(request['context'])).hexdigest()==row['context_sha256']
                and telemetry.get('wire_body_sha256')==response.get('wire_body_sha256')==summary.get('wire_body_sha256'),
                'owner_semantic_completed_attempt_binding')
        if 'transport_result_ref' in description:
            transport=_semantic_evidence(description['transport_result_ref'])
            require(transport.get('reservation_id')==row['attempt_id'] and transport.get('role')==row['role']
                    and transport.get('outcome')=='COMPLETED' and transport.get('terminal_observed') is True
                    and transport.get('response_id')==telemetry['response_id']
                    and transport.get('context_sha256')==row['context_sha256']
                    and transport.get('wire',{}).get('body_sha256')==telemetry['wire_body_sha256']
                    and hashlib.sha256(_canonical(transport['request_body'])).hexdigest()==telemetry['wire_body_sha256']
                    and transport.get('source_identity_sha256')==actual['source_identity_sha256']
                    and all(transport.get('proposal_observation',{}).get(key)==value
                        for key,value in response.items() if key!='wall_seconds')
                    and transport.get('completed_output',{}).get('lifecycle_terminal_received') is True
                    and transport['completed_output'].get('role_product_accepted') is True,
                    'owner_semantic_terminal_wire_binding')
    return result


def _semantic_current_ledger(proposal):
    """Exact historical occupancy is retained; it supplies no new effect consent."""
    ledger_raw=_read(PROJECT/'state/model_turns.json');ledger=json.loads(ledger_raw)
    before=proposal['ledger_before'];binding=proposal['occupancy_binding']
    policy=json.loads(_read(PROJECT/'config/model_policy.json'))
    require(before['path']=='state/model_turns.json'
            and hashlib.sha256(ledger_raw).hexdigest()==before['sha256']
            and type(before['counted']) is int and before['counted']==len(ledger['attempts'])
            and 1<=before['counted'] and before['counted']+proposal['effect_permission']['max_new_model_requests']<=policy['max_new_turn_attempts']
            and before['active_attempt_id'] is None and ledger['active_attempt_id'] is None
            and ledger['version']=='radik.turn_ledger.v03'
            and hashlib.sha256(_canonical(ledger['recovery_history'])).hexdigest()==before['recovery_history_sha256']
            and len(ledger['recovery_history'])==len(proposal['receipt_refs'])>=1
            and hashlib.sha256(_canonical(ledger['attempts'][-1])).hexdigest()==before['latest_attempt_sha256'],
            'owner_semantic_current_ledger_changed')
    for reference,application in zip(proposal['receipt_refs'],ledger['recovery_history']):
        receipt=_semantic_evidence(reference)
        require(receipt.get('budget_receipt',{}).get('application')==application
                and receipt.get('owner_operation_id')==application['owner_operation_id'],
                'owner_semantic_receipt_changed')
    latest=ledger['recovery_history'][-1]
    require(binding=={'owner_operation_id':proposal['owner_operation_id'],
            'recovery_contract_sha256':latest['contract_sha256'],
            'receipt_ref':proposal['receipt_refs'][-1]}
            and latest['owner_operation_id']==proposal['owner_operation_id'],
            'owner_semantic_historical_occupancy_binding')
    old_policy=_semantic_evidence(proposal['old_closed_policy'])
    require(old_policy.get('save_allowed') is False and type(old_policy.get('revision')) is int
            and old_policy['revision']>=2 and type(old_policy.get('valid_to')) is int,
            'owner_semantic_old_policy_changed')
    _semantic_predecessor(proposal,ledger)
    require(quota_state()==proposal['quota_state']=={'state':'KNOWN_EMPTY'},
            'owner_semantic_quota_changed')
    return ledger


def prepare_semantic_owner_continuation(prior, admitted, expected_sha256):
    """Bind a stopped checkpoint to exact actual closure, including lost fields."""
    proposal,review_sha=semantic_continuation_material(expected_sha256,admitted)
    for relative,expected in proposal['old_public_state_pins'].items():
        require(hashlib.sha256(_read(PROJECT/relative)).hexdigest()==expected,
                'owner_semantic_prior_state_changed')
    result=_semantic_evidence(proposal['actual']['evidence_refs']['result'])
    require(prior.get('stage')=='LIVE_STOPPED_REVIEW_REQUIRED'
            and prior.get('operation_id')==proposal['owner_operation_id']
            and prior.get('actual_result_path')==proposal['actual']['evidence_refs']['result']['path']
            and (prior.get('action_policy_closed') is True
                or 'action_policy_closed' not in prior and result.get('action_policy_closed') is True)
            and json.loads(_read(STATE))==prior,
            'owner_semantic_stopped_checkpoint_required')
    _semantic_current_ledger(proposal)
    return proposal,review_sha

def _semantic_record_path(expected_sha256, *, entered=False):
    require(type(expected_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_sha256),
            'owner_semantic_exact_proposal_hash_required')
    folder=PASSAGE/'semantic_continuations'
    require(not folder.is_symlink(),'owner_semantic_record_symlink')
    return folder/(expected_sha256+('.entered.json' if entered else '.json'))


def _semantic_write_once(path,value):
    require(path.parent.parent==PASSAGE and not path.parent.is_symlink(),
            'owner_semantic_record_path')
    path.parent.mkdir(mode=0o700,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(_canonical(value)+b'\n');stream.flush();os.fsync(stream.fileno())
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)


def semantic_continuation_status(expected_sha256):
    """A repeat reports durable identity; it cannot renew or enter the run."""
    path=_semantic_record_path(expected_sha256)
    if not path.exists():return None
    value=json.loads(_read(path))
    require(value.get('proposal_sha256')==expected_sha256,'owner_semantic_record_binding')
    return {key:value[key] for key in ('proposal_sha256','owner_operation_id','continuation_id',
            'run_id','activated_at','valid_to')}


def activate_semantic_owner_continuation(prior, admitted, expected_sha256):
    """Explicit owner entry persists the only activation before setup/reexec."""
    require(semantic_continuation_status(expected_sha256) is None,'owner_semantic_already_started_no_retry')
    proposal,review_sha=prepare_semantic_owner_continuation(prior,admitted,expected_sha256)
    activated=_now()
    value={'schema':'radik.completed_semantic_continuation_activation.v02',
        'proposal_ref':{'path':str((SOURCE_PASSAGE/'continuation_proposal.json').relative_to(PROJECT)),
            'sha256':expected_sha256},
        'proposal_review_ref':{'path':str((SOURCE_PASSAGE/'continuation_source_review.json').relative_to(PROJECT)),
            'sha256':review_sha},
        'actual_review_ref':{'path':str((SOURCE_PASSAGE/'actual_predecessor_review.json').relative_to(PROJECT)),
            'sha256':hashlib.sha256(_read(SOURCE_PASSAGE/'actual_predecessor_review.json')).hexdigest()},
        'proposal_sha256':expected_sha256,'proposal_review_sha256':review_sha,
        'owner_operation_id':proposal['owner_operation_id'],'continuation_id':str(uuid.uuid4()),
        'run_id':uuid.uuid4().hex[:12],'activated_at':activated,'valid_to':activated+86400,
        'source_identity_sha256':proposal['current_source_identity_sha256'],
        'auth_source_identity_sha256':proposal['auth_source_identity_sha256'],
        'ledger_before_sha256':proposal['ledger_before']['sha256'],
        'occupancy_binding':proposal['occupancy_binding'],'effect_permission':proposal['effect_permission'],
        'automatic_retry':False,'activation_scope':'ONE_EXPLICIT_SAME_OPERATION_FIXED_EXPERIMENT'}
    require(value['run_id']!=proposal['actual']['run_id'],'owner_semantic_fresh_run_required')
    _semantic_write_once(_semantic_record_path(expected_sha256),value)
    return value


def restore_semantic_owner_continuation(prior, admitted, expected_sha256):
    """Reexec consumes the saved activation once; it never creates a new window."""
    proposal,review_sha=semantic_continuation_material(expected_sha256,admitted)
    value=json.loads(_read(_semantic_record_path(expected_sha256)))
    expected_context={'semantic_continuation_proposal_sha256':expected_sha256,
        'semantic_continuation_activation_sha256':hashlib.sha256(_canonical(value)+b'\n').hexdigest(),
        'continuation_id':value['continuation_id'],'continuation_run_id':value['run_id'],
        'effect_activated_at':value['activated_at'],'effect_valid_to':value['valid_to']}
    require(prior.get('stage')=='DEPENDENCIES_READY_FOR_OWN_AUTH'
            and json.loads(_read(STATE))==prior
            and prior.get('operation_kind')=='EXPLICIT_COMPLETED_SEMANTIC_CONTINUATION'
            and prior.get('source_identity_sha256')==proposal['auth_source_identity_sha256']
            and prior.get('ledger_sha256')==proposal['ledger_before']['sha256']
            and prior.get('ledger_before_sha256')==proposal['ledger_before']['sha256']
            and prior.get('quota_state')==proposal['quota_state']
            and prior.get('operation_id')==proposal['owner_operation_id']==value['owner_operation_id']
            and value['schema']=='radik.completed_semantic_continuation_activation.v02'
            and value.get('proposal_ref')=={'path':str((SOURCE_PASSAGE/'continuation_proposal.json').relative_to(PROJECT)),'sha256':expected_sha256}
            and value.get('proposal_review_ref')=={'path':str((SOURCE_PASSAGE/'continuation_source_review.json').relative_to(PROJECT)),'sha256':review_sha}
            and value.get('actual_review_ref')=={'path':str((SOURCE_PASSAGE/'actual_predecessor_review.json').relative_to(PROJECT)),
                'sha256':hashlib.sha256(_read(SOURCE_PASSAGE/'actual_predecessor_review.json')).hexdigest()}
            and value['proposal_sha256']==expected_sha256 and value['proposal_review_sha256']==review_sha
            and all(prior.get(key)==item for key,item in expected_context.items())
            and value['source_identity_sha256']==proposal['current_source_identity_sha256']
            and value['auth_source_identity_sha256']==proposal['auth_source_identity_sha256']
            and value['ledger_before_sha256']==proposal['ledger_before']['sha256']
            and value['effect_permission']==proposal['effect_permission']
            and value['occupancy_binding']==proposal['occupancy_binding']
            and type(value['activated_at']) is int and type(value['valid_to']) is int
            and value['valid_to']==value['activated_at']+86400
            and value['activated_at']<=_now()<value['valid_to'],
            'owner_semantic_reexec_activation_binding')
    _semantic_current_ledger(proposal)
    _semantic_write_once(_semantic_record_path(expected_sha256,entered=True),
        {'schema':'radik.semantic_continuation_entered.v01',**expected_context,
         'owner_operation_id':value['owner_operation_id'],'entered_at':_now(),
         'automatic_retry':False})
    return value


def select_console_continuation(args):
    """Select only the explicit, reviewed console continuation command."""
    selected=args.continue_console_stream
    if selected is None:return None
    require(args.console and not args.stage04_acceptance
        and not (args.recover_auth or args.resume_setup or args.accept_remote_unknown or args.continue_semantic),
        'owner_console_continuation_command')
    raw=_read(CURRENT_SOURCE_PASSAGE/'continuation_proposal.json')
    require(type(selected) is str and hashlib.sha256(raw).hexdigest()==selected,
        'owner_console_continuation_proposal')
    return selected


def _console_continuation_predecessor(prior):
    """Bind the original checkpoint to the selected typed proposal, read-only."""
    from app.console_continuation import typed_predecessor,typed_proposal
    reference,_raw,proposal,_before,_tasks,_result=typed_proposal(PROJECT)
    checkpoint_copy=str((CURRENT_SOURCE_PASSAGE/'actual_evidence/actual_owner/owner_state.json').relative_to(PROJECT))
    original_raw=_read(PROJECT/checkpoint_copy)
    require(proposal['actual_evidence_pins'].get(checkpoint_copy)==hashlib.sha256(original_raw).hexdigest()
        and prior==json.loads(original_raw)
        and prior.get('stage')=='CONSOLE_STOPPED_REVIEW_REQUIRED',
        'owner_console_continuation_predecessor')
    return typed_predecessor(PROJECT,reference,prior)


def prepare_console_continuation_entry(prior, admitted, proposal_sha256, *,
        owner_lock_fd, owner_operation_id, run_id):
    """Shared source-admitted preparation; provider execution needs separate M.

    The real launcher calls its full execution predicate before this function.
    A source-certified isolated exam may dispatch synthetic data after this same
    preparation, without representing that exam as real launcher execution.
    """
    from review.transport.direct_plan_gate import console_source_entry,digest
    from app.console_continuation import apply_typed
    require(hashlib.sha256(_read(CURRENT_SOURCE_PASSAGE/'continuation_proposal.json')).hexdigest()==proposal_sha256,
        'owner_console_continuation_proposal')
    _console_continuation_predecessor(prior)
    source=console_source_entry(PROJECT)
    require(source['current_source_identity_sha256']==digest(source['code_pins'])
        and admitted['pins']==json.loads(_read(CURRENT_SOURCE_PASSAGE/'owner_source_review.json'))['pins'],
        'owner_console_continuation_source')
    continuation=apply_typed(PROJECT,
        dict(path=str((CURRENT_SOURCE_PASSAGE/'continuation_proposal.json').relative_to(PROJECT)),sha256=proposal_sha256),
        owner_lock_fd=owner_lock_fd,owner_operation_id=owner_operation_id,
        run_id=run_id,source_identity_sha256=source['current_source_identity_sha256'],
        auth_source_identity_sha256=digest(admitted['pins']))
    return dict(continuation=continuation,source_preparation_only=True,
        provider_or_effect_authorized=False,proposal_sha256=proposal_sha256)


def main():
    global _ARGS,_CONTEXT
    parser=argparse.ArgumentParser(description='Radik: отдельное разрешение ChatGPT plan и ограниченный live.')
    parser.add_argument('--status',action='store_true')
    parser.add_argument('--recover-auth',action='store_true')
    parser.add_argument('--resume-setup',action='store_true')
    parser.add_argument('--console',action='store_true')
    parser.add_argument('--owner-scenario',action='store_true')
    parser.add_argument('--owner-operation-started-ns',type=int)
    parser.add_argument('--owner-operation-deadline-ns',type=int)
    parser.add_argument('--owner-operation-started-utc',type=int)
    parser.add_argument('--owner-supervisor-launch')
    parser.add_argument('--owner-run-binding')
    parser.add_argument('--owner-lock-fd',type=int)
    parser.add_argument('--rehearsal-seal-sha256')
    parser.add_argument('--rehearsal-action',choices=('entry','ordinary_console','ordinary_controls','restart_read','grant_stage','grant_review'),default='entry')
    parser.add_argument('--stage04-acceptance',action='store_true',
        help='Выполнить связанный информационный сценарий через обычные обработчики консоли и сохранить actual report.')
    parser.add_argument('--stage04-native-scenario',action='store_true',
        help='Наблюдать текущие nested/U2 через обычные обработчики, сохранить отчёт и открыть обычную рабочую сессию.')
    parser.add_argument('--continue-console-stream',metavar='REVIEWED_PROPOSAL_SHA256',
        help='Явно подтвердить выбранную UNKNOWN и выполнить оставшиеся A cold → B → A memory-only → C в пределах проверенного allowance.')
    parser.add_argument('--accept-remote-unknown',metavar='REVIEWED_CONTRACT_SHA256',
        help='Явно принять unresolved remote outcome точной старой попытки и новый ограниченный local request.')
    parser.add_argument('--continue-semantic',metavar='REVIEWED_PROPOSAL_SHA256',
        help='Явно продолжить завершённую owner operation с проверенным SOURCE и новым окном эффекта.')
    parser.add_argument('--_lock-fd',type=int,help=argparse.SUPPRESS)
    _ARGS=parser.parse_args()
    require(not (_ARGS.status and (_ARGS.recover_auth or _ARGS.resume_setup or _ARGS.console
                                  or _ARGS.stage04_acceptance or _ARGS.stage04_native_scenario or _ARGS.continue_console_stream
                                  or _ARGS.accept_remote_unknown or _ARGS.continue_semantic
                                  or _ARGS._lock_fd is not None)),
            'owner_status_no_actions')
    require(not _ARGS.stage04_acceptance or _ARGS.console,'owner_stage04_requires_console')
    require(not _ARGS.stage04_native_scenario or _ARGS.console and not _ARGS.stage04_acceptance
        and not _ARGS.continue_console_stream,'owner_native_scenario_requires_normal_console')
    continuation_selected=select_console_continuation(_ARGS)
    require(sum((_ARGS.recover_auth,_ARGS.resume_setup,_ARGS.console,bool(_ARGS.accept_remote_unknown),
                 bool(_ARGS.continue_semantic)))<=1,
            'owner_one_operation_required')
    selected_profile=_profile_selection()
    if selected_profile is not None and not _ARGS.status:
        require(_ARGS.console,'owner_current_application_console_scope_required')
        admitted=bootstrap()
        return _ordinary_profile_main(_ARGS,selected_profile)
    unused_cache=PROJECT/'.venv-plan/.disabled_bytecode_cache'
    require(not unused_cache.exists() and not unused_cache.is_symlink()
            and not any(name.startswith('review.transport') for name in sys.modules),
            'owner_disabled_cache_must_be_absent')
    admitted=bootstrap()
    sys.pycache_prefix=str(unused_cache)
    sys.path.insert(0,str(PROJECT))
    if _profile_selection() is not None and not _ARGS.status:
        require(_ARGS.console,'owner_current_application_console_scope_required')
        from config.native_profile_loader import install
        install(PROJECT)
    if _ARGS.status:
        print(json.dumps(public_state(),ensure_ascii=False,indent=2));return 0
    from review.transport.direct_plan_gate import (source_review,read,digest,live_transition,
        console_transition,console_source_entry,console_execution_entry)
    from review.transport.plan_dependencies import setup_owner,verify_installed,site_directory
    fd=_lock(_ARGS._lock_fd);client=None;auth=None;live_started=False;report_path=None;auth_verified=False
    normal_operation_ref=None
    package=None;report_started=False;primary_live_failure=None;action_policy_closed=None
    try:
        prior=json.loads(_read(STATE)) if STATE.exists() else {}
        if _ARGS._lock_fd is None:
            if continuation_selected:_console_continuation_predecessor(prior)
            if _ARGS.continue_semantic:
                started=semantic_continuation_status(_ARGS.continue_semantic)
                if started is not None:
                    print('Продолжение уже активировано. Окно и запуск не повторяются; нужен разбор сохранённого статуса.',flush=True)
                    print(json.dumps(started,sort_keys=True),flush=True)
                    return 0
            semantic_activation=activate_semantic_owner_continuation(prior,admitted,_ARGS.continue_semantic) \
                if _ARGS.continue_semantic else None
            recovery_info=prepare_unknown_owner_continuation(prior,admitted,_ARGS.accept_remote_unknown) \
                if _ARGS.accept_remote_unknown else None
            if not (_ARGS.console or _ARGS.recover_auth or _ARGS.resume_setup or recovery_info or semantic_activation):
                require_ready_checkpoint(prior,admitted)
            permitted=(not prior or prior.get('stage') in ('AUTH_RECOVERED_NO_LIVE_REPLAY','DEPENDENCIES_READY_OWNER_AUTHORIZATION_PENDING'))
            require(permitted or _ARGS.console or _ARGS.recover_auth or _ARGS.resume_setup or recovery_info or semantic_activation,
                    'owner_prior_attempt_checkpoint_no_automatic_restart')
            if _ARGS.recover_auth:
                require(prior.get('stage') not in ('LIVE_STARTED','LIVE_EVIDENCE_READY','LIVE_STOPPED_REVIEW_REQUIRED'),
                        'owner_recovery_cannot_restart_live')
            if _ARGS.console:
                console_source_entry(PROJECT)
                console_execution_entry(PROJECT)
            if _ARGS.resume_setup:
                journal=require_setup_resume(prior)
                _CONTEXT={key:journal[key] for key in ('setup_binding','source_identity_sha256','ledger_sha256','quota_state','auth_ever_started','live_ever_started')}
            else:
                _CONTEXT={key:prior[key] for key in ('setup_binding','source_identity_sha256','ledger_sha256','quota_state','auth_ever_started','live_ever_started')} if prior else {
                    'setup_binding':str(uuid.uuid4()),
                    'source_identity_sha256':hashlib.sha256(json.dumps(admitted['pins'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                    'ledger_sha256':hashlib.sha256(_read(PROJECT/'state/model_turns.json')).hexdigest(),
                    'quota_state':quota_state(require_unspent=not (_ARGS.console or _ARGS.recover_auth)),
                    'auth_ever_started':False,'live_ever_started':False}
            ledger=json.loads(_read(PROJECT/'state/model_turns.json'))
            require(ledger['active_attempt_id'] is None or recovery_info,'owner_setup_after_unknown_refused')
            _CONTEXT['ledger_sha256']=hashlib.sha256(_read(PROJECT/'state/model_turns.json')).hexdigest()
            _CONTEXT['ledger_before_sha256']=_CONTEXT['ledger_sha256']
            if recovery_info:_CONTEXT.update(recovery_info)
            _CONTEXT['quota_state']=quota_state(require_unspent=not (_ARGS.console or _ARGS.recover_auth))
            # A new explicitly selected operation uses the current admitted
            # closure. Prior failure/source evidence and auth history survive.
            _CONTEXT['source_identity_sha256']=hashlib.sha256(json.dumps(admitted['pins'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
            _CONTEXT['operation_id']=semantic_activation['owner_operation_id'] if semantic_activation else str(uuid.uuid4())
            if semantic_activation:
                _CONTEXT.update(semantic_continuation_proposal_sha256=_ARGS.continue_semantic,
                    semantic_continuation_activation_sha256=hashlib.sha256(_canonical(semantic_activation)+b'\n').hexdigest(),
                    continuation_id=semantic_activation['continuation_id'],continuation_run_id=semantic_activation['run_id'],
                    effect_activated_at=semantic_activation['activated_at'],effect_valid_to=semantic_activation['valid_to'])
            if _ARGS.console:
                _CONTEXT.update(console_run_id=uuid.uuid4().hex[:12],budget_scope='console',
                    console_profile=_profile_selection()['manifest']['profile_id'] if _profile_selection() is not None else 'stage04_dynamic_information_v01',
                    stage04_acceptance_requested=_ARGS.stage04_acceptance)
                _CONTEXT['ledger_sha256']=hashlib.sha256(_read(PROJECT/'state/console_model_turns.json')).hexdigest()
                _CONTEXT['ledger_before_sha256']=_CONTEXT['ledger_sha256']
                if continuation_selected:_CONTEXT['console_continuation_proposal_sha256']=continuation_selected
                previous=_read(STATE)
                predecessor=PROJECT/'state/console_operation_predecessors'
                require(not predecessor.is_symlink(),'owner_console_predecessor_symlink')
                predecessor.mkdir(mode=0o700,exist_ok=True)
                destination=predecessor/(_CONTEXT['operation_id']+'.json')
                previous_fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(previous_fd,'wb') as stream:
                    stream.write(previous);stream.flush();os.fsync(stream.fileno())
                _CONTEXT.update(console_predecessor_path=str(destination.relative_to(PROJECT)),
                    console_predecessor_sha256=hashlib.sha256(previous).hexdigest(),
                    console_predecessor_reason='EXPLICIT_NEW_NO_EFFECT_CONSOLE_OPERATION')
            _CONTEXT['auth_this_operation']=False
            _CONTEXT['live_this_operation']=False
            _CONTEXT['operation_kind']='AUTH_ONLY_RECOVERY' if _ARGS.recover_auth else (
                'EXPLICIT_COMPLETED_SEMANTIC_CONTINUATION' if semantic_activation else (
                'EXPLICIT_LOCAL_CLOSED_REMOTE_UNKNOWN_CONTINUATION' if recovery_info else ('EXPLICIT_NO_EFFECT_CONSOLE' if _ARGS.console else 'REVIEWED_OWNER_LIVE_OR_CONSOLE')))
            _CONTEXT['command_point']='STARTUP_SETUP_PHASE'
            phase('SETUP')
            _CONTEXT['command_point']='STARTUP_FIRST_CHECKPOINT'
            checkpoint('DEPENDENCY_SETUP_OWNER_STARTED')
            print('Проверяю отдельное окружение Radik и точные dependency locks.',flush=True)
            _CONTEXT['command_point']='DEPENDENCY_SETUP'
            public_observation('owner_dependency_observation.json',setup_owner(PROJECT,resume=_ARGS.resume_setup,phase_binding=_CONTEXT['setup_binding'],
                progress=lambda stage:print('Подготовка окружения: '+stage,flush=True)))
            phase('SETUP_READY')
            _CONTEXT['command_point']='STARTUP_READY_CHECKPOINT'
            if _ARGS.resume_setup:
                checkpoint('DEPENDENCIES_READY_OWNER_AUTHORIZATION_PENDING')
                _write_continuation({'schema':'radik.direct_plan_continuation.v01','next_operation':'owner_run',
                    'owner_command':COMMAND,'no_automatic_auth_model_or_SAVE':True})
                print('DEPENDENCIES_READY / OWNER_AUTHORIZATION_PENDING. Для продолжения запустите обычную команду, когда готовы.',flush=True)
                return 0
            checkpoint('DEPENDENCIES_READY_FOR_OWN_AUTH')
            _CONTEXT['command_point']='REEXEC_BOUNDARY'
            return _reexec(fd)
        _CONTEXT={key:prior[key] for key in ('operation_id','setup_binding','source_identity_sha256','ledger_sha256','quota_state','auth_ever_started','live_ever_started')}
        for key in ('ledger_before_sha256','unknown_recovery_contract_sha256','unknown_recovery_review_sha256',
                    'unknown_previous_owner_operation_id','unknown_effect_valid_to',
                    'auth_this_operation','live_this_operation','command_phase','command_point'):
            if key in prior:_CONTEXT[key]=prior[key]
        for key in ('semantic_continuation_proposal_sha256','semantic_continuation_activation_sha256',
                    'continuation_id','continuation_run_id','effect_activated_at','effect_valid_to',
                    'console_run_id','budget_scope','console_profile','console_predecessor_path',
                    'console_predecessor_sha256','console_predecessor_reason','stage04_acceptance_requested',
                    'console_continuation_proposal_sha256'):
            if key in prior:_CONTEXT[key]=prior[key]
        _CONTEXT['operation_kind']='AUTH_ONLY_RECOVERY' if _ARGS.recover_auth else (
            'EXPLICIT_COMPLETED_SEMANTIC_CONTINUATION' if _ARGS.continue_semantic else (
            'EXPLICIT_LOCAL_CLOSED_REMOTE_UNKNOWN_CONTINUATION' if _ARGS.accept_remote_unknown else ('EXPLICIT_NO_EFFECT_CONSOLE' if _ARGS.console else 'REVIEWED_OWNER_LIVE_OR_CONSOLE')))
        require(Path(sys.prefix).absolute()==PROJECT/'.venv-plan','owner_selected_environment_required')
        require(prior.get('stage')=='DEPENDENCIES_READY_FOR_OWN_AUTH','owner_reexec_checkpoint_binding')
        if _ARGS.console:
            require(prior.get('console_profile')==(_profile_selection()['manifest']['profile_id'] if _profile_selection() is not None else 'stage04_dynamic_information_v01')
                and prior.get('stage04_acceptance_requested') is _ARGS.stage04_acceptance
                and prior.get('console_continuation_proposal_sha256')==continuation_selected,
                'owner_stage04_reexec_scope')
        sys.path.insert(0,str(site_directory(PROJECT/'.venv-plan')))
        unused_cache=PROJECT/'.venv-plan/.disabled_bytecode_cache'
        require(not unused_cache.exists(),'owner_disabled_cache_must_be_absent')
        sys.pycache_prefix=str(unused_cache)
        public_observation('owner_dependency_observation.json',verify_installed(PROJECT))
        accepted_auth=source_review(PROJECT,runtime=False)
        _CONTEXT['auth_source_identity_sha256']=digest(accepted_auth['pins'])
        if not _ARGS.recover_auth:
            runtime_admitted=source_review(PROJECT,runtime=True)
            # The effect handoff belongs only to the future live path.
            if not (_ARGS.continue_semantic or _ARGS.console):
                handoff=Path('/Users/admin/Downloads/RADIK_BOOTSTRAP_AND_LIVE_EXAM_RU.txt')
                require(not handoff.is_symlink() and digest(handoff.read_bytes())==
                        '2af8077da9aeda9b31b4b3cb61cf9e584b801f9fb1da85ba9e75e41ba28e73f1',
                        'owner_fixed_effect_handoff_missing_or_changed')
        owner_semantic_continuation=restore_semantic_owner_continuation(prior,admitted,_ARGS.continue_semantic) \
            if _ARGS.continue_semantic else None
        owner_unknown_recovery=None
        if _ARGS.accept_remote_unknown:
            owner_unknown_recovery=apply_unknown_owner_continuation(admitted,_ARGS.accept_remote_unknown)
            checkpoint('LOCAL_UNKNOWN_CONTINUATION_APPLIED')
            print('Старая попытка остаётся UNKNOWN и учтённой. Принято только освобождение local occupancy; server completion/cancellation не подтверждены. Начинается новая owner operation.',flush=True)
        console_continuation=None
        if continuation_selected:
            console_execution_entry(PROJECT)
            predecessor_raw=_read(PROJECT/_CONTEXT['console_predecessor_path'])
            require(hashlib.sha256(predecessor_raw).hexdigest()==_CONTEXT['console_predecessor_sha256'],
                'owner_console_continuation_predecessor')
            prepared=prepare_console_continuation_entry(json.loads(predecessor_raw),admitted,
                continuation_selected,owner_lock_fd=fd,owner_operation_id=_CONTEXT['operation_id'],
                run_id=_CONTEXT['console_run_id'])
            console_continuation=prepared['continuation']
            checkpoint('CONSOLE_LOCAL_UNKNOWN_ACKNOWLEDGED',console_continuation=console_continuation)
        phase('AUTH')
        from app.plan_auth import PlanAuth,PlanAuthError
        auth=PlanAuth(PROJECT)
        pending=auth.pending_registration_status()
        if pending.get('explicit_recovery_required') is True and not _ARGS.recover_auth:
            raise ValueError('owner_explicit_auth_recovery_required')
        connection=auth.connection_receipt()
        recovery_mode='RETAINED_VERIFIED_GRANT'
        if _ARGS.recover_auth and connection.get('status')!='OWN_PLAN_GRANT_VERIFIED':
            checkpoint('OWN_AUTHORIZATION_OWNER_STARTED')
            print('Radik требуется отдельное разрешение на использование ChatGPT plan. Сейчас откроется стандартная страница OpenAI; прежний Codex login не используется.',flush=True)
            connection=auth.authorize_owner(recovery=_ARGS.recover_auth,browser_open=owner_browser,
                progress=lambda stage:print('Авторизация Radik: '+stage,flush=True))
            recovery_mode='EXPLICIT_NEW_AUTHORIZATION'
        if connection.get('status')!='OWN_PLAN_GRANT_VERIFIED':
            raise PlanAuthError(connection.get('status','AUTHORIZATION_REQUIRED'),
                                connection.get('operation','grant'),http_status=connection.get('http_status'))
        auth_verified=True
        if _ARGS.recover_auth:
            return finish_auth_recovery(connection,auth.public_observations(),recovery_mode=recovery_mode)
        checkpoint('OWN_GRANT_VERIFIED',connection=connection)
        public_observation('owner_auth_observations.json',auth.public_observations())
        _CONTEXT['source_identity_sha256']=digest(runtime_admitted['pins'])
        sys.path.insert(0,str(PROJECT/'source/reference'))
        from app.runtime import make_client,bounded_live_exam,main as console_main
        if _ARGS.console:
            console_transition(PROJECT)
            console_execution_entry(PROJECT)
            from app.task_budget import read_state
            from app import normal_session
            if console_continuation is None:
                normal_session.apply_transition(PROJECT,owner_lock_fd=fd,
                    source_identity_sha256=digest(runtime_admitted['pins']),
                    auth_source_identity_sha256=digest(admitted['pins']))
                current_profile=_profile_selection()
                normal_operation_ref=normal_session.open_operation(PROJECT,owner_lock_fd=fd,
                    owner_operation_id=_CONTEXT['operation_id'],run_id=_CONTEXT['console_run_id'],
                    source_review_ref=current_profile['manifest']['source_review_ref'] if current_profile is not None else {'path':str((CURRENT_SOURCE_PASSAGE/'runtime_source_review.json').relative_to(PROJECT)),
                        'sha256':digest(_read(CURRENT_SOURCE_PASSAGE/'runtime_source_review.json'))},
                    source_admission_ref=current_profile['manifest']['source_admission_ref'] if current_profile is not None else {'path':str((CURRENT_SOURCE_PASSAGE/'current_source_admission.json').relative_to(PROJECT)),
                        'sha256':digest(_read(CURRENT_SOURCE_PASSAGE/'current_source_admission.json'))},
                    source_identity_sha256=digest(runtime_admitted['pins']),
                    auth_source_identity_sha256=digest(admitted['pins']),
                    profile_ref=current_profile['profile_ref'] if current_profile is not None else None)
            transition=read_state(PROJECT)
            _CONTEXT['console_source_transition_sha256']=transition['transition_sha256']
            client=make_client(auth,scope='console')
            client.budget.set_console_operation(_CONTEXT['operation_id'],_CONTEXT['console_run_id'])
            if normal_operation_ref is not None:client.budget.set_normal_operation(normal_operation_ref)
            from review.transport.model_scope import read_scope_state
            phase('CONSOLE')
            checkpoint('CONSOLE_STARTED',console_budget=read_scope_state(PROJECT,'console'))
            code=console_main(client=client,console_continuation=console_continuation) if console_continuation else (
                console_main(client=client,stage04_acceptance=True) if _ARGS.stage04_acceptance else
                console_main(client=client,native_scenario=_ARGS.stage04_native_scenario))
            normal_close=None
            if normal_operation_ref is not None:
                normal_close=normal_session.close_operation(PROJECT,owner_lock_fd=fd,
                    operation_ref=normal_operation_ref,failed=code!=0)
                normal_operation_ref=None
            actual_path=getattr(client,'last_stage04_result_path',None)
            checkpoint('CONSOLE_EXITED' if code==0 else 'CONSOLE_STOPPED_REVIEW_REQUIRED',
                console_budget=read_scope_state(PROJECT,'console'),automatic_retry=False,
                stage04_actual_result_path=actual_path,normal_operation_close_ref=normal_close)
            return code
        phase('CATALOG')
        client=make_client(auth);catalog=client.preflight()
        if owner_unknown_recovery is not None:client.owner_unknown_recovery=owner_unknown_recovery
        if owner_semantic_continuation is not None:client.owner_semantic_continuation=owner_semantic_continuation
        live_transition(preflight_receipt=catalog,project=PROJECT)
        ledger=json.loads(read(PROJECT,'state/model_turns.json'))
        require(ledger['active_attempt_id'] is None and len(ledger['attempts'])+6<=16,
                'owner_six_attempts_not_available')
        quota=PROJECT/'state/live_save_quota'
        require(not quota.is_symlink() and (not quota.exists() or not any(quota.iterdir())),
                'owner_prior_save_state_no_reset')
        phase('LIVE')
        checkpoint('LIVE_STARTED',connection=connection,catalog=catalog)
        live_started=True
        print('Запускаю fixed live: cold → DRS warm → delta → один SAVE. Автоматических повторов нет.',flush=True)
        code=bounded_live_exam(client)
        require(client.last_live_result_path is not None,'owner_actual_live_result_missing')
        report_path=client.last_live_result_path
        report=json.loads(read(PROJECT,report_path))
        primary_live_failure=report.get('error');action_policy_closed=report.get('action_policy_closed')
        checkpoint('LIVE_EVIDENCE_READY' if code==0 else 'LIVE_STOPPED_REVIEW_REQUIRED',
            actual_result_path=report_path,action_policy_closed=report['action_policy_closed'],connection=connection)
        from review.package_direct_plan_return import publish_owner_live
        public_observation('owner_auth_observations.json',auth.public_observations())
        _continue_review(report_path,client.observation_directory)
        report_started=True
        package=publish_owner_live(PROJECT,str(Path(report_path).parent),client.observation_directory)
        _continue_review(report_path,client.observation_directory,package)
        print('LIVE_EVIDENCE_READY / CONSOLE_BEHAVIOR_REVIEW_PENDING' if code==0 else
              'LIVE_STOPPED_REVIEW_REQUIRED: нужен разбор actual observations; повтор запрещён.',flush=True)
        print('Отправьте в эту сессию готовый continuation prompt из возвращённого архива.',flush=True)
        return code
    except BaseException as error:
        if _ARGS.console:
            from app.stage04_diagnostics import observe_failure, record_secondary, mark_primary_persisted, print_primary
            observe_failure(error,phase='OWNER_ENTRY',step='UNKNOWN')
            if normal_operation_ref is not None:
                try:
                    from app import normal_session
                    normal_session.close_operation(PROJECT,owner_lock_fd=fd,
                        operation_ref=normal_operation_ref,failed=True)
                    normal_operation_ref=None
                except Exception as closing_error:
                    record_secondary(error,closing_error,phase='TASK_ROUND_CLOSE',step='UNKNOWN')
            primary=error_projection(error)
            prior_return=getattr(client,'last_stage04_return',None)
            failure_state=None
            checkpoint_status='NOT_WRITTEN'
            checkpoint_failure=None
            reporting_failure=None
            if _CONTEXT.get('operation_id'):
                try:
                    failure_state=checkpoint('CONSOLE_STOPPED_REVIEW_REQUIRED',error=primary,
                        stage04_actual_result_path=getattr(client,'last_stage04_result_path',None),
                        stage04_transport_directory=getattr(client,'observation_directory',None),
                        automatic_retry=False,model_or_effect_automatic_retry=False)
                    require(json.loads(_read(STATE))==failure_state,'owner_stage04_failure_checkpoint_readback')
                    mark_primary_persisted(error)
                    checkpoint_status='WRITTEN_DURABLE'
                except Exception as checkpoint_error:
                    record_secondary(error,checkpoint_error,phase='OWNER_CHECKPOINT',step=primary.get('step','UNKNOWN'))
                    checkpoint_failure=error_projection(checkpoint_error)
                    checkpoint_status='UNCONFIRMED'
            package=prior_return if type(prior_return) is dict else None
            report_status='UNCONFIRMED' if prior_return is not None else 'NOT_STARTED'
            if prior_return is None and failure_state is not None:
                try:
                    from review.package_direct_plan_return import publish_stage04_owner_failure
                    package=publish_stage04_owner_failure(failure_state,source_admitted=True,
                        transport_directory=client.observation_directory if client is not None else None)
                    if client is not None:client.last_stage04_return=package
                    report_status=reporting_observation(package)['status']
                except Exception as reporting_error:
                    record_secondary(error,reporting_error,phase='RETURN_PUBLICATION',step=primary.get('step','UNKNOWN'))
                    reporting_failure=error_projection(reporting_error)
                    report_status=reporting_observation(package,started=True,error=reporting_error)['status']
            elif package is not None:
                try:report_status=reporting_observation(package)['status']
                except Exception:report_status='UNCONFIRMED'
            print_primary(error)
            print('Запись статуса: '+checkpoint_status+'; отчёт: '+report_status
                +'. Автоматического повтора и повторной упаковки готовой пары нет.',flush=True)
            return 2
        if auth_verified and _ARGS.recover_auth:
            # A refused/failed public terminal cannot revoke the already verified
            # grant or route it into the earlier AUTH failure publisher.
            try:
                checkpoint('AUTH_RECOVERED_NO_LIVE_REPLAY',connection=connection,
                    auth_status='OWN_PLAN_GRANT_VERIFIED',actual_result_path=None,
                    reporting_status='AUTH_TERMINAL_RECORDING_REFUSED_NO_REPACK',
                    terminal_error=error_projection(error))
                _write_continuation({'schema':'radik.auth_only_continuation.v01',
                    'next_operation':'independent_actual_auth_result_review_no_live',
                    'operation_id':_CONTEXT['operation_id'],'auth_status':'OWN_PLAN_GRANT_VERIFIED',
                    'auth_source_identity_sha256':_CONTEXT.get('auth_source_identity_sha256'),
                    'reporting_status':'AUTH_TERMINAL_RECORDING_REFUSED_NO_REPACK',
                    'automatic_retry':False,'live_admission':'NOT_GRANTED'})
            except Exception:pass
            print('AUTH прошёл; public terminal/report отказал. Grant сохранён, вход и упаковка не повторяются. Передайте этот статус в Codex; live/console не допущены.',flush=True)
            return 0
        if not _CONTEXT.get('operation_id'):
            print('Radik: '+error_projection(error)['code']+'. Предыдущая попытка сохранена; повтор не выполнялся.',flush=True)
            return 2
        phase_name=_CONTEXT.get('command_phase','UNKNOWN')
        point=_CONTEXT.get('command_point','UNKNOWN')
        if phase_name not in ('SETUP','SETUP_READY','AUTH','AUTH_RECOVERED','CATALOG','CONSOLE','LIVE'):phase_name='UNKNOWN'
        if point not in ('STARTUP_SETUP_PHASE','STARTUP_FIRST_CHECKPOINT','DEPENDENCY_SETUP',
                         'STARTUP_READY_CHECKPOINT','REEXEC_BOUNDARY'):point='PHASE_BOUNDARY'
        diagnostic={'schema':'radik.owner_failure_diagnostic.v01','error':error_projection(error),
            'phase':phase_name,'point':point,'checkpoint_status':'FAILED',
            'continuation_status':'NOT_REQUIRED','report_status':reporting_observation(
                package,started=report_started,error=error)['status'],
            'automatic_retry':False,'raw_error_recorded':False}
        preserved=owner_failure_observation(primary_live_failure=primary_live_failure,
            secondary_failure=error,action_policy_closed=action_policy_closed,
            package=package,report_started=report_started)
        diagnostic.update(preserved)
        try:
            failure_state=checkpoint('LIVE_STOPPED_REVIEW_REQUIRED' if live_started else 'STOPPED_BEFORE_LIVE',
                error=primary_live_failure if primary_live_failure is not None else diagnostic['error'],
                **preserved,command_stage=phase_name,failure_point=point,
                category='OWNER_OPERATION_FAILURE',actual_result_path=report_path,
                recovery_command=failure_recovery_command(error,phase_name),automatic_retry=False)
            diagnostic['checkpoint_status']='WRITTEN_DURABLE'
        except Exception:
            failure_state=None
        if report_path is None:
            try:
                _write_continuation({'schema':'radik.direct_plan_continuation.v01',
                'next_operation':'review_actual_owner_failure_no_retry','reviewer':'/root/semantic_continuation_reviewer',
                'owner_state_path':str(STATE.relative_to(PROJECT)),
                'owner_operation_id':_CONTEXT['operation_id'],
                'auth_observations_path':'review/direct_plan_passage/owner_auth_observations.json',
                'transport_observations':client.observation_directory if client is not None else None,
                'error':diagnostic['error'],'failure_phase':phase_name,'failure_point':point,
                'checkpoint_status':diagnostic['checkpoint_status'],'automatic_retry':False,
                'no_repeat':'Preserve actual ledger/quota and failures; no login, inference, exam or SAVE replay.'})
                diagnostic['continuation_status']='WRITTEN_DURABLE'
            except Exception:diagnostic['continuation_status']='FAILED'
        if auth is not None:
            try:public_observation('owner_auth_observations.json',auth.public_observations())
            except (ValueError,OSError):pass
        if failure_state is not None and not live_started:
            try:
                from review.transport.owner_failure_report import report
                package=report(failure_state,source_admitted=True,
                    transport_directory=client.observation_directory if client is not None else None)
                diagnostic['report_status']=reporting_observation(package)['status']
                print('Отчёт об отказе: '+package['delivery']['status']+'. Отправьте continuation prompt из архива в эту сессию.',flush=True)
            except Exception as reporting_error:
                diagnostic['report_status']=reporting_observation(package,started=True,error=reporting_error)['status']
                diagnostic['secondary_reporting_failure']=error_projection(reporting_error)
        print(json.dumps(diagnostic,sort_keys=True,allow_nan=False),flush=True)
        saved='checkpoint сохранён' if diagnostic['checkpoint_status']=='WRITTEN_DURABLE' else 'запись checkpoint не подтверждена'
        print('Radik остановлен: '+diagnostic['error']['type']+'/'+diagnostic['error']['code']+
              ', '+phase_name+'/'+point+'. Автоматического повтора нет; '+saved+'.',flush=True)
        return 2
    finally:
        if auth is not None:
            try:public_observation('owner_auth_observations.json',auth.public_observations())
            except (ValueError,OSError):print('Не удалось сохранить public auth accounting; нужен разбор сохранённого состояния.',flush=True)
        if client is not None:client.close()
        os.close(fd)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError) as error:
        if getattr(globals().get('_ARGS'), 'status',False):
            print('Radik: readonly status refused; source admission отсутствует или изменилась.',flush=True)
            raise SystemExit(2)
        try:
            # Independently confirm the minimal reporter before loading it.
            seal=json.loads(_read(CURRENT_SOURCE_PASSAGE/'failure_reporter_review.json'))
            for relative in ('review/transport/owner_failure_report.py','review/package_direct_plan_return.py',
                    'app/stage04_diagnostics.py'):
                require(hashlib.sha256(_read(PROJECT/relative)).hexdigest()==seal['code_source_pins'][relative],'owner_reporter_identity_changed')
            reporter=__import__('runpy').run_path(str(PROJECT/'review/transport/owner_failure_report.py'),run_name='owner_failure_only')
            package=reporter['bootstrap_failure'](error_projection(error))
            print('Отчёт source refusal: '+package['delivery']['status']+'. Runtime не допущен.',flush=True)
        except Exception:
            print('Без подтверждённого reporter отказ показан только здесь. Передайте в Codex: source admission refused; login/model не запускать, продолжить affected source review.',flush=True)
        print('Radik: required source/dependency admission отсутствует или изменилась. Вход и модель не запускались.',flush=True)
        raise SystemExit(2)
