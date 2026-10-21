"""Shared G2B/G2C/D informational baseline issuance over public native APIs."""
from dataclasses import fields
from hedgehog import action_commit_packet_v02 as action
from hedgehog import drs_semantic_address_v01 as address, drs_memory_resolution_v01 as memory
from hedgehog import drs_g2b_compatibility_v01 as compatibility, reuse_certificate_v01 as reuse
from hedgehog.kernel import abi_v01 as abi, work_composition_v01 as work
from hedgehog.kernel import execution_mode_router_v01 as router, fractal_runtime_v02 as fractal
from hedgehog.kernel import transition_registry_v01 as transitions
from . import native_authority as authority, informational_material as source_material
require,canonical,digest,plain=authority.require,authority.canonical,authority.digest,authority.plain


def current_semantic_domain(task):
    """Read a domain only after the live Host verifies its committed source.

    A coherent foreign packet is insufficient: native Work revalidates the
    retained outcome against the original Host policy source fingerprint, BSEP,
    task, Root and semantic artifact. This validates retained provenance, not
    fresh permission or post-edit source eligibility. The informational carrier,
    actual current capture and invalidation supply those separate boundaries.
    No domain allowlist supplies authority.
    """
    semantic = task.common["semantic_proposal"]
    snapshot = work.inspect_work_task_v01(task.host, task_id=task.task_id)
    context = work.work_continuation_context_v01(task.host, task_id=task.task_id,
        expected_revision=snapshot.host_revision)
    outcome = work.inspect_work_continuation_outcome_v01(context)
    require(outcome.status == "COMPLETED" and outcome.program == task.program
        and task.program.candidate.task_id == snapshot.policy.task_id == task.task_id
        and semantic.owner_root_id == snapshot.policy.owning_root_id == task.root_id,
        "native_information_current_work_identity")
    require(work.validate_work_continuation_outcome_v01(outcome, context=context,
        review_bindings=getattr(task, "review_bindings", ()), **task.common) == (True, ()),
        "native_information_current_work_context")
    return task.common["source_context"].business_request_context_packet["domain"]


def baseline_semantic_domain(task):
    """Keep the actual baseline, G2B query and current business source linked."""
    domain = current_semantic_domain(task)
    baseline, report = task.d_baseline, task.information[0]
    source = baseline.source_context
    snapshot = source.router_input.local_routing_snapshot
    require(source is task.d_source and source.g2c_source_context.g2b_resolution_report is report
        and snapshot.request_id == baseline.runtime_report.request_id == task.task_id
        and snapshot.owning_root_id == task.root_id
        and snapshot.transaction_id == baseline.topology.transaction_id == report.query.query_id
        and snapshot.domain_id == report.query.domain == domain,
        "native_information_baseline_domain_identity")
    return domain


def build_information(task, material, accepted_review):
    """A source-bound accepted Work information record for the native B/C/D path."""
    from . import document_temporal as temporal
    horizon = temporal.INFORMATION_SECONDS if task.informational_profile else 3600
    domain = current_semantic_domain(task)
    accepted_root = authority.root_plain(accepted_review)
    require(accepted_review[2].decision == "ACCEPT" and accepted_review[1].target_root_id == task.root_id
        and accepted_review[1].transaction_id == task.common["semantic_proposal"].transaction_id,
        "native_information_accepted_work_root_identity")
    now = task.source.clock()
    scope = digest(dict(task=task.task_id, sources=source_material.descriptors(task.sources), material=material))
    ref = digest(material)
    addr = address.build_semantic_address_v01(namespace="radik", domain=domain, subject_class="bounded_document_work",
        intent_class="informational_summary", meaning_schema_id="radik.document.accepted", meaning_schema_version="v02")
    envelope = address.build_drs_time_envelope_v01(pt_created_at=now, kt_as_of=now, et_observed_at=now, ct_context_anchor=now,
        ttl_seconds=horizon, valid_from=now, valid_to=now+horizon, source_observed_at=now, source_reported_at=now,
        system_ingested_at=now, system_verified_at=now, freshness_policy_id="radik:document_current")
    authority_envelope = address.build_drs_authority_envelope_v01(authority_class="ROOT_ACCEPTED_WORK", owning_local_root_id=task.root_id,
        source_root_decision_input_id=accepted_review[1].decision_input_id, source_root_decision_id=accepted_review[2].decision_id,
        source_root_decision_hash=digest(accepted_root["result"]), authority_scope_fingerprint=scope,
        root_acceptance_state="ACCEPTED_WORK", recording_component="radik:current_document_work")
    record = address.build_meaning_record_v01(semantic_address=addr, predecessor_record_id=None, supersession_reason=None,
        # Descriptive text is distinct from typed identity/fingerprint fields.
        # Exact accepted Work/source material is bound by ref and scope below.
        safe_summary="Source-bound document processing completed by native Work and accepted by the current local Root.",
        semantic_tags=("document",), resonance_reason="Actual source-bound native Work accepted by local Root.",
        memory_pointers=(), artifact_pointers=(), source_reference_ids=(ref,), lineage_edges=(), time_envelope=envelope,
        authority_envelope=authority_envelope, persistent_lifecycle_state="ACTIVE", risk_hints=(), conflict_hints=(),
        reuse_policy_class="ANSWER_SHORTCUT", policy_version=authority.POLICY, schema_versions=(authority.POLICY,),
        content_fingerprint=ref, recording_component="radik:current_document_work")
    query = memory.build_drs_temporal_query_v01(query_mode="DIRECT_REUSE_CANDIDATE", semantic_address_id=addr.semantic_address_id,
        scope_fingerprint=scope, as_of=now, evaluation_time=now, evaluation_time_source="INJECTED_CURRENT_DECISION_TIME",
        time_range_start=now, time_range_end=now+horizon, required_time_axes=("PT", "KT", "ET", "CT", "TTL", "VALIDITY"),
        freshness_policy_id=envelope.freshness_policy_id, max_age_seconds=horizon, domain=domain, risk_class="LOW",
        reuse_intent="INFORMATIONAL_SHORTCUT_CONSIDERATION", requested_reuse_classes=("ANSWER_SHORTCUT",),
        required_evidence_classes=("SOURCE_IDENTITY", "SOURCE_INTEGRITY", "PROVENANCE_CHAIN", "TIME_FITNESS", "POLICY_COMPATIBILITY",
            "SCHEMA_COMPATIBILITY", "CONFLICT_CLEARANCE", "ROOT_DECISION", "SOURCE_HISTORY"), forbidden_changes=("POLICY_CHANGED",),
        policy_version=authority.POLICY, schema_versions=(authority.POLICY,), owning_local_root_id=task.root_id)
    evaluation = memory.evaluate_drs_candidate_v01(semantic_address=addr, query=query, meaning_record=record)
    require(evaluation.eligible_for_ranking, "native_information_ineligible")
    candidate = memory.build_resolution_candidate_v01(query_id=query.query_id, semantic_address_id=addr.semantic_address_id,
        meaning_record_id=record.meaning_record_id, query_evaluation_id=evaluation.query_evaluation_id, safe_summary=record.safe_summary,
        evidence_ref_ids=record.source_reference_ids, source_history_hash=evaluation.source_history_hash, action_history_binding_id=None,
        semantic_similarity_units=10000, freshness_units=evaluation.current_freshness_units, source_authority_prior_units=10000,
        lineage_proximity_units=10000, historical_utility_units=0, gt_advisory_prior_units=0, conflict_penalty_units=0, risk_penalty_units=0, retrieval_cost_units=1)
    ranked = memory.rank_eligible_drs_candidates_v01(query=query, query_evaluations=(evaluation,), candidates=(candidate,))
    budget = memory.build_memory_descent_budget_v01(max_depth=0, max_records_opened=1, max_pointers_opened=0, max_artifacts_opened=0,
        max_bytes_opened=0, max_lineage_edges=0, max_conflict_records=0)
    plan = memory.build_retrieval_plan_v01(query_id=query.query_id, semantic_address_id=addr.semantic_address_id,
        proposed_record_ids=(record.meaning_record_id,), proposed_memory_pointer_ids=(), proposed_artifact_pointer_ids=(),
        requested_descent_class="SUMMARY_ONLY", proposed_budget_id=budget.memory_descent_budget_id, required_access_policy_ids=(), reason_codes=())
    claim = dict(profile_version="v0.1", semantic_address_id=addr.semantic_address_id, meaning_record_id=record.meaning_record_id,
        query_id=query.query_id, query_evaluation_id=evaluation.query_evaluation_id, resolution_candidate_id=candidate.resolution_candidate_id,
        reuse_class="ANSWER_SHORTCUT", case_type="NON_ACTION_INFORMATIONAL", scope_fingerprint=scope, policy_version=query.policy_version,
        schema_versions=list(query.schema_versions), required_evidence_classes=list(query.required_evidence_classes),
        observed_evidence_fingerprint=evaluation.observed_evidence_fingerprint, forbidden_changes=list(query.forbidden_changes),
        checked_dependency_fingerprint=evaluation.checked_dependency_fingerprint, source_history_hash=evaluation.source_history_hash,
        action_history_binding_id=None, valid_from=now, valid_to=now+horizon, issued_at=now, evaluated_at=now,
        root_shortcut_policy_ref="policy:drs_answer_shortcut:v0.1")
    review = authority.root_review(candidate.resolution_candidate_id, claim,
        dict(eligible=evaluation.eligible_for_ranking, ranked=ranked == (candidate,)), now, transaction_id=query.query_id,
        owning_root_id=task.root_id, predicate="authorize_non_action_informational_answer_shortcut_v01", subject=addr.semantic_address_id)
    require(review[2].decision == "ACCEPT", "native_information_root_refused")
    root_hash = action.domain_separated_sha256_hex_v01(domain="hedgehog:drs:root_shortcut_root_result_binding:v01",
        payload=canonical(authority.root_plain(review)["result"]))
    shortcut = reuse.build_root_shortcut_authorization_projection_v01(owning_local_root_id=task.root_id, root_kernel_id=review[0].kernel_id,
        root_decision_input_id=review[1].decision_input_id, root_decision_id=review[2].decision_id, root_decision_hash=root_hash,
        selected_candidate_id=candidate.resolution_candidate_id, semantic_address_id=addr.semantic_address_id, meaning_record_id=record.meaning_record_id,
        query_id=query.query_id, query_evaluation_id=evaluation.query_evaluation_id, allowed_reuse_class="ANSWER_SHORTCUT", scope_fingerprint=scope,
        policy_version=query.policy_version, schema_versions=query.schema_versions, valid_from=now, valid_to=now+horizon,
        root_shortcut_policy_ref=claim["root_shortcut_policy_ref"])
    certificate = reuse.build_reuse_certificate_v01(semantic_address_id=addr.semantic_address_id, meaning_record_id=record.meaning_record_id,
        query_id=query.query_id, query_evaluation_id=evaluation.query_evaluation_id, resolution_candidate_id=candidate.resolution_candidate_id,
        root_shortcut_authorization_projection=shortcut, case_type=claim["case_type"], required_evidence_classes=query.required_evidence_classes,
        observed_evidence_fingerprint=evaluation.observed_evidence_fingerprint, forbidden_changes=query.forbidden_changes,
        checked_dependency_fingerprint=evaluation.checked_dependency_fingerprint, valid_from=now, valid_to=now+horizon, reuse_class="ANSWER_SHORTCUT",
        source_history_hash=evaluation.source_history_hash, action_history_binding_id=None, issued_at=now, evaluated_at=now)
    # This producer label belongs to the public compatibility projection format.
    # It neither imports a retired component nor supplies historical authority.
    legacy = dict(record_id=record.meaning_record_id, layer="work", type="generic", domain=domain,
        content=dict(summary=record.safe_summary), time_envelope=dict(pt_created_at=authority.stamp(now), kt_asof=authority.stamp(now),
        et_observed_at=authority.stamp(now), ct_session_anchor=task.task_id, ttl_seconds=horizon, freshness_class="static",
        valid_from=authority.stamp(now), valid_to=authority.stamp(now+horizon)), provenance=dict(request_id=task.task_id,
        created_by="root_orchestrator", trace_refs=[dict(trace_id=ref)]), status="active")
    projection = compatibility.build_legacy_drs_projection_v01(source_family="LOCAL_DRS_DICT", source=legacy, target_semantic_address=addr)
    report = memory.build_drs_resolution_report_v01(semantic_address=addr, query=query, source_projections=(projection,), source_records=(record,),
        query_evaluations=(evaluation,), eligible_candidates=(candidate,), ranked_candidate_ids=(candidate.resolution_candidate_id,),
        selected_candidate_id=candidate.resolution_candidate_id, retrieval_plan=plan, memory_descent_result=None, root_shortcut_projection=shortcut,
        reuse_certificate=certificate, context_only_record_ids=(), historical_only_record_ids=(), warning_only_record_ids=(),
        rerun_required_record_ids=(), blocked_record_ids=(), provider_calls=0, network_calls=0, gemini_calls=0, external_drs_calls=0,
        connector_calls=0, real_world_effects_count=0, final_status="PASS", reason_codes=())
    require(reuse.validate_existing_root_shortcut_decision_v01(resolution_report=report, root_kernel=review[0], root_decision_input=review[1],
        root_decision_result=review[2], use_time=now)[0], "native_information_root_binding")
    return report, review


def build_d_source(task, information):
    report, review = information
    from . import document_temporal as temporal
    horizon = temporal.INFORMATION_SECONDS if task.informational_profile else 3600
    domain = current_semantic_domain(task)
    current_now = task.source.clock()
    # The fresh G2B decision supplies one native-required evaluation instant.
    # Source/Root authority is still checked above and its validity below.
    now = report.query.evaluation_time
    require(report.query.domain == domain and report.query.owning_local_root_id == task.root_id,
        "native_information_query_domain_identity")
    require(report.query.evaluation_time_source == "INJECTED_CURRENT_DECISION_TIME"
        and now <= current_now < min(report.query.time_range_end, report.reuse_certificate.valid_to),
        "native_information_current_query_time")
    current = task.source.current()
    require(current["now"] >= current_now, "native_information_current_clock")
    require(current["full_sources"] == task.sources, "native_information_current_sources_changed")
    caps_material = dict(policy=current["policy"], semantic=plain(task.common["semantic_proposal"]),
        information=plain(report), information_root=authority.root_plain(review))
    if task.semantic_family is not None and hasattr(task.semantic_family, "scope"):
        caps_material["semantic_family"] = task.semantic_family.scope
    if task.accepted is not None:
        caps_material["accepted_result"] = task.accepted.plain
    caps = temporal.collect_caps(caps_material)
    require(caps, "native_information_temporal_caps_missing")
    temporal.require_remaining(min(row["valid_to"] for row in caps), current["now"],
        temporal.NATIVE_SECONDS + temporal.CONSUMER_SECONDS if task.informational_profile else 0)
    item = task.program.candidate.items[-1]
    scope = work.build_work_review_scope_ref_v01(candidate=task.program.candidate, item=item,
        source_context=task.common["source_context"], semantic_proposal=task.common["semantic_proposal"])
    ids = dict(request_id=task.task_id, transaction_id=report.query.query_id, owning_root_id=task.root_id, domain_id=domain)
    profiles = tuple(router.build_execution_mode_local_mode_profile_v01(**ids, mode=mode,
        policy_snapshot_id="radik:document_control", capability_snapshot_id="radik:loaded_native_control", cost_model_id="radik:finite_control",
        policy_allowed=mode == "full_fractal", scope_allowed=True, risk_allowed=True, privacy_allowed=True,
        capability_state="NOT_REQUIRED" if mode in ("sealed_replay", "direct_informational_reuse") else "AVAILABLE",
        capability_id=None if mode in ("sealed_replay", "direct_informational_reuse") else "radik:capability:" + mode,
        cost_units=index+1) for index, mode in enumerate(router.EXECUTABLE_EXECUTION_MODES_V01))
    snapshot = router.build_execution_mode_local_routing_snapshot_v01(**ids, request_class="BOUNDED_REVIEW", action_class="NON_ACTION",
        action_packet_relation="NOT_APPLICABLE", scope_class="BOUNDED", scope_ref=scope, permitted_narrower_scope_refs=(), risk_class="LOW",
        policy_snapshot_id="radik:document_control", capability_snapshot_id="radik:loaded_native_control", cost_model_id="radik:finite_control",
        required_user_input_state="COMPLETE", hard_block_state="CLEAR", evaluation_time_epoch_seconds=now,
        pt_created_at_utc=authority.stamp(now), et_observed_at_utc=authority.stamp(now), ct_session_anchor=task.task_id,
        ttl_seconds=horizon, freshness_class="static", valid_from_utc=authority.stamp(now), valid_to_utc=authority.stamp(now+horizon), mode_profiles=profiles)
    source_args = {f.name: getattr(task.common["source_context"], f.name) for f in fields(router.ExecutionModeSourceContextV01)}
    source_args.update(g2a_evaluation_time=now, g2a_evaluation_time_source=snapshot.created_by,
        g2a_evaluation_context_id=snapshot.local_routing_snapshot_id, g2b_resolution_report=report,
        g2b_compatibility_projections=report.source_projections, g2b_use_time=now, g2b_root_kernel=review[0],
        g2b_root_decision_input=review[1], g2b_root_decision_result=review[2])
    source = router.build_execution_mode_source_context_v01(**source_args)
    routing = router.build_execution_mode_router_input_v01(request_id=task.task_id, transaction_id=ids["transaction_id"], owning_root_id=task.root_id,
        bsep_binding=router.build_execution_mode_bsep_binding_v01(**ids, source_context=source), local_routing_snapshot=snapshot,
        replay_binding=router.build_execution_mode_replay_not_applicable_binding_v01(**ids),
        g2a_binding=router.build_execution_mode_g2a_no_packet_binding_v01(**ids, evaluation_time=now,
            evaluation_time_source=snapshot.created_by, evaluation_context_id=snapshot.local_routing_snapshot_id),
        g2b_binding=router.build_execution_mode_g2b_binding_v01(**ids, source_context=source))
    proposal, validation = router.route_execution_mode_v01(router_input=routing, source_context=source)
    require(validation.validation_status == "PASS" and proposal.selected_mode == "full_fractal", "native_control_route")
    artifact = router.project_execution_mode_proposal_kernel_artifact_v01(proposal=proposal, router_input=routing, source_context=source)
    registry = transitions.build_execution_mode_transition_registry_profile_v01()
    before = router.evaluate_execution_mode_proposal_to_root_transition_v01(registry=registry, proposal=proposal,
        router_input=routing, source_context=source, proposal_artifact=artifact)
    review_input = router.build_root_execution_mode_review_input_v01(proposal=proposal, router_input=routing, source_context=source,
        proposal_artifact=artifact, proposal_transition_decision=before, review_action="ACCEPT", accepted_scope_ref=scope, narrowing_basis_refs=())
    decision, kernel, root_input, result, validation = router.review_execution_mode_proposal_v01(review_input=review_input, proposal=proposal,
        router_input=routing, source_context=source, proposal_artifact=artifact, proposal_transition_decision=before)
    require(validation.validation_status == "PASS" and decision.outcome == "ACCEPT", "native_control_root")
    args = dict(review_input=review_input, decision=decision, proposal=proposal, router_input=routing, source_context=source,
        proposal_artifact=artifact, proposal_transition_decision=before, root_kernel=kernel, root_decision_input=root_input, root_decision_result=result)
    decision_artifact = router.project_root_execution_mode_decision_kernel_artifact_v01(**args)
    after = router.evaluate_execution_mode_root_route_transition_v01(registry=registry, **args, decision_artifact=decision_artifact)
    eligibility = router.project_execution_mode_route_eligibility_kernel_artifact_v01(**args, decision_artifact=decision_artifact, root_route_transition_decision=after)
    args["g2c_source_context"] = args.pop("source_context")
    return fractal.build_fractal_runtime_source_context_v02(**args, transition_registry=registry, decision_artifact=decision_artifact,
        root_route_transition_decision=after, route_eligibility_artifact=eligibility, runtime_policy=fractal.build_fractal_runtime_policy_v02(
            required_downstream_capability_ids=proposal.required_downstream_capability_ids, permitted_child_scope_refs=()))


