"""Current local Root, semantic membrane and owned reference SAVE adapters.

This module has no import-time I/O. The trusted launcher must check its accepted
source closure before import. Provider proposals and stored evidence are data;
only verified current adapter observations supply the local decision inputs.
"""
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import asdict, fields, is_dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re

from hedgehog import action_commit_packet_v02 as action
from hedgehog import avf_v02 as avf
from hedgehog import context_packets as packets, structured_rationale as rationale
from hedgehog import work_execution_host_v01 as hosts
from hedgehog.kernel import abi_v01 as abi, effect_firewall_v01 as firewall
from hedgehog.kernel import execution_mode_router_v01 as router
from hedgehog.kernel import root_decision_v01 as roots, semantic_work_v01 as semantic
from hedgehog.kernel import transition_registry_v01 as transitions, trust_model_v01 as trust

from . import contracts
from . import semantic_membrane as membrane

DOMAIN = "RADIK_DOCUMENT"
POLICY = "radik.document.v01"
PENDING_SAVE_SECONDS = 3600
CURRENT_SAVE = ContextVar("radik_current_owned_save", default=None)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value if type(value) is bytes else canonical(value)).hexdigest()


def plain(value):
    """Portable evidence only: live origins, callbacks and Host objects are omitted."""
    if isinstance(value, abi.KernelArtifactV01):
        return abi.kernel_artifact_to_plain_dict_v01(value)
    if is_dataclass(value):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value) if not f.name.startswith("_")}
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain(v) for v in value]
    if type(value) is bytes:
        return dict(bytes=len(value), sha256=digest(value))
    require(value is None or type(value) in (str, int, float, bool), "evidence_nonportable_value")
    return value


def stamp(now):
    return datetime.fromtimestamp(now, timezone.utc).isoformat()


def records(data):
    return tuple(action.build_action_effect_parameter_record_v01(parameter_name=n, value_type=k, value=v)
        for n, (k, v) in sorted(data.items()))


def values(data):
    return {v.parameter_name: v.value for v in data}


def root_review(candidate_id, material, checks, now, *, transaction_id, predicate="radik_document_validation",
                subject="radik:documents", owning_root_id="root:radik", root=None, task_id=None,
                bsep_ref=None, topology_ref=None, permission_ref=None, temporal=True):
    root_id = root or owning_root_id
    require(type(now) is int and checks and all(type(v) is bool for v in checks.values()), "root_adapter_checks")
    evidence_ref = "radik:evidence:" + digest(material)
    request = semantic.build_semantic_work_request_v01(request_id="radik:review:" + digest(dict(candidate=candidate_id, time=now)),
        transaction_id=transaction_id, target_root_id=root_id, runtime_topology_ref=topology_ref or "radik:local_review",
        bounded_context_refs=(evidence_ref,), permitted_actor_ids=("radik:independent_validator",),
        permitted_contribution_modes=("DETERMINISTIC",), requested_subjects=(subject,),
        required_evidence_classes=("DEPENDENCY_EVIDENCE",), forbidden_claims=("authority_creation",))
    evidence = semantic.build_evidence_binding_v01(evidence_id="binding:" + evidence_ref, evidence_ref=evidence_ref,
        evidence_class="DEPENDENCY_EVIDENCE", source_component_id="radik:independent_validator",
        provenance_ref="radik:trusted_current_adapter", evidence_state="PRESENT")
    claim = semantic.build_normalized_claim_v01(claim_id=candidate_id, subject=subject, predicate=predicate,
        object_or_value=material, time_envelope_ref="radik:time:" + str(now), provenance_refs=(evidence_ref,),
        evidence_refs=(evidence.evidence_id,), confidence_micros=1000000,
        source_role="deterministic_runtime", source_mode="DETERMINISTIC")
    contribution = semantic.build_actor_contribution_v01(contribution_id="contribution:" + request.request_id,
        request_id=request.request_id, actor_id="radik:independent_validator", actor_role="deterministic_runtime",
        contribution_mode="DETERMINISTIC", bsep_projection_ref=bsep_ref or "radik:local_validation",
        scope=task_id or subject, bounded_context_refs=(evidence_ref,), claims=(claim,), evidence_bindings=(evidence,),
        constraint_bindings=(), uncertainty_bindings=(), requested_validators=tuple(sorted(checks)), forbidden_claims_observed=())
    packet = semantic.build_root_review_packet_from_contributions_v01(request=request, contributions=(contribution,),
        trust_profiles=trust.build_default_component_trust_profiles_v01())
    passed = all(checks.values())
    kernel = roots.build_root_decision_kernel_v01()
    root_input = roots.build_root_decision_input_v01(transaction_id=transaction_id, target_root_id=root_id,
        root_review_packet=packet,
        post_vv_bundle=dict(bundle_id="checks:" + digest(checks), post_vv_passed=passed,
            validated_candidate_ids=[candidate_id] if passed else [], rejected_candidate_ids=[] if passed else [candidate_id],
            required_evidence_refs=[evidence_ref], provided_evidence_refs=[evidence_ref],
            hard_failure_reasons=[] if passed else ["candidate_validation_failed"]),
        gt_advisory=dict(advisory_id="radik:gt:" + digest(dict(candidate=candidate_id, checks=checks)),
            candidate_ids=[candidate_id], selected_candidate_id=candidate_id,
            score_micros_by_candidate={candidate_id: 1000000 if passed else 0},
            source_artifact_type="GTAdvisoryReport", source_lifecycle_state="VALIDATED", actor_role="gt",
            attempted_effect="CREATE_ROOT_DECISION", target_artifact_type="RootDecision", advisory_only=True,
            creates_final_output=False, requests_effect=False),
        policy_state=dict(policy_id=POLICY, identity_passed=True, scope_passed=passed, hard_policy_passed=passed,
            allow_accept=passed, conflict_policy="DEFER", no_candidate_policy="NO_UPDATE"),
        permission_state=dict(permission_required=permission_ref is not None, user_permission_present=permission_ref is not None,
            permission_scope_valid=passed, permission_ref=permission_ref),
        temporal_state=dict(temporal_valid=temporal, expired=not temporal, not_before_satisfied=True,
            time_envelope_ref="radik:time:" + str(now)),
        conflict_state=dict(material_unresolved_conflict=bool(packet.conflict_set_ids), conflict_set_ids=list(packet.conflict_set_ids)),
        prior_root_state=dict(prior_decision_id=None, prior_decision=None, prior_selected_candidate_id=None))
    result = roots.decide_root_v01(kernel=kernel, decision_input=root_input)
    require(not roots.validate_root_decision_result_v01(kernel=kernel, decision_input=root_input, result=result), "root_invalid_result")
    return kernel, root_input, result


def root_plain(review):
    kernel, root_input, result = review
    require(not roots.validate_root_decision_result_v01(kernel=kernel, decision_input=root_input, result=result), "root_invalid_result")
    return dict(kernel=plain(kernel), input=roots.root_decision_input_to_plain_dict_v01(root_input),
        result=roots.root_decision_result_to_plain_dict_v01(result))


def document_transaction_id(task_id, topic):
    return "radik:transaction:" + digest(dict(task=task_id, topic=topic))


def _native_semantic_family(scope, product, provenance):
    """Public native construction; no downstream response is its own ancestor."""
    strategy, now = product["strategy"], scope["created_at"]
    task_id, root_id, transaction_id = scope["task_id"], scope["root_id"], scope["transaction_id"]
    material = dict(scope=scope, orchestrator_product=product, orchestrator_provenance=provenance)
    candidates = tuple(avf.AVFCandidateV02("compare_" + name, "Source-bound " + name + " comparison",
        base_viability_score=0.9 if name == strategy else 0.8) for name in ("claims", "topics")) + (
        avf.AVFCandidateV02("reuse_expired", "Forbidden expired material", base_viability_score=1.0, ttl_valid=False),)
    evaluated = avf.evaluate_avf_candidates_v02(avf.AVFEvaluationInputV02(task_id, candidates))
    selected = evaluated.top_candidate_id
    require(selected == "compare_" + strategy and evaluated.hard_masked_count == 1, "avf_route_refused")
    review = root_review("route:" + digest(material), dict(selected=selected, avf=plain(evaluated), route_material=material),
        dict(allowed=selected in ("compare_claims", "compare_topics"), two_sources=len(scope["source_descriptors"]) == 2,
            checked_orchestrator_product=True, checked_producer_binding=True), now,
        transaction_id=transaction_id, owning_root_id=root_id, task_id=task_id)
    require(review[2].decision == "ACCEPT", "root_route_refused")
    ref = digest(material)
    business = packets.build_business_request_context_packet(packet_id="radik:business:" + ref,
        created_by="radik:owned_intake", domain=DOMAIN, request_id=task_id,
        business_subject="two_allowed_documents", requested_action="compare_documents",
        user_visible_summary="Compare approved source spans under the current bounded document request.")
    business_ref = dict(source="G2C_BUSINESS_REQUEST_CONTEXT_PACKET_V01", packet_id=business["packet_id"], request_id=task_id, domain_id=DOMAIN)
    route_id, vectors, guards = "radik:route:" + selected, ("radik:vector:" + ref,), ("radik:guard:current_root",)
    route = packets.build_orchestrator_route_context_packet(packet_id="radik:route_context:" + ref,
        created_by="radik:runtime_canonicalization", source_refs=(business_ref,), domain=DOMAIN,
        allowed_routes=(route_id,), required_guards=guards, selected_vector_ids=vectors,
        route_validation_expectations=dict(root_review_required=True, selected_only_allowed_vectors=True),
        orchestrator_is_root=False, creates_action_commit_packet=False, calls_connectors=False)
    proposal = dict(proposal_id="radik:orchestrator_product:" + digest(dict(product=product, provenance=provenance)), suggested_route=route_id,
        selected_vector_ids=vectors, required_guards=guards, reason="The checked route producer selected " + strategy,
        confidence=0.75, needs_review=True, uncertainty_notes=(product["uncertainty"],), root_review_required=True,
        truth_claimed=False, authority_claimed=False, action_permission_claimed=False, final_output_claimed=False,
        connector_command_claimed=False, drs_write_claimed=False, plan_graph_claimed=False, bypass_root_claimed=False,
        # Native C strings are compact semantic observations, not document
        # carriers. Exact fragments live only in the checked app projection.
        semantic_observations=("The approved route requests bounded UTF-8 spans from two distinct logical sources.",
            "Producer profile: " + provenance["producer_kind"] + ". External document truth remains unverified."),
        route_reasoning=("Consume only the producer's checked source spans.",),
        rejected_route_reasoning=("Expired and foreign inputs are forbidden.",), guard_reasoning=("Fresh local Root reviewed this route.",),
        vector_reasoning=("The requested strategy and evidence needs constrain downstream selection.",),
        authority_boundary_reasoning=("Document and model text remain evidence.",))
    structured = rationale.build_orchestrator_structured_rationale(observed_semantics=proposal["semantic_observations"],
        route_selection_reason=proposal["route_reasoning"], rejected_routes=proposal["rejected_route_reasoning"],
        required_guards_reasoning=proposal["guard_reasoning"], selected_vector_reasoning=proposal["vector_reasoning"],
        uncertainty_notes=proposal["uncertainty_notes"], authority_boundary=proposal["authority_boundary_reasoning"], root_review_required=True)
    structured_validation = rationale.validate_orchestrator_structured_rationale(structured)
    require(structured_validation["accepted"], "orchestrator_rationale_refused")
    def evidence(text, kind):
        return packets.semantic_evidence_item(text, source="runtime_canonicalization", evidence_kind=kind, confidence_label="medium")
    bsep = packets.build_bounded_semantic_evidence_packet(packet_id="radik:bsep:" + ref, source_refs=(business_ref,),
        domain=DOMAIN, source_role="orchestrator", target_role="architect", source_route_id=route_id,
        source_proposal_id=proposal["proposal_id"], source_context_packet_id=route["packet_id"],
        source_structured_rationale_ref="structured_rationale_v01:" + digest(structured),
        observed_semantic_facts=tuple(evidence(text, "observed_fact") for text in proposal["semantic_observations"]),
        missing_evidence=(evidence("External document truth is not independently established.", "missing_evidence"),),
        uncertainty_notes=(evidence(product["uncertainty"], "uncertainty"),),
        risk_boundary_notes=(evidence("SAVE requires its own current packet.", "risk_boundary"),),
        rejected_action_routes=(evidence("Arbitrary paths and effects are forbidden.", "rejected_route"),),
        required_approvals_or_conditions=(evidence("Independent local Root validation.", "approval_condition"),),
        authority_boundary_notes=(evidence("No permission transfers through evidence.", "authority_boundary"),),
        selected_vector_ids=vectors, required_guards=guards)
    packet_validation = packets.validate_bounded_semantic_evidence_packet(bsep, route_context_packet=route,
        orchestrator_proposal=proposal, structured_rationale_validation=structured_validation)
    require(packet_validation["accepted"], "native_bsep_relational_refused")
    args = {f.name: (() if f.name.endswith(("file_contents", "observations", "projections")) else None)
        for f in fields(router.ExecutionModeSourceContextV01)}
    args.update(business_request_context_packet=business, bsep_packet=bsep, bsep_route_context_packet=route,
        bsep_orchestrator_proposal=proposal, bsep_structured_rationale=structured, g2a_evaluation_time=now,
        g2a_evaluation_time_source="radik:trusted_clock", g2a_evaluation_context_id=task_id)
    source = router.build_execution_mode_source_context_v01(**args)
    binding = router.build_execution_mode_bsep_binding_v01(request_id=task_id, transaction_id=transaction_id,
        owning_root_id=root_id, domain_id=DOMAIN, source_context=source)
    require(router.validate_execution_mode_source_context_v01(source).validation_status == "PASS", "native_semantic_source_refused")
    evidence_body = dict(avf=plain(evaluated), root=root_plain(review), producer_kind=provenance["producer_kind"],
        orchestrator_product=product, orchestrator_provenance=provenance,
        structured_rationale_validation=structured_validation, relational_bsep_validation=packet_validation)
    native_sha = digest(dict(source=plain(source), binding=plain(binding), route_review=root_plain(review), evidence=evidence_body))
    return source, binding, review, evidence_body, native_sha


def _architect_projection(scope, product, provenance, sources, binding, native_sha):
    return dict(version=membrane.PROJECTION_VERSION, family_ref="radik:semantic_family:" + native_sha,
        task_id=scope["task_id"], root_id=scope["root_id"], topic=scope["topic"], strategy=product["strategy"],
        created_at=scope["created_at"], valid_to=scope["valid_to"], policy_revision=scope["policy"]["revision"],
        policy_sha256=digest(scope["policy"]), source_descriptors=scope["source_descriptors"],
        orchestrator_provenance=provenance, bsep_binding=plain(binding),
        approved_evidence=membrane.approved_evidence(product, sources), route_uncertainty=product["uncertainty"],
        validation_obligations=list(contracts.CRITIC_CHECKS), continuation=scope["continuation"])


def source_context(product, provenance, sources, *, task_id, topic, goal, criterion, root_id, transaction_id,
                   now, policy, continuation=None, informational_profile=False):
    """Create the membrane after its actual producer and before the Architect.

    The runtime session checks its owned observation receiver before this call;
    this adapter independently checks product/provenance scope and native law.
    The deterministic memory profile is named explicitly and claims no LLM turn.
    """
    descriptors = membrane.checked_sources(sources)
    product = contracts.validate_orchestrator(product, sources, task_id=task_id, topic=topic, continuation=continuation)
    memory = provenance.get("producer_kind") == "DETERMINISTIC_MEMORY_ROUTE" if type(provenance) is dict else False
    provenance = membrane.checked_provenance(provenance, product, role="orchestrator", task_id=task_id, root_id=root_id, memory=memory)
    require(type(now) is int and now >= 0 and type(goal) is str and goal
        and type(criterion) is str and criterion and type(root_id) is str and root_id, "semantic_scope_shape")
    require(transaction_id == document_transaction_id(task_id, topic), "semantic_transaction_scope")
    from . import document_temporal as temporal
    require(type(informational_profile) is bool, "informational_profile_shape")
    family_version = temporal.FAMILY_VERSION if informational_profile else membrane.FAMILY_VERSION
    family_ttl = temporal.INFORMATION_SECONDS if informational_profile else membrane.FAMILY_TTL
    scope = dict(version=family_version, task_id=task_id, root_id=root_id, topic=topic, goal=goal,
        criterion=criterion, transaction_id=transaction_id, source_descriptors=descriptors,
        policy=membrane.checked_policy(policy), created_at=now, valid_to=now+family_ttl,
        continuation=json.loads(canonical(continuation)))
    source, binding, review, evidence_body, native_sha = _native_semantic_family(scope, product, provenance)
    projection = _architect_projection(scope, product, provenance, sources, binding, native_sha)
    require(len(canonical(projection)) <= 32768, "semantic_projection_byte_budget")
    return membrane.create_family(source, binding, review, native_sha, scope=scope, product=product,
        provenance=provenance, projection=projection, evidence=evidence_body)


def source_family_witness(family):
    membrane.require_live_family(family)
    return dict(version=membrane.FAMILY_VERSION, scope=family.scope, product=family.product, provenance=family.provenance,
        projection=family.projection, native_sha256=family.native_sha256, source_context=plain(family.source_context),
        binding=plain(family.binding), route_review=root_plain(family.route_review), evidence=family.evidence)


def source_family_record(family):
    """Bounded memory data; the complete typed witness is persisted separately."""
    witness = source_family_witness(family)
    return dict(version="radik.semantic.source_family_record.v02", scope=witness["scope"], product=witness["product"],
        provenance=witness["provenance"], projection=witness["projection"], native_sha256=witness["native_sha256"],
        root_decision_id=witness["route_review"]["result"]["decision_id"], root_sha256=digest(witness["route_review"]),
        full_witness_sha256=digest(witness))


def family_ttl(version):
    from . import document_temporal as temporal
    require(version in (membrane.FAMILY_VERSION, temporal.FAMILY_VERSION), "semantic_family_version")
    return membrane.FAMILY_TTL if version == membrane.FAMILY_VERSION else temporal.INFORMATION_SECONDS


def validate_source_family(family, sources, *, task_id, topic, goal, criterion, root_id, now, policy):
    from . import document_temporal as temporal
    membrane.require_live_family(family)
    scope = family.scope
    require(set(scope) == {"version", "task_id", "root_id", "topic", "goal", "criterion", "transaction_id",
        "source_descriptors", "policy", "created_at", "valid_to", "continuation"}
        and scope["version"] in (membrane.FAMILY_VERSION, temporal.FAMILY_VERSION) and all(scope[key] == value for key, value in
        dict(task_id=task_id, topic=topic, goal=goal, criterion=criterion, root_id=root_id).items()), "semantic_family_scope")
    require(type(now) is int and scope["created_at"] <= now < scope["valid_to"]
        and scope["valid_to"] == scope["created_at"] + family_ttl(scope["version"]), "semantic_family_time")
    require(scope["policy"] == membrane.checked_policy(policy) and scope["source_descriptors"] == membrane.checked_sources(sources),
        "semantic_family_current_source_policy")
    product = contracts.validate_orchestrator(family.product, sources, task_id=task_id, topic=topic)
    memory = family.kind == "DETERMINISTIC_MEMORY_ROUTE"
    membrane.checked_provenance(family.provenance, product, role="orchestrator", task_id=task_id, root_id=root_id, memory=memory)
    require(not roots.validate_root_decision_result_v01(kernel=family.route_review[0], decision_input=family.route_review[1], result=family.route_review[2])
        and family.route_review[2].decision == "ACCEPT", "semantic_family_root_refused")
    route_material = dict(scope=scope, orchestrator_product=product, orchestrator_provenance=family.provenance)
    root_data = root_plain(family.route_review)
    route_claim = dict(selected="compare_" + product["strategy"], avf=family.evidence["avf"], route_material=route_material)
    claims = root_data["input"]["root_review_packet"]["synthesis_proposal"]["normalized_claims"]
    candidate_id = "route:" + digest(route_material)
    require(root_data["result"]["selected_candidate_id"] == candidate_id
        and any(claim["claim_id"] == candidate_id and claim["object_or_value"] == route_claim for claim in claims)
        and family.evidence["root"] == root_data and family.evidence["orchestrator_product"] == product
        and family.evidence["orchestrator_provenance"] == family.provenance, "semantic_family_root_source_binding")
    structured_validation = rationale.validate_orchestrator_structured_rationale(family.source_context.bsep_structured_rationale)
    packet_validation = packets.validate_bounded_semantic_evidence_packet(family.source_context.bsep_packet,
        route_context_packet=family.source_context.bsep_route_context_packet,
        orchestrator_proposal=family.source_context.bsep_orchestrator_proposal, structured_rationale_validation=structured_validation)
    require(structured_validation["accepted"] and packet_validation["accepted"], "semantic_family_relational_bsep")
    binding = router.build_execution_mode_bsep_binding_v01(request_id=task_id, transaction_id=scope["transaction_id"],
        owning_root_id=root_id, domain_id=DOMAIN, source_context=family.source_context)
    actual_sha = digest(dict(source=plain(family.source_context), binding=plain(binding),
        route_review=root_plain(family.route_review), evidence=family.evidence))
    require(binding == family.binding and actual_sha == family.native_sha256, "semantic_family_native_binding_changed")
    require(family.projection == _architect_projection(scope, product, family.provenance, sources, binding, actual_sha),
        "semantic_family_projection_changed")
    return family


def validate_historical_source_family(witness, sources):
    """Rebuild historical identities only; discard every typed Root/source object."""
    require(type(witness) is dict and set(witness) == {"version", "scope", "product", "provenance", "projection",
        "native_sha256", "root_decision_id", "root_sha256", "full_witness_sha256"}
        and witness["version"] == "radik.semantic.source_family_record.v02", "saved_semantic_family_shape")
    from . import document_temporal as temporal
    scope = witness["scope"]
    require(type(scope) is dict and set(scope) == {"version", "task_id", "root_id", "topic", "goal", "criterion", "transaction_id",
        "source_descriptors", "policy", "created_at", "valid_to", "continuation"}
        and scope["version"] in (membrane.FAMILY_VERSION, temporal.FAMILY_VERSION) and type(scope["created_at"]) is int and scope["created_at"] >= 0
        and scope["policy"] == membrane.checked_policy(scope["policy"])
        and scope["source_descriptors"] == membrane.checked_sources(sources)
        and scope["transaction_id"] == document_transaction_id(scope["task_id"], scope["topic"])
        and scope["valid_to"] == scope["created_at"] + family_ttl(scope["version"]), "saved_semantic_family_scope")
    product = contracts.validate_orchestrator(witness["product"], sources, task_id=scope["task_id"], topic=scope["topic"])
    provenance = membrane.checked_provenance(witness["provenance"], product, role="orchestrator",
        task_id=scope["task_id"], root_id=scope["root_id"], memory=witness["provenance"]["producer_kind"] == "DETERMINISTIC_MEMORY_ROUTE")
    source, binding, review, evidence_body, native_sha = _native_semantic_family(scope, product, provenance)
    full = dict(version=membrane.FAMILY_VERSION, scope=scope, product=product, provenance=provenance,
        projection=_architect_projection(scope, product, provenance, sources, binding, native_sha),
        native_sha256=native_sha, source_context=plain(source), binding=plain(binding), route_review=root_plain(review), evidence=evidence_body)
    rebuilt = dict(version="radik.semantic.source_family_record.v02", scope=scope, product=product, provenance=provenance,
        projection=full["projection"], native_sha256=native_sha, root_decision_id=full["route_review"]["result"]["decision_id"],
        root_sha256=digest(full["route_review"]), full_witness_sha256=digest(full))
    require(rebuilt == witness, "saved_semantic_family_public_reconstruction")
    return witness


def validate_save_inputs(definition, inputs):
    errors = firewall.validate_capability_values_v01(definition.input_fields, inputs)
    if not errors:
        try:
            job = CURRENT_SAVE.get()
            require(job is not None, "save_context_missing")
            data = values(inputs)
            require(data == job["inputs"], "save_exact_result_binding")
            current = job["current"]()
            require(current["sources"] == job["sources"], "save_current_source_mismatch")
            policy = current["policy"]
            require(policy["save_allowed"] and policy["consent_ref"] == job["consent_ref"], "save_policy_withdrawn")
            require(current["now"] < min(policy["valid_to"], job["expires"]), "save_expired")
            require(re.fullmatch(r"[a-z0-9_]{1,32}\.txt", data["target"]), "save_unsafe_target")
        except (ValueError, KeyError, TypeError) as exc:
            errors = (str(exc),)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=inputs,
        invocation_id=None, valid=not errors, reason_codes=errors)


def execute_save(invocation):
    job = CURRENT_SAVE.get()
    require(job is not None and invocation.packet_id == job["packet_id"] and invocation.owning_root_id == job["root_id"], "save_invocation_scope")
    require(validate_save_inputs(job["definition"], invocation.inputs).valid, "save_current_validation")
    data = values(invocation.inputs)
    directory = job["directory"]
    require(not directory.is_symlink() and directory.resolve() == job["directory_identity"], "save_directory_changed")
    target = directory / data["target"]
    require(not target.is_symlink() and target.parent.resolve() == job["directory_identity"], "save_owned_target")
    payload = data["content"].encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    readback = target.read_bytes()
    require(readback == payload, "save_readback_mismatch")
    job["readback"] = dict(target=data["target"], sha256=digest(readback), bytes=len(readback), invocation_id=invocation.invocation_id)
    return records(dict(sha256=("TEXT", digest(readback))))


def validate_save_outputs(definition, invocation, output):
    errors = firewall.validate_capability_values_v01(definition.output_fields, output)
    job = CURRENT_SAVE.get()
    if not errors and (job is None or job.get("readback", {}).get("invocation_id") != invocation.invocation_id or
        values(output)["sha256"] != job["readback"]["sha256"]):
        errors = ("save_output_binding",)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=output,
        invocation_id=invocation.invocation_id, valid=not errors, reason_codes=errors)


def admit_save(host_ref):
    funcs = validate_save_inputs, validate_save_outputs, execute_save
    snapshots = tuple(hosts.observe_local_capability_code_v01(fn) for fn in funcs)
    shape = (("content", "TEXT"), ("result_ref", "REFERENCE"), ("source_scope_sha256", "TEXT"), ("target", "TEXT"))
    semantics = firewall.build_capability_business_semantics_v01(operation_key="radik.document.save.v01",
        selected_action_class="mock_action:radik_owned_save", logical_effect_class="RADIK_OWNED_OUTPUT",
        logical_effect_namespace="radik.document.save.v01", business_object_class="DOMAIN_OBJECT", business_object_namespace="radik.output",
        input_bindings=tuple(firewall.build_capability_business_input_binding_v01(input_name=n, source_kind="RECORD", source_name=n,
            value_type=k) for n, k in shape))
    definition = firewall.build_capability_definition_v01(operation_id="radik.document.save.v01", version="v01",
        effect_kind="MOCK_CONSEQUENTIAL", business_semantics=semantics,
        input_fields=tuple(firewall.build_capability_field_v01(name=n, value_type=k, required=True, consequential=True) for n, k in shape),
        output_fields=(firewall.build_capability_field_v01(name="sha256", value_type="TEXT", required=True, consequential=False),),
        resource_refs=("radik:owned_output",), input_validator_ref=snapshots[0].public_symbol,
        output_validator_ref=snapshots[1].public_symbol, executor_ref=snapshots[2].public_symbol,
        code_sha256s=tuple((s.public_symbol, s.source_sha256) for s in snapshots))
    return hosts.admit_local_capability_v01(definition=definition, input_validator=funcs[0], output_validator=funcs[1], executor=funcs[2],
        catalogue_revision=0, host_instance_ref=host_ref)


def prepare_save(admitted, inputs, source, checks, *, root_id, task_id, transaction_id, consent_ref):
    """Prepare a genuine current pending owned output command without dispatch."""
    current = source.current()
    clock = source.sample()
    now = clock.evaluation_time
    expires = min(current["policy"]["valid_to"], now + PENDING_SAVE_SECONDS)
    require(expires > now and consent_ref == current["policy"]["consent_ref"], "save_no_current_consent")
    object_ref = "radik:output:" + digest(dict(task=task_id, inputs=values(inputs)))
    dep_id = "radik:dependency:" + digest(dict(task=task_id, object_ref=object_ref))
    sha = source.scope_sha256(current)
    ref = "radik:source_scope:" + sha
    provenance = ("radik:trusted_intake:" + task_id,)
    env = action.build_action_dependency_time_envelope_id_v01(dependency_id=dep_id, evidence_ref=ref,
        content_sha256=sha, freshness_policy_id=POLICY, source_provenance_refs=provenance,
        valid_from_utc=now, valid_to_utc=expires)
    dependency_record = action.build_dependency_set_candidate_record_v01(dependency_id=dep_id,
        dependency_class="DOMAIN_AUTHORIZATION_INPUT", evidence_ref=ref, content_sha256=sha, requirement_class="MANDATORY",
        time_envelope_id=env, freshness_policy_id=POLICY, source_provenance_refs=provenance, expected_accepting_local_root_id=root_id)
    dependency = action.build_dependency_set_candidate_v01(dependency_records=(dependency_record,))
    policy = action.build_action_authority_policy_profile_v01(policy_version=POLICY, owning_local_root_id=root_id,
        authority_rule_refs=("radik:current_local_root",), kill_switch_condition_refs=("radik:policy_withdrawn",),
        retry_policy="NON_CONSUMING_RETRY", supersession_policy="ROOT_DECISION_ONLY", logical_effect_namespace="radik.document.save.v01",
        allowed_logical_effect_classes=("RADIK_OWNED_OUTPUT",), allowed_business_object_namespaces=("radik.output",),
        allowed_corridor_classes=("radik.local.mock",))
    packet = action.build_native_action_commit_packet_v01(transaction_id=transaction_id, owning_local_root_id=root_id,
        canonical_permission_ref=consent_ref, selected_canonical_action="mock_action:radik_owned_save",
        normalized_subject_scope=action.build_action_subject_scope_profile_v01(included_subject_refs=(root_id,), excluded_subject_refs=()),
        normalized_target_scope=action.build_action_target_scope_profile_v01(included_target_refs=("radik:owned_output",), excluded_target_refs=()),
        normalized_permission_scope=action.build_action_permission_scope_profile_v01(allowed_action_classes=("mock_action:radik_owned_save",),
            forbidden_action_classes=(), allowed_adapter_ids=("mock_adapter:radik_owned_output",), forbidden_adapter_ids=(),
            required_approval_refs=(consent_ref,), prohibited_effect_classes=()),
        adapter_binding=action.build_action_adapter_binding_profile_v01(corridor_class="radik.local.mock",
            adapter_id="mock_adapter:radik_owned_output", adapter_kind="DETERMINISTIC_MOCK", adapter_version="v01"),
        dependency_candidate=dependency, temporal_authority=action.build_action_temporal_authority_profile_v01(issued_at_utc=now,
            expires_at_utc=expires, ttl_seconds=expires-now, temporal_policy_version=POLICY), authority_policy=policy,
        business_object_identity=action.build_action_business_object_identity_profile_v01(business_object_class="DOMAIN_OBJECT",
            business_object_namespace="radik.output", business_object_ref=object_ref, owning_effect_root_id=root_id),
        consequential_effect_parameters=action.build_action_consequential_effect_parameters_profile_v01(
            amount_decimal=None, currency_code=None, quantity_decimal=None, parameter_records=inputs),
        evaluation_time=now, evaluation_time_source=clock.evaluation_time_source, evaluation_context_id=clock.evaluation_context_id,
        admitted_capability=admitted, inputs=inputs)
    candidate_id = packet.authorization_candidate.root_packet_authorization_candidate_id
    review = root_review(candidate_id, dict(candidate_id=candidate_id, candidate_kind="PACKET_AUTHORIZATION"), checks, now,
        transaction_id=transaction_id, owning_root_id=root_id, task_id=task_id, predicate="root_packet_authorization_candidate",
        permission_ref=consent_ref, temporal=packet.temporal_evaluation.executable)
    require(review[2].decision == "ACCEPT", "save_root_refused")
    root_data = roots.root_decision_input_to_plain_dict_v01(review[1])
    kwargs = {k: root_data[k] for k in ("post_vv_bundle", "gt_advisory", "policy_state", "permission_state",
        "temporal_state", "conflict_state", "prior_root_state")}
    kwargs["policy_state"]["policy_id"] = packet.authority_policy_fingerprint
    kwargs["temporal_state"]["time_envelope_ref"] = packet.temporal_authority_fingerprint
    required = [r.evidence_ref for r in dependency.dependency_records if r.requirement_class == "MANDATORY"]
    for key in ("required_evidence_refs", "provided_evidence_refs"):
        kwargs["post_vv_bundle"][key] = sorted(set(kwargs["post_vv_bundle"][key] + required))
    root_input = roots.build_root_decision_input_v01(transaction_id=transaction_id, target_root_id=root_id,
        root_review_packet=review[1].root_review_packet, **kwargs)
    review = review[0], root_input, roots.decide_root_v01(kernel=review[0], decision_input=root_input)
    projection = action.build_root_decision_candidate_projection_v01(candidate_kind="PACKET_AUTHORIZATION",
        projected_candidate_id=candidate_id, root_decision_kernel=review[0], root_decision_input=review[1], root_decision_result=review[2])
    bound = action.build_native_root_bound_action_commit_packet_v01(canonical_projection=packet, root_decision_projection=projection)
    profile = transitions.build_action_packet_transition_registry_profile_v01()
    events = []
    packet_id = bound.packet_identity.packet_id
    for rule_id in ("g2a_t01_activate_root_authorization", "g2a_t02_queue", "g2a_t03_pending"):
        rule = transitions.lookup_action_packet_transition_rule_v01(registry=profile, transition_rule_id=rule_id)
        bindings = tuple(action.build_transition_evidence_binding_v01(action_packet_transition_registry_profile=profile,
            transition_rule_id=rule_id, evidence_code=code, evidence_ref="radik:lifecycle:" + digest(dict(packet=packet_id, code=code)),
            evidence_sha256=digest(dict(packet=packet_id, root=review[2].decision_id, code=code)),
            validator_profile_id="radik:reviewed_owned_save_lifecycle.v01") for code in rule.required_evidence_codes)
        attempt = action.build_action_execution_attempt_identity_v01(packet_id=packet_id,
            idempotency_key=packet.idempotency_identity.idempotency_key, attempt_ordinal=1,
            evaluation_context_id=clock.evaluation_context_id) if rule_id == "g2a_t03_pending" else None
        event = action.build_action_packet_transition_event_v01(action_packet_transition_registry_profile=profile,
            transition_rule_id=rule_id, packet_id=packet_id, idempotency_key=packet.idempotency_identity.idempotency_key,
            previous_transition_event_id=events[-1].transition_event_id if events else None, owning_local_root_id=root_id,
            root_decision_ref=review[2].decision_id if not events else None, transition_evidence_bindings=bindings,
            dependency_set_candidate_fingerprint=packet.dependency_set_candidate_fingerprint,
            temporal_authority_fingerprint=packet.temporal_authority_fingerprint, evaluation_time=now,
            evaluation_time_source=clock.evaluation_time_source, evaluation_context_id=clock.evaluation_context_id,
            execution_attempt_identity=attempt, receipt_ref=None)
        if not events:
            reserve = action.build_idempotency_disposition_event_v01(idempotency_key=packet.idempotency_identity.idempotency_key,
                event_class="RESERVE", from_disposition="UNCLAIMED", to_disposition="RESERVED", from_owner_packet_id=None,
                to_owner_packet_id=packet_id, previous_disposition_event_id=None, cause_transition_event_ids=(event.transition_event_id,),
                root_decision_ref=review[2].decision_id, predecessor_packet_id=None, successor_packet_id=None,
                evidence_refs=tuple(sorted(b.transition_evidence_binding_id for b in bindings if b.evidence_code in
                    ("packet_genesis_valid", "source_root_authorization_valid", "idempotency_acquisition_valid"))),
                evaluation_time=now, evaluation_time_source=clock.evaluation_time_source, evaluation_context_id=clock.evaluation_context_id)
        events.append(event)
    step = action.build_common_corridor_step_v01(transaction_id=transaction_id, owning_local_root_id=root_id,
        packet_id=packet_id, authorization_candidate_id=candidate_id, action_class=packet.selected_canonical_action,
        adapter_binding=packet.adapter_binding, subject_scope=packet.normalized_subject_scope, target_scope=packet.normalized_target_scope,
        effect_parameters=packet.normalized_effect_parameters, issued_at_utc=now, expires_at_utc=expires)
    corridor = action.build_common_contract_fulfillment_corridor_v01(transaction_id=transaction_id, owning_local_root_id=root_id,
        packet_id=packet_id, corridor_class="radik.local.mock", steps=(step,))
    source.add_dependency(dependency_record, now, expires)
    return dict(root_bound=bound, corridor=corridor, corridor_step=step, transition_events=tuple(events), disposition_event=reserve,
        inputs=inputs, admission_id=admitted.admission_id), review, dependency_record, expires
