"""Native informational E source arguments for the ordinary dynamic Work graph."""
from hedgehog.kernel import abi_v01 as abi, integrity_replay_v01 as integrity
from hedgehog.kernel import continuous_delta_runtime_v01 as delta_runtime
from . import native_authority as authority
require,digest=authority.require,authority.digest


def build_arguments(task, updated_sources, changed_index, state, capture, observed_document, invalidation, graph_plan):
    """Public informational authority, with the existing document source/cell mapping."""
    from . import informational_core as informational
    from .informational_control import baseline_semantic_domain
    baseline, report, documents = task.d_baseline, task.information[0], state.documents
    domain=baseline_semantic_domain(task)
    require(state.carrier.domain_id==domain,'dynamic_delta_informational_domain_identity')
    effective_valid_to, _caps = informational.caps_for_task(task)
    effective_valid_to = min(state.valid_to, effective_valid_to)
    informational.temporal.require_remaining(effective_valid_to, task.source.clock(),
        informational.temporal.NATIVE_SECONDS+informational.temporal.CONSUMER_SECONDS)
    def artifact(payload, parents=()):
        return informational._artifact(task, payload, created_at=capture.evaluation_time,
            valid_to=state.valid_to, parents=parents)
    root_input = next(v for v in baseline.cell_inputs if v.parent_cell_id is None)
    projections = []
    cells = (root_input.cell_id, *root_input.ordered_planned_child_cell_ids) if graph_plan['native_scope'] == 'FULL_CLOSURE_NO_RETAINED_PROOF' else root_input.ordered_planned_child_cell_ids
    require(len(task.native_bridge['bindings'])==len(cells),'dynamic_delta_bridge_cell_inventory')
    for child_id,declared in zip(cells,task.native_bridge['bindings'],strict=True):
        child = next(v for v in baseline.cell_inputs if v.cell_id == child_id)
        seed = next(a for q, a in zip(baseline.queue_entries, baseline.queue_artifacts, strict=True)
            if q.queue_entry_id == child.ordered_initial_queue_entry_ids[0])
        body = abi.kernel_artifact_to_plain_dict_v01(seed)
        require(declared['cell_id']==child_id and declared['seed_artifact']==body
            and declared['business_leaves']==[task.native_declaration['leaves'][i] for i in declared['source_indices']],
            'dynamic_delta_cold_seed_binding_changed')
        projections.append(artifact(dict(projection_profile_id="g2e_baseline_runtime_artifact_projection_v01",
            projected_runtime_artifact=body, projected_runtime_artifact_sha256=digest(body)), (seed.artifact_id,)))
    before = (*documents, *projections)
    after = tuple(observed_document if v is documents[changed_index] else v for v in before)
    raw_edges = tuple(integrity.ArtifactDependencyEdgeV01(projection.artifact_id, documents[index].artifact_id)
        for projection, indices in zip(projections, [r['source_indices'] for r in task.native_bridge['bindings']], strict=True) for index in indices)
    manifest = integrity.build_artifact_manifest_v01(transaction_id=baseline.topology.transaction_id,
        profile=integrity.build_default_seal_profile_v01(), artifacts=tuple(abi.kernel_artifact_to_canonical_ref_v01(v) for v in before),
        dependency_edges=raw_edges, root_ownership_bindings=tuple(integrity.RootOwnershipBindingV01(v.artifact_id, task.root_id) for v in before),
        evidence_class_bindings=tuple(integrity.EvidenceClassBindingV01(v.artifact_id, "SOURCE_EVIDENCE") for v in before),
        authority_class_bindings=tuple(integrity.AuthorityClassBindingV01(v.artifact_id, v.authority_class) for v in before))
    replay = integrity.verify_artifact_replay_v01(manifest=manifest,
        payload_rows=tuple((v.artifact_id, abi.kernel_artifact_to_plain_dict_v01(v)["payload"]) for v in before), expected_manifest_hash=manifest.manifest_hash)
    source_context = delta_runtime.build_continuous_delta_source_context_v02(source_authority_kind="INFORMATIONAL",
        informational_carrier=state.carrier, informational_invalidation=invalidation,
        integrity_manifest=manifest, integrity_replay=replay, baseline_source_artifacts=before, observed_source_artifacts=after,
        g2b_resolution_report=report, g2b_reuse_certificate=report.reuse_certificate, g2b_writeback_evidence=None,
        g2c_source_context=baseline.source_context.g2c_source_context,
        baseline_g2c_route_eligibility_artifact=baseline.source_context.route_eligibility_artifact, baseline_g2d_execution_bundle=baseline,
        root_kernel=baseline.source_context.root_kernel, post_vv_profile=None, gt_profile=None,
        current_source_host=state.host, current_source_capture=capture)
    source_validation = delta_runtime.validate_continuous_delta_source_context_v01(source_context)
    require(source_validation.status == "PASS", "delta_current_source_family:" + repr(source_validation.reason_codes))
    common = dict(transaction_id=baseline.topology.transaction_id, owning_root_id=task.root_id, domain_id=domain,
        policy_version=report.query.policy_version, schema_versions=report.query.schema_versions,
        source_history_hash=report.query_evaluations[0].source_history_hash)
    basis, edges = delta_runtime.project_integrity_replay_dependency_edges_v01(manifest=manifest, replay=replay, source_artifacts=before,
        graph_version=delta_runtime.CONTINUOUS_DELTA_GRAPH_VERSION_V01,
        edge_projection_bindings=tuple((v.artifact_id, v.depends_on_artifact_id, ("/content_sha256",), "FIELD_CAUSAL") for v in raw_edges), **common)
    graph = delta_runtime.build_dependency_graph_index_v01(graph_basis_sha256=basis, graph_version=delta_runtime.CONTINUOUS_DELTA_GRAPH_VERSION_V01,
        manifest=manifest, replay=replay, source_artifacts=before, dependency_edges=edges, trace_refs=tuple(v.artifact_id for v in documents), **common)
    fingerprint_args = {k: common[k] for k in ("policy_version", "schema_versions", "source_history_hash")}
    fp_profile = delta_runtime.build_dependency_fingerprint_profile_v01()
    fingerprints = tuple(delta_runtime.build_dependency_fingerprint_v01(profile=fp_profile, graph=graph, dependency_edges=edges,
        source_artifacts=rows, **fingerprint_args) for rows in (before, after))
    old = abi.kernel_artifact_to_plain_dict_v01(documents[changed_index])
    new = abi.kernel_artifact_to_plain_dict_v01(observed_document)
    valid_from = authority.stamp(capture.evaluation_time)
    valid_to = authority.stamp(effective_valid_to)
    binding = delta_runtime.build_delta_source_binding_v01(request_id=baseline.runtime_report.request_id, transaction_id=common["transaction_id"],
        owning_root_id=task.root_id, domain_id=domain, baseline_source_artifact_id=documents[changed_index].artifact_id,
        baseline_source_artifact_type=documents[changed_index].artifact_type, baseline_source_artifact_sha256=digest(old),
        baseline_source_payload_sha256=digest(old["payload"]), observed_source_artifact_id=observed_document.artifact_id,
        observed_source_artifact_type=observed_document.artifact_type, observed_source_artifact_sha256=digest(new), observed_source_payload_sha256=digest(new["payload"]),
        baseline_report_id=baseline.runtime_report.report_id, baseline_graph_id=graph.graph_id, baseline_graph_version=graph.graph_version,
        baseline_policy_version=common["policy_version"], observed_policy_version=common["policy_version"], baseline_schema_versions=common["schema_versions"],
        observed_schema_versions=common["schema_versions"], baseline_source_history_hash=common["source_history_hash"], observed_source_history_hash=common["source_history_hash"],
        valid_from_utc=valid_from, valid_to_utc=valid_to, trace_refs=(documents[changed_index].artifact_id, observed_document.artifact_id))
    changed_fields = tuple(delta_runtime.build_changed_field_binding_v01(source_binding_id=binding.source_binding_id, json_pointer="/payload/" + key,
        prior_value_sha256=digest(old["payload"][key]), observed_value_sha256=digest(new["payload"][key]), change_class="FIELD_VALUE_CHANGE",
        observed_at_utc=valid_from, trace_refs=(binding.source_binding_id,)) for key in ("content_sha256", "source_revision", "text")
        if old["payload"][key] != new["payload"][key])
    changed_artifact = delta_runtime.build_changed_artifact_binding_v01(source_binding_id=binding.source_binding_id,
        baseline_artifact_id=documents[changed_index].artifact_id, baseline_artifact_type=documents[changed_index].artifact_type,
        baseline_payload_sha256=digest(old["payload"]), observed_artifact_id=observed_document.artifact_id, observed_artifact_type=observed_document.artifact_type,
        observed_payload_sha256=digest(new["payload"]), baseline_dependency_fingerprint=fingerprints[0], observed_dependency_fingerprint=fingerprints[1],
        change_class="ARTIFACT_SUCCESSOR", observed_at_utc=valid_from, trace_refs=(binding.source_binding_id,))
    delta = delta_runtime.build_world_state_delta_v01(ordered_source_binding_ids=(binding.source_binding_id,), request_id=binding.request_id,
        transaction_id=binding.transaction_id, owning_root_id=binding.owning_root_id, domain_id=binding.domain_id,
        baseline_report_id=baseline.runtime_report.report_id, baseline_graph_id=graph.graph_id, baseline_graph_version=graph.graph_version,
        observed_at_utc=valid_from, valid_from_utc=valid_from, valid_to_utc=valid_to,
        baseline_policy_version=common["policy_version"], observed_policy_version=common["policy_version"], baseline_schema_versions=common["schema_versions"],
        observed_schema_versions=common["schema_versions"], baseline_source_history_hash=common["source_history_hash"], observed_source_history_hash=common["source_history_hash"],
        ordered_changed_field_binding_ids=tuple(v.changed_field_binding_id for v in changed_fields), ordered_changed_artifact_binding_ids=(changed_artifact.changed_artifact_binding_id,),
        dependency_fingerprint_before=fingerprints[0], dependency_fingerprint_after=fingerprints[1], trace_refs=(graph.graph_id,))
    return dict(source_context=source_context, source_bindings=(binding,), changed_field_bindings=changed_fields,
        changed_artifact_bindings=(changed_artifact,), delta=delta, dependency_edges=edges, dependency_graph=graph, retained_profile='fractal_retained_work_v01' if graph_plan['native_scope'] == 'STRICT_SUBSET_ONE_NATIVE_CHILD' else None)

