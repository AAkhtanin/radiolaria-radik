"""Finite source-bound document Work and current native continuation adapters.

No provider is called here. PURE functions consume explicit bytes/proposals and
perform no I/O. Current intake, policy, Root, evidence I/O and SAVE are separate
trusted controller responsibilities. Import/install requires accepted source pins.
"""
from dataclasses import dataclass, field, fields, replace
from datetime import datetime
import json
from pathlib import Path
import re
import time

from hedgehog import action_commit_packet_v02 as action
from hedgehog import work_execution_host_v01 as hosts
from hedgehog import drs_semantic_address_v01 as address, drs_memory_resolution_v01 as memory
from hedgehog import drs_g2b_compatibility_v01 as compatibility, reuse_certificate_v01 as reuse
from hedgehog.kernel import abi_v01 as abi, effect_firewall_v01 as firewall
from hedgehog.kernel import work_composition_v01 as work, execution_mode_router_v01 as router
from hedgehog.kernel import fractal_runtime_v02 as fractal, continuous_delta_runtime_v01 as delta_runtime
from hedgehog.kernel import integrity_replay_v01 as integrity, transition_registry_v01 as transitions

from . import native_authority as authority
from . import contracts
from . import semantic_membrane as membrane
from .evidence import persist
from .memory import (MemorySelection, memory_origin_from_selection, validate_memory_origin,
    MEMORY_ORIGIN_VERSION, bounded_json_bytes, memory_payload_bytes, memory_require)

require, canonical, digest, plain = authority.require, authority.canonical, authority.digest, authority.plain
MAX_SOURCE_BYTES, MAX_RESULT_BYTES, MAX_CLAIMS, MAX_QUOTE_BYTES = 16384, 8192, 8, 512
SOURCE_KEYS = {"source_ref", "revision", "sha256"}
PROPOSAL_KEYS = {"version", "task_id", "topic", "strategy", "claims", "statement", "uncertainty"}
CLAIM_KEYS = {"source_ref", "revision", "sha256", "start", "end", "quote"}
MEMORY_WORK_OPERATION = 'radik.document.memory_consumer.v02'
MEMORY_WORK_PROJECTION = 'radik.document.memory_work_projection.v02'
MEMORY_WORK_FIELDS = ('projection', 'source_material', 'candidate', 'memory_origin', 'semantic_witness')


def normalize_source(value):
    require(type(value) is dict and SOURCE_KEYS | {"text"} <= set(value) <= SOURCE_KEYS | {"text", "observed_at"}, "source_shape")
    require(type(value["source_ref"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_:.-]{0,127}", value["source_ref"]), "source_logical_id")
    require(type(value["revision"]) is int and value["revision"] > 0 and type(value["text"]) is str, "source_revision_text")
    raw = value["text"].encode("utf-8")
    require(0 < len(raw) <= MAX_SOURCE_BYTES and value["sha256"] == digest(raw), "source_bytes_hash")
    return {k: value[k] for k in ("source_ref", "revision", "sha256", "text")}


def normalize_sources(sources):
    require(type(sources) in (list, tuple) and len(sources) == 2, "two_sources_required")
    result = tuple(normalize_source(v) for v in sources)
    require(result[0]["source_ref"] != result[1]["source_ref"], "source_ids_distinct")
    return result


def descriptors(sources):
    return [{k: source[k] for k in ("source_ref", "revision", "sha256")} for source in sources]


def validate_proposal(proposal, sources, *, task_id=None, topic=None):
    sources = normalize_sources(sources)
    require(type(proposal) is dict, "proposal_shape")
    checked = contracts.validate_proposal(proposal, sources,
        task_id=task_id or proposal.get("task_id"), topic=topic or proposal.get("topic"))
    expected_keys = PROPOSAL_KEYS | ({"validation_obligations"} if proposal.get("version") == "radik.document.candidate.v02" else set())
    require(type(proposal) is dict and set(proposal) == expected_keys and proposal["version"] in
        ("radik.document.proposal.v01", "radik.document.candidate.v02"), "proposal_shape")
    require(task_id is None or proposal["task_id"] == task_id, "proposal_foreign_task")
    require(topic is None or proposal["topic"] == topic, "proposal_foreign_topic")
    require(proposal["strategy"] in ("claims", "topics"), "proposal_strategy")
    require(type(proposal["claims"]) is list and 2 <= len(proposal["claims"]) <= MAX_CLAIMS, "proposal_claim_budget")
    require(type(proposal["statement"]) is str and 0 < len(proposal["statement"].encode()) <= 2048, "proposal_statement_budget")
    require(type(proposal["uncertainty"]) is str and 0 < len(proposal["uncertainty"].encode()) <= 512, "proposal_uncertainty")
    by_ref = {v["source_ref"]: v for v in sources}
    seen = set()
    for claim in proposal["claims"]:
        require(type(claim) is dict and set(claim) == CLAIM_KEYS, "claim_shape")
        source = by_ref.get(claim["source_ref"])
        require(source is not None and all(claim[k] == source[k] for k in SOURCE_KEYS), "claim_source_binding")
        start, end = claim["start"], claim["end"]
        raw = source["text"].encode()
        require(type(start) is type(end) is int and 0 <= start < end <= len(raw), "claim_byte_span")
        require(type(claim["quote"]) is str and len(claim["quote"].encode()) <= MAX_QUOTE_BYTES, "claim_quote_budget")
        try:
            quote = raw[start:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("claim_utf8_boundary") from exc
        require(quote == claim["quote"], "claim_quote_mismatch")
        seen.add(claim["source_ref"])
    require(seen == set(by_ref), "claim_each_source_required")
    return json.loads(canonical(checked))


def extraction(material):
    source = normalize_source(material["source"])
    claims = material["claims"]
    require(type(claims) is list and 0 < len(claims) <= MAX_CLAIMS, "extraction_claims")
    raw = source["text"].encode()
    if "semantic_selection" in material:
        membrane.validate_selection_proof(material["semantic_selection"], source, claims)
    seen = set()
    for claim in claims:
        require(set(claim) == CLAIM_KEYS and all(claim[k] == source[k] for k in SOURCE_KEYS), "extraction_source")
        require(type(claim["start"]) is type(claim["end"]) is int and 0 <= claim["start"] < claim["end"] <= len(raw), "extraction_span")
        require(raw[claim["start"]:claim["end"]].decode() == claim["quote"] and len(claim["quote"].encode()) <= MAX_QUOTE_BYTES, "extraction_quote")
        key = claim["start"], claim["end"]
        require(key not in seen, "extraction_duplicate_span")
        seen.add(key)
    return dict(**{k: source[k] for k in SOURCE_KEYS}, selected=claims)


def comparison(left, right, proposal):
    require(left["source_ref"] != right["source_ref"] and proposal["strategy"] in ("claims", "topics"), "comparison_scope")
    selected = left["selected"] + right["selected"]
    require(sorted(canonical(c) for c in selected) == sorted(canonical(c) for c in proposal["claims"]), "comparison_actual_branch_outputs")
    return dict(left=left, right=right, strategy=proposal["strategy"], statement=proposal["statement"],
        uncertainty=proposal["uncertainty"], conclusion_status="UNCERTAIN_INTERPRETATION",
        verified_scope="Cited UTF-8 byte spans and source identities; external truth and entailment are not certified.")


def validate_memory_consumer(data, *, task_id=None, memory_origin=None, evaluated_at=None, sources=None):
    """Recompute bounded memory business data inside each actual PURE seam.

    Historical lineage is evidence. It cannot replace current exact source
    bytes, the adapted candidate, current semantic witness or trusted dispatch.
    """
    memory_require(type(data) is dict and set(data) == set(MEMORY_WORK_FIELDS), 'memory_work_projection_shape')
    projection, candidate, witness = data['projection'], data['candidate'], data['semantic_witness']
    origin = validate_memory_origin(data['memory_origin'], now=evaluated_at)
    memory_require(type(projection) is dict and set(projection) == {'version', 'prior_task_id', 'proposal',
        'comparison', 'source_descriptors', 'memory_origin_sha256'}
        and projection['version'] == MEMORY_WORK_PROJECTION, 'memory_work_projection_shape')
    bounded_json_bytes(projection, limit=32768, size_code='memory_work_projection_budget',
        depth_code='memory_work_projection_budget')
    raw_sources = normalize_sources(data['source_material'])
    bounded_json_bytes(data['source_material'], limit=131072, size_code='memory_work_sources_budget',
        depth_code='memory_work_sources_budget')
    memory_require(projection['source_descriptors'] == descriptors(raw_sources)
        and origin['source_scope_sha256'] == digest(descriptors(raw_sources)), 'memory_work_sources')
    if sources is not None:
        memory_require(raw_sources == normalize_sources(sources), 'memory_work_sources')
    memory_require(projection['memory_origin_sha256'] == digest(origin)
        and (memory_origin is None or origin == memory_origin), 'memory_work_projection_origin')
    prior = projection['proposal']
    memory_require(type(projection['prior_task_id']) is str and 0 < len(projection['prior_task_id']) <= 128
        and type(prior) is dict and type(candidate) is dict and type(candidate.get('task_id')) is str
        and 0 < len(candidate['task_id']) <= 128 and prior['task_id'] == projection['prior_task_id']
        and candidate == dict(prior, task_id=candidate['task_id'])
        and (task_id is None or candidate['task_id'] == task_id)
        and origin['candidate_sha256'] == digest(prior), 'memory_work_candidate_binding')
    candidate = validate_proposal(candidate, raw_sources, task_id=candidate['task_id'], topic=candidate['topic'])
    memory_require(candidate['version'] == contracts.ARCHITECT_VERSION and type(witness) is dict
        and witness.get('producer_kind') == 'DETERMINISTIC_MEMORY_ROUTE', 'memory_work_candidate_binding')
    membrane.validate_business_witness(witness, candidate, descriptors(raw_sources))
    branches = tuple(extraction(dict(source=source, claims=[claim for claim in candidate['claims']
        if claim['source_ref'] == source['source_ref']])) for source in raw_sources)
    recomputed = comparison(branches[0], branches[1], candidate)
    memory_require(projection['comparison'] == recomputed, 'memory_work_business_comparison')
    return recomputed


def build_memory_work_projection(selection, saved, task):
    """After actual descent and full validation, retain only immediate lineage."""
    now = task.source.current()['now']
    origin = memory_origin_from_selection(selection,
        evaluated_at=task.semantic_provenance['memory_origin']['evaluated_at'])
    validate_memory_origin(origin, now=now)
    memory_require(origin == task.semantic_provenance['memory_origin'], 'memory_work_projection_origin')
    projection = dict(version=MEMORY_WORK_PROJECTION, prior_task_id=saved['task_id'],
        proposal=saved['proposal'], comparison=saved['comparison'], source_descriptors=descriptors(task.sources),
        memory_origin_sha256=digest(origin))
    data = dict(projection=projection, source_material=list(task.source.current()['full_sources']),
        candidate=task.proposal, memory_origin=origin, semantic_witness=task.semantic_witness)
    validate_memory_consumer(data, task_id=task.task_id, memory_origin=origin, evaluated_at=now, sources=task.sources)
    return data


def validate_saved_memory_work_record(final, saved):
    """Rebuild the v02 contract and evidence from the actual stored Work values.

    This pure historical check admits no callbacks or capability. Independent
    business recomputation is performed separately on these same stored values.
    """
    invocation, result = final['invocation'], final['result']
    input_values = authority.records({value['parameter_name']: (value['value_type'], value['value'])
        for value in invocation['inputs']})
    output_values = authority.records({value['parameter_name']: (value['value_type'], value['value'])
        for value in result['output']})
    input_ref = 'app.native_document.validate_pure_inputs'
    output_ref = 'app.native_document.validate_pure_outputs'
    executor_ref = 'app.native_document.execute_memory_consumer'
    source_sha = result['actual_implementation_sha256']
    definition = firewall.build_capability_definition_v01(operation_id=MEMORY_WORK_OPERATION,
        version='v02', effect_kind='PURE', business_semantics=None,
        input_fields=tuple(firewall.build_capability_field_v01(name=name, value_type='TEXT', required=True,
            consequential=False) for name in MEMORY_WORK_FIELDS),
        output_fields=tuple(firewall.build_capability_field_v01(name=name, value_type='TEXT', required=True,
            consequential=False) for name in ('comparison', 'left', 'right')),
        resource_refs=(), input_validator_ref=input_ref, output_validator_ref=output_ref,
        executor_ref=executor_ref, code_sha256s=tuple((name, source_sha) for name in (input_ref, output_ref, executor_ref)))
    input_evidence = firewall.build_capability_validation_evidence_v01(definition=definition,
        values=input_values, invocation_id=None, valid=True, reason_codes=())
    output_evidence = firewall.build_capability_validation_evidence_v01(definition=definition,
        values=output_values, invocation_id=invocation['invocation_id'], valid=True, reason_codes=())
    memory_require(invocation['definition_id'] == definition.definition_id
        and invocation['input_validation'] == plain(input_evidence)
        and result['output_validation'] == plain(output_evidence)
        and invocation['task_id'] == final['task_id'] == saved['task_id']
        and final['revision_id'] == saved['work']['revision_id']
        and invocation['owning_root_id'] == saved['work']['result_artifact']['owner_root_id']
        and invocation['candidate_id'] is None and invocation['packet_id'] is None and invocation['resource_refs'] == []
        and result['invocation_id'] == invocation['invocation_id']
        and result['admission_id'] == invocation['admission_id']
        and result['execution_attempt_id'] == invocation['execution_attempt_id']
        and result['consumed_input_sha256'] == firewall.capability_value_subject_sha256_v01(input_values)
        and result['outcome'] == 'SUCCEEDED', 'saved_memory_work_contract_binding')


def validate_pure_inputs(definition, inputs):
    errors = firewall.validate_capability_values_v01(definition.input_fields, inputs)
    try:
        if not errors:
            require(all(len(v.value.encode()) <= 131072 for v in inputs), "pure_input_budget")
            data = authority.values(inputs)
            if definition.operation_id == "radik.document.extract.v01":
                material = json.loads(data["material"])
                require(set(material) == {"source", "claims", "semantic_selection"}, "pure_current_extraction_membrane")
                extraction(material)
            elif definition.operation_id == "radik.document.compare.v01":
                left, right, proposal = json.loads(data["left"]), json.loads(data["right"]), json.loads(data["proposal"])
                membrane.validate_business_witness(json.loads(data["semantic_witness"]), proposal,
                    [{key: side[key] for key in ("source_ref", "revision", "sha256")} for side in (left, right)])
                comparison(left, right, proposal)
            elif definition.operation_id == MEMORY_WORK_OPERATION:
                memory_require(definition.version == 'v02', 'memory_work_projection_shape')
                validate_memory_consumer({key: json.loads(value) for key, value in data.items()})
            else:
                raise ValueError("pure_unknown_operation")
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        errors = (str(exc),)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=inputs,
        invocation_id=None, valid=not errors, reason_codes=errors)


def execute_extraction(invocation):
    output = extraction(json.loads(authority.values(invocation.inputs)["material"]))
    return authority.records(dict(material=("TEXT", canonical(output).decode())))


def execute_comparison(invocation):
    data = authority.values(invocation.inputs)
    left, right, proposal = json.loads(data["left"]), json.loads(data["right"]), json.loads(data["proposal"])
    membrane.validate_business_witness(json.loads(data["semantic_witness"]), proposal,
        [{key: side[key] for key in ("source_ref", "revision", "sha256")} for side in (left, right)])
    output = comparison(left, right, proposal)
    return authority.records(dict(comparison=("TEXT", canonical(output).decode())))


def execute_memory_consumer(invocation):
    data = authority.values(invocation.inputs)
    result = validate_memory_consumer({key: json.loads(value) for key, value in data.items()}, task_id=invocation.task_id)
    return authority.records(dict(comparison=("TEXT", canonical(result).decode()),
        left=("TEXT", canonical(result["left"]).decode()), right=("TEXT", canonical(result["right"]).decode())))


def validate_pure_outputs(definition, invocation, output):
    errors = firewall.validate_capability_values_v01(definition.output_fields, output)
    try:
        if not errors:
            data = authority.values(invocation.inputs)
            if definition.operation_id == "radik.document.extract.v01":
                expected = dict(material=canonical(extraction(json.loads(data["material"]))).decode())
            elif definition.operation_id == "radik.document.compare.v01":
                expected = dict(comparison=canonical(comparison(json.loads(data["left"]), json.loads(data["right"]), json.loads(data["proposal"]))).decode())
            elif definition.operation_id == MEMORY_WORK_OPERATION:
                memory_require(definition.version == 'v02', 'memory_work_projection_shape')
                result = validate_memory_consumer({key: json.loads(value) for key, value in data.items()}, task_id=invocation.task_id)
                expected = dict(comparison=canonical(result).decode(), left=canonical(result["left"]).decode(), right=canonical(result["right"]).decode())
            else:
                raise ValueError('pure_unknown_operation')
            require(authority.values(output) == expected, "pure_actual_output_binding")
    except (ValueError, KeyError, TypeError) as exc:
        errors = (str(exc),)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=output,
        invocation_id=invocation.invocation_id, valid=not errors, reason_codes=errors)


def admit_pure(operation, shape, output, executor, host_ref):
    funcs = validate_pure_inputs, validate_pure_outputs, executor
    snapshots = tuple(hosts.observe_local_capability_code_v01(fn) for fn in funcs)
    definition = firewall.build_capability_definition_v01(operation_id=operation,
        version='v02' if operation == MEMORY_WORK_OPERATION else 'v01', effect_kind="PURE", business_semantics=None,
        input_fields=tuple(firewall.build_capability_field_v01(name=n, value_type="TEXT", required=True, consequential=False) for n in shape),
        output_fields=tuple(firewall.build_capability_field_v01(name=n, value_type="TEXT", required=True, consequential=False) for n in output),
        resource_refs=(), input_validator_ref=snapshots[0].public_symbol, output_validator_ref=snapshots[1].public_symbol,
        executor_ref=snapshots[2].public_symbol, code_sha256s=tuple((s.public_symbol, s.source_sha256) for s in snapshots))
    return hosts.admit_local_capability_v01(definition=definition, input_validator=funcs[0], output_validator=funcs[1], executor=funcs[2],
        catalogue_revision=0, host_instance_ref=host_ref)


class CurrentDocumentSource:
    """Trusted callbacks re-observe allowed bytes, policy and wall time outside PURE."""
    def __init__(self, task_id, source_reader, policy_reader, clock):
        self.task_id, self.source_reader, self.policy_reader, self.clock = task_id, source_reader, policy_reader, clock
        now = int(clock())
        bridge = action.build_logical_time_bridge_v01(origin_utc_epoch_seconds=now, seconds_per_tick=1, bridge_policy_version=authority.POLICY)
        self.snapshot = hosts.TrustedWorkSourceSnapshotV01((), bridge, now, "radik:trusted_clock", task_id, 0)
        self.evaluation_time = now
        self.dependencies = {}

    def current(self):
        now = self.clock()
        require(type(now) is int and now >= self.snapshot.evaluation_time, "clock_regression")
        sources = normalize_sources(self.source_reader())
        policy = self.policy_reader()
        require(type(policy) is dict and set(policy) == {"save_allowed", "consent_ref", "valid_to", "revision", "workspace_ref"}, "policy_shape")
        require(type(policy["save_allowed"]) is bool and type(policy["valid_to"]) is int and type(policy["revision"]) is int,
            "policy_types")
        require(policy["consent_ref"] is None or type(policy["consent_ref"]) is str, "policy_consent")
        require(policy["workspace_ref"] == "radik:owned:output" and policy["revision"] >= 1, "policy_owned_workspace")
        return dict(sources=descriptors(sources), full_sources=sources, policy=dict(policy), now=now)

    def scope_sha256(self, current):
        return digest(dict(sources=current["sources"], policy=current["policy"]))

    def read_current_v01(self):
        current = self.current()
        observed = []
        for record, start, end in self.dependencies.values():
            sha = self.scope_sha256(current)
            env = action.build_action_dependency_time_envelope_id_v01(dependency_id=record.dependency_id, evidence_ref=record.evidence_ref,
                content_sha256=sha, freshness_policy_id=record.freshness_policy_id, source_provenance_refs=record.source_provenance_refs,
                valid_from_utc=start, valid_to_utc=end)
            observed.append(action.build_action_dependency_current_observation_v01(dependency_id=record.dependency_id,
                evidence_ref=record.evidence_ref, observed_content_sha256=sha, time_envelope_id=env, freshness_policy_id=record.freshness_policy_id,
                source_provenance_refs=record.source_provenance_refs, valid_from_utc=start, valid_to_utc=end,
                observed_at_utc=self.evaluation_time, observation_context_id=self.task_id))
        observations = tuple(sorted(observed, key=lambda v: v.dependency_id))
        changed = observations != self.snapshot.observations or self.evaluation_time != self.snapshot.evaluation_time
        self.snapshot = replace(self.snapshot, observations=observations,
            evaluation_time=self.evaluation_time, source_revision=self.snapshot.source_revision + int(changed))
        return self.snapshot

    def sample(self):
        # One integer UTC sample binds a native invocation. read_current still
        # re-reads actual source/policy bytes; input validation checks live expiry.
        self.evaluation_time = self.clock()
        return self.read_current_v01()

    def add_dependency(self, record, start, end):
        self.dependencies[record.dependency_id] = record, start, end
        self.sample()


@dataclass
class DocumentTask:
    task_id: str
    topic: str
    goal: str
    criterion: str
    root_id: str
    sources: tuple
    proposal: dict
    source: CurrentDocumentSource
    workspace: Path
    evidence_directory: Path
    common: dict
    catalogue: tuple
    route_evidence: dict
    on_event: object = None
    semantic_family: object = None
    critic_assessment: object = None
    semantic_provenance: object = None
    semantic_pipeline: object = None
    semantic_witness: object = None
    continuation_enabled: bool = False
    informational_profile: bool = False
    informational_origin: object = None
    host: object = None
    program: object = None
    results: tuple = ()
    accepted: object = None
    information: object = None
    d_source: object = None
    d_baseline: object = None
    pending: object = None
    delta_bundle: object = None
    delta_count: int = 0
    branch_slots: tuple = ("left0", "right0")
    branch_fields: tuple = ("material", "material")
    branch_result_ids: tuple = ()
    delta_arguments: object = None
    delta_expected: object = None
    last_retained_binding: object = None
    last_save: object = None
    stage: str = "BUILT"
    evidence_refs: list = field(default_factory=list)
    timings: list = field(default_factory=list)

    def emit(self, stage, **details):
        self.stage = stage
        if self.on_event is not None:
            self.on_event(dict(task_id=self.task_id, stage=stage, **details))

    def snapshot(self):
        return dict(task_id=self.task_id, topic=self.topic, stage=self.stage, sources=descriptors(self.sources),
            result_id=self.accepted.plain["result_id"] if self.accepted else None,
            native_work_attempts=len(self.host.work_attempts) if self.host else 0, delta_count=self.delta_count,
            timings=list(self.timings), evidence_refs=list(self.evidence_refs))


@dataclass(frozen=True)
class AcceptedDocumentResult:
    plain: dict
    task: DocumentTask
    program: object
    results: tuple
    result_artifact: object
    root_review: tuple

    @property
    def content(self):
        return self.plain["content"]


def literal(name, value):
    return work.WorkInputBindingV01(name, work.WorkLiteralV01(action.build_action_effect_parameter_record_v01(
        parameter_name=name, value_type="TEXT", value=canonical(value).decode())))


def validate_semantic_inputs(family, candidate, critic_assessment, provenance, sources, *, task_id, topic, goal,
                            criterion, root_id, now, policy):
    authority.validate_source_family(family, sources, task_id=task_id, topic=topic, goal=goal,
        criterion=criterion, root_id=root_id, now=now, policy=policy)
    candidate = contracts.validate_architect(candidate, sources, family.projection, task_id=task_id, topic=topic)
    continuation = family.scope["continuation"]
    if continuation is not None:
        retained_ref = continuation["unchanged_source"]["current"]["source_ref"]
        require([claim for claim in candidate["claims"] if claim["source_ref"] == retained_ref] == continuation["retained_claims"],
            "semantic_delta_retained_selection")
    assessment = contracts.validate_critic(critic_assessment, candidate, task_id=task_id, topic=topic)
    keys = {"orchestrator", "architect", "critic", "candidate_sha256", "pipeline_version"}
    require(type(provenance) is dict and set(provenance) in (keys, keys | {"memory_origin"})
        and provenance["pipeline_version"] == membrane.PIPELINE_VERSION
        and provenance["candidate_sha256"] == digest(candidate)
        and provenance["orchestrator"] == family.provenance, "semantic_pipeline_provenance")
    memory = family.kind == "DETERMINISTIC_MEMORY_ROUTE"
    membrane.checked_provenance(provenance["architect"], candidate, role="architect", task_id=task_id, root_id=root_id, memory=memory)
    membrane.checked_provenance(provenance["critic"], assessment, role="critic", task_id=task_id, root_id=root_id, memory=memory)
    memory_origin = provenance.get("memory_origin")
    if memory:
        validate_memory_origin(memory_origin, now=now)
    else:
        require(memory_origin is None and len({provenance[role]["response_id"] for role in ("orchestrator", "architect", "critic")}) == 3
            and len({provenance[role]["reservation_id"] for role in ("orchestrator", "architect", "critic")}) == 3,
            "semantic_distinct_actual_role_observations")
    normalized_provenance = dict(provenance, memory_origin=memory_origin)
    return dict(version=membrane.PIPELINE_VERSION, producer_kind=family.kind,
        source_family=authority.source_family_record(family), candidate_sha256=digest(candidate),
        critic_assessment=assessment, semantic_provenance=json.loads(canonical(normalized_provenance)),
        qualification="DETERMINISTIC_MEMORY_REVALIDATION_NO_NEW_LLM" if memory else "ACTUAL_BSEP_BEFORE_ARCHITECT")


def install_semantic_pipeline(task, family, assessment, provenance, base_pipeline):
    origin = dict(intent_ref="radik:intent:" + digest(dict(goal=task.goal, criterion=task.criterion)),
        bsep_ref=task.common["source_context"].bsep_packet["packet_id"],
        semantic_proposal_ref=task.common["semantic_proposal"].artifact_id)
    witness = dict(pipeline_version=membrane.PIPELINE_VERSION, producer_kind=family.kind,
        family_ref=family.family_ref, projection_sha256=digest(family.projection), candidate_sha256=digest(task.proposal),
        critic_sha256=digest(assessment), source_scope_sha256=digest(descriptors(task.sources)),
        source_binding_sha256=digest(plain(family.binding)), critic_provenance_sha256=digest(provenance["critic"]),
        origin_intent_ref=origin["intent_ref"], origin_bsep_ref=origin["bsep_ref"], origin_semantic_ref=origin["semantic_proposal_ref"])
    membrane.validate_business_witness(witness, task.proposal, descriptors(task.sources))
    task.semantic_family, task.critic_assessment, task.semantic_provenance = family, assessment, provenance
    task.semantic_witness = witness
    task.semantic_pipeline = dict(base_pipeline, work_origin=origin, business_witness=witness)


def validate_task_semantics(task):
    from .informational_document import require_family_profile
    require_family_profile(task.semantic_family, task.informational_profile)
    current = task.source.current()
    require(current["sources"] == descriptors(task.sources), "semantic_task_current_sources")
    base = validate_semantic_inputs(task.semantic_family, task.proposal, task.critic_assessment, task.semantic_provenance,
        task.sources, task_id=task.task_id, topic=task.topic, goal=task.goal, criterion=task.criterion,
        root_id=task.root_id, now=current["now"], policy=current["policy"])
    require(base == {key: value for key, value in task.semantic_pipeline.items() if key not in ("work_origin", "business_witness")},
        "semantic_task_pipeline_changed")
    membrane.validate_business_witness(task.semantic_witness, task.proposal, descriptors(task.sources))
    semantic_payload = abi.kernel_artifact_to_plain_dict_v01(task.common["semantic_proposal"])["payload"]
    require(semantic_payload["control_purpose"] == control_purpose(task), "semantic_control_purpose_changed")
    return current


def control_purpose(task):
    return "E_BASELINE_CONTROL" if task.continuation_enabled else "NOT_REQUIRED_INFORMATIONAL"


def build_task(task_id, topic, goal, sources, proposal, *, criterion, semantic_family, critic_assessment,
               semantic_provenance, root_id="root:radik", clock, source_reader, policy_reader,
               workspace, evidence_directory, on_event=None, continuation_enabled=False, informational_profile=False):
    sources = normalize_sources(sources)
    proposal = validate_proposal(proposal, sources, task_id=task_id, topic=topic)
    require(type(goal) is str and goal and type(criterion) is str and criterion, "task_goal_criterion")
    require(type(continuation_enabled) is bool, "task_continuation_profile")
    workspace, evidence_directory = Path(workspace), Path(evidence_directory)
    require(workspace.is_dir() and not workspace.is_symlink() and workspace.absolute() == workspace.resolve(), "task_owned_output")
    require(evidence_directory.is_dir() and not evidence_directory.is_symlink(), "task_owned_evidence")
    require(type(informational_profile) is bool and (not informational_profile or continuation_enabled), "informational_profile_requires_baseline")
    from . import informational_document as informational
    source_type = informational.InformationalDocumentSource if informational_profile else CurrentDocumentSource
    source = source_type(task_id, source_reader, policy_reader, clock)
    if informational_profile:
        informational.require_no_effects(source)
    horizon = informational.temporal.INFORMATION_SECONDS if informational_profile else 3600
    require(source.current()["sources"] == descriptors(sources), "task_intake_current_mismatch")
    informational.require_family_profile(semantic_family, informational_profile)
    current = source.current()
    pipeline = validate_semantic_inputs(semantic_family, proposal, critic_assessment, semantic_provenance, sources,
        task_id=task_id, topic=topic, goal=goal, criterion=criterion, root_id=root_id, now=current["now"], policy=current["policy"])
    transaction_id = semantic_family.binding.transaction_id
    material = dict(goal=goal, criterion=criterion, sources=descriptors(sources), proposal=proposal, semantic_pipeline=pipeline,
        control_purpose="E_BASELINE_CONTROL" if continuation_enabled else "NOT_REQUIRED_INFORMATIONAL")
    common_source, route_evidence = semantic_family.source_context, semantic_family.evidence
    semantic_artifact = abi.build_kernel_artifact_v01(abi_version="v1.0", artifact_id="radik:semantic:" + digest(material),
        artifact_type="SemanticArchitectProposal", schema_version="v1", transaction_id=transaction_id,
        owner_root_id=root_id, source_component="radik:checked_semantic_architect_adapter", authority_class="ADVISORY", lifecycle_state="PROPOSED",
        payload=material, trace_refs=(task_id, "radik:intent:" + digest(dict(goal=goal, criterion=criterion))),
        parent_refs=(common_source.bsep_packet["packet_id"],),
        time_envelope=dict(pt_created_at=authority.stamp(clock()), kt_asof=authority.stamp(clock()), et_observed_at=None,
            ct_session_anchor=task_id, ttl_seconds=horizon, freshness_class="static",
            valid_from=authority.stamp(clock()), valid_to=authority.stamp(clock()+horizon)))
    host_ref = "host:" + root_id + ":" + digest(task_id)[:16]
    catalogue = (admit_pure("radik.document.extract.v01", ("material",), ("material",), execute_extraction, host_ref),
        admit_pure("radik.document.compare.v01", ("left", "right", "proposal", "semantic_witness"), ("comparison",), execute_comparison, host_ref),
        admit_pure(MEMORY_WORK_OPERATION, MEMORY_WORK_FIELDS, ("comparison", "left", "right"), execute_memory_consumer, host_ref),
        authority.admit_save(host_ref))
    task = DocumentTask(task_id, topic, goal, criterion, root_id, sources, proposal, source, workspace, evidence_directory,
        dict(catalogue=catalogue, source_context=common_source, semantic_proposal=semantic_artifact), catalogue, route_evidence, on_event)
    task.continuation_enabled = continuation_enabled
    task.informational_profile = informational_profile
    install_semantic_pipeline(task, semantic_family, critic_assessment, semantic_provenance, pipeline)
    task.evidence_refs.append(persist(task.evidence_directory, "pre_architect_semantic_family", authority.source_family_witness(semantic_family)))
    task.evidence_refs.append(persist(task.evidence_directory, "checked_semantic_pipeline", task.semantic_pipeline))
    return task


def build_information(task,material,accepted_review):
    from .informational_control import build_information as build
    return build(task,material,accepted_review)


def build_d_source(task,information):
    from .informational_control import build_d_source as build
    return build(task,information)


def initialize_task(task, items):
    require(task.host is None, "task_already_started")
    candidate = work.build_work_program_candidate_v01(task_id=task.task_id, previous_revision_id=None,
        intent_ref="radik:intent:" + digest(dict(goal=task.goal, criterion=task.criterion)),
        bsep_ref=task.common["source_context"].bsep_packet["packet_id"],
        semantic_proposal_ref=task.common["semantic_proposal"].artifact_id, catalogue_revision=0,
        budget=work.WorkBudgetV01(8, 4, 0, 12, 2), items=items, trigger_evidence_refs=(), **task.common)
    program = work.materialize_work_program_v01(candidate, **task.common)
    policy = work.build_work_task_policy_v01(candidate, **task.common, host_instance_ref=task.catalogue[0].host_instance_ref,
        definition_ids=tuple(sorted(a.definition.definition_id for a in task.catalogue)), resource_refs=("radik:owned_output",))
    clock = task.source.sample()
    host = hosts.build_root_work_execution_host_v01(owning_root_id=task.root_id,
        registry=action.build_empty_action_commit_packet_registry_v02(), catalogue=task.catalogue, packet_bindings=(),
        current_dependency_observations=clock.observations, logical_time_bridge=clock.logical_time_bridge, trusted_source=task.source,
        task_policies=(policy,))
    work.enroll_work_program_v01(host, program, **task.common, expected_revision=host.state_revision)
    task.host, task.program = host, program


def continuation_context(task):
    return work.work_continuation_context_v01(task.host, task_id=task.task_id, expected_revision=task.host.state_revision)


def advance(task, program):
    require(task.source.current()["sources"] == descriptors(task.sources), "work_intake_changed")
    start = time.monotonic()
    outcome = work.advance_work_program_v01(program, **task.common, host_map={task.root_id: task.host},
        continuation_context=continuation_context(task))
    require(work.validate_work_continuation_outcome_v01(outcome, context=continuation_context(task), **task.common) == (True, ()), "work_outcome_invalid")
    require(outcome.status == "COMPLETED" and all(v.status == "COMPLETED" for v in outcome.results), "work_not_completed")
    task.program, task.results = program, outcome.results
    task.timings.append(dict(phase="native_work", seconds=time.monotonic()-start, work_count=len(outcome.results)))
    return work.work_program_result_to_artifact_v01(program, outcome.results, **task.common,
        host_map={task.root_id: task.host}, continuation_context=continuation_context(task))


def render_result(compared):
    lines = [compared["statement"], "", "Проверенные основания:"]
    for side in ("left", "right"):
        material = compared[side]
        lines.append(material["source_ref"] + " / revision " + str(material["revision"]) + " / sha256 " + material["sha256"])
        for claim in material["selected"]:
            lines.append("  [" + str(claim["start"]) + ":" + str(claim["end"]) + "] " + claim["quote"])
    lines.extend(("", "Ограничения: " + compared["uncertainty"],
        "Сопоставление является интерпретацией. Проверены ссылки и точные байты цитат; истинность внешних документов не удостоверена."))
    content = "\n".join(lines) + "\n"
    require(len(content.encode()) <= MAX_RESULT_BYTES, "accepted_result_byte_budget")
    return content


def result_material(task, compared, artifact):
    return dict(task_id=task.task_id, topic=task.topic, goal=task.goal, criterion=task.criterion,
        sources=descriptors(task.sources), proposal=task.proposal, comparison=compared,
        work_artifact_ref=artifact.artifact_id, work_artifact_sha256=digest(abi.kernel_artifact_to_plain_dict_v01(artifact)),
        semantic_pipeline_sha256=digest(task.semantic_pipeline))


def accept_result(task, artifact, *, make_baseline=False):
    validate_task_semantics(task)
    require(not make_baseline or (task.continuation_enabled and task.d_baseline is None), "control_baseline_scope_or_duplicate")
    combine = task.results[-1]
    compared = json.loads(next(v.value for v in combine.result.output if v.parameter_name == "comparison"))
    material = result_material(task, compared, artifact)
    require(task.source.current()["sources"] == descriptors(task.sources), "accept_current_source_mismatch")
    review = authority.root_review("radik:result_candidate:" + digest(material), material,
        dict(native_work=True, source_spans=True, current_sources=True, uncertain_external_truth=compared["conclusion_status"] == "UNCERTAIN_INTERPRETATION"),
        task.source.clock(), transaction_id=task.common["semantic_proposal"].transaction_id, owning_root_id=task.root_id,
        task_id=task.task_id, bsep_ref=task.common["source_context"].bsep_packet["packet_id"], topology_ref=task.program.topology_artifact.artifact_id)
    require(review[2].decision == "ACCEPT", "result_root_refused")
    if make_baseline:
        compact = dict(task_id=task.task_id, source_scope_sha256=digest(descriptors(task.sources)),
            native_work_ref=artifact.artifact_id, native_work_sha256=material["work_artifact_sha256"], accepted_root_ref=review[2].decision_id)
        task.information = build_information(task, compact, review)
        task.d_source = build_d_source(task, task.information)
        task.emit("NATIVE_D_START", purpose="E_BASELINE_CONTROL", required_work_review=False)
        start = time.monotonic()
        baseline, validation = fractal.run_fractal_runtime_v02(task.d_source)
        require(baseline is not None and validation.status == "PASS", "native_D:" + repr(validation.reason_codes))
        require(fractal.validate_fractal_runtime_execution_bundle_v02(baseline).status == "PASS", "native_D_supplied_validation")
        task.d_baseline = baseline
        task.timings.append(dict(phase="native_D", seconds=time.monotonic()-start, executed_cells=len(baseline.cell_results)))
        task.evidence_refs.append(persist(task.evidence_directory, "native_d_return", baseline))
        task.emit("NATIVE_D_RETURN", status=validation.status)
        if task.informational_profile:
            from . import informational_document as informational
            informational.prepare_origin(task)
            task.emit("INFORMATIONAL_ORIGIN_ENROLLED")
    now = task.source.clock()
    current = task.source.current()
    require(current["sources"] == descriptors(task.sources), "final_current_source_mismatch")
    validate_task_semantics(task)
    result_valid_to = now+600
    if task.informational_profile:
        from . import informational_document as informational
        informational.require_publication(task)
        now = informational.publication_readback(task)
        result_valid_to = min(task.informational_origin.valid_to, now+informational.temporal.RESULT_REUSE_SECONDS)
    final_material = dict(material, control_purpose=control_purpose(task),
        native_d_report_ref=task.d_baseline.runtime_report.report_id if task.d_baseline is not None else None,
        native_e_report_ref=task.delta_bundle.runtime_report.report_id if task.delta_bundle is not None else None)
    control_completed = task.d_baseline is not None and task.d_baseline.runtime_report.runtime_outcome == "COMPLETED"
    review = authority.root_review("radik:final_candidate:" + digest(final_material), final_material,
        dict(actual_native_work=True, required_control_completed=not task.continuation_enabled or control_completed, current_sources=True), now,
        transaction_id=task.common["semantic_proposal"].transaction_id, owning_root_id=task.root_id, task_id=task.task_id)
    require(review[2].decision == "ACCEPT", "final_root_refused")
    task.evidence_refs.append(persist(task.evidence_directory, "native_business_history",
        dict(history=work.inspect_work_task_history_v01(continuation_context(task)),
            completed_work=task.host.completed_work, work_attempts=task.host.work_attempts,
            events=task.host.events)))
    artifact_plain = abi.kernel_artifact_to_plain_dict_v01(artifact)
    body = dict(version="radik.document.result.v02", task_id=task.task_id, topic=task.topic, goal=task.goal, criterion=task.criterion,
        proposal=task.proposal, proposal_id="radik:model_proposal:" + digest(task.proposal), strategy=task.proposal["strategy"],
        sources=descriptors(task.sources), comparison=compared, content=render_result(compared),
        work=dict(revision_id=task.program.candidate.revision_id, result_artifact_ref=artifact.artifact_id,
            result_artifact_sha256=digest(artifact_plain), result_artifact=artifact_plain, combine_result_id=combine.result.result_id,
            left_result_id=task.branch_result_ids[0], right_result_id=task.branch_result_ids[1],
            root_material_sha256=digest(final_material)), root=authority.root_plain(review), root_binding_sha256=digest(authority.root_plain(review)),
        native_d_report_ref=task.d_baseline.runtime_report.report_id if task.d_baseline is not None else None,
        native_e_report_ref=task.delta_bundle.runtime_report.report_id if task.delta_bundle is not None else None,
        evidence_refs=list(task.evidence_refs), semantic_pipeline=task.semantic_pipeline,
        control_purpose=control_purpose(task), accepted_at=now, valid_to=result_valid_to)
    body["result_id"] = "radik:result:" + digest(dict(work=artifact.artifact_id, root=review[2].decision_id, comparison=compared))
    body["result_sha256"] = digest(body)
    bounded_json_bytes(body, limit=131072, size_code='saved_outcome_budget', depth_code='saved_outcome_depth_limit',
        stage='ACCEPTED_RESULT_PREPUBLICATION')
    memory_payload_bytes(body, task.sources, task_id=task.task_id, topic_id=task.topic, intent=task.goal,
        criterion=task.criterion, stage='ACCEPTED_RESULT_PREPUBLICATION')
    if task.informational_profile:
        informational.publication_readback(task)
    accepted = AcceptedDocumentResult(body, task, task.program, task.results, artifact, review)
    task.accepted = accepted
    task.evidence_refs.append(persist(task.evidence_directory, "accepted_document_result", body))
    task.emit("ACCEPTED_RESULT", result_id=body["result_id"])
    return accepted


def run_task(task):
    require(task.host is None, "task_already_started")
    require(task.semantic_family.kind == "ACTUAL_ORCHESTRATOR_OBSERVATION", "cold_actual_role_pipeline_required")
    validate_task_semantics(task)
    extract, compare = task.catalogue[:2]
    branches = tuple(work.WorkItemV01(name, extract.definition.definition_id, task.root_id,
        (literal("material", dict(source=source, claims=[v for v in task.proposal["claims"] if v["source_ref"] == source["source_ref"]],
            semantic_selection=membrane.selection_proof(task.semantic_family, task.proposal, source))),),
        (), (), None, None) for name, source in zip(("left0", "right0"), task.sources, strict=True))
    combine = work.WorkItemV01("combine0", compare.definition.definition_id, task.root_id,
        (work.WorkInputBindingV01("left", work.WorkOutputBindingV01("left0", "material", "TEXT")),
         work.WorkInputBindingV01("right", work.WorkOutputBindingV01("right0", "material", "TEXT")), literal("proposal", task.proposal),
         literal("semantic_witness", task.semantic_witness)),
        (), ("left0", "right0"), None, None)
    initialize_task(task, (*branches, combine))
    task.emit("NATIVE_WORK_START")
    artifact = advance(task, task.program)
    task.branch_result_ids = tuple(v.result.result_id for v in task.results[:2])
    accepted = accept_result(task, artifact, make_baseline=task.continuation_enabled)
    current = task.source.current()
    if task.continuation_enabled and not task.informational_profile and current["policy"]["save_allowed"] and current["policy"]["consent_ref"] is not None and current["now"] < current["policy"]["valid_to"]:
        prepare_pending(task, "pending_" + digest(task.task_id)[:16] + ".txt")
    return accepted


def consume_memory(task, selection):
    require(task.host is None, "task_already_started")
    require(type(selection) is MemorySelection, "memory_checked_selection_required")
    require(selection.material["topic_id"] == task.topic and selection.material["intent"] == task.goal and
        selection.material["criterion"] == task.criterion, "memory_selected_scope")
    saved = validate_persisted_outcome(selection.material["outcome"], task.sources)
    require(saved["version"] == "radik.document.result.v02" and task.semantic_family.kind == "DETERMINISTIC_MEMORY_ROUTE",
        "memory_qualified_current_pipeline_required")
    validate_task_semantics(task)
    require(selection.material["sources"] == descriptors(task.sources), "memory_selected_current_sources")
    require(digest(selection.material) == selection.payload_sha256 and
        selection.descent["opened_payload_fingerprints"] == [selection.payload_sha256] and
        selection.descent["opened_record_ids"] == [selection.record_id] and
        selection.descent["bytes_opened"] == len(canonical(selection.material)) and
        selection.descent["executed_descent_class"] == "OPEN_ONE_ARTIFACT" and
        selection.descent["limits_respected"] and not selection.descent["reason_codes"], "memory_actual_descent_payload_binding")
    require(selection.root_decision_id != selection.historical_root_decision_id, "memory_fresh_root_required")
    origin = task.semantic_provenance["memory_origin"]
    require(origin["result_id"] == saved["result_id"] and origin["result_sha256"] == saved["result_sha256"]
        and origin["candidate_sha256"] == digest(saved["proposal"])
        and origin["descent_id"] == selection.descent["memory_descent_result_id"], "memory_semantic_origin_descent")
    task.evidence_refs.append(persist(task.evidence_directory, "memory_business_consumer_selection", selection))
    consumer = task.catalogue[2]
    data = build_memory_work_projection(selection, saved, task)
    item = work.WorkItemV01("memory0", consumer.definition.definition_id, task.root_id,
        tuple(literal(key, data[key]) for key in MEMORY_WORK_FIELDS), (), (), None, None)
    initialize_task(task, (item,))
    task.branch_slots, task.branch_fields = ("memory0", "memory0"), ("left", "right")
    task.emit("NATIVE_MEMORY_CONSUMER_START", record_id=selection.record_id)
    artifact = advance(task, task.program)
    task.branch_result_ids = (task.results[0].result.result_id, task.results[0].result.result_id)
    accepted = accept_result(task, artifact, make_baseline=task.continuation_enabled)
    current = task.source.current()
    if task.continuation_enabled and not task.informational_profile and current["policy"]["save_allowed"] and current["policy"]["consent_ref"] is not None and current["now"] < current["policy"]["valid_to"]:
        prepare_pending(task, "pending_" + digest(task.task_id)[:16] + ".txt")
    return accepted


def validate_saved_semantic_pipeline(saved, sources):
    pipeline = saved["semantic_pipeline"]
    require(type(pipeline) is dict and set(pipeline) == {"version", "producer_kind", "source_family", "candidate_sha256",
        "critic_assessment", "semantic_provenance", "qualification", "work_origin", "business_witness"}
        and pipeline["version"] == membrane.PIPELINE_VERSION, "saved_semantic_pipeline_shape")
    family = authority.validate_historical_source_family(pipeline["source_family"], sources)
    scope, projection, provenance = family["scope"], family["projection"], pipeline["semantic_provenance"]
    require(all(scope[key] == saved[key] for key in ("task_id", "topic", "goal", "criterion"))
        and pipeline["producer_kind"] == family["provenance"]["producer_kind"]
        and scope["created_at"] <= saved["accepted_at"] < scope["valid_to"], "saved_semantic_pipeline_scope")
    candidate = contracts.validate_architect(saved["proposal"], sources, projection, task_id=saved["task_id"], topic=saved["topic"])
    assessment = contracts.validate_critic(pipeline["critic_assessment"], candidate, task_id=saved["task_id"], topic=saved["topic"])
    require(type(provenance) is dict and set(provenance) == {"orchestrator", "architect", "critic", "candidate_sha256", "pipeline_version", "memory_origin"}
        and provenance["pipeline_version"] == membrane.PIPELINE_VERSION
        and provenance["orchestrator"] == family["provenance"]
        and provenance["candidate_sha256"] == pipeline["candidate_sha256"] == digest(candidate), "saved_semantic_producer_bindings")
    memory = pipeline["producer_kind"] == "DETERMINISTIC_MEMORY_ROUTE"
    if memory:
        origin = provenance['memory_origin']
        if type(origin) is dict and origin.get('version') == MEMORY_ORIGIN_VERSION:
            validate_memory_origin(origin, now=saved['accepted_at'])
        else:
            require(type(origin) is dict and set(origin) ==
                {"result_id", "result_sha256", "candidate_sha256", "descent_id"}, "saved_semantic_memory_origin")
    else:
        require(provenance["memory_origin"] is None and len({provenance[role]["response_id"] for role in
            ("orchestrator", "architect", "critic")}) == 3 and len({provenance[role]["reservation_id"] for role in
            ("orchestrator", "architect", "critic")}) == 3, "saved_distinct_actual_role_producers")
    for role, product in (("architect", candidate), ("critic", assessment)):
        membrane.checked_provenance(provenance[role], product, role=role, task_id=saved["task_id"], root_id=scope["root_id"], memory=memory)
    require(pipeline["qualification"] == ("DETERMINISTIC_MEMORY_REVALIDATION_NO_NEW_LLM" if memory else "ACTUAL_BSEP_BEFORE_ARCHITECT"),
        "saved_semantic_qualification")
    require(type(pipeline["work_origin"]) is dict and set(pipeline["work_origin"]) == {"intent_ref", "bsep_ref", "semantic_proposal_ref"},
        "saved_semantic_origin_shape")
    witness = pipeline["business_witness"]
    membrane.validate_business_witness(witness, candidate, saved["sources"])
    require(witness["family_ref"] == projection["family_ref"] and witness["projection_sha256"] == digest(projection)
        and witness["critic_sha256"] == digest(assessment) and witness["critic_provenance_sha256"] == digest(provenance["critic"])
        and witness["source_binding_sha256"] == digest(projection["bsep_binding"])
        and witness["origin_intent_ref"] == pipeline["work_origin"]["intent_ref"] ==
            "radik:intent:" + digest(dict(goal=saved["goal"], criterion=saved["criterion"]))
        and witness["origin_bsep_ref"] == pipeline["work_origin"]["bsep_ref"]
        and witness["origin_semantic_ref"] == pipeline["work_origin"]["semantic_proposal_ref"], "saved_semantic_business_witness")
    return pipeline


def validate_persisted_outcome(saved, sources):
    """Verify historical data bindings without reconstructing live authority."""
    sources = normalize_sources(sources)
    require(type(saved) is dict and saved.get("version") in ("radik.document.result.v01", "radik.document.result.v02"), "saved_outcome_shape")
    current_profile = saved["version"] == "radik.document.result.v02"
    expected_keys = {"version", "task_id", "topic", "goal", "criterion", "proposal", "proposal_id", "strategy", "sources", "comparison",
        "content", "work", "root", "root_binding_sha256", "native_d_report_ref", "native_e_report_ref", "evidence_refs", "accepted_at", "valid_to",
        "result_id", "result_sha256"}
    if current_profile:
        expected_keys.update(("semantic_pipeline", "control_purpose"))
    require(set(saved) == expected_keys, "saved_outcome_closed_fields")
    require(set(saved["work"]) == {"revision_id", "result_artifact_ref", "result_artifact_sha256", "result_artifact", "combine_result_id",
        "left_result_id", "right_result_id", "root_material_sha256"}, "saved_work_closed_fields")
    bounded_json_bytes(saved, limit=131072, size_code='saved_outcome_budget', depth_code='saved_outcome_depth_limit')
    require(saved["result_sha256"] == digest({k: v for k, v in saved.items() if k != "result_sha256"}), "saved_outcome_hash")
    require(saved["sources"] == descriptors(sources), "saved_current_sources")
    proposal = validate_proposal(saved["proposal"], sources, task_id=saved["task_id"], topic=saved["topic"])
    if current_profile:
        validate_saved_semantic_pipeline(saved, sources)
    require(saved["proposal_id"] == "radik:model_proposal:" + digest(proposal), "saved_proposal_hash")
    expected = tuple(extraction(dict(source=source, claims=[v for v in proposal["claims"] if v["source_ref"] == source["source_ref"]]))
        for source in sources)
    require(saved["comparison"] == comparison(expected[0], expected[1], proposal), "saved_comparison_binding")
    require(saved["content"] == render_result(saved["comparison"]), "saved_content_binding")
    artifact_data = saved["work"]["result_artifact"]
    arguments = dict(artifact_data, trace_refs=tuple(artifact_data["trace_refs"]), parent_refs=tuple(artifact_data["parent_refs"]))
    artifact = abi.build_kernel_artifact_v01(**arguments)
    require((artifact.artifact_type, artifact.source_component, artifact.authority_class, artifact.lifecycle_state) ==
        ("ResultProposal", "work_composition", "EVIDENCE_ONLY", "PROPOSED") and artifact.trace_refs ==
        (saved["task_id"], saved["work"]["revision_id"]), "saved_work_producer_profile")
    require(not abi.validate_kernel_artifact_v01(artifact) and abi.kernel_artifact_to_plain_dict_v01(artifact) == artifact_data, "saved_work_abi")
    require(artifact.artifact_id == saved["work"]["result_artifact_ref"] and digest(artifact_data) == saved["work"]["result_artifact_sha256"], "saved_work_artifact_hash")
    rows = artifact_data["payload"]["work_results"]
    final = next((v for v in rows if v["result"] and v["result"]["result_id"] == saved["work"]["combine_result_id"]), None)
    require(final is not None and final["status"] == "COMPLETED", "saved_actual_combine")
    output = next((v for v in final["result"]["output"] if v["parameter_name"] == "comparison"), None)
    require(output is not None and json.loads(output["value"]) == saved["comparison"], "saved_actual_work_output")
    root = saved["root"]
    require(set(root) == {"kernel", "input", "result"} and root["result"]["decision"] == "ACCEPT" and
        saved["root_binding_sha256"] == digest(root), "saved_root_provenance_hash")
    material = dict(task_id=saved["task_id"], topic=saved["topic"], goal=saved["goal"], criterion=saved["criterion"],
        sources=saved["sources"], proposal=proposal, comparison=saved["comparison"], work_artifact_ref=artifact.artifact_id,
        work_artifact_sha256=digest(artifact_data), native_d_report_ref=saved["native_d_report_ref"], native_e_report_ref=saved["native_e_report_ref"])
    if current_profile:
        material["semantic_pipeline_sha256"] = digest(saved["semantic_pipeline"])
        require(saved["control_purpose"] in ("NOT_REQUIRED_INFORMATIONAL", "E_BASELINE_CONTROL")
            and ((saved["native_d_report_ref"] is None and saved["native_e_report_ref"] is None)
                if saved["control_purpose"] == "NOT_REQUIRED_INFORMATIONAL" else saved["native_d_report_ref"] is not None),
            "saved_control_purpose")
        material["control_purpose"] = saved["control_purpose"]
        semantic_input = next((value for value in final["invocation"]["inputs"] if value["parameter_name"] == "semantic_witness"), None)
        require(semantic_input is not None and json.loads(semantic_input["value"]) == saved["semantic_pipeline"]["business_witness"],
            "saved_actual_semantic_witness_consumption")
        bounded_memory_profile = False
        if saved['semantic_pipeline']['producer_kind'] == 'DETERMINISTIC_MEMORY_ROUTE':
            origin = saved['semantic_pipeline']['semantic_provenance']['memory_origin']
            invocation_inputs = final['invocation']['inputs']
            names = {value['parameter_name'] for value in invocation_inputs}
            bounded_memory_profile = len(invocation_inputs) == len(MEMORY_WORK_FIELDS) and names == set(MEMORY_WORK_FIELDS)
            legacy_memory_profile = len(invocation_inputs) == 4 and names == {'material', 'source_scope', 'candidate', 'semantic_witness'}
            memory_require((bounded_memory_profile and origin.get('version') == MEMORY_ORIGIN_VERSION)
                or (legacy_memory_profile and set(origin) == {'result_id', 'result_sha256', 'candidate_sha256', 'descent_id'}),
                'saved_memory_work_input_binding')
        if bounded_memory_profile:
            bounded_json_bytes(saved, limit=131072, size_code='saved_outcome_budget', depth_code='saved_outcome_depth_limit')
            memory_require(len(rows) == 1 and final['work_id'] == 'memory0'
                and saved['work']['left_result_id'] == saved['work']['right_result_id'] == final['result']['result_id'],
                'saved_memory_work_input_binding')
            invocation_inputs = final['invocation']['inputs']
            memory_require(type(invocation_inputs) is list and len(invocation_inputs) == len(MEMORY_WORK_FIELDS)
                and {value['parameter_name'] for value in invocation_inputs} == set(MEMORY_WORK_FIELDS)
                and all(value['value_type'] == 'TEXT' for value in invocation_inputs), 'saved_memory_work_input_binding')
            data = {value['parameter_name']: json.loads(value['value']) for value in invocation_inputs}
            origin = saved['semantic_pipeline']['semantic_provenance']['memory_origin']
            recomputed = validate_memory_consumer(data, task_id=saved['task_id'], memory_origin=origin,
                evaluated_at=saved['accepted_at'], sources=sources)
            memory_require(data['candidate'] == saved['proposal']
                and data['semantic_witness'] == saved['semantic_pipeline']['business_witness']
                and recomputed == saved['comparison'], 'saved_memory_projection_binding')
            expected_outputs = {'comparison': canonical(recomputed).decode(),
                'left': canonical(recomputed['left']).decode(), 'right': canonical(recomputed['right']).decode()}
            actual_outputs = final['result']['output']
            memory_require(len(actual_outputs) == 3 and {value['parameter_name'] for value in actual_outputs} == set(expected_outputs)
                and all(value['value_type'] == 'TEXT' and value['value'] == expected_outputs[value['parameter_name']]
                    for value in actual_outputs), 'saved_memory_work_output_binding')
            validate_saved_memory_work_record(final, saved)
    require(saved["work"]["root_material_sha256"] == digest(material), "saved_root_material_hash")
    candidate = "radik:final_candidate:" + digest(material)
    claims = root["input"]["root_review_packet"]["synthesis_proposal"]["normalized_claims"]
    require(any(v["claim_id"] == candidate and v["object_or_value"] == material for v in claims), "saved_root_claim_binding")
    require(root["result"]["selected_candidate_id"] == candidate, "saved_root_selected_candidate")
    require(root["input"]["target_root_id"] == root["result"]["target_root_id"] == artifact.owner_root_id, "saved_root_owner")
    # Pure historical identity reconstruction, not current permission. The
    # resulting objects are discarded and never enter a Host or effect packet.
    checks = dict(actual_native_work=True, required_control_completed=True, current_sources=True) if current_profile else \
        dict(actual_native_work=True, native_d_completed=True, current_sources=True)
    historical = authority.root_review(candidate, material, checks, saved["accepted_at"],
        transaction_id=artifact.transaction_id, owning_root_id=artifact.owner_root_id, task_id=saved["task_id"])
    require(authority.root_plain(historical) == root, "saved_root_public_identity_reconstruction")
    require(saved["result_id"] == "radik:result:" + digest(dict(work=artifact.artifact_id,
        root=root["result"]["decision_id"], comparison=saved["comparison"])), "saved_result_id")
    require(type(saved["accepted_at"]) is int and type(saved["valid_to"]) is int and saved["accepted_at"] < saved["valid_to"], "saved_time_shape")
    return json.loads(canonical(saved))


def validate_outcome(outcome, sources):
    require(type(outcome) is AcceptedDocumentResult and outcome.task.accepted is outcome, "outcome_actual_task_origin")
    task = outcome.task
    validate_task_semantics(task)
    require(outcome.plain["version"] == "radik.document.result.v02" and outcome.plain["semantic_pipeline"] == task.semantic_pipeline,
        "outcome_actual_current_semantic_pipeline")
    require(task.source.current()["sources"] == descriptors(normalize_sources(sources)), "outcome_current_intake")
    ok, reasons = work.validate_work_program_result_v01(outcome.program, outcome.results, **task.common,
        host_map={task.root_id: task.host}, continuation_context=continuation_context(task))
    require(ok, "outcome_native_work:" + repr(reasons))
    artifact = work.work_program_result_to_artifact_v01(outcome.program, outcome.results, **task.common,
        host_map={task.root_id: task.host}, continuation_context=continuation_context(task))
    require(artifact == outcome.result_artifact and authority.root_plain(outcome.root_review) == outcome.plain["root"], "outcome_actual_root_work_binding")
    return validate_persisted_outcome(outcome.plain, sources)


def save_job(task, target):
    saved = validate_outcome(task.accepted, task.sources)
    current = task.source.current()
    policy = current["policy"]
    require(policy["save_allowed"] and policy["consent_ref"] is not None and current["now"] < policy["valid_to"], "save_no_current_policy")
    require(re.fullmatch(r"[a-z0-9_]{1,32}\.txt", target), "save_unsafe_target")
    data = dict(content=saved["content"], result_ref=saved["result_id"], source_scope_sha256=digest(saved["sources"]), target=target)
    job = dict(inputs=data, sources=saved["sources"], consent_ref=policy["consent_ref"], expires=min(policy["valid_to"], current["now"]+authority.PENDING_SAVE_SECONDS),
        current=task.source.current, directory=task.workspace, directory_identity=task.workspace.resolve(), root_id=task.root_id,
        definition=task.catalogue[3].definition, packet_id=None)
    inputs = authority.records({k: ("REFERENCE" if k == "result_ref" else "TEXT", v) for k, v in data.items()})
    return job, inputs


def prepare_pending(task, target):
    require(task.continuation_enabled and task.information is not None and task.d_baseline is not None,
        "pending_declared_control_baseline_required")
    job, inputs = save_job(task, target)
    token = authority.CURRENT_SAVE.set(job)
    try:
        prepared, review, dependency, expires = authority.prepare_save(task.catalogue[3], inputs, task.source,
            dict(accepted_result=True, exact_current_sources=True, owner_policy=True), root_id=task.root_id,
            task_id=task.task_id, transaction_id=task.information[0].query.query_id, consent_ref=job["consent_ref"])
        clock = task.source.sample()
        packet_id, revision = hosts.install_current_action_v01(task.host, **prepared, expected_revision=task.host.revision,
            evaluation_time=clock.evaluation_time, evaluation_time_source=clock.evaluation_time_source, evaluation_context_id=clock.evaluation_context_id)
        job.update(packet_id=packet_id, expires=expires)
        task.pending = dict(job=job, prepared=prepared, review=review, dependency=dependency, packet_id=packet_id,
            original_sources=descriptors(task.sources), original_scope_sha256=dependency.content_sha256)
        task.evidence_refs.append(persist(task.evidence_directory, "pending_save_packet", prepared["root_bound"]))
        return task.pending
    finally:
        authority.CURRENT_SAVE.reset(token)


def save_output(task, target, *, consent_ref=None):
    require(task.accepted is not None, "save_no_accepted_result")
    require(task.continuation_enabled and task.information is not None and task.d_baseline is not None,
        "save_declared_control_baseline_required")
    current = task.source.current()
    require(consent_ref is None or consent_ref == current["policy"]["consent_ref"], "save_consent_substitution")
    if task.last_save and task.last_save["job"]["inputs"]["target"] == target and \
        task.last_save["job"]["inputs"]["result_ref"] == task.accepted.plain["result_id"]:
        pending = task.last_save
    else:
        job, inputs = save_job(task, target)
        admitted = authority.admit_save("host:" + task.root_id + ":effect:" + digest(dict(task=task.task_id, target=target))[:16])
        clock = task.source.sample()
        effect_host = hosts.build_root_work_execution_host_v01(owning_root_id=task.root_id,
            registry=action.build_empty_action_commit_packet_registry_v02(), catalogue=(admitted,), packet_bindings=(),
            current_dependency_observations=clock.observations, logical_time_bridge=clock.logical_time_bridge, trusted_source=task.source)
        job["definition"] = admitted.definition
        token = authority.CURRENT_SAVE.set(job)
        try:
            prepared, review, dependency, expires = authority.prepare_save(admitted, inputs, task.source,
                dict(accepted_result=True, exact_current_sources=True, owner_policy=True), root_id=task.root_id,
                task_id=task.task_id, transaction_id=task.information[0].query.query_id, consent_ref=job["consent_ref"])
            clock = task.source.sample()
            packet_id, _ = hosts.install_current_action_v01(effect_host, **prepared, expected_revision=effect_host.revision,
                evaluation_time=clock.evaluation_time, evaluation_time_source=clock.evaluation_time_source, evaluation_context_id=clock.evaluation_context_id)
            job.update(packet_id=packet_id, expires=expires)
            pending = dict(job=job, prepared=prepared, review=review, dependency=dependency, packet_id=packet_id, effect_host=effect_host)
            task.last_save = pending
        finally:
            authority.CURRENT_SAVE.reset(token)
    return dispatch_pending(task, pending)


def dispatch_pending(task, pending):
    """Public exact-packet hook also permits an independent duplicate-dispatch exam."""
    token = authority.CURRENT_SAVE.set(pending["job"])
    try:
        clock = task.source.sample()
        task.emit("SAVE_DISPATCH", packet_id=pending["packet_id"])
        effect_host = pending.get("effect_host")
        require(type(effect_host) is hosts.RootWorkExecutionHostV01, "save_standalone_effect_host_required")
        registry, revision = hosts.dispatch_current_action_v01(effect_host, packet_id=pending["packet_id"], task_id=task.task_id,
            expected_revision=effect_host.revision, evaluation_time=clock.evaluation_time,
            evaluation_time_source=clock.evaluation_time_source, evaluation_context_id=clock.evaluation_context_id)
        context = registry.action_packet_fulfillment_attempt_contexts[-1]
        require(context.receipt is not None and pending["job"].get("readback") is not None, "save_unknown_or_missing_receipt")
        result = dict(classification="OWNED_LOCAL_REFERENCE_MOCK_CONSEQUENTIAL_WITH_ACTUAL_FILE_WRITE",
            packet_id=pending["packet_id"], receipt=abi.kernel_artifact_to_plain_dict_v01(context.receipt),
            root=authority.root_plain(pending["review"]), readback=pending["job"]["readback"], host_revision=revision,
            real_world_effects_count=0)
        task.last_save = pending
        task.evidence_refs.append(persist(task.evidence_directory, "save_receipt_readback", result))
        task.emit("SAVE_RECEIPT", packet_id=pending["packet_id"], receipt_id=context.receipt.artifact_id)
        return result
    finally:
        authority.CURRENT_SAVE.reset(token)


def document_delta_arguments(task, updated_sources, changed_index):
    """Build the current document-specific native E family using public APIs."""
    if task.informational_profile:
        from . import informational_document as informational
        return informational.delta_arguments(task, updated_sources, changed_index)
    require(task.pending is not None, "delta_missing_legitimate_pending_save_carrier")
    baseline = task.d_baseline
    clock = task.source.sample()
    capture = hosts.capture_current_action_source_v01(task.host, packet_id=task.pending["packet_id"], expected_revision=task.host.revision,
        evaluation_time=clock.evaluation_time, evaluation_time_source=clock.evaluation_time_source, evaluation_context_id=clock.evaluation_context_id)
    dependency = task.pending["dependency"]
    current = task.source.current()
    invalidation = action.build_action_invalidation_evidence_v01(source_invalidation_event_ref="radik:source_change:" + digest(descriptors(updated_sources)),
        packet_id=task.pending["packet_id"], dependency_id=dependency.dependency_id, invalidation_class="DEPENDENCY_CHANGED",
        evidence_ref=dependency.evidence_ref, evidence_sha256=task.source.scope_sha256(current), observed_status="CHANGED",
        time_envelope_id=dependency.time_envelope_id, freshness_policy_id=dependency.freshness_policy_id,
        owning_local_root_id=task.root_id, accepted_by_local_root_id=task.root_id, authority_effect="DETERMINISTIC_BLOCK",
        evaluation_time=capture.evaluation_time, evaluation_time_source=capture.evaluation_time_source, evaluation_context_id=capture.evaluation_context_id)
    require(action.validate_action_invalidation_evidence_against_packet_v01(invalidation, capture.root_bound_packet) == (True, ()), "delta_invalidation_binding")
    report = task.information[0]
    old_time = abi.kernel_artifact_to_plain_dict_v01(baseline.source_context.route_eligibility_artifact)["time_envelope"]
    def artifact(payload, parents=(), observed=False):
        envelope = dict(old_time)
        if observed:
            envelope.update(pt_created_at=authority.stamp(capture.evaluation_time), et_observed_at=authority.stamp(capture.evaluation_time))
        ref = "radik:document_source:" + digest(dict(payload=payload, parents=parents, time=envelope))
        return abi.build_kernel_artifact_v01(abi_version="v1.0", artifact_id=ref, artifact_type="SemanticEvidence", schema_version="v1",
            transaction_id=baseline.topology.transaction_id, owner_root_id=task.root_id, source_component="radik:trusted_document_intake",
            authority_class="EVIDENCE_ONLY", lifecycle_state="VALIDATED", payload=payload, trace_refs=(task.task_id,), parent_refs=parents, time_envelope=envelope)
    def source_payload(source):
        return dict(source_ref=source["source_ref"], source_revision=source["revision"], content_sha256=source["sha256"], text=source["text"])
    documents = tuple(artifact(source_payload(v)) for v in task.sources)
    observed_document = artifact(source_payload(updated_sources[changed_index]), (documents[changed_index].artifact_id,), True)
    root_input = next(v for v in baseline.cell_inputs if v.parent_cell_id is None)
    projections = []
    for child_id in root_input.ordered_planned_child_cell_ids:
        child = next(v for v in baseline.cell_inputs if v.cell_id == child_id)
        seed = next(a for q, a in zip(baseline.queue_entries, baseline.queue_artifacts, strict=True)
            if q.queue_entry_id == child.ordered_initial_queue_entry_ids[0])
        body = abi.kernel_artifact_to_plain_dict_v01(seed)
        projections.append(artifact(dict(projection_profile_id="g2e_baseline_runtime_artifact_projection_v01",
            projected_runtime_artifact=body, projected_runtime_artifact_sha256=digest(body)), (seed.artifact_id,)))
    before = (documents[0], projections[0], documents[1], projections[1])
    after = tuple(observed_document if v is documents[changed_index] else v for v in before)
    raw_edges = tuple(integrity.ArtifactDependencyEdgeV01(projections[i].artifact_id, documents[i].artifact_id) for i in range(2))
    manifest = integrity.build_artifact_manifest_v01(transaction_id=baseline.topology.transaction_id,
        profile=integrity.build_default_seal_profile_v01(), artifacts=tuple(abi.kernel_artifact_to_canonical_ref_v01(v) for v in before),
        dependency_edges=raw_edges, root_ownership_bindings=tuple(integrity.RootOwnershipBindingV01(v.artifact_id, task.root_id) for v in before),
        evidence_class_bindings=tuple(integrity.EvidenceClassBindingV01(v.artifact_id, "SOURCE_EVIDENCE") for v in before),
        authority_class_bindings=tuple(integrity.AuthorityClassBindingV01(v.artifact_id, v.authority_class) for v in before))
    replay = integrity.verify_artifact_replay_v01(manifest=manifest,
        payload_rows=tuple((v.artifact_id, abi.kernel_artifact_to_plain_dict_v01(v)["payload"]) for v in before), expected_manifest_hash=manifest.manifest_hash)
    source_context = delta_runtime.build_continuous_delta_source_context_v01(integrity_manifest=manifest, integrity_replay=replay,
        baseline_source_artifacts=before, observed_source_artifacts=after, g2a_registry=capture.registry, g2a_packet=capture.root_bound_packet,
        g2a_dependency_candidate=capture.root_bound_packet.canonical_projection.dependency_candidate, g2a_current_observations=capture.observations,
        g2a_root_invalidation_material=invalidation, g2b_resolution_report=report, g2b_reuse_certificate=report.reuse_certificate,
        g2b_writeback_evidence=None, g2c_source_context=baseline.source_context.g2c_source_context,
        baseline_g2c_route_eligibility_artifact=baseline.source_context.route_eligibility_artifact, baseline_g2d_execution_bundle=baseline,
        root_kernel=baseline.source_context.root_kernel, post_vv_profile=None, gt_profile=None, current_source_host=task.host, current_source_capture=capture)
    source_validation = delta_runtime.validate_continuous_delta_source_context_v01(source_context)
    require(source_validation.status == "PASS", "delta_current_source_family:" + repr(source_validation.reason_codes))
    common = dict(transaction_id=baseline.topology.transaction_id, owning_root_id=task.root_id, domain_id=authority.DOMAIN,
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
    valid_to = authority.stamp(min(task.pending["job"]["expires"], capture.evaluation_time+600))
    binding = delta_runtime.build_delta_source_binding_v01(request_id=baseline.runtime_report.request_id, transaction_id=common["transaction_id"],
        owning_root_id=task.root_id, domain_id=authority.DOMAIN, baseline_source_artifact_id=documents[changed_index].artifact_id,
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
        changed_artifact_bindings=(changed_artifact,), delta=delta, dependency_edges=edges, dependency_graph=graph, retained_profile="fractal_retained_work_v01")


def informational_delta_family(task, updated_sources, changed_index, state, capture, observed_document, invalidation):
    """Public informational authority, with the existing document source/cell mapping."""
    from . import informational_document as informational
    baseline, report, documents = task.d_baseline, task.information[0], state.documents
    effective_valid_to, _caps = informational.caps_for_task(task)
    effective_valid_to = min(state.valid_to, effective_valid_to)
    informational.temporal.require_remaining(effective_valid_to, task.source.clock(),
        informational.temporal.NATIVE_SECONDS+informational.temporal.CONSUMER_SECONDS)
    def artifact(payload, parents=()):
        return informational._artifact(task, payload, created_at=capture.evaluation_time,
            valid_to=state.valid_to, parents=parents)
    root_input = next(v for v in baseline.cell_inputs if v.parent_cell_id is None)
    projections = []
    for child_id in root_input.ordered_planned_child_cell_ids:
        child = next(v for v in baseline.cell_inputs if v.cell_id == child_id)
        seed = next(a for q, a in zip(baseline.queue_entries, baseline.queue_artifacts, strict=True)
            if q.queue_entry_id == child.ordered_initial_queue_entry_ids[0])
        body = abi.kernel_artifact_to_plain_dict_v01(seed)
        projections.append(artifact(dict(projection_profile_id="g2e_baseline_runtime_artifact_projection_v01",
            projected_runtime_artifact=body, projected_runtime_artifact_sha256=digest(body)), (seed.artifact_id,)))
    before = (documents[0], projections[0], documents[1], projections[1])
    after = tuple(observed_document if v is documents[changed_index] else v for v in before)
    raw_edges = tuple(integrity.ArtifactDependencyEdgeV01(projections[i].artifact_id, documents[i].artifact_id) for i in range(2))
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
    common = dict(transaction_id=baseline.topology.transaction_id, owning_root_id=task.root_id, domain_id=authority.DOMAIN,
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
        owning_root_id=task.root_id, domain_id=authority.DOMAIN, baseline_source_artifact_id=documents[changed_index].artifact_id,
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
        changed_artifact_bindings=(changed_artifact,), delta=delta, dependency_edges=edges, dependency_graph=graph, retained_profile="fractal_retained_work_v01")


def validate_delta_mapping(task, bundle):
    """Check the reviewed source/cell/Work map on the actual current typed return.

    The public E/D validators run once in continue_task. This consumer performs
    cheap actual source/slot/origin checks again, including meaningful mutations.
    It never accepts a portable captured JSON body as a current typed return.
    """
    require(type(bundle) is delta_runtime.ContinuousDeltaExecutionBundleV01 and task.delta_expected is not None, "delta_typed_return_required")
    expected = task.delta_expected
    context = bundle.source_context
    require(context.baseline_g2d_execution_bundle is task.d_baseline and
        context.g2c_source_context == task.d_baseline.source_context.g2c_source_context and
        bundle.delta.owning_root_id == task.root_id and bundle.delta.request_id == task.task_id, "delta_foreign_source_family")
    require(bundle.delta.delta_id == task.delta_arguments["delta"].delta_id and
        bundle.source_bindings == task.delta_arguments["source_bindings"], "delta_source_binding")
    if task.informational_profile:
        from . import informational_document as informational
        informational.validate_consumption_boundary(task, context)
    else:
        require(context.current_source_host is task.host and context.current_source_capture is not None, "delta_current_host_origin")
        try:
            hosts.validate_retained_action_source_capture_v01(task.host, context.current_source_capture, require_current=False)
        except ValueError as exc:
            raise ValueError("delta_current_host_origin:" + str(exc)) from exc
    require(task.source.current()["sources"] == descriptors(expected["updated"]), "delta_stale_source_observation")
    require(task.source.clock() < int(datetime.fromisoformat(bundle.delta.valid_to_utc).timestamp()), "delta_stale_time")
    require(len(context.baseline_source_artifacts) == len(context.observed_source_artifacts) == 4, "delta_source_inventory")
    changed = expected["changed_index"]
    retained = 1-changed
    for index in range(2):
        old = abi.kernel_artifact_to_plain_dict_v01(context.baseline_source_artifacts[index*2])["payload"]
        new = abi.kernel_artifact_to_plain_dict_v01(context.observed_source_artifacts[index*2])["payload"]
        def source_payload(source):
            return dict(source_ref=source["source_ref"], source_revision=source["revision"], content_sha256=source["sha256"], text=source["text"])
        require(old == source_payload(expected["old"][index]), "delta_swapped_source_binding")
        require(new == source_payload(expected["updated"][index]), "delta_retained_source_changed" if index == retained else "delta_changed_source_binding")
    require(abi.kernel_artifact_to_plain_dict_v01(context.baseline_source_artifacts[retained*2]) ==
        abi.kernel_artifact_to_plain_dict_v01(context.observed_source_artifacts[retained*2]), "delta_retained_source_changed")
    root_input = next(v for v in task.d_baseline.cell_inputs if v.parent_cell_id is None)
    children = root_input.ordered_planned_child_cell_ids
    require(bundle.recomputation_plan.ordered_affected_cell_ids == (children[changed],), "delta_unknown_impact")
    current = bundle.recomputed_g2d_execution_bundle
    require(type(current) is fractal.FractalRetainedWorkExecutionBundleV01 and len(current.retained_consumptions) == 1, "delta_native_retained_profile")
    historical = next(v for v in task.d_baseline.cell_results if v.cell_id == children[retained])
    consumption = current.retained_consumptions[0]
    require(consumption.consumed_result == historical and
        canonical(fractal.fractal_cell_result_to_plain_data_v02(consumption.consumed_result)) ==
        canonical(fractal.fractal_cell_result_to_plain_data_v02(historical)), "delta_retained_D_result_changed")
    parent = next(v for v in current.cell_results if v.parent_cell_id is None)
    fresh = next(v for v in current.cell_results if v.parent_cell_id is not None)
    by_cell = {fresh.cell_id: fresh.result_id, historical.cell_id: historical.result_id}
    require(parent.ordered_child_result_ids == tuple(by_cell[cell] for cell in children) and fresh.cell_id == children[changed] and
        not any(q.cell_id == historical.cell_id for q in current.queue_entries), "delta_actual_parent_consumption")
    # Follow the native observed source -> affected CONTROL output chain. The
    # subsequent mapping to document Work remains an explicit app-owned bridge.
    source_artifact = context.observed_source_artifacts[changed*2]
    prior_artifact = next(v.artifact_id for r, v in zip(task.d_baseline.cell_results,
        task.d_baseline.result_artifacts, strict=True) if r.cell_id == children[changed])
    recomputed = tuple(v for v in bundle.recomputed_bindings if v.prior_artifact_id == prior_artifact)
    require(len(recomputed) == 1 and recomputed[0].g2d_cell_result_ref == fresh.result_id and
        recomputed[0].g2d_runtime_report_ref == current.runtime_report.report_id and fresh.outcome == "COMPLETED" and
        fresh.accepted_output_refs, "delta_recomputed_result_binding")
    observed = current.observed_work_context
    consumed = tuple(v for v in observed.ordered_binding_artifacts if
        abi.kernel_artifact_to_plain_dict_v01(v)["payload"]["source_pair"]["observed_identity_ref"] == source_artifact.artifact_id and
        abi.kernel_artifact_to_plain_dict_v01(v)["payload"]["topology_binding"]["cell_ref"] == children[changed])
    require(len(consumed) == 1, "delta_native_observed_source_consumption")
    rows = tuple(q for q in current.queue_entries if q.cell_id == children[changed] and q.state == "COMPLETED" and
        set(q.observed_output_refs).intersection(fresh.accepted_output_refs))
    require(rows and all(consumed[0].artifact_id in q.observed_evidence_refs for q in rows), "delta_actual_output_evidence")
    artifacts = {v.artifact_id: v for v in (*current.queue_artifacts, *current.result_artifacts, *observed.ordered_binding_artifacts)}
    frontier = [v.artifact_id for q, v in zip(current.queue_entries, current.queue_artifacts, strict=True) if q in rows]
    reached = set()
    while frontier:
        ref = frontier.pop()
        if ref not in reached:
            reached.add(ref)
            if ref in artifacts:
                frontier.extend(artifacts[ref].parent_refs)
    require(consumed[0].artifact_id in reached, "delta_native_causal_parent_chain")
    require(bundle.plan_root_decision_result.decision == bundle.final_root_decision_result.decision == "ACCEPT", "delta_current_root_refused")
    return dict(changed_index=changed, retained_index=retained, actual_changed_source=expected["updated"][changed],
        affected_cell_id=children[changed], retained_cell_id=historical.cell_id, retained_D_result_id=historical.result_id,
        observed_source_artifact_ref=source_artifact.artifact_id, native_observed_binding_ref=consumed[0].artifact_id,
        retained_D_bytes_sha256=digest(canonical(fractal.fractal_cell_result_to_plain_data_v02(historical))),
        parent_consumed_child_result_ids=list(parent.ordered_child_result_ids), retained_consumption_ref=consumption.consumption_id)


def validate_historical_binding(task, binding):
    valid, reasons = work.validate_work_historical_output_v01(binding, context=continuation_context(task))
    require(valid, reasons[0] if reasons else "historical_binding_refused")
    return binding


def continue_task(task, sources, proposal, *, semantic_family, critic_assessment, semantic_provenance):
    require(task.accepted is not None and task.delta_count == 0, "one_delta_per_task")
    require(task.continuation_enabled and task.d_baseline is not None, "delta_declared_control_baseline_required")
    updated = normalize_sources(sources)
    require([v["source_ref"] for v in updated] == [v["source_ref"] for v in task.sources], "delta_foreign_sources")
    require(task.source.current()["sources"] == descriptors(updated), "delta_actual_intake_mismatch")
    changed = [i for i in range(2) if updated[i] != task.sources[i]]
    require(len(changed) == 1 and updated[changed[0]]["revision"] > task.sources[changed[0]]["revision"] and
        updated[changed[0]]["sha256"] != task.sources[changed[0]]["sha256"], "delta_expected_one_changed_source")
    changed_index, retained_index = changed[0], 1-changed[0]
    proposal = validate_proposal(proposal, updated, task_id=task.task_id, topic=task.topic)
    require(semantic_family.kind == "ACTUAL_ORCHESTRATOR_OBSERVATION", "delta_actual_role_pipeline_required")
    from .informational_document import require_family_profile
    require_family_profile(semantic_family, task.informational_profile)
    current = task.source.current()
    pipeline = validate_semantic_inputs(semantic_family, proposal, critic_assessment, semantic_provenance, updated,
        task_id=task.task_id, topic=task.topic, goal=task.goal, criterion=task.criterion, root_id=task.root_id,
        now=current["now"], policy=current["policy"])
    retained_source_ref = updated[retained_index]["source_ref"]
    retained_claims = [v for v in proposal["claims"] if v["source_ref"] == retained_source_ref]
    old_side = "left" if retained_index == 0 else "right"
    require(retained_claims == task.accepted.plain["comparison"][old_side]["selected"], "delta_retained_proposal_changed")
    # The fresh family already preceded this Architect. It remains a separate
    # witness; U2's immutable intent/BSEP/semantic origin is never replaced.
    original_common = task.common
    task.evidence_refs.append(persist(task.evidence_directory, "continuation_pre_architect_family", authority.source_family_witness(semantic_family)))
    retained_binding = work.build_work_historical_output_v01(continuation_context(task), revision_id=task.program.candidate.revision_id,
        work_id=task.branch_slots[retained_index], output_field=task.branch_fields[retained_index])
    validate_historical_binding(task, retained_binding)
    trigger = work.build_work_revision_trigger_v01(continuation_context(task), work_id=task.branch_slots[retained_index],
        output_field=task.branch_fields[retained_index])
    require(trigger.output == retained_binding, "delta_genuine_unchanged_work_trigger")
    task.delta_expected = dict(old=task.sources, updated=updated, changed_index=changed_index)
    arguments = document_delta_arguments(task, updated, changed_index)
    task.delta_arguments = arguments
    task.emit("NATIVE_E_START")
    task.evidence_refs.append(persist(task.evidence_directory, "native_e_input_family", arguments))
    start = time.monotonic()
    bundle, validation = delta_runtime.run_continuous_delta_runtime_v01(**arguments)
    require(bundle is not None and validation.status == "PASS", "native_E:" + repr(validation.reason_codes))
    require(delta_runtime.validate_continuous_delta_execution_bundle_v01(bundle).status == "PASS", "native_E_supplied_validation")
    require(fractal.validate_fractal_retained_work_execution_bundle_v01(bundle.recomputed_g2d_execution_bundle).status == "PASS", "native_retained_D_supplied_validation")
    mapping = validate_delta_mapping(task, bundle)
    task.delta_bundle = bundle
    task.last_retained_binding = retained_binding
    task.evidence_refs.append(persist(task.evidence_directory, "native_e_typed_return", bundle))
    task.evidence_refs.append(persist(task.evidence_directory, "native_retained_d_return", bundle.recomputed_g2d_execution_bundle))
    task.timings.append(dict(phase="native_E_D", seconds=time.monotonic()-start, executed_cells=len(bundle.recomputed_g2d_execution_bundle.cell_results)))
    task.emit("NATIVE_E_RETURN", status=validation.status, mapping=mapping)
    actual_source = mapping["actual_changed_source"]
    current = task.source.current()
    authority.validate_source_family(semantic_family, updated, task_id=task.task_id, topic=task.topic, goal=task.goal,
        criterion=task.criterion, root_id=task.root_id, now=current["now"], policy=current["policy"])
    task.sources, task.proposal = updated, proposal
    install_semantic_pipeline(task, semantic_family, critic_assessment, semantic_provenance, pipeline)
    require(task.common is original_common, "delta_immutable_work_origin_changed")
    task.evidence_refs.append(persist(task.evidence_directory, "continuation_checked_semantic_pipeline", task.semantic_pipeline))
    new_name = "left1" if changed_index == 0 else "right1"
    extract, compare = task.catalogue[:2]
    branch = work.WorkItemV01(new_name, extract.definition.definition_id, task.root_id,
        (literal("material", dict(source=actual_source, claims=[v for v in proposal["claims"] if v["source_ref"] == actual_source["source_ref"]],
            semantic_selection=membrane.selection_proof(semantic_family, proposal, actual_source))),),
        (), (), None, None)
    inputs = tuple(work.WorkInputBindingV01(side, work.WorkOutputBindingV01(new_name, "material", "TEXT") if index == changed_index else retained_binding)
        for index, side in enumerate(("left", "right"))) + (literal("proposal", proposal), literal("semantic_witness", task.semantic_witness))
    combine = work.WorkItemV01("combine1", compare.definition.definition_id, task.root_id, inputs, (), (new_name,), None, None)
    usage = continuation_context(task).snapshot.usage
    revised = work.revise_work_program_v01(continuation_context(task), previous_revision_id=task.program.candidate.revision_id,
        trigger=trigger, items=(branch, combine), budget=work.WorkBudgetV01(8, 4, 0, 12-usage.compute_units, 1), **task.common)
    artifact = advance(task, revised.program)
    new_result = task.results[0]
    ids = list(task.branch_result_ids)
    ids[changed_index] = new_result.result.result_id
    require(ids[retained_index] == retained_binding.result_id and next(v.value for v in task.results[-1].invocation.inputs
        if v.parameter_name == old_side) == retained_binding.value.value, "delta_actual_retained_business_consumption")
    task.branch_result_ids = tuple(ids)
    task.delta_count += 1
    task.evidence_refs.append(persist(task.evidence_directory, "business_retained_trigger", dict(trigger=plain(trigger), historical=plain(retained_binding),
        classification="GENUINE_UNCHANGED_COMPLETED_WORK_TRIGGER_NOT_NATIVE_CHANGED_SOURCE_OBSERVATION", mapping=mapping)))
    accepted = accept_result(task, artifact)
    current = task.source.current()
    if task.continuation_enabled and not task.informational_profile and current["policy"]["save_allowed"] and current["policy"]["consent_ref"] is not None and current["now"] < current["policy"]["valid_to"]:
        prepare_pending(task, "pending_" + digest(accepted.plain["result_id"])[:16] + ".txt")
    return accepted
