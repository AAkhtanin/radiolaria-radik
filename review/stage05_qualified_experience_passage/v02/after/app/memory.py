"""Owned persisted document memory with current typed eligibility and descent.

Native Work validation and independent Root review are injected trusted adapters.
Stored history never restores either adapter, a live Host, or an action grant.
Import is inert. File reads occur in this application adapter, outside PURE Work.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Callable

from hedgehog.drs import LocalDRS, assert_no_sensitive_drs_keys
from hedgehog import drs_semantic_address_v01 as address
from hedgehog import drs_memory_resolution_v01 as resolution
from hedgehog import local_drs_resolver as resolver
from hedgehog.kernel import integrity_replay_v01 as integrity
from hedgehog.kernel import root_decision_v01 as roots

from .dynamic_temporal import REUSE_WINDOW_SECONDS, reuse_valid_to


DOMAIN = "RADIK_DOCUMENT"
POLICY = "radik.document.memory.v02"
FRESHNESS = "freshness:radik:document_memory"
ACCESS_POLICY = "radik:owned_accepted_document_memory"
MAX_PAYLOAD_BYTES = 131072
MAX_RECORD_BYTES = 65536
MAX_RECORDS = 64
MAX_MEMORY_JSON_DEPTH = 64
MEMORY_ORIGIN_VERSION = 'radik.document.memory_origin.v02'
MEMORY_ORIGIN_KEYS = {'version', 'result_id', 'result_sha256', 'candidate_sha256', 'descent_id',
    'record_id', 'payload_sha256', 'record_plain_sha256', 'record_readback_sha256',
    'descent_root_decision_id', 'historical_root_decision_id', 'historical_accepted_at',
    'historical_valid_to', 'evaluated_at', 'record_clocks', 'source_scope_sha256'}
MEMORY_WRITEBACK_ERROR_CODES = frozenset({'memory_accepted_source_binding', 'memory_accepted_task_binding',
    'memory_accepted_time_binding', 'memory_context_shape', 'memory_current_root_refused', 'memory_finite_time',
    'memory_logical_path_invalid', 'memory_original_root_provenance', 'memory_outcome_validator_must_return_verified_plain',
    'memory_owned_path_symlink', 'memory_path_outside_owned_directory', 'memory_payload_canonical_binding',
    'memory_payload_identity_conflict', 'memory_record_count_limit', 'memory_record_file_boundary',
    'memory_record_id_invalid', 'memory_record_size_limit', 'memory_root_callback_shape',
    'memory_root_exact_claim_binding', 'memory_root_input_invalid', 'memory_root_kernel_invalid',
    'memory_root_owner_or_transaction', 'memory_root_result_invalid', 'memory_source_duplicate',
    'memory_source_hash', 'memory_source_identity', 'memory_source_shape', 'memory_two_sources_required',
    'memory_write_requires_causal_v02', 'memory_writeback_expired', 'memory_writeback_payload_readback',
    'memory_writeback_record_readback', 'memory_dynamic_task_spec', 'memory_dynamic_context',
    'memory_dynamic_source_count'})
BOUNDED_MEMORY_ERROR_CODES = frozenset({'memory_payload_size_limit', 'memory_payload_depth_limit',
    'saved_outcome_budget', 'saved_outcome_depth_limit', 'saved_memory_projection_binding',
    'saved_memory_work_input_binding', 'saved_memory_work_output_binding',
    'memory_work_projection_shape', 'memory_work_projection_budget', 'memory_work_projection_origin',
    'memory_work_sources', 'memory_work_sources_budget', 'memory_work_candidate_binding',
    'memory_work_business_comparison', 'memory_work_current_time', 'memory_origin_shape',
    'memory_origin_identity', 'memory_origin_clock', 'memory_writeback_payload_readback',
    'memory_writeback_record_readback', 'saved_memory_work_contract_binding'}) | MEMORY_WRITEBACK_ERROR_CODES
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RECORD_ID = re.compile(r"drsmeaning_v01:[0-9a-f]{64}\Z")
_SOURCE_KEYS = {"source_ref", "revision", "sha256"}


class BoundedMemoryRefusal(ValueError):
    """Closed diagnostic data; never include document or exception text."""
    def __init__(self, code, stage):
        if code not in BOUNDED_MEMORY_ERROR_CODES or stage not in {
                'ACCEPTED_RESULT_PREPUBLICATION', 'MEMORY_WRITEBACK_VALIDATION', 'MEMORY_CONSUMER_VALIDATION'}:
            raise ValueError('memory_refusal_contract')
        self.code, self.stage = code, stage
        super().__init__(code)


def memory_require(value, code, *, stage='MEMORY_CONSUMER_VALIDATION'):
    if not value:
        raise BoundedMemoryRefusal(code, stage)


def _require(value: bool, reason: str) -> None:
    if not value:
        if reason in BOUNDED_MEMORY_ERROR_CODES:
            stage = 'MEMORY_WRITEBACK_VALIDATION' if reason.startswith(('memory_payload_', 'memory_writeback_')) else 'MEMORY_CONSUMER_VALIDATION'
            raise BoundedMemoryRefusal(reason, stage)
        raise ValueError(reason)


def _canonical(value: object) -> bytes:
    return integrity.canonical_json_bytes_v01(value)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bounded_json_bytes(value, *, limit, size_code, depth_code, stage='MEMORY_CONSUMER_VALIDATION'):
    """Measure the actual canonical wrapper, including JSON string escaping."""
    raw = _canonical(value)
    memory_require(len(raw) <= limit, size_code, stage=stage)
    def visit(item, depth):
        memory_require(depth <= MAX_MEMORY_JSON_DEPTH, depth_code, stage=stage)
        children = item.values() if type(item) is dict else item if type(item) in (list, tuple) else ()
        for child in children:
            visit(child, depth + 1)
    visit(value, 0)
    return raw


def memory_payload_bytes(accepted, sources, *, task_id, topic_id, intent, criterion,
                         stage='MEMORY_WRITEBACK_VALIDATION', task_spec=None):
    """Pure bounded writeback material; neither validate Work nor publish it."""
    ordered_sources = [{key: source[key] for key in sorted(_SOURCE_KEYS)} for source in sources]
    material = dict(version='radik.document.memory.payload.v02', task_id=task_id, topic_id=topic_id,
        intent=intent, criterion=criterion, sources=ordered_sources, outcome=accepted)
    if task_spec is not None:
        from .task_spec import meaning_key
        material.update(version='radik.dynamic.memory.payload.v01', meaning_key=meaning_key(task_spec, sources))
    return bounded_json_bytes(material, limit=MAX_PAYLOAD_BYTES,
        size_code='memory_payload_size_limit', depth_code='memory_payload_depth_limit', stage=stage)


def validate_memory_origin(origin, *, now=None):
    """Check bounded historical lineage as data, without restoring authority."""
    _require(type(origin) is dict and set(origin) == MEMORY_ORIGIN_KEYS
        and origin['version'] == MEMORY_ORIGIN_VERSION, 'memory_origin_shape')
    hashes = ('result_sha256', 'candidate_sha256', 'payload_sha256', 'record_plain_sha256',
        'record_readback_sha256', 'source_scope_sha256')
    refs = ('result_id', 'descent_id', 'record_id', 'descent_root_decision_id', 'historical_root_decision_id')
    _require(all(type(origin[key]) is str and _HASH.fullmatch(origin[key]) is not None for key in hashes)
        and all(type(origin[key]) is str and 0 < len(origin[key]) <= 256 for key in refs)
        and _RECORD_ID.fullmatch(origin['record_id']) is not None
        and origin['descent_root_decision_id'] != origin['historical_root_decision_id'], 'memory_origin_identity')
    clocks = origin['record_clocks']
    clock_names = {'ct_context_anchor', 'et_observed_at', 'freshness_policy_id', 'kt_as_of',
        'pt_created_at', 'source_observed_at', 'source_reported_at', 'system_ingested_at',
        'system_verified_at', 'time_envelope_id', 'time_envelope_version', 'ttl_seconds', 'valid_from', 'valid_to'}
    _require(type(clocks) is dict and set(clocks) == clock_names
        and all(type(clocks[key]) is int and clocks[key] >= 0 for key in clock_names -
            {'freshness_policy_id', 'time_envelope_id', 'time_envelope_version'})
        and clocks['freshness_policy_id'] == FRESHNESS and clocks['time_envelope_version'] == 'v0.1'
        and type(clocks['time_envelope_id']) is str and 0 < len(clocks['time_envelope_id']) <= 128
        and all(type(origin[key]) is int and origin[key] >= 0 for key in
            ('historical_accepted_at', 'historical_valid_to', 'evaluated_at')), 'memory_origin_clock')
    observed = origin['evaluated_at'] if now is None else now
    _require(type(observed) is int and origin['historical_accepted_at'] == clocks['pt_created_at'] == clocks['valid_from']
        and 0 < clocks['ttl_seconds'] == clocks['valid_to'] - clocks['valid_from'] <= 86400
        and clocks['valid_to'] <= origin['historical_valid_to']
        and clocks['valid_from'] <= origin['evaluated_at'] <= observed < clocks['valid_to']
        and all(clocks[key] == clocks['pt_created_at'] for key in ('ct_context_anchor', 'et_observed_at',
            'kt_as_of', 'source_observed_at', 'source_reported_at'))
        and clocks['pt_created_at'] <= clocks['system_ingested_at'] <= clocks['system_verified_at'] <= origin['evaluated_at'],
        'memory_origin_clock')
    return json.loads(_canonical(origin))


def _stamp(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _json_copy(value: object) -> object:
    return json.loads(_canonical(value))


def _source_scope(sources: object, *, dynamic=False) -> list[dict]:
    _require(type(sources) in (tuple, list) and (1 <= len(sources) <= 4 if dynamic else len(sources) == 2),
        "memory_dynamic_source_count" if dynamic else "memory_two_sources_required")
    result = []
    for source in sources:
        _require(type(source) is dict and _SOURCE_KEYS.issubset(source), "memory_source_shape")
        row = {key: source[key] for key in sorted(_SOURCE_KEYS)}
        _require(type(row["source_ref"]) is str and bool(row["source_ref"])
            and type(row["revision"]) is int and row["revision"] >= 1, "memory_source_identity")
        _require(type(row["sha256"]) is str and _HASH.fullmatch(row["sha256"]) is not None, "memory_source_hash")
        result.append(row)
    _require(len({row["source_ref"] for row in result}) == len(result), "memory_source_duplicate")
    return sorted(result, key=lambda row: row["source_ref"])


def _scope(sources: object, topic_id: str, intent: str, criterion: str) -> dict:
    _require(all(type(value) is str and value for value in (topic_id, intent, criterion)), "memory_context_shape")
    return dict(sources=_source_scope(sources), topic_id=topic_id, intent=intent, criterion=criterion, policy=POLICY)


def _review(callback: Callable, *, root_id: str, candidate_id: str, material: dict,
            checks: dict, now: int, transaction_id: str, predicate: str, subject: str) -> tuple:
    """Require an actual checked Root result over this exact local subject."""
    result = callback(candidate_id=candidate_id, material=material, checks=checks, now=now,
        transaction_id=transaction_id, predicate=predicate, subject=subject, owning_root_id=root_id)
    _require(type(result) is tuple and len(result) == 3, "memory_root_callback_shape")
    kernel, inputs, decision = result
    _require(not roots.validate_root_decision_kernel_v01(kernel), "memory_root_kernel_invalid")
    _require(not roots.validate_root_decision_input_v01(kernel=kernel, decision_input=inputs), "memory_root_input_invalid")
    _require(not roots.validate_root_decision_result_v01(kernel=kernel, decision_input=inputs, result=decision),
        "memory_root_result_invalid")
    _require(inputs.target_root_id == decision.target_root_id == root_id and inputs.transaction_id == transaction_id,
        "memory_root_owner_or_transaction")
    _require(decision.decision == "ACCEPT" and decision.selected_candidate_id == candidate_id
        and not decision.permission_created and not decision.final_output_created and not decision.effect_requested,
        "memory_current_root_refused")
    plain = roots.root_decision_input_to_plain_dict_v01(inputs)
    claims = plain["root_review_packet"]["synthesis_proposal"]["normalized_claims"]
    _require(len(claims) == 1 and claims[0]["claim_id"] == candidate_id and claims[0]["subject"] == subject
        and claims[0]["predicate"] == predicate and claims[0]["object_or_value"] == material,
        "memory_root_exact_claim_binding")
    return result


def _rebuild(builder: Callable, plainifier: Callable, plain: object, keys: tuple[str, ...],
             tuple_keys: tuple[str, ...] = ()) -> object:
    """Use public builders and compare every saved derived field after rebuilding."""
    _require(type(plain) is dict and all(key in plain for key in keys), "memory_saved_typed_shape")
    args = {key: plain[key] for key in keys}
    for key in tuple_keys:
        _require(type(args[key]) is list, "memory_saved_tuple_shape")
        args[key] = tuple(args[key])
    value = builder(**args)
    _require(_canonical(plainifier(value)) == _canonical(plain), "memory_saved_typed_identity_or_hash")
    return value


def reconstruct_meaning_record(plain: object) -> object:
    """Reconstruct saved values only; preserve all recorded clocks and Root IDs."""
    _require(type(plain) is dict, "memory_saved_record_shape")
    semantic = _rebuild(address.build_semantic_address_v01, address.semantic_address_to_plain_data_v01,
        plain.get("semantic_address"), ("namespace", "domain", "subject_class", "intent_class", "meaning_schema_id", "meaning_schema_version"))
    time_envelope = _rebuild(address.build_drs_time_envelope_v01, address.drs_time_envelope_to_plain_data_v01,
        plain.get("time_envelope"), ("pt_created_at", "kt_as_of", "et_observed_at", "ct_context_anchor", "ttl_seconds", "valid_from",
            "valid_to", "source_observed_at", "source_reported_at", "system_ingested_at", "system_verified_at", "freshness_policy_id"))
    authority = _rebuild(address.build_drs_authority_envelope_v01, address.drs_authority_envelope_to_plain_data_v01,
        plain.get("authority_envelope"), ("authority_class", "owning_local_root_id", "source_root_decision_input_id",
            "source_root_decision_id", "source_root_decision_hash", "authority_scope_fingerprint", "root_acceptance_state", "recording_component"))
    _require(plain.get("memory_pointers") == [] and plain.get("lineage_edges") == []
        and type(plain.get("artifact_pointers")) is list and len(plain["artifact_pointers"]) == 1,
        "memory_closed_pointer_profile")
    pointer = _rebuild(address.build_artifact_pointer_v01, address.artifact_pointer_to_plain_data_v01,
        plain["artifact_pointers"][0], ("storage_class", "object_reference", "content_sha256", "media_type", "byte_length",
            "access_policy_id", "sensitivity_class", "allowed_use_classes", "forbidden_use_classes", "summary_read_permitted",
            "payload_read_permitted"), ("allowed_use_classes", "forbidden_use_classes"))
    keys = ("predecessor_record_id", "supersession_reason", "safe_summary", "semantic_tags", "resonance_reason",
        "source_reference_ids", "persistent_lifecycle_state", "risk_hints", "conflict_hints", "reuse_policy_class",
        "policy_version", "schema_versions", "content_fingerprint", "recording_component")
    _require(all(key in plain for key in keys), "memory_saved_record_fields")
    args = {key: plain[key] for key in keys}
    for key in ("semantic_tags", "source_reference_ids", "risk_hints", "conflict_hints", "schema_versions"):
        _require(type(args[key]) is list, "memory_saved_record_tuple")
        args[key] = tuple(args[key])
    record = address.build_meaning_record_v01(semantic_address=semantic, time_envelope=time_envelope,
        authority_envelope=authority, memory_pointers=(), artifact_pointers=(pointer,), lineage_edges=(), **args)
    _require(_canonical(address.meaning_record_to_plain_data_v01(record)) == _canonical(plain), "memory_saved_record_identity")
    return record


@dataclass(frozen=True)
class MemorySelection:
    """Descent-approved ordinary data plus provenance, never a live Work record."""
    record_id: str
    payload_sha256: str
    material: dict
    descent: dict
    root_decision_id: str
    historical_root_decision_id: str
    record_plain: dict
    record_readback_sha256: str


def memory_origin_from_selection(selection, *, evaluated_at):
    """Project one actual current descent; omit every ancestor result tree."""
    _require(type(selection) is MemorySelection, 'memory_origin_shape')
    prior = selection.material['outcome']
    origin = dict(version=MEMORY_ORIGIN_VERSION, result_id=prior['result_id'], result_sha256=prior['result_sha256'],
        candidate_sha256=_sha(_canonical(prior['proposal'])), descent_id=selection.descent['memory_descent_result_id'],
        record_id=selection.record_id, payload_sha256=selection.payload_sha256,
        record_plain_sha256=_sha(_canonical(selection.record_plain)), record_readback_sha256=selection.record_readback_sha256,
        descent_root_decision_id=selection.root_decision_id, historical_root_decision_id=selection.historical_root_decision_id,
        historical_accepted_at=prior['accepted_at'], historical_valid_to=prior['valid_to'], evaluated_at=evaluated_at,
        record_clocks=selection.record_plain['time_envelope'], source_scope_sha256=_sha(_canonical(prior['sources'])))
    return validate_memory_origin(origin, now=evaluated_at)


class DocumentMemory:
    """Finite single-writer local memory in a trusted app-owned directory."""
    def __init__(self, directory: str | Path, *, owning_root_id: str,
                 root_review: Callable, validate_outcome: Callable, validate_persisted_outcome: Callable,
                 task_spec=None):
        directory = Path(directory)
        _require(not directory.is_symlink(), "memory_directory_symlink")
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory.resolve()
        self.owning_root_id = owning_root_id
        self.root_review = root_review
        self.validate_outcome = validate_outcome
        self.validate_persisted_outcome = validate_persisted_outcome
        if task_spec is not None:
            from .task_spec import TaskSpec
            _require(type(task_spec) is TaskSpec, 'memory_dynamic_task_spec')
        self.task_spec = task_spec
        self.dynamic = task_spec is not None
        self.policy = 'radik.dynamic.memory.v01' if self.dynamic else POLICY
        self.result_version = 'radik.dynamic.result.v01' if self.dynamic else 'radik.document.result.v02'
        self.pipeline_version = 'radik.dynamic.pipeline.v01' if self.dynamic else 'radik.semantic.pipeline.v02'
        self.payload_version = 'radik.dynamic.memory.payload.v01' if self.dynamic else 'radik.document.memory.payload.v02'
        self.events: list[dict] = []
        self._owned_path("work").mkdir(exist_ok=True)
        self._owned_path("payloads").mkdir(exist_ok=True)

    def _context(self, sources, topic_id, intent, criterion):
        if not self.dynamic:
            return _scope(sources, topic_id, intent, criterion)
        from .task_spec import meaning_scope, meaning_key
        spec = self.task_spec
        _require((topic_id, intent, criterion) == (spec.topic, spec.goal, spec.criterion), 'memory_dynamic_context')
        return dict(sources=_source_scope(sources, dynamic=True), policy=self.policy,
            meaning=meaning_scope(spec, sources), meaning_key=meaning_key(spec, sources))

    def _owned_path(self, *components: str) -> Path:
        _require(all(type(part) is str and part and part not in (".", "..") and "/" not in part and "\\" not in part
            for part in components), "memory_logical_path_invalid")
        path = self.directory
        for part in components:
            path = path / part
            _require(not path.is_symlink(), "memory_owned_path_symlink")
        _require(path.resolve().is_relative_to(self.directory), "memory_path_outside_owned_directory")
        return path

    def _record_path(self, record_id: str) -> Path:
        _require(type(record_id) is str and _RECORD_ID.fullmatch(record_id) is not None, "memory_record_id_invalid")
        return self._owned_path("work", record_id.replace(":", "_") + ".json")

    def _check_record_inventory(self) -> None:
        files = list(self._owned_path("work").glob("*.json"))
        _require(len(files) <= MAX_RECORDS, "memory_record_count_limit")
        for path in files:
            _require(not path.is_symlink() and path.is_file() and path.stat().st_size <= MAX_RECORD_BYTES,
                "memory_record_file_boundary")

    def remember(self, *, outcome: object, sources: object, task_id: str, topic_id: str,
                 intent: str, criterion: str, now: int, ttl_seconds: int | None = None) -> str:
        """Attribute only closed owned validation refusals to this writeback seam."""
        try:
            return self._remember(outcome=outcome, sources=sources, task_id=task_id, topic_id=topic_id,
                intent=intent, criterion=criterion, now=now, ttl_seconds=ttl_seconds)
        except BoundedMemoryRefusal as error:
            raise BoundedMemoryRefusal(error.code, 'MEMORY_WRITEBACK_VALIDATION') from None
        except ValueError as error:
            if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str \
                    and error.args[0] in MEMORY_WRITEBACK_ERROR_CODES:
                raise BoundedMemoryRefusal(error.args[0], 'MEMORY_WRITEBACK_VALIDATION') from None
            raise

    def _remember(self, *, outcome: object, sources: object, task_id: str, topic_id: str,
                  intent: str, criterion: str, now: int, ttl_seconds: int | None = None) -> str:
        """Write only validated actual accepted Work, then a new local Root review."""
        if ttl_seconds is None:
            ttl_seconds = REUSE_WINDOW_SECONDS if self.dynamic else 3600
        _require(type(now) is int and type(ttl_seconds) is int and 0 < ttl_seconds <= 86400, "memory_finite_time")
        context = self._context(sources, topic_id, intent, criterion)
        # The injected validator must inspect the actual live native Work/Host and Root.
        try:
            verified = self.validate_outcome(outcome, sources)
        except BoundedMemoryRefusal as error:
            raise BoundedMemoryRefusal(error.code, 'MEMORY_WRITEBACK_VALIDATION') from None
        _require(type(verified) is dict, "memory_outcome_validator_must_return_verified_plain")
        accepted = _json_copy(verified)
        _require(accepted.get("task_id") == task_id and accepted.get("criterion") == criterion
            and accepted.get("topic") == topic_id and accepted.get("goal") == intent,
            "memory_accepted_task_binding")
        _require(_source_scope(accepted.get("sources"), dynamic=self.dynamic) == context["sources"], "memory_accepted_source_binding")
        started, native_valid_to = accepted.get("accepted_at"), accepted.get("valid_to")
        _require(type(started) is int and type(native_valid_to) is int and started <= now < native_valid_to,
            "memory_accepted_time_binding")
        valid_to = min(native_valid_to, started + ttl_seconds)
        if self.dynamic:
            valid_to = reuse_valid_to(started, valid_to)
        _require(now < valid_to, "memory_writeback_expired")
        effective_ttl = valid_to - started
        payload = memory_payload_bytes(accepted, sources, task_id=task_id, topic_id=topic_id, intent=intent,
            criterion=criterion, task_spec=self.task_spec)
        material = json.loads(payload)
        _require(accepted.get("version") == self.result_version
            and accepted.get("semantic_pipeline", {}).get("version") == self.pipeline_version,
            "memory_write_requires_causal_v02")
        assert_no_sensitive_drs_keys(material)
        _require(_canonical(material) == payload, 'memory_payload_canonical_binding')
        payload_sha = _sha(payload)
        scope_hash = _sha(_canonical(context))
        writeback = _review(self.root_review, root_id=self.owning_root_id, candidate_id="memory_write:" + payload_sha,
            material=material, checks=dict(actual_work_validated=True, exact_sources=True, current_time=now < valid_to),
            now=now, transaction_id="memory_writeback:" + payload_sha, predicate="radik_document_memory_writeback",
            subject="radik:accepted_document_result")
        original_root = accepted.get("root")
        _require(type(original_root) is dict and type(original_root.get("result")) is dict,
            "memory_original_root_provenance")
        original_decision = original_root["result"]["decision_id"]
        semantic = address.build_semantic_address_v01(namespace="radik", domain=DOMAIN,
            subject_class="accepted_dynamic_document_result" if self.dynamic else "accepted_two_document_result",
            intent_class="context_lookup", meaning_schema_id="radik.dynamic.memory" if self.dynamic else "radik.document.memory",
            meaning_schema_version="v01" if self.dynamic else "v02")
        envelope = address.build_drs_time_envelope_v01(pt_created_at=started, kt_as_of=started, et_observed_at=started,
            ct_context_anchor=started, ttl_seconds=effective_ttl, valid_from=started, valid_to=valid_to,
            source_observed_at=started, source_reported_at=started, system_ingested_at=now, system_verified_at=now,
            freshness_policy_id=FRESHNESS)
        write_result = roots.root_decision_result_to_plain_dict_v01(writeback[2])
        authority = address.build_drs_authority_envelope_v01(authority_class="ROOT_ACCEPTED_WORK",
            owning_local_root_id=self.owning_root_id, source_root_decision_input_id=writeback[1].decision_input_id,
            source_root_decision_id=writeback[2].decision_id, source_root_decision_hash=_sha(_canonical(write_result)),
            authority_scope_fingerprint=scope_hash, root_acceptance_state="ACCEPTED_WORK", recording_component="radik:document_memory")
        pointer = address.build_artifact_pointer_v01(storage_class="LOCAL_DOCUMENT", object_reference=payload_sha,
            content_sha256=payload_sha, media_type="application/json", byte_length=len(payload), access_policy_id=ACCESS_POLICY,
            sensitivity_class="INTERNAL", allowed_use_classes=("OPEN_ONE_ARTIFACT",), forbidden_use_classes=(),
            summary_read_permitted=True, payload_read_permitted=True)
        summary = ("Accepted document Work result. The exact profile result, source bindings and original Root "
            "provenance are in the controlled local artifact. Current eligibility and fresh Root descent are required.")
        record = address.build_meaning_record_v01(semantic_address=semantic, predecessor_record_id=None,
            supersession_reason=None, safe_summary=summary, semantic_tags=("document", "accepted_result"),
            resonance_reason="Actual accepted document Work; new current eligibility and independent descent required.",
            memory_pointers=(), artifact_pointers=(pointer,), source_reference_ids=tuple(row["sha256"] for row in context["sources"])
                + (_sha(accepted["result_id"].encode("utf-8")), original_decision), lineage_edges=(), time_envelope=envelope, authority_envelope=authority,
            persistent_lifecycle_state="ACTIVE", risk_hints=(), conflict_hints=(), reuse_policy_class="CONTEXT_ONLY",
            policy_version=self.policy, schema_versions=(self.policy,), content_fingerprint=payload_sha, recording_component="radik:document_memory")
        path = self._owned_path("payloads", payload_sha + ".json")
        if path.exists():
            _require(path.read_bytes() == payload, "memory_payload_identity_conflict")
        else:
            with path.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        self._check_record_inventory()
        existing = list(self._owned_path("work").glob("*.json"))
        _require(len(existing) < MAX_RECORDS or self._record_path(record.meaning_record_id).exists(), "memory_record_count_limit")
        stored_content = dict(kind="accepted_dynamic_result" if self.dynamic else "accepted_document_result",
            topic_id=topic_id, intent=intent, criterion=criterion, worldstate=context,
            record=address.meaning_record_to_plain_data_v01(record), writeback_root=write_result)
        if self.dynamic:
            stored_content['meaning_key'] = context['meaning_key']
        stored = resolver.write_semantic_record(LocalDRS(self.directory), resolver.SemanticDRSRecordInput(
            record_id=record.meaning_record_id, domain=DOMAIN,
            record_type="radik_accepted_dynamic_result_v01" if self.dynamic else "radik_accepted_document_result_v02",
            content=stored_content,
            semantic_keys=("document", "accepted_result"), time_envelope=dict(pt_created_at=_stamp(started), kt_asof=_stamp(started),
                et_observed_at=_stamp(started), ct_session_anchor=task_id, ttl_seconds=effective_ttl, freshness_class="static",
                valid_from=_stamp(started), valid_to=_stamp(valid_to)), provenance=dict(request_id=task_id,
                created_by="radik:document_memory", trace_refs=[dict(trace_id=accepted["result_id"])]),
            root_final_ref=writeback[2].decision_id, worldstate_ref=scope_hash))
        _require(self._record_path(record.meaning_record_id).stat().st_size <= MAX_RECORD_BYTES, "memory_record_size_limit")
        _require(path.read_bytes() == payload, 'memory_writeback_payload_readback')
        record_readback = self._record_path(record.meaning_record_id).read_bytes()
        _require(_canonical(json.loads(record_readback)) == _canonical(stored), 'memory_writeback_record_readback')
        self.events.append(dict(operation="WRITEBACK", record_id=record.meaning_record_id, payload_sha256=payload_sha,
            actual_result_id=accepted["result_id"], original_root_decision_id=original_decision,
            writeback_root_decision_id=writeback[2].decision_id, persisted_record_sha256=_sha(_canonical(stored)),
            original_accepted_at=started, valid_to=valid_to, creates_permission=False))
        return record.meaning_record_id

    def select(self, *, sources: object, task_id: str, topic_id: str, intent: str,
               criterion: str, now: int) -> MemorySelection | None:
        """Search a new store, read the selected saved record, and approve exact bytes."""
        _require(type(now) is int, "memory_current_time_type")
        context = self._context(sources, topic_id, intent, criterion)
        scope_hash = _sha(_canonical(context))
        if self.dynamic:
            self.events.append(dict(operation='SEARCH_SCOPE', meaning_key=context['meaning_key'],
                policy=self.policy, profile=self.task_spec.profile,
                legacy_compatibility='DISTINCT_PROFILE_CRITERION_POLICY_NOT_ADAPTED',
                authority_on_restart='NOT_RESTORED'))
        self._check_record_inventory()
        # A new resolver/store instance prevents accidental use of a producer's record object.
        store = LocalDRS(self.directory)
        search = resolver.SemanticResolveQuery(query_id="memory_search:" + _sha(_canonical(dict(task_id=task_id,
            context=context, now=now))), domain=DOMAIN, semantic_terms=("document", "accepted_result"),
            content_filters=dict(kind="accepted_dynamic_result", meaning_key=context['meaning_key']) if self.dynamic
                else dict(kind="accepted_document_result", topic_id=topic_id, intent=intent, criterion=criterion),
            temporal_query=dict(as_of=_stamp(now)), worldstate=context, max_candidates=MAX_RECORDS, require_root_review=True)
        try:
            found = resolver.resolve_semantic_candidates(store, search, layers=("work",))
        except (ValueError, OSError, TypeError, KeyError) as error:
            self.events.append(dict(operation="SEARCH_REFUSED", reason=type(error).__name__, query_id=search.query_id))
            return None
        self.events.append(dict(operation="SEARCH", query_id=search.query_id, candidate_ids=[row.record_id for row in found.candidates],
            new_store_instance=True, current_task_id=task_id))
        for candidate in found.candidates:
            try:
                record_id = candidate.record_id
                raw = self._record_path(record_id).read_bytes()
                _require(len(raw) <= MAX_RECORD_BYTES, "memory_record_size_limit")
                saved = json.loads(raw)
                _require(saved["record_id"] == record_id and saved["domain"] == DOMAIN and saved["layer"] == "work"
                    and saved["status"] == "active",
                    "memory_swapped_wrapper")
                content = saved["content"]
                record = reconstruct_meaning_record(content["record"])
                _require(record.meaning_record_id == record_id, "memory_swapped_record_identity")
                _require(content["worldstate"] == context and record.authority_envelope.authority_scope_fingerprint == scope_hash,
                    "memory_current_source_or_scope_mismatch")
                _require(record.policy_version == self.policy and record.authority_envelope.owning_local_root_id == self.owning_root_id,
                    "memory_current_policy_or_owner_mismatch")
                historical_root = content["writeback_root"]
                _require(historical_root["decision_id"] == record.authority_envelope.source_root_decision_id
                    and historical_root["decision_input_id"] == record.authority_envelope.source_root_decision_input_id
                    and _sha(_canonical(historical_root)) == record.authority_envelope.source_root_decision_hash
                    and historical_root["decision"] == "ACCEPT", "memory_saved_root_provenance_binding")
                envelope = record.time_envelope
                query = resolution.build_drs_temporal_query_v01(query_mode="CURRENT_DECISION",
                    semantic_address_id=record.semantic_address.semantic_address_id, scope_fingerprint=scope_hash,
                    as_of=now, evaluation_time=now, evaluation_time_source="INJECTED_CURRENT_DECISION_TIME",
                    time_range_start=now, time_range_end=now+1, required_time_axes=("PT", "KT", "ET", "CT", "TTL", "VALIDITY"),
                    freshness_policy_id=envelope.freshness_policy_id,
                    max_age_seconds=min(envelope.ttl_seconds, REUSE_WINDOW_SECONDS) if self.dynamic else envelope.ttl_seconds, domain=DOMAIN,
                    risk_class="LOW", reuse_intent="CONTEXT", requested_reuse_classes=("CONTEXT_ONLY",),
                    required_evidence_classes=("SOURCE_IDENTITY", "SOURCE_INTEGRITY", "PROVENANCE_CHAIN", "TIME_FITNESS",
                        "POLICY_COMPATIBILITY", "SCHEMA_COMPATIBILITY", "CONFLICT_CLEARANCE", "ROOT_DECISION", "SOURCE_HISTORY"),
                    forbidden_changes=("POLICY_CHANGED",), policy_version=self.policy, schema_versions=(self.policy,),
                    owning_local_root_id=self.owning_root_id)
                evaluated = resolution.evaluate_drs_candidate_v01(semantic_address=record.semantic_address,
                    query=query, meaning_record=record)
                self.events.append(dict(operation="READBACK_ELIGIBILITY", record_id=record_id,
                    raw_record_sha256=_sha(raw), record_plain_sha256=_sha(_canonical(content["record"])),
                    time_envelope=address.drs_time_envelope_to_plain_data_v01(envelope),
                    evaluation=resolution.query_evaluation_state_to_plain_data_v01(evaluated)))
                _require(not candidate.blocked and evaluated.eligible_for_ranking, "memory_typed_current_eligibility_refused")
                pointer = record.artifact_pointers[0]
                _require(pointer.storage_class == "LOCAL_DOCUMENT" and pointer.access_policy_id == ACCESS_POLICY
                    and pointer.object_reference == pointer.content_sha256
                    and record.content_fingerprint == pointer.content_sha256 and _HASH.fullmatch(pointer.content_sha256) is not None
                    and type(pointer.byte_length) is int and 0 < pointer.byte_length <= MAX_PAYLOAD_BYTES,
                    "memory_closed_artifact_pointer")
                budget = resolution.build_memory_descent_budget_v01(max_depth=1, max_records_opened=1, max_pointers_opened=1,
                    max_artifacts_opened=1, max_bytes_opened=pointer.byte_length, max_lineage_edges=0, max_conflict_records=0)
                plan = resolution.build_retrieval_plan_v01(query_id=query.query_id,
                    semantic_address_id=record.semantic_address.semantic_address_id, proposed_record_ids=(record_id,),
                    proposed_memory_pointer_ids=(), proposed_artifact_pointer_ids=(pointer.pointer_id,),
                    requested_descent_class="OPEN_ONE_ARTIFACT", proposed_budget_id=budget.memory_descent_budget_id,
                    required_access_policy_ids=(ACCESS_POLICY,), reason_codes=())
                plan_plain = resolution.retrieval_plan_to_plain_data_v01(plan)
                current = _review(self.root_review, root_id=self.owning_root_id, candidate_id=plan.retrieval_plan_id,
                    material=plan_plain, checks=dict(typed_eligible=evaluated.eligible_for_ranking, current_sources=True, owned_payload=True),
                    now=now, transaction_id=query.query_id, predicate="approve_controlled_memory_descent_plan_v01",
                    subject=record.semantic_address.semantic_address_id)
                root_hash = integrity.domain_separated_sha256_hex_v01(domain="hedgehog:drs:memory_descent_root_result_binding:v01",
                    payload=_canonical(roots.root_decision_result_to_plain_dict_v01(current[2])))
                request = resolution.build_memory_descent_request_v01(retrieval_plan_id=plan.retrieval_plan_id,
                    query_id=query.query_id, owning_local_root_id=self.owning_root_id, root_kernel_id=current[0].kernel_id,
                    root_decision_input_id=current[1].decision_input_id, root_decision_id=current[2].decision_id,
                    root_decision_hash=root_hash, requested_descent_class="OPEN_ONE_ARTIFACT", approved_descent_class="OPEN_ONE_ARTIFACT",
                    proposed_budget_id=budget.memory_descent_budget_id, approved_budget=budget, approved_record_ids=(record_id,),
                    approved_memory_pointer_ids=(), approved_artifact_pointer_ids=(pointer.pointer_id,))
                # Files are opened only by this trusted adapter after current Root approval.
                payload_path = self._owned_path("payloads", pointer.content_sha256 + ".json")
                _require(payload_path.stat().st_size == pointer.byte_length, "memory_persisted_payload_size")
                payload = payload_path.read_bytes()
                _require(_sha(payload) == pointer.content_sha256, "memory_persisted_payload_corrupt")
                descent = resolution.execute_local_memory_descent_v01(retrieval_plan=plan, proposed_budget=budget,
                    descent_request=request, root_kernel=current[0], root_decision_input=current[1], root_decision_result=current[2],
                    source_records=(record,), artifact_payloads=((pointer.pointer_id, payload),))
                _require(descent.opened_record_ids == (record_id,) and descent.opened_artifact_pointer_ids == (pointer.pointer_id,)
                    and descent.opened_payload_fingerprints == (pointer.content_sha256,) and descent.bytes_opened == len(payload)
                    and descent.limits_respected and not descent.reason_codes, "memory_actual_descent_material_binding")
                material = json.loads(payload)
                same_meaning = material.get('meaning_key') == context['meaning_key'] if self.dynamic else (
                    material.get('topic_id') == topic_id and material.get('intent') == intent and material.get('criterion') == criterion)
                _require(_canonical(material) == payload and material["version"] == self.payload_version
                    and _source_scope(material["sources"], dynamic=self.dynamic) == context["sources"] and same_meaning,
                    "memory_selected_payload_source_or_context")
                accepted = material["outcome"]
                _require(accepted.get("version") == self.result_version
                    and accepted.get("semantic_pipeline", {}).get("version") == self.pipeline_version,
                    "memory_legacy_result_not_causally_qualified")
                # This verifier checks closed proposal/span/Work/Root provenance as data.
                # It must not reconstruct a live Host or grant from historical JSON.
                checked_accepted = self.validate_persisted_outcome(accepted, sources)
                _require(type(checked_accepted) is dict and _canonical(checked_accepted) == _canonical(accepted),
                    "memory_saved_outcome_not_verified")
                _require(_source_scope(accepted["sources"], dynamic=self.dynamic) == context["sources"]
                    and accepted["accepted_at"] == envelope.pt_created_at and envelope.valid_to <= accepted["valid_to"]
                    and record.source_reference_ids == tuple(row["sha256"] for row in context["sources"])
                        + (_sha(accepted["result_id"].encode("utf-8")), accepted["root"]["result"]["decision_id"]),
                    "memory_original_work_provenance_binding")
                selected = MemorySelection(record_id, pointer.content_sha256, material,
                    resolution.memory_descent_result_to_plain_data_v01(descent), current[2].decision_id,
                    historical_root["decision_id"], content["record"], _sha(raw))
                self.events.append(dict(operation="DESCENT_APPROVED", record_id=record_id,
                    payload_sha256=pointer.content_sha256, descent_id=descent.memory_descent_result_id,
                    current_root_decision_id=current[2].decision_id, historical_task_id=material["task_id"],
                    current_task_id=task_id, current_authority_restored=False))
                return selected
            except (ValueError, OSError, TypeError, KeyError, AttributeError) as error:
                known = {'memory_swapped_wrapper', 'memory_swapped_record_identity',
                    'memory_current_source_or_scope_mismatch', 'memory_current_policy_or_owner_mismatch',
                    'memory_saved_root_provenance_binding', 'memory_typed_current_eligibility_refused',
                    'memory_closed_artifact_pointer', 'memory_persisted_payload_size',
                    'memory_persisted_payload_corrupt', 'memory_actual_descent_material_binding',
                    'memory_selected_payload_source_or_context', 'memory_legacy_result_not_causally_qualified',
                    'memory_saved_outcome_not_verified', 'memory_original_work_provenance_binding'}
                reason = error.code if type(error) is BoundedMemoryRefusal else (
                    error.args[0] if type(error) is ValueError and len(error.args) == 1
                    and type(error.args[0]) is str and error.args[0] in known else 'UNKNOWN')
                self.events.append(dict(operation="CANDIDATE_REFUSED", record_id=candidate.record_id, reason=reason))
        return None
