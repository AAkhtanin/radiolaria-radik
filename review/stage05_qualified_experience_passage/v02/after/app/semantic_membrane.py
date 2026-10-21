"""Closed application projections over a separately validated native BSEP.

This module performs no I/O and calls no provider. Runtime owns role stages and
the actual observation receiver; ordinary provenance dictionaries never certify
their own producer. Native strings carry compact semantics, while bounded quoted
fragments live in this explicit application projection and remain evidence.
"""
from dataclasses import dataclass
import json
import re

from .contracts import canonical, digest, require

PIPELINE_VERSION = 'radik.semantic.pipeline.v02'
FAMILY_VERSION = 'radik.semantic.source_family.v02'
PROJECTION_VERSION = 'radik.semantic.architect_projection.v02'
FAMILY_TTL = 3600
PROVENANCE_KEYS = {'producer_kind', 'role', 'task_id', 'root_id', 'context_sha256',
    'response_id', 'reservation_id', 'wire_body_sha256', 'observation_sha256', 'product_sha256'}
ACTUAL_KINDS = {'orchestrator': 'ACTUAL_ORCHESTRATOR_OBSERVATION',
    'architect': 'ACTUAL_ARCHITECT_OBSERVATION', 'critic': 'ACTUAL_CRITIC_OBSERVATION'}
MEMORY_KINDS = {'orchestrator': 'DETERMINISTIC_MEMORY_ROUTE',
    'architect': 'DETERMINISTIC_MEMORY_ADAPTATION', 'critic': 'DETERMINISTIC_MEMORY_REVALIDATION'}
WITNESS_KEYS = {'pipeline_version', 'producer_kind', 'family_ref', 'projection_sha256',
    'candidate_sha256', 'critic_sha256', 'source_scope_sha256', 'source_binding_sha256',
    'critic_provenance_sha256', 'origin_intent_ref', 'origin_bsep_ref', 'origin_semantic_ref'}
_FAMILY_ORIGIN = object()


def checked_sources(sources):
    require(type(sources) in (list, tuple) and len(sources) == 2, 'membrane_two_sources')
    result = []
    for source in sources:
        require(type(source) is dict and type(source.get('text')) is str
            and type(source.get('source_ref')) is str and type(source.get('revision')) is int
            and source['revision'] >= 1, 'membrane_source_shape')
        raw = source['text'].encode('utf-8')
        require(0 < len(raw) <= 16384 and digest(raw) == source.get('sha256'), 'membrane_source_bytes')
        result.append({key: source[key] for key in ('source_ref', 'revision', 'sha256')})
    require(result[0]['source_ref'] != result[1]['source_ref'], 'membrane_source_identity')
    return result


def checked_policy(policy):
    require(type(policy) is dict and set(policy) == {'save_allowed', 'consent_ref', 'valid_to', 'revision', 'workspace_ref'},
        'membrane_policy_shape')
    require(type(policy['save_allowed']) is bool and type(policy['revision']) is int and policy['revision'] >= 1
        and type(policy['valid_to']) is int and policy['workspace_ref'] == 'radik:owned:output'
        and (policy['consent_ref'] is None or type(policy['consent_ref']) is str), 'membrane_policy_binding')
    return json.loads(canonical(policy))


def checked_provenance(value, product, *, role, task_id, root_id, memory=False):
    require(type(value) is dict and set(value) == PROVENANCE_KEYS, 'membrane_provenance_closed_fields')
    expected = MEMORY_KINDS[role] if memory else ACTUAL_KINDS[role]
    require(value['producer_kind'] == expected and value['role'] == role
        and value['task_id'] == task_id and value['root_id'] == root_id
        and value['product_sha256'] == digest(product), 'membrane_provenance_product_scope')
    hashes = ('context_sha256', 'observation_sha256', 'product_sha256')
    if not memory:
        hashes += ('wire_body_sha256',)
    require(all(type(value[name]) is str and re.fullmatch('[0-9a-f]{64}', value[name]) for name in hashes),
        'membrane_provenance_hashes')
    if memory:
        require(all(value[name] == 'NOT_CALLED:MEMORY' for name in ('response_id', 'reservation_id', 'wire_body_sha256')),
            'membrane_memory_no_provider_claim')
    else:
        require(all(type(value[name]) is str and 0 < len(value[name]) <= 256
            and value[name] != 'NOT_CALLED:MEMORY' for name in ('response_id', 'reservation_id')),
            'membrane_actual_observation_refs')
    return json.loads(canonical(value))


def approved_evidence(product, sources):
    by_ref = {source['source_ref']: source for source in sources}
    result = []
    for request in product['evidence_requests']:
        source = by_ref[request['source_ref']]
        raw = source['text'].encode('utf-8')
        quote = raw[request['start']:request['end']].decode('utf-8')
        result.append(dict(request, quote=quote, quote_sha256=digest(quote.encode('utf-8'))))
    return result


@dataclass(frozen=True)
class SemanticSourceFamily:
    """Live native family; JSON views are copies, never mutable role state."""
    source_context: object
    binding: object
    route_review: tuple
    native_sha256: str
    _scope_bytes: bytes
    _product_bytes: bytes
    _provenance_bytes: bytes
    _projection_bytes: bytes
    _evidence_bytes: bytes
    _origin: object

    @property
    def scope(self): return json.loads(self._scope_bytes)
    @property
    def product(self): return json.loads(self._product_bytes)
    @property
    def provenance(self): return json.loads(self._provenance_bytes)
    @property
    def projection(self): return json.loads(self._projection_bytes)
    @property
    def evidence(self): return json.loads(self._evidence_bytes)
    @property
    def kind(self): return self.provenance['producer_kind']
    @property
    def family_ref(self): return self.projection['family_ref']


def create_family(source_context, binding, route_review, native_sha256, *, scope, product, provenance, projection, evidence):
    return SemanticSourceFamily(source_context, binding, route_review, native_sha256,
        canonical(scope), canonical(product), canonical(provenance), canonical(projection), canonical(evidence), _FAMILY_ORIGIN)


def require_live_family(family):
    require(type(family) is SemanticSourceFamily and family._origin is _FAMILY_ORIGIN, 'membrane_live_family_required')
    return family


def selection_proof(family, candidate, source):
    claims = [claim for claim in candidate['claims'] if claim['source_ref'] == source['source_ref']]
    return dict(pipeline_version=PIPELINE_VERSION, family_ref=family.family_ref,
        projection_sha256=digest(family.projection), candidate_sha256=digest(candidate),
        source={key: source[key] for key in ('source_ref', 'revision', 'sha256')}, selected_claims_sha256=digest(claims))


def validate_selection_proof(proof, source, claims):
    require(type(proof) is dict and set(proof) == {'pipeline_version', 'family_ref', 'projection_sha256',
        'candidate_sha256', 'source', 'selected_claims_sha256'}, 'pure_selection_proof_shape')
    require(proof['pipeline_version'] == PIPELINE_VERSION and proof['source'] ==
        {key: source[key] for key in ('source_ref', 'revision', 'sha256')}
        and proof['selected_claims_sha256'] == digest(claims), 'pure_selection_source_binding')
    require(type(proof['family_ref']) is str and proof['family_ref'].startswith('radik:semantic_family:')
        and all(type(proof[name]) is str and re.fullmatch('[0-9a-f]{64}', proof[name])
            for name in ('projection_sha256', 'candidate_sha256')), 'pure_selection_identity')
    return proof


def validate_business_witness(witness, candidate, source_descriptors):
    require(type(witness) is dict and set(witness) == WITNESS_KEYS, 'pure_semantic_witness_shape')
    require(witness['pipeline_version'] == PIPELINE_VERSION and witness['producer_kind'] in
        ('ACTUAL_ORCHESTRATOR_OBSERVATION', 'DETERMINISTIC_MEMORY_ROUTE')
        and witness['candidate_sha256'] == digest(candidate)
        and witness['source_scope_sha256'] == digest(source_descriptors), 'pure_semantic_business_binding')
    require(all(type(witness[name]) is str and re.fullmatch('[0-9a-f]{64}', witness[name]) for name in
        ('projection_sha256', 'candidate_sha256', 'critic_sha256', 'source_scope_sha256',
         'source_binding_sha256', 'critic_provenance_sha256')), 'pure_semantic_witness_hashes')
    require(all(type(witness[name]) is str and 0 < len(witness[name]) <= 512 for name in
        ('family_ref', 'origin_intent_ref', 'origin_bsep_ref', 'origin_semantic_ref')), 'pure_semantic_origin_refs')
    return witness
