"""Pure source qualification capabilities; no I/O, providers or permissions.

The Boolean predicts absence of explicit unresolved markers in the approved raw
documents. It does not measure answer quality, external truth or model honesty.
"""
import json
import re

from hedgehog.kernel import effect_firewall_v01 as firewall
from . import native_authority as authority
from .dynamic_roles import source_scope

VERIFY = 'radik.experience.source_verification.v01'
AUDIT = 'radik.experience.source_condition_audit.v01'
MARKER = re.compile(r'\b(?:unknown|unspecified|undisclosed|tbd|not\s+specified)\b', re.IGNORECASE)


def compute(material, operation):
    authority.require(type(material) is dict and set(material) == {
        'version', 'scope_sha256', 'accepted_result_sha256', 'checks'}, 'experience_material_shape')
    authority.require(material['version'] == 'radik.qualified_material.v01'
        and operation in (VERIFY, AUDIT) and len(material['checks']) == 1, 'experience_material_profile')
    check = material['checks'][0]
    authority.require(type(check) is dict and set(check) == {'semantic_ref', 'observations'}, 'experience_check_shape')
    observations = check['observations']
    authority.require(type(observations) is list and 1 <= len(observations) <= 4, 'experience_observation_bound')
    sources = []
    findings = []
    for observation in observations:
        authority.require(set(observation) == {'observation_id', 'source'}, 'experience_observation_shape')
        source = observation['source']
        source_scope([source])
        authority.require(observation['observation_id'] == 'radik:observation:' + authority.digest(
            {key: source[key] for key in ('source_ref', 'revision', 'sha256')}), 'experience_observation_identity')
        sources.append(source)
        for match in MARKER.finditer(source['text']):
            start = len(source['text'][:match.start()].encode('utf-8'))
            raw = match.group().encode('utf-8')
            findings.append(dict(source_ref=source['source_ref'], revision=source['revision'],
                sha256=source['sha256'], start=start, end=start + len(raw), quote=match.group()))
    authority.require(len({source['source_ref'] for source in sources}) == len(sources)
        and len(findings) <= 128, 'experience_source_or_finding_bound')
    result = dict(stage='RESULT', input_sha256=authority.digest(material),
        semantic_refs=[check['semantic_ref']], checks=[dict(semantic_ref=check['semantic_ref'], healthy=not findings)],
        predicate='ABSENCE_OF_EXPLICIT_UNRESOLVED_SOURCE_MARKERS',
        qualified_scope='Approved raw source markers only; no external truth or model quality claim.')
    if operation == AUDIT:
        result.update(findings=findings, checked_source_scope=source_scope(sources),
            finding_count=len(findings), next_review='CHECK_UNRESOLVED_SOURCE_CONDITIONS' if findings else 'NO_MARKER_FOUND')
    return result


def validate_inputs(definition, inputs):
    errors = firewall.validate_capability_values_v01(definition.input_fields, inputs)
    try:
        if not errors:
            values = authority.values(inputs)
            authority.require(set(values) == {'material'} and len(values['material'].encode()) <= 131072,
                'experience_input_bound')
            compute(json.loads(values['material']), definition.operation_id)
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        errors = (str(error),)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=inputs,
        invocation_id=None, valid=not errors, reason_codes=errors)


def validate_outputs(definition, invocation, output):
    errors = firewall.validate_capability_values_v01(definition.output_fields, output)
    try:
        if not errors:
            expected = compute(json.loads(authority.values(invocation.inputs)['material']), definition.operation_id)
            authority.require(authority.values(output) == {'material': authority.canonical(expected).decode()},
                'experience_output_binding')
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        errors = (str(error),)
    return firewall.build_capability_validation_evidence_v01(definition=definition, values=output,
        invocation_id=invocation.invocation_id, valid=not errors, reason_codes=errors)


def execute_verify(invocation):
    result = compute(json.loads(authority.values(invocation.inputs)['material']), VERIFY)
    return authority.records(dict(material=('TEXT', authority.canonical(result).decode())))


def execute_audit(invocation):
    result = compute(json.loads(authority.values(invocation.inputs)['material']), AUDIT)
    return authority.records(dict(material=('TEXT', authority.canonical(result).decode())))
