"""PURE full-closure source successor consumer, with a genuine U2 predecessor.

The old business output is transition evidence. Every current business branch
is recomputed here; this contract never claims retained business consumption.
"""
import json

from hedgehog.kernel import effect_firewall_v01 as firewall
from . import native_authority as authority
from .contracts import canonical, digest, require
from .task_spec import TaskSpec
from .dynamic_work import _candidate, extract, business_result


def compute(data):
    require(set(data)=={'material','previous'},'dynamic_full_delta_input_shape')
    material,previous=data['material'],data['previous']
    spec=TaskSpec.from_plain(material['task'])
    require(material['mode']=='source_delta' and material['prior_business_sha256']==digest(previous)
        and previous['version']=='radik.dynamic.business.v01' and previous['profile']==spec.profile
        and previous['criterion']==spec.criterion,'dynamic_full_delta_prior_meaning')
    if spec.profile=='verify':
        require(previous['supplied_candidate']==spec.supplied_candidate,'dynamic_full_delta_verify_candidate')
    candidate=_candidate(spec,material['candidate'],material['sources'],material['family'])
    require(material['intake']['task_spec_sha256']==digest(spec.plain())
        and material['intake']['current_source_scope_sha256']==candidate['source_scope_sha256'],
        'dynamic_full_delta_current_intake')
    branches=[extract(dict(source=s,claims=[c for c in candidate['claims'] if c['source_ref']==s['source_ref']]))
        for s in material['sources']]
    return {'result':canonical(business_result(spec,candidate,branches)).decode()}


def _decode(inputs):
    return {name:json.loads(value) for name,value in authority.values(inputs).items()}


def validate_inputs(definition,inputs):
    errors=firewall.validate_capability_values_v01(definition.input_fields,inputs)
    if not errors:
        try:compute(_decode(inputs))
        except (ValueError,TypeError,KeyError):errors=('dynamic_full_delta_input_contract',)
    return firewall.build_capability_validation_evidence_v01(definition=definition,values=inputs,
        invocation_id=None,valid=not errors,reason_codes=errors)


def execute(invocation):
    require(invocation.candidate_id is None and invocation.packet_id is None,'dynamic_full_delta_pure_boundary')
    return authority.records({key:('TEXT',value) for key,value in compute(_decode(invocation.inputs)).items()})


def validate_outputs(definition,invocation,output):
    errors=firewall.validate_capability_values_v01(definition.output_fields,output)
    if not errors and authority.values(output)!=compute(_decode(invocation.inputs)):
        errors=('dynamic_full_delta_output_contract',)
    return firewall.build_capability_validation_evidence_v01(definition=definition,values=output,
        invocation_id=invocation.invocation_id,valid=not errors,reason_codes=errors)
