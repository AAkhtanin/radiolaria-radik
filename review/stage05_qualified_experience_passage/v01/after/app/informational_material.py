"""Generic approved informational source material; no controller or legacy imports."""
from dataclasses import replace
import re
from hedgehog import action_commit_packet_v02 as action, work_execution_host_v01 as hosts
from hedgehog.kernel import work_composition_v01 as work
from . import native_authority as authority
require,canonical,digest=authority.require,authority.canonical,authority.digest


def normalize_source(value):
    require(type(value)is dict and {'source_ref','revision','sha256','text'}<=set(value)<=
        {'source_ref','revision','sha256','text','observed_at'},'informational_source_shape')
    require(type(value['source_ref'])is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_:.-]{0,127}',value['source_ref'])
        and type(value['revision'])is int and value['revision']>0 and type(value['text'])is str,'informational_source_identity')
    raw=value['text'].encode('utf-8')
    require(0<len(raw)<=16384 and digest(raw)==value['sha256'],'informational_source_bytes')
    return {key:value[key]for key in ('source_ref','revision','sha256','text')}


def normalize_sources(values):
    require(type(values)in(list,tuple)and 1<=len(values)<=4,'informational_source_count')
    result=tuple(normalize_source(v)for v in values)
    require(len({v['source_ref']for v in result})==len(result),'informational_source_duplicates')
    return result


def descriptors(values):
    return [{key:value[key]for key in ('source_ref','revision','sha256')}for value in values]


def literal(name,value):
    return work.WorkInputBindingV01(name,work.WorkLiteralV01(action.build_action_effect_parameter_record_v01(
        parameter_name=name,value_type='TEXT',value=canonical(value).decode())))


class CurrentInformationalSource:
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

