"""Source/claim/Work dependency plans; plans confer no native authority."""
from .contracts import digest, require


def plan(old_sources, new_sources, old_candidate, new_candidate=None, *, spec):
    require(1 <= len(old_sources) == len(new_sources) <= 4, 'dynamic_delta_source_count')
    require([s['source_ref'] for s in old_sources] == [s['source_ref'] for s in new_sources],
        'dynamic_delta_resource_scope_changed')
    changed = [i for i, (a, b) in enumerate(zip(old_sources, new_sources, strict=True))
        if any(a[k] != b[k] for k in ('revision', 'sha256', 'text'))]
    require(len(changed) == 1, 'dynamic_delta_one_approved_source_required')
    index = changed[0]
    before, after = old_sources[index], new_sources[index]
    require(after['revision'] > before['revision'] and after['sha256'] != before['sha256'],
        'dynamic_delta_source_revision_required')
    candidate = old_candidate if new_candidate is None else new_candidate
    route = old_candidate['program']['route']
    require(candidate['program']['route'] == route, 'dynamic_delta_route_change_requires_new_intake')
    retained = []
    for i, source in enumerate(old_sources):
        if i != index:
            old_claims = [c for c in old_candidate['claims'] if c['source_ref'] == source['source_ref']]
            new_claims = [c for c in candidate['claims'] if c['source_ref'] == source['source_ref']]
            require(old_claims == new_claims, 'dynamic_delta_retained_claims_changed')
            retained.append(i)
    source_nodes = ['source:' + source['source_ref'] for source in old_sources]
    if route == 'short':
        # The actual short capability consumes every source in one literal.
        nodes = [dict(id='short0', dependencies=source_nodes + ['candidate', 'family'])]
        affected, retained_work = ['short0'], []
        groups = [list(range(len(old_sources)))] * 3
        native_scope = 'FULL_CLOSURE_NO_RETAINED_PROOF'
    else:
        nodes = [dict(id='extract' + str(i), dependencies=[source_nodes[i], 'claims:' + source['source_ref']])
            for i, source in enumerate(old_sources)]
        exception_source = next((c['source_ref'] for c in candidate['claims'] if c['kind'] == 'exception'),
            old_sources[0]['source_ref'])
        audit_index = next(i for i, s in enumerate(old_sources) if s['source_ref'] == exception_source)
        nodes.extend((dict(id='gate0', dependencies=['candidate']),
            dict(id='audit0', dependencies=['extract' + str(audit_index), 'gate0'])))
        enabled = candidate['program']['optional_exceptions'] and any(c['kind'] == 'exception' for c in candidate['claims'])
        parent = ['extract' + str(i) for i in range(len(old_sources))] + ['candidate', 'family']
        if enabled:
            parent.append('audit0')
        nodes.append(dict(id='result0', dependencies=parent))
        affected_set = {source_nodes[index], 'claims:' + before['source_ref'], 'candidate', 'family'}
        for node in nodes:
            if affected_set.intersection(node['dependencies']):
                affected_set.add(node['id'])
        affected = [n['id'] for n in nodes if n['id'] in affected_set]
        retained_work = ['extract' + str(i) for i in retained]
        if len(old_sources) == 1:
            # Both control child calculations and parent depend on the sole
            # business branch; the full native closure is reported honestly.
            groups, native_scope = [[0], [0], [0]], 'FULL_CLOSURE_NO_RETAINED_PROOF'
        else:
            # One seed wrapper per child. Multiple Work leaves can feed that
            # seed; distinct document count never creates extra native cells.
            groups = [list(range(0, len(old_sources), 2)), list(range(1, len(old_sources), 2))]
            native_scope = 'STRICT_SUBSET_ONE_NATIVE_CHILD'
    return dict(schema='radik.dynamic.source_work_graph.v01',
        changed_sources=[before['source_ref']], changed_index=index, route=route,
        source_revisions=[dict(source_ref=s['source_ref'], old_revision=s['revision'], old_sha256=s['sha256'],
            new_revision=t['revision'], new_sha256=t['sha256']) for s, t in zip(old_sources, new_sources, strict=True)],
        source_claim_dependencies={s['source_ref']: digest([c for c in candidate['claims']
            if c['source_ref'] == s['source_ref']]) for s in new_sources},
        work_nodes=nodes, affected_work=affected, retained_work=retained_work,
        native_source_groups=groups, native_scope=native_scope,
        retained_business_claims_checked=new_candidate is not None,
        task_spec_sha256=digest(spec.plain()),
        verify_candidate_sha256=digest(spec.supplied_candidate) if spec.profile=='verify' else None)
