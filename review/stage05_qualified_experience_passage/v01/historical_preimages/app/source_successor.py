"""Durable source transitions are historical facts, never restored authority.

The canonical TaskStore remains the sole task inventory. This finite sidecar
records source revisions separately from immutable TaskSpec/origin dependencies.
An indexed missing/partial record is a refusal; readers never search directories.
"""
from dataclasses import dataclass
import json
import uuid

from .contracts import canonical, digest, require
from .task_spec import TaskSpec, meaning_key, meaning_scope
from .normal_session import _read, _reference, _exclusive, _replace, _path

INDEX = 'workspace/owner_documents/state/dynamic_source_successors.json'
RECORDS = 'workspace/owner_documents/state/source_successors/'
VERSION = 'radik.source_successor.v01'
MAX_RECORDS = 512
_ORIGIN = object()
TERMINAL = ('ACCEPTED', 'FAILED', 'CANCELLED', 'RESTART_INTERRUPTED')
NEXT = {'STAGED': ('ROUND_LINKED', 'FAILED', 'CANCELLED', 'RESTART_INTERRUPTED'),
    'ROUND_LINKED': ('STARTED', 'FAILED', 'CANCELLED', 'RESTART_INTERRUPTED'),
    'STARTED': ('PLANNED', 'FAILED', 'CANCELLED', 'RESTART_INTERRUPTED'),
    'PLANNED': ('ACCEPTED', 'FAILED', 'CANCELLED', 'RESTART_INTERRUPTED')}


def dependencies(spec, sources):
    require(type(spec) is TaskSpec, 'source_successor_task_type')
    return dict(meaning_key=meaning_key(spec, sources), sources=meaning_scope(spec, sources)['sources'])


def _root(store):
    root=store.project.parent.parent
    require(store.project==root/'workspace/owner_documents','source_successor_canonical_task_store')
    return root


def read(store):
    """Read exactly the registered records, including grants without a start."""
    require(not _path(_root(store), INDEX + '.pending').exists(), 'source_successor_partial_index')
    if not _path(_root(store), INDEX).exists():
        return [], {}
    index = json.loads(_read(_root(store), INDEX, 262144))
    require(type(index) is dict and set(index) == {'schema', 'records'}
        and index['schema'] == VERSION and type(index['records']) is list
        and len(index['records']) <= MAX_RECORDS, 'source_successor_index')
    latest, seen, paths = {}, set(), set()
    for ordinal, reference in enumerate(index['records']):
        row = _reference(_root(store), reference)
        require(type(row) is dict and set(row) == {'schema', 'ordinal', 'successor_id', 'task_id',
            'task_spec_sha256', 'previous_ref', 'base', 'status', 'round_binding', 'plan', 'result_ref', 'at'}
            and row['schema'] == VERSION and row['ordinal'] == ordinal
            and type(row['successor_id']) is str and len(row['successor_id']) == 32
            and all(ch in '0123456789abcdef' for ch in row['successor_id'])
            and reference['path'] == RECORDS + row['successor_id'] + '-' + str(ordinal) + '.json'
            and reference['path'] not in paths and row['task_id'] in store.state['tasks']
            and row['task_spec_sha256'] == digest(store.state['tasks'][row['task_id']]['spec'])
            and type(row['at']) is int and row['at'] >= 0, 'source_successor_record')
        paths.add(reference['path'])
        previous = latest.get(row['successor_id'])
        if previous is None:
            require(row['status'] == 'STAGED' and row['previous_ref'] is None
                and row['round_binding'] is None and row['plan'] is None and row['result_ref'] is None
                and set(row['base']) == {'old_dependencies', 'new_dependencies', 'prior_result_ref',
                    'prior_root_sha256', 'changed_sources', 'affected_graph'}
                and (row['task_id'], digest(row['base']['new_dependencies'])) not in seen,
                'source_successor_duplicate_or_origin')
            seen.add((row['task_id'], digest(row['base']['new_dependencies'])))
        else:
            old_ref, old = previous
            require(row['previous_ref'] == old_ref and row['status'] in NEXT.get(old['status'], ())
                and all(row[key] == old[key] for key in ('task_id', 'task_spec_sha256', 'base'))
                and row['at'] >= old['at'], 'source_successor_transition')
            require(old['round_binding'] is None or row['round_binding'] == old['round_binding'],
                'source_successor_round_changed')
            require(old['plan'] is None or row['plan'] == old['plan'], 'source_successor_plan_changed')
        require(row['status'] in NEXT or row['status'] in TERMINAL, 'source_successor_status')
        if row['status'] in ('ROUND_LINKED', 'STARTED', 'PLANNED', 'ACCEPTED'):
            binding = row['round_binding']
            require(type(binding) is dict and binding['task_id'] == row['task_id']
                and binding['task_spec_sha256'] == row['task_spec_sha256']
                and binding['dependencies_sha256'] == digest(row['base']['new_dependencies'])
                and binding['max_attempts'] == 3
                and binding['normal_round_scope']['mode'] == 'INFORMATIONAL_DELTA',
                'source_successor_round_binding')
        if row['status'] in ('PLANNED', 'ACCEPTED'):
            require(type(row['plan']) is dict and row['plan'].get('changed_sources') == row['base']['changed_sources'],
                'source_successor_plan_required')
        require((row['result_ref'] is not None) == (row['status'] == 'ACCEPTED'),
            'source_successor_result_state')
        latest[row['successor_id']] = (reference, row)
    active = [r for _ref, r in latest.values() if r['status'] not in TERMINAL]
    require(len({r['task_id'] for r in active}) == len(active), 'source_successor_duplicate_active')
    return index['records'], latest


def _append(store, row):
    records, _latest = read(store)
    require(len(records) < MAX_RECORDS, 'source_successor_journal_limit')
    row = dict(row, schema=VERSION, ordinal=len(records), at=int(store.clock()))
    path = RECORDS + row['successor_id'] + '-' + str(len(records)) + '.json'
    reference = dict(path=path, sha256=digest(row))
    # Index first: any interruption remains finitely discoverable and refuses.
    value = dict(schema=VERSION, records=records + [reference])
    if _path(_root(store), INDEX).exists():
        _replace(_root(store), INDEX, value)
    else:
        _exclusive(_root(store), INDEX, value)
    _exclusive(_root(store), path, row)
    read(store)
    return reference


@dataclass(frozen=True)
class SourceSuccessor:
    store: object
    successor_id: str
    staged_ref: dict
    _origin: object


def current_dependencies(store, task_id):
    _records, latest = read(store)
    accepted = [row for _ref, row in latest.values() if row['task_id'] == task_id and row['status'] == 'ACCEPTED']
    if not accepted:
        return store.state['tasks'][task_id]['origin_dependencies']
    row = max(accepted, key=lambda r: r['ordinal'])
    require(row['result_ref'] in store.state['tasks'][task_id]['results'],
        'source_successor_accepted_result_changed')
    current = store.result(task_id)
    require(current['task']==store.spec(task_id).plain() and current['sources']==row['base']['new_dependencies']['sources'],
        'source_successor_latest_result_dependencies')
    return row['base']['new_dependencies']


def stage(store, task_id, sources, *, affected_graph):
    spec = store.spec(task_id)
    require(store.state['active_task_id'] is None and store.state['tasks'][task_id]['status'] == 'COMPLETED',
        'source_successor_completed_task_required')
    old, new = current_dependencies(store, task_id), dependencies(spec, sources)
    require(old is not None and old != new and type(affected_graph) is dict, 'source_successor_changed_dependencies')
    old_sources, new_sources = old['sources'], new['sources']
    require([s['source_ref'] for s in old_sources] == [s['source_ref'] for s in new_sources],
        'source_successor_resource_scope_changed')
    changed = []
    for before, after in zip(old_sources, new_sources, strict=True):
        if before != after:
            require(after['revision'] > before['revision'] and after['sha256'] != before['sha256'],
                'source_successor_revision_required')
            changed.append(after['source_ref'])
    require(bool(changed) and affected_graph.get('changed_sources') == changed, 'source_successor_affected_sources')
    _records, latest = read(store)
    require(not any(row['task_id'] == task_id and (row['status'] not in TERMINAL
        or row['base']['new_dependencies'] == new) for _ref, row in latest.values()),
        'source_successor_no_retry_or_duplicate')
    result = store.result(task_id)
    require(result is not None and result['task'] == spec.plain() and result['sources'] == old_sources
        and type(result.get('root')) is dict, 'source_successor_prior_result_binding')
    identity = uuid.uuid4().hex
    row = dict(successor_id=identity, task_id=task_id, task_spec_sha256=digest(spec.plain()), previous_ref=None,
        base=dict(old_dependencies=old, new_dependencies=new,
            prior_result_ref=store.state['tasks'][task_id]['results'][-1], prior_root_sha256=digest(result['root']),
            changed_sources=changed, affected_graph=affected_graph), status='STAGED', round_binding=None, plan=None, result_ref=None)
    reference = _append(store, row)
    return SourceSuccessor(store, identity, reference, _ORIGIN)


def validate(store, token, sources=None, *, statuses=('STAGED',)):
    require(type(token) is SourceSuccessor and token.store is store and token._origin is _ORIGIN,
        'source_successor_live_origin')
    _records, latest = read(store)
    reference, row = latest[token.successor_id]
    require(row['status'] in statuses, 'source_successor_closed')
    if sources is not None:
        require(dependencies(store.spec(row['task_id']), sources) == row['base']['new_dependencies'],
            'source_successor_current_sources_changed')
    return reference, row


def advance(store, token, status, *, round_binding=None, plan=None, result_ref=None):
    reference, row = validate(store, token, statuses=tuple(NEXT))
    require(status in NEXT[row['status']], 'source_successor_transition')
    return _append(store, dict(row, previous_ref=reference, status=status,
        round_binding=row['round_binding'] if round_binding is None else round_binding,
        plan=row['plan'] if plan is None else plan, result_ref=result_ref))


def interrupt(store, *, task_id=None, disposition='RESTART_INTERRUPTED'):
    require(disposition in ('RESTART_INTERRUPTED', 'CANCELLED'), 'source_successor_interrupt_state')
    _records, latest = read(store)
    for reference, row in latest.values():
        if row['status'] not in TERMINAL and (task_id is None or row['task_id'] == task_id):
            _append(store, dict(row, previous_ref=reference, status=disposition, result_ref=None))
