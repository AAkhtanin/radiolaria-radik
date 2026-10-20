"""Single-writer task queue, approved source registry and immutable result history."""
import json
import os
from pathlib import Path
import stat
import time
import uuid

from .contracts import canonical, digest, require
from .intake import ApprovedSourceStore
from .task_spec import TaskSpec, TASK_VERSION, TASK_ID, SOURCE_ID

STORE_VERSION = 'radik.dynamic.task_store.v01'
STATUSES = ('CLARIFICATION_REQUIRED', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED',
    'FAILED_AFTER_ACCEPTANCE', 'INTERRUPTED', 'CANCELLED')
MAX_TASKS = 64
MAX_STATE_BYTES = 1048576
MAX_RESULT_BYTES = 262144


def _copy(value):
    return json.loads(canonical(value))


class TaskStore:
    def __init__(self, project, *, clock=None, require_existing=False):
        self.project = Path(project).resolve(strict=True)
        self.clock = clock or time.time
        self._source_successors = {}
        self.state_path = self._path('state', 'dynamic_tasks.json')
        require(type(require_existing) is bool and (not require_existing or self.state_path.is_file()),
            'task_store_existing_state_required')
        for name in ('input', 'state', 'output'):
            self._path(name).mkdir(exist_ok=True)
        if self.state_path.exists():
            raw = self.state_path.read_bytes()
            require(len(raw) <= MAX_STATE_BYTES, 'task_store_size')
            self.state = json.loads(raw)
            self._validate()
        else:
            self.state = dict(version=STORE_VERSION, selected_task_id=None, active_task_id=None,
                sources={}, tasks={}, queue=[], sequence=0)
            self._save()
        # A stopped process cannot restore an in-memory native authority or retry.
        from . import source_successor
        source_successor.interrupt(self)
        active = self.state['active_task_id']
        if active is not None:
            self._event(active, 'PROCESS_RESTART_INTERRUPTED')
            self.state['tasks'][active]['status'] = 'INTERRUPTED'
            self.state['active_task_id'] = None
            self._save()

    def _path(self, *parts):
        require(all(type(part) is str and part and part not in ('.', '..')
            and '/' not in part and '\\' not in part for part in parts), 'task_store_path')
        result = self.project
        for part in parts:
            result = result / part
            require(not result.is_symlink(), 'task_store_symlink')
        require(result.resolve().is_relative_to(self.project), 'task_store_owned_path')
        return result

    def _validate(self, state=None):
        s = self.state if state is None else state
        require(type(s) is dict and set(s) == {'version', 'selected_task_id', 'active_task_id',
            'sources', 'tasks', 'queue', 'sequence'} and s['version'] == STORE_VERSION,
            'task_store_shape')
        require(type(s['sources']) is dict and len(s['sources']) <= 64
            and type(s['tasks']) is dict and len(s['tasks']) <= MAX_TASKS
            and type(s['queue']) is list and len(set(s['queue'])) == len(s['queue'])
            and all(item in s['tasks'] for item in s['queue'])
            and type(s['sequence']) is int and s['sequence'] >= 0, 'task_store_inventory')
        for source_id, row in s['sources'].items():
            require(SOURCE_ID.fullmatch(source_id) is not None and type(row) is dict
                and set(row) == {'filename', 'label'} and row['filename'] == source_id.split(':')[-1] + '.txt'
                and type(row['label']) is str and len(row['label'].encode('utf-8')) <= 512,
                'task_store_source_registry')
        for task_id, row in s['tasks'].items():
            require(TASK_ID.fullmatch(task_id) is not None and type(row) is dict
                and set(row) == {'spec', 'draft', 'status', 'history', 'results', 'spec_history', 'origin_dependencies'}
                and row['status'] in STATUSES and type(row['history']) is list
                and type(row['results']) is list and type(row['spec_history']) is list,
                'task_store_task_shape')
            if row['spec'] is not None:
                spec = TaskSpec.from_plain(row['spec'])
                require(spec.task_id == task_id and set(spec.resource_scope) <= set(s['sources']),
                    'task_store_registered_scope')
            require(row['origin_dependencies'] is None or type(row['origin_dependencies']) is dict
                and set(row['origin_dependencies']) == {'meaning_key', 'sources'}, 'task_store_origin_shape')
            require(all(type(ref) is dict and set(ref) == {'filename', 'sha256', 'result_id', 'accepted_at', 'valid_to'}
                and ref['filename'].startswith(task_id.split(':')[-1] + '-')
                and Path(ref['filename']).name == ref['filename'] for ref in row['results']),
                'task_store_result_refs')
        if any('operation_round' in event for row in s['tasks'].values() for event in row['history']):
            from . import console_continuation as continuation
            ledger=json.loads(continuation.read(self.project.parent.parent,'state/console_model_turns.json'))
            continuation.validate_allowance_history(self.project.parent.parent,ledger,s)
        require(s['selected_task_id'] is None or s['selected_task_id'] in s['tasks'], 'task_store_selection')
        require(s['active_task_id'] is None or s['active_task_id'] in s['tasks']
            and s['tasks'][s['active_task_id']]['status'] == 'RUNNING', 'task_store_active')
        require(sum(row['status'] == 'RUNNING' for row in s['tasks'].values())
            == int(s['active_task_id'] is not None), 'task_store_single_active')

    def _save(self):
        self._validate()
        raw = canonical(self.state)
        require(len(raw) <= MAX_STATE_BYTES, 'task_store_size')
        pending = self._path('state', 'dynamic_tasks.pending')
        with pending.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, self.state_path)

    def _event(self, task_id, kind):
        row = self.state['tasks'][task_id]
        require(len(row['history']) < 256, 'task_store_history_limit')
        self.state['sequence'] += 1
        row['history'].append({'sequence': self.state['sequence'], 'at': int(self.clock()), 'kind': kind})

    def register_source(self, logical_key, label, raw):
        require(type(logical_key) is str and 0 < len(logical_key.encode('utf-8')) <= 8192
            and type(label) is str and 0 < len(label.encode('utf-8')) <= 512
            and type(raw) is bytes and 0 < len(raw) <= 16384 and b'\0' not in raw,
            'task_source_registration')
        raw.decode('utf-8', errors='strict')
        source_id = 'radik:source:' + digest(logical_key.encode('utf-8'))[:32]
        filename = source_id.split(':')[-1] + '.txt'
        require(source_id in self.state['sources'] or len(self.state['sources']) < 64, 'task_source_registry_limit')
        path, pending = self._path('input', filename), self._path('input', filename + '.pending')
        with pending.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, path)
        self.state['sources'][source_id] = {'filename': filename, 'label': label}
        self._save()
        return source_id

    def source_reader(self, spec):
        require(type(spec) is TaskSpec and set(spec.resource_scope) <= set(self.state['sources']),
            'task_registered_resources')
        registry = {source_id: self.state['sources'][source_id]['filename'] for source_id in spec.source_ids}
        intake = ApprovedSourceStore(self.project, registry, dynamic=True)
        def read():
            raw = self._path('state', 'dynamic_tasks.json').read_bytes()
            require(len(raw) <= MAX_STATE_BYTES, 'task_store_size')
            current = json.loads(raw)
            self._validate(current)
            row = current['tasks'].get(spec.task_id)
            require(row is not None and row['status'] != 'CANCELLED', 'task_cancelled_before_dispatch')
            require(row['status'] in ('QUEUED', 'RUNNING', 'COMPLETED', 'INTERRUPTED')
                and row['spec'] == spec.plain()
                and all(current['sources'][key]['filename'] == filename for key, filename in registry.items()),
                'task_current_dispatch_scope')
            return intake.read()
        return read

    def prepare_round_sources(self, spec):
        """Read sources once for a new explicit round; create no task or grant.

        Failed tasks may prepare a fresh normal round. The controller retains
        the separate strict source_reader and can never dispatch from FAILED.
        Revision numbers are derived without writing the intake revision index;
        the ordinary intake rechecks and commits them after the durable start.
        """
        require(type(spec)is TaskSpec and set(spec.resource_scope)<=set(self.state['sources']),
            'task_registered_resources')
        def raw(parts,limit):
            path=self._path(*parts)
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb')as stream:
                info=os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_size<=limit,'task_preparation_regular_bound')
                value=stream.read(limit+1)
            require(len(value)<=limit,'task_preparation_regular_bound')
            return value
        current=json.loads(raw(('state','dynamic_tasks.json'),MAX_STATE_BYTES))
        self._validate(current)
        row=current['tasks'].get(spec.task_id)
        require(row is not None and row['status']!='CANCELLED','task_cancelled_before_dispatch')
        require(current==self.state and current['active_task_id'] is None
            and row['status'] in ('QUEUED','COMPLETED','INTERRUPTED','FAILED','FAILED_AFTER_ACCEPTANCE')
            and row['spec']==spec.plain(),'task_round_preparation_scope')
        registry={source_id:current['sources'][source_id]['filename'] for source_id in spec.source_ids}
        intake=ApprovedSourceStore(self.project,registry,dynamic=True)
        require(not intake.state.is_symlink(),'intake_symlink')
        prior=json.loads(raw(('state',intake.state.name),65536)) if intake.state.exists() else {}
        require(type(prior)is dict and len(prior)<=64 and all(type(item)is dict
            and set(item)=={'revision','sha256'} and type(item['revision'])is int and item['revision']>=1
            and type(item['sha256'])is str and len(item['sha256'])==64 for item in prior.values()),
            'intake_revision_inventory')
        sources=[]
        for logical,filename in sorted(registry.items()):
            value=raw(('input',filename),16384)
            require(0<len(value)<=16384 and b'\0' not in value,'intake_input_limit')
            sha=digest(value);previous=prior.get(logical,{})
            revision=previous.get('revision',0)+(previous.get('sha256')!=sha)
            sources.append(dict(source_ref=logical,revision=revision,sha256=sha,
                text=value.decode('utf-8',errors='strict'),observed_at=int(self.clock())))
        return tuple(sources)

    def create(self, *, goal, source_ids, profile=None, criterion=None, topic='document_conditions',
               supplied_candidate=None, predecessor_task_id=None):
        require(self.state['active_task_id'] is None and len(self.state['tasks']) < MAX_TASKS,
            'task_queue_capacity_or_active')
        task_id = 'radik-task:' + uuid.uuid4().hex
        draft = dict(goal=goal, source_ids=list(source_ids), resource_scope=list(source_ids), profile=profile,
            criterion=criterion, topic=topic, supplied_candidate=supplied_candidate,
            predecessor_task_id=predecessor_task_id, created_at=int(self.clock()))
        require(type(goal) is str and bool(goal.strip()) and len(goal.encode('utf-8')) <= 2048
            and 1 <= len(source_ids) <= 4 and len(set(source_ids)) == len(source_ids)
            and set(source_ids) <= set(self.state['sources'])
            and (predecessor_task_id is None or predecessor_task_id in self.state['tasks']), 'task_draft_scope')
        self.state['tasks'][task_id] = dict(spec=None, draft=draft, status='CLARIFICATION_REQUIRED',
            history=[], results=[], spec_history=[], origin_dependencies=None)
        self.state['queue'].append(task_id)
        self.state['selected_task_id'] = task_id
        self._event(task_id, 'TASK_CREATED')
        if profile is not None and criterion is not None and (profile != 'verify' or supplied_candidate is not None):
            self._clarify(task_id, {})
        self._save()
        return task_id

    def _clarify(self, task_id, updates):
        row = self.state['tasks'][task_id]
        require(row['status'] in ('CLARIFICATION_REQUIRED', 'QUEUED', 'INTERRUPTED')
            and type(updates) is dict and set(updates) <= {'profile', 'criterion', 'topic', 'goal', 'supplied_candidate'},
            'task_clarification_state')
        draft = dict(row['draft'], **updates)
        spec = TaskSpec(version=TASK_VERSION, task_id=task_id, **dict(draft,
            source_ids=tuple(draft['source_ids']), resource_scope=tuple(draft['resource_scope'])))
        if row['origin_dependencies'] is not None:
            require(row['spec'] == spec.plain(), 'task_clarification_changed_dispatched_origin')
        if row['spec'] is not None:
            row['spec_history'].append(row['spec'])
        row['draft'], row['spec'], row['status'] = draft, spec.plain(), 'QUEUED'
        self._event(task_id, 'TASK_CLARIFIED')

    def clarify(self, task_id, updates):
        self._clarify(task_id, updates)
        self._save()
        return self.spec(task_id)

    def spec(self, task_id=None):
        task_id = task_id or self.state['selected_task_id']
        require(task_id in self.state['tasks'] and self.state['tasks'][task_id]['spec'] is not None,
            'task_not_clarified')
        return TaskSpec.from_plain(self.state['tasks'][task_id]['spec'])

    def select(self, task_id):
        require(task_id in self.state['tasks'], 'task_unknown_id')
        self.state['selected_task_id'] = task_id
        self._event(task_id, 'TASK_SELECTED')
        self._save()

    def stage_source_successor(self, task_id, sources, *, affected_graph):
        from . import source_successor
        token = source_successor.stage(self, task_id, sources, affected_graph=affected_graph)
        self._source_successors[task_id] = token
        return token

    def check_dispatch_sources(self, task_id, sources, *, source_transition=None):
        from . import source_successor
        dependencies = source_successor.dependencies(self.spec(task_id), sources)
        prior = source_successor.current_dependencies(self, task_id)
        if source_transition is None:
            require(prior is None or prior == dependencies, 'task_source_change_requires_explicit_successor')
        else:
            _reference, row = source_successor.validate(self, source_transition, sources,
                statuses=('STAGED', 'ROUND_LINKED', 'STARTED', 'PLANNED'))
            require(row['task_id'] == task_id and row['base']['old_dependencies'] == prior,
                'task_source_successor_origin_changed')
        return dependencies

    def begin(self, task_id, sources, *, operation_round=None, source_transition=None):
        normal=type(operation_round)is dict and 'normal_round_scope' in operation_round
        require(self.state['active_task_id'] is None and task_id in self.state['tasks']
            and (self.state['tasks'][task_id]['status'] in ('QUEUED', 'COMPLETED', 'INTERRUPTED')
                or normal and self.state['tasks'][task_id]['status'] in ('FAILED','FAILED_AFTER_ACCEPTANCE')),
            'task_dispatch_state')
        from . import console_continuation as continuation
        if operation_round is None:
            require(sum(event['kind']=='ROUND_STARTED' for event in self.state['tasks'][task_id]['history'])<3,
                'task_round_budget_exhausted')
        else:
            continuation.validate_round_binding(operation_round)
            require(operation_round['task_id']==task_id,'console_allowance_task_binding')
            owned_project=self.project.parent.parent
            ledger=json.loads(continuation.read(owned_project,'state/console_model_turns.json'))
            proof=operation_round.get('operation_allowance')
            if normal:
                from .normal_session import validate_round
                validate_round(owned_project,operation_round,task_state=self.state,before_begin=True,current=True)
            elif proof is not None:
                expected=continuation.prepare_round(owned_project,ledger,operation_round,
                    owner_operation_id=proof['owner_operation_id'],run_id=proof['run_id'],
                    operation_action=proof['action_id'],task_state=self.state)
                require(operation_round==expected,'console_allowance_task_binding')
            else:
                require(sum(event['kind']=='ROUND_STARTED' for event in self.state['tasks'][task_id]['history'])<3,
                    'task_round_budget_exhausted')
        self.spec(task_id)
        dependencies = self.check_dispatch_sources(task_id, sources, source_transition=source_transition)
        if source_transition is not None:
            from . import source_successor
            _ref, transition = source_successor.validate(self, source_transition, sources, statuses=('ROUND_LINKED',))
            require(transition['round_binding'] == operation_round
                and operation_round['normal_round_scope']['source_successor_ref'] == source_transition.staged_ref,
                'task_source_successor_round_binding')
        if operation_round is not None:
            require(operation_round['task_spec_sha256']==digest(self.spec(task_id).plain())
                and operation_round['dependencies_sha256']==digest(dependencies),
                'console_allowance_task_dependencies')
        if self.state['tasks'][task_id]['origin_dependencies'] is None:
            self.state['tasks'][task_id]['origin_dependencies'] = dependencies
        self.state['active_task_id'] = task_id
        self.state['tasks'][task_id]['status'] = 'RUNNING'
        self._event(task_id, 'ROUND_STARTED')
        if operation_round is not None:
            self.state['tasks'][task_id]['history'][-1]['operation_round']=_copy(operation_round)
        self._save()
        parent=os.open(self.state_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)

        if source_transition is not None:
            source_successor.advance(self, source_transition, 'STARTED')

    def console_continuation_context(self, project, continuation):
        """Validate one reviewed historical failure without creating replay authority."""
        from . import console_continuation as contract
        from review.transport import model_scope
        project = Path(project).resolve(strict=True)
        if type(continuation)is dict and 'proposal_ref' in continuation:
            return self._typed_continuation_context(project,continuation)
        require(self.project == project / 'workspace/owner_documents'
            and type(continuation) is dict and set(continuation) == {
                'receipt_ref', 'owner_operation_id', 'run_id', 'counted',
                'local_occupancy_released', 'server_outcome', 'new_request_started'},
            'task_console_continuation_shape')
        contract.actual_basis(project)
        scope_state = model_scope.read_scope_state(project, 'console')
        raw = model_scope.read_public(project, model_scope.SCOPE_PATHS['console']['ledger'])
        ledger = json.loads(raw)
        checked = contract.validate(project, ledger)
        require(len(ledger['attempts']) == continuation['counted'] == 4
            and scope_state['counted'] == 4 and scope_state['active_attempt_id'] is None
            and ledger['active_attempt_id'] is None
            and continuation['receipt_ref'] == checked['continuation_receipt_ref']
            and continuation['owner_operation_id'] == checked['continuation_owner_operation_id']
            and continuation['run_id'] == checked['continuation_run_id']
            and continuation['local_occupancy_released'] is True
            and continuation['server_outcome'] == checked['remote_outcome'] == 'UNKNOWN'
            and continuation['new_request_started'] is False,
            'task_console_continuation_receipt')
        actual_relative = contract.PASSAGE + '/actual_evidence/actual_task_state/dynamic_tasks.json'
        actual_raw = model_scope.read_public(project, actual_relative)
        require(digest(actual_raw) == contract.ACTUAL_PINS[actual_relative],
            'task_console_continuation_actual_pin')
        actual = json.loads(actual_raw)
        require(self.state == actual and model_scope.read_public(project,
            'workspace/owner_documents/state/dynamic_tasks.json') == canonical(actual)
            and self.state['active_task_id'] is None,
            'task_console_continuation_history_changed')
        connected_raw = model_scope.read_public(project,
            contract.PASSAGE + '/actual_evidence/actual_owner/connected_result.json')
        connected = json.loads(connected_raw)
        task_ids = connected['task_ids']
        require(set(task_ids) == {'a', 'b', 'c'} and len(set(task_ids.values())) == 3
            and set(task_ids.values()) == set(actual['tasks'])
            and actual['tasks'][task_ids['a']]['status'] == 'FAILED'
            and not actual['tasks'][task_ids['a']]['results']
            and all(actual['tasks'][task_ids[key]]['status'] == 'QUEUED' for key in ('b', 'c'))
            and connected['owner_operation_id'] == contract.OLD_OPERATION
            and connected['run_id'] == contract.OLD_RUN,
            'task_console_continuation_actual_tasks')
        return dict(task_ids=dict(task_ids), receipt_ref=dict(continuation['receipt_ref']),
            old_owner_operation_id=contract.OLD_OPERATION, old_run_id=contract.OLD_RUN,
            owner_operation_id=continuation['owner_operation_id'], run_id=continuation['run_id'],
            actual_task_state_sha256=digest(actual_raw), historical_server_outcome='UNKNOWN',
            historical_task_history_preserved=True, acknowledgement_started_new_request=False)

    def _typed_continuation_context(self, project, continuation):
        from . import console_continuation as contract
        require(self.project==project/'workspace/owner_documents' and set(continuation)=={
            'receipt_ref','proposal_ref','owner_operation_id','run_id','counted','local_occupancy_released',
            'server_outcome','new_request_started'},'task_console_continuation_shape')
        ledger=json.loads(contract.read(project,'state/console_model_turns.json'))
        checked=contract.validate(project,ledger)
        _ref,_review,proposal,before,tasks,result,_seal=contract.typed_approval(project,continuation['proposal_ref'])
        require(len(ledger['attempts'])==len(before['attempts'])==continuation['counted']
            and ledger['active_attempt_id'] is None and self.state==tasks
            and contract.read(project,'workspace/owner_documents/state/dynamic_tasks.json')==canonical(tasks)
            and continuation['receipt_ref']==checked['continuation_receipt_ref']
            and continuation['proposal_ref']==checked['continuation_proposal_ref']
            and continuation['owner_operation_id']==checked['continuation_owner_operation_id']
            and continuation['run_id']==checked['continuation_run_id']
            and continuation['local_occupancy_released'] is True
            and continuation['server_outcome']=='UNKNOWN' and continuation['new_request_started'] is False,
            'task_console_continuation_receipt')
        selected=next(row for row in before['attempts'] if row['attempt_id']==proposal['selected_attempt_id'])
        actions=proposal['operation_allowance']['actions'];resume_task_id=actions[0]['task_id']
        require(resume_task_id==selected['round_binding']['task_id']
            and tasks['tasks'][resume_task_id]['status']=='FAILED','task_console_continuation_actual_tasks')
        return dict(task_ids=dict(proposal['operation_allowance']['task_ids']),receipt_ref=continuation['receipt_ref'],
            proposal_ref=continuation['proposal_ref'],operation_actions=[action['action_id'] for action in actions],
            resume_task_id=resume_task_id,old_owner_operation_id=selected['owner_operation_id'],
            old_run_id=selected['run_id'],owner_operation_id=continuation['owner_operation_id'],run_id=continuation['run_id'],
            actual_task_state_sha256=proposal['before_task_state_ref']['sha256'],historical_server_outcome='UNKNOWN',
            historical_task_history_preserved=True,acknowledgement_started_new_request=False)

    def prepare_console_continuation(self, project, continuation):
        """Queue only the selected failed task once; ordinary begin creates its new round."""
        context = self.console_continuation_context(project, continuation)
        task_id = context.get('resume_task_id',context['task_ids']['a'])
        self.state['tasks'][task_id]['status'] = 'QUEUED'
        self._event(task_id, 'EXPLICIT_CONSOLE_LOCAL_CONTINUATION')
        self._save()
        parent = os.open(self.state_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        require(self.state_path.read_bytes() == canonical(self.state),
            'task_console_continuation_readback')
        return context

    def complete(self, task_id, accepted, *, late_failure=False):
        require(self.state['active_task_id'] == task_id and type(accepted) is dict
            and type(late_failure) is bool
            and accepted.get('task_id') == task_id and accepted.get('version') == 'radik.dynamic.result.v01'
            and all(key in accepted for key in ('result_id', 'accepted_at', 'valid_to')),
            'task_completion_binding')
        from . import console_continuation as continuation
        started=next(event for event in reversed(self.state['tasks'][task_id]['history']) if event['kind']=='ROUND_STARTED')
        normal=started.get('operation_round',{}).get('normal_round_scope')
        require(normal is None or normal['mode']!='MEMORY_ONLY'
            or type(accepted.get('semantic_pipeline',{}).get('memory_origin'))is dict,
            'normal_memory_result_required')
        proof=started.get('operation_round',{}).get('operation_allowance')
        require(proof is None or proof['mode']!='MEMORY_ONLY'
            or type(accepted.get('semantic_pipeline',{}).get('memory_origin'))is dict,
            'console_allowance_memory_result_required')
        if proof is not None and proof['schema']==continuation.RELATIVE_ROUND_ALLOWANCE_VERSION and proof['mode']=='MEMORY_ONLY':
            memory=proof['memory_result_ref'];origin=accepted['semantic_pipeline']['memory_origin']
            require(memory is not None and origin.get('result_id')==memory['result_id']
                and origin.get('prior_task_id')==memory['task_id']==task_id
                and accepted['accepted_at']==memory['accepted_at'] and accepted['valid_to']<=memory['valid_to'],
                'console_relative_memory_result_binding')
        raw = canonical(accepted)
        require(len(raw) <= MAX_RESULT_BYTES, 'task_result_size')
        filename = task_id.split(':')[-1] + '-' + digest(raw) + '.json'
        path = self._path('output', filename)
        if path.exists():
            require(path.read_bytes() == raw, 'task_result_identity')
        else:
            with path.open('xb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        row = self.state['tasks'][task_id]
        row['results'].append(dict(filename=filename, sha256=digest(raw),
            result_id=accepted['result_id'], accepted_at=accepted['accepted_at'], valid_to=accepted['valid_to']))
        row['status'], self.state['active_task_id'] = ('FAILED_AFTER_ACCEPTANCE' if late_failure else 'COMPLETED'), None
        self._event(task_id, 'ACCEPTED_RESULT_RETAINED_WITH_LATE_FAILURE' if late_failure else 'ROUND_ACCEPTED')
        self._save()
        token = self._source_successors.get(task_id)
        if token is not None:
            from . import source_successor
            source_successor.advance(self, token, 'ACCEPTED', result_ref=row['results'][-1])
            self._source_successors.pop(task_id)

    def fail(self, task_id):
        require(self.state['active_task_id'] == task_id, 'task_failure_state')
        self.state['tasks'][task_id]['status'] = 'FAILED'
        self.state['active_task_id'] = None
        self._event(task_id, 'ROUND_STOPPED_WITHOUT_RETRY')
        self._save()
        token = self._source_successors.get(task_id)
        if token is not None:
            from . import source_successor
            source_successor.advance(self, token, 'FAILED')
            self._source_successors.pop(task_id)

    def cancel(self, task_id):
        require(task_id in self.state['tasks'] and self.state['active_task_id'] != task_id,
            'task_cancel_active_requires_receipt')
        from . import source_successor
        source_successor.interrupt(self, task_id=task_id, disposition='CANCELLED')
        self._source_successors.pop(task_id,None)
        self.state['tasks'][task_id]['status'] = 'CANCELLED'
        self._event(task_id, 'TASK_CANCELLED_FUTURE_DISPATCH_ONLY')
        self._save()

    def result(self, task_id=None):
        task_id = task_id or self.state['selected_task_id']
        require(task_id in self.state['tasks'], 'task_unknown_id')
        refs = self.state['tasks'][task_id]['results']
        if not refs:
            return None
        ref = refs[-1]
        raw = self._path('output', ref['filename']).read_bytes()
        require(len(raw) <= MAX_RESULT_BYTES and digest(raw) == ref['sha256'], 'task_result_readback')
        value = json.loads(raw)
        require(value['task_id'] == task_id and value['result_id'] == ref['result_id'], 'task_result_current_selection')
        return value

    def snapshot(self):
        return _copy(self.state)
