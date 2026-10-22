"""Two-owner Stage06 support clarification through public Gate5 contracts.

The ordinary owner launcher supplies independent public trust anchors. Neither
wire data nor retained evidence reconstructs a live signer, Root or Host.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time

from hedgehog.drs import LocalDRS
from hedgehog import local_drs_resolver as resolver
from hedgehog.external_drs import gate5_contracts_v01 as c, gate5_exchange_v01 as exchange
from hedgehog.external_drs import gate5_native_v01 as native, gate5_lifecycle_v01 as lifecycle
from hedgehog.external_drs.gate5_body_profile_v01 import ReviewedBodyProfileV01, COMMON_BODY_FIELDS
from . import external_drs_work as pure

ROOT_A, ROOT_B = 'root:radik:rowan_support_owner', 'root:radik:external_drs_recipient'
SCHEMA = 'RadikSupportTermsV01'
SUMMARY = 'Bounded Service Rowan support-price metadata; body requires owner disclosure.'
SOURCE_REF = 'source:stage06:rowan_support'
OBJECT = 'object:stage06:rowan_support'
TASKS = {key:'task:stage06:' + key for key in ('revision1', 'revision2', 'denied', 'restart')}


def _read(path):
    return json.loads(Path(path).read_bytes())


def _save(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    raw = c.canonical(value)
    if path.exists():
        c.require(not path.is_symlink() and path.read_bytes() == raw, 'stage06_immutable_replacement')
    else:
        with path.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    c.require(path.read_bytes() == raw, 'stage06_evidence_readback')
    return dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))


def _state(path, value):
    exchange.state_write(Path(path), value)
    c.require(Path(path).read_bytes() == c.canonical(value), 'stage06_state_readback')


def _line(kind, role, session, **value):
    print(json.dumps(dict(kind=kind, role=role, session=session, **value), sort_keys=True), flush=True)


def _event(callback, label, value):
    if callback is not None:
        return callback(label, value)
    return None


def contexts():
    return {TASKS[key]:dict(requester=ROOT_B, object_id=OBJECT, source_revision=1 if key in ('revision1','denied') else 2,
        uses=['AUDIT'] if key == 'denied' else ['LOCAL_CONTEXT'], purpose='STAGE06_' + key.upper(),
        owner_epoch='radik.stage06.prospective.v01') for key in TASKS}


def policies(a_public_keys):
    """Public policy template only; no source document or answer is embedded."""
    base = dict(source_record_ref=SOURCE_REF, source_policy_ref='policy:stage06:rowan_support',
        max_source_age=300, max_validity_horizon=300, domain='RADIK_SUPPORT', currency='USD')
    a = dict(base, policy_version='radik.stage06.publisher.v01', local_root=ROOT_A, peer_root=ROOT_B,
        publish_enabled=True, recipients=[ROOT_B], release_uses=['LOCAL_CONTEXT'])
    b = dict(base, policy_version='radik.stage06.recipient.v01', peer_root=ROOT_A, local_root=ROOT_B,
        peer_keys=a_public_keys, endpoint='endpoint:gate5:A', object_id=OBJECT,
        transport_scope='owner:stage06:inherited_pipes', schemas=[SCHEMA], uses=['LOCAL_CONTEXT','AUDIT'],
        accept_support_terms=True, status_max_age=60)
    return dict(producer=a, recipient=b)


def validate_body(body):
    c.ref(body['publisher']); c.ref(body['recipient']); c.hash_value(body['document_sha256'])
    terms = body['terms']
    c.shape(terms, ('service','currency','unit','unit_price','revision','document_sha256'))
    c.require((terms['service'], terms['currency'], terms['unit']) == ('Service Rowan','USD','support_call'), 'stage06_body_scope')
    c.require(type(terms['unit_price']) is int and 0 <= terms['unit_price'] <= 100
        and terms['revision'] == body['source_revision'] and terms['document_sha256'] == body['document_sha256'], 'stage06_body_values')


def validate_pointer(pointer):
    c.require(pointer['safe_summary'] == SUMMARY, 'stage06_metadata_summary')


def validate_binding(body, policy, pointer):
    c.require((body['publisher'], body['recipient']) == (policy['peer_root'], policy['local_root']), 'stage06_body_audience')
    c.require(body['terms']['currency'] == policy['currency'] and pointer['published_scope'] ==
        dict(domain=policy['domain'], currency=policy['currency']), 'stage06_body_policy_scope')


def profile():
    return ReviewedBodyProfileV01(SCHEMA, COMMON_BODY_FIELDS + ('publisher','recipient','document_sha256','terms'),
        ('domain','currency'), 'accept_support_terms', validate_body, validate_pointer, validate_binding)


def check_source_revision(pointer, state):
    """Persistent monotone source guard; this function creates no authority."""
    key = c.canonical([pointer['publisher_root_id'],pointer['source_record_ref']]).decode()
    row = state.get(key)
    c.require(row is None or pointer['source_revision'] >= row['revision'],'stage06_source_revision_rollback')
    return pointer


def _review(root, label, value, checks, *, window=None):
    now = int(time.time())
    result = native.root_review(root, 'transaction:stage06:' + label, 'candidate:stage06:' + c.sha(value),
        SOURCE_REF, checks, value, now, predicate='radik_stage06_current_context', window=window)
    return result


def _work(root, task, operation, material, reader, folder, callback):
    span = 'stage06:' + operation + ':' + c.sha(dict(root=root, task=task))
    _event(callback, 'native_enter', dict(span_id=span, root=root, task=task, operation=operation))
    started = time.monotonic_ns()
    try:
        value = pure.perform(root, task, operation, material, reader, folder)
    except BaseException:
        try:_event(callback, 'native_exit', dict(span_id=span, completed=False, wall_ns=time.monotonic_ns()-started))
        except BaseException:pass
        raise
    _event(callback, 'native_exit', dict(span_id=span, completed=True, wall_ns=time.monotonic_ns()-started,
        work_artifact_ref=value['artifact']['artifact_id']))
    return value


def _request(policy, operation, task, pointer=None, *, use='LOCAL_CONTEXT', subject=None, nonce=None):
    now = int(time.time())
    value = c.with_id('request', dict(version='g51.request.v01', op=operation, requester=ROOT_B, publisher=ROOT_A,
        task_ref=task, request_revision=1, pointer_ref=None if pointer is None else pointer['pointer_id'],
        trust_profile_hash=c.sha(policy), use_class=use, object_id=OBJECT, allowed_size=c.BODY_MAX,
        nonce=nonce or secrets.token_hex(32), issued_at=now, deadline=now+60,
        subject_request_ref=subject, owner_transport_scope=policy['transport_scope']))
    c.validate('request', value)
    return value


class Producer:
    def __init__(self, folder, cap, keys, scenario, callback):
        self.folder, self.cap, self.keys, self.scenario, self.callback = folder, cap, keys, scenario, callback
        self.sources = {}

    def build(self, revision, policy):
        if revision in self.sources:return self.sources[revision]
        c.require(revision in (1,2) and (revision == 1 or 1 in self.sources), 'stage06_source_sequence')
        source = self.scenario['revisions'][revision-1]
        c.shape(source, ('document','revision'))
        c.require(source['revision'] == revision, 'stage06_source_revision')
        source_bytes = c.canonical(source)
        def reader():
            current = _read(self.folder/'scenario.json')['revisions'][revision-1]
            c.require(c.canonical(current) == source_bytes, 'stage06_producer_source_changed')
            return dict(source_sha256=c.sha(current), source_revision=revision, policy_sha256=c.sha(policy))
        target = self.folder/('revision_' + str(revision)); target.mkdir()
        work = _work(ROOT_A, TASKS['revision'+str(revision)] + ':producer', 'producer', source, reader, target, self.callback)
        now = int(time.time()); terms = work['output']
        source_review = _review(ROOT_A, 'source', dict(terms=terms, work_ref=work['artifact']['artifact_id'], input_sha256=c.sha(source)),
            dict(actual_native=work['attempts'] == 1, current_source=reader()['source_sha256'] == c.sha(source)))
        c.require(source_review[2].decision == 'ACCEPT', 'stage06_source_root_refused')
        env = c.drs.drs_time_envelope_to_plain_data_v01(c.drs.build_drs_time_envelope_v01(pt_created_at=now,
            kt_as_of=now, et_observed_at=now, ct_context_anchor=now, ttl_seconds=300, valid_from=now, valid_to=now+300,
            source_observed_at=now, source_reported_at=now, system_ingested_at=now, system_verified_at=now,
            freshness_policy_id='freshness:stage06:source'))
        previous = [] if revision == 1 else [self.sources[1]['body']['source_work_ref']]
        body = dict(version='g51.body.v01', source_record_ref=SOURCE_REF, source_revision=revision,
            source_work_ref=work['artifact']['artifact_id'], source_review_ref=source_review[2].decision_id,
            time_envelope=env, ttl_base='pt_created_at', source_lineage_refs=previous+[work['artifact']['artifact_id']],
            publisher=ROOT_A, recipient=ROOT_B, document_sha256=terms['document_sha256'], terms=terms)
        c.validate('body', body, profile=profile())
        manifest = c.with_id('manifest', dict(version='g51.manifest.v01', publisher=ROOT_A, source_revision=revision,
            source_refs=[SOURCE_REF,body['source_work_ref'],body['source_review_ref']], declared_schema=SCHEMA,
            files=[dict(path='body.json', bytes=len(c.canonical(body)), sha256=c.sha(body))]))
        c.validate('manifest', manifest, profile=profile())
        pointer = c.with_id('pointer', dict(version='g51.pointer.v01', publisher_root_id=ROOT_A, publisher_key_id=self.cap.key_id,
            semantic_address=dict(namespace='radik', domain='RADIK_SUPPORT', subject_class='support_terms',
                intent_class='context_lookup', schema_id=SCHEMA, schema_version='v01'), source_record_ref=SOURCE_REF,
            source_revision=revision, source_review_ref=body['source_review_ref'], body_sha256=c.sha(body),
            body_bytes=len(c.canonical(body)), media_type='application/json', artifact_manifest_ref=manifest['manifest_id'],
            safe_summary=SUMMARY, published_scope=dict(domain='RADIK_SUPPORT', currency='USD'),
            allowed_use_classes=['LOCAL_CONTEXT'], forbidden_use_classes=['ACTION'], recipient_scope=[ROOT_B],
            time_envelope=env, source_lineage_refs=body['source_lineage_refs'], access_policy_ref=policy['source_policy_ref'],
            revocation_stream_id='stream:stage06:rowan:' + str(revision), transport_object_id=OBJECT,
            creates_authority=False, creates_permission=False))
        c.validate('pointer', pointer, profile=profile())
        publication = _review(ROOT_A, 'publication', pointer, dict(owner_publication=policy['publish_enabled'],
            source_review=source_review[2].decision == 'ACCEPT', current_source=reader()['source_sha256'] == c.sha(source)), window=(now,now+300))
        c.require(publication[2].decision == 'ACCEPT', 'stage06_publication_refused')
        descriptor = c.sign(self.cap, self.keys, 'POINTER', pointer, manifest['manifest_id'].split(':')[1])
        entry = dict(version='g51.entry.v01', pointer_id=pointer['pointer_id'], publisher_root_id=ROOT_A,
            stream_id=pointer['revocation_stream_id'], revision=1, state='ACTIVE', effective_at=now,
            reason_ref='reason:stage06:owner_published')
        entry['entry_hash'] = c.sha(entry); c.validate('entry', entry)
        value = dict(body=body, manifest=manifest, descriptor=descriptor, entry=entry,
            source_input_sha256=c.sha(source))
        self.sources[revision] = value
        for name, data in [('body',body),('manifest',manifest),('pointer',descriptor),('source_review',native.root_plain(source_review)),
                           ('publication_review',native.root_plain(publication))]:_save(target/(name+'.json'), data)
        self.status_state()
        if revision == 2:self.terminal(1, 'SUPERSEDED')
        _event(self.callback, 'source_published', dict(revision=revision, pointer_ref=pointer['pointer_id'], work_ref=body['source_work_ref']))
        return value

    def status_state(self):
        _state(self.folder/'status_state.json', {str(k):v['entry'] for k,v in self.sources.items()})

    def current_source(self, source):
        revision = source['body']['source_revision']
        current = _read(self.folder/'scenario.json')['revisions'][revision-1]
        return current['revision'] == revision and c.sha(current) == source['source_input_sha256']

    def terminal(self, revision, state):
        old = self.sources[revision]['entry']
        c.require(old['state'] == 'ACTIVE', 'stage06_source_terminal_revival')
        entry = dict(old, revision=old['revision']+1, state=state, effective_at=int(time.time()), reason_ref='reason:stage06:owner_' + state.lower())
        entry['entry_hash'] = c.sha({k:v for k,v in entry.items() if k != 'entry_hash'})
        c.validate('entry', entry); self.sources[revision]['entry'] = entry; self.status_state()

    def serve(self, channel, bootstrap, session):
        policy, recipient_policy = bootstrap['own_policy'], bootstrap['requester_policy']
        budget = exchange.PublisherBudget(self.folder/'publisher_budget.json', contexts())
        self.build(1, policy)
        _line('READY', 'producer', session)
        for _ in range(32):
            msg = channel.receive(); c.require(msg['kind'] == 'REQUEST', 'stage06_expected_request')
            req = c.verify(msg['value'], bootstrap['peer_keys'], 'REQUEST', c.sha(recipient_policy)); c.validate('request',req)
            c.require(req['requester'] == ROOT_B and req['publisher'] == ROOT_A and req['issued_at'] <= int(time.time()) < req['deadline'], 'stage06_request_identity_or_time')
            c.require(req['trust_profile_hash'] == c.sha(recipient_policy) and req['owner_transport_scope'] == recipient_policy['transport_scope'], 'stage06_request_policy')
            reserved = budget.reserve(req)
            if req['op'] == 'CLOSE':
                c.require(reserved, 'stage06_publisher_attempt_budget')
                channel.send('CLOSED', c.sign(self.cap,self.keys,'CLOSE',dict(request_ref=req['request_id'],session=session),c.sha(recipient_policy)))
                _line('SESSION_CLOSED','producer',session);return
            revision = contexts()[req['task_ref']]['source_revision']
            if req['op'] == 'DESCRIBE':
                c.require(reserved, 'stage06_publisher_attempt_budget')
                source = self.build(revision, policy)
                channel.send('POINTER',source['descriptor']);continue
            match = [s for s in self.sources.values() if s['descriptor']['value']['pointer_id'] == req['pointer_ref']]
            c.require(len(match) == 1, 'stage06_pointer_lookup')
            source = match[0]; body, pointer, manifest = source['body'], source['descriptor']['value'], source['manifest']
            manifest_hash = manifest['manifest_id'].split(':')[1]
            if req['op'] == 'STATUS':
                c.require(reserved and budget.matches_source(req,body['source_revision']), 'stage06_status_context')
                c.require(self.current_source(source), 'stage06_producer_source_changed')
                if body['source_revision'] == 2 and budget.read()['tasks'][TASKS['revision2']]['bodies'] == 1 and source['entry']['state'] == 'ACTIVE':
                    self.terminal(2,'REVOKED')
                now = int(time.time())
                status = dict(version='g51.status.v01', entry=source['entry'], requested_pointer_hash=c.sha(pointer), requester=ROOT_B,
                    subject_request_ref=req['subject_request_ref'], request_revision=req['request_revision'], nonce=req['nonce'], checked_at=now, valid_until=now+60)
                c.validate('status',status);channel.send('STATUS',c.sign(self.cap,self.keys,'STATUS',status,manifest_hash));continue
            c.require(req['op'] == 'FETCH', 'stage06_fetch_operation')
            now = int(time.time()); end = c.temporal(body['time_envelope'],now,policy)
            review = _review(ROOT_A,'disclosure',dict(request=req,pointer_ref=pointer['pointer_id']),
                dict(reserved=reserved, source_revision=budget.matches_source(req,body['source_revision']),
                    source_document_current=self.current_source(source),
                    audience=req['requester'] in policy['recipients'], owner_use=req['use_class'] in policy['release_uses'],
                    active=source['entry']['state'] == 'ACTIVE', size=pointer['body_bytes'] <= req['allowed_size']),
                window=(body['time_envelope']['valid_from'],min(end,req['deadline'])))
            allowed = review[2].decision == 'ACCEPT'
            if allowed:budget.disclosure(req,len(c.canonical(body)))
            release = dict(version='g51.release.v01',state='RELEASED' if allowed else 'REFUSED',request_ref=req['request_id'],
                request_revision=req['request_revision'],pointer_ref=pointer['pointer_id'],manifest_ref=manifest['manifest_id'],
                body_hash=c.sha(body),recipient=ROOT_B,use_class=req['use_class'],nonce=req['nonce'],deadline=req['deadline'],release_review_ref=review[2].decision_id)
            c.validate('release',release)
            response = dict(release=c.sign(self.cap,self.keys,'RELEASE',release,manifest_hash),manifest=manifest if allowed else None,body=body if allowed else None)
            budget.response(req,allowed)
            _save(self.folder/'releases'/(c.sha(req)+'.json'),dict(request=req,review=native.root_plain(review),response=response,budget=budget.read()))
            channel.send('BUNDLE',response)
        raise ValueError('stage06_finite_session_limit')


class Recipient:
    def __init__(self, folder, cap, keys, bootstrap, channel, session, callback):
        self.folder,self.cap,self.keys,self.bootstrap,self.channel,self.session,self.callback = folder,cap,keys,bootstrap,channel,session,callback
        self.policy = bootstrap['own_policy']; self.scenario = _read(folder/'scenario.json')
        c.shape(self.scenario,('base_price','support_calls'))
        self.store = lifecycle.ImportStore(folder)
        self.current_path = folder/'current_source_revisions.json'
        if not self.current_path.exists():_state(self.current_path,{})
        self.controls = []

    def io(self, req):
        c.require(req['task_ref'] in contexts() and req['use_class'] in contexts()[req['task_ref']]['uses'], 'stage06_receiver_context')
        review = _review(ROOT_B,'retrieval',req,dict(pinned_endpoint=self.policy['endpoint'] == 'endpoint:gate5:A',
            admitted_use=req['use_class'] in self.policy['uses'], owner_transport=req['owner_transport_scope'] == self.policy['transport_scope']),
            window=(req['issued_at'],req['deadline']))
        c.require(review[2].decision == 'ACCEPT','stage06_retrieval_refused')
        _save(self.folder/'requests'/(c.sha(req)+'.json'),dict(request=req,review=native.root_plain(review)))
        exchange.Budget(self.folder/'budgets'/(req['task_ref']+'.json'),req['task_ref']).reserve(req)
        self.channel.send('REQUEST',c.sign(self.cap,self.keys,'REQUEST',req,c.sha(self.policy)))
        return self.channel.receive()

    def current_pointer(self, descriptor):
        pointer = c.check_pointer(descriptor,self.policy,int(time.time()),profile=profile())
        c.check_route(pointer,self.policy)
        return check_source_revision(pointer,_read(self.current_path))

    def remember_current(self,pointer):
        state = _read(self.current_path); key = c.canonical([pointer['publisher_root_id'],pointer['source_record_ref']]).decode()
        prior = state.get(key)
        c.require(prior is None or pointer['source_revision'] >= prior['revision'],'stage06_source_revision_rollback')
        if prior is not None and prior['revision'] == pointer['source_revision']:
            c.require(prior['body_sha256'] == pointer['body_sha256'],'stage06_source_revision_equivocation')
        state[key] = dict(revision=pointer['source_revision'],body_sha256=pointer['body_sha256'],pointer_ref=pointer['pointer_id'])
        _state(self.current_path,state)

    def describe(self,task):
        response = self.io(_request(self.policy,'DESCRIBE',task)); c.require(response['kind'] == 'POINTER','stage06_expected_pointer')
        descriptor = response['value']; pointer = self.current_pointer(descriptor)
        drs = LocalDRS(self.folder/'address_index')
        resolver.write_semantic_record(drs,resolver.SemanticDRSRecordInput(record_id=pointer['pointer_id'],domain='RADIK_EXTERNAL_SUPPORT',
            content=dict(kind='pointer',revision=pointer['source_revision'],descriptor=descriptor),semantic_keys=('rowan','support')))
        found = resolver.resolve_semantic_candidates(LocalDRS(self.folder/'address_index'),resolver.SemanticResolveQuery(
            query_id='query:stage06:'+str(pointer['source_revision']),domain='RADIK_EXTERNAL_SUPPORT',semantic_terms=('rowan','support'),
            content_filters=dict(kind='pointer',revision=pointer['source_revision']),require_root_review=True),layers=('work',))
        c.require(len(found.candidates) == 1,'stage06_local_pointer_resolution')
        retained = drs.read_record('work',found.candidates[0].record_id)['content']['descriptor']
        c.require(retained == descriptor,'stage06_local_pointer_identity')
        review = _review(ROOT_B,'pointer_lookup',dict(descriptor=descriptor,resolution=native.plain(found)),
            dict(current_pointer=self.current_pointer(retained) == pointer, metadata_only=True))
        c.require(review[2].decision == 'ACCEPT','stage06_pointer_root_refused')
        _save(self.folder/('pointer_'+str(pointer['source_revision'])+'.json'),dict(descriptor=descriptor,resolver=native.plain(found),review=native.root_plain(review)))
        return descriptor

    def status(self,descriptor,task):
        pointer = self.current_pointer(descriptor)
        fetch = _request(self.policy,'FETCH',task,pointer)
        query = _request(self.policy,'STATUS',task,pointer,subject=fetch['request_id'],nonce=fetch['nonce'])
        response = self.io(query);c.require(response['kind'] == 'STATUS','stage06_expected_status')
        self.store.observe(response['value'],pointer,fetch,self.policy,int(time.time()))
        return fetch,response['value']

    def check(self,record):
        pointer = self.current_pointer(record['descriptor'])
        checked = c.check_bundle(record['bundle'],record['descriptor'],record['request'],record['status'],self.policy,int(time.time()),
            _read(self.store.path)['highwater'],self.store.conflicts(),profile=profile())
        c.require(c.sha(_read(self.folder/'scenario.json')) == c.sha(self.scenario),'stage06_recipient_source_changed')
        return dict(body_sha256=c.sha(checked['body']),source_revision=pointer['source_revision'],
            status_entry_hash=checked['status_entry']['entry_hash'],local_input_sha256=c.sha(self.scenario),policy_sha256=c.sha(self.policy))

    def consume(self,descriptor,task):
        request,status = self.status(descriptor,task)
        c.check_status(status,descriptor['value'],request,self.policy,int(time.time()),_read(self.store.path)['highwater'])
        response = self.io(request);c.require(response['kind'] == 'BUNDLE','stage06_expected_bundle')
        bundle = response['value']
        checked = c.check_bundle(bundle,descriptor,request,status,self.policy,int(time.time()),
            _read(self.store.path)['highwater'],self.store.conflicts(),profile=profile())
        budget = exchange.Budget(self.folder/'budgets'/(task+'.json'),task);budget.received_body(len(c.canonical(bundle['body'])))
        kind = self.store.import_body(checked,descriptor['value']);c.require(kind == 'NEW_SOURCE','stage06_new_source_required')
        self.remember_current(descriptor['value'])
        body = checked['body']; revision = body['source_revision'];target = self.folder/('revision_'+str(revision));target.mkdir()
        candidate = c.with_id('import',dict(version='g51.import.v01',local_request_ref=request['request_id'],pointer_ref=descriptor['value']['pointer_id'],
            foreign_publisher=ROOT_A,foreign_source_ref=SOURCE_REF,foreign_revision=revision,received_manifest_hash=c.sha(bundle['manifest']),
            body_hash=c.sha(body),receive_event_ref='receive:'+c.sha(bundle),validation_results={k:True for k in
                ('shape','signature','integrity','arithmetic','provenance','temporal','scope','status','conflict','local_policy')},
            status_entry_hash=checked['status_entry']['entry_hash'],dependency_fingerprint=c.sha(self.scenario),policy_hash=c.sha(self.policy),creates_permission=False))
        c.validate('import',candidate)
        record = dict(descriptor=descriptor,request=request,status=status,bundle=bundle,candidate=candidate)
        acceptance = _review(ROOT_B,'import',candidate,dict(checked_current=self.check(record)['body_sha256'] == c.sha(body),
            local_task_scope=body['terms']['service'] == 'Service Rowan'),
            window=(body['time_envelope']['valid_from'],min(checked['source_end'],request['deadline'],status['value']['valid_until'])))
        c.require(acceptance[2].decision == 'ACCEPT','stage06_local_import_refused')
        record['review'] = native.root_plain(acceptance);_save(target/'import.json',record)
        adaptation = dict(version='radik.stage06.current_support_adaptation.v01',import_ref=candidate['import_id'],
            body_sha256=c.sha(body),source_work_ref=body['source_work_ref'],source_review_ref=body['source_review_ref'],
            local_acceptance_ref=acceptance[2].decision_id,local_task_ref=task,terms=body['terms'])
        material = dict(self.scenario,terms=body['terms'],import_ref=candidate['import_id'],body_sha256=c.sha(body),local_acceptance_ref=acceptance[2].decision_id)
        result = _work(ROOT_B,task+':consumer','consumer',material,lambda:self.check(record),target,self.callback)
        accepted = dict(import_record=record,adaptation=adaptation,work=result,actual_output=result['output'],use_time=int(time.time()))
        _save(target/'accepted.json',accepted)
        resolver.write_semantic_record(LocalDRS(self.folder/'history'),resolver.SemanticDRSRecordInput(
            record_id=result['artifact']['artifact_id'],domain='RADIK_EXTERNAL_SUPPORT_HISTORY',
            content=dict(revision=revision,result=accepted),semantic_keys=('rowan','support','result')))
        _event(self.callback,'current_consumption',dict(revision=revision,body_sha256=c.sha(body),work_ref=result['artifact']['artifact_id'],output=result['output']))
        return record,accepted

    def refuse(self,label,expected,call,*,clock='ACTUAL_INTEGER_UTC'):
        before = len(list(self.folder.glob('revision_*/native_work.json')))
        try:call()
        except ValueError as exc:
            c.require(type(exc.args[0]) is str and exc.args[0] == expected,'stage06_refusal_reason_mismatch')
        else:raise ValueError('stage06_expected_refusal_missing')
        review = _review(ROOT_B,'refusal_'+label,dict(reason=expected,control=label,clock=clock),dict(current_use_allowed=False))
        c.require(review[2].decision != 'ACCEPT','stage06_refusal_root_accepted')
        after = len(list(self.folder.glob('revision_*/native_work.json')));c.require(before == after,'stage06_refusal_dispatched_work')
        row = dict(label=label,reason=expected,clock=clock,work_before=before,work_after=after,root=native.root_plain(review))
        self.controls.append(row);_save(self.folder/'controls'/(label+'.json'),row)
        return row

    def history(self):
        drs = LocalDRS(self.folder/'history')
        found = resolver.resolve_semantic_candidates(drs,resolver.SemanticResolveQuery(query_id='query:stage06:history:'+str(self.session),
            domain='RADIK_EXTERNAL_SUPPORT_HISTORY',semantic_terms=('rowan','support'),require_root_review=True),layers=('work',))
        rows = [drs.read_record('work',x.record_id) for x in found.candidates]
        c.require(len(rows) == 2,'stage06_history_count')
        review = _review(ROOT_B,'historical_read',dict(record_ids=[x.record_id for x in found.candidates],hashes=[c.sha(x) for x in rows]),dict(historical_only=True))
        return dict(mode='HISTORICAL_EVIDENCE_NOT_CURRENT_AUTHORITY',records=rows,resolver=native.plain(found),root=native.root_plain(review))

    def run(self):
        if self.session == 1:
            private_path = Path(self.bootstrap['forbidden_peer_private_path'])
            try:
                with private_path.open('rb') as stream:stream.read(1)
            except ValueError as exc:
                c.require(exc.args == ('stage06_peer_read_outside_admitted_scope',),'stage06_peer_private_refusal_reason')
                _save(self.folder/'peer_private_read_refused.json',dict(status='REFUSED_BEFORE_READ',bytes_read=0,
                    hash_computed=False,guard_code='stage06_peer_read_outside_admitted_scope'))
            else:raise ValueError('stage06_peer_private_read_not_blocked')
            local = dict(self.scenario,terms=None,import_ref=None,body_sha256=None,local_acceptance_ref=None)
            def local_reader():
                c.require(_read(self.folder/'scenario.json') == self.scenario,'stage06_local_source_changed')
                return dict(local_input_sha256=c.sha(self.scenario))
            baseline = _work(ROOT_B,'task:stage06:baseline','baseline',local,local_reader,self.folder/'baseline',self.callback)
            descriptor = self.describe(TASKS['revision1'])
            denied = _request(self.policy,'FETCH',TASKS['denied'],descriptor['value'],use='AUDIT')
            before = self.channel.counters();response = self.io(denied);c.require(response['kind'] == 'BUNDLE','stage06_expected_denied_bundle')
            release = c.verify(response['value']['release'],self.policy['peer_keys'],'RELEASE',descriptor['value']['artifact_manifest_ref'].split(':')[1]);c.validate('release',release)
            c.require((release['request_ref'],release['request_revision'],release['pointer_ref'],release['manifest_ref'],
                release['body_hash'],release['recipient'],release['use_class'],release['nonce'],release['deadline']) ==
                (denied['request_id'],denied['request_revision'],descriptor['value']['pointer_id'],descriptor['value']['artifact_manifest_ref'],
                 descriptor['value']['body_sha256'],ROOT_B,denied['use_class'],denied['nonce'],denied['deadline']), 'stage06_denial_request_binding')
            c.require(release['state'] == 'REFUSED' and response['value']['body'] is None and response['value']['manifest'] is None,'stage06_disclosure_not_refused')
            _save(self.folder/'disclosure_refusal.json',dict(request=denied,response=response,wire_before=before,wire_after=self.channel.counters(),body_opened=False,consumer_work=False))
            first,one = self.consume(descriptor,TASKS['revision1'])
            newer = self.describe(TASKS['revision2']);second,two = self.consume(newer,TASKS['revision2'])
            c.require(baseline['output']['total_price'] is None and one['actual_output']['total_price'] != two['actual_output']['total_price'], 'stage06_actual_consumer_not_changed')
            changed_pointer = c.with_id('pointer',dict(newer['value'],body_sha256='0'*64))
            self.refuse('altered_signed_pointer','signed_content_binding',lambda:c.check_pointer(
                dict(newer,value=changed_pointer),self.policy,int(time.time()),profile=profile()))
            # The preceding coherent shape reaches the signed content binding.
            changed = json.loads(c.canonical(newer));changed['signature']['signature_hex'] = ('0' if changed['signature']['signature_hex'][0] != '0' else '1') + changed['signature']['signature_hex'][1:]
            self.refuse('altered_signature','signature_invalid',lambda:c.check_pointer(changed,self.policy,int(time.time()),profile=profile()))
            self.refuse('wrong_anchor','signature_invalid',lambda:c.check_pointer(newer,dict(self.policy,peer_keys=c.crypto.trusted_root_key_set_to_plain_dict_v01(self.keys)),int(time.time()),profile=profile()))
            self.refuse('wrong_issuer','publisher_identity',lambda:c.check_pointer(newer,dict(self.policy,peer_root='root:stage06:wrong_owner'),int(time.time()),profile=profile()))
            self.refuse('wrong_scope','schema_scope',lambda:c.check_pointer(newer,dict(self.policy,domain='UNRELATED_SCOPE'),int(time.time()),profile=profile()))
            changed_bundle = json.loads(c.canonical(second['bundle']))
            changed_bundle['body']['terms']['unit_price'] = (changed_bundle['body']['terms']['unit_price'] + 1) % 101
            self.refuse('altered_body_bytes','body_integrity',lambda:c.check_bundle(changed_bundle,newer,second['request'],
                second['status'],self.policy,int(time.time()),_read(self.store.path)['highwater'],self.store.conflicts(),profile=profile()))
            future = newer['value']['time_envelope']['valid_to']
            self.refuse('expired_source','source_not_current',lambda:c.check_pointer(newer,self.policy,future,profile=profile()),clock='CONTROLLED_FUTURE_NEGATIVE_ONLY')
            request,terminal = self.status(newer,TASKS['revision2'])
            c.require(terminal['value']['entry']['state'] == 'REVOKED','stage06_revocation_expected')
            self.refuse('revoked_current_use','status_not_active',lambda:c.check_status(terminal,newer['value'],request,self.policy,int(time.time()),_read(self.store.path)['highwater']))
            _save(self.folder/'terminal_observation.json',dict(request=request,status=terminal,retained_state=_read(self.store.path)))
            report = dict(status='PASS_SESSION_1',baseline=baseline['output'],revision1=one['actual_output'],revision2=two['actual_output'],
                history=self.history(),controls=self.controls,revision_highwater=_read(self.current_path),process_id=os.getpid())
        else:
            first = _read(self.folder/'revision_1/import.json');second = _read(self.folder/'revision_2/import.json')
            before = _read(self.store.path);revision_before = _read(self.current_path)
            self.refuse('restart_old_revision','stage06_source_revision_rollback',lambda:self.current_pointer(first['descriptor']))
            self.refuse('restart_old_active','status_rollback',lambda:self.store.observe(second['status'],second['descriptor']['value'],second['request'],self.policy,int(time.time())))
            c.require(_read(self.store.path)['highwater'] == before['highwater'] and _read(self.current_path) == revision_before,'stage06_restart_state_changed')
            report = dict(status='PASS_SESSION_2',historical_only=True,history=self.history(),controls=self.controls,
                revision_highwater=revision_before,status_highwater=before['highwater'],process_id=os.getpid(),fresh_signer_key_id=self.cap.key_id)
        close = _request(self.policy,'CLOSE',TASKS['restart'])
        response = self.io(close);c.require(response['kind'] == 'CLOSED','stage06_close_response')
        value = c.verify(response['value'],self.policy['peer_keys'],'CLOSE',c.sha(self.policy))
        c.require(value == dict(request_ref=close['request_id'],session=self.session),'stage06_close_binding')
        report['wire_counters'] = self.channel.counters();report['provider_calls'] = 0
        ref = _save(self.folder/('session_'+str(self.session)+'.json'),report)
        _line('DONE','recipient',self.session,status=report['status'],report_ref=ref)
        return report


def peer(role, read_fd, write_fd, folder, *, session=1, on_event=None, task_selector='external_drs_owner_v01'):
    """Entry is called only after the ordinary launcher admitted source and I/O."""
    c.require(task_selector == 'external_drs_owner_v01' and role in ('producer','recipient') and session in (1,2),'stage06_peer_arguments')
    folder = Path(folder)
    root = ROOT_A if role == 'producer' else ROOT_B
    cap = c.crypto.generate_root_signer_capability_v01(root_id=root)
    keys = c.crypto.build_trusted_root_key_set_v01(capabilities=(cap,))
    public = c.crypto.trusted_root_key_set_to_plain_dict_v01(keys)
    _line('PUBLIC_KEYS',role,0 if role == 'producer' else session,public_keys=public)
    try:
        if role == 'producer':
            private = folder/'private';private.mkdir();(private/'canary.txt').write_text(secrets.token_hex(32))
            scenario = _read(folder/'scenario.json');c.shape(scenario,('revisions',))
            c.require(type(scenario['revisions']) is list and len(scenario['revisions']) == 2,'stage06_source_revisions')
            producer = Producer(folder,cap,keys,scenario,on_event)
            for current_session in (1,2):
                bootstrap = json.loads(input());c.require(bootstrap['session'] == current_session and bootstrap['contexts'] == contexts(),'stage06_bootstrap_context')
                expected = policies(public)
                c.require(bootstrap['own_policy'] == expected['producer'] and bootstrap['requester_policy'] == expected['recipient'],'stage06_publisher_bootstrap_policy')
                c.require(c.keyset(bootstrap['peer_keys']).root_ids == (ROOT_B,),'stage06_publisher_peer_anchor')
                _save(folder/('bootstrap_'+str(current_session)+'.json'),bootstrap)
                directory=folder/('session_'+str(current_session));directory.mkdir()
                channel=exchange.PipeChannel(read_fd,write_fd,directory)
                producer.serve(channel,bootstrap,current_session)
                _save(directory/'counters.json',channel.counters())
            ref=_save(folder/'producer_result.json',dict(status='PASS_PRODUCER',process_id=os.getpid(),public_keys=public,
                publisher_budget=_read(folder/'publisher_budget.json'),status_state=_read(folder/'status_state.json'),provider_calls=0))
            _line('DONE','producer',2,status='PASS_PRODUCER',report_ref=ref)
        else:
            bootstrap=json.loads(input());c.require(bootstrap['session'] == session and bootstrap['contexts'] == contexts(),'stage06_bootstrap_context')
            c.require(bootstrap['own_policy'] == policies(bootstrap['peer_keys'])['recipient'],'stage06_recipient_bootstrap_policy')
            c.require(c.keyset(bootstrap['peer_keys']).root_ids == (ROOT_A,),'stage06_recipient_peer_anchor')
            _save(folder/('bootstrap_'+str(session)+'.json'),bootstrap)
            directory=folder/('session_'+str(session));directory.mkdir()
            channel=exchange.PipeChannel(read_fd,write_fd,directory)
            return Recipient(folder,cap,keys,bootstrap,channel,session,on_event).run()
    finally:
        primary = sys.exc_info()[0]
        for descriptor in (read_fd,write_fd):
            try:os.close(descriptor)
            except OSError:
                if primary is None:raise
                try:_event(on_event,'cleanup_secondary',dict(code='stage06_peer_pipe_close_failed'))
                except BaseException:pass
