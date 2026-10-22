"""Bounded engineering contract probe, distinct from the owner scenario.

One producer and one consumer Work are exercised. The second recipient process
tests retained terminal STATUS and a labeled mechanical revision guard only.
No owner baseline, two-price owner story or second revision Work is performed.
"""
import json
import os
from pathlib import Path
import secrets
import sys
import time

from hedgehog.external_drs import gate5_contracts_v01 as c, gate5_exchange_v01 as x
from hedgehog.external_drs import gate5_lifecycle_v01 as life, gate5_native_v01 as n
from . import external_drs as app

ROOT_A='root:radik:stage06:contract_probe:producer'
ROOT_B='root:radik:stage06:contract_probe:recipient'
SOURCE='source:stage06:contract_probe'
OBJECT='object:stage06:contract_probe'
TASK='task:stage06:contract_probe'
DENIED=TASK+':denied'
CLOSE=TASK+':close'


def contexts():
    return {task:dict(requester=ROOT_B,object_id=OBJECT,source_revision=1,
        uses=['AUDIT'] if task==DENIED else ['LOCAL_CONTEXT'],purpose='BOUNDED_ENGINEERING_CONTRACT_PROBE',
        owner_epoch='radik.stage06.contract_probe.v01') for task in (TASK,DENIED,CLOSE)}


def policies(keys):
    base=dict(source_record_ref=SOURCE,source_policy_ref='policy:stage06:contract_probe',max_source_age=300,
        max_validity_horizon=300,domain='RADIK_SUPPORT',currency='USD')
    return dict(producer=dict(base,local_root=ROOT_A,peer_root=ROOT_B,publish_enabled=True,
        release_uses=['LOCAL_CONTEXT'],recipients=[ROOT_B],policy_version='stage06.probe.publisher.v01'),
        recipient=dict(base,local_root=ROOT_B,peer_root=ROOT_A,peer_keys=keys,endpoint='endpoint:gate5:A',
        object_id=OBJECT,transport_scope='owner:stage06:engineering_pipes',schemas=[app.SCHEMA],
        uses=['LOCAL_CONTEXT','AUDIT'],accept_support_terms=True,status_max_age=60,policy_version='stage06.probe.recipient.v01'))


def review(root,label,value,checks,window=None):
    return n.root_review(root,'transaction:stage06:probe:'+label,'candidate:stage06:probe:'+c.sha(value),SOURCE,
        checks,value,int(time.time()),predicate='radik_stage06_engineering_contract',window=window)


def request(policy,op,task,pointer=None,use='LOCAL_CONTEXT',subject=None,nonce=None):
    now=int(time.time())
    value=c.with_id('request',dict(version='g51.request.v01',op=op,requester=ROOT_B,publisher=ROOT_A,task_ref=task,
        request_revision=1,pointer_ref=None if pointer is None else pointer['pointer_id'],trust_profile_hash=c.sha(policy),
        use_class=use,object_id=OBJECT,allowed_size=c.BODY_MAX,nonce=nonce or secrets.token_hex(32),issued_at=now,
        deadline=now+60,subject_request_ref=subject,owner_transport_scope=policy['transport_scope']))
    c.validate('request',value);return value


def source(folder,cap,keys,policy,callback):
    material=app._read(folder/'scenario.json');c.shape(material,('document','revision'))
    def current():
        c.require(app._read(folder/'scenario.json')==material,'stage06_probe_source_changed')
        return dict(source_sha256=c.sha(material),policy_sha256=c.sha(policy))
    result=app._work(ROOT_A,TASK+':producer','producer',material,current,folder/'source',callback)
    terms=result['output'];now=int(time.time())
    checked=review(ROOT_A,'source',dict(terms=terms,work_ref=result['artifact']['artifact_id']),
        dict(native=result['attempts']==1,current=current()['source_sha256']==c.sha(material)))
    c.require(checked[2].decision=='ACCEPT','stage06_probe_source_review')
    env=c.drs.drs_time_envelope_to_plain_data_v01(c.drs.build_drs_time_envelope_v01(pt_created_at=now,kt_as_of=now,
        et_observed_at=now,ct_context_anchor=now,ttl_seconds=300,valid_from=now,valid_to=now+300,
        source_observed_at=now,source_reported_at=now,system_ingested_at=now,system_verified_at=now,
        freshness_policy_id='freshness:stage06:probe'))
    body=dict(version='g51.body.v01',source_record_ref=SOURCE,source_revision=material['revision'],
        source_work_ref=result['artifact']['artifact_id'],source_review_ref=checked[2].decision_id,time_envelope=env,
        ttl_base='pt_created_at',source_lineage_refs=[result['artifact']['artifact_id']],publisher=ROOT_A,recipient=ROOT_B,
        document_sha256=terms['document_sha256'],terms=terms)
    c.validate('body',body,profile=app.profile())
    manifest=c.with_id('manifest',dict(version='g51.manifest.v01',publisher=ROOT_A,source_revision=body['source_revision'],
        source_refs=[SOURCE,body['source_work_ref'],body['source_review_ref']],declared_schema=app.SCHEMA,
        files=[dict(path='body.json',bytes=len(c.canonical(body)),sha256=c.sha(body))]))
    c.validate('manifest',manifest,profile=app.profile())
    pointer=c.with_id('pointer',dict(version='g51.pointer.v01',publisher_root_id=ROOT_A,publisher_key_id=cap.key_id,
        semantic_address=dict(namespace='radik_probe',domain='RADIK_SUPPORT',subject_class='support_terms',
            intent_class='context_lookup',schema_id=app.SCHEMA,schema_version='v01'),source_record_ref=SOURCE,
        source_revision=body['source_revision'],source_review_ref=body['source_review_ref'],body_sha256=c.sha(body),
        body_bytes=len(c.canonical(body)),media_type='application/json',artifact_manifest_ref=manifest['manifest_id'],
        safe_summary=app.SUMMARY,published_scope=dict(domain='RADIK_SUPPORT',currency='USD'),allowed_use_classes=['LOCAL_CONTEXT'],
        forbidden_use_classes=['ACTION'],recipient_scope=[ROOT_B],time_envelope=env,source_lineage_refs=body['source_lineage_refs'],
        access_policy_ref=policy['source_policy_ref'],revocation_stream_id='stream:stage06:contract_probe',transport_object_id=OBJECT,
        creates_authority=False,creates_permission=False))
    c.validate('pointer',pointer,profile=app.profile())
    publication=review(ROOT_A,'publication',pointer,dict(publish=policy['publish_enabled'],source_current=current()['source_sha256']==c.sha(material)))
    c.require(publication[2].decision=='ACCEPT','stage06_probe_publication_review')
    descriptor=c.sign(cap,keys,'POINTER',pointer,manifest['manifest_id'].split(':')[1])
    entry=dict(version='g51.entry.v01',pointer_id=pointer['pointer_id'],publisher_root_id=ROOT_A,
        stream_id=pointer['revocation_stream_id'],revision=1,state='ACTIVE',effective_at=now,reason_ref='reason:stage06:probe_published')
    entry['entry_hash']=c.sha(entry);c.validate('entry',entry)
    publication_ref=app._save(folder/'source/publication.json',dict(body=body,manifest=manifest,descriptor=descriptor,
        source_review=n.root_plain(checked),publication_review=n.root_plain(publication),status_entry=entry))
    app._event(callback,'source_published',dict(publication_ref=publication_ref,source_revision=body['source_revision']))
    return dict(body=body,manifest=manifest,descriptor=descriptor,entry=entry,current=current)


def producer_session(folder,channel,cap,keys,bootstrap,built,session):
    policy=bootstrap['requester_policy'];own=bootstrap['own_policy'];budget=x.PublisherBudget(folder/'publisher_budget.json',contexts())
    pointer=built['descriptor']['value'];manifest_hash=built['manifest']['manifest_id'].split(':')[1]
    app._line('READY','producer',session)
    for _ in range(16):
        msg=channel.receive();c.require(msg['kind']=='REQUEST','stage06_probe_wire_request')
        req=c.verify(msg['value'],bootstrap['peer_keys'],'REQUEST',c.sha(policy));c.validate('request',req)
        c.require((req['requester'],req['publisher'],req['trust_profile_hash'],req['owner_transport_scope'])==
            (ROOT_B,ROOT_A,c.sha(policy),policy['transport_scope']) and req['issued_at']<=int(time.time())<req['deadline'],'stage06_probe_request_binding')
        reserved=budget.reserve(req)
        if req['op']=='CLOSE':
            c.require(reserved,'stage06_probe_request_budget')
            channel.send('CLOSED',c.sign(cap,keys,'CLOSE',dict(request_ref=req['request_id'],session=session),c.sha(policy)))
            app._line('SESSION_CLOSED','producer',session);return
        c.require(reserved,'stage06_probe_request_budget');built['current']()
        if req['op']=='DESCRIBE':channel.send('POINTER',built['descriptor']);continue
        c.require(req['pointer_ref']==pointer['pointer_id'],'stage06_probe_pointer_binding')
        if req['op']=='STATUS':
            if budget.read()['tasks'][TASK]['bodies']==1 and built['entry']['state']=='ACTIVE':
                entry=dict(built['entry'],revision=2,state='REVOKED',effective_at=int(time.time()),reason_ref='reason:stage06:probe_revoked')
                entry['entry_hash']=c.sha({k:v for k,v in entry.items() if k!='entry_hash'});c.validate('entry',entry)
                built['entry']=entry;app._state(folder/'terminal_status.json',entry)
            now=int(time.time());status=dict(version='g51.status.v01',entry=built['entry'],requested_pointer_hash=c.sha(pointer),
                requester=ROOT_B,subject_request_ref=req['subject_request_ref'],request_revision=req['request_revision'],nonce=req['nonce'],checked_at=now,valid_until=now+60)
            c.validate('status',status);channel.send('STATUS',c.sign(cap,keys,'STATUS',status,manifest_hash));continue
        c.require(req['op']=='FETCH','stage06_probe_wire_operation')
        reviewed=review(ROOT_A,'disclosure',req,dict(current=built['entry']['state']=='ACTIVE',use=req['use_class'] in own['release_uses'],
            audience=req['requester'] in own['recipients'],budget=reserved),window=(req['issued_at'],req['deadline']))
        allowed=reviewed[2].decision=='ACCEPT'
        if allowed:budget.disclosure(req,len(c.canonical(built['body'])))
        release=dict(version='g51.release.v01',state='RELEASED' if allowed else 'REFUSED',request_ref=req['request_id'],
            request_revision=req['request_revision'],pointer_ref=pointer['pointer_id'],manifest_ref=built['manifest']['manifest_id'],
            body_hash=c.sha(built['body']),recipient=ROOT_B,use_class=req['use_class'],nonce=req['nonce'],deadline=req['deadline'],release_review_ref=reviewed[2].decision_id)
        c.validate('release',release);response=dict(release=c.sign(cap,keys,'RELEASE',release,manifest_hash),
            manifest=built['manifest'] if allowed else None,body=built['body'] if allowed else None)
        budget.response(req,allowed);app._save(folder/'releases'/(c.sha(req)+'.json'),dict(request=req,review=n.root_plain(reviewed),response=response))
        channel.send('BUNDLE',response)
    raise ValueError('stage06_probe_message_bound')


def recipient_session(folder,channel,cap,keys,bootstrap,session,callback):
    policy=bootstrap['own_policy'];store=life.ImportStore(folder);controls=[]
    def io(req):
        check=review(ROOT_B,'request',req,dict(scope=req['task_ref'] in contexts(),endpoint=policy['endpoint']=='endpoint:gate5:A'),window=(req['issued_at'],req['deadline']))
        c.require(check[2].decision=='ACCEPT','stage06_probe_retrieval_review')
        x.Budget(folder/'budgets'/(req['task_ref']+'.json'),req['task_ref']).reserve(req)
        channel.send('REQUEST',c.sign(cap,keys,'REQUEST',req,c.sha(policy)));return channel.receive()
    def refusal(label,reason,fn,clock='ACTUAL_INTEGER_UTC'):
        try:fn()
        except ValueError as exc:c.require(exc.args==(reason,),'stage06_probe_wrong_refusal')
        else:raise ValueError('stage06_probe_missing_refusal')
        controls.append(dict(label=label,reason=reason,clock=clock,consumer_work_dispatched=False))
    if session==1:
        response=io(request(policy,'DESCRIBE',TASK));c.require(response['kind']=='POINTER','stage06_probe_pointer_response')
        descriptor=response['value'];pointer=c.check_pointer(descriptor,policy,int(time.time()),profile=app.profile());c.check_route(pointer,policy)
        denied=request(policy,'FETCH',DENIED,pointer,use='AUDIT');response=io(denied)
        c.require(response['kind']=='BUNDLE','stage06_probe_denial_response')
        released=c.verify(response['value']['release'],policy['peer_keys'],'RELEASE',pointer['artifact_manifest_ref'].split(':')[1]);c.validate('release',released)
        c.require(released['state']=='REFUSED' and released['request_ref']==denied['request_id'] and response['value']['body'] is None and response['value']['manifest'] is None,'stage06_probe_denial')
        app._save(folder/'denied.json',dict(request=denied,response=response,body_read=False))
        fetch=request(policy,'FETCH',TASK,pointer);q=request(policy,'STATUS',TASK,pointer,subject=fetch['request_id'],nonce=fetch['nonce'])
        response=io(q);c.require(response['kind']=='STATUS','stage06_probe_status_response');status=response['value']
        store.observe(status,pointer,fetch,policy,int(time.time()));response=io(fetch);c.require(response['kind']=='BUNDLE','stage06_probe_bundle_response');bundle=response['value']
        def checked():
            return c.check_bundle(bundle,descriptor,fetch,status,policy,int(time.time()),app._read(store.path)['highwater'],store.conflicts(),profile=app.profile())
        admission=checked();c.require(store.import_body(admission,pointer)=='NEW_SOURCE','stage06_probe_import')
        x.Budget(folder/'budgets'/(TASK+'.json'),TASK).received_body(len(c.canonical(bundle['body'])))
        local=app._read(folder/'scenario.json');c.shape(local,('base_price','support_calls'))
        accepted=review(ROOT_B,'import',dict(body_sha256=c.sha(bundle['body']),request=fetch),dict(current=checked()['body']==bundle['body']))
        c.require(accepted[2].decision=='ACCEPT','stage06_probe_import_review')
        material=dict(local,terms=bundle['body']['terms'],import_ref='import:stage06:probe:'+c.sha(bundle),body_sha256=c.sha(bundle['body']),local_acceptance_ref=accepted[2].decision_id)
        def current():
            value=checked();c.require(app._read(folder/'scenario.json')==local,'stage06_probe_local_changed')
            return dict(body_sha256=c.sha(value['body']),status_entry_hash=value['status_entry']['entry_hash'],local_sha256=c.sha(local))
        work=app._work(ROOT_B,TASK+':consumer','consumer',material,current,folder/'consumer',callback)
        accepted_ref=app._save(folder/'accepted.json',dict(descriptor=descriptor,request=fetch,status=status,bundle=bundle,review=n.root_plain(accepted),work=work))
        app._event(callback,'current_consumption',dict(accepted_ref=accepted_ref,source_revision=pointer['source_revision']))
        changed=json.loads(c.canonical(bundle));changed['body']['terms']['unit_price']=(changed['body']['terms']['unit_price']+1)%101
        refusal('body_integrity','body_integrity',lambda:c.check_bundle(changed,descriptor,fetch,status,policy,int(time.time()),app._read(store.path)['highwater'],store.conflicts(),profile=app.profile()))
        refusal('wrong_anchor','signature_invalid',lambda:c.check_pointer(descriptor,dict(policy,peer_keys=c.crypto.trusted_root_key_set_to_plain_dict_v01(keys)),int(time.time()),profile=app.profile()))
        refusal('wrong_scope','schema_scope',lambda:c.check_pointer(descriptor,dict(policy,domain='UNRELATED'),int(time.time()),profile=app.profile()))
        refusal('expiry','source_not_current',lambda:c.check_pointer(descriptor,policy,pointer['time_envelope']['valid_to'],profile=app.profile()),'CONTROLLED_FUTURE_NEGATIVE_ONLY')
        qfetch=request(policy,'FETCH',TASK,pointer);q=request(policy,'STATUS',TASK,pointer,subject=qfetch['request_id'],nonce=qfetch['nonce'])
        response=io(q);c.require(response['kind']=='STATUS','stage06_probe_terminal_response');terminal=response['value']
        store.observe(terminal,pointer,qfetch,policy,int(time.time()))
        refusal('revoked','status_not_active',lambda:c.check_status(terminal,pointer,qfetch,policy,int(time.time()),app._read(store.path)['highwater']))
        app._save(folder/'terminal.json',dict(request=qfetch,status=terminal,highwater=app._read(store.path)['highwater']))
        report=dict(status='PASS_PROBE_SESSION_1',scope='ONE_CURRENT_NATIVE_CONSUMER_AND_CONTRACT_CONTROLS',output=work['output'],controls=controls)
    else:
        old=app._read(folder/'accepted.json');before=app._read(store.path)['highwater']
        refusal('restart_old_active','status_rollback',lambda:store.observe(old['status'],old['descriptor']['value'],old['request'],policy,int(time.time())))
        pointer=old['descriptor']['value'];key=c.canonical([pointer['publisher_root_id'],pointer['source_record_ref']]).decode()
        mechanical={key:dict(revision=pointer['source_revision']+1,body_sha256='0'*64,pointer_ref='fixture:mechanical:revision_guard')}
        refusal('mechanical_revision_highwater','stage06_source_revision_rollback',lambda:app.check_source_revision(pointer,mechanical),'MECHANICAL_STATE_FIXTURE_NOT_CURRENT_AUTHORITY')
        c.require(app._read(store.path)['highwater']==before,'stage06_probe_restart_highwater')
        report=dict(status='PASS_PROBE_SESSION_2',scope='RESTART_STATUS_AND_MECHANICAL_REVISION_GUARD_ONLY',controls=controls,
            historical_accepted_sha256=c.sha(old),retained_status_highwater=before,new_native_work=0,owner_revision2_consumption=False)
    close=request(policy,'CLOSE',CLOSE);response=io(close);c.require(response['kind']=='CLOSED','stage06_probe_close')
    c.require(c.verify(response['value'],policy['peer_keys'],'CLOSE',c.sha(policy))==dict(request_ref=close['request_id'],session=session),'stage06_probe_close_binding')
    report.update(process_id=os.getpid(),fresh_key_id=cap.key_id,provider_calls=0,task_selector='engineering_probe_v01')
    ref=app._save(folder/('session_'+str(session)+'.json'),report);app._line('DONE','recipient',session,status=report['status'],report_ref=ref)


def peer(role,read_fd,write_fd,folder,*,session=1,on_event=None,task_selector='engineering_probe_v01'):
    c.require(task_selector=='engineering_probe_v01' and role in ('producer','recipient') and session in (1,2),'stage06_probe_peer_arguments')
    folder=Path(folder);root=ROOT_A if role=='producer' else ROOT_B
    cap=c.crypto.generate_root_signer_capability_v01(root_id=root);keys=c.crypto.build_trusted_root_key_set_v01(capabilities=(cap,))
    public=c.crypto.trusted_root_key_set_to_plain_dict_v01(keys);app._line('PUBLIC_KEYS',role,0 if role=='producer' else session,public_keys=public)
    try:
        built=None
        for current_session in ((1,2) if role=='producer' else (session,)):
            bootstrap=json.loads(input());c.require(bootstrap['session']==current_session and bootstrap['contexts']==contexts(),'stage06_probe_bootstrap')
            expected=policies(public if role=='producer' else bootstrap['peer_keys'])
            c.require(bootstrap['own_policy']==expected[role],'stage06_probe_policy')
            c.require(c.keyset(bootstrap['peer_keys']).root_ids==((ROOT_B,) if role=='producer' else (ROOT_A,)),'stage06_probe_anchor')
            app._save(folder/('bootstrap_'+str(current_session)+'.json'),bootstrap)
            directory=folder/('session_'+str(current_session));directory.mkdir();channel=x.PipeChannel(read_fd,write_fd,directory)
            if role=='producer':
                c.require(bootstrap['requester_policy']==expected['recipient'],'stage06_probe_requester_policy')
                if built is None:built=source(folder,cap,keys,bootstrap['own_policy'],on_event)
                producer_session(folder,channel,cap,keys,bootstrap,built,current_session)
            else:recipient_session(folder,channel,cap,keys,bootstrap,current_session,on_event)
            app._save(directory/'counters.json',channel.counters())
        if role=='producer':
            ref=app._save(folder/'producer_result.json',dict(status='PASS_PROBE_PRODUCER',process_id=os.getpid(),provider_calls=0,
                task_selector='engineering_probe_v01',native_work_calls=1,publisher_budget=app._read(folder/'publisher_budget.json')))
            app._line('DONE','producer',2,status='PASS_PROBE_PRODUCER',report_ref=ref)
    finally:
        primary=sys.exc_info()[0]
        for descriptor in (read_fd,write_fd):
            try:os.close(descriptor)
            except OSError:
                if primary is None:raise
