"""Typed external fixtures for the SOURCE-only copied ordinary entry.

Only external grant/catalog/HTTP bytes are synthetic. The existing transport,
HTTP parser, SSE parser, issued requests and normal validators remain active.
"""
from dataclasses import dataclass
import http.client
import io
import json
from pathlib import Path
import re
import sys
import time

from config.application_profile_gate import validate_rehearsal_context,require
from .contracts import canonical,digest

_FIXTURE_KEY=object()
SCOPES=('openid','profile','email','offline_access','resource.invoke','chatgpt.tokens.use.direct')


@dataclass(frozen=True,repr=False)
class _FixtureGrant:
    access_token:str
    connection_id:str
    scopes:tuple
    expires_at:int
    context_sha256:str

    def public_receipt(self):
        return dict(schema='radik.plan_connection_receipt.v01',status='ISOLATED_REHEARSAL_GRANT_NO_AUTHORITY',
            connection_id=self.connection_id,scopes=list(self.scopes),expires_at=self.expires_at,
            issuer_verified=False,issued_client_identity_binding_verified=False,
            workspace_binding_basis='EXACT_SOURCE_REHEARSAL_COPY_NOT_REAL_IDENTITY',
            rehearsal_context_sha256=self.context_sha256)


class RehearsalAuth:
    def __init__(self,project,context,*,_key=None):
        require(_key is _FIXTURE_KEY,'rehearsal_auth_typed_factory_required')
        self.project=Path(project);self.context=validate_rehearsal_context(project,context)
        self._grant=_FixtureGrant('INERT_REHEARSAL_NO_CREDENTIAL','radik-plan:rehearsal:'+context.seal_sha256[:24],
            SCOPES,int(time.time())+10800,context.seal_sha256)
        self.requests=[]

    def access_for_plan(self):
        validate_rehearsal_context(self.project,self.context)
        return self._grant

    def connection(self,sender):
        require(sender.project==self.project and sender.auth is self,'rehearsal_connection_origin')
        validate_rehearsal_context(self.project,self.context)
        return _Connection(self,sender)


def make_auth(project,context):return RehearsalAuth(project,context,_key=_FIXTURE_KEY)


def validate_fixture_catalog(project,context,value):
    validate_rehearsal_context(project,context)
    require(value.get('connection',{}).get('rehearsal_context_sha256')==context.seal_sha256
        and value['connection']['status']=='ISOLATED_REHEARSAL_GRANT_NO_AUTHORITY',
        'rehearsal_fixture_catalog_binding')


class _Socket:
    def __init__(self,raw=b''):self.raw=raw
    def settimeout(self,_seconds):pass
    def shutdown(self,_how):pass
    def close(self):pass
    def makefile(self,*_args,**_kwargs):return io.BytesIO(self.raw)


class _Connection:
    host='api.openai.com';port=443
    def __init__(self,auth,sender):self.auth=auth;self.sender=sender;self.sock=None;self.wire=None
    def connect(self):
        validate_rehearsal_context(self.auth.project,self.auth.context);self.sock=_Socket()
    def close(self):
        if self.sock is not None:self.sock.close()
    def request(self,method,path,body=None,headers=None):
        require(method in ('GET','POST')and path==('/v1/models'if method=='GET'else'/v1/responses'),
            'rehearsal_fixed_endpoint')
        require(self.wire is None,'rehearsal_http_no_repeat')
        validate_rehearsal_context(self.auth.project,self.auth.context)
        self.wire=(method,path,body)
        self.auth.requests.append(dict(method=method,path=path,body_sha256=None if body is None else digest(body),
            classification='INERT_NO_NETWORK_NO_AUTHORITY'))
    def getresponse(self):
        method,path,body=self.wire
        if method=='GET':payload=canonical(dict(models=[dict(slug='gpt-6.1-sol',visibility='list')]));media='application/json'
        else:payload=_stream(json.loads(body));media='text/event-stream'
        raw=('HTTP/1.1 200 OK\r\nContent-Type: '+media+'\r\nContent-Length: '+str(len(payload))+'\r\n\r\n').encode()+payload
        response=http.client.HTTPResponse(_Socket(raw),method=method);response.begin();return response


def _synthetic_claims(context):
    """Produce fixture claims from exact source lines, never edit real responses.

    This deterministic inert HTTP producer exercises the ordinary validators.
    Its labels are synthetic source preparation, not semantic model evidence.
    """
    claims=[]
    for source in context['sources']:
        raw=source['text'].encode('utf-8');offset=0;rows=[]
        for line in raw.splitlines(keepends=True):
            quoted=line.rstrip(b'\r\n');start=offset;offset+=len(line)
            if not quoted:continue
            quote=quoted.decode('utf-8');text=quote.casefold()
            kind=('exception' if re.search(r'\b(exception|except|unless)\b|исключени|кроме',text)
                else 'unknown' if re.search(r'\b(unknown|unspecified|unconfirmed)\b|not stated|not specified|неизвест|не указан',text)
                else 'condition' if re.search(r'\b(condition|if|provided)\b|only when|only with|только|если|услови',text)
                else 'support')
            rows.append(dict(source_ref=source['source_ref'],revision=source['revision'],sha256=source['sha256'],
                start=start,end=start+len(quoted),quote=quote,kind=kind))
        require(rows and all(len(row['quote'].encode('utf-8'))<=2048 for row in rows),
            'rehearsal_fixture_claim_lines')
        # A bounded round-robin retains every source before adding more claims.
        claims.append(rows)
    result=[]
    for index in range(max(map(len,claims))):
        for rows in claims:
            if index<len(rows) and len(result)<8:result.append(rows[index])
    require(1<=len(result)<=8,'rehearsal_fixture_claim_count')
    return result


def _product(context):
    from .dynamic_roles import ROLE_VERSIONS,CRITIC_CHECKS
    role=context['role'];spec=context['task'];uncertainty='Synthetic inert rehearsal response; no model quality or external authority.'
    value=dict(version=ROLE_VERSIONS[role],task_id=spec['task_id'],profile=spec['profile'],criterion=spec['criterion'])
    if role=='orchestrator':
        value.update(source_scope_sha256=context['source_scope_sha256'],route='short',
            evidence_requests=context['available_exact_spans'],uncertainty=uncertainty)
    elif role=='architect':
        sources={s['source_ref']:s for s in context['sources']}
        claims=[dict(span,
            quote=sources[span['source_ref']]['text'].encode()[span['start']:span['end']].decode(),kind='support')
            for span in context['available_exact_spans']] if spec['profile']=='compare' else _synthetic_claims(context)
        value.update(source_scope_sha256=context['source_scope_sha256'],claims=claims,
            statement='Synthetic source-bound short comparison.' if spec['profile']=='compare'
                else 'Synthetic source-bound short '+spec['profile']+'.',
            uncertainty=uncertainty,program=dict(route='short',optional_exceptions=False))
    else:
        value.update(candidate_sha256=digest(context['candidate']),work_sha256=digest(context['work']),verdict='ACCEPT',
            checks=[dict(name=name,passed=True)for name in CRITIC_CHECKS],supporting_claims=list(range(len(context['candidate']['claims']))),
            uncertainty=uncertainty)
    return value


def _stream(body):
    context=json.loads(body['input'][0]['content'][0]['text']);text=canonical(_product(context)).decode()
    response_id='resp_rehearsal_'+digest(body)[:24];item_id='msg_rehearsal_'+digest(body)[:24]
    item=dict(id=item_id,type='message',role='assistant',status='completed',content=[dict(type='output_text',text=text,annotations=[])])
    events=[dict(type='response.created',response=dict(id=response_id,status='in_progress',output=[])),
        dict(type='response.output_item.added',output_index=0,item=dict(item,status='in_progress',content=[])),
        dict(type='response.output_text.delta',output_index=0,content_index=0,item_id=item_id,delta=text),
        dict(type='response.output_text.done',output_index=0,content_index=0,item_id=item_id,text=text),
        dict(type='response.output_item.done',output_index=0,item=item),
        dict(type='response.completed',response=dict(id=response_id,status='completed',output=[item],model=body['model'],
            reasoning=body['reasoning'],service_tier=body['service_tier'],usage=dict(input_tokens=1,output_tokens=1,total_tokens=2)))]
    return b''.join(('event: '+e['type']+'\ndata: ').encode()+canonical(dict(e,sequence_number=i))+b'\n\n'for i,e in enumerate(events))


def install_fence(project,context):
    """Deny actual sockets, secret paths and all production writes before imports."""
    validate_rehearsal_context(project,context);root=Path(project);real=context.environment_root
    def audit(event,args):
        if event.startswith(('socket.','subprocess.','os.system','os.exec')):
            raise ValueError('rehearsal_external_process_or_network_refused')
        if event in ('open','os.mkdir','os.remove','os.rename','os.rmdir','os.unlink'):
            if not args or not isinstance(args[0],(str,bytes,Path)):return
            path=Path(args[0]).absolute()
            require(not set(path.parts).intersection(('private','.codex','.aws','Arena','arena')),
                'rehearsal_credential_path_refused')
            if event=='open':
                mode=args[1];flags=args[2]
                writing=(isinstance(mode,str)and any(c in mode for c in 'wax+'))or isinstance(flags,int)and bool(flags& (1|2|64|512|1024))
                if writing:require(path.is_relative_to(root),'rehearsal_production_write_refused')
            else:
                require(path.is_relative_to(root),'rehearsal_production_write_refused')
                if event=='os.rename'and isinstance(args[1],(str,bytes,Path)):
                    require(Path(args[1]).absolute().is_relative_to(root),'rehearsal_production_write_refused')
    sys.addaudithook(audit)
    return dict(network='DENIED',credentials='DENIED_BEFORE_REAL_AUTH',writes='EXACT_OWNED_COPY_ONLY',
        application_root=str(root),environment_root=str(real))
