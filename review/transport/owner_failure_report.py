"""Minimal independently pinned stdlib owner-failure return entry.

No application, identity, credential, native or provider module is imported.
If this writer closure is not confirmed, the only action is a stdout refusal.
"""
import hashlib
import json
from pathlib import Path
import re
import runpy
import stat
import os

PROJECT=Path('/Users/admin/Projects/RadiolariaRadik')
REVIEW='review/normal_session_g2e_passage/failure_reporter_review.json'
AUTH_REVIEW='review/normal_session_g2e_passage/auth_reporter_review.json'
SELF='review/transport/owner_failure_report.py'
PACK='review/package_direct_plan_return.py'
DIAGNOSTICS='app/stage04_diagnostics.py'


def _read(relative):
    path=PROJECT/relative
    for item in (path,*path.parents):
        if item.is_symlink():raise ValueError('reporter_symlink')
        if item==PROJECT:break
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('reporter_regular_file')
        raw=stream.read(8*1024*1024+1)
    if len(raw)>8*1024*1024:raise ValueError('reporter_byte_bound')
    return raw


def _writer_review():
    record=json.loads(_read(REVIEW))
    if record.get('status')!='ACCEPTED_FOR_STDLIB_OWNER_FAILURE_RETURN' or record.get('reviewer')!='/root/semantic_continuation_reviewer':
        raise ValueError('reporter_independent_acceptance_required')
    if set(record['code_source_pins'])!={SELF,PACK,DIAGNOSTICS}:raise ValueError('reporter_closure')
    for relative,expected in record['code_source_pins'].items():
        if hashlib.sha256(_read(relative)).hexdigest()!=expected:raise ValueError('reporter_source_identity_changed')
    return record


def report(state, *, source_admitted, transport_directory=None):
    _writer_review()
    pack=runpy.run_path(str(PROJECT/PACK),run_name='independently_reviewed_failure_writer')
    return pack['publish_stage04_owner_failure'](state,source_admitted=source_admitted,transport_directory=transport_directory)


def report_auth_success(state):
    """One independently sealed auth-only return; no live gate or app import."""
    record=json.loads(_read(AUTH_REVIEW))
    if (record.get('status')!='ACCEPTED_FOR_STDLIB_AUTH_ONLY_RETURN'
            or record.get('scope')!='CURATED_AUTH_ONLY_OWNER_RETURN'
            or record.get('reviewer')!='/root/semantic_continuation_reviewer'):
        raise ValueError('reporter_auth_independent_acceptance_required')
    if set(record.get('code_source_pins',{}))!={SELF,PACK}:raise ValueError('reporter_auth_closure')
    for relative,expected in record['code_source_pins'].items():
        if hashlib.sha256(_read(relative)).hexdigest()!=expected:raise ValueError('reporter_auth_source_identity_changed')
    pack=runpy.run_path(str(PROJECT/PACK),run_name='independently_reviewed_auth_only_writer')
    return pack['publish_owner_auth_success'](state)


def bootstrap_failure(error):
    _writer_review()
    diagnostics=runpy.run_path(str(PROJECT/DIAGNOSTICS),run_name='reviewed_bootstrap_diagnostics')
    projected=diagnostics['safe_projection'](error)
    # Reentry on the same source refusal shares a permanent build marker.
    core={key:projected[key] for key in ('code','type','phase','step')}
    identity=hashlib.sha256(_read(REVIEW)+json.dumps(core,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:32]
    state={'schema':'radik.direct_plan_owner_state.v01','stage':'BOOTSTRAP_SOURCE_REFUSED',
        'operation_id':identity,'actual_result_path':None,'error':projected,
        'command_stage':'BOOTSTRAP','runtime':'NOT_ADMITTED','console':'NOT_ADMITTED',
        'auth_catalog_model_Work_SAVE':'NOT_STARTED_BY_THIS_INVOCATION; CURRENT_CONNECTION_NOT_OBSERVED'}
    return report(state,source_admitted=False)
