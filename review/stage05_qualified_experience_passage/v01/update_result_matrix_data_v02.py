"""Authored evidence mapping only; reads retained JSON and hashes, never imports app code."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

PROJECT=Path('/Users/admin/Projects/RadiolariaRadik')
BASE=Path('review/stage05_qualified_experience_passage/v01')

def ref(path):
    path=Path(path)
    if path.is_absolute():path=path.relative_to(PROJECT)
    raw=path.read_bytes()
    return dict(path=str(path),sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))

def checked(value):
    actual=ref(value['path'])
    assert actual['sha256']==value['sha256'] and actual['size_bytes']==value.get('size_bytes',value.get('bytes'))
    return actual

def unique(values):
    result={}
    for value in values:
        value=checked(value)
        assert value['path'] not in result or result[value['path']]==value
        result[value['path']]=value
    return list(result.values())

old=BASE/'metadata_history/v05/result_matrix.json'
raw=old.read_bytes();assert hashlib.sha256(raw).hexdigest()=='08e60935c4335b4c5ab3250b7fec675574f6a788b0cf12fa8d4562ac4b93b4e7'
assert (BASE/'result_matrix.json').read_bytes()==raw
matrix=json.loads(raw)
read=lambda name:json.loads((BASE/name).read_bytes())
tail=read('g4_native_tail_independent_result_review_v01.json')
eligibility=read('g3_eligibility_independent_result_review_v01.json')
reporter=read('failure_capture_controls_independent_result_review_v02.json')
ordinary=read('rehearsal_v02_independent_result_review.json')
assert tail['reviewer']==eligibility['reviewer']==reporter['reviewer']=='/root/private_remote_controls'
assert tail['status']=='COMPLETED_NATIVE_G3_G4_PREFIX_ACCEPTED_CONTROLS_STOPPED'
assert eligibility['status']=='PASS_FRESH_NATIVE_ELIGIBILITY_AND_UNSCORABLE_ONLY'
assert reporter['status']=='PASS_SYNTHETIC_AST_HELPERS_ONLY'
T=ref(BASE/'g4_native_tail_independent_result_review_v01.json')
E=ref(BASE/'g3_eligibility_independent_result_review_v01.json')
D=ref(BASE/'failure_capture_controls_independent_result_review_v02.json')
O=ref(BASE/'rehearsal_v02_independent_result_review.json')
tail_refs=unique(tail['evidence_refs']);elig_refs=unique(eligibility['evidence_refs'])
def selected(values, fragment):
    return [value for value in values if fragment in Path(value['path']).name]
feedback=selected(tail_refs,'feedback_');cold_g3=selected(tail_refs,'cold_G3_');qualified_g3=selected(tail_refs,'qualified_G3_')
g4=selected(tail_refs,'qualified_allocation_actual_')+selected(tail_refs,'qualified_allocation_pre_dispatch_')
controls=selected(elig_refs,'controls_');unscorable=selected(elig_refs,'unscorable_')
assert len(feedback)==len(cold_g3)==len(qualified_g3)==len(controls)==len(unscorable)==1 and len(g4)==4
source_fix=ref(BASE/'g3_restriction_independent_source_review_v01.json')
g4_fix=ref(BASE/'g4_targeted_revision_independent_source_review_v01.json')
current_source=ref(BASE/'runtime_source_review.json')
current_manifest=ref(BASE/'ordinary_profile_manifest.json')
review_map={
 'S5-01':([T,*feedback,*cold_g3,*qualified_g3], 'SOURCE_AND_FOCUSED_NATIVE_CAUSAL_CHAIN_OBSERVED',
     'The isolated fresh-memory/raw-fixture route retained a prospective claim before a new PURE observation, recorded an eligible negative event, and changed actual G3 Work from verification to an additional source audit at prior_fp=-62500000. This is not the ordinary cold three-role route.'),
 'S5-02':([E,*unscorable], 'SOURCE_AND_FOCUSED_UNSCORABLE_AUDIT_OBSERVED',
     'A labelled UNSCORABLE_MODEL_RESPONSE category left a nonempty qualified history head unchanged with NO_UPDATE. No actual transport, AUTH or provider failure was induced or claimed.'),
 'S5-03':([E,*controls], 'SOURCE_AND_FOCUSED_NATIVE_TEMPORAL_REFUSALS_OBSERVED',
     'Fresh history was eligible; explicit evaluation at age300 and original expiry refused current ranking/open. Original record/head/TTL remained unchanged. These are controlled future clocks, not elapsed wall time; an additional Work after aged refusal was not executed.'),
 'S5-04':([E,*controls], 'SOURCE_AND_FOCUSED_NATIVE_SOURCE_KEY_MISMATCH_OBSERVED',
     'A controlled advisory_source_revision mismatch was refused by native current history discovery while retaining the original record/head. This is a changed-key query, not an actual source edit, revision or supersession event.'),
 'S5-05':([E,*controls], 'SOURCE_AND_FOCUSED_NATIVE_RESTRICTIVE_STATE_REFUSALS_OBSERVED',
     'Injected conflict and quarantine restricted eligibility; the ordinary consume method refused before history payload descent, numeric advice or new Work binding. Both controls preserved original history and time envelopes and restored only the prior in-memory restriction setting.'),
 'S5-06':([T,E,*cold_g3,*qualified_g3,*controls], 'SOURCE_AND_FOCUSED_SCOPED_CONSUMER_CHANGE_OBSERVED',
     'The tail consumed a different source audit for the same eligible negative history. A separate fresh-history fixture refused an unrelated task-class query; it did not run a third unrelated-task Work program. No transfer of prior or permission is inferred.'),
 'S5-07':([T,*g4], 'SOURCE_AND_FOCUSED_NATIVE_HARD_MASK_EXCLUSION_OBSERVED',
     'Both retained native allocations exclude external_unapproved despite its maximal configured features. The materialized programs and actual check outputs contain only approved quotation/qualification branches; the excluded branch consumes zero native units.'),
 'S5-08':([T,*g4], 'SOURCE_AND_FOCUSED_NATIVE_EQUAL_BUDGET_REDISTRIBUTION_OBSERVED',
     'Two actual native programs each consumed9 units: source gate1, selected checks7 and final consumer1. Allocation changed4/3 to3/4 and each final consumer read all7 selected outputs. Full revision outcomes, programs, results, usage and two distinct Root reviews are retained. No speedup is claimed.'),
 'S5-09':([O,D,checked(ordinary['owner_receipt_ref']),checked(reporter['result_ref'])], 'SOURCE_ORDINARY_STOP_AND_FOCUSED_REPORTER_CONTROLS_OBSERVED',
     'V02 preserved its stopped receipt/readbacks and reaped its child; its original sanitized G4 cause remains unknown. The later exact reporter passed synthetic AST checks for closed causes, frames and primary precedence. No complete ordinary or owner scenario is established; 3000/900 limits remain caps, not a measured ordinary-route ETA.'),
 'S5-10':([O,T,E,D,checked(ordinary['native_origins_ref'])], 'SOURCE_AND_COMPOSED_ISOLATED_BOUNDARIES_OBSERVED',
     'V02 observed54 native origins,26 callbacks and33 schemas with admitted source bytes. Both short native fixtures loaded69 pinned protected modules and preserved378 production guards. Native result hashes and PURE bindings are retained; a separate complete G4 callback source-snapshot receipt is not claimed. Final current source admission plus these bounded observations support preparation, not owner acceptance.'),
}
for row in matrix['rows']:
    refs,status,scope=review_map[row['id']]
    row['preparation_status']=status
    row['scope']=scope
    row['short_fixture_evidence']=dict(status='OBSERVED_WITHIN_INDEPENDENTLY_REVIEWED_SCOPE_ONLY',refs=unique(refs),
        ordinary_route_acceptance=False,owner_actual=False,Stage05_closure=False)
    row['ordinary_v02']['status']='STOPPED_AFTER_COLD_G3_WITH_ORIGINAL_G4_CAUSE_UNKNOWN'
    row['ordinary_v02']['actual_refs']=unique([O,checked(ordinary['stopped_result_ref'])])
    current=[]
    for previous in row['source_and_control_refs']:
        current.append(current_source if previous['path']==str(BASE/'runtime_source_review.json') else previous)
    if row['id'] in ('S5-01','S5-02','S5-03','S5-04','S5-05','S5-06'):current.append(source_fix)
    if row['id'] in ('S5-06','S5-07','S5-08'):current.append(g4_fix)
    if row['id'] in ('S5-09','S5-10'):current.append(D)
    row['source_and_control_refs']=unique(current)
    assert row['owner_actual_status']=='NOT_RUN'and row['Stage05_closure']=='NOT_ESTABLISHED'
matrix['status']='SOURCE_AND_COMPOSED_SHORT_NATIVE_EVIDENCE_OWNER_NOT_RUN'
matrix['created_at_utc']=datetime.now(timezone.utc).isoformat()
matrix['supersedes_ref']=ref(old)
matrix['source_manifest_ref']=current_manifest
matrix['current_source_review_ref']=current_source
matrix['mapping_generation']=dict(application_imports=0,application_execution=False,author='/root/stage05_g3_contract',
    independent_acceptance_required=True)
matrix['observed_execution_scope']='Retained ordinary V01/V02 stops and separately admitted isolated short native fixtures; no owner execution.'
matrix['limitations']=[
 'Original ORDINARY_V02 sanitized G4 cause remains unknown. Later API fixes and focused observations do not recover that lost exception.',
 'The native tail and eligibility fixtures use fresh current memory descent with unchanged historical clocks and pinned raw-source reads; they do not execute the normal TaskStore source path or three cold model roles.',
 'NATIVE_TAIL_V01 stopped after successful G3/G4 phases at the eligibility constructor mismatch. ELIGIBILITY_V01 separately observed the repaired branch with one new prospective native history; no earlier live binding was reconstructed.',
 'Explicit future clocks, changed-key queries and conflict/quarantine are labelled controls. No elapsed wall time, external source event or unrelated-task Work execution is claimed.',
 'G4 gates apply at selection, source/Host setup, bootstrap/allocation and final acceptance. Individual PURE quanta use captured material without per-quantum history cancellation.',
 '23.63001254107803s tail and6.192874915897846s eligibility durations measure their isolated raw-fixture routes. They do not establish ordinary-route speed or complete owner timing.',
 'Owner actual remains NOT_RUN and Stage05 closure NOT_ESTABLISHED. Publication remains LOCAL_ONLY; the separate Stage04 public repository grants no Stage05 push.',
]
matrix['independent_actual_reviews']=[O,T,E,D]
assert checked(matrix['prospective_matrix_ref'])==matrix['prospective_matrix_ref']
assert len(matrix['rows'])==10
original=json.loads(raw)
for before,after in zip(original['rows'],matrix['rows']):
    for key in ('id','claim','prospective_requirement','owner_actual_status','Stage05_closure'):
        assert before[key]==after[key]
assert matrix['owner_actual']=='NOT_RUN' and matrix['publication']=='LOCAL_ONLY' and matrix['prospective_matrix_modified'] is False
payload=(json.dumps(matrix,indent=2,sort_keys=True)+'\n').encode()
(BASE/'result_matrix.json').write_bytes(payload)
print(hashlib.sha256(payload).hexdigest(),len(payload))
