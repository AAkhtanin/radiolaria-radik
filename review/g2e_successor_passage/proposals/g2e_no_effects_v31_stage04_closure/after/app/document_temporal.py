"""New informational issuance policy; existing ACTION anchors are unchanged."""
from datetime import datetime, timedelta

PROFILE = 'radik.informational_document.temporal.v26'
FAMILY_VERSION = 'radik.semantic.source_family.informational.v26'
INFORMATION_SECONDS = 10800
RESULT_REUSE_SECONDS = 7200
NATIVE_SECONDS = 3600
CONSUMER_SECONDS = 120
PROVIDER_REQUEST_SECONDS = 600
PROVIDER_CALLS = 6
PROVIDER_SECONDS = PROVIDER_REQUEST_SECONDS * PROVIDER_CALLS
OWNER_WORK_SECONDS = PROVIDER_SECONDS + NATIVE_SECONDS + 600
CLEANUP_SECONDS = 30


def epoch(value):
    if type(value) is int:
        return value
    if type(value) is str:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0):
            return int(parsed.timestamp())
    raise ValueError('informational_time_shape')


def require_remaining(valid_to, now, required=0):
    if not all(type(v) is int for v in (valid_to, now, required)) or not 0 <= required < valid_to-now:
        raise ValueError('informational_insufficient_validity')
    return valid_to-now


def collect_caps(value, prefix='material'):
    """Read every explicit public expiry and PT/TTL cap, without renewing one."""
    rows=[]; visited=0
    def visit(node,path,depth=0):
        nonlocal visited
        visited+=1
        if visited>300000 or depth>48:
            raise ValueError("informational_temporal_material_bound")
        if type(node) is dict:
            for key,item in node.items():
                if key in ('valid_to','valid_to_utc','expires_at_utc') and item is not None:
                    rows.append(dict(path=path+'.'+key,valid_to=epoch(item)))
                visit(item,path+'.'+key,depth+1)
            if 'ttl_seconds' in node and type(node['ttl_seconds']) is int:
                for key in ('pt_created_at','pt_created_at_utc'):
                    if node.get(key) is not None:
                        rows.append(dict(path=path+'.'+key+'+ttl_seconds',valid_to=epoch(node[key])+node['ttl_seconds']))
        elif type(node) is list:
            for index,item in enumerate(node):visit(item,path+'['+str(index)+']',depth+1)
    visit(value,prefix)
    return rows
