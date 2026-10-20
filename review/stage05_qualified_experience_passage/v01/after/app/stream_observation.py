"""Bounded public stream structure; no event body or provider text escapes.

This module performs no I/O. The projector accepts only this closed structural
schema, including on durable readback; arbitrary nested dictionaries are refused.
"""
import hashlib
import json
import math
import re

from .stage04_diagnostics import project_stream_event


SCHEMA = 'radik.public_stream_event_observation.v03'
MAX_OBSERVATION_BYTES = 16384
MAX_PAYLOAD_BYTES = 262144
RECENT_TYPE_COUNT = 8
_TOKEN = re.compile(r'[a-z][a-z0-9_.]{0,95}\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[A-Za-z0-9_-]{1,160}\Z')
_SHAPES = ('ABSENT', 'NULL', 'BOOLEAN', 'INTEGER', 'FLOAT', 'STRING', 'ARRAY', 'OBJECT', 'OTHER')
_FIELDS = ('type', 'sequence_number', 'response', 'response_id', 'item', 'item_id', 'output_index',
    'content_index', 'summary_index', 'annotation_index', 'part', 'delta', 'text', 'refusal', 'annotation',
    'status', 'logprobs', 'code', 'message', 'param', 'arguments', 'name', 'input', 'command', 'obfuscation',
    'metadata', 'safety_buffering')
_NAME_STATES = ('ABSENT', 'NULL', 'INVALID_TYPE', 'TOKEN', 'INVALID_TOKEN', 'OVERSIZED', 'INVALID_UTF8')
_COUNT_KEYS = ('accepted_events', 'item_count', 'finalized_count', 'text_parts', 'reasoning_parts',
    'summary_parts', 'refusal_parts')
MAX_METADATA_BYTES = 16384
MAX_JSON_INTEGER_DIGITS = 4300
METADATA_KEYS = ('type', 'openai_verification_recommendation', 'openai_chatgpt_moderation_metadata',
    'use_cases', 'reasons', 'retry_model')
METADATA_HEADERS = ('openai-model', 'x-openai-model', 'x-codex-turn-state',
    'x-codex-safety-buffering-enabled', 'x-codex-safety-buffering-faster-model')
METADATA_REFUSALS = ('plan_metadata_shape', 'plan_metadata_byte_limit', 'plan_metadata_model_shape',
    'plan_metadata_model_conflict', 'plan_metadata_verification_shape', 'plan_metadata_verification_required',
    'plan_metadata_buffering_shape', 'plan_metadata_control_conflict', 'plan_metadata_control_not_supported')


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _shape(value, present=True):
    return 'ABSENT' if not present else 'NULL' if value is None else 'BOOLEAN' if type(value) is bool else \
        'INTEGER' if type(value) is int else 'FLOAT' if type(value) is float else 'STRING' if type(value) is str else \
        'ARRAY' if type(value) is list else 'OBJECT' if type(value) is dict else 'OTHER'


def _name(value, present=True):
    result = dict(state='ABSENT', token=None, chars=None, bytes=None, sha256=None)
    if not present:
        return result
    if value is None:
        return dict(result, state='NULL')
    if type(value) is bytes:
        result.update(bytes=len(value), sha256=_sha(value))
        try:
            value = value.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            return dict(result, state='INVALID_UTF8')
    if type(value) is not str:
        return dict(result, state='INVALID_TYPE')
    raw = value.encode('utf-8', errors='surrogatepass')
    result.update(chars=len(value), bytes=len(raw), sha256=_sha(raw))
    result['state'] = 'OVERSIZED' if len(raw) > 96 else 'TOKEN' if _TOKEN.fullmatch(value) else 'INVALID_TOKEN'
    if result['state'] == 'TOKEN':
        result['token'] = value
    return result


class EventJSONRefusal(ValueError):
    """Closed decoder failure; partial material remains private in memory."""
    def __init__(self, code, *, resource=None, partial_event=None):
        super().__init__(code)
        self.code, self.resource, self.partial_event = code, resource, partial_event


def _resource(kind, measurement, value, relation, limit, complete):
    return dict(limit_kind=kind, measurement=measurement, value=value, relation=relation,
        limit=limit, traversal_complete=complete)


def decode_event_json(raw):
    """Iterative strict event decoder, with storage/work bounded by event bytes.

    Frames replace the recursive object/array decoder. Decimal integer conversion
    retains an explicit 4300-digit implementation ceiling; it is not an opaque
    metadata schema. The scanned token size is exact, while the event traversal
    is incomplete on that refusal. No process-global recursion/digit setting is
    changed. Duplicate members and nonfinite numbers keep their closed refusals.
    """
    root, have_root, frames = None, False, []
    try:
        text = raw.decode('utf-8', errors='strict') if type(raw) is bytes else raw
        if type(text) is not str:
            raise ValueError
        length, position = len(text), 0
        number_pattern = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')
        while True:
            while position < length and text[position] in ' \t\r\n':
                position += 1
            if not frames and have_root:
                if position != length:
                    raise ValueError
                return root
            frame = frames[-1] if frames else None
            state = frame[2] if frame else 'VALUE'
            if state in ('KEY_OR_END', 'KEY'):
                if state == 'KEY_OR_END' and position < length and text[position] == '}':
                    frames.pop(); position += 1; continue
                if position >= length or text[position] != '"':
                    raise ValueError
                key, position = json.decoder.scanstring(text, position + 1, True)
                if key in frame[1]:
                    raise EventJSONRefusal('plan_duplicate_json_key')
                frame[3], frame[2] = key, 'COLON'
                continue
            if state == 'COLON':
                if position >= length or text[position] != ':':
                    raise ValueError
                position += 1; frame[2] = 'VALUE'; continue
            if state == 'COMMA_OR_END':
                if position >= length:
                    raise ValueError
                closing = '}' if frame[0] == 'OBJECT' else ']'
                if text[position] == closing:
                    frames.pop(); position += 1; continue
                if text[position] != ',':
                    raise ValueError
                position += 1
                frame[2] = 'KEY' if frame[0] == 'OBJECT' else 'VALUE'
                continue
            if state == 'VALUE_OR_END' and position < length and text[position] == ']':
                frames.pop(); position += 1; continue
            if position >= length:
                raise ValueError
            char, child_kind = text[position], None
            if char == '{':
                value, child_kind = {}, 'OBJECT'; position += 1
            elif char == '[':
                value, child_kind = [], 'ARRAY'; position += 1
            elif char == '"':
                value, position = json.decoder.scanstring(text, position + 1, True)
            elif text.startswith('null', position):
                value = None; position += 4
            elif text.startswith('true', position):
                value = True; position += 4
            elif text.startswith('false', position):
                value = False; position += 5
            else:
                if any(text.startswith(token, position) for token in ('NaN', 'Infinity', '-Infinity')):
                    raise EventJSONRefusal('plan_nonfinite_json')
                match = number_pattern.match(text, position)
                if match is None:
                    raise ValueError
                token = match.group(); position = match.end()
                if '.' not in token and 'e' not in token.lower():
                    digits = len(token) - int(token.startswith('-'))
                    if digits > MAX_JSON_INTEGER_DIGITS:
                        raise EventJSONRefusal('plan_json_integer_digit_limit', partial_event=root,
                            resource=_resource('JSON_INTEGER_DIGITS', 'DECIMAL_DIGITS', digits,
                                'EXACT', MAX_JSON_INTEGER_DIGITS, False))
                    # Decimal chunks avoid dependence on an altered process-wide
                    # int-string setting; the explicit local ceiling stays fixed.
                    value, sign, digits_text = 0, -1 if token.startswith('-') else 1, token.lstrip('-')
                    for offset in range(0, len(digits_text), 9):
                        part = digits_text[offset:offset + 9]
                        value = value * (10 ** len(part)) + int(part)
                    value *= sign
                else:
                    value = float(token)
                    if not math.isfinite(value):
                        raise EventJSONRefusal('plan_nonfinite_json')
            if frame:
                if frame[0] == 'OBJECT':
                    frame[1][frame[3]] = value; frame[3] = None
                else:
                    frame[1].append(value)
                frame[2] = 'COMMA_OR_END'
            else:
                root, have_root = value, True
            if child_kind:
                frames.append([child_kind, value, 'KEY_OR_END' if child_kind == 'OBJECT' else 'VALUE_OR_END', None])
    except EventJSONRefusal:
        raise
    except (ValueError, TypeError, UnicodeError, OverflowError):
        raise EventJSONRefusal('plan_invalid_json') from None


def _integer_text(value):
    if value == 0:
        return '0'
    negative = value < 0; value = abs(value); parts = []
    while value:
        value, part = divmod(value, 1000000000); parts.append(part)
    return ('-' if negative else '') + str(parts[-1]) + ''.join(f'{part:09d}' for part in reversed(parts[:-1]))


def measure_opaque_json(value, *, limit=MAX_METADATA_BYTES):
    """Iterative canonical UTF-8 measurement/hash, stopping on byte crossing.

    Only active iterator frames and at most limit+1 output bytes are retained.
    Every frame/member/scalar has a canonical byte cost. Thus successful steps
    and stack depth are bounded by this same byte budget, without a second
    structural schema. Sorting a container is bounded by the decoded event's
    existing byte bound. A crossed count is a lower bound, never an exact size.
    """
    output, stack, active = bytearray(), [('VALUE', value)], set()
    def emit(raw):
        remaining = limit + 1 - len(output)
        output.extend(raw[:remaining])
        return len(raw) <= remaining and len(output) <= limit
    try:
        while stack:
            operation, item = stack.pop()
            if operation == 'FRAME':
                container, iterator, first = item
                try:
                    child = next(iterator)
                except StopIteration:
                    active.remove(id(container))
                    if not emit(b'}' if type(container) is dict else b']'):
                        break
                    continue
                stack.append(('FRAME', (container, iterator, False)))
                if not first and not emit(b','):
                    break
                if type(container) is dict:
                    key, child = child
                    if type(key) is not str:
                        raise ValueError
                    if not emit(json.dumps(key, ensure_ascii=False, allow_nan=False).encode('utf-8')) or not emit(b':'):
                        break
                stack.append(('VALUE', child)); continue
            if type(item) in (dict, list):
                if id(item) in active:
                    raise ValueError
                active.add(id(item))
                if not emit(b'{' if type(item) is dict else b'['):
                    break
                iterator = iter(sorted(item.items())) if type(item) is dict else iter(item)
                stack.append(('FRAME', (item, iterator, True)))
            else:
                if not (item is None or type(item) in (bool, int, float, str)):
                    raise ValueError
                encoded = _integer_text(item) if type(item) is int else json.dumps(item, ensure_ascii=False, allow_nan=False)
                if not emit(encoded.encode('utf-8')):
                    break
        else:
            raw = bytes(output)
            return dict(bytes=len(raw), sha256=_sha(raw), resource=_resource('AUXILIARY_CANONICAL_BYTES',
                'CANONICAL_UTF8_BYTES', len(raw), 'EXACT', limit, True), shape_valid=True)
        return dict(bytes=None, sha256=None, resource=_resource('AUXILIARY_CANONICAL_BYTES',
            'CANONICAL_UTF8_BYTES', len(output), 'LOWER_BOUND', limit, False), shape_valid=True)
    except (UnicodeError, ValueError, TypeError, OverflowError):
        return dict(bytes=None, sha256=None, resource=None, shape_valid=False)


def inspect_metadata_carrier(event, *, ordinal, expected_model, inspection_complete=True):
    """Separate bounded opaque resources from independently observed controls."""
    if type(event) is not dict:
        return None
    response = event.get('response')
    response_headers = response.get('headers') if type(response) is dict else None
    is_metadata = event.get('type') == 'response.metadata'
    if not (is_metadata or 'headers' in event or response_headers is not None or 'safety_buffering' in event):
        return None
    present = 'metadata' in event
    metadata = event.get('metadata')
    obj = metadata if type(metadata) is dict else {}
    unknown = {key: value for key, value in obj.items() if key not in METADATA_KEYS}
    headers = [event.get('headers'), response_headers]
    cells = {key: [] for key in METADATA_HEADERS}
    for source in headers:
        if type(source) is dict:
            for key, value in source.items():
                if type(key) is str and key.lower() in cells:
                    cells[key.lower()].append(value)
    absent = 'ABSENT' if inspection_complete else 'NOT_INSPECTED'
    categories = dict(model=absent, verification=absent, moderation=absent, buffering=absent,
        turn_state='PRESENT_OPAQUE' if cells['x-codex-turn-state'] else absent, control=absent)
    known_refusals = []
    def refuse(code):
        if code not in known_refusals:
            known_refusals.append(code)
    auxiliary = dict(metadata=metadata, headers=headers, safety_buffering=event.get('safety_buffering'))
    measured = measure_opaque_json(auxiliary)
    metadata_measured = measure_opaque_json(metadata) if present else None
    resource = measured['resource'] if inspection_complete else None
    if is_metadata and type(metadata) is not dict and inspection_complete:
        refuse('plan_metadata_shape')
    if any(source is not None and type(source) is not dict for source in headers):
        refuse('plan_metadata_shape')
    def header_strings(value):
        if type(value) is str:
            return [value]
        if type(value) is list and value and all(type(item) is str for item in value):
            return value
        return None
    for values in (cells['openai-model'], cells['x-openai-model']):
        for value in values:
            claims = header_strings(value)
            if claims is None or any(re.fullmatch(r'[A-Za-z0-9._-]{1,128}', claim) is None for claim in claims):
                if categories['model'] != 'CONFLICT':
                    categories['model'] = 'MALFORMED'
                refuse('plan_metadata_model_shape')
            elif any(claim != expected_model for claim in claims):
                categories['model'] = 'CONFLICT'; refuse('plan_metadata_model_conflict')
            elif categories['model'] in ('ABSENT', 'NOT_INSPECTED'):
                categories['model'] = 'MATCH_REQUEST'
    if is_metadata and 'openai_verification_recommendation' in obj:
        value = obj['openai_verification_recommendation']
        if type(value) is not list or not all(type(item) is str and len(item.encode('utf-8', errors='surrogatepass')) <= 128 for item in value):
            categories['verification'] = 'MALFORMED'; refuse('plan_metadata_verification_shape')
        elif 'trusted_access_for_cyber' in value:
            categories['verification'] = 'REQUIRES_UNSUPPORTED_VERIFICATION'; refuse('plan_metadata_verification_required')
        else:
            categories['verification'] = 'NO_RECOGNIZED_REQUIREMENT'
    if is_metadata and 'openai_chatgpt_moderation_metadata' in obj:
        categories['moderation'] = 'PRESENT_OPAQUE'
    buffering = []
    if 'safety_buffering' in event:
        buffering.append(event['safety_buffering'])
    if is_metadata and obj.get('type') == 'safety_buffering':
        buffering.append(obj)
    def buffering_identity(value):
        if value is None or value is False:
            return ('INACTIVE',)
        if type(value) is dict and all(type(value.get(key)) is list
                and all(type(item) is str for item in value[key]) for key in ('use_cases', 'reasons')):
            retry = value.get('retry_model')
            if retry is not None and type(retry) is not str:
                return None
            return (value['use_cases'], value['reasons'], retry)
        return None
    identities = [buffering_identity(value) for value in buffering]
    if len(identities) == 2 and all(value is not None for value in identities) and identities[0] != identities[1]:
        categories['control'] = 'CONFLICT'; refuse('plan_metadata_control_conflict')
    for value in buffering:
        if value is None or value is False:
            categories['buffering'] = 'INACTIVE'; continue
        if type(value) is not dict or any(type(value.get(key)) is not list
                or not all(type(item) is str for item in value[key]) for key in ('use_cases', 'reasons')):
            categories['buffering'] = 'MALFORMED'; refuse('plan_metadata_buffering_shape'); continue
        if value.get('retry_model') is not None:
            if type(value['retry_model']) is not str or not value['retry_model']:
                categories['buffering'] = 'MALFORMED'; refuse('plan_metadata_buffering_shape')
            else:
                categories['buffering'] = 'RETRY_MODEL_REQUESTED'
                if categories['control'] != 'CONFLICT':
                    categories['control'] = 'UNSUPPORTED'
                refuse('plan_metadata_control_not_supported')
        else:
            categories['buffering'] = 'PASSIVE_NOTIFICATION'
    if cells['x-codex-safety-buffering-faster-model']:
        if categories['control'] != 'CONFLICT':
            categories['control'] = 'UNSUPPORTED'
        refuse('plan_metadata_control_not_supported')
    if not inspection_complete:
        # A completed prefix can prove a positive conflict/requirement, but it
        # cannot prove the absence of a later claim or retry instruction.
        for key, category in tuple(categories.items()):
            if category in ('ABSENT', 'MATCH_REQUEST', 'NO_RECOGNIZED_REQUIREMENT', 'PASSIVE_NOTIFICATION', 'INACTIVE'):
                categories[key] = 'NOT_INSPECTED'
    resource_refusal = ('plan_metadata_byte_limit' if resource is not None
        and not resource['traversal_complete'] else 'plan_metadata_shape' if not measured['shape_valid'] else None)
    refusal = resource_refusal or (known_refusals[0] if known_refusals else None)
    return dict(event_ordinal=ordinal, metadata_shape=_shape(metadata, present) if present or inspection_complete else 'NOT_INSPECTED',
        metadata_bytes=metadata_measured['bytes'] if metadata_measured is not None and inspection_complete else None,
        metadata_sha256=metadata_measured['sha256'] if metadata_measured is not None and inspection_complete else None,
        auxiliary_bytes=measured['bytes'] if inspection_complete else None,
        auxiliary_sha256=measured['sha256'] if inspection_complete else None,
        known_shapes={key: _shape(obj.get(key), key in obj) if key in obj or inspection_complete
            else 'NOT_INSPECTED' for key in METADATA_KEYS},
        header_shapes={key: absent if not values else _shape(values[0]) if len(values) == 1 else 'MULTIPLE'
            for key, values in cells.items()},
        unknown_fields=dict(count=len(unknown), names_sha256=_sha(json.dumps(sorted(unknown), ensure_ascii=True,
            separators=(',', ':')).encode('ascii')), shape_counts={shape: sum(_shape(value) == shape
                for value in unknown.values()) for shape in _SHAPES}, inspection_complete=inspection_complete),
        categories=categories, refusal=refusal, resource=resource, known_refusals=known_refusals,
        known_inspection_complete=inspection_complete)


def unobserved_stream_event():
    return dict(schema=SCHEMA, observation='NOT_OBSERVED')


def observe_stream_event(name, event, raw, *, ordinal, previous_sequence, response_id, items,
                         finalized_count, counts, accepted_events, recent, json_state='PARSED', auxiliary_trace=(),
                         auxiliary_count=0, expected_model=None, decoder_resource=None):
    """Observe before dispatch or type/identity/sequence rejection."""
    obj = event if type(event) is dict else {}
    structure_scope = ('COMPLETE_EVENT' if json_state == 'PARSED' else 'PARSED_PREFIX'
        if json_state == 'DECODER_RESOURCE_REFUSED' and event is not None else 'NOT_PARSED')
    sse, kind = _name(name, name is not None), _name(obj.get('type'), 'type' in obj)
    recent = [*recent[-(RECENT_TYPE_COUNT - 1):], kind]
    relation = 'JSON_TYPE_MISSING' if kind['state'] == 'ABSENT' else 'MALFORMED' if kind['state'] != 'TOKEN' \
        or sse['state'] not in ('TOKEN', 'ABSENT') else 'SSE_NAME_ABSENT' if sse['state'] == 'ABSENT' \
        else 'MATCH' if sse['token'] == kind['token'] else 'MISMATCH'
    number = obj.get('sequence_number')
    valid_number = type(number) is int and 0 <= number <= 2**63 - 1
    response = obj.get('response')
    rid = obj.get('response_id') if 'response_id' in obj else response.get('id') if type(response) is dict else None
    index, item_id = obj.get('output_index'), obj.get('item_id')
    if item_id is None and type(obj.get('item')) is dict:
        item_id = obj['item'].get('id')
    known_item = items.get(index) if type(index) is int else None
    response_relation = 'ABSENT' if rid is None else 'MALFORMED' if type(rid) is not str else \
        'CURRENT_NOT_CREATED' if response_id is None else 'MATCH' if rid == response_id else 'MISMATCH'
    item_relation = 'ABSENT' if item_id is None else 'MALFORMED' if type(item_id) is not str else \
        'NOT_REGISTERED' if known_item is None else 'MATCH' if known_item[0] == item_id else 'MISMATCH'
    unknown = {key: value for key, value in obj.items() if key not in _FIELDS}
    shapes = {shape: sum(_shape(value) == shape for value in unknown.values()) for shape in _SHAPES}
    auxiliary = inspect_metadata_carrier(event, ordinal=ordinal, expected_model=expected_model,
        inspection_complete=json_state == 'PARSED') if json_state in ('PARSED', 'DECODER_RESOURCE_REFUSED') else None
    observation = dict(schema=SCHEMA, observation='OBSERVED', event_ordinal=ordinal,
        sse_name=sse, json_type=kind, name_type_relation=relation, json_state=json_state,
        json_root_shape=_shape(event) if structure_scope != 'NOT_PARSED' else 'NOT_PARSED',
        structure_scope=structure_scope,
        payload=dict(bytes=len(raw), sha256=_sha(raw)),
        sequence=dict(shape=_shape(number, 'sequence_number' in obj), value=number if valid_number else None,
            relation='INCREASING' if valid_number and number > previous_sequence else 'NOT_INCREASING'
                if valid_number else 'MALFORMED'),
        parser_state=dict(phase='BEFORE_RESPONSE' if response_id is None else 'ACTIVE',
            accepted_events=accepted_events, item_count=len(items), finalized_count=finalized_count,
            **{key: counts.get(key, 0) for key in _COUNT_KEYS if key not in ('accepted_events', 'item_count', 'finalized_count')}),
        links=dict(response_relation=response_relation,
            response_id_sha256=_sha(rid.encode('utf-8', errors='surrogatepass')) if type(rid) is str else None,
            item_relation=item_relation,
            item_id_sha256=_sha(item_id.encode('utf-8', errors='surrogatepass')) if type(item_id) is str else None,
            **{key: obj[key] if type(obj.get(key)) is int and 0 <= obj[key] < 64 else None
                for key in ('output_index', 'content_index', 'summary_index', 'annotation_index')}),
        field_shapes={key: _shape(obj.get(key), key in obj) if key in obj or structure_scope != 'PARSED_PREFIX'
            else 'NOT_INSPECTED' for key in _FIELDS},
        unknown_fields=dict(count=len(unknown), names_sha256=_sha(json.dumps(sorted(unknown), ensure_ascii=True,
            separators=(',', ':')).encode('ascii')), shape_counts=shapes, inspection_complete=json_state == 'PARSED'),
        recent_types=recent, disposition='OBSERVED_PREDISPATCH', transport_binding=None, decoder_resource=decoder_resource,
        auxiliary_count=auxiliary_count + int(auxiliary is not None),
        auxiliary_trace=[*list(auxiliary_trace)[-1:], auxiliary] if auxiliary is not None else list(auxiliary_trace))
    return observation



def bind_stream_event(value, *, reservation_id, source_identity_sha256, context_sha256, body_sha256, response_id):
    result = project_stream_event(value)
    if result is None or result['observation'] == 'NOT_OBSERVED':
        return result
    result['transport_binding'] = dict(reservation_id=reservation_id, source_identity_sha256=source_identity_sha256,
        context_sha256=context_sha256, body_sha256=body_sha256,
        response_id_sha256=_sha(response_id.encode('ascii')) if type(response_id) is str
            and response_id != 'UNKNOWN' and _ID.fullmatch(response_id) else None)
    return project_stream_event(result)
