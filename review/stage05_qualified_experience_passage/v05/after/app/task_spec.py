"""Finite user intent and immutable task identity, without inference or I/O."""
from dataclasses import asdict, dataclass
import re
import unicodedata

from .contracts import canonical, digest, require

TASK_VERSION = 'radik.dynamic.task.v01'
PROFILES = ('compare', 'explain', 'verify')
MAX_SOURCES = 4
TASK_ID = re.compile(r'radik-task:[0-9a-f]{32}\Z')
SOURCE_ID = re.compile(r'radik:source:[0-9a-f]{32}\Z')


def normalized_text(value):
    require(type(value) is str, 'task_text_type')
    return ' '.join(unicodedata.normalize('NFC', value).split())


def _text(value, maximum, code):
    require(type(value) is str and bool(value.strip()) and '\x00' not in value
        and len(value.encode('utf-8')) <= maximum, code)


@dataclass(frozen=True)
class TaskSpec:
    version: str
    task_id: str
    profile: str
    goal: str
    criterion: str
    topic: str
    source_ids: tuple
    resource_scope: tuple
    supplied_candidate: object
    predecessor_task_id: object
    created_at: int

    def __post_init__(self):
        require(self.version == TASK_VERSION and type(self.task_id) is str
            and TASK_ID.fullmatch(self.task_id) is not None, 'task_identity')
        require(self.profile in PROFILES, 'task_profile')
        _text(self.goal, 2048, 'task_goal')
        _text(self.criterion, 2048, 'task_criterion')
        _text(self.topic, 160, 'task_topic')
        for values in (self.source_ids, self.resource_scope):
            require(type(values) is tuple and 1 <= len(values) <= MAX_SOURCES
                and len(set(values)) == len(values)
                and all(type(item) is str and SOURCE_ID.fullmatch(item) is not None
                    for item in values), 'task_source_scope')
        require(set(self.source_ids) <= set(self.resource_scope), 'task_resource_scope')
        if self.profile == 'verify':
            _text(self.supplied_candidate, 4096, 'task_supplied_candidate')
        else:
            require(self.supplied_candidate is None, 'task_unexpected_candidate')
        require(self.predecessor_task_id is None or type(self.predecessor_task_id) is str
            and TASK_ID.fullmatch(self.predecessor_task_id) is not None
            and self.predecessor_task_id != self.task_id, 'task_predecessor')
        require(type(self.created_at) is int and self.created_at >= 0, 'task_created_at')

    def plain(self):
        value = asdict(self)
        value['source_ids'] = list(self.source_ids)
        value['resource_scope'] = list(self.resource_scope)
        return value

    @classmethod
    def from_plain(cls, value):
        require(type(value) is dict and set(value) == set(cls.__dataclass_fields__), 'task_plain_shape')
        require(type(value['source_ids']) is list and type(value['resource_scope']) is list,
            'task_plain_sources')
        fields = dict(value, source_ids=tuple(value['source_ids']), resource_scope=tuple(value['resource_scope']))
        return cls(**fields)


def meaning_scope(spec, sources):
    """Bind meaning to current source revisions, independently of task identity."""
    require(type(spec) is TaskSpec and type(sources) in (list, tuple), 'task_meaning_shape')
    rows = []
    for source in sources:
        require(type(source) is dict and all(key in source for key in ('source_ref', 'revision', 'sha256')),
            'task_meaning_source_shape')
        require(source['source_ref'] in spec.source_ids and type(source['revision']) is int
            and source['revision'] >= 1 and type(source['sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', source['sha256']) is not None,
            'task_meaning_source_binding')
        rows.append({key: source[key] for key in ('source_ref', 'revision', 'sha256')})
    require(len(rows) == len(spec.source_ids) and len({row['source_ref'] for row in rows}) == len(rows),
        'task_meaning_source_inventory')
    return {'version': 'radik.dynamic.meaning.v01', 'profile': spec.profile,
        'goal': normalized_text(spec.goal), 'criterion': normalized_text(spec.criterion),
        'topic': normalized_text(spec.topic), 'supplied_candidate_sha256': None if spec.supplied_candidate is None
            else digest(spec.supplied_candidate.encode('utf-8')),
        'sources': sorted(rows, key=lambda row: row['source_ref'])}


def meaning_key(spec, sources):
    return digest(canonical(meaning_scope(spec, sources)))


def classify_intent(text):
    """Recognize finite informational intents; ambiguity requires clarification."""
    _text(text, 2048, 'task_goal')
    value = normalized_text(text).casefold()
    patterns = {'compare': r'\b(compare|comparison|contrast)\b|сравн|сопостав',
        'explain': r'\b(explain|summari[sz]e|describe)\b|объясн|разъясн|поясн|опиши|расскаж',
        'verify': r'\b(verify|check|validate|is it true)\b|проверь|проверить|верно ли|подтверд'}
    found = tuple(profile for profile in PROFILES if re.search(patterns[profile], value))
    return found[0] if len(found) == 1 else None
