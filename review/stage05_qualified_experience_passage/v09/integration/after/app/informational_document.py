"""Legacy two-source bridge to the common informational preparation component."""
from .informational_core import (InformationalDocumentSource, InformationalOriginLink,
    validate_source_inputs_v26, validate_source_outputs_v26, execute_source_digest_v26,
    admit_source_digest, source_payload, caps_for_task, _artifact, prepare_origin,
    validate_link, validate_update_sources, capture_current, validate_consumption_boundary,
    require_no_effects, require_publication, publication_readback, require_family_profile)
from . import informational_core as core
from . import document_temporal as temporal


def delta_arguments(task,updated,changed_index):
    from .native_document import informational_delta_family
    state,updated,capture,observed,invalidation=core.prepare_delta_components(task,updated,changed_index)
    return informational_delta_family(task,updated,changed_index,state,capture,observed,invalidation)
