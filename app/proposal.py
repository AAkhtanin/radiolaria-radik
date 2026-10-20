"""Provider-neutral semantic observation; proposal material confers no authority."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ProposalObservation:
    value: object
    context_sha256: str
    response_id: str
    reservation_id: str
    requested_model: str
    resolved_model: str
    served_model: str
    requested_effort: str
    resolved_effort: str
    speed_tier: str
    outcome: str
    usage: object
    wall_seconds: float
    requested_service_tier: str = 'default'
    service_tier_basis: str = 'RETURNED_RESPONSE_TELEMETRY_OR_UNKNOWN'
    wire_body_sha256: str = ''
    transport_version: str = ''
    catalog_receipt_sha256: str = ''
    provider_output_token_cap: str = 'UNKNOWN_UNSUPPORTED_BY_PLAN_HTTP_ROUTE'
