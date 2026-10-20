"""Finite temporal policy for new owned informational material.

These application horizons create no effect permission. Historical clocks are
inputs to a minimum, never anchors for a newly extended window. Import is inert.
"""
from datetime import datetime, timedelta


TEMPORAL_POLICY_VERSION = 'radik.dynamic.temporal.v01'
INFORMATION_HORIZON_SECONDS = 10800
REUSE_WINDOW_SECONDS = 7200
_MAX_UTC_EPOCH_SECONDS = 253402300799


def _valid_to(created_at, seconds, earlier_caps):
    values = (created_at, *earlier_caps)
    if any(type(value) is not int or not 0 <= value <= _MAX_UTC_EPOCH_SECONDS for value in values) \
            or created_at + seconds > _MAX_UTC_EPOCH_SECONDS:
        raise ValueError('dynamic_temporal_policy_input')
    return min(created_at + seconds, *earlier_caps) if earlier_caps else created_at + seconds


def informational_valid_to(created_at, *earlier_caps):
    """Bound a new informational projection by every earlier applicable cap."""
    return _valid_to(created_at, INFORMATION_HORIZON_SECONDS, earlier_caps)


def reuse_valid_to(accepted_at, *earlier_caps):
    """Preserve an original acceptance anchor and all narrower expiry limits."""
    return _valid_to(accepted_at, REUSE_WINDOW_SECONDS, earlier_caps)


def utc_epoch_seconds(value):
    """Read an exact whole-second UTC bound from an actual native envelope."""
    try:
        if type(value) is not str:
            raise ValueError
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0) or parsed.microsecond:
            raise ValueError
        epoch = int(parsed.timestamp())
        if not 0 <= epoch <= _MAX_UTC_EPOCH_SECONDS:
            raise ValueError
        return epoch
    except (ValueError, TypeError, OverflowError, OSError):
        raise ValueError('dynamic_temporal_policy_input') from None
