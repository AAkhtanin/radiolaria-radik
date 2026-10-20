"""Optional owning-operation measurements; no validation result or authority."""
from contextvars import ContextVar

_COLLECTOR = ContextVar('native_validation_cost_collector_v01',default=None)
LABELS = frozenset(('D_BUNDLE_VALIDATE','D_BUNDLE_PLAIN','D_SOURCE_VALIDATE','INFO_BASELINE',
    'INFO_CARRIER','INFO_ORIGIN','INFO_CURRENT_ROOT','HOST_CAPTURE_VALIDATE',
    'E_SOURCE_REASON','E_INFORMATIONAL_CONTEXT','E_TEMPORAL_CONTEXT','D_RETAINED_COMPLETE_VALIDATE'))


def activate_diagnostic_telemetry_v01(collector):
    return _COLLECTOR.set(collector)


def reset_diagnostic_telemetry_v01(token):
    _COLLECTOR.reset(token)


def _secondary(collector,code,*,preserve_primary=False):
    try:collector.secondary(code)
    except Exception:pass
    except BaseException:
        if not preserve_primary:raise


class _DiagnosticSpanV01:
    def __init__(self,label,value):
        self.collector=_COLLECTOR.get();self.label=label;self.value=value;self.ticket=None

    def __enter__(self):
        if self.collector is not None:
            try:self.ticket=self.collector.enter(self.label,self.value)
            except Exception:_secondary(self.collector,'TELEMETRY_SPAN_FAILED')
        self.value=None
        return None

    def __exit__(self,error_type,_error,_traceback):
        if self.collector is not None:
            try:self.collector.exit(self.ticket,error_type is not None)
            except Exception:_secondary(self.collector,'TELEMETRY_SPAN_FAILED',
                preserve_primary=error_type is not None)
            except BaseException:
                if error_type is None:raise
                # Preserve the exact already-unwinding business primary. A new
                # interruption outside cleanup remains a primary interruption.
                try:self.collector.secondary('TELEMETRY_INTERRUPTED_WHILE_UNWINDING')
                except BaseException:pass
        return False


def diagnostic_span_v01(label,value):
    return _DiagnosticSpanV01(label,value)


class _DiagnosticPhaseV01:
    def __init__(self,stage):
        self.collector=_COLLECTOR.get();self.stage=stage;self.ticket=None
    def __enter__(self):
        if self.collector is not None:
            try:self.ticket=self.collector.semantic_enter(self.stage)
            except Exception:_secondary(self.collector,'TELEMETRY_SPAN_FAILED')
        return None
    def __exit__(self,error_type,_error,_traceback):
        if self.collector is not None:
            try:self.collector.semantic_exit(self.ticket,error_type is not None)
            except Exception:_secondary(self.collector,'TELEMETRY_SPAN_FAILED',preserve_primary=error_type is not None)
            except BaseException:
                if error_type is None:raise
                try:self.collector.secondary('TELEMETRY_INTERRUPTED_WHILE_UNWINDING')
                except BaseException:pass
        return False


def diagnostic_phase_v01(stage):
    return _DiagnosticPhaseV01(stage)


def diagnostic_consumer_v01(kind,factory):
    collector=_COLLECTOR.get()
    if collector is None:return
    try:collector.produced(kind,factory)
    except Exception:_secondary(collector,'TELEMETRY_PASSIVE_FAILED')


def diagnostic_progress_v01(kind,factory):
    """Observe only actual producer completions; no deferred live-object retention."""
    collector=_COLLECTOR.get()
    if collector is None:return
    try:collector.progress(kind,factory)
    except Exception:_secondary(collector,'TELEMETRY_PROGRESS_FAILED')


def diagnostic_report_v01(kind,factory):
    """Immediately project a selected produced report; no report is authority."""
    collector=_COLLECTOR.get()
    if collector is None:return
    try:collector.reported(kind,factory)
    except Exception:_secondary(collector,'TELEMETRY_PASSIVE_FAILED')


def diagnostic_report_return_v01(kind,value,factory):
    """Observe the exact existing return once, then preserve its object identity."""
    diagnostic_report_v01(kind,lambda:factory(value))
    return value
