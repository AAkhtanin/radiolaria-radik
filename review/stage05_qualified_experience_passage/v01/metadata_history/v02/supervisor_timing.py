"""Stage05 finite clock and exact-child event protocol for one owner operation.

This module is stdlib-only. Importing it creates no operation, file, timer thread,
application object, model call, native call, authorization or execution admission.
"""
import json
import os
import re
import time


SCHEMA = 'radik.p28.owner_event.v01'
EMERGENCY_IO_EXIT = 86
LIMITS = dict(operation_seconds=2400, native_seconds=300,
    early_checkpoint_seconds=600, semantic_idle_seconds=900, cleanup_seconds=30,
    interrupt_grace_seconds=10, terminate_grace_seconds=5, kill_wait_seconds=5,
    poll_seconds=0.05, status_seconds=30, event_rows=8192, event_row_bytes=65536,
    stdout_bytes=33554432, evidence_bytes=67108864, receipt_bytes=4194304,
    input_bytes=67108864, input_count=1024)
PHASES = frozenset(('BOOTSTRAP', 'SETUP', 'INTAKE', 'PROVIDER', 'NATIVE', 'E',
    'PERSISTENCE', 'FINALIZATION'))
KINDS = frozenset(('PHASE_ENTER', 'PHASE_EXIT', 'E_ENTER', 'E_EXIT',
    'REPORT_READBACK_ACK', 'STATUS', 'HEARTBEAT', 'PRIMARY_FAILURE',
    'REQUIRED_WITNESS_UNAVAILABLE', 'FINAL'))
NS = 1000000000


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def token(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_:./-]{1,256}', value),
        'terminal_event_token')
    return value


def failure(value):
    """Only closed diagnostic identifiers enter Terminal; full raw evidence stays raw."""
    require(type(value) is dict and set(value) == {'phase', 'error_class', 'code'},
        'terminal_failure_shape')
    return {key: token(value[key]) for key in ('phase', 'error_class', 'code')}


def fallback(code, error_class='ProtocolIntegrityError', phase='OWNER_TERMINAL'):
    return dict(phase=token(phase), error_class=token(error_class), code=token(code))


def validate_operation_clock(*, started_ns, deadline_ns, started_utc):
    """Validate inherited elapsed time against real UTC without creating authority."""
    now_ns = time.monotonic_ns()
    now_utc = time.time()
    require(type(started_ns) is int and type(deadline_ns) is int
        and type(started_utc) is int and started_utc > 0
        and deadline_ns == started_ns + LIMITS['operation_seconds'] * NS
        and started_ns <= now_ns < deadline_ns
        and abs((now_utc-started_utc) - (now_ns-started_ns)/NS) <= 5,
        'terminal_inherited_real_time_boundary')
    return dict(operation_started_ns=started_ns, operation_deadline_ns=deadline_ns,
        operation_started_utc=started_utc, observed_monotonic_ns=now_ns,
        observed_utc=now_utc)


def event_shape(row, *, child_pid, run_binding, operation_started_ns):
    require(type(row) is dict and row.get('schema') == SCHEMA
        and row.get('child_pid') == child_pid and row.get('run_binding') == run_binding
        and row.get('operation_started_ns') == operation_started_ns,
        'terminal_event_binding')
    require(type(row.get('sequence')) is int and row['sequence'] > 0
        and row.get('kind') in KINDS and row.get('phase') in PHASES,
        'terminal_event_shape')
    require(all(type(row.get(key)) is int and row[key] >= 0 for key in
        ('at_monotonic_ns', 'elapsed_wall_ns', 'elapsed_process_cpu_ns',
            'elapsed_main_thread_cpu_ns')), 'terminal_event_clocks')
    require(row['elapsed_wall_ns'] == row['at_monotonic_ns'] - operation_started_ns,
        'terminal_event_operation_clock_reset')
    return row


class Deadline:
    """One nonrenewable operation clock; native spans accumulate across all phases.

    Native time is the union of explicitly entered native intervals. It never
    restarts at E. Early-checkpoint and semantic-idle clocks exist only inside
    the single evidenced E invocation. Parent observation time grants progress;
    child elapsed clocks and liveness never grant it.
    """
    def __init__(self, started_ns, *, limits=None):
        require(type(started_ns) is int and started_ns >= 0, 'terminal_start_clock')
        self.limits = dict(LIMITS if limits is None else limits)
        self.started_ns = started_ns
        self.deadline_ns = started_ns + int(self.limits['operation_seconds'] * NS)
        self.phase = 'BOOTSTRAP'
        self.native_spans = set()
        self.native_since_ns = None
        self.native_elapsed_ns = 0
        self.provider_span = None
        self.last_event_ns = started_ns
        self.e_call_id = None
        self.e_entered_ns = None
        self.e_exited_ns = None
        self.first_checkpoint_ns = None
        self.last_useful_ns = None
        self.last_useful_identity = None
        self.stop_ns = None
        self.reason = None
        self.terminate_ns = None
        self.kill_ns = None

    def native_used_ns(self, now_ns):
        return self.native_elapsed_ns + (0 if self.native_since_ns is None else
            max(0, now_ns - self.native_since_ns))

    def event(self, row, *, observed_ns, readback_verified=False):
        require(self.started_ns <= row['at_monotonic_ns'] <= observed_ns
            and row['at_monotonic_ns'] >= self.last_event_ns,
            'terminal_event_time_order')
        at = row['at_monotonic_ns']
        self.last_event_ns = at
        kind = row['kind']
        if self.stop_ns is not None:
            return False
        if kind in ('PHASE_ENTER', 'PHASE_EXIT'):
            native = row.get('native')
            require(type(native) is bool, 'terminal_native_scope_flag')
            span = token(row.get('span_id'))
            if row['phase'] == 'PROVIDER':
                require(not native and (self.e_entered_ns is None or
                    self.e_exited_ns is not None),
                    'terminal_provider_inside_e_refused')
                if kind == 'PHASE_ENTER':
                    require(self.provider_span is None, 'terminal_overlapping_provider')
                    self.provider_span = span
                    if self.native_since_ns is not None:
                        self.native_elapsed_ns += at - self.native_since_ns
                        self.native_since_ns = None
                else:
                    require(self.provider_span == span, 'terminal_provider_exit_binding')
                    self.provider_span = None
                    if self.native_spans:
                        self.native_since_ns = at
                self.phase = row['phase'] if kind == 'PHASE_ENTER' else 'NATIVE'
                return False
            if kind == 'PHASE_ENTER':
                require(span not in self.native_spans, 'terminal_duplicate_native_span')
                if native:
                    require(self.provider_span is None, 'terminal_native_during_provider')
                    require(row['phase'] in ('NATIVE', 'E'), 'terminal_native_phase')
                    if not self.native_spans:
                        self.native_since_ns = at
                    self.native_spans.add(span)
                self.phase = row['phase']
            elif native:
                require(span in self.native_spans, 'terminal_unknown_native_span')
                self.native_spans.remove(span)
                if not self.native_spans:
                    require(self.provider_span is None, 'terminal_native_exit_during_provider')
                    self.native_elapsed_ns += at - self.native_since_ns
                    self.native_since_ns = None
        elif kind == 'E_ENTER':
            require(self.e_entered_ns is None and row['phase'] == 'E'
                and readback_verified and self.native_spans,
                'terminal_e_entry_requires_native_and_capture_readback')
            self.e_call_id = token(row.get('e_call_id'))
            self.e_entered_ns = at
            self.last_useful_ns = at
            self.phase = 'E'
        elif kind == 'E_EXIT':
            require(self.e_entered_ns is not None and self.e_exited_ns is None
                and row.get('e_call_id') == self.e_call_id and row['phase'] == 'E',
                'terminal_e_exit_binding')
            self.e_exited_ns = at
        elif kind == 'REPORT_READBACK_ACK':
            useful = row.get('useful')
            require(type(useful) is bool, 'terminal_useful_readback_flag')
            if useful:
                require(row['phase'] == 'E' and self.e_entered_ns is not None
                    and self.e_exited_ns is None and row.get('e_call_id') == self.e_call_id
                    and readback_verified, 'terminal_useful_e_readback_binding')
                # A late readback never rescues an already expired boundary.
                early = self.e_entered_ns + int(self.limits['early_checkpoint_seconds'] * NS)
                idle = self.last_useful_ns + int(self.limits['semantic_idle_seconds'] * NS)
                if (self.first_checkpoint_ns is None and observed_ns >= early) or observed_ns >= idle:
                    return False
                self.first_checkpoint_ns = self.first_checkpoint_ns or observed_ns
                self.last_useful_ns = observed_ns
                self.last_useful_identity = dict(report_kind=token(row.get('report_kind')),
                    readback_ref=dict(row['readback_ref']), sequence=row['sequence'])
                return True
        return False

    def due_reason(self, now_ns):
        require(type(now_ns) is int and now_ns >= self.started_ns,
            'terminal_parent_clock')
        if now_ns >= self.deadline_ns:
            return 'OPERATION_LIMIT'
        if self.native_used_ns(now_ns) >= int(self.limits['native_seconds'] * NS):
            return 'CUMULATIVE_NATIVE_LIMIT'
        if self.e_entered_ns is not None and self.e_exited_ns is None:
            if self.first_checkpoint_ns is None and now_ns - self.e_entered_ns >= \
                    int(self.limits['early_checkpoint_seconds'] * NS):
                return 'E_EARLY_CHECKPOINT_TIMEOUT'
            if now_ns - self.last_useful_ns >= int(self.limits['semantic_idle_seconds'] * NS):
                return 'E_SEMANTIC_IDLE_LIMIT'
        return None

    def action(self, now_ns, *, owner_interrupt=False, monitor_failure=False,
            required_failure=False, emergency_failure=False):
        if self.stop_ns is None:
            reason = ('REQUIRED_WITNESS_UNAVAILABLE' if required_failure else
                'REQUIRED_WITNESS_CHANNEL_IO_FAILED' if emergency_failure else
                'MONITOR_FAILURE' if monitor_failure else
                'OWNER_INTERRUPT' if owner_interrupt else self.due_reason(now_ns))
            if reason is not None:
                self.reason, self.stop_ns = reason, now_ns
                return 'INTERRUPT'
        elif self.terminate_ns is None and now_ns - self.stop_ns >= \
                int(self.limits['interrupt_grace_seconds'] * NS):
            self.terminate_ns = now_ns
            return 'TERMINATE'
        elif self.terminate_ns is not None and self.kill_ns is None and now_ns - self.terminate_ns >= \
                int(self.limits['terminate_grace_seconds'] * NS):
            self.kill_ns = now_ns
            return 'KILL'
        return None

    def measurement(self, now_ns):
        return dict(clock='SHARED_HOST_MONOTONIC_NS', started_ns=self.started_ns,
            deadline_ns=self.deadline_ns, elapsed_wall_ns=now_ns-self.started_ns,
            native_elapsed_ns=self.native_used_ns(now_ns), phase=self.phase,
            open_native_spans=sorted(self.native_spans), provider_span=self.provider_span,
            e_call_id=self.e_call_id,
            e_entered_ns=self.e_entered_ns, e_exited_ns=self.e_exited_ns,
            first_checkpoint_ns=self.first_checkpoint_ns,
            last_useful_ns=self.last_useful_ns, last_useful_identity=self.last_useful_identity,
            stop_ns=self.stop_ns, stop_reason=self.reason,
            heartbeat_status_cpu_counter_credit=False)


class EventWriter:
    """Small pinned bridge, installed only after source admission in the child.

    Hooks call this bridge at actual call boundaries. It does not wrap a model,
    choose a route, perform readbacks, accept native results or mint authority.
    """
    def __init__(self, *, started_ns, deadline_ns, run_binding, child_pid=None,
            write=None, emergency_exit=None):
        require(type(started_ns) is int and type(deadline_ns) is int
            and deadline_ns == started_ns + LIMITS['operation_seconds'] * NS
            and started_ns <= time.monotonic_ns() < deadline_ns,
            'terminal_inherited_operation_clock')
        require(type(run_binding) is str and re.fullmatch('[0-9a-f]{64}', run_binding),
            'terminal_run_binding')
        self.started_ns, self.deadline_ns = started_ns, deadline_ns
        self.run_binding, self.pid = run_binding, os.getpid() if child_pid is None else child_pid
        require(self.pid == os.getpid(), 'terminal_writer_own_child')
        self.sequence = 0
        # These OS CPU clocks already measure the child's lifetime, including
        # earlier bootstrap/exec work. A newly attached bridge must not reset it.
        self.cpu_started_ns = 0
        self.thread_started_ns = 0
        self.write = (lambda raw: os.write(1, raw)) if write is None else write
        self.emergency_exit = os._exit if emergency_exit is None else emergency_exit

    def emit(self, kind, phase, **details):
        require(kind in KINDS and phase in PHASES, 'terminal_writer_closed_event')
        now = time.monotonic_ns()
        require(now < self.deadline_ns or kind in ('PRIMARY_FAILURE',
            'REQUIRED_WITNESS_UNAVAILABLE', 'FINAL'), 'terminal_operation_deadline')
        self.sequence += 1
        row = dict(schema=SCHEMA, child_pid=self.pid, run_binding=self.run_binding,
            operation_started_ns=self.started_ns, sequence=self.sequence,
            kind=kind, phase=phase, at_monotonic_ns=now,
            elapsed_wall_ns=now-self.started_ns,
            elapsed_process_cpu_ns=time.process_time_ns()-self.cpu_started_ns,
            elapsed_main_thread_cpu_ns=time.thread_time_ns()-self.thread_started_ns)
        require(not set(details).intersection(row), 'terminal_writer_reserved_field')
        row.update(details)
        raw = canonical(row) + b'\n'
        require(len(raw) <= LIMITS['event_row_bytes'], 'terminal_writer_event_bound')
        try:
            offset = 0
            while offset < len(raw):
                written = self.write(raw[offset:])
                require(type(written) is int and 0 < written <= len(raw)-offset,
                    'terminal_writer_short_write')
                offset += written
        except BaseException:
            # The exit code is an independent fail-closed emergency channel.
            self.emergency_exit(EMERGENCY_IO_EXIT)
            raise RuntimeError('terminal_emergency_exit_returned') from None
        return row


class CleanupBoundary:
    """One saved stop instant and one signal ledger across every cleanup path.

    A second exception may request cleanup again but cannot restart its clock
    or resend an action already issued to the exact child.
    """
    def __init__(self, *, started_ns, limits):
        self.started_ns = started_ns
        self.limits = dict(limits)
        self.stop_ns = None
        self.signals = []
        self.entries = 0

    def begin(self, now_ns, *, known_stop_ns=None):
        require(type(now_ns) is int and now_ns >= self.started_ns,
            'terminal_cleanup_clock')
        if self.stop_ns is None:
            self.stop_ns = now_ns if known_stop_ns is None else known_stop_ns
            require(type(self.stop_ns) is int and self.started_ns <= self.stop_ns <= now_ns,
                'terminal_cleanup_saved_stop')
        self.entries += 1
        return self.stop_ns

    def end_ns(self):
        require(self.stop_ns is not None, 'terminal_cleanup_not_started')
        seconds = min(self.limits['cleanup_seconds'],
            self.limits['interrupt_grace_seconds'] +
            self.limits['terminate_grace_seconds'] + self.limits['kill_wait_seconds'])
        return self.stop_ns + int(seconds * NS)

    def record_signal(self, action, now_ns):
        require(action in ('INTERRUPT', 'TERMINATE', 'KILL'), 'terminal_cleanup_action')
        if any(row['action'] == action for row in self.signals):
            return False
        self.signals.append(dict(action=action, elapsed_wall_ns=now_ns-self.started_ns))
        return True

    def measurement(self):
        return dict(stop_ns=self.stop_ns, end_ns=None if self.stop_ns is None else self.end_ns(),
            entries=self.entries, signals=list(self.signals), clock_renewal_allowed=False)
