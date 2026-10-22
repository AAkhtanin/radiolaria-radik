"""Stage06 adapter for the accepted Stage05 clock and exact-child cleanup code.

The original sources remain unchanged. Each process has a native-span clock;
the supervisor retains their Work subtotals and conservatively budgets every
peer incarnation wall interval, including native validation and waiting time.
A verified Stage06 receipt advances the early/idle boundary without claiming E.
"""
import hashlib
from pathlib import Path
import time
import types

PREFIX = 'review/stage05_qualified_experience_passage/v09/integration/'
PRIMITIVES = {
    'supervisor_timing.py': '2f793adecf280708d585b4ee5e3bb751056f1679e3e18b056fb521d73098d3af',
    'owner_terminal.py': '81a0834702f6469d5794e5ee0b7b571381ef3a5366982d7757920789d7df1fb1',
}


def require(value, code):
    if not value:
        raise ValueError(code)


def load_primitives(project):
    """Pin both stdlib-only sources before compiling either accepted primitive."""
    project = Path(project)
    sources = {}
    for filename, digest in PRIMITIVES.items():
        path = project/(PREFIX+filename)
        for ancestor in (path, *path.parents):
            require(not ancestor.is_symlink(), 'stage06_timing_symlink')
            if ancestor == project:
                break
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == digest, 'stage06_timing_source_changed')
        sources[filename] = (path, raw)
    modules = {}
    for filename, (path, raw) in sources.items():
        module = types.ModuleType('stage06_accepted_'+filename[:-3])
        module.__file__ = str(path)
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        modules[filename] = module
    return modules['supervisor_timing.py'], modules['owner_terminal.py']


class OperationClock:
    """Bound the same operation across concurrent peers and a reaped restart."""
    def __init__(self, timing, *, started_ns, limits):
        self.timing = timing
        self.started_ns = started_ns
        self.limits = dict(limits)
        self.deadline_ns = started_ns + int(limits['operation_seconds']*10**9)
        self.process_clocks = {}
        self.peer_intervals = {}
        self.first_native_ns = None
        self.first_checkpoint_ns = None
        self.last_checkpoint_ns = None
        self.last_checkpoint = None
        self.stop_ns = None
        self.stop_reason = None
        self.cleanup = timing.CleanupBoundary(started_ns=started_ns, limits=limits)

    def attach(self, name):
        require(name not in self.process_clocks, 'stage06_duplicate_child_clock')
        self.process_clocks[name] = self.timing.Deadline(self.started_ns, limits=self.limits)
        self.peer_intervals[name] = dict(started_ns=time.monotonic_ns(), ended_ns=None)

    def closed(self, name):
        interval = self.peer_intervals[name]
        if interval['ended_ns'] is None:
            interval['ended_ns'] = time.monotonic_ns()

    def native_event(self, name, *, entering, span_id, at_ns, observed_ns):
        require(self.started_ns <= at_ns <= observed_ns, 'stage06_native_event_clock')
        row = dict(kind='PHASE_ENTER' if entering else 'PHASE_EXIT', phase='NATIVE',
            native=True, span_id=span_id, at_monotonic_ns=at_ns)
        self.process_clocks[name].event(row, observed_ns=observed_ns)
        if entering and self.first_native_ns is None:
            self.first_native_ns = observed_ns

    def checkpoint(self, *, label, reference, observed_ns):
        # Readback verification is performed by the caller before this method.
        if self.due_reason(observed_ns) is not None:
            return False
        self.first_checkpoint_ns = self.first_checkpoint_ns or observed_ns
        self.last_checkpoint_ns = observed_ns
        self.last_checkpoint = dict(label=label, reference=dict(reference))
        return True

    def native_ns(self, now_ns):
        # This conservative upper bound includes Root, DRS, signature validation,
        # setup and IPC waits; the Work-only subtotal is reported separately.
        return sum(max(0, (row['ended_ns'] or now_ns)-row['started_ns'])
            for row in self.peer_intervals.values())

    def due_reason(self, now_ns):
        require(now_ns >= self.started_ns, 'stage06_operation_clock')
        if now_ns >= self.deadline_ns:
            return 'STAGE06_OPERATION_LIMIT'
        if self.native_ns(now_ns) >= int(self.limits['native_seconds']*10**9):
            return 'STAGE06_NATIVE_LIMIT'
        if self.first_native_ns is not None:
            if self.first_checkpoint_ns is None and now_ns-self.first_native_ns >= \
                    int(self.limits['early_checkpoint_seconds']*10**9):
                return 'STAGE06_EARLY_CHECKPOINT_TIMEOUT'
            since = self.last_checkpoint_ns or self.first_native_ns
            if now_ns-since >= int(self.limits['semantic_idle_seconds']*10**9):
                return 'STAGE06_SEMANTIC_IDLE_LIMIT'
        return None

    def stop(self, reason, now_ns=None):
        now_ns = time.monotonic_ns() if now_ns is None else now_ns
        if self.stop_ns is None:
            self.stop_ns, self.stop_reason = now_ns, reason
        self.cleanup.begin(now_ns, known_stop_ns=self.stop_ns)
        return self.stop_ns

    def measurement(self, now_ns):
        return dict(clock='SHARED_HOST_MONOTONIC_NS', started_ns=self.started_ns,
            deadline_ns=self.deadline_ns, elapsed_wall_ns=now_ns-self.started_ns,
            conservative_native_upper_bound_ns=self.native_ns(now_ns),
            observed_host_work_span_ns=sum(clock.native_used_ns(now_ns)
                for clock in self.process_clocks.values()),
            peer_wall_intervals=self.peer_intervals,
            process_clocks={name: clock.measurement(now_ns)
                for name, clock in self.process_clocks.items()},
            first_native_ns=self.first_native_ns, first_checkpoint_ns=self.first_checkpoint_ns,
            last_checkpoint_ns=self.last_checkpoint_ns, last_checkpoint=self.last_checkpoint,
            stop_ns=self.stop_ns, stop_reason=self.stop_reason,
            heartbeat_or_cpu_is_semantic_progress=False,
            native_overlap_accounting='SUM_OF_FULL_PEER_WALL_INTERVALS_CONSERVATIVE_UPPER_BOUND',
            cleanup=self.cleanup.measurement())
