#!/usr/bin/env python3
"""Cheap, source-admitted P28 clocks and one real owned-child cleanup control.

No application, native, Work, D, E, AUTH, transport or provider module is loaded.
The exact three implementation files must first receive independent source review.
"""
import time
COMMAND_STARTED_NS = time.monotonic_ns()
import signal


def _command_limit(_signum, _frame):
    raise TimeoutError('timer_command_limit')


if __name__ == '__main__':
    # Nine seconds of work leave one fixed second for the owned-child cleanup.
    signal.signal(signal.SIGALRM, _command_limit)
    remaining = 9 - (time.monotonic_ns()-COMMAND_STARTED_NS)/1000000000
    if remaining <= 0:
        raise TimeoutError('timer_command_limit')
    signal.setitimer(signal.ITIMER_REAL, remaining)

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import types


PROJECT = Path(__file__).absolute().parents[4]
PREFIX = 'review/g2e_successor_passage/proposals/g2e_no_effects_v28_ordinary_entry_owner_scenario'
SELF = PREFIX + '/timer_preparation.py'
TIMING = PREFIX + '/supervisor_timing.py'
SUPERVISOR = PREFIX + '/owner_terminal.py'
REVIEW = PREFIX + '/timer_source_review.json'
NS = 1000000000
CHILD_SOURCE = '''import json,os,signal,time
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print(json.dumps({"schema":"radik.p28.timer_child.v01","pid":os.getpid(),"ready":True}),flush=True)
time.sleep(10)
'''


def require(value, code):
    if not value:
        raise ValueError(code)


def raw_read(path, cap=8388608):
    require(path.is_absolute() and path.is_relative_to(PROJECT), 'timer_owned_read')
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'timer_symlink_refused')
        if parent == PROJECT:
            break
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == os.geteuid() and 0 <= before.st_size <= cap,
            'timer_regular_read')
        raw = stream.read(before.st_size+1)
        after = os.fstat(stream.fileno())
    require(len(raw) == before.st_size and (before.st_dev,before.st_ino,before.st_size,
        before.st_mtime_ns,before.st_ctime_ns) == (after.st_dev,after.st_ino,after.st_size,
        after.st_mtime_ns,after.st_ctime_ns), 'timer_changed_read')
    return raw


def load_source(name, pins, module_name):
    raw = raw_read(PROJECT/name)
    require(hashlib.sha256(raw).hexdigest() == pins.get(name), 'timer_source_pin_changed')
    module = types.ModuleType(module_name)
    module.__file__ = str(PROJECT/name)
    exec(compile(raw,module.__file__,'exec',dont_inherit=True), module.__dict__)
    return module


def reviewed_source(expected):
    require(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected), 'timer_review_hash')
    raw = raw_read(PROJECT/REVIEW)
    require(hashlib.sha256(raw).hexdigest() == expected, 'timer_review_changed')
    review = json.loads(raw)
    require(review.get('reviewer') == '/root/p20_reviewer'
        and review.get('status') == 'SOURCE_ACCEPTED_FOR_P28_TIMER_CONTROLS'
        and review.get('application_native_AUTH_provider_SAVE_allowed') is False,
        'timer_independent_source_grant_required')
    pins = review.get('code_pins')
    require(type(pins) is dict and set(pins) == {SELF,TIMING,SUPERVISOR}, 'timer_finite_source_set')
    for name,sha in pins.items():
        require(hashlib.sha256(raw_read(PROJECT/name)).hexdigest() == sha, 'timer_exact_source_review')
    require(review.get('child_source_sha256') == hashlib.sha256(CHILD_SOURCE.encode()).hexdigest()
        and review.get('maximum_wall_seconds') == 10, 'timer_child_source_and_budget')
    return review


def event(timing, clock, seconds, kind, phase, **details):
    row = dict(at_monotonic_ns=clock.started_ns+int(seconds*NS), kind=kind,
        phase=phase, sequence=int(seconds*1000)+1)
    row.update(details)
    return row


def pure_controls(timing):
    rows = []
    start = 100*NS
    def observe(clock, seconds, kind, phase, verified=False, **details):
        row = event(timing,clock,seconds,kind,phase,**details)
        return clock.event(row, observed_ns=row['at_monotonic_ns'], readback_verified=verified)
    def record(name, clock, now, expected):
        actual = clock.due_reason(start+int(now*NS))
        require(actual == expected, 'timer_control_'+name)
        rows.append(dict(control=name, status='PASS', expected=expected, observed=actual,
            measurement=clock.measurement(start+int(now*NS)), synthetic_clock=True,
            application_native_provider_AUTH_SAVE_calls=0))

    clock = timing.Deadline(start)
    observe(clock,0,'PHASE_ENTER','NATIVE',native=True,span_id='scenario')
    observe(clock,10,'PHASE_ENTER','PROVIDER',native=False,span_id='cold_O')
    record('provider_latency_excluded_from_native_and_e_idle',clock,609,None)
    require(clock.native_used_ns(start+609*NS) == 10*NS,'timer_provider_exclusion')
    observe(clock,610,'PHASE_EXIT','PROVIDER',native=False,span_id='cold_O')
    observe(clock,620,'E_ENTER','E',verified=True,e_call_id='E1')
    observe(clock,700,'REPORT_READBACK_ACK','E',verified=True,useful=True,
        e_call_id='E1',report_kind='COMPLETED_SEMANTIC_SUBCHECK',
        readback_ref=dict(path='fixture/completed.json',sha256='0'*64,size_bytes=2))
    observe(clock,710,'E_EXIT','E',e_call_id='E1')
    observe(clock,711,'PHASE_EXIT','NATIVE',native=True,span_id='scenario')
    record('success',clock,712,None)
    require(clock.native_used_ns(start+712*NS)==111*NS and clock.first_checkpoint_ns==start+700*NS
        and clock.deadline_ns==start+7800*NS,'timer_success_measurements')

    clock = timing.Deadline(start)
    record('total_operation_limit',clock,7800,'OPERATION_LIMIT')
    clock = timing.Deadline(start)
    observe(clock,0,'PHASE_ENTER','NATIVE',native=True,span_id='cold_native')
    observe(clock,1000,'PHASE_EXIT','NATIVE',native=True,span_id='cold_native')
    observe(clock,2000,'PHASE_ENTER','NATIVE',native=True,span_id='delta_native')
    record('native_cumulative_all_spans',clock,4600,'CUMULATIVE_NATIVE_LIMIT')

    clock = timing.Deadline(start)
    record('bootstrap_has_no_e_early_or_idle_clock',clock,3000,None)
    observe(clock,3000,'PHASE_ENTER','NATIVE',native=True,span_id='scenario')
    observe(clock,3000,'E_ENTER','E',verified=True,e_call_id='E1')
    record('e_early_not_operation_start',clock,3599,None)
    record('e_early_checkpoint_expired',clock,3600,'E_EARLY_CHECKPOINT_TIMEOUT')
    late = observe(clock,3600,'REPORT_READBACK_ACK','E',verified=True,useful=True,
        e_call_id='E1',report_kind='LATE_COMPLETION',readback_ref=dict(
            path='fixture/completed.json',sha256='0'*64,size_bytes=2))
    require(late is False and clock.first_checkpoint_ns is None,'timer_late_ack_does_not_rescue')

    clock = timing.Deadline(start)
    observe(clock,0,'PHASE_ENTER','NATIVE',native=True,span_id='scenario')
    observe(clock,10,'E_ENTER','E',verified=True,e_call_id='E1')
    observe(clock,11,'REPORT_READBACK_ACK','E',verified=True,useful=True,
        e_call_id='E1',report_kind='COMPLETED_SEMANTIC_SUBCHECK',
        readback_ref=dict(path='fixture/completed.json',sha256='0'*64,size_bytes=2))
    for seconds,kind in ((100,'HEARTBEAT'),(400,'STATUS'),(910,'HEARTBEAT')):
        observe(clock,seconds,kind,'E',cpu_counter=900000,validator_calls=9999)
    record('e_idle_liveness_cpu_counters_no_credit',clock,911,'E_SEMANTIC_IDLE_LIMIT')
    require(clock.last_useful_ns==start+11*NS and clock.deadline_ns==start+7800*NS,
        'timer_liveness_never_resets_clock')

    clock = timing.Deadline(start)
    action = clock.action(start+NS,required_failure=True,monitor_failure=True,owner_interrupt=True)
    require(action=='INTERRUPT' and clock.reason=='REQUIRED_WITNESS_UNAVAILABLE',
        'timer_required_witness_precedence')
    original=(clock.reason,clock.stop_ns)
    clock.action(start+2*NS,monitor_failure=True)
    require((clock.reason,clock.stop_ns)==original,'timer_primary_cause_stable')
    rows.append(dict(control='required_witness_loss_preserves_primary',status='PASS',
        action=action,reason=clock.reason,synthetic_clock=True))
    clock = timing.Deadline(start)
    action = clock.action(start+NS,emergency_failure=True)
    require(action=='INTERRUPT' and clock.reason=='REQUIRED_WITNESS_CHANNEL_IO_FAILED',
        'timer_emergency_channel_failure')
    exits=[]
    now=time.monotonic_ns()
    writer=timing.EventWriter(started_ns=now,deadline_ns=now+7800*NS,
        run_binding='0'*64,write=lambda _raw: (_ for _ in ()).throw(OSError('fixture')),
        emergency_exit=lambda code: exits.append(code))
    try:
        writer.emit('REQUIRED_WITNESS_UNAVAILABLE','E',failure=timing.fallback('FIXTURE_LOSS'))
    except RuntimeError as error:
        require(str(error)=='terminal_emergency_exit_returned','timer_emergency_exit_projection')
    require(exits==[timing.EMERGENCY_IO_EXIT],'timer_emergency_exit_code')
    rows.append(dict(control='emergency_channel_write_failure',status='PASS',
        action=action,reason=clock.reason,observed_exit_code=exits[0],synthetic_clock=True))
    return rows


def real_cleanup(supervisor, timing, workspace):
    """One actual short stdlib child; its reviewed source contains no native call."""
    started_ns=time.monotonic_ns()
    child=None
    lock_fd=None
    stop_ns=None
    signals=[]
    raw=b''
    limits=dict(timing.LIMITS,interrupt_grace_seconds=0.05,terminate_grace_seconds=0.05,
        kill_wait_seconds=0.5,cleanup_seconds=1)
    try:
        lock_fd=os.open(workspace/'cleanup_control.lock',
            os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        child=subprocess.Popen([sys.executable,'-I','-S','-B','-c',CHILD_SOURCE],
            cwd=workspace,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
            close_fds=True,pass_fds=(lock_fd,),
            env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},start_new_session=True)
        ready,_,_=select.select([child.stdout],[],[],2)
        require(bool(ready),'timer_real_child_readiness_timeout')
        raw=os.read(child.stdout.fileno(),4096)
        fd=os.open(workspace/'real_child_stdout.raw',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        row=json.loads(raw)
        require(row==dict(schema='radik.p28.timer_child.v01',pid=child.pid,ready=True),
            'timer_real_child_ready_binding')
        stop_ns=time.monotonic_ns()
        reaped=supervisor.bounded_cleanup(child,stop_ns=stop_ns,limits=limits,
            signals=signals,started_ns=started_ns)
        elapsed=time.monotonic_ns()-stop_ns
        require(reaped and child.poll() is not None and child.returncode==-signal.SIGKILL
            and [row['action'] for row in signals]==['INTERRUPT','TERMINATE','KILL']
            and elapsed<=int(limits['cleanup_seconds']*NS),'timer_real_child_bounded_reap')
        released=supervisor.release_owned_lock(lock_fd,child_started=True,
            receipt=dict(lock_explicit_unlock_permitted=reaped))
        lock_fd=None
        require(released,'timer_lock_release_after_reap')
        probe=os.open(workspace/'cleanup_control.lock',os.O_RDWR|os.O_NOFOLLOW)
        try:
            fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(probe,fcntl.LOCK_UN)
        finally:
            os.close(probe)
        receipt=dict(schema='radik.p28.timer_cleanup_control.v01',status='PASS',
            control='real_short_owned_child_interrupt_terminate_kill_reap',
            child_pid=child.pid,child_exit_code=child.returncode,child_reaped=True,
            inherited_lock_released_after_reap=True,subsequent_lock_acquire_succeeded=True,
            signals=signals,cleanup_elapsed_ns=elapsed,cleanup_limit_seconds=limits['cleanup_seconds'],
            child_source_sha256=hashlib.sha256(CHILD_SOURCE.encode()).hexdigest(),
            stdout_sha256=hashlib.sha256(raw).hexdigest(),stdout_bytes=len(raw),
            application_native_provider_AUTH_SAVE_calls=0,automatic_retry=False)
        receipt_ref=supervisor.put(workspace/'real_child_receipt.json',receipt)
        require(json.loads(supervisor.checked_reference(receipt_ref))==receipt,'timer_real_receipt_readback')
        return receipt_ref
    finally:
        if child is not None and child.poll() is None:
            if stop_ns is None:
                stop_ns=time.monotonic_ns()
            supervisor.bounded_cleanup(child,stop_ns=stop_ns,limits=limits,
                signals=signals,started_ns=started_ns)
        if child is not None:
            child.stdout.close()
        if lock_fd is not None:
            supervisor.release_owned_lock(lock_fd,child_started=child is not None,
                receipt=dict(lock_explicit_unlock_permitted=child is None or child.poll() is not None))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source-review-sha256',required=True)
    parser.add_argument('--workspace',required=True)
    args=parser.parse_args()
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'timer_isolated_python_required')
    name=args.workspace
    require(type(name)is str and name.startswith(PREFIX+'/timer_actual/')
        and not any(part in ('','..','.') for part in name.split('/')),
        'timer_finite_workspace')
    review=reviewed_source(args.source_review_sha256)
    timing=load_source(TIMING,review['code_pins'],'radik_p28_timing_control')
    supervisor=load_source(SUPERVISOR,review['code_pins'],'radik_p28_supervisor_control')
    workspace=PROJECT/name
    require(not workspace.exists() and not workspace.is_symlink(),'timer_actual_no_overwrite')
    parent=workspace.parent
    require(parent.is_dir() and not parent.is_symlink(),'timer_prepared_workspace_parent')
    workspace.mkdir(mode=0o700)
    started=COMMAND_STARTED_NS
    rows=pure_controls(timing)
    control_ref=supervisor.put(workspace/'clock_controls.json',dict(
        schema='radik.p28.timer_controls.v01',status='PASS',rows=rows,
        source_review_sha256=args.source_review_sha256,code_pins=review['code_pins'],
        limits=timing.LIMITS,synthetic_clocks=True,actual_native_E_calls=0,
        actual_AUTH_provider_SAVE_calls=0))
    cleanup_ref=real_cleanup(supervisor,timing,workspace)
    elapsed=time.monotonic_ns()-started
    require(elapsed<10*NS,'timer_total_short_budget')
    result=dict(schema='radik.p28.timer_preparation_result.v01',status='PASS',
        source_review_sha256=args.source_review_sha256,code_pins=review['code_pins'],
        clock_controls_ref=control_ref,real_child_receipt_ref=cleanup_ref,
        elapsed_wall_ns=elapsed,maximum_wall_seconds=10,
        application_native_provider_AUTH_SAVE_calls=0,automatic_retry=False)
    result_ref=supervisor.put(workspace/'result.json',result)
    signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps(dict(status='PASS',result_ref=result_ref),sort_keys=True),flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
