"""Explicit two-document informational consumer entry for a future admitted owner profile.

This is not a console activation or a provider admission. The shared console
history compatibility gate must be admitted before a launcher may call it.
The existing transport remains responsible for finite model scope and receipts.
"""
import os
from pathlib import Path

from .controller import DocumentConsole
from .contracts import require
from .native_document import normalize_sources, descriptors
from .informational_document import require_publication

PROFILE='radik.document.informational.two_sources.v26'
OWNER_COMMAND_STATUS='BLOCKED_SHARED_CONSOLE_HISTORY_READER_COMPATIBILITY'


def make_console(workspace, *, semantic_provider, semantic_receiver, runtime_admitted, clock=None):
    """The final pinned launcher must supply the existing admitted transport."""
    require(runtime_admitted is True, 'informational_owner_profile_not_admitted')
    console=DocumentConsole(workspace,semantic_provider=semantic_provider,semantic_receiver=semantic_receiver,
        runtime_admitted=runtime_admitted,clock=clock,continuation_enabled=True,informational_profile=True)
    console.current_policy()
    return console


def run_two_document_scenario(console, *, expected_initial, successor_bytes):
    """Same task, fresh O/A/C on each phase, one changed file, one E, no SAVE.

    This callable is prepared source. It is not reachable from the published
    console and has no model admission of its own. An admitted launcher must
    establish the durable cold/delta task rounds and shared-ledger compatibility.
    """
    require(type(console)is DocumentConsole and console.informational_profile,
        'informational_owner_console_profile')
    require(type(successor_bytes)is bytes and 0<len(successor_bytes)<=16384 and b'\0'not in successor_bytes,
        'informational_owner_successor_bytes')
    successor_bytes.decode('utf-8','strict')
    before=normalize_sources(console.intake.read())
    require(descriptors(before)==expected_initial and console.task is None,'informational_owner_initial_sources')
    require(successor_bytes!=before[0]['text'].encode(),'informational_owner_successor_unchanged')
    cold=console.compare()
    require(cold.task is console.task and console.model_calls==3,'informational_owner_cold_roles')
    logical=before[0]['source_ref'];name=console.intake.registry[logical]
    target=console.intake.directory/name
    require(not target.is_symlink() and target.resolve().parent==console.intake.directory.resolve(),
        'informational_owner_source_path')
    # Only the new owned RUN's admitted demo document may be changed by this entry.
    temporary=target.with_suffix('.successor')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:
        stream.write(successor_bytes);stream.flush();os.fsync(stream.fileno())
    require(normalize_sources(console.intake.read())==before,'informational_owner_cold_snapshot_changed')
    os.replace(temporary,target)
    updated=normalize_sources(console.intake.read())
    require(updated[1]==before[1] and updated[0]['revision']==before[0]['revision']+1,
        'informational_owner_successor_scope')
    result=console.update()
    require(result.task is cold.task and console.task.delta_count==1 and console.model_calls==6,
        'informational_owner_same_task_delta')
    require_publication(console.task)
    require(any(event['stage']=='INFORMATIONAL_DELTA_MEMORY_WRITEBACK'for event in console.events),
        'informational_owner_memory_writeback')
    return dict(profile=PROFILE,native_E_status='PASS',business_consumer_status='PASS',
        overall_status='PASS',result_id=result.plain['result_id'],model_calls=console.model_calls,
        same_task_id=console.task.task_id,source_descriptors=descriptors(updated),SAVE_performed=False)
