# Stage06 supervisor repair 01

This passage repairs only timeout diagnostics and first-failure persistence in
`../owner_terminal.py`. The accepted Stage06 producer/disclosure/consumer chain
and PROBE_02 retain their original evidence and acceptance scope. No native Work,
model, owner scenario, application entry, or repeated PROBE_02 runs here.

The four `OperationClock.due_reason` values now remain exact in Terminal
`PRIMARY_FAILURE`, the receipt's primary failure and `measurement.stop_reason`:
`STAGE06_OPERATION_LIMIT`, `STAGE06_NATIVE_LIMIT`,
`STAGE06_EARLY_CHECKPOINT_TIMEOUT`, and `STAGE06_SEMANTIC_IDLE_LIMIT`.

The first failure saves the original stop before one exclusive
`first_failure.json` publication. The existing writer flushes and fsyncs the
file and directory, then reads it back; the supervisor performs an additional
hash-bound readback. The record is capped at 64 KiB. A temporary SIGALRM limits
ordinary interruptible persistence to one second within the existing cleanup
deadline, restores the previous handler, and never renews the stop. An
uninterruptible kernel I/O stall is not claimed to have a hard wall bound.
Persistence failure is a separate secondary failure, is never retried, and does
not bypass child teardown or replace the original cause. Terminal output errors
also cannot prevent teardown.

Eight isolated stdlib controls exercise the actual supervisor failure/finally
path with synthetic clock states and disposable stdlib children: four limits,
write failure, explicit readback failure, interruptible write timeout, and a
secondary cleanup error. They inspect durable ordering, exact diagnostics,
immutable first stop, final receipt, child reaping, lock release and timer
restoration. These are mechanical controls, not a new Stage06 semantic actual.
The closed control invocation took 1.341037333 seconds; all eight cases passed.
Its complete result and each case's files are under `controls_run_01/`.

Old admission, readiness, inventories, probe evidence and RETURN remain unchanged.
The new `../source_manifest_PROBE_04.json` is an inventory filename accepted by
the existing loader; no fourth probe was run. Its executable delta is exactly
one owner supervisor pin, plus finite diagnostic literals. Peer source pins and
the native reference are unchanged. The new owner admission is a separately
reviewed one-use file, selected by a fixed basename option. Its command is kept
only in the external owner handoff and RETURN.

`engineering_budget.json` continues the existing 900-second budget. It carries
the previous conservative 105.981691582-second ceiling, including the entire
previous finalization reservation, without resetting historical charges. New
measured preparation and controls are added; reserves are not measured elapsed
time. Stage06 remains open pending owner actual. No push or release is performed.
