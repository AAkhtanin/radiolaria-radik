# Stage07 public U3 integration map

The frozen reference is `800f38c3407b3f4ec93dc943c977ffeecb614881`. This map describes the candidate application boundary; it is not an execution grant or Stage07 acceptance. The independent contract review supplies exact file pins and authoritative scope.

## Existing public chain

- `build_pure_need_permission_v01(program, *, catalogue, source_context, semantic_proposal, work_id, memory_scope, max_generation_attempts=2, max_admissions=3, max_drs_bytes=131072)` — `source/reference/hedgehog/kernel/work_composition_v01.py` at line 1023.
- `observe_missing_pure_need_v01(context)` — `source/reference/hedgehog/kernel/work_composition_v01.py` at line 1042.
- `validate_current_pure_need_v01(host, *, need)` — `source/reference/hedgehog/kernel/work_composition_v01.py` at line 1068.
- `build_pure_missing_trigger_v01(context, *, need, resolution)` — `source/reference/hedgehog/kernel/work_composition_v01.py` at line 1075.
- `build_work_historical_output_v01(context, *, revision_id, work_id, output_field)` — `source/reference/hedgehog/kernel/work_composition_v01.py` at line 1132.
- `revise_work_program_v01(context, *, previous_revision_id, trigger, items, budget, catalogue, source_context, semantic_proposal)` — `source/reference/hedgehog/kernel/work_composition_v01.py` at line 1246.
- `advance_work_program_v01(program, *, catalogue, source_context, semantic_proposal, host_map, results=(), review_bindings=(), action_authorizers=None, continuation_context=None)` — `source/reference/hedgehog/kernel/work_composition_v01.py` at line 1314.
- `pure_need_oracle_v01(need)` — `source/reference/hedgehog/capability_admission_v01.py` at line 203.
- `pure_source_freeze_v01()` — `source/reference/hedgehog/capability_admission_v01.py` at line 210.
- `generate_controlled_pure_candidate_v01(host, *, need, expected_revision)` — `source/reference/hedgehog/capability_admission_v01.py` at line 219.
- `admit_pure_candidate_v01(host, *, need, source, source_format, contract_version, expected_revision, fuel=worker.MAX_FUEL, wall_seconds=worker.MAX_WALL)` — `source/reference/hedgehog/capability_admission_v01.py` at line 254.
- `validate_admitted_pure_package_v01(package, *, host, need)` — `source/reference/hedgehog/capability_admission_v01.py` at line 290.
- `reserve_pure_need_work_v01(host, *, need, kind, byte_count, expected_revision)` — `source/reference/hedgehog/work_execution_host_v01.py` at line 836.
- `install_admitted_pure_capability_v01(host, *, package, need, expected_revision)` — `source/reference/hedgehog/work_execution_host_v01.py` at line 892.
- `inspect_pure_need_resources_v01(host, *, task_id)` — `source/reference/hedgehog/work_execution_host_v01.py` at line 874.
- `search_pure_need_v01(store, *, host, need, as_of=None)` — `source/reference/hedgehog/capability_memory_binding_v01.py` at line 41.
- `write_pure_memory_v01(store, *, host, package, proposal)` — `source/reference/hedgehog/capability_memory_binding_v01.py` at line 210.
- `retrieve_pure_memory_v01(store, *, host, need, as_of=None, evaluation_time=None)` — `source/reference/hedgehog/capability_memory_binding_v01.py` at line 282.
- `validate_pure_memory_retrieval_v01(value, *, host, need)` — `source/reference/hedgehog/capability_memory_binding_v01.py` at line 379.
- `run_pure_wasm_worker_v01(source, *, source_format, inputs, fuel=MAX_FUEL, wall_seconds=MAX_WALL)` — `source/reference/hedgehog/wasm_pure_worker_v01.py` at line 199.

## Application obligations

The new application chain starts with actual PURE source Work. The requested capability is absent from the admitted catalogue; the ordinary native handler records NEEDS_CAPABILITY before a need is observed. Cold search uses semantic need fields rather than a known code digest. The existing controlled producer freezes common source and the independent all256 oracle before generation. A full worker admission precedes Host-scoped installation, a native continuation trigger and same-task guest-to-label consumption. Completed baseline Work is retained rather than replayed.

Warm reuse has a different task and fresh Host, while retaining the owning Root identity required by the public LocalDRS scope. Search, temporal eligibility/ranking, Root-reviewed descent and retrieval precede a full new admission. Stored material restores no Host or permission; generation remains zero for the warm task.

## Resource and time units

The unmodified worker is Wasmtime48.0.0, `pure-i32-closed-v01`, transform(i32)->i32 over0..255, at most16384 source/Wasm bytes, no imports/WASI/memory/table. Fuel at most100000 applies to each individual computation; an admission evaluates256 inputs. The30-second worker wall bound includes startup, conversion, compilation and its trials. The enclosing operation and one cleanup deadline are measured and bounded separately.

The native writer has a fixed controlled memory clock and validity interval. This candidate declares cold1014 and warm1015 with a fresh invocation-owned store; it does not import old records or rewrite their timestamps. Actual UTC raw-source intake/freshness and monotonic operation deadlines are independent guards. Explicit controlled future expiry is a negative control. UTC-age or persistent cross-run memory freshness is not claimed; that broader profile needs a public current-time writer contract.

## Boundaries

All application work is PURE with candidate_id=None and packet_id=None. Generation, admission and memory writing use existing U3 permissions; they grant no generic SAVE or consequential effect. No reference demo is run as application evidence. AUTH, provider, model and E calls are zero. The owner scenario remains unexecuted until the owner uses a fresh one-use admission.
